use std::{io, path::Path, time::Duration};

use certifex_core::NodeRegistration;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use thiserror::Error;
use tokio::{fs, time::sleep};
use tracing::warn;

use crate::cloudflare::{Cloudflare, CloudflareError};

#[derive(Debug, Error)]
pub enum AcmeError {
    #[error("ACME protocol error: {0}")]
    Protocol(#[from] instant_acme::Error),
    #[error("Cloudflare DNS error: {0}")]
    Dns(#[from] CloudflareError),
    #[error("ACME state I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("ACME account state error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid CSR PEM: {0}")]
    Pem(#[from] pem::PemError),
    #[error("authorization entered unexpected state: {0:?}")]
    AuthorizationState(AuthorizationStatus),
    #[error("ACME server did not offer a DNS-01 challenge")]
    MissingDnsChallenge,
    #[error("ACME order contained a non-DNS identifier")]
    UnsupportedIdentifier,
    #[error("ACME order did not become ready: {0:?}")]
    OrderNotReady(OrderStatus),
    #[error("CSR PEM has unexpected tag `{0}`")]
    UnexpectedCsrTag(String),
}

#[derive(Clone)]
pub struct AcmeIssuer {
    account: Account,
    cloudflare: Cloudflare,
    propagation_delay: Duration,
}

impl AcmeIssuer {
    /// Loads or creates the persistent ACME account used by the registrar.
    ///
    /// # Errors
    /// Returns an error when account state cannot be read/written or the ACME server rejects
    /// account creation/restoration.
    pub async fn load_or_create(
        cloudflare: Cloudflare,
        state_dir: &Path,
        directory_url: &str,
        email: Option<&str>,
        propagation_delay: Duration,
    ) -> Result<Self, AcmeError> {
        fs::create_dir_all(state_dir).await?;
        let credentials_path = state_dir.join("acme-account.json");
        let builder = Account::builder()?;
        let account = if credentials_path.exists() {
            let credentials =
                serde_json::from_slice::<AccountCredentials>(&fs::read(&credentials_path).await?)?;
            builder.from_credentials(credentials).await?
        } else {
            let contact = email.map(|value| format!("mailto:{value}"));
            let contacts = contact.as_deref().into_iter().collect::<Vec<_>>();
            let (account, credentials) = builder
                .create(
                    &NewAccount {
                        contact: &contacts,
                        terms_of_service_agreed: true,
                        only_return_existing: false,
                    },
                    directory_url.to_owned(),
                    None,
                )
                .await?;
            write_secret_json(&credentials_path, &credentials).await?;
            account
        };

        Ok(Self {
            account,
            cloudflare,
            propagation_delay,
        })
    }

    /// Issues a certificate for exactly the DNS names already signed into the node CSR.
    ///
    /// # Errors
    /// Returns an error when ACME authorization, DNS provisioning, CSR finalization, or
    /// certificate retrieval fails.
    pub async fn issue(&self, registration: &NodeRegistration) -> Result<String, AcmeError> {
        let identifiers = registration
            .hostnames
            .iter()
            .cloned()
            .map(Identifier::Dns)
            .collect::<Vec<_>>();
        let mut order = self.account.new_order(&NewOrder::new(&identifiers)).await?;

        let mut challenges = Vec::new();
        {
            let mut authorizations = order.authorizations();
            while let Some(result) = authorizations.next().await {
                let mut authorization = result?;
                match authorization.status {
                    AuthorizationStatus::Pending => {}
                    AuthorizationStatus::Valid => continue,
                    status => return Err(AcmeError::AuthorizationState(status)),
                }
                let challenge = authorization
                    .challenge(ChallengeType::Dns01)
                    .ok_or(AcmeError::MissingDnsChallenge)?;
                let Identifier::Dns(domain) = challenge.identifier().identifier else {
                    return Err(AcmeError::UnsupportedIdentifier);
                };
                challenges.push((
                    format!("_acme-challenge.{domain}"),
                    challenge.key_authorization().dns_value(),
                ));
            }
        }

        let mut record_ids = Vec::with_capacity(challenges.len());
        for (name, value) in &challenges {
            match self.cloudflare.create_txt(name, value).await {
                Ok(record_id) => record_ids.push(record_id),
                Err(error) => {
                    self.cleanup_records(&record_ids).await;
                    return Err(error.into());
                }
            }
        }

        let result = async {
            sleep(self.propagation_delay).await;

            let mut authorizations = order.authorizations();
            while let Some(result) = authorizations.next().await {
                let mut authorization = result?;
                match authorization.status {
                    AuthorizationStatus::Pending => {
                        let mut challenge = authorization
                            .challenge(ChallengeType::Dns01)
                            .ok_or(AcmeError::MissingDnsChallenge)?;
                        challenge.set_ready().await?;
                    }
                    AuthorizationStatus::Valid => {}
                    status => return Err(AcmeError::AuthorizationState(status)),
                }
            }

            let status = order.poll_ready(&RetryPolicy::default()).await?;
            if status != OrderStatus::Ready {
                return Err(AcmeError::OrderNotReady(status));
            }

            let csr = pem::parse(registration.csr_pem.as_bytes())?;
            if csr.tag() != "CERTIFICATE REQUEST" && csr.tag() != "NEW CERTIFICATE REQUEST" {
                return Err(AcmeError::UnexpectedCsrTag(csr.tag().to_owned()));
            }
            order.finalize_csr(csr.contents()).await?;
            Ok(order.poll_certificate(&RetryPolicy::default()).await?)
        }
        .await;

        self.cleanup_records(&record_ids).await;
        result
    }

    async fn cleanup_records(&self, record_ids: &[String]) {
        for record_id in record_ids {
            if let Err(error) = self.cloudflare.delete_record(record_id).await {
                warn!(%record_id, %error, "failed to clean up ACME TXT record");
            }
        }
    }
}

#[cfg(unix)]
async fn write_secret_json<T: serde::Serialize + Sync>(
    path: &Path,
    value: &T,
) -> Result<(), AcmeError> {
    use tokio::io::AsyncWriteExt;

    let bytes = serde_json::to_vec_pretty(value)?;
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(path).await?;
    file.write_all(&bytes).await?;
    file.sync_all().await?;
    Ok(())
}

#[cfg(not(unix))]
async fn write_secret_json<T: serde::Serialize + Sync>(
    path: &Path,
    value: &T,
) -> Result<(), AcmeError> {
    fs::write(path, serde_json::to_vec_pretty(value)?).await?;
    Ok(())
}

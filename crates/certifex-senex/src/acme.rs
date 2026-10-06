use std::{
    io,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use certifex_core::NodeRegistration;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, CertificateIdentifier, ChallengeType,
    Error as InstantAcmeError, Identifier, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use rustls_pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{fs, time::sleep};
use tracing::warn;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::cloudflare::{Cloudflare, CloudflareError};

const ARI_RETRY_AFTER_ERROR: Duration = Duration::from_secs(3600);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RenewalSchedule {
    pub renew_after: i64,
    pub ari_check_after: Option<i64>,
    pub ari_window_start: Option<i64>,
    pub ari_window_end: Option<i64>,
}

impl RenewalSchedule {
    #[must_use]
    pub const fn renewal_due(&self, now_unix: i64) -> bool {
        now_unix >= self.renew_after
    }

    #[must_use]
    pub fn ari_refresh_due(&self, now_unix: i64) -> bool {
        self.ari_check_after
            .is_some_and(|deadline| now_unix >= deadline)
    }
}

#[derive(Debug, Error)]
pub enum AcmeError {
    #[error("ACME protocol error: {0}")]
    Protocol(#[from] InstantAcmeError),
    #[error("Cloudflare DNS error: {0}")]
    Dns(#[from] CloudflareError),
    #[error("ACME state I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("ACME account state error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid certificate or CSR PEM: {0}")]
    Pem(#[from] pem::PemError),
    #[error("invalid issued certificate: {0}")]
    Certificate(String),
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
    /// When `replaces_certificate_chain_pem` is supplied, Certifex marks the new ACME order as
    /// replacing that certificate when the CA supports ARI.
    ///
    /// # Errors
    /// Returns an error when ACME authorization, DNS provisioning, CSR finalization, or
    /// certificate retrieval fails.
    pub async fn issue(
        &self,
        registration: &NodeRegistration,
        replaces_certificate_chain_pem: Option<&str>,
    ) -> Result<String, AcmeError> {
        let identifiers = registration
            .hostnames
            .iter()
            .cloned()
            .map(Identifier::Dns)
            .collect::<Vec<_>>();
        let replacement_leaf = replaces_certificate_chain_pem
            .map(leaf_certificate_der)
            .transpose()?;
        let replacement_id = replacement_leaf
            .as_ref()
            .map(CertificateIdentifier::try_from)
            .transpose()
            .map_err(AcmeError::Certificate)?;

        let mut order = if let Some(replacement_id) = replacement_id {
            let replacement_order = NewOrder::new(&identifiers).replaces(replacement_id);
            match self.account.new_order(&replacement_order).await {
                Ok(order) => order,
                Err(InstantAcmeError::Unsupported(_)) => {
                    self.account.new_order(&NewOrder::new(&identifiers)).await?
                }
                Err(error) => return Err(error.into()),
            }
        } else {
            self.account.new_order(&NewOrder::new(&identifiers)).await?
        };

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

    /// Computes or refreshes the persisted renewal schedule for an issued certificate.
    ///
    /// ARI is preferred. If the CA does not support ARI, renewal falls back to two-thirds of the
    /// certificate lifetime. Transient ARI failures preserve an existing target and retry ARI in
    /// one hour rather than risking certificate expiry.
    ///
    /// # Errors
    /// Returns an error when the leaf certificate cannot be parsed or its validity interval is
    /// malformed.
    pub async fn renewal_schedule(
        &self,
        certificate_chain_pem: &str,
        previous: Option<&RenewalSchedule>,
    ) -> Result<RenewalSchedule, AcmeError> {
        let leaf_der = leaf_certificate_der(certificate_chain_pem)?;
        let fallback = fallback_schedule(&leaf_der)?;
        let certificate_id =
            CertificateIdentifier::try_from(&leaf_der).map_err(AcmeError::Certificate)?;
        let now = unix_now();

        match self.account.renewal_info(&certificate_id).await {
            Ok((info, retry_after)) => {
                let start = info.suggested_window.start.unix_timestamp();
                let end = info.suggested_window.end.unix_timestamp();
                if end <= start {
                    return Err(AcmeError::Certificate(
                        "ARI suggested renewal window is empty".to_owned(),
                    ));
                }
                let renew_after = if start <= now {
                    now
                } else if previous.is_some_and(|schedule| {
                    schedule.ari_window_start == Some(start)
                        && schedule.ari_window_end == Some(end)
                        && (start..end).contains(&schedule.renew_after)
                }) {
                    previous.map_or(start, |schedule| schedule.renew_after)
                } else {
                    random_unix_in_window(start, end)?
                };
                Ok(RenewalSchedule {
                    renew_after,
                    ari_check_after: Some(add_duration(now, retry_after)),
                    ari_window_start: Some(start),
                    ari_window_end: Some(end),
                })
            }
            Err(InstantAcmeError::Unsupported(_)) => Ok(fallback),
            Err(error) => {
                warn!(%error, "failed to refresh ACME ARI; retaining safe renewal schedule");
                let mut schedule = previous.cloned().unwrap_or(fallback);
                schedule.ari_check_after = Some(add_duration(now, ARI_RETRY_AFTER_ERROR));
                Ok(schedule)
            }
        }
    }

    async fn cleanup_records(&self, record_ids: &[String]) {
        for record_id in record_ids {
            if let Err(error) = self.cloudflare.delete_record(record_id).await {
                warn!(%record_id, %error, "failed to clean up ACME TXT record");
            }
        }
    }
}

fn leaf_certificate_der(certificate_chain_pem: &str) -> Result<CertificateDer<'static>, AcmeError> {
    let blocks = pem::parse_many(certificate_chain_pem.as_bytes())?;
    let leaf = blocks
        .into_iter()
        .find(|block| block.tag() == "CERTIFICATE")
        .ok_or_else(|| AcmeError::Certificate("certificate chain contains no leaf".to_owned()))?;
    Ok(CertificateDer::from(leaf.into_contents()))
}

fn fallback_schedule(leaf_der: &CertificateDer<'_>) -> Result<RenewalSchedule, AcmeError> {
    let (_, certificate) = X509Certificate::from_der(leaf_der.as_ref())
        .map_err(|error| AcmeError::Certificate(error.to_string()))?;
    let not_before = certificate.validity().not_before.timestamp();
    let not_after = certificate.validity().not_after.timestamp();
    if not_after <= not_before {
        return Err(AcmeError::Certificate(
            "certificate validity interval is empty".to_owned(),
        ));
    }
    let lifetime = not_after.saturating_sub(not_before);
    let target = not_before.saturating_add(lifetime.saturating_mul(2) / 3);
    Ok(RenewalSchedule {
        renew_after: target.max(unix_now()),
        ari_check_after: None,
        ari_window_start: None,
        ari_window_end: None,
    })
}

fn random_unix_in_window(start: i64, end: i64) -> Result<i64, AcmeError> {
    let span = end.saturating_sub(start);
    let span = u64::try_from(span)
        .map_err(|error| AcmeError::Certificate(format!("invalid ARI window: {error}")))?;
    if span == 0 {
        return Err(AcmeError::Certificate(
            "ARI suggested renewal window is empty".to_owned(),
        ));
    }
    let offset = fastrand::u64(0..span);
    Ok(start.saturating_add(i64::try_from(offset).unwrap_or(i64::MAX)))
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
        })
}

fn add_duration(unix: i64, duration: Duration) -> i64 {
    unix.saturating_add(i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
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

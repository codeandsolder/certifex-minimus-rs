mod acme;
mod cloudflare;

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use acme::{AcmeError, AcmeIssuer, RenewalSchedule};
use axum::{
    Json, Router,
    extract::{ConnectInfo, State},
    http::StatusCode,
    routing::{get, post},
};
use certifex_core::{CertificateBundle, NodeRegistration, RegistrationResponse};
use clap::Parser;
use cloudflare::{Cloudflare, CloudflareError};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    fs,
    sync::{Mutex, RwLock},
    time::{MissedTickBehavior, interval},
};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

#[derive(Debug, Parser)]
#[command(version, about = "Certifex registrar and certificate control plane")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:7443")]
    listen: String,

    #[arg(long)]
    domain: String,

    #[arg(long, default_value = "CLOUDFLARE_API_TOKEN")]
    cloudflare_token_env: String,

    #[arg(long, default_value = "/var/lib/certifex-minimus/senex")]
    state_dir: PathBuf,

    #[arg(long, default_value = LETS_ENCRYPT_STAGING)]
    acme_directory: String,

    #[arg(long)]
    acme_email: Option<String>,

    #[arg(long, default_value_t = 5)]
    dns_propagation_seconds: u64,

    #[arg(long, default_value_t = 3600)]
    renewal_check_seconds: u64,
}

#[derive(Clone)]
struct AppState {
    controller: Arc<Controller>,
}

struct Controller {
    domain: String,
    cloudflare: Cloudflare,
    issuer: AcmeIssuer,
    nodes_dir: PathBuf,
    nodes: RwLock<BTreeMap<String, StoredNode>>,
    reconcile: Mutex<()>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredNode {
    registration: NodeRegistration,
    certificate: CertificateBundle,
    #[serde(default)]
    renewal: Option<RenewalSchedule>,
}

#[derive(Debug, Error)]
enum ControllerError {
    #[error("hostname `{0}` is not a direct child of the configured domain")]
    OutsideDomain(String),
    #[error("hostname `{name}` is already owned by node `{node_id}`")]
    NameCollision { name: String, node_id: String },
    #[error("claimed address is not a Tailscale IPv4 address: {0}")]
    InvalidTailscaleIp(IpAddr),
    #[error("Cloudflare error: {0}")]
    Cloudflare(#[from] CloudflareError),
    #[error("ACME error: {0}")]
    Acme(#[from] AcmeError),
    #[error("state I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("state serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let token = env::var(&args.cloudflare_token_env).map_err(|_| {
        format!(
            "Cloudflare token environment variable `{}` is not set",
            args.cloudflare_token_env
        )
    })?;
    let client = reqwest::Client::builder().build()?;
    let cloudflare = Cloudflare::for_zone(client, token, &args.domain).await?;
    let issuer = AcmeIssuer::load_or_create(
        cloudflare.clone(),
        &args.state_dir,
        &args.acme_directory,
        args.acme_email.as_deref(),
        Duration::from_secs(args.dns_propagation_seconds),
    )
    .await?;
    let controller =
        Arc::new(Controller::load(args.domain, args.state_dir, cloudflare, issuer).await?);
    let state = AppState {
        controller: controller.clone(),
    };
    let _renewal_task = tokio::spawn(renewal_loop(
        controller,
        Duration::from_secs(args.renewal_check_seconds.max(1)),
    ));

    let app = Router::new()
        .route("/healthz", get(health))
        .route("/v1/register", post(register))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    info!(listen = %args.listen, "certifex-senex listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

async fn renewal_loop(controller: Arc<Controller>, cadence: Duration) {
    controller.maintain_renewals().await;
    let mut ticker = interval(cadence);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    ticker.tick().await;
    loop {
        ticker.tick().await;
        controller.maintain_renewals().await;
    }
}

async fn health() -> StatusCode {
    StatusCode::OK
}

async fn register(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(registration): Json<NodeRegistration>,
) -> Result<Json<RegistrationResponse>, (StatusCode, String)> {
    if let Err(error) = registration.validate() {
        warn!(node_id = %registration.node_id, %error, "rejected registration");
        return Err((StatusCode::BAD_REQUEST, error.to_string()));
    }
    if !peer.ip().is_loopback() && peer.ip() != registration.tailscale_ip {
        return Err((
            StatusCode::FORBIDDEN,
            format!(
                "registration source {} does not match claimed Tailscale address {}",
                peer.ip(),
                registration.tailscale_ip
            ),
        ));
    }

    let node_id = registration.node_id.clone();
    match state.controller.reconcile(registration).await {
        Ok(response) => {
            info!(%node_id, "node reconciliation complete");
            Ok(Json(response))
        }
        Err(
            error @ (ControllerError::OutsideDomain(_)
            | ControllerError::NameCollision { .. }
            | ControllerError::InvalidTailscaleIp(_)),
        ) => {
            warn!(%node_id, %error, "rejected registration");
            Err((StatusCode::CONFLICT, error.to_string()))
        }
        Err(error) => {
            warn!(%node_id, %error, "registration reconciliation failed");
            Err((StatusCode::BAD_GATEWAY, error.to_string()))
        }
    }
}

impl Controller {
    async fn load(
        domain: String,
        state_dir: PathBuf,
        cloudflare: Cloudflare,
        issuer: AcmeIssuer,
    ) -> Result<Self, ControllerError> {
        let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        let nodes_dir = state_dir.join("nodes");
        fs::create_dir_all(&nodes_dir).await?;
        let mut nodes = BTreeMap::new();
        let mut entries = fs::read_dir(&nodes_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let stored = serde_json::from_slice::<StoredNode>(&fs::read(entry.path()).await?)?;
            nodes.insert(stored.registration.node_id.clone(), stored);
        }
        Ok(Self {
            domain,
            cloudflare,
            issuer,
            nodes_dir,
            nodes: RwLock::new(nodes),
            reconcile: Mutex::new(()),
        })
    }

    async fn reconcile(
        &self,
        registration: NodeRegistration,
    ) -> Result<RegistrationResponse, ControllerError> {
        let _serial = self.reconcile.lock().await;
        self.validate_registration_scope(&registration).await?;

        let old = self.nodes.read().await.get(&registration.node_id).cloned();
        for name in &registration.hostnames {
            self.cloudflare
                .ensure_a(name, registration.tailscale_ip)
                .await?;
        }

        let (certificate, renewal) = match old.as_ref() {
            Some(previous)
                if previous.certificate.hostnames == registration.hostnames
                    && previous.registration.csr_pem == registration.csr_pem =>
            {
                let mut renewal = previous.renewal.clone();
                let now = unix_now();
                if renewal
                    .as_ref()
                    .is_none_or(|schedule| schedule.ari_refresh_due(now))
                {
                    renewal = Some(
                        self.issuer
                            .renewal_schedule(
                                &previous.certificate.certificate_chain_pem,
                                renewal.as_ref(),
                            )
                            .await?,
                    );
                }
                if renewal
                    .as_ref()
                    .is_some_and(|schedule| schedule.renewal_due(now))
                {
                    self.issue_bundle(
                        &registration,
                        previous.certificate.generation.saturating_add(1),
                        Some(&previous.certificate.certificate_chain_pem),
                    )
                    .await?
                } else {
                    (previous.certificate.clone(), renewal)
                }
            }
            Some(previous) => {
                let replacement = replacement_chain(previous, &registration);
                self.issue_bundle(
                    &registration,
                    previous.certificate.generation.saturating_add(1),
                    replacement,
                )
                .await?
            }
            None => self.issue_bundle(&registration, 1, None).await?,
        };

        let response_certificate = (registration.installed_generation
            != Some(certificate.generation))
        .then(|| certificate.clone());
        let stored = StoredNode {
            registration: registration.clone(),
            certificate,
            renewal,
        };
        self.persist_node(&stored).await?;
        self.nodes
            .write()
            .await
            .insert(registration.node_id.clone(), stored);

        if let Some(previous) = &old {
            let current = registration.hostnames.iter().collect::<BTreeSet<_>>();
            for old_name in &previous.registration.hostnames {
                if !current.contains(old_name)
                    && let Err(error) = self.cloudflare.delete_owned_a(old_name).await
                {
                    warn!(%old_name, %error, "failed to remove stale managed DNS record");
                }
            }
        }

        Ok(RegistrationResponse {
            certificate: response_certificate,
        })
    }

    async fn maintain_renewals(&self) {
        let _serial = self.reconcile.lock().await;
        let node_ids = self.nodes.read().await.keys().cloned().collect::<Vec<_>>();
        for node_id in node_ids {
            if let Err(error) = self.maintain_node_renewal(&node_id).await {
                warn!(%node_id, %error, "certificate renewal maintenance failed");
            }
        }
    }

    async fn maintain_node_renewal(&self, node_id: &str) -> Result<(), ControllerError> {
        let Some(mut stored) = self.nodes.read().await.get(node_id).cloned() else {
            return Ok(());
        };
        let now = unix_now();
        let schedule_refreshed = if stored
            .renewal
            .as_ref()
            .is_none_or(|schedule| schedule.ari_refresh_due(now))
        {
            stored.renewal = Some(
                self.issuer
                    .renewal_schedule(
                        &stored.certificate.certificate_chain_pem,
                        stored.renewal.as_ref(),
                    )
                    .await?,
            );
            true
        } else {
            false
        };

        let renewed = if stored
            .renewal
            .as_ref()
            .is_some_and(|schedule| schedule.renewal_due(now))
        {
            let generation = stored.certificate.generation.saturating_add(1);
            let old_chain = stored.certificate.certificate_chain_pem.clone();
            let (certificate, renewal) = self
                .issue_bundle(&stored.registration, generation, Some(&old_chain))
                .await?;
            info!(%node_id, generation, "renewed certificate while node may be offline");
            stored.certificate = certificate;
            stored.renewal = renewal;
            true
        } else {
            false
        };

        if schedule_refreshed || renewed {
            self.persist_node(&stored).await?;
            self.nodes.write().await.insert(node_id.to_owned(), stored);
        }
        Ok(())
    }

    async fn validate_registration_scope(
        &self,
        registration: &NodeRegistration,
    ) -> Result<(), ControllerError> {
        if !is_tailscale_ipv4(registration.tailscale_ip) {
            return Err(ControllerError::InvalidTailscaleIp(
                registration.tailscale_ip,
            ));
        }
        let suffix = format!(".{}", self.domain);
        for name in &registration.hostnames {
            let Some(prefix) = name.strip_suffix(&suffix) else {
                return Err(ControllerError::OutsideDomain(name.clone()));
            };
            if prefix.is_empty() || prefix.contains('.') {
                return Err(ControllerError::OutsideDomain(name.clone()));
            }
        }

        for (other_id, other) in self.nodes.read().await.iter() {
            if other_id == &registration.node_id {
                continue;
            }
            for name in &registration.hostnames {
                if other.registration.hostnames.contains(name) {
                    return Err(ControllerError::NameCollision {
                        name: name.clone(),
                        node_id: other_id.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    async fn issue_bundle(
        &self,
        registration: &NodeRegistration,
        generation: u64,
        replaces_certificate_chain_pem: Option<&str>,
    ) -> Result<(CertificateBundle, Option<RenewalSchedule>), ControllerError> {
        info!(
            node_id = %registration.node_id,
            names = registration.hostnames.len(),
            generation,
            "issuing certificate"
        );
        let certificate_chain_pem = self
            .issuer
            .issue(registration, replaces_certificate_chain_pem)
            .await?;
        let renewal = Some(
            self.issuer
                .renewal_schedule(&certificate_chain_pem, None)
                .await?,
        );
        Ok((
            CertificateBundle {
                generation,
                hostnames: registration.hostnames.clone(),
                certificate_chain_pem,
            },
            renewal,
        ))
    }

    async fn persist_node(&self, node: &StoredNode) -> Result<(), ControllerError> {
        let filename = format!("{}.json", encoded_node_id(&node.registration.node_id));
        let path = self.nodes_dir.join(filename);
        let temporary = path.with_extension("json.tmp");
        fs::write(&temporary, serde_json::to_vec_pretty(node)?).await?;
        fs::rename(temporary, path).await?;
        Ok(())
    }
}

fn replacement_chain<'a>(
    previous: &'a StoredNode,
    registration: &NodeRegistration,
) -> Option<&'a str> {
    previous
        .registration
        .hostnames
        .iter()
        .any(|name| registration.hostnames.contains(name))
        .then_some(previous.certificate.certificate_chain_pem.as_str())
}

fn encoded_node_id(node_id: &str) -> String {
    let mut result = String::with_capacity(node_id.len());
    for byte in node_id.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') {
            result.push(char::from(byte));
        } else {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            result.push('%');
            result.push(char::from(HEX[usize::from(byte >> 4)]));
            result.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    result
}

fn is_tailscale_ipv4(ip: IpAddr) -> bool {
    let IpAddr::V4(ip) = ip else {
        return false;
    };
    let octets = ip.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn recognizes_tailscale_range() {
        assert!(is_tailscale_ipv4(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(is_tailscale_ipv4(IpAddr::V4(Ipv4Addr::new(
            100, 127, 255, 254
        ))));
        assert!(!is_tailscale_ipv4(IpAddr::V4(Ipv4Addr::new(
            100, 128, 0, 1
        ))));
    }

    #[test]
    fn encodes_node_ids_without_path_separators() {
        assert_eq!(encoded_node_id("foo/bar"), "foo%2Fbar");
        assert_eq!(encoded_node_id("sf314-42"), "sf314-42");
    }
}

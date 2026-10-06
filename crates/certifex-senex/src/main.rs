mod acme;
mod cloudflare;

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use acme::{AcmeError, AcmeIssuer};
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
    let controller = Controller::load(args.domain, args.state_dir, cloudflare, issuer).await?;
    let state = AppState {
        controller: Arc::new(controller),
    };

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
        if let Some(previous) = &old {
            let current = registration.hostnames.iter().collect::<BTreeSet<_>>();
            for old_name in &previous.registration.hostnames {
                if !current.contains(old_name) {
                    self.cloudflare.delete_owned_a(old_name).await?;
                }
            }
        }

        let certificate = if let Some(previous) = &old {
            if previous.certificate.hostnames == registration.hostnames {
                previous.certificate.clone()
            } else {
                self.issue_bundle(
                    &registration,
                    previous.certificate.generation.saturating_add(1),
                )
                .await?
            }
        } else {
            self.issue_bundle(&registration, 1).await?
        };

        let response_certificate = (registration.installed_generation
            != Some(certificate.generation))
        .then(|| certificate.clone());
        let stored = StoredNode {
            registration: registration.clone(),
            certificate,
        };
        self.persist_node(&stored).await?;
        self.nodes
            .write()
            .await
            .insert(registration.node_id.clone(), stored);

        Ok(RegistrationResponse {
            certificate: response_certificate,
        })
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
    ) -> Result<CertificateBundle, ControllerError> {
        info!(
            node_id = %registration.node_id,
            names = registration.hostnames.len(),
            generation,
            "issuing certificate"
        );
        let certificate_chain_pem = self.issuer.issue(registration).await?;
        Ok(CertificateBundle {
            generation,
            hostnames: registration.hostnames.clone(),
            certificate_chain_pem,
        })
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

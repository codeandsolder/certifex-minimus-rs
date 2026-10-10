mod acme;
mod cloudflare;
mod telemetry;

use std::{
    collections::{BTreeMap, BTreeSet},
    env, io,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use acme::{AcmeError, AcmeIssuer, RenewalSchedule};
use axum::{
    Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, State},
    http::StatusCode,
    routing::{get, post},
};
use certifex_core::{
    CertificateBundle, IdentityError, NodeRegistration, REGISTRAR_PORT, RegistrationResponse,
    canonical_domain, csr_public_key_spki_der, registrar_hostname,
};
use clap::Parser;
use cloudflare::{Cloudflare, CloudflareError};
use serde::{Deserialize, Serialize};
use telemetry::Telemetry;
use thiserror::Error;
use tokio::{
    fs,
    io::AsyncWriteExt,
    sync::{Mutex, RwLock},
    time::{MissedTickBehavior, interval},
};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
const MAX_REGISTRATION_BODY_BYTES: usize = 256 * 1024;
const RENEWAL_FAILURE_BACKOFF_SECONDS: i64 = 6 * 60 * 60;

#[derive(Debug, Parser)]
#[command(version, about = "Certifex registrar and certificate control plane")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:7443")]
    listen: SocketAddr,

    #[arg(long)]
    domain: String,

    #[arg(long)]
    cloudflare_token_file: Option<PathBuf>,

    #[arg(long)]
    cloudflare_token_json_file: Option<PathBuf>,

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

    #[arg(long)]
    metrics_endpoint: Option<String>,

    #[arg(long)]
    metrics_instance: Option<String>,

    #[arg(long, default_value = "/var/lib/certifex-minimus/metrics-senex")]
    metrics_spool_dir: PathBuf,
}

#[derive(Clone)]
struct AppState {
    controller: Arc<Controller>,
}

struct Controller {
    domain: String,
    registrar_hostname: String,
    telemetry: Telemetry,
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
    #[error("hostname `{0}` is not below the configured domain")]
    OutsideDomain(String),
    #[error("hostname `{0}` is reserved for the Certifex registrar")]
    ReservedHostname(String),
    #[error("hostname `{name}` is already owned by node `{node_id}`")]
    NameCollision { name: String, node_id: String },
    #[error("claimed address is not a Tailscale IPv4 address: {0}")]
    InvalidTailscaleIp(IpAddr),
    #[error("node_id `{0}` is already bound to a different node key")]
    NodeKeyMismatch(String),
    #[error("stored node identity is invalid: {0}")]
    Identity(#[from] IdentityError),
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
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| std::io::Error::other("failed to install Ring as rustls crypto provider"))?;
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let domain = canonical_domain(&args.domain)?;
    let registrar_name = registrar_hostname(&domain)?;
    let registrar_ip = registrar_publish_ip(args.listen)?;
    let metrics_instance = args
        .metrics_instance
        .clone()
        .or_else(|| env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "unknown".to_string());
    let telemetry = Telemetry::new(
        args.metrics_endpoint.as_deref(),
        &metrics_instance,
        &args.metrics_spool_dir,
    )?;
    let token = load_cloudflare_token(&args)?;
    let client = reqwest::Client::builder().build()?;
    let cloudflare = Cloudflare::for_zone(client, token, &domain).await?;
    if let Some(ip) = registrar_ip {
        cloudflare.ensure_a(&registrar_name, ip).await?;
        info!(hostname = %registrar_name, %ip, "published registrar DNS record");
    }
    let issuer = AcmeIssuer::load_or_create(
        cloudflare.clone(),
        &args.state_dir,
        &args.acme_directory,
        args.acme_email.as_deref(),
        Duration::from_secs(args.dns_propagation_seconds),
    )
    .await?;
    let controller = Arc::new(
        Controller::load(
            domain,
            registrar_name,
            args.state_dir,
            cloudflare,
            issuer,
            telemetry,
        )
        .await?,
    );
    let state = AppState {
        controller: controller.clone(),
    };
    let _renewal_task = tokio::spawn(renewal_loop(
        controller,
        Duration::from_secs(args.renewal_check_seconds.max(1)),
    ));

    let app = Router::new()
        .route("/healthz", get(health))
        .route(
            "/v1/register",
            post(register).layer(DefaultBodyLimit::max(MAX_REGISTRATION_BODY_BYTES)),
        )
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

fn load_cloudflare_token(args: &Args) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(path) = &args.cloudflare_token_file {
        return Ok(normalize_secret(
            &std::fs::read_to_string(path)?,
            &format!("Cloudflare token file `{}`", path.display()),
        )?);
    }
    if let Some(path) = &args.cloudflare_token_json_file {
        return Ok(parse_cloudflare_token_json(
            &std::fs::read_to_string(path)?,
            &format!("Cloudflare token JSON file `{}`", path.display()),
        )?);
    }

    if let Some(credentials_dir) = env::var_os("CREDENTIALS_DIRECTORY") {
        let credentials_dir = PathBuf::from(credentials_dir);
        let path = credentials_dir.join("cloudflare-token");
        if path.is_file() {
            return Ok(normalize_secret(
                &std::fs::read_to_string(&path)?,
                &format!("systemd credential `{}`", path.display()),
            )?);
        }
        let path = credentials_dir.join("cloudflare-token-json");
        if path.is_file() {
            return Ok(parse_cloudflare_token_json(
                &std::fs::read_to_string(&path)?,
                &format!("systemd credential `{}`", path.display()),
            )?);
        }
    }

    let token = env::var(&args.cloudflare_token_env).map_err(|_| {
        format!(
            "no Cloudflare token found: pass --cloudflare-token-file/--cloudflare-token-json-file, provide systemd credential `cloudflare-token`/`cloudflare-token-json`, or set `{}`",
            args.cloudflare_token_env
        )
    })?;
    Ok(normalize_secret(
        &token,
        &format!("environment variable `{}`", args.cloudflare_token_env),
    )?)
}

fn parse_cloudflare_token_json(value: &str, source: &str) -> Result<String, std::io::Error> {
    let document: serde_json::Value = serde_json::from_str(value).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{source} is not valid JSON: {error}"),
        )
    })?;
    let token = document
        .get("value")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{source} does not contain a string `value` field"),
            )
        })?;
    normalize_secret(token, source)
}

fn normalize_secret(value: &str, source: &str) -> Result<String, std::io::Error> {
    let value = value.trim();
    if value.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{source} is empty"),
        ));
    }
    Ok(value.to_owned())
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
        state.controller.telemetry.registration_failed();
        warn!(node_id = %registration.node_id, %error, "rejected registration");
        return Err((StatusCode::BAD_REQUEST, error.to_string()));
    }
    if !peer.ip().is_loopback() && peer.ip() != registration.tailscale_ip {
        state.controller.telemetry.registration_failed();
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
            state.controller.telemetry.registration_ok();
            info!(%node_id, "node reconciliation complete");
            Ok(Json(response))
        }
        Err(
            error @ (ControllerError::OutsideDomain(_)
            | ControllerError::ReservedHostname(_)
            | ControllerError::NameCollision { .. }
            | ControllerError::InvalidTailscaleIp(_)
            | ControllerError::NodeKeyMismatch(_)),
        ) => {
            state.controller.telemetry.registration_failed();
            warn!(%node_id, %error, "rejected registration");
            Err((StatusCode::CONFLICT, error.to_string()))
        }
        Err(error) => {
            state.controller.telemetry.registration_failed();
            warn!(%node_id, %error, "registration reconciliation failed");
            Err((StatusCode::BAD_GATEWAY, error.to_string()))
        }
    }
}

impl Controller {
    async fn load(
        domain: String,
        registrar_hostname: String,
        state_dir: PathBuf,
        cloudflare: Cloudflare,
        issuer: AcmeIssuer,
        telemetry: Telemetry,
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
            registrar_hostname,
            telemetry,
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
        if registration.hostnames.is_empty() {
            return self.deregister_node(&registration, old.as_ref()).await;
        }

        self.reconcile_dns(&registration, old.as_ref()).await?;
        let (certificate, renewal) = self
            .certificate_for_registration(&registration, old.as_ref())
            .await?;
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
            .insert(registration.node_id.clone(), stored.clone());
        self.telemetry.node_state(
            &registration.node_id,
            stored.certificate.generation,
            stored.renewal.as_ref().map(|schedule| schedule.renew_after),
            stored
                .renewal
                .as_ref()
                .and_then(|schedule| schedule.ari_check_after),
        );

        Ok(RegistrationResponse {
            certificate: response_certificate,
        })
    }

    async fn deregister_node(
        &self,
        registration: &NodeRegistration,
        previous: Option<&StoredNode>,
    ) -> Result<RegistrationResponse, ControllerError> {
        if let Some(previous) = previous {
            for old_name in &previous.registration.hostnames {
                self.cloudflare.delete_owned_a(old_name).await?;
            }
            let tombstone = deregistration_tombstone(registration, previous);
            self.persist_node(&tombstone).await?;
            self.nodes
                .write()
                .await
                .insert(registration.node_id.clone(), tombstone);
            info!(
                node_id = %registration.node_id,
                generation = previous.certificate.generation,
                "node relinquished its final managed hostname"
            );
        }
        Ok(RegistrationResponse { certificate: None })
    }

    async fn reconcile_dns(
        &self,
        registration: &NodeRegistration,
        previous: Option<&StoredNode>,
    ) -> Result<(), ControllerError> {
        for name in &registration.hostnames {
            self.cloudflare
                .ensure_a(name, registration.tailscale_ip)
                .await?;
        }
        if let Some(previous) = previous {
            let current = registration.hostnames.iter().collect::<BTreeSet<_>>();
            for old_name in &previous.registration.hostnames {
                if !current.contains(old_name) {
                    self.cloudflare.delete_owned_a(old_name).await?;
                }
            }
        }
        Ok(())
    }

    async fn certificate_for_registration(
        &self,
        registration: &NodeRegistration,
        previous: Option<&StoredNode>,
    ) -> Result<(CertificateBundle, Option<RenewalSchedule>), ControllerError> {
        let same_key = previous
            .map(|previous| {
                same_csr_public_key(&previous.registration.csr_pem, &registration.csr_pem)
            })
            .transpose()?
            .unwrap_or(false);
        match previous {
            Some(previous)
                if previous.certificate.hostnames == registration.hostnames && same_key =>
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
                // Registration is a reconciliation path, not the renewal scheduler.
                // Retrying a due renewal here couples the node retry cadence (30s by default)
                // to ACME issuance and can hammer the CA after a terminal/rate-limit error.
                // The registrar's maintenance loop owns renewal attempts.
                Ok((previous.certificate.clone(), renewal))
            }
            Some(previous) => {
                let replacement = replacement_chain(previous, registration);
                self.issue_bundle(
                    registration,
                    previous.certificate.generation.saturating_add(1),
                    replacement,
                )
                .await
            }
            None => self.issue_bundle(registration, 1, None).await,
        }
    }

    async fn maintain_renewals(&self) {
        let _serial = self.reconcile.lock().await;
        let node_ids = self.nodes.read().await.keys().cloned().collect::<Vec<_>>();
        for node_id in node_ids {
            if let Err(error) = self.maintain_node_renewal(&node_id).await {
                self.telemetry.renewal_failed();
                warn!(%node_id, %error, "certificate renewal maintenance failed");
            }
        }
    }

    async fn maintain_node_renewal(&self, node_id: &str) -> Result<(), ControllerError> {
        let Some(mut stored) = self.nodes.read().await.get(node_id).cloned() else {
            return Ok(());
        };
        if stored.registration.hostnames.is_empty() {
            return Ok(());
        }
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
            match self
                .issue_bundle(&stored.registration, generation, Some(&old_chain))
                .await
            {
                Ok((certificate, renewal)) => {
                    info!(%node_id, generation, "renewed certificate while node may be offline");
                    stored.certificate = certificate;
                    stored.renewal = renewal;
                    true
                }
                Err(error) => {
                    if let Some(schedule) = stored.renewal.as_mut() {
                        defer_renewal_after_failure(schedule, now);
                        let renew_after = schedule.renew_after;
                        let ari_check_after = schedule.ari_check_after;
                        self.persist_node(&stored).await?;
                        self.telemetry.node_state(
                            node_id,
                            stored.certificate.generation,
                            Some(renew_after),
                            ari_check_after,
                        );
                        self.nodes.write().await.insert(node_id.to_owned(), stored);
                    }
                    return Err(error);
                }
            }
        } else {
            false
        };

        if schedule_refreshed || renewed {
            self.persist_node(&stored).await?;
            self.telemetry.node_state(
                node_id,
                stored.certificate.generation,
                stored.renewal.as_ref().map(|schedule| schedule.renew_after),
                stored
                    .renewal
                    .as_ref()
                    .and_then(|schedule| schedule.ari_check_after),
            );
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
        for name in &registration.hostnames {
            if !is_domain_descendant(name, &self.domain) {
                return Err(ControllerError::OutsideDomain(name.clone()));
            }
            if name == &self.registrar_hostname {
                return Err(ControllerError::ReservedHostname(name.clone()));
            }
        }

        let nodes = self.nodes.read().await;
        if let Some(previous) = nodes.get(&registration.node_id)
            && !registration_identity_allowed(&previous.registration, registration)?
        {
            return Err(ControllerError::NodeKeyMismatch(
                registration.node_id.clone(),
            ));
        }
        for (other_id, other) in nodes.iter() {
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
        drop(nodes);
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
        self.telemetry.certificate_issued();
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
        durable_replace(&path, &serde_json::to_vec_pretty(node)?).await?;
        Ok(())
    }
}

async fn durable_replace(path: &std::path::Path, contents: &[u8]) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "state path has no parent directory",
        )
    })?;
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "state path has no UTF-8 filename",
            )
        })?;
    let temporary = parent.join(format!(".{filename}.{:016x}.tmp", fastrand::u64(..)));

    let result = async {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .await?;
        file.write_all(contents).await?;
        file.sync_all().await?;
        drop(file);
        fs::rename(&temporary, path).await?;
        fs::File::open(parent).await?.sync_all().await
    }
    .await;
    if result.is_err() {
        let _ = fs::remove_file(&temporary).await;
    }
    result
}

fn deregistration_tombstone(registration: &NodeRegistration, previous: &StoredNode) -> StoredNode {
    StoredNode {
        registration: registration.clone(),
        certificate: previous.certificate.clone(),
        renewal: None,
    }
}

fn same_csr_public_key(left: &str, right: &str) -> Result<bool, IdentityError> {
    Ok(csr_public_key_spki_der(left)? == csr_public_key_spki_der(right)?)
}

fn registration_identity_allowed(
    previous: &NodeRegistration,
    registration: &NodeRegistration,
) -> Result<bool, IdentityError> {
    if previous.hostnames.is_empty() {
        return Ok(true);
    }
    same_csr_public_key(&previous.csr_pem, &registration.csr_pem)
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

fn defer_renewal_after_failure(schedule: &mut RenewalSchedule, now: i64) {
    let retry_at = now.saturating_add(RENEWAL_FAILURE_BACKOFF_SECONDS);
    schedule.renew_after = schedule.renew_after.max(retry_at);
    schedule.ari_check_after = Some(
        schedule
            .ari_check_after
            .map_or(retry_at, |deadline| deadline.max(retry_at)),
    );
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

fn is_domain_descendant(name: &str, domain: &str) -> bool {
    name.strip_suffix(domain)
        .is_some_and(|prefix| !prefix.is_empty() && prefix.ends_with('.'))
}

fn is_tailscale_ipv4(ip: IpAddr) -> bool {
    let IpAddr::V4(ip) = ip else {
        return false;
    };
    let octets = ip.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

fn registrar_publish_ip(listen: SocketAddr) -> io::Result<Option<IpAddr>> {
    let ip = listen.ip();
    if ip.is_loopback() {
        return Ok(None);
    }
    if is_tailscale_ipv4(ip) {
        if listen.port() != REGISTRAR_PORT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("tailnet registrar must listen on port {REGISTRAR_PORT}"),
            ));
        }
        return Ok(Some(ip));
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("registrar listen address must be loopback or Tailscale IPv4, got {ip}"),
    ))
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

    use certifex_core::NodeIdentity;

    use super::*;

    #[test]
    fn node_key_continuity_is_required_until_relinquished() -> Result<(), Box<dyn std::error::Error>>
    {
        let identity = NodeIdentity::generate()?;
        let replacement_identity = NodeIdentity::generate()?;
        let registration = |csr_pem| NodeRegistration {
            node_id: "node".to_owned(),
            tailscale_ip: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
            hostnames: vec!["one.example.com".to_owned()],
            csr_pem,
            installed_generation: None,
        };
        let previous = registration(identity.csr_pem(&["one.example.com".to_owned()])?);
        let same_key = registration(identity.csr_pem(&["two.example.com".to_owned()])?);
        let new_key = registration(replacement_identity.csr_pem(&["one.example.com".to_owned()])?);

        assert!(registration_identity_allowed(&previous, &same_key)?);
        assert!(!registration_identity_allowed(&previous, &new_key)?);

        let mut relinquished = previous;
        relinquished.hostnames.clear();
        assert!(registration_identity_allowed(&relinquished, &new_key)?);
        Ok(())
    }

    #[test]
    fn certificate_identity_uses_public_key_not_csr_bytes() -> Result<(), Box<dyn std::error::Error>>
    {
        let identity = NodeIdentity::generate()?;
        let other_identity = NodeIdentity::generate()?;
        let names = vec!["one.example.com".to_owned()];
        let first = identity.csr_pem(&names)?;
        let second = identity.csr_pem(&names)?;
        let other = other_identity.csr_pem(&names)?;

        assert!(same_csr_public_key(&first, &second)?);
        assert!(!same_csr_public_key(&first, &other)?);
        Ok(())
    }

    #[test]
    fn deregistration_tombstone_releases_names_but_preserves_generation()
    -> Result<(), Box<dyn std::error::Error>> {
        let identity = NodeIdentity::generate()?;
        let previous = StoredNode {
            registration: NodeRegistration {
                node_id: "node".to_owned(),
                tailscale_ip: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
                hostnames: vec!["one.example.com".to_owned()],
                csr_pem: identity.csr_pem(&["one.example.com".to_owned()])?,
                installed_generation: Some(41),
            },
            certificate: CertificateBundle {
                generation: 41,
                hostnames: vec!["one.example.com".to_owned()],
                certificate_chain_pem: "certificate".to_owned(),
            },
            renewal: Some(RenewalSchedule {
                renew_after: 123,
                ari_check_after: Some(456),
                ari_window_start: None,
                ari_window_end: None,
            }),
        };
        let replacement_identity = NodeIdentity::generate()?;
        let deregistration = NodeRegistration {
            node_id: "node".to_owned(),
            tailscale_ip: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
            hostnames: Vec::new(),
            csr_pem: replacement_identity.csr_pem(&[])?,
            installed_generation: Some(41),
        };

        let tombstone = deregistration_tombstone(&deregistration, &previous);

        assert_eq!(tombstone.registration.hostnames, Vec::<String>::new());
        assert_eq!(tombstone.certificate.generation, 41);
        assert_eq!(tombstone.certificate.hostnames, vec!["one.example.com"]);
        assert!(tombstone.renewal.is_none());
        Ok(())
    }

    #[test]
    fn failed_renewal_defers_both_issue_and_ari_retry() {
        let now = 1_000_000;
        let mut schedule = RenewalSchedule {
            renew_after: now - 1,
            ari_check_after: Some(now - 10),
            ari_window_start: Some(now - 100),
            ari_window_end: Some(now + 100),
        };

        defer_renewal_after_failure(&mut schedule, now);

        let retry_at = now + RENEWAL_FAILURE_BACKOFF_SECONDS;
        assert_eq!(schedule.renew_after, retry_at);
        assert_eq!(schedule.ari_check_after, Some(retry_at));
        assert!(!schedule.renewal_due(retry_at - 1));
        assert!(schedule.renewal_due(retry_at));
    }

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
    fn trims_and_rejects_empty_secrets() {
        assert_eq!(
            normalize_secret("  token\n", "test").ok().as_deref(),
            Some("token")
        );
        assert!(normalize_secret(" \n\t", "test").is_err());
    }

    #[tokio::test]
    async fn durable_replace_replaces_state_without_leaving_temp_files() -> io::Result<()> {
        let directory = std::env::temp_dir().join(format!(
            "certifex-registrar-state-{:016x}",
            fastrand::u64(..)
        ));
        fs::create_dir_all(&directory).await?;
        let path = directory.join("node.json");

        durable_replace(&path, b"one").await?;
        durable_replace(&path, b"two").await?;
        assert_eq!(fs::read(&path).await?, b"two");
        let mut entries = fs::read_dir(&directory).await?;
        let mut count = 0;
        while entries.next_entry().await?.is_some() {
            count += 1;
        }
        assert_eq!(count, 1);

        fs::remove_dir_all(directory).await
    }

    #[test]
    fn encodes_node_ids_without_path_separators() {
        assert_eq!(encoded_node_id("foo/bar"), "foo%2Fbar");
        assert_eq!(encoded_node_id("sf314-42"), "sf314-42");
    }
    #[test]
    fn registrar_publish_address_is_tailnet_only() -> io::Result<()> {
        assert_eq!(
            registrar_publish_ip(SocketAddr::from(([100, 118, 45, 4], 7443)))?,
            Some(IpAddr::from([100, 118, 45, 4]))
        );
        assert_eq!(
            registrar_publish_ip(SocketAddr::from(([127, 0, 0, 1], 7443)))?,
            None
        );
        assert!(registrar_publish_ip(SocketAddr::from(([100, 118, 45, 4], 7444))).is_err());
        assert!(registrar_publish_ip(SocketAddr::from(([0, 0, 0, 0], 7443))).is_err());
        assert!(registrar_publish_ip(SocketAddr::from(([192, 168, 1, 2], 7443))).is_err());
        Ok(())
    }

    #[test]
    fn accepts_descendants_but_not_apex_or_lookalikes() {
        assert!(is_domain_descendant("grafana.onhir.eu", "onhir.eu"));
        assert!(is_domain_descendant("exits.waw.onhir.eu", "onhir.eu"));
        assert!(!is_domain_descendant("onhir.eu", "onhir.eu"));
        assert!(!is_domain_descendant("evilonhir.eu", "onhir.eu"));
        assert!(!is_domain_descendant("onhir.eu.example", "onhir.eu"));
    }
    #[test]
    fn parses_cloudflare_cli_token_json() {
        assert_eq!(
            parse_cloudflare_token_json(r#"{"id":"abc","value":"token-value"}"#, "test")
                .ok()
                .as_deref(),
            Some("token-value")
        );
        assert!(parse_cloudflare_token_json(r#"{"id":"abc"}"#, "test").is_err());
        assert!(parse_cloudflare_token_json("not-json", "test").is_err());
    }
}

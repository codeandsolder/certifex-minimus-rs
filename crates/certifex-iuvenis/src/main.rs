mod certificate;
mod proxy;
mod telemetry;

use std::{
    fs, io,
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    time::Duration,
};

use certifex_core::{
    CertificateBundle, NodeConfig, NodeIdentity, NodeRegistration, RegistrationResponse,
};
use clap::Parser;
use proxy::ProxyState;
use reqwest::Client;
use telemetry::Telemetry;
use tokio::time::{Instant, sleep};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(version, about = "Certifex node agent and HTTPS ingress")]
struct Args {
    #[arg(long, default_value = "/etc/certifex-minimus/node.toml")]
    config: PathBuf,

    #[arg(long, default_value = "/var/lib/certifex-minimus")]
    state_dir: PathBuf,

    #[arg(long, default_value_t = 443)]
    https_port: u16,

    #[arg(long, default_value_t = 21_600)]
    poll_seconds: u64,

    #[arg(long, default_value_t = 30)]
    retry_seconds: u64,

    #[arg(long, default_value_t = 2)]
    config_check_seconds: u64,

    #[arg(long)]
    once: bool,

    #[arg(long)]
    metrics_endpoint: Option<String>,

    #[arg(long)]
    metrics_instance: Option<String>,

    #[arg(long, default_value = "/var/lib/certifex-minimus/metrics-iuvenis")]
    metrics_spool_dir: PathBuf,
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
    let metrics_instance = args
        .metrics_instance
        .clone()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "unknown".to_string());
    let telemetry = Telemetry::new(
        args.metrics_endpoint.as_deref(),
        &metrics_instance,
        &args.metrics_spool_dir,
    )?;
    let client = Client::builder().build()?;
    let proxy = ProxyState::new(telemetry.clone());
    prepare_proxy(&args, &proxy).await?;
    let tailscale_ip = detect_tailscale_ip()?;

    if args.once {
        match reconcile(&client, &args, &proxy, tailscale_ip).await {
            Ok(_) => telemetry.reconcile_ok(),
            Err(error) => {
                telemetry.reconcile_failed();
                return Err(error);
            }
        }
        return Ok(());
    }

    let proxy_task = proxy.clone().serve(tailscale_ip, args.https_port);
    let reconciliation_task =
        reconciliation_loop(&client, &args, &proxy, tailscale_ip, telemetry.clone());
    tokio::pin!(proxy_task);
    tokio::pin!(reconciliation_task);

    tokio::select! {
        result = &mut proxy_task => result.map_err(Into::into),
        result = &mut reconciliation_task => result,
    }
}

async fn reconciliation_loop(
    client: &Client,
    args: &Args,
    proxy: &ProxyState,
    bound_tailscale_ip: IpAddr,
    telemetry: Telemetry,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut baseline = fs::read(&args.config).unwrap_or_default();
    loop {
        if let Ok(current_ip) = detect_tailscale_ip()
            && current_ip != bound_tailscale_ip
        {
            return Err(tailscale_ip_changed(bound_tailscale_ip, current_ip).into());
        }
        let delay = match reconcile(client, args, proxy, bound_tailscale_ip).await {
            Ok(config_bytes) => {
                telemetry.reconcile_ok();
                baseline = config_bytes;
                Duration::from_secs(args.poll_seconds.saturating_add(fastrand::u64(0..=900)))
            }
            Err(error) => {
                telemetry.reconcile_failed();
                warn!(%error, "registration failed; retrying");
                Duration::from_secs(args.retry_seconds.saturating_add(fastrand::u64(0..=15)))
            }
        };
        wait_for_reconcile_trigger(
            &args.config,
            &baseline,
            delay,
            args.config_check_seconds,
            bound_tailscale_ip,
        )
        .await;
    }
}

async fn prepare_proxy(args: &Args, proxy: &ProxyState) -> Result<(), Box<dyn std::error::Error>> {
    let config: NodeConfig = toml::from_str(&fs::read_to_string(&args.config)?)?;
    proxy.set_routes(&config).await?;
    fs::create_dir_all(&args.state_dir)?;
    let key_path = args.state_dir.join("node-key.pem");
    let _identity = load_or_create_identity(&key_path)?;
    if args.state_dir.join("certificate.pem").exists() {
        match proxy.reload_tls(&args.state_dir) {
            Ok(()) => info!("loaded previously installed TLS certificate"),
            Err(error) => {
                warn!(%error, "installed TLS state is unusable; registration will repair it");
            }
        }
    }
    Ok(())
}

async fn reconcile(
    client: &Client,
    args: &Args,
    proxy: &ProxyState,
    tailscale_ip: IpAddr,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let config_bytes = fs::read(&args.config)?;
    let config: NodeConfig = toml::from_str(std::str::from_utf8(&config_bytes)?)?;
    let hostnames = config.hostnames()?;
    proxy.set_routes(&config).await?;
    fs::create_dir_all(&args.state_dir)?;

    let key_path = args.state_dir.join("node-key.pem");
    let generation_path = args.state_dir.join("certificate-generation");
    let identity = load_or_create_identity(&key_path)?;
    let csr_pem = identity.csr_pem(&hostnames)?;
    let installed_generation = if proxy.has_tls()? {
        read_generation(&generation_path)?
    } else {
        None
    };
    let registration = NodeRegistration {
        node_id: config.node_id.clone(),
        tailscale_ip,
        hostnames,
        csr_pem,
        installed_generation,
    };

    let endpoint = format!("{}/v1/register", config.registrar_url()?);
    let response = client
        .post(endpoint)
        .json(&registration)
        .send()
        .await?
        .error_for_status()?
        .json::<RegistrationResponse>()
        .await?;

    if registration.hostnames.is_empty() {
        proxy.clear_tls()?;
        clear_certificate_state(&args.state_dir)?;
        info!(
            node_id = %config.node_id,
            "registration relinquished all hostnames and disabled TLS ingress"
        );
    } else if let Some(certificate) = response.certificate {
        if installed_generation.is_some_and(|generation| certificate.generation < generation) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "registrar attempted certificate generation rollback",
            )
            .into());
        }
        certificate::validate_bundle(&certificate, &registration.hostnames, &identity)?;
        install_certificate(&args.state_dir, &certificate)?;
        proxy.reload_tls(&args.state_dir)?;
        proxy
            .telemetry()
            .certificate_installed(certificate.generation);
        info!(
            node_id = %config.node_id,
            generation = certificate.generation,
            "validated, installed, and activated certificate generation"
        );
    } else {
        info!(
            node_id = %config.node_id,
            tailscale_ip = %registration.tailscale_ip,
            names = registration.hostnames.len(),
            installed_generation = ?installed_generation,
            "registration reconciled"
        );
    }
    Ok(config_bytes)
}

async fn wait_for_reconcile_trigger(
    path: &Path,
    baseline: &[u8],
    timeout: Duration,
    check_seconds: u64,
    bound_tailscale_ip: IpAddr,
) {
    let deadline = Instant::now() + timeout;
    let check = Duration::from_secs(check_seconds.max(1));
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return;
        }
        sleep(check.min(remaining)).await;
        match fs::read(path) {
            Ok(current) if current == baseline => {}
            _ => return,
        }
        if detect_tailscale_ip().is_ok_and(|current_ip| current_ip != bound_tailscale_ip) {
            return;
        }
    }
}

fn tailscale_ip_changed(bound: IpAddr, current: IpAddr) -> io::Error {
    io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        format!(
            "Tailscale IPv4 changed from {bound} to {current}; restart required to rebind HTTPS"
        ),
    )
}

fn load_or_create_identity(path: &Path) -> Result<NodeIdentity, Box<dyn std::error::Error>> {
    if path.exists() {
        return Ok(NodeIdentity::from_private_key_pem(&fs::read_to_string(
            path,
        )?)?);
    }

    let identity = NodeIdentity::generate()?;
    write_private_key(path, &identity.private_key_pem())?;
    Ok(identity)
}

fn read_generation(path: &Path) -> io::Result<Option<u64>> {
    if !path.exists() {
        return Ok(None);
    }
    let value = fs::read_to_string(path)?;
    value
        .trim()
        .parse::<u64>()
        .map(Some)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn install_certificate(state_dir: &Path, certificate: &CertificateBundle) -> io::Result<()> {
    atomic_write(
        &state_dir.join("certificate.pem"),
        certificate.certificate_chain_pem.as_bytes(),
    )?;
    atomic_write(
        &state_dir.join("certificate-generation"),
        certificate.generation.to_string().as_bytes(),
    )
}

fn clear_certificate_state(state_dir: &Path) -> io::Result<()> {
    for filename in ["certificate-generation", "certificate.pem"] {
        match fs::remove_file(state_dir.join(filename)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    sync_directory(state_dir)
}

fn atomic_write(path: &Path, contents: &[u8]) -> io::Result<()> {
    use std::io::Write;

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

    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn sync_directory(path: &Path) -> io::Result<()> {
    fs::File::open(path)?.sync_all()
}

fn detect_tailscale_ip() -> io::Result<IpAddr> {
    let mut fallback = Vec::new();

    for interface in if_addrs::get_if_addrs()? {
        if !interface.is_oper_up() {
            continue;
        }
        let IpAddr::V4(ip) = interface.ip() else {
            continue;
        };
        if !is_tailscale_ipv4(ip) {
            continue;
        }
        if interface.name.to_ascii_lowercase().contains("tailscale") {
            return Ok(IpAddr::V4(ip));
        }
        fallback.push(ip);
    }

    fallback.sort_unstable();
    fallback.dedup();
    match fallback.as_slice() {
        [ip] => Ok(IpAddr::V4(*ip)),
        [] => Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no Tailscale IPv4 address found",
        )),
        _ => Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "multiple CGNAT IPv4 addresses found without an identifiable Tailscale interface",
        )),
    }
}

fn is_tailscale_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

#[cfg(unix)]
fn write_private_key(path: &Path, pem: &str) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "private key path has no parent directory",
        )
    })?;
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "private key path has no UTF-8 filename",
            )
        })?;
    let temporary = parent.join(format!(".{filename}.{:016x}.tmp", fastrand::u64(..)));

    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = options.open(&temporary)?;
        file.write_all(pem.as_bytes())?;
        file.sync_all()?;
        drop(file);
        fs::hard_link(&temporary, path)?;
        fs::remove_file(&temporary)?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(not(unix))]
fn write_private_key(path: &Path, pem: &str) -> io::Result<()> {
    fs::write(path, pem)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_replaces_state_without_leaving_temp_files() -> io::Result<()> {
        let directory =
            std::env::temp_dir().join(format!("certifex-node-state-{:016x}", fastrand::u64(..)));
        fs::create_dir_all(&directory)?;
        let path = directory.join("certificate-generation");

        atomic_write(&path, b"1")?;
        atomic_write(&path, b"2")?;
        assert_eq!(fs::read(&path)?, b"2");
        assert_eq!(fs::read_dir(&directory)?.count(), 1);

        fs::remove_dir_all(directory)
    }

    #[test]
    fn clearing_certificate_state_preserves_node_identity() -> io::Result<()> {
        let directory =
            std::env::temp_dir().join(format!("certifex-node-clear-{:016x}", fastrand::u64(..)));
        fs::create_dir_all(&directory)?;
        fs::write(directory.join("certificate.pem"), b"certificate")?;
        fs::write(directory.join("certificate-generation"), b"17")?;
        fs::write(directory.join("node-key.pem"), b"private-key")?;

        clear_certificate_state(&directory)?;

        assert!(!directory.join("certificate.pem").exists());
        assert!(!directory.join("certificate-generation").exists());
        assert_eq!(fs::read(directory.join("node-key.pem"))?, b"private-key");
        fs::remove_dir_all(directory)
    }

    #[cfg(unix)]
    #[test]
    fn private_key_publish_is_atomic_and_does_not_overwrite() -> io::Result<()> {
        let directory =
            std::env::temp_dir().join(format!("certifex-key-publish-{:016x}", fastrand::u64(..)));
        fs::create_dir_all(&directory)?;
        let path = directory.join("node-key.pem");

        write_private_key(&path, "first")?;
        assert!(write_private_key(&path, "second").is_err());
        assert_eq!(fs::read_to_string(&path)?, "first");
        assert_eq!(fs::read_dir(&directory)?.count(), 1);

        fs::remove_dir_all(directory)
    }

    #[test]
    fn tailscale_ip_change_requests_rebind_restart() {
        let error =
            tailscale_ip_changed(IpAddr::from([100, 64, 0, 1]), IpAddr::from([100, 64, 0, 2]));
        assert_eq!(error.kind(), io::ErrorKind::AddrNotAvailable);
        assert!(error.to_string().contains("restart required"));
    }

    #[test]
    fn recognizes_tailscale_ipv4_range() {
        assert!(is_tailscale_ipv4(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(is_tailscale_ipv4(Ipv4Addr::new(100, 127, 255, 254)));
        assert!(!is_tailscale_ipv4(Ipv4Addr::new(100, 63, 255, 255)));
        assert!(!is_tailscale_ipv4(Ipv4Addr::new(100, 128, 0, 1)));
    }
}

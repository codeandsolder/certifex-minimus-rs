use std::{
    fs, io,
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    time::Duration,
};

use certifex_core::{NodeConfig, NodeIdentity, NodeRegistration, RegistrationResponse};
use clap::Parser;
use reqwest::Client;
use tokio::time::sleep;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(version, about = "Certifex node agent")]
struct Args {
    #[arg(long, default_value = "/etc/certifex-minimus/node.toml")]
    config: PathBuf,

    #[arg(long, default_value = "/var/lib/certifex-minimus")]
    state_dir: PathBuf,

    #[arg(long, default_value_t = 21_600)]
    poll_seconds: u64,

    #[arg(long, default_value_t = 30)]
    retry_seconds: u64,

    #[arg(long)]
    once: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let client = Client::builder().build()?;

    loop {
        match reconcile(&client, &args).await {
            Ok(()) => {
                if args.once {
                    return Ok(());
                }
                let jitter = fastrand::u64(0..=900);
                sleep(Duration::from_secs(
                    args.poll_seconds.saturating_add(jitter),
                ))
                .await;
            }
            Err(error) => {
                if args.once {
                    return Err(error);
                }
                warn!(%error, "registration failed; retrying");
                let jitter = fastrand::u64(0..=15);
                sleep(Duration::from_secs(
                    args.retry_seconds.saturating_add(jitter),
                ))
                .await;
            }
        }
    }
}

async fn reconcile(client: &Client, args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let config: NodeConfig = toml::from_str(&fs::read_to_string(&args.config)?)?;
    let hostnames = config.hostnames()?;
    fs::create_dir_all(&args.state_dir)?;

    let key_path = args.state_dir.join("node-key.pem");
    let identity = load_or_create_identity(&key_path)?;
    let csr_pem = identity.csr_pem(&hostnames)?;
    let registration = NodeRegistration {
        node_id: config.node_id.clone(),
        tailscale_ip: detect_tailscale_ip()?,
        hostnames,
        csr_pem,
        installed_generation: None,
    };

    let endpoint = format!("{}/v1/register", config.registrar.trim_end_matches('/'));
    let response = client
        .post(endpoint)
        .json(&registration)
        .send()
        .await?
        .error_for_status()?
        .json::<RegistrationResponse>()
        .await?;

    if let Some(certificate) = response.certificate {
        info!(
            node_id = %config.node_id,
            generation = certificate.generation,
            "registrar returned a certificate generation; installation is not enabled yet"
        );
    } else {
        info!(
            node_id = %config.node_id,
            tailscale_ip = %registration.tailscale_ip,
            names = registration.hostnames.len(),
            "registration reconciled"
        );
    }
    Ok(())
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

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(pem.as_bytes())?;
    file.sync_all()
}

#[cfg(not(unix))]
fn write_private_key(path: &Path, pem: &str) -> io::Result<()> {
    fs::write(path, pem)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_tailscale_ipv4_range() {
        assert!(is_tailscale_ipv4(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(is_tailscale_ipv4(Ipv4Addr::new(100, 127, 255, 254)));
        assert!(!is_tailscale_ipv4(Ipv4Addr::new(100, 63, 255, 255)));
        assert!(!is_tailscale_ipv4(Ipv4Addr::new(100, 128, 0, 1)));
    }
}

use std::{fs, path::PathBuf};

use certifex_core::{NodeConfig, NodeIdentity};
use clap::Parser;

#[derive(Debug, Parser)]
#[command(version, about = "Certifex node agent")]
struct Args {
    #[arg(long, default_value = "/etc/certifex-minimus/node.toml")]
    config: PathBuf,

    #[arg(long, default_value = "/var/lib/certifex-minimus")]
    state_dir: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let config: NodeConfig = toml::from_str(&fs::read_to_string(&args.config)?)?;
    let hostnames = config.hostnames()?;
    fs::create_dir_all(&args.state_dir)?;

    let key_path = args.state_dir.join("node-key.pem");
    let identity = if key_path.exists() {
        NodeIdentity::from_private_key_pem(&fs::read_to_string(&key_path)?)?
    } else {
        let identity = NodeIdentity::generate()?;
        write_private_key(&key_path, &identity.private_key_pem())?;
        identity
    };

    let csr = identity.csr_pem(&hostnames)?;
    fs::write(args.state_dir.join("node.csr.pem"), csr)?;
    println!("node={} names={}", config.node_id, hostnames.join(","));
    Ok(())
}

#[cfg(unix)]
fn write_private_key(path: &std::path::Path, pem: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(pem.as_bytes())?;
    file.sync_all()
}

#[cfg(not(unix))]
fn write_private_key(path: &std::path::Path, pem: &str) -> std::io::Result<()> {
    fs::write(path, pem)
}

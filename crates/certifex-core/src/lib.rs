use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

use rcgen::{
    CertificateParams, CertificateSigningRequestParams, DistinguishedName, KeyPair, PublicKeyData,
    SanType,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_NODE_ID_BYTES: usize = 128;
pub const MAX_HOSTNAMES: usize = 100;
pub const MAX_CSR_PEM_BYTES: usize = 64 * 1024;
pub const REGISTRAR_LABEL: &str = "certifex";
pub const REGISTRAR_PORT: u16 = 7443;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    pub node_id: String,
    pub domain: String,
    pub services: BTreeMap<String, u16>,
    #[serde(default)]
    pub fanouts: BTreeMap<String, FanoutConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FanoutConfig {
    #[serde(default)]
    pub files: Vec<FileRoute>,
    #[serde(default)]
    pub tunnels: Vec<TunnelRoute>,
    #[serde(default)]
    pub ranges: Vec<TunnelRangeRoute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRoute {
    pub path: String,
    pub source: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelRoute {
    pub path: String,
    #[serde(flatten)]
    pub target: TunnelTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "transport", rename_all = "kebab-case")]
pub enum TunnelTarget {
    Tcp { address: SocketAddr },
    UnixStream { socket: PathBuf },
    Udp { address: SocketAddr },
    UnixDatagram { socket: PathBuf },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelRangeRoute {
    pub path_prefix: String,
    pub first: u16,
    pub last: u16,
    #[serde(flatten)]
    pub target: PortRangeTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "transport", rename_all = "kebab-case")]
pub enum PortRangeTarget {
    Tcp { host: IpAddr, port_start: u16 },
    Udp { host: IpAddr, port_start: u16 },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("node_id must not be empty")]
    EmptyNodeId,
    #[error("node_id exceeds {MAX_NODE_ID_BYTES} bytes")]
    NodeIdTooLong,
    #[error("node config contains more than {MAX_HOSTNAMES} hostnames")]
    TooManyServices,
    #[error("service and fanout both claim label `{0}`")]
    DuplicateLabel(String),
    #[error("fanout `{0}` has no routes")]
    EmptyFanout(String),
    #[error("invalid fanout path `{0}`")]
    InvalidPath(String),
    #[error("fanout file source must be absolute: `{0}`")]
    RelativeFile(String),
    #[error("invalid tunnel target in fanout `{0}`")]
    InvalidTunnelTarget(String),
    #[error("invalid tunnel range in fanout `{0}`")]
    InvalidTunnelRange(String),
    #[error("domain must not be empty")]
    EmptyDomain,
    #[error("invalid DNS label `{0}`")]
    InvalidLabel(String),
    #[error("service or fanout name `{0}` is reserved")]
    ReservedName(String),
    #[error("service `{0}` uses port 0")]
    ZeroPort(String),
    #[error("hostname for service or fanout `{0}` exceeds 253 bytes")]
    HostnameTooLong(String),
}

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("certificate operation failed: {0}")]
    Certificate(#[from] rcgen::Error),
    #[error("CSR contains a non-DNS subject alternative name")]
    NonDnsSan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRegistration {
    pub node_id: String,
    pub tailscale_ip: IpAddr,
    pub hostnames: Vec<String>,
    pub csr_pem: String,
    pub installed_generation: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateBundle {
    pub generation: u64,
    pub hostnames: Vec<String>,
    pub certificate_chain_pem: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationResponse {
    pub certificate: Option<CertificateBundle>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegistrationError {
    #[error("node_id must not be empty")]
    EmptyNodeId,
    #[error("node_id exceeds {MAX_NODE_ID_BYTES} bytes")]
    NodeIdTooLong,
    #[error("registration contains more than {MAX_HOSTNAMES} hostnames")]
    TooManyHostnames,
    #[error("invalid or non-canonical hostname `{0}`")]
    InvalidHostname(String),
    #[error("CSR PEM exceeds {MAX_CSR_PEM_BYTES} bytes")]
    CsrTooLarge,
    #[error("registration hostnames are not canonical")]
    NonCanonicalHostnames,
    #[error("CSR SANs do not match registered hostnames")]
    CsrNameMismatch,
    #[error("invalid CSR: {0}")]
    InvalidCsr(String),
}

impl NodeRegistration {
    /// Validates the registration's identity and CSR name set.
    ///
    /// # Errors
    ///
    /// Returns an error when the node ID or hostname set is invalid, the CSR cannot be
    /// parsed and verified, or the CSR SANs differ from the declared hostnames.
    pub fn validate(&self) -> Result<(), RegistrationError> {
        if self.node_id.trim().is_empty() {
            return Err(RegistrationError::EmptyNodeId);
        }
        if self.node_id.len() > MAX_NODE_ID_BYTES {
            return Err(RegistrationError::NodeIdTooLong);
        }
        if self.hostnames.len() > MAX_HOSTNAMES {
            return Err(RegistrationError::TooManyHostnames);
        }
        if self.csr_pem.len() > MAX_CSR_PEM_BYTES {
            return Err(RegistrationError::CsrTooLarge);
        }
        for hostname in &self.hostnames {
            if hostname != &hostname.to_ascii_lowercase() || validate_domain(hostname).is_err() {
                return Err(RegistrationError::InvalidHostname(hostname.clone()));
            }
        }

        let mut canonical = self.hostnames.clone();
        canonical.sort_unstable();
        canonical.dedup();
        if canonical != self.hostnames {
            return Err(RegistrationError::NonCanonicalHostnames);
        }

        let csr_names = csr_dns_names(&self.csr_pem)
            .map_err(|error| RegistrationError::InvalidCsr(error.to_string()))?;
        if csr_names != self.hostnames {
            return Err(RegistrationError::CsrNameMismatch);
        }
        Ok(())
    }
}

fn validate_tunnel_target(target: &TunnelTarget) -> Result<(), ()> {
    match target {
        TunnelTarget::Tcp { address } | TunnelTarget::Udp { address } => {
            if address.ip().is_loopback() && address.port() != 0 {
                Ok(())
            } else {
                Err(())
            }
        }
        TunnelTarget::UnixStream { socket } | TunnelTarget::UnixDatagram { socket } => {
            if socket.is_absolute() {
                Ok(())
            } else {
                Err(())
            }
        }
    }
}

impl NodeConfig {
    /// Validates the node identifier, base domain, service labels, and ports.
    ///
    /// # Errors
    ///
    /// Returns an error when an identifier, DNS label, or service port is invalid.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.node_id.trim().is_empty() {
            return Err(ConfigError::EmptyNodeId);
        }
        if self.node_id.len() > MAX_NODE_ID_BYTES {
            return Err(ConfigError::NodeIdTooLong);
        }
        if self.services.len().saturating_add(self.fanouts.len()) > MAX_HOSTNAMES {
            return Err(ConfigError::TooManyServices);
        }

        let domain = canonical_domain(&self.domain)?;
        validate_hostname_length(REGISTRAR_LABEL, &domain)?;

        for (label, port) in &self.services {
            validate_relative_name(label)?;
            validate_hostname_length(label, &domain)?;
            if *port == 0 {
                return Err(ConfigError::ZeroPort(label.clone()));
            }
            if self.fanouts.contains_key(label) {
                return Err(ConfigError::DuplicateLabel(label.clone()));
            }
        }
        for (label, fanout) in &self.fanouts {
            validate_relative_name(label)?;
            validate_hostname_length(label, &domain)?;
            if fanout.files.is_empty() && fanout.tunnels.is_empty() && fanout.ranges.is_empty() {
                return Err(ConfigError::EmptyFanout(label.clone()));
            }
            for (index, route) in fanout.files.iter().enumerate() {
                validate_path(&route.path)?;
                if !route.source.is_absolute() {
                    return Err(ConfigError::RelativeFile(
                        route.source.display().to_string(),
                    ));
                }
                if fanout.files[index + 1..]
                    .iter()
                    .any(|other| other.path == route.path)
                {
                    return Err(ConfigError::InvalidPath(route.path.clone()));
                }
            }
            for (index, route) in fanout.tunnels.iter().enumerate() {
                validate_path(&route.path)?;
                validate_tunnel_target(&route.target)
                    .map_err(|()| ConfigError::InvalidTunnelTarget(label.clone()))?;
                if fanout.tunnels[index + 1..]
                    .iter()
                    .any(|other| other.path == route.path)
                {
                    return Err(ConfigError::InvalidPath(route.path.clone()));
                }
            }
            for range in &fanout.ranges {
                validate_path_prefix(&range.path_prefix)?;
                let Some(span) = range.last.checked_sub(range.first) else {
                    return Err(ConfigError::InvalidTunnelRange(label.clone()));
                };
                let valid = match range.target {
                    PortRangeTarget::Tcp { host, port_start }
                    | PortRangeTarget::Udp { host, port_start } => {
                        host.is_loopback()
                            && port_start != 0
                            && port_start
                                .checked_add(span)
                                .is_some_and(|last_port| last_port != 0)
                    }
                };
                if !valid {
                    return Err(ConfigError::InvalidTunnelRange(label.clone()));
                }
            }
            for (index, left) in fanout.ranges.iter().enumerate() {
                for right in &fanout.ranges[index + 1..] {
                    let overlaps = !(left.last < right.first || right.last < left.first);
                    if left.path_prefix == right.path_prefix && overlaps {
                        return Err(ConfigError::InvalidTunnelRange(label.clone()));
                    }
                }
            }
        }

        Ok(())
    }

    /// Expands configured service labels into canonical fully qualified DNS names.
    ///
    /// # Errors
    ///
    /// Returns an error when the node configuration is invalid.
    pub fn hostnames(&self) -> Result<Vec<String>, ConfigError> {
        self.validate()?;
        let domain = normalize_domain(&self.domain)?;
        let mut hostnames = self
            .services
            .keys()
            .chain(self.fanouts.keys())
            .map(|label| format!("{label}.{domain}"))
            .collect::<Vec<_>>();
        hostnames.sort_unstable();
        Ok(hostnames)
    }

    /// Returns the normalized base domain after validating the complete node configuration.
    ///
    /// # Errors
    /// Returns an error when the node configuration is invalid.
    pub fn canonical_domain(&self) -> Result<String, ConfigError> {
        self.validate()?;
        canonical_domain(&self.domain)
    }

    /// Returns the registrar control-plane URL derived from the base domain.
    ///
    /// # Errors
    /// Returns an error when the configured base domain is invalid.
    pub fn registrar_url(&self) -> Result<String, ConfigError> {
        self.validate()?;
        Ok(format!(
            "http://{}:{REGISTRAR_PORT}",
            registrar_hostname(&self.domain)?
        ))
    }
}

/// Normalizes and validates a base DNS domain.
///
/// # Errors
/// Returns an error when the domain is empty or contains an invalid DNS label.
pub fn canonical_domain(domain: &str) -> Result<String, ConfigError> {
    let domain = normalize_domain(domain)?;
    validate_domain(&domain)?;
    Ok(domain)
}

/// Returns the reserved registrar hostname for a base domain.
///
/// # Errors
/// Returns an error when the domain is invalid or the resulting hostname is too long.
pub fn registrar_hostname(domain: &str) -> Result<String, ConfigError> {
    let domain = canonical_domain(domain)?;
    validate_hostname_length(REGISTRAR_LABEL, &domain)?;
    Ok(format!("{REGISTRAR_LABEL}.{domain}"))
}

fn validate_hostname_length(label: &str, domain: &str) -> Result<(), ConfigError> {
    if label.len() + 1 + domain.len() <= 253 {
        Ok(())
    } else {
        Err(ConfigError::HostnameTooLong(label.to_owned()))
    }
}

fn validate_path(path: &str) -> Result<(), ConfigError> {
    if path.starts_with('/') && !path.contains(['?', '#']) {
        Ok(())
    } else {
        Err(ConfigError::InvalidPath(path.to_owned()))
    }
}

fn validate_path_prefix(prefix: &str) -> Result<(), ConfigError> {
    validate_path(prefix)?;
    if prefix.ends_with('/') {
        Ok(())
    } else {
        Err(ConfigError::InvalidPath(prefix.to_owned()))
    }
}

pub struct NodeIdentity {
    key_pair: KeyPair,
}

impl NodeIdentity {
    /// Generates a fresh P-256 node identity.
    ///
    /// # Errors
    ///
    /// Returns an error if the cryptographic backend cannot generate a key pair.
    pub fn generate() -> Result<Self, IdentityError> {
        Ok(Self {
            key_pair: KeyPair::generate()?,
        })
    }

    /// Restores a node identity from a PKCS#8 PEM private key.
    ///
    /// # Errors
    ///
    /// Returns an error when the PEM or private key is invalid or unsupported.
    pub fn from_private_key_pem(pem: &str) -> Result<Self, IdentityError> {
        Ok(Self {
            key_pair: KeyPair::from_pem(pem)?,
        })
    }

    #[must_use]
    pub fn private_key_pem(&self) -> String {
        self.key_pair.serialize_pem()
    }

    /// Returns the node public key as DER-encoded `SubjectPublicKeyInfo`.
    #[must_use]
    pub fn public_key_spki_der(&self) -> Vec<u8> {
        self.key_pair.subject_public_key_info()
    }

    /// Creates a signed CSR for the supplied DNS names without exposing the private key.
    ///
    /// # Errors
    ///
    /// Returns an error when a DNS name is invalid or CSR generation fails.
    pub fn csr_pem(&self, hostnames: &[String]) -> Result<String, IdentityError> {
        let mut params = CertificateParams::new(hostnames.to_vec())?;
        params.distinguished_name = DistinguishedName::new();
        Ok(params.serialize_request(&self.key_pair)?.pem()?)
    }
}

/// Parses and verifies a CSR and returns its DNS SANs in sorted order.
///
/// # Errors
///
/// Returns an error when the CSR is malformed, has an invalid signature, or contains an
/// unsupported certificate request extension.
pub fn csr_dns_names(csr_pem: &str) -> Result<Vec<String>, IdentityError> {
    let csr = CertificateSigningRequestParams::from_pem(csr_pem)?;
    let mut names = csr
        .params
        .subject_alt_names
        .into_iter()
        .map(|san| match san {
            SanType::DnsName(name) => Ok(name.as_str().to_owned()),
            _ => Err(IdentityError::NonDnsSan),
        })
        .collect::<Result<Vec<_>, _>>()?;
    names.sort_unstable();
    Ok(names)
}

/// Parses and verifies a CSR and returns its DER-encoded `SubjectPublicKeyInfo`.
///
/// # Errors
/// Returns an error when the CSR is malformed or has an invalid signature.
pub fn csr_public_key_spki_der(csr_pem: &str) -> Result<Vec<u8>, IdentityError> {
    let csr = CertificateSigningRequestParams::from_pem(csr_pem)?;
    Ok(csr.public_key.subject_public_key_info())
}

fn normalize_domain(domain: &str) -> Result<String, ConfigError> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() {
        return Err(ConfigError::EmptyDomain);
    }
    Ok(domain)
}

fn validate_domain(domain: &str) -> Result<(), ConfigError> {
    if domain.len() > 253 {
        return Err(ConfigError::InvalidLabel(domain.to_owned()));
    }
    for label in domain.split('.') {
        validate_label(label)?;
    }
    Ok(())
}

fn validate_relative_name(name: &str) -> Result<(), ConfigError> {
    validate_domain(name).map_err(|_| ConfigError::InvalidLabel(name.to_owned()))?;
    if name == REGISTRAR_LABEL {
        return Err(ConfigError::ReservedName(name.to_owned()));
    }
    Ok(())
}

fn validate_label(label: &str) -> Result<(), ConfigError> {
    let valid = !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if valid {
        Ok(())
    } else {
        Err(ConfigError::InvalidLabel(label.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> NodeConfig {
        NodeConfig {
            node_id: "sf314-42".to_owned(),
            domain: "Onhir.EU.".to_owned(),
            services: BTreeMap::from([("grafana".to_owned(), 3000), ("victoria".to_owned(), 8428)]),
            fanouts: BTreeMap::new(),
        }
    }

    #[test]
    fn registrar_is_derived_from_the_base_domain() -> Result<(), ConfigError> {
        assert_eq!(registrar_hostname("Onhir.EU.")?, "certifex.onhir.eu");
        assert_eq!(config().registrar_url()?, "http://certifex.onhir.eu:7443");
        Ok(())
    }

    #[test]
    fn hostnames_are_normalized_and_sorted() -> Result<(), ConfigError> {
        assert_eq!(
            config().hostnames()?,
            ["grafana.onhir.eu", "victoria.onhir.eu"]
        );
        Ok(())
    }

    #[test]
    fn nested_service_names_expand_below_the_base_domain() -> Result<(), ConfigError> {
        let mut config = config();
        config.services.clear();
        config.services.insert("exits.waw".to_owned(), 443);
        assert_eq!(config.hostnames()?, ["exits.waw.onhir.eu"]);
        Ok(())
    }

    #[test]
    fn rejects_reserved_registrar_service_name() {
        let mut config = config();
        config.services.insert(REGISTRAR_LABEL.to_owned(), 7443);
        assert_eq!(
            config.validate(),
            Err(ConfigError::ReservedName(REGISTRAR_LABEL.to_owned()))
        );
    }

    #[test]
    fn rejects_bad_service_names() {
        let mut config = config();
        config.services.insert("bad..name".to_owned(), 443);
        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidLabel("bad..name".to_owned()))
        );
    }

    #[test]
    fn csr_contains_exact_requested_sans_and_reuses_key() -> Result<(), IdentityError> {
        let names = vec![
            "grafana.onhir.eu".to_owned(),
            "victoria.onhir.eu".to_owned(),
        ];
        let identity = NodeIdentity::generate()?;
        let key = identity.private_key_pem();
        let first = identity.csr_pem(&names)?;
        let reloaded = NodeIdentity::from_private_key_pem(&key)?;
        let second = reloaded.csr_pem(&names)?;

        assert_eq!(csr_dns_names(&first)?, names);
        assert_eq!(csr_dns_names(&second)?, names);
        assert_eq!(
            csr_public_key_spki_der(&first)?,
            csr_public_key_spki_der(&second)?
        );
        let parsed = CertificateSigningRequestParams::from_pem(&first)?;
        assert_eq!(parsed.params.distinguished_name.iter().count(), 0);
        Ok(())
    }

    #[test]
    fn rejects_protocol_size_limits_before_csr_parse() {
        let too_many = NodeRegistration {
            node_id: "node".to_owned(),
            tailscale_ip: IpAddr::from([100, 64, 0, 1]),
            hostnames: (0..=MAX_HOSTNAMES)
                .map(|index| format!("s{index}.example.com"))
                .collect(),
            csr_pem: String::new(),
            installed_generation: None,
        };
        assert_eq!(
            too_many.validate(),
            Err(RegistrationError::TooManyHostnames)
        );

        let huge_csr = NodeRegistration {
            node_id: "node".to_owned(),
            tailscale_ip: IpAddr::from([100, 64, 0, 1]),
            hostnames: vec!["one.example.com".to_owned()],
            csr_pem: "x".repeat(MAX_CSR_PEM_BYTES + 1),
            installed_generation: None,
        };
        assert_eq!(huge_csr.validate(), Err(RegistrationError::CsrTooLarge));

        let long_id = NodeRegistration {
            node_id: "n".repeat(MAX_NODE_ID_BYTES + 1),
            tailscale_ip: IpAddr::from([100, 64, 0, 1]),
            hostnames: vec!["one.example.com".to_owned()],
            csr_pem: String::new(),
            installed_generation: None,
        };
        assert_eq!(long_id.validate(), Err(RegistrationError::NodeIdTooLong));
    }

    #[test]
    fn rejects_invalid_hostname_before_csr_parse() {
        let registration = NodeRegistration {
            node_id: "node".to_owned(),
            tailscale_ip: IpAddr::from([100, 64, 0, 1]),
            hostnames: vec!["_bad.example.com".to_owned()],
            csr_pem: String::new(),
            installed_generation: None,
        };
        assert!(matches!(
            registration.validate(),
            Err(RegistrationError::InvalidHostname(_))
        ));
    }

    #[test]
    fn csr_parser_rejects_non_dns_sans() -> Result<(), Box<dyn std::error::Error>> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec!["one.example.com".to_owned()])?;
        params
            .subject_alt_names
            .push(SanType::URI("spiffe://example/workload".try_into()?));
        let csr = params.serialize_request(&key)?.pem()?;

        assert!(matches!(csr_dns_names(&csr), Err(IdentityError::NonDnsSan)));
        Ok(())
    }

    #[test]
    fn node_config_enforces_service_and_identifier_limits() {
        let mut too_many = config();
        too_many.services = (0..=MAX_HOSTNAMES)
            .map(|index| (format!("s{index}"), 443))
            .collect();
        assert_eq!(too_many.validate(), Err(ConfigError::TooManyServices));

        let mut long_id = config();
        long_id.node_id = "n".repeat(MAX_NODE_ID_BYTES + 1);
        assert_eq!(long_id.validate(), Err(ConfigError::NodeIdTooLong));

        let mut uppercase = config();
        uppercase.services.insert("Grafana".to_owned(), 443);
        assert_eq!(
            uppercase.validate(),
            Err(ConfigError::InvalidLabel("Grafana".to_owned()))
        );

        let mut hostname_too_long = config();
        hostname_too_long.domain = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61),
        ]
        .join(".");
        assert_eq!(
            hostname_too_long.validate(),
            Err(ConfigError::HostnameTooLong("certifex".to_owned()))
        );
    }

    #[test]
    fn registration_rejects_declared_names_that_differ_from_csr() -> Result<(), IdentityError> {
        let csr_names = vec!["victoria.onhir.eu".to_owned()];
        let identity = NodeIdentity::generate()?;
        let registration = NodeRegistration {
            node_id: "sf314-42".to_owned(),
            tailscale_ip: std::net::IpAddr::from([100, 118, 45, 4]),
            hostnames: vec!["grafana.onhir.eu".to_owned()],
            csr_pem: identity.csr_pem(&csr_names)?,
            installed_generation: None,
        };

        assert_eq!(
            registration.validate(),
            Err(RegistrationError::CsrNameMismatch)
        );
        Ok(())
    }

    #[test]
    fn empty_registration_is_a_valid_deregistration() -> Result<(), Box<dyn std::error::Error>> {
        let identity = NodeIdentity::generate()?;
        let registration = NodeRegistration {
            node_id: "sf314-42".to_owned(),
            tailscale_ip: std::net::IpAddr::from([100, 118, 45, 4]),
            hostnames: Vec::new(),
            csr_pem: identity.csr_pem(&[])?,
            installed_generation: Some(17),
        };

        registration.validate()?;
        Ok(())
    }

    #[test]
    fn fanout_hostname_and_routes_validate() -> Result<(), ConfigError> {
        let mut config = config();
        config.fanouts.insert(
            "workers".to_owned(),
            FanoutConfig {
                files: vec![FileRoute {
                    path: "/inventory.json".to_owned(),
                    source: PathBuf::from("/run/example/inventory.json"),
                }],
                tunnels: Vec::new(),
                ranges: vec![TunnelRangeRoute {
                    path_prefix: "/".to_owned(),
                    first: 1,
                    last: 30,
                    target: PortRangeTarget::Tcp {
                        host: IpAddr::from([127, 0, 0, 1]),
                        port_start: 17_400,
                    },
                }],
            },
        );
        assert!(config.hostnames()?.contains(&"workers.onhir.eu".to_owned()));
        Ok(())
    }

    #[test]
    fn fanout_rejects_nonlocal_and_relative_tunnel_targets() {
        let mut config = config();
        config.fanouts.insert(
            "workers".to_owned(),
            FanoutConfig {
                files: Vec::new(),
                tunnels: vec![TunnelRoute {
                    path: "/remote".to_owned(),
                    target: TunnelTarget::Tcp {
                        address: SocketAddr::from(([192, 0, 2, 10], 9000)),
                    },
                }],
                ranges: Vec::new(),
            },
        );
        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidTunnelTarget("workers".to_owned()))
        );

        config.fanouts.insert(
            "workers".to_owned(),
            FanoutConfig {
                files: Vec::new(),
                tunnels: vec![TunnelRoute {
                    path: "/relative".to_owned(),
                    target: TunnelTarget::UnixDatagram {
                        socket: PathBuf::from("relative.sock"),
                    },
                }],
                ranges: Vec::new(),
            },
        );
        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidTunnelTarget("workers".to_owned()))
        );
    }

    #[test]
    fn fanout_rejects_overflow_and_label_collision() {
        let mut config = config();
        config.fanouts.insert(
            "grafana".to_owned(),
            FanoutConfig {
                files: Vec::new(),
                tunnels: Vec::new(),
                ranges: vec![TunnelRangeRoute {
                    path_prefix: "/".to_owned(),
                    first: 1,
                    last: 30,
                    target: PortRangeTarget::Tcp {
                        host: IpAddr::from([127, 0, 0, 1]),
                        port_start: u16::MAX - 10,
                    },
                }],
            },
        );
        assert_eq!(
            config.validate(),
            Err(ConfigError::DuplicateLabel("grafana".to_owned()))
        );

        config.services.remove("grafana");
        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidTunnelRange("grafana".to_owned()))
        );
    }
}

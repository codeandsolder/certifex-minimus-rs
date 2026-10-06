use std::{collections::BTreeMap, net::IpAddr};

use rcgen::{CertificateParams, CertificateSigningRequestParams, KeyPair, PublicKeyData, SanType};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_NODE_ID_BYTES: usize = 128;
pub const MAX_HOSTNAMES: usize = 100;
pub const MAX_CSR_PEM_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeConfig {
    pub node_id: String,
    pub domain: String,
    pub registrar: String,
    pub services: BTreeMap<String, u16>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("node_id must not be empty")]
    EmptyNodeId,
    #[error("node_id exceeds {MAX_NODE_ID_BYTES} bytes")]
    NodeIdTooLong,
    #[error("node config contains more than {MAX_HOSTNAMES} services")]
    TooManyServices,
    #[error("domain must not be empty")]
    EmptyDomain,
    #[error("invalid DNS label `{0}`")]
    InvalidLabel(String),
    #[error("service `{0}` uses port 0")]
    ZeroPort(String),
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
    #[error("registration contains no hostnames")]
    EmptyHostnames,
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
        if self.hostnames.is_empty() {
            return Err(RegistrationError::EmptyHostnames);
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
        if self.services.len() > MAX_HOSTNAMES {
            return Err(ConfigError::TooManyServices);
        }

        let domain = normalize_domain(&self.domain)?;
        validate_domain(&domain)?;

        for (label, port) in &self.services {
            validate_label(label)?;
            if *port == 0 {
                return Err(ConfigError::ZeroPort(label.clone()));
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
        Ok(self
            .services
            .keys()
            .map(|label| format!("{label}.{domain}"))
            .collect())
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
        let params = CertificateParams::new(hostnames.to_vec())?;
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
            registrar: "https://certifex.onhir.eu".to_owned(),
            services: BTreeMap::from([("grafana".to_owned(), 3000), ("victoria".to_owned(), 8428)]),
        }
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
    fn rejects_bad_service_labels() {
        let mut config = config();
        config.services.insert("bad.name".to_owned(), 443);
        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidLabel("bad.name".to_owned()))
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
}

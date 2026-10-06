use std::sync::Arc;

use certifex_core::{CertificateBundle, NodeIdentity};
use rustls::{
    RootCertStore,
    client::{WebPkiServerVerifier, danger::ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use thiserror::Error;
use x509_parser::{extensions::GeneralName, prelude::FromDer};

#[derive(Debug, Error)]
pub enum CertificateError {
    #[error("certificate bundle names differ from the requested names")]
    BundleNamesMismatch,
    #[error("certificate bundle contains no leaf certificate")]
    EmptyChain,
    #[error("certificate bundle contains non-certificate PEM data")]
    UnexpectedPem,
    #[error("invalid certificate PEM: {0}")]
    Pem(#[from] pem::PemError),
    #[error("invalid leaf certificate: {0}")]
    X509(String),
    #[error("leaf certificate SANs differ from the requested names")]
    CertificateNamesMismatch,
    #[error("leaf certificate contains a non-DNS SAN entry")]
    NonDnsSan,
    #[error("leaf certificate public key does not match the node private key")]
    PublicKeyMismatch,
    #[error("cannot construct public trust verifier: {0}")]
    Verifier(String),
    #[error("invalid DNS name `{0}`")]
    InvalidDnsName(String),
    #[error("certificate failed public trust validation for `{name}`: {source}")]
    Trust { name: String, source: rustls::Error },
}

/// Validates a certificate bundle before it is installed on a node.
///
/// # Errors
/// Returns an error unless the bundle has the exact requested SAN set, chains to a public trust
/// anchor, is currently valid for every requested hostname, and contains the node's public key.
pub fn validate_bundle(
    bundle: &CertificateBundle,
    expected_names: &[String],
    identity: &NodeIdentity,
) -> Result<(), CertificateError> {
    if bundle.hostnames != expected_names {
        return Err(CertificateError::BundleNamesMismatch);
    }

    let blocks = pem::parse_many(bundle.certificate_chain_pem.as_bytes())?;
    if blocks.is_empty() {
        return Err(CertificateError::EmptyChain);
    }
    if blocks.iter().any(|block| block.tag() != "CERTIFICATE") {
        return Err(CertificateError::UnexpectedPem);
    }
    let certificates = blocks
        .into_iter()
        .map(|block| CertificateDer::from(block.into_contents()))
        .collect::<Vec<_>>();
    let Some(leaf_der) = certificates.first() else {
        return Err(CertificateError::EmptyChain);
    };

    let (_, leaf) = x509_parser::certificate::X509Certificate::from_der(leaf_der.as_ref())
        .map_err(|error| CertificateError::X509(error.to_string()))?;
    let san = leaf
        .subject_alternative_name()
        .map_err(|error| CertificateError::X509(error.to_string()))?
        .ok_or(CertificateError::CertificateNamesMismatch)?;
    let mut certificate_names = exact_dns_names(&san.value.general_names)?;
    certificate_names.sort_unstable();
    if certificate_names != expected_names {
        return Err(CertificateError::CertificateNamesMismatch);
    }

    if leaf.public_key().raw != identity.public_key_spki_der() {
        return Err(CertificateError::PublicKeyMismatch);
    }

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let verifier = WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|error| CertificateError::Verifier(error.to_string()))?;
    let intermediates = &certificates[1..];
    for name in expected_names {
        let server_name = ServerName::try_from(name.clone())
            .map_err(|_| CertificateError::InvalidDnsName(name.clone()))?;
        verifier
            .verify_server_cert(leaf_der, intermediates, &server_name, &[], UnixTime::now())
            .map_err(|source| CertificateError::Trust {
                name: name.clone(),
                source,
            })?;
    }

    Ok(())
}

fn exact_dns_names(names: &[GeneralName<'_>]) -> Result<Vec<String>, CertificateError> {
    names
        .iter()
        .map(|name| match name {
            GeneralName::DNSName(name) => Ok((*name).to_owned()),
            _ => Err(CertificateError::NonDnsSan),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_dns_names_accepts_only_dns_entries() -> Result<(), CertificateError> {
        let names = [
            GeneralName::DNSName("one.example"),
            GeneralName::DNSName("two.example"),
        ];
        assert_eq!(
            exact_dns_names(&names)?,
            vec!["one.example".to_owned(), "two.example".to_owned()]
        );
        Ok(())
    }

    #[test]
    fn exact_dns_names_rejects_additional_non_dns_entries() {
        let names = [
            GeneralName::DNSName("one.example"),
            GeneralName::URI("spiffe://example/workload"),
        ];
        assert!(matches!(
            exact_dns_names(&names),
            Err(CertificateError::NonDnsSan)
        ));
    }
}

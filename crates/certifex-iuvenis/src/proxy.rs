use std::{
    collections::BTreeMap,
    convert::Infallible,
    io,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::{Arc, RwLock},
};

use bytes::Bytes;
use certifex_core::{ConfigError, NodeConfig};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{
    Request, Response, StatusCode, Uri, Version,
    body::Incoming,
    header::{
        CONNECTION, HOST, HeaderName, HeaderValue, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE,
        TRAILER, TRANSFER_ENCODING, UPGRADE,
    },
    service::service_fn,
};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use thiserror::Error;
use tokio::{net::TcpListener, sync::RwLock as AsyncRwLock};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
const X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");
const PROXY_CONNECTION: HeaderName = HeaderName::from_static("proxy-connection");
const KEEP_ALIVE: HeaderName = HeaderName::from_static("keep-alive");

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type ProxyBody = BoxBody<Bytes, BoxError>;
type BackendClient = Client<HttpConnector, Incoming>;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("proxy state I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid proxy certificate PEM: {0}")]
    Pem(#[from] pem::PemError),
    #[error("proxy certificate file contains no certificates")]
    EmptyCertificateChain,
    #[error("proxy key PEM has unexpected tag `{0}`")]
    UnexpectedKeyTag(String),
    #[error("invalid TLS certificate/key pair: {0}")]
    Tls(#[from] rustls::Error),
    #[error("proxy TLS configuration lock is poisoned")]
    PoisonedTlsLock,
    #[error("service configuration is invalid: {0}")]
    Config(#[from] ConfigError),
}

#[derive(Clone)]
pub struct ProxyState {
    tls: Arc<RwLock<Option<Arc<ServerConfig>>>>,
    routes: Arc<AsyncRwLock<BTreeMap<String, u16>>>,
}

impl ProxyState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            tls: Arc::new(RwLock::new(None)),
            routes: Arc::new(AsyncRwLock::new(BTreeMap::new())),
        }
    }

    /// Replaces the hostname routing table from the current node configuration.
    ///
    /// # Errors
    /// Returns an error if the node configuration is invalid.
    pub async fn set_routes(&self, config: &NodeConfig) -> Result<(), ProxyError> {
        let hostnames = config.hostnames()?;
        let routes = hostnames
            .into_iter()
            .zip(config.services.values().copied())
            .collect();
        *self.routes.write().await = routes;
        Ok(())
    }

    /// Loads the installed certificate and private key into a fresh TLS server configuration.
    ///
    /// Existing connections keep their old TLS state; subsequent handshakes use the new
    /// certificate immediately.
    ///
    /// # Errors
    /// Returns an error when certificate/key state cannot be read or does not form a valid TLS
    /// certificate/key pair.
    pub fn reload_tls(&self, state_dir: &Path) -> Result<(), ProxyError> {
        let certificate_pem = std::fs::read_to_string(state_dir.join("certificate.pem"))?;
        let key_pem = std::fs::read_to_string(state_dir.join("node-key.pem"))?;
        let certificates = pem::parse_many(certificate_pem.as_bytes())?
            .into_iter()
            .filter(|block| block.tag() == "CERTIFICATE")
            .map(|block| CertificateDer::from(block.into_contents()))
            .collect::<Vec<_>>();
        if certificates.is_empty() {
            return Err(ProxyError::EmptyCertificateChain);
        }
        let key = pem::parse(key_pem.as_bytes())?;
        if key.tag() != "PRIVATE KEY" {
            return Err(ProxyError::UnexpectedKeyTag(key.tag().to_owned()));
        }
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.into_contents()));
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificates, key)?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        *self.tls.write().map_err(|_| ProxyError::PoisonedTlsLock)? = Some(Arc::new(config));
        Ok(())
    }

    /// Serves HTTPS forever on the supplied Tailscale address and port.
    ///
    /// # Errors
    /// Returns an error only if the listening socket cannot be created. Individual TLS or HTTP
    /// connection failures are logged and isolated to that connection.
    pub async fn serve(self, ip: IpAddr, port: u16) -> Result<(), ProxyError> {
        let address = SocketAddr::new(ip, port);
        let listener = TcpListener::bind(address).await?;
        let mut connector = HttpConnector::new();
        connector.enforce_http(true);
        let mut client_builder = Client::builder(TokioExecutor::new());
        client_builder.set_host(false);
        let client = client_builder.build(connector);
        info!(%address, "HTTPS proxy listening");

        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(connection) => connection,
                Err(error) => {
                    warn!(%error, "failed to accept HTTPS connection");
                    continue;
                }
            };
            let tls_config = match self.current_tls_config() {
                Ok(Some(config)) => config,
                Ok(None) => {
                    debug!(%peer, "dropping connection because no certificate is installed yet");
                    continue;
                }
                Err(error) => {
                    warn!(%error, "cannot read TLS configuration");
                    continue;
                }
            };
            let routes = self.routes.clone();
            let client = client.clone();
            tokio::spawn(async move {
                let acceptor = TlsAcceptor::from(tls_config);
                let tls = match acceptor.accept(stream).await {
                    Ok(tls) => tls,
                    Err(error) => {
                        debug!(%peer, %error, "TLS handshake failed");
                        return;
                    }
                };
                let service = service_fn(move |request| {
                    proxy_request(request, peer, routes.clone(), client.clone())
                });
                if let Err(error) = Builder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(TokioIo::new(tls), service)
                    .await
                {
                    debug!(%peer, %error, "HTTPS connection ended with error");
                }
            });
        }
    }

    /// Returns whether a usable TLS certificate/key pair is currently active.
    ///
    /// # Errors
    /// Returns an error if the TLS state lock is poisoned.
    pub fn has_tls(&self) -> Result<bool, ProxyError> {
        Ok(self.current_tls_config()?.is_some())
    }

    fn current_tls_config(&self) -> Result<Option<Arc<ServerConfig>>, ProxyError> {
        Ok(self
            .tls
            .read()
            .map_err(|_| ProxyError::PoisonedTlsLock)?
            .clone())
    }
}

async fn proxy_request(
    mut request: Request<Incoming>,
    peer: SocketAddr,
    routes: Arc<AsyncRwLock<BTreeMap<String, u16>>>,
    client: BackendClient,
) -> Result<Response<ProxyBody>, Infallible> {
    let Some(authority) = request_authority(&request) else {
        return Ok(text_response(
            StatusCode::BAD_REQUEST,
            "missing Host header\n",
        ));
    };
    let host = normalize_host(&authority);
    let port = {
        let routes = routes.read().await;
        routes.get(&host).copied()
    };
    let Some(port) = port else {
        return Ok(text_response(
            StatusCode::NOT_FOUND,
            "unknown Certifex service\n",
        ));
    };

    let frontend_upgrade = is_upgrade_request(&request).then(|| hyper::upgrade::on(&mut request));
    let path = request
        .uri()
        .path_and_query()
        .map_or("/", hyper::http::uri::PathAndQuery::as_str);
    let uri = match format!("http://127.0.0.1:{port}{path}").parse::<Uri>() {
        Ok(uri) => uri,
        Err(error) => {
            warn!(%host, port, %error, "failed to construct backend URI");
            return Ok(text_response(
                StatusCode::BAD_GATEWAY,
                "invalid backend URI\n",
            ));
        }
    };
    *request.uri_mut() = uri;
    *request.version_mut() = Version::HTTP_11;
    sanitize_hop_by_hop(request.headers_mut(), frontend_upgrade.is_some());
    if let Ok(value) = HeaderValue::from_str(&authority) {
        request.headers_mut().insert(HOST, value);
    }
    set_forwarded_headers(request.headers_mut(), &authority, peer.ip());

    match client.request(request).await {
        Ok(mut response) => {
            if let Some(frontend_upgrade) = frontend_upgrade
                && response.status() == StatusCode::SWITCHING_PROTOCOLS
            {
                let backend_upgrade = hyper::upgrade::on(&mut response);
                tokio::spawn(tunnel_upgrade(
                    frontend_upgrade,
                    backend_upgrade,
                    host.clone(),
                ));
            }
            let status = response.status();
            sanitize_response_hop_by_hop(response.headers_mut(), status);
            let (parts, body) = response.into_parts();
            Ok(Response::from_parts(
                parts,
                body.map_err(|error| -> BoxError { Box::new(error) })
                    .boxed(),
            ))
        }
        Err(error) => {
            warn!(%host, port, %error, "backend request failed");
            Ok(text_response(
                StatusCode::BAD_GATEWAY,
                "backend unavailable\n",
            ))
        }
    }
}

async fn tunnel_upgrade(
    frontend: hyper::upgrade::OnUpgrade,
    backend: hyper::upgrade::OnUpgrade,
    host: String,
) {
    let (frontend, backend) = match tokio::try_join!(frontend, backend) {
        Ok(upgrades) => upgrades,
        Err(error) => {
            debug!(%host, %error, "HTTP upgrade failed");
            return;
        }
    };
    let mut frontend = TokioIo::new(frontend);
    let mut backend = TokioIo::new(backend);
    if let Err(error) = tokio::io::copy_bidirectional(&mut frontend, &mut backend).await {
        debug!(%host, %error, "upgraded connection tunnel ended with error");
    }
}

fn request_authority(request: &Request<Incoming>) -> Option<String> {
    request
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .or_else(|| request.uri().authority().map(ToString::to_string))
}

fn normalize_host(value: &str) -> String {
    let host = value
        .rsplit_once(':')
        .filter(|(_, port)| port.bytes().all(|byte| byte.is_ascii_digit()))
        .map_or(value, |(host, _)| host);
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn is_upgrade_request(request: &Request<Incoming>) -> bool {
    request.headers().contains_key(UPGRADE)
        && request
            .headers()
            .get(CONNECTION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            })
}

fn sanitize_hop_by_hop(headers: &mut hyper::HeaderMap, preserve_upgrade: bool) {
    let connection_named = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .filter_map(|value| HeaderName::from_bytes(value.as_bytes()).ok())
        .collect::<Vec<_>>();
    for name in connection_named {
        if preserve_upgrade && name == UPGRADE {
            continue;
        }
        headers.remove(name);
    }

    if preserve_upgrade {
        headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
    } else {
        headers.remove(CONNECTION);
        headers.remove(UPGRADE);
    }
    for name in [
        TRANSFER_ENCODING,
        TE,
        TRAILER,
        PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
        PROXY_CONNECTION,
        KEEP_ALIVE,
    ] {
        headers.remove(name);
    }
}

fn sanitize_response_hop_by_hop(headers: &mut hyper::HeaderMap, status: StatusCode) {
    sanitize_hop_by_hop(headers, status == StatusCode::SWITCHING_PROTOCOLS);
}

fn set_forwarded_headers(headers: &mut hyper::HeaderMap, host: &str, peer_ip: IpAddr) {
    if let Ok(value) = HeaderValue::from_str(host) {
        headers.insert(X_FORWARDED_HOST, value);
    }
    headers.insert(X_FORWARDED_PROTO, HeaderValue::from_static("https"));
    if let Ok(value) = HeaderValue::from_str(&peer_ip.to_string()) {
        headers.insert(X_FORWARDED_FOR, value);
    }
}

fn text_response(status: StatusCode, body: &'static str) -> Response<ProxyBody> {
    let body = Full::new(Bytes::from_static(body.as_bytes()))
        .map_err(|never| -> BoxError { match never {} })
        .boxed();
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_hostnames_and_numeric_ports() {
        assert_eq!(normalize_host("Victoria.Onhir.EU:443"), "victoria.onhir.eu");
        assert_eq!(normalize_host("Grafana.Onhir.EU."), "grafana.onhir.eu");
    }

    #[test]
    fn strips_connection_named_hop_headers() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            CONNECTION,
            HeaderValue::from_static("keep-alive, x-certifex-hop"),
        );
        headers.insert(
            HeaderName::from_static("x-certifex-hop"),
            HeaderValue::from_static("secret"),
        );
        headers.insert(KEEP_ALIVE, HeaderValue::from_static("timeout=5"));

        sanitize_hop_by_hop(&mut headers, false);

        assert!(!headers.contains_key(CONNECTION));
        assert!(!headers.contains_key(HeaderName::from_static("x-certifex-hop")));
        assert!(!headers.contains_key(KEEP_ALIVE));
    }

    #[test]
    fn preserves_only_upgrade_connection_state_for_tunnels() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(CONNECTION, HeaderValue::from_static("keep-alive, Upgrade"));
        headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(KEEP_ALIVE, HeaderValue::from_static("timeout=5"));

        sanitize_hop_by_hop(&mut headers, true);

        assert_eq!(
            headers.get(CONNECTION),
            Some(&HeaderValue::from_static("upgrade"))
        );
        assert_eq!(
            headers.get(UPGRADE),
            Some(&HeaderValue::from_static("websocket"))
        );
        assert!(!headers.contains_key(KEEP_ALIVE));
    }
}

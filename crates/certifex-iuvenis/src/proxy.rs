use std::{
    collections::BTreeMap,
    convert::Infallible,
    io,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::{Arc, RwLock},
    time::Duration,
};

use crate::telemetry::Telemetry;
use bytes::Bytes;
use certifex_core::{
    ConfigError, FanoutConfig, NodeConfig, PortRangeTarget, TunnelRangeRoute, TunnelTarget,
};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{
    Method, Request, Response, StatusCode, Uri, Version,
    body::Incoming,
    header::{
        ALLOW, CACHE_CONTROL, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, HOST, HeaderName,
        HeaderValue, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE, TRAILER, TRANSFER_ENCODING,
        UPGRADE,
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
use tokio::{
    fs,
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream, UnixStream},
    sync::RwLock as AsyncRwLock,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

mod datagram;

const FORWARDED: HeaderName = HeaderName::from_static("forwarded");
const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
const X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");
const X_REAL_IP: HeaderName = HeaderName::from_static("x-real-ip");
const PROXY_CONNECTION: HeaderName = HeaderName::from_static("proxy-connection");
const KEEP_ALIVE: HeaderName = HeaderName::from_static("keep-alive");
const CAPSULE_PROTOCOL: HeaderName = HeaderName::from_static("capsule-protocol");
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TUNNEL_BUFFER_BYTES: usize = 64 * 1024;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type ProxyBody = BoxBody<Bytes, BoxError>;
type BackendClient = Client<HttpConnector, Incoming>;

#[derive(Clone)]
enum Route {
    Http(u16),
    Fanout(FanoutConfig),
}

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
    routes: Arc<AsyncRwLock<BTreeMap<String, Route>>>,
    telemetry: Telemetry,
}

impl ProxyState {
    #[must_use]
    pub fn new(telemetry: Telemetry) -> Self {
        Self {
            tls: Arc::new(RwLock::new(None)),
            routes: Arc::new(AsyncRwLock::new(BTreeMap::new())),
            telemetry,
        }
    }

    #[must_use]
    pub const fn telemetry(&self) -> &Telemetry {
        &self.telemetry
    }

    /// Replaces the hostname routing table from the current node configuration.
    ///
    /// # Errors
    /// Returns an error if the node configuration is invalid.
    pub async fn set_routes(&self, config: &NodeConfig) -> Result<(), ProxyError> {
        let domain = config.canonical_domain()?;
        let mut routes = BTreeMap::new();
        for (label, port) in &config.services {
            routes.insert(format!("{label}.{domain}"), Route::Http(*port));
        }
        for (label, fanout) in &config.fanouts {
            routes.insert(format!("{label}.{domain}"), Route::Fanout(fanout.clone()));
        }
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
            let telemetry = self.telemetry.clone();
            tokio::spawn(async move {
                let acceptor = TlsAcceptor::from(tls_config);
                let tls = match acceptor.accept(stream).await {
                    Ok(tls) => tls,
                    Err(error) => {
                        telemetry.tls_handshake_failed();
                        debug!(%peer, %error, "TLS handshake failed");
                        return;
                    }
                };
                let service = service_fn(move |request| {
                    proxy_request(
                        request,
                        peer,
                        routes.clone(),
                        client.clone(),
                        telemetry.clone(),
                    )
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

    /// Stops serving the currently installed certificate for future handshakes.
    ///
    /// Existing TLS connections retain the configuration they already cloned.
    ///
    /// # Errors
    /// Returns an error if the TLS state lock is poisoned.
    pub fn clear_tls(&self) -> Result<(), ProxyError> {
        *self.tls.write().map_err(|_| ProxyError::PoisonedTlsLock)? = None;
        Ok(())
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
    request: Request<Incoming>,
    peer: SocketAddr,
    routes: Arc<AsyncRwLock<BTreeMap<String, Route>>>,
    client: BackendClient,
    telemetry: Telemetry,
) -> Result<Response<ProxyBody>, Infallible> {
    let Some(authority) = request_authority(&request) else {
        return Ok(text_response(
            StatusCode::BAD_REQUEST,
            "missing Host header\n",
        ));
    };
    let host = normalize_host(&authority);
    let route = {
        let routes = routes.read().await;
        routes.get(&host).cloned()
    };
    let Some(route) = route else {
        return Ok(text_response(
            StatusCode::NOT_FOUND,
            "unknown Certifex service\n",
        ));
    };

    let response = match route {
        Route::Http(port) => {
            proxy_http_request(
                request,
                peer,
                client,
                authority,
                host.clone(),
                port,
                telemetry.clone(),
            )
            .await
        }
        Route::Fanout(fanout) => fanout_request(request, host.clone(), fanout).await,
    };
    telemetry.request(&host, response.status().as_u16());
    Ok(response)
}

async fn proxy_http_request(
    mut request: Request<Incoming>,
    peer: SocketAddr,
    client: BackendClient,
    authority: String,
    host: String,
    port: u16,
    telemetry: Telemetry,
) -> Response<ProxyBody> {
    let frontend_upgrade = is_upgrade_request(&request).then(|| hyper::upgrade::on(&mut request));
    let path = request
        .uri()
        .path_and_query()
        .map_or("/", hyper::http::uri::PathAndQuery::as_str);
    let uri = match format!("http://127.0.0.1:{port}{path}").parse::<Uri>() {
        Ok(uri) => uri,
        Err(error) => {
            warn!(%host, port, %error, "failed to construct backend URI");
            return text_response(StatusCode::BAD_GATEWAY, "invalid backend URI\n");
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
            Response::from_parts(
                parts,
                body.map_err(|error| -> BoxError { Box::new(error) })
                    .boxed(),
            )
        }
        Err(error) => {
            telemetry.backend_failed(&host);
            warn!(%host, port, %error, "backend request failed");
            text_response(StatusCode::BAD_GATEWAY, "backend unavailable\n")
        }
    }
}

async fn fanout_request(
    mut request: Request<Incoming>,
    host: String,
    fanout: FanoutConfig,
) -> Response<ProxyBody> {
    let path = request.uri().path().to_owned();
    if let Some(route) = fanout.files.iter().find(|route| route.path == path) {
        return file_response(request.method(), route.source.as_path(), &host, &path).await;
    }

    let Some(target) = tunnel_target_for_path(&fanout, &path) else {
        return text_response(StatusCode::NOT_FOUND, "unknown fanout route\n");
    };

    match target {
        TunnelTarget::Tcp { address } => {
            if let Some(response) = require_stream_connect(&request) {
                return response;
            }
            let backend = match timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(address)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    warn!(%host, %address, %error, "fanout TCP backend unavailable");
                    return text_response(StatusCode::BAD_GATEWAY, "backend unavailable\n");
                }
                Err(_) => {
                    warn!(%host, %address, "fanout TCP backend connect timed out");
                    return text_response(
                        StatusCode::GATEWAY_TIMEOUT,
                        "backend connect timed out\n",
                    );
                }
            };
            let frontend = hyper::upgrade::on(&mut request);
            tokio::spawn(tunnel_stream(frontend, backend, host, address.to_string()));
            empty_response(StatusCode::OK)
        }
        TunnelTarget::UnixStream {
            socket: socket_path,
        } => {
            if let Some(response) = require_stream_connect(&request) {
                return response;
            }
            let backend =
                match timeout(TCP_CONNECT_TIMEOUT, UnixStream::connect(&socket_path)).await {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(error)) => {
                        warn!(
                            %host,
                            path = %socket_path.display(),
                            %error,
                            "fanout Unix-stream backend unavailable"
                        );
                        return text_response(StatusCode::BAD_GATEWAY, "backend unavailable\n");
                    }
                    Err(_) => {
                        warn!(
                            %host,
                            path = %socket_path.display(),
                            "fanout Unix-stream backend connect timed out"
                        );
                        return text_response(
                            StatusCode::GATEWAY_TIMEOUT,
                            "backend connect timed out\n",
                        );
                    }
                };
            let frontend = hyper::upgrade::on(&mut request);
            tokio::spawn(tunnel_stream(
                frontend,
                backend,
                host,
                socket_path.display().to_string(),
            ));
            empty_response(StatusCode::OK)
        }
        TunnelTarget::Udp { address } => {
            datagram_response(&mut request, host, path, datagram::Target::Udp(address)).await
        }
        TunnelTarget::UnixDatagram {
            socket: socket_path,
        } => {
            datagram_response(
                &mut request,
                host,
                path,
                datagram::Target::Unix(socket_path),
            )
            .await
        }
    }
}

fn require_stream_connect(request: &Request<Incoming>) -> Option<Response<ProxyBody>> {
    if request.method() != Method::CONNECT {
        return Some(text_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "stream tunnel requires CONNECT\n",
        ));
    }
    if request.version() != Version::HTTP_11 {
        return Some(text_response(
            StatusCode::HTTP_VERSION_NOT_SUPPORTED,
            "stream tunnel requires HTTP/1.1 CONNECT\n",
        ));
    }
    None
}

async fn datagram_response(
    request: &mut Request<Incoming>,
    host: String,
    route_path: String,
    target: datagram::Target,
) -> Response<ProxyBody> {
    if request.version() != Version::HTTP_11 {
        return text_response(
            StatusCode::HTTP_VERSION_NOT_SUPPORTED,
            "datagram tunnel currently requires HTTP/1.1 Upgrade\n",
        );
    }
    if request.method() != Method::GET
        || !has_upgrade_token(request, datagram::UPGRADE_TOKEN)
        || request
            .headers()
            .get(CAPSULE_PROTOCOL)
            .is_none_or(|value| value != "?1")
    {
        return text_response(
            StatusCode::BAD_REQUEST,
            "datagram tunnel requires GET + Upgrade: certifex-datagram + Capsule-Protocol: ?1\n",
        );
    }

    let frontend = hyper::upgrade::on(request);
    if let Err(error) =
        datagram::spawn_relay(frontend, target, host.clone(), route_path.clone()).await
    {
        warn!(%host, path = %route_path, %error, "fanout datagram backend unavailable");
        return text_response(StatusCode::BAD_GATEWAY, "backend unavailable\n");
    }

    let mut response = empty_response(StatusCode::SWITCHING_PROTOCOLS);
    response
        .headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("Upgrade"));
    response
        .headers_mut()
        .insert(UPGRADE, HeaderValue::from_static(datagram::UPGRADE_TOKEN));
    response
        .headers_mut()
        .insert(CAPSULE_PROTOCOL, HeaderValue::from_static("?1"));
    response
}

fn has_upgrade_token<B>(request: &Request<B>, token: &str) -> bool {
    is_upgrade_request(request)
        && request
            .headers()
            .get(UPGRADE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case(token))
}

async fn file_response(
    method: &Method,
    source: &Path,
    host: &str,
    route_path: &str,
) -> Response<ProxyBody> {
    if method != Method::GET && method != Method::HEAD {
        let mut response = text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed\n");
        response
            .headers_mut()
            .insert(ALLOW, HeaderValue::from_static("GET, HEAD"));
        return response;
    }

    let contents = match fs::read(source).await {
        Ok(contents) => contents,
        Err(error) => {
            warn!(%host, path = %route_path, source = %source.display(), %error, "fanout file unavailable");
            return text_response(StatusCode::BAD_GATEWAY, "file unavailable\n");
        }
    };
    let content_length = contents.len();
    let body = if method == Method::HEAD {
        Bytes::new()
    } else {
        Bytes::from(contents)
    };
    let mut response = bytes_response(StatusCode::OK, body);
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if source
        .extension()
        .is_some_and(|extension| extension == "json")
    {
        response
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    }
    if let Ok(value) = HeaderValue::from_str(&content_length.to_string()) {
        response.headers_mut().insert(CONTENT_LENGTH, value);
    }
    response
}

fn tunnel_target_for_path(fanout: &FanoutConfig, path: &str) -> Option<TunnelTarget> {
    if let Some(route) = fanout.tunnels.iter().find(|route| route.path == path) {
        return Some(route.target.clone());
    }
    fanout
        .ranges
        .iter()
        .filter_map(|range| {
            tunnel_range_match(range, path).map(|target| (range.path_prefix.len(), target))
        })
        .max_by_key(|(prefix_len, _)| *prefix_len)
        .map(|(_, target)| target)
}

fn tunnel_range_match(range: &TunnelRangeRoute, path: &str) -> Option<TunnelTarget> {
    let suffix = path.strip_prefix(&range.path_prefix)?;
    if suffix.is_empty() || suffix.contains('/') {
        return None;
    }
    let index = suffix.parse::<u16>().ok()?;
    if !(range.first..=range.last).contains(&index) {
        return None;
    }
    let offset = index.checked_sub(range.first)?;
    match range.target {
        PortRangeTarget::Tcp { host, port_start } => Some(TunnelTarget::Tcp {
            address: SocketAddr::new(host, port_start.checked_add(offset)?),
        }),
        PortRangeTarget::Udp { host, port_start } => Some(TunnelTarget::Udp {
            address: SocketAddr::new(host, port_start.checked_add(offset)?),
        }),
    }
}

async fn tunnel_stream<S>(
    frontend: hyper::upgrade::OnUpgrade,
    mut backend: S,
    host: String,
    target: String,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let frontend = match frontend.await {
        Ok(frontend) => frontend,
        Err(error) => {
            debug!(%host, %target, %error, "CONNECT upgrade failed");
            return;
        }
    };
    let mut frontend = TokioIo::new(frontend);
    if let Err(error) = tokio::io::copy_bidirectional_with_sizes(
        &mut frontend,
        &mut backend,
        TUNNEL_BUFFER_BYTES,
        TUNNEL_BUFFER_BYTES,
    )
    .await
    {
        debug!(%host, %target, %error, "stream tunnel ended with error");
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
    if let Err(error) = tokio::io::copy_bidirectional_with_sizes(
        &mut frontend,
        &mut backend,
        TUNNEL_BUFFER_BYTES,
        TUNNEL_BUFFER_BYTES,
    )
    .await
    {
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

fn is_upgrade_request<B>(request: &Request<B>) -> bool {
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
    headers.remove(FORWARDED);
    if let Ok(value) = HeaderValue::from_str(host) {
        headers.insert(X_FORWARDED_HOST, value);
    }
    headers.insert(X_FORWARDED_PROTO, HeaderValue::from_static("https"));
    if let Ok(value) = HeaderValue::from_str(&peer_ip.to_string()) {
        headers.insert(X_FORWARDED_FOR, value.clone());
        headers.insert(X_REAL_IP, value);
    }
}

fn bytes_response(status: StatusCode, body: Bytes) -> Response<ProxyBody> {
    let body = Full::new(body)
        .map_err(|never| -> BoxError { match never {} })
        .boxed();
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response
}

fn empty_response(status: StatusCode) -> Response<ProxyBody> {
    bytes_response(status, Bytes::new())
}

fn text_response(status: StatusCode, body: &'static str) -> Response<ProxyBody> {
    bytes_response(status, Bytes::from_static(body.as_bytes()))
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
    #[test]
    fn overwrites_client_supplied_forwarding_identity() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(FORWARDED, HeaderValue::from_static("for=203.0.113.10"));
        headers.insert(X_FORWARDED_FOR, HeaderValue::from_static("203.0.113.10"));
        headers.insert(X_REAL_IP, HeaderValue::from_static("203.0.113.10"));

        set_forwarded_headers(
            &mut headers,
            "grafana.example.com",
            IpAddr::from([100, 64, 0, 7]),
        );

        assert!(!headers.contains_key(FORWARDED));
        assert_eq!(
            headers.get(X_FORWARDED_FOR),
            Some(&HeaderValue::from_static("100.64.0.7"))
        );
        assert_eq!(
            headers.get(X_REAL_IP),
            Some(&HeaderValue::from_static("100.64.0.7"))
        );
    }

    #[test]
    fn parses_flat_generic_tunnel_config() -> Result<(), Box<dyn std::error::Error>> {
        let config: NodeConfig = toml::from_str(
            r#"
node_id = "test"
domain = "example.com"

[services]

[fanouts.workers]

[[fanouts.workers.tunnels]]
path = "/control"
transport = "unix-stream"
socket = "/run/example/control.sock"

[[fanouts.workers.tunnels]]
path = "/dns"
transport = "udp"
address = "127.0.0.1:5353"

[[fanouts.workers.ranges]]
path_prefix = "/tcp/"
first = 1
last = 30
transport = "tcp"
host = "127.0.0.1"
port_start = 17400

[[fanouts.workers.ranges]]
path_prefix = "/udp/"
first = 1
last = 30
transport = "udp"
host = "127.0.0.1"
port_start = 18400
"#,
        )?;
        config.validate()?;
        let fanout = &config.fanouts["workers"];
        assert_eq!(fanout.tunnels.len(), 2);
        assert_eq!(fanout.ranges.len(), 2);
        Ok(())
    }

    #[test]
    fn maps_exact_and_numeric_fanout_paths_to_targets() {
        let fanout = FanoutConfig {
            files: Vec::new(),
            tunnels: vec![certifex_core::TunnelRoute {
                path: "/control".to_owned(),
                target: TunnelTarget::UnixStream {
                    socket: "/run/example/control.sock".into(),
                },
            }],
            ranges: vec![
                TunnelRangeRoute {
                    path_prefix: "/tcp/".to_owned(),
                    first: 1,
                    last: 30,
                    target: PortRangeTarget::Tcp {
                        host: IpAddr::from([127, 0, 0, 1]),
                        port_start: 17_400,
                    },
                },
                TunnelRangeRoute {
                    path_prefix: "/udp/".to_owned(),
                    first: 1,
                    last: 30,
                    target: PortRangeTarget::Udp {
                        host: IpAddr::from([127, 0, 0, 1]),
                        port_start: 18_400,
                    },
                },
            ],
        };
        assert_eq!(
            tunnel_target_for_path(&fanout, "/control"),
            Some(TunnelTarget::UnixStream {
                socket: "/run/example/control.sock".into(),
            })
        );
        assert_eq!(
            tunnel_target_for_path(&fanout, "/tcp/1"),
            Some(TunnelTarget::Tcp {
                address: SocketAddr::from(([127, 0, 0, 1], 17_400)),
            })
        );
        assert_eq!(
            tunnel_target_for_path(&fanout, "/udp/2"),
            Some(TunnelTarget::Udp {
                address: SocketAddr::from(([127, 0, 0, 1], 18_401)),
            })
        );
        assert_eq!(tunnel_target_for_path(&fanout, "/tcp/0"), None);
        assert_eq!(tunnel_target_for_path(&fanout, "/tcp/31"), None);
        assert_eq!(tunnel_target_for_path(&fanout, "/tcp/1/extra"), None);
    }
}

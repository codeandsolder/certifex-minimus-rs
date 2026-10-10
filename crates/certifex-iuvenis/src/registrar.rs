use bytes::Bytes;
use certifex_core::{NodeRegistration, RegistrationResponse};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, StatusCode, header::CONTENT_TYPE};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use thiserror::Error;

const MAX_RESPONSE_BODY_BYTES: usize = 1024 * 1024;

type HttpClient = Client<HttpConnector, Full<Bytes>>;

#[derive(Debug, Error)]
pub enum RegistrarError {
    #[error("failed to encode registration JSON: {0}")]
    EncodeJson(serde_json::Error),
    #[error("invalid registrar request: {0}")]
    Request(#[from] hyper::http::Error),
    #[error("registrar request failed: {0}")]
    Http(#[from] hyper_util::client::legacy::Error),
    #[error("failed to read registrar response body: {0}")]
    Body(String),
    #[error("registrar returned HTTP {status}: {preview}")]
    Status { status: StatusCode, preview: String },
    #[error("invalid registrar response JSON: {0}")]
    DecodeJson(serde_json::Error),
}

#[derive(Clone)]
pub struct RegistrarClient {
    client: HttpClient,
}

impl RegistrarClient {
    #[must_use]
    pub fn new() -> Self {
        let mut connector = HttpConnector::new();
        connector.enforce_http(true);
        Self {
            client: Client::builder(TokioExecutor::new()).build(connector),
        }
    }

    /// Registers the node with the tailnet-only Certifex registrar.
    ///
    /// # Errors
    /// Returns an error if the request cannot be encoded or sent, the response is too large,
    /// the registrar returns a non-success status, or its JSON response is invalid.
    pub async fn register(
        &self,
        endpoint: &str,
        registration: &NodeRegistration,
    ) -> Result<RegistrationResponse, RegistrarError> {
        let request = registration_request(endpoint, registration)?;
        let response = self.client.request(request).await?;
        let status = response.status();
        let body = Limited::new(response.into_body(), MAX_RESPONSE_BODY_BYTES)
            .collect()
            .await
            .map_err(|error| RegistrarError::Body(error.to_string()))?
            .to_bytes();
        if !status.is_success() {
            return Err(RegistrarError::Status {
                status,
                preview: String::from_utf8_lossy(&body[..body.len().min(4096)]).into_owned(),
            });
        }
        serde_json::from_slice(&body).map_err(RegistrarError::DecodeJson)
    }
}

fn registration_request(
    endpoint: &str,
    registration: &NodeRegistration,
) -> Result<Request<Full<Bytes>>, RegistrarError> {
    let body = serde_json::to_vec(registration).map_err(RegistrarError::EncodeJson)?;
    Ok(Request::post(endpoint)
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))?)
}

#[cfg(test)]
mod tests {
    use std::{io, net::IpAddr};

    use http_body_util::BodyExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    async fn spawn_response(
        status: &'static str,
        response_body: Vec<u8>,
    ) -> io::Result<(
        std::net::SocketAddr,
        tokio::task::JoinHandle<io::Result<Vec<u8>>>,
    )> {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
        let address = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut headers = Vec::with_capacity(2048);
            let mut byte = [0_u8; 1];
            while !headers.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await?;
                headers.push(byte[0]);
                if headers.len() > 64 * 1024 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "request headers too large",
                    ));
                }
            }

            let header_text = std::str::from_utf8(&headers)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            let content_length = header_text
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find_map(|(name, value)| {
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "missing Content-Length")
                })?;
            let mut body = vec![0_u8; content_length];
            stream.read_exact(&mut body).await?;
            headers.extend_from_slice(&body);

            let response_head = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response_body.len()
            );
            stream.write_all(response_head.as_bytes()).await?;
            stream.write_all(&response_body).await?;
            stream.shutdown().await?;
            Ok(headers)
        });
        Ok((address, task))
    }

    fn registration() -> NodeRegistration {
        NodeRegistration {
            node_id: "node".to_owned(),
            tailscale_ip: IpAddr::from([100, 64, 0, 1]),
            hostnames: vec!["svc.example.com".to_owned()],
            csr_pem: "csr".to_owned(),
            installed_generation: Some(7),
        }
    }

    #[tokio::test]
    async fn request_is_plain_http_json_post() -> Result<(), Box<dyn std::error::Error>> {
        let registration = registration();
        let request = registration_request(
            "http://certifex.example.com:7443/v1/register",
            &registration,
        )?;
        assert_eq!(request.method(), hyper::Method::POST);
        assert_eq!(request.uri().scheme_str(), Some("http"));
        assert_eq!(request.uri().path(), "/v1/register");
        assert_eq!(
            request.headers().get(CONTENT_TYPE),
            Some(&hyper::header::HeaderValue::from_static("application/json"))
        );
        let body = request.into_body().collect().await?.to_bytes();
        assert_eq!(
            serde_json::from_slice::<NodeRegistration>(&body)?,
            registration
        );
        Ok(())
    }

    #[tokio::test]
    async fn client_round_trips_registration() -> Result<(), Box<dyn std::error::Error>> {
        let response_body = serde_json::to_vec(&RegistrationResponse { certificate: None })?;
        let (address, server) = spawn_response("200 OK", response_body).await?;
        let registration = registration();
        let endpoint = format!("http://{address}/v1/register");

        assert_eq!(
            RegistrarClient::new()
                .register(&endpoint, &registration)
                .await?,
            RegistrationResponse { certificate: None }
        );

        let request = server
            .await
            .map_err(|error| io::Error::other(error.to_string()))??;
        let header_end = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing header terminator")
            })?;
        assert_eq!(
            serde_json::from_slice::<NodeRegistration>(&request[header_end + 4..])?,
            registration
        );
        Ok(())
    }

    #[tokio::test]
    async fn client_rejects_oversized_response() -> Result<(), Box<dyn std::error::Error>> {
        let oversized = vec![b'x'; MAX_RESPONSE_BODY_BYTES + 1];
        let (address, server) = spawn_response("200 OK", oversized).await?;
        let endpoint = format!("http://{address}/v1/register");

        assert!(
            RegistrarClient::new()
                .register(&endpoint, &registration())
                .await
                .is_err()
        );
        server
            .await
            .map_err(|error| io::Error::other(error.to_string()))??;
        Ok(())
    }
}

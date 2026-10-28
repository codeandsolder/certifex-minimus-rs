use bytes::Bytes;
use certifex_core::{
    HandoffActivationRequest, HandoffActivationResponse, HandoffApproval, HandoffApprovalResponse,
    HandoffOfferResponse, NodeRegistration, RegistrationResponse,
};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, StatusCode, header::CONTENT_TYPE};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;

const MAX_RESPONSE_BODY_BYTES: usize = 1024 * 1024;

type HttpClient = Client<HttpConnector, Full<Bytes>>;

#[derive(Debug, Error)]
pub enum RegistrarError {
    #[error("failed to encode registrar JSON: {0}")]
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
    pub async fn register(
        &self,
        endpoint: &str,
        registration: &NodeRegistration,
    ) -> Result<RegistrationResponse, RegistrarError> {
        self.post_json(endpoint, registration).await
    }

    /// Creates or retrieves an explicit hostname handoff offer for this node registration.
    pub async fn offer_handoff(
        &self,
        endpoint: &str,
        registration: &NodeRegistration,
    ) -> Result<HandoffOfferResponse, RegistrarError> {
        self.post_json(endpoint, registration).await
    }

    /// Approves a pending handoff as one of its current source nodes.
    pub async fn approve_handoff(
        &self,
        endpoint: &str,
        approval: &HandoffApproval,
    ) -> Result<HandoffApprovalResponse, RegistrarError> {
        self.post_json(endpoint, approval).await
    }

    /// Confirms that a prepared handoff certificate has been installed by its destination.
    pub async fn activate_handoff(
        &self,
        endpoint: &str,
        activation: &HandoffActivationRequest,
    ) -> Result<HandoffActivationResponse, RegistrarError> {
        self.post_json(endpoint, activation).await
    }

    async fn post_json<RequestBody, ResponseBody>(
        &self,
        endpoint: &str,
        body: &RequestBody,
    ) -> Result<ResponseBody, RegistrarError>
    where
        RequestBody: Serialize + Sync,
        ResponseBody: DeserializeOwned,
    {
        let request = json_request(endpoint, body)?;
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

fn json_request<T: Serialize>(
    endpoint: &str,
    value: &T,
) -> Result<Request<Full<Bytes>>, RegistrarError> {
    let body = serde_json::to_vec(value).map_err(RegistrarError::EncodeJson)?;
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
        let request = json_request(
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
        let response_body = serde_json::to_vec(&RegistrationResponse {
            certificate: None,
            handoff_activation: None,
        })?;
        let (address, server) = spawn_response("200 OK", response_body).await?;
        let registration = registration();
        let endpoint = format!("http://{address}/v1/register");

        assert_eq!(
            RegistrarClient::new()
                .register(&endpoint, &registration)
                .await?,
            RegistrationResponse {
                certificate: None,
                handoff_activation: None,
            }
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
    async fn client_round_trips_handoff_approval() -> Result<(), Box<dyn std::error::Error>> {
        let response = HandoffApprovalResponse {
            offer_id: "abc".to_owned(),
            ready: true,
            remaining_node_ids: Vec::new(),
        };
        let (address, server) = spawn_response("200 OK", serde_json::to_vec(&response)?).await?;
        let approval = HandoffApproval {
            offer_id: "abc".to_owned(),
            source: NodeRegistration {
                node_id: "old".to_owned(),
                tailscale_ip: IpAddr::from([100, 64, 0, 2]),
                hostnames: vec!["svc.example.com".to_owned()],
                csr_pem: "csr".to_owned(),
                installed_generation: Some(7),
            },
        };
        let endpoint = format!("http://{address}/v1/handoff/approve");
        assert_eq!(
            RegistrarClient::new()
                .approve_handoff(&endpoint, &approval)
                .await?,
            response
        );
        server
            .await
            .map_err(|error| io::Error::other(error.to_string()))??;
        Ok(())
    }

    #[tokio::test]
    async fn client_round_trips_handoff_activation() -> Result<(), Box<dyn std::error::Error>> {
        let response = HandoffActivationResponse {
            offer_id: "abc".to_owned(),
        };
        let (address, server) = spawn_response("200 OK", serde_json::to_vec(&response)?).await?;
        let activation = HandoffActivationRequest {
            offer_id: "abc".to_owned(),
            node_id: "new".to_owned(),
            tailscale_ip: IpAddr::from([100, 64, 0, 3]),
            generation: 8,
        };
        let endpoint = format!("http://{address}/v1/handoff/activate");
        assert_eq!(
            RegistrarClient::new()
                .activate_handoff(&endpoint, &activation)
                .await?,
            response
        );
        server
            .await
            .map_err(|error| io::Error::other(error.to_string()))??;
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

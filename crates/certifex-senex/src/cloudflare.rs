use std::net::IpAddr;

use reqwest::Client;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

const API_BASE: &str = "https://api.cloudflare.com/client/v4";
const MANAGED_COMMENT: &str = "managed by certifex-minimus-rs";

#[derive(Debug, Error)]
pub enum CloudflareError {
    #[error("Cloudflare HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Cloudflare API rejected the request: {0}")]
    Api(String),
    #[error("Cloudflare token cannot access zone `{0}`")]
    ZoneNotFound(String),
    #[error("multiple A records exist for `{0}`")]
    MultipleAddressRecords(String),
    #[error("only IPv4 Tailscale addresses are supported in v1: {0}")]
    UnsupportedIp(IpAddr),
}

#[derive(Clone)]
pub struct Cloudflare {
    client: Client,
    token: String,
    zone_id: String,
    api_base: String,
}

impl Cloudflare {
    /// Resolves a zone by name using the supplied scoped Cloudflare token.
    ///
    /// # Errors
    /// Returns an error when the request fails or the token cannot see exactly one matching zone.
    pub async fn for_zone(
        client: Client,
        token: String,
        zone: &str,
    ) -> Result<Self, CloudflareError> {
        let temporary = Self {
            client,
            token,
            zone_id: String::new(),
            api_base: API_BASE.to_owned(),
        };
        let zones: Vec<Zone> = temporary
            .get("/zones", &[("name", zone), ("status", "active")])
            .await?;
        let [zone] = zones.as_slice() else {
            return Err(CloudflareError::ZoneNotFound(zone.to_owned()));
        };
        Ok(Self {
            zone_id: zone.id.clone(),
            ..temporary
        })
    }

    /// Ensures a DNS-only A record maps `name` directly to the supplied Tailscale address.
    ///
    /// # Errors
    /// Returns an error for non-IPv4 addresses, ambiguous existing records, or API failures.
    pub async fn ensure_a(&self, name: &str, ip: IpAddr) -> Result<(), CloudflareError> {
        let IpAddr::V4(ip) = ip else {
            return Err(CloudflareError::UnsupportedIp(ip));
        };
        let content = ip.to_string();
        let records = self.records("A", name).await?;
        match records.as_slice() {
            [] => {
                let request = RecordWrite {
                    kind: "A",
                    name,
                    content: &content,
                    ttl: 1,
                    proxied: Some(false),
                    comment: Some(MANAGED_COMMENT),
                };
                let _: DnsRecord = self.post(&self.records_path(), &request).await?;
            }
            [record] => {
                if record.content != content
                    || record.proxied.unwrap_or(false)
                    || record.comment.as_deref() != Some(MANAGED_COMMENT)
                {
                    let request = RecordPatch {
                        content: &content,
                        ttl: 1,
                        proxied: false,
                        comment: MANAGED_COMMENT,
                    };
                    let _: DnsRecord = self
                        .patch(&format!("{}/{}", self.records_path(), record.id), &request)
                        .await?;
                }
            }
            _ => return Err(CloudflareError::MultipleAddressRecords(name.to_owned())),
        }
        Ok(())
    }

    /// Deletes an A record only when it is owned by Certifex.
    ///
    /// # Errors
    /// Returns an error when Cloudflare cannot list or delete the record.
    pub async fn delete_owned_a(&self, name: &str) -> Result<(), CloudflareError> {
        for record in self.records("A", name).await? {
            if record.comment.as_deref() == Some(MANAGED_COMMENT) {
                self.delete_record(&record.id).await?;
            }
        }
        Ok(())
    }

    /// Creates a temporary TXT record and returns its Cloudflare record ID.
    ///
    /// # Errors
    /// Returns an error when Cloudflare rejects the record.
    pub async fn create_txt(&self, name: &str, value: &str) -> Result<String, CloudflareError> {
        let request = RecordWrite {
            kind: "TXT",
            name,
            content: value,
            ttl: 60,
            proxied: None,
            comment: Some(MANAGED_COMMENT),
        };
        let record: DnsRecord = self.post(&self.records_path(), &request).await?;
        Ok(record.id)
    }

    /// Deletes a DNS record by Cloudflare record ID.
    ///
    /// # Errors
    /// Returns an error when Cloudflare rejects the deletion.
    pub async fn delete_record(&self, record_id: &str) -> Result<(), CloudflareError> {
        let path = format!("{}/{}", self.records_path(), record_id);
        let _: DeleteResult = self.delete(&path).await?;
        Ok(())
    }

    async fn records(&self, kind: &str, name: &str) -> Result<Vec<DnsRecord>, CloudflareError> {
        self.get(&self.records_path(), &[("type", kind), ("name", name)])
            .await
    }

    fn records_path(&self) -> String {
        format!("/zones/{}/dns_records", self.zone_id)
    }

    async fn get<T: DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, &str)],
    ) -> Result<T, CloudflareError> {
        let response = self
            .client
            .get(format!("{}{}", self.api_base, path))
            .bearer_auth(&self.token)
            .query(query)
            .send()
            .await?;
        self.decode(response).await
    }

    async fn post<T: DeserializeOwned, B: Serialize + Sync + ?Sized>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, CloudflareError> {
        let response = self
            .client
            .post(format!("{}{}", self.api_base, path))
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .await?;
        self.decode(response).await
    }

    async fn patch<T: DeserializeOwned, B: Serialize + Sync + ?Sized>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, CloudflareError> {
        let response = self
            .client
            .patch(format!("{}{}", self.api_base, path))
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .await?;
        self.decode(response).await
    }

    async fn delete<T: DeserializeOwned>(&self, path: &str) -> Result<T, CloudflareError> {
        let response = self
            .client
            .delete(format!("{}{}", self.api_base, path))
            .bearer_auth(&self.token)
            .send()
            .await?;
        self.decode(response).await
    }

    async fn decode<T: DeserializeOwned>(
        &self,
        response: reqwest::Response,
    ) -> Result<T, CloudflareError> {
        let response = response.error_for_status()?;
        let envelope = response.json::<Envelope<T>>().await?;
        if envelope.success {
            Ok(envelope.result)
        } else {
            let message = envelope
                .errors
                .into_iter()
                .map(|error| format!("{}: {}", error.code, error.message))
                .collect::<Vec<_>>()
                .join("; ");
            Err(CloudflareError::Api(message))
        }
    }
}

#[derive(Debug, Deserialize)]
struct Zone {
    id: String,
}

#[derive(Debug, Deserialize)]
struct DnsRecord {
    id: String,
    content: String,
    proxied: Option<bool>,
    comment: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DeleteResult {
    #[allow(
        dead_code,
        reason = "successful decoding validates the Cloudflare delete response"
    )]
    id: String,
}

#[derive(Debug, Serialize)]
struct RecordWrite<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    name: &'a str,
    content: &'a str,
    ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    proxied: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct RecordPatch<'a> {
    content: &'a str,
    ttl: u32,
    proxied: bool,
    comment: &'a str,
}

#[derive(Debug, Deserialize)]
struct Envelope<T> {
    success: bool,
    result: T,
    #[serde(default)]
    errors: Vec<ApiError>,
}

#[derive(Debug, Deserialize)]
struct ApiError {
    code: i64,
    message: String,
}

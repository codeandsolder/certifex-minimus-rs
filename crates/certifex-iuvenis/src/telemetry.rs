use lurkmoar::{Client, ClientBuilder};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tracing::warn;

#[derive(Clone, Default)]
pub struct Telemetry {
    inner: Option<Arc<Inner>>,
}

struct Inner {
    client: Client,
    counters: Mutex<BTreeMap<String, u64>>,
}

impl Telemetry {
    pub fn new(
        endpoint: Option<&str>,
        instance: &str,
        spool_dir: &Path,
    ) -> Result<Self, lurkmoar::Error> {
        let Some(endpoint) = endpoint else {
            return Ok(Self::default());
        };
        let client = ClientBuilder::new(endpoint)
            .static_label("job", "certifex")
            .static_label("component", "iuvenis")
            .static_label("instance", instance)
            .static_label("resolution", "raw")
            .spool(spool_dir, 10 * 1024 * 1024)
            .build()?;
        Ok(Self {
            inner: Some(Arc::new(Inner {
                client,
                counters: Mutex::new(BTreeMap::new()),
            })),
        })
    }

    pub fn reconcile_ok(&self) {
        self.increment("certifex_reconciliations_total", &[]);
    }

    pub fn reconcile_failed(&self) {
        self.increment("certifex_reconcile_failures_total", &[]);
    }

    pub fn certificate_installed(&self, generation: u64) {
        self.increment("certifex_certificate_installs_total", &[]);
        self.set(
            "certifex_certificate_generation",
            metric_u64(generation),
            &[],
        );
    }

    pub fn tls_handshake_failed(&self) {
        self.increment("certifex_tls_handshake_failures_total", &[]);
    }

    pub fn request(&self, host: &str, status: u16) {
        let class = format!("{}xx", status / 100);
        self.increment(
            "certifex_proxy_requests_total",
            &[("host", host), ("status_class", class.as_str())],
        );
    }

    pub fn backend_failed(&self, host: &str) {
        self.increment("certifex_backend_failures_total", &[("host", host)]);
    }

    fn increment(&self, name: &str, labels: &[(&str, &str)]) {
        let Some(inner) = &self.inner else {
            return;
        };
        let mut key = name.to_string();
        for (label, value) in labels {
            key.push('\0');
            key.push_str(label);
            key.push('=');
            key.push_str(value);
        }
        let value = match inner.counters.lock() {
            Ok(mut counters) => {
                let value = counters.entry(key).or_insert(0);
                *value = value.saturating_add(1);
                *value
            }
            Err(error) => {
                warn!(%error, metric = name, "Certifex telemetry counter lock poisoned");
                return;
            }
        };
        self.set(name, metric_u64(value), labels);
    }

    fn set(&self, name: &str, value: f64, labels: &[(&str, &str)]) {
        let Some(inner) = &self.inner else {
            return;
        };
        if let Err(error) = inner.client.sample(name, value, labels.iter().copied()) {
            warn!(%error, metric = name, "failed to queue Certifex telemetry");
        }
    }
}

#[expect(
    clippy::cast_precision_loss,
    reason = "the metrics backend stores samples as f64; retaining the full f64 integer range is preferable to clamping at u32::MAX"
)]
const fn metric_u64(value: u64) -> f64 {
    value as f64
}

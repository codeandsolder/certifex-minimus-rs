use lurkmoar::{Client, ClientBuilder};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{
        Arc, RwLock, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::Duration,
};
use tracing::warn;

const FLUSH_INTERVAL: Duration = Duration::from_secs(1);
const HTTP_STATUS_CLASSES: usize = 5;

#[derive(Clone, Default)]
pub struct Telemetry {
    inner: Option<Arc<Inner>>,
}

struct Inner {
    client: Client,
    metrics: Metrics,
}

#[derive(Default)]
struct Metrics {
    reconciliations: AtomicU64,
    reconcile_failures: AtomicU64,
    certificate_installs: AtomicU64,
    certificate_generation: AtomicU64,
    tls_handshake_failures: AtomicU64,
    hosts: RwLock<BTreeMap<String, Arc<HostMetrics>>>,
    dirty: AtomicBool,
}

struct HostMetrics {
    requests: [AtomicU64; HTTP_STATUS_CLASSES],
    backend_failures: AtomicU64,
}

impl Default for HostMetrics {
    fn default() -> Self {
        Self {
            requests: std::array::from_fn(|_| AtomicU64::new(0)),
            backend_failures: AtomicU64::new(0),
        }
    }
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
        let inner = Arc::new(Inner {
            client,
            metrics: Metrics::default(),
        });
        spawn_flush_worker(Arc::downgrade(&inner))?;
        Ok(Self { inner: Some(inner) })
    }

    pub fn reconcile_ok(&self) {
        if let Some(inner) = &self.inner {
            inner.increment(&inner.metrics.reconciliations);
        }
    }

    pub fn reconcile_failed(&self) {
        if let Some(inner) = &self.inner {
            inner.increment(&inner.metrics.reconcile_failures);
        }
    }

    pub fn certificate_installed(&self, generation: u64) {
        if let Some(inner) = &self.inner {
            inner.increment(&inner.metrics.certificate_installs);
            inner
                .metrics
                .certificate_generation
                .store(generation, Ordering::Relaxed);
            inner.mark_dirty();
        }
    }

    pub fn tls_handshake_failed(&self) {
        if let Some(inner) = &self.inner {
            inner.increment(&inner.metrics.tls_handshake_failures);
        }
    }

    pub fn request(&self, host: &str, status: u16) {
        let Some(inner) = &self.inner else {
            return;
        };
        let Some(index) = status_class_index(status) else {
            return;
        };
        let Some(metrics) = inner.metrics.host(host) else {
            return;
        };
        metrics.requests[index].fetch_add(1, Ordering::Relaxed);
        inner.mark_dirty();
    }

    pub fn backend_failed(&self, host: &str) {
        let Some(inner) = &self.inner else {
            return;
        };
        let Some(metrics) = inner.metrics.host(host) else {
            return;
        };
        metrics.backend_failures.fetch_add(1, Ordering::Relaxed);
        inner.mark_dirty();
    }
}

impl Inner {
    fn increment(&self, counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
        self.mark_dirty();
    }

    fn mark_dirty(&self) {
        self.metrics.dirty.store(true, Ordering::Release);
    }

    fn flush_if_dirty(&self) {
        if !self.metrics.dirty.swap(false, Ordering::AcqRel) {
            return;
        }
        let text = match self.metrics.snapshot() {
            Ok(text) => text,
            Err(error) => {
                self.mark_dirty();
                warn!(%error, "failed to render Certifex telemetry snapshot");
                return;
            }
        };
        if text.is_empty() {
            return;
        }
        if let Err(error) = self.client.submit_prometheus_text(text) {
            self.mark_dirty();
            warn!(%error, "failed to queue Certifex telemetry snapshot");
        }
    }
}

impl Metrics {
    fn host(&self, host: &str) -> Option<Arc<HostMetrics>> {
        {
            let hosts = match self.hosts.read() {
                Ok(hosts) => hosts,
                Err(error) => {
                    warn!(%error, "Certifex telemetry host map read lock poisoned");
                    return None;
                }
            };
            if let Some(metrics) = hosts.get(host) {
                return Some(Arc::clone(metrics));
            }
        }

        let mut hosts = match self.hosts.write() {
            Ok(hosts) => hosts,
            Err(error) => {
                warn!(%error, "Certifex telemetry host map write lock poisoned");
                return None;
            }
        };
        Some(Arc::clone(
            hosts
                .entry(host.to_owned())
                .or_insert_with(|| Arc::new(HostMetrics::default())),
        ))
    }

    fn snapshot(&self) -> Result<String, std::fmt::Error> {
        use std::fmt::Write as _;

        let mut text = String::with_capacity(1024);
        append_nonzero(
            &mut text,
            "certifex_reconciliations_total",
            self.reconciliations.load(Ordering::Relaxed),
        )?;
        append_nonzero(
            &mut text,
            "certifex_reconcile_failures_total",
            self.reconcile_failures.load(Ordering::Relaxed),
        )?;
        append_nonzero(
            &mut text,
            "certifex_certificate_installs_total",
            self.certificate_installs.load(Ordering::Relaxed),
        )?;
        append_nonzero(
            &mut text,
            "certifex_certificate_generation",
            self.certificate_generation.load(Ordering::Relaxed),
        )?;
        append_nonzero(
            &mut text,
            "certifex_tls_handshake_failures_total",
            self.tls_handshake_failures.load(Ordering::Relaxed),
        )?;

        let hosts = match self.hosts.read() {
            Ok(hosts) => hosts,
            Err(error) => {
                warn!(%error, "Certifex telemetry host map snapshot lock poisoned");
                return Ok(text);
            }
        };
        for (host, metrics) in &*hosts {
            let host = escape_label_value(host);
            for (index, counter) in metrics.requests.iter().enumerate() {
                let value = counter.load(Ordering::Relaxed);
                if value != 0 {
                    writeln!(
                        text,
                        "certifex_proxy_requests_total{{host=\"{host}\",status_class=\"{}xx\"}} {value}",
                        index + 1
                    )?;
                }
            }
            let backend_failures = metrics.backend_failures.load(Ordering::Relaxed);
            if backend_failures != 0 {
                writeln!(
                    text,
                    "certifex_backend_failures_total{{host=\"{host}\"}} {backend_failures}"
                )?;
            }
        }
        drop(hosts);
        Ok(text)
    }
}

fn spawn_flush_worker(inner: Weak<Inner>) -> Result<(), lurkmoar::Error> {
    thread::Builder::new()
        .name("certifex-telemetry".to_owned())
        .spawn(move || {
            loop {
                thread::sleep(FLUSH_INTERVAL);
                let Some(inner) = inner.upgrade() else {
                    return;
                };
                inner.flush_if_dirty();
            }
        })?;
    Ok(())
}

fn append_nonzero(text: &mut String, name: &str, value: u64) -> Result<(), std::fmt::Error> {
    use std::fmt::Write as _;

    if value != 0 {
        writeln!(text, "{name} {value}")?;
    }
    Ok(())
}

fn status_class_index(status: u16) -> Option<usize> {
    match status / 100 {
        class @ 1..=5 => Some(usize::from(class - 1)),
        _ => None,
    }
}

fn escape_label_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_telemetry_is_a_noop() {
        let telemetry = Telemetry::default();
        telemetry.request("grafana.example.com", 200);
        telemetry.backend_failed("grafana.example.com");
        telemetry.reconcile_ok();
    }

    #[test]
    fn snapshot_coalesces_absolute_request_counters() -> Result<(), std::fmt::Error> {
        let metrics = Metrics::default();
        let Some(host) = metrics.host("grafana.example.com") else {
            return Err(std::fmt::Error);
        };
        host.requests[1].fetch_add(3, Ordering::Relaxed);
        host.requests[4].fetch_add(2, Ordering::Relaxed);
        host.backend_failures.fetch_add(1, Ordering::Relaxed);
        metrics.reconciliations.fetch_add(4, Ordering::Relaxed);

        let snapshot = metrics.snapshot()?;
        assert!(snapshot.contains("certifex_reconciliations_total 4\n"));
        assert!(snapshot.contains(
            "certifex_proxy_requests_total{host=\"grafana.example.com\",status_class=\"2xx\"} 3\n"
        ));
        assert!(snapshot.contains(
            "certifex_proxy_requests_total{host=\"grafana.example.com\",status_class=\"5xx\"} 2\n"
        ));
        assert!(
            snapshot.contains("certifex_backend_failures_total{host=\"grafana.example.com\"} 1\n")
        );
        Ok(())
    }

    #[test]
    fn status_classes_cover_valid_http_statuses() {
        assert_eq!(status_class_index(100), Some(0));
        assert_eq!(status_class_index(299), Some(1));
        assert_eq!(status_class_index(404), Some(3));
        assert_eq!(status_class_index(599), Some(4));
        assert_eq!(status_class_index(99), None);
        assert_eq!(status_class_index(600), None);
    }

    #[test]
    fn label_values_are_prometheus_escaped() {
        assert_eq!(escape_label_value("a\\b\"c\nd"), "a\\\\b\\\"c\\nd");
    }
}

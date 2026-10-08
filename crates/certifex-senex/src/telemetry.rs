use lurkmoar::{Client, ClientBuilder, Counter};
use std::path::Path;
use tracing::warn;

#[derive(Clone, Default)]
pub struct Telemetry {
    client: Option<Client>,
    registrations: Option<Counter>,
    registration_failures: Option<Counter>,
    certificates_issued: Option<Counter>,
    renewal_failures: Option<Counter>,
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
            .static_label("component", "senex")
            .static_label("instance", instance)
            .static_label("resolution", "raw")
            .spool(spool_dir, 10 * 1024 * 1024)
            .build()?;
        Ok(Self {
            registrations: Some(
                client.counter("certifex_registrations_total", [] as [(&str, &str); 0])?,
            ),
            registration_failures: Some(client.counter(
                "certifex_registration_failures_total",
                [] as [(&str, &str); 0],
            )?),
            certificates_issued: Some(client.counter(
                "certifex_certificates_issued_total",
                [] as [(&str, &str); 0],
            )?),
            renewal_failures: Some(
                client.counter("certifex_renewal_failures_total", [] as [(&str, &str); 0])?,
            ),
            client: Some(client),
        })
    }

    pub fn registration_ok(&self) {
        increment(self.registrations.as_ref(), "registration");
    }

    pub fn registration_failed(&self) {
        increment(self.registration_failures.as_ref(), "registration failure");
    }

    pub fn certificate_issued(&self) {
        increment(self.certificates_issued.as_ref(), "certificate issuance");
    }

    pub fn renewal_failed(&self) {
        increment(self.renewal_failures.as_ref(), "renewal failure");
    }

    pub fn node_state(
        &self,
        node_id: &str,
        generation: u64,
        renew_after: Option<i64>,
        ari_check_after: Option<i64>,
    ) {
        let Some(client) = &self.client else {
            return;
        };
        let labels = [("node_id", node_id)];
        for (name, value) in [
            ("certifex_certificate_generation", metric_u64(generation)),
            (
                "certifex_certificate_renew_after_timestamp_seconds",
                metric_i64(renew_after.unwrap_or_default()),
            ),
            (
                "certifex_certificate_ari_check_after_timestamp_seconds",
                metric_i64(ari_check_after.unwrap_or_default()),
            ),
        ] {
            if let Err(error) = client.sample(name, value, labels) {
                warn!(%error, metric = name, "failed to queue Certifex telemetry");
            }
        }
    }
}

fn increment(counter: Option<&Counter>, what: &str) {
    if let Some(counter) = counter
        && let Err(error) = counter.inc()
    {
        warn!(%error, %what, "failed to queue Certifex telemetry");
    }
}

#[expect(
    clippy::cast_precision_loss,
    reason = "the metrics backend stores samples as f64; retaining the full f64 integer range is preferable to clamping at u32::MAX"
)]
const fn metric_u64(value: u64) -> f64 {
    value as f64
}

#[expect(
    clippy::cast_precision_loss,
    reason = "Unix timestamps are metrics samples; f64 exactly represents all practical timestamp values"
)]
const fn metric_i64(value: i64) -> f64 {
    value as f64
}

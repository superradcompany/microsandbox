//! OTLP exporter — ships per-sandbox metrics to any OTel-compatible
//! backend (Grafana Cloud, Grafana Alloy, otel-collector, …).
//!
//! # Metric names
//!
//! - `microsandbox.cpu.utilization`     — gauge (vCPU-seconds per wall-second; can exceed 1.0)
//! - `microsandbox.memory.usage`        — gauge (bytes)
//! - `microsandbox.memory.limit`        — gauge (bytes)
//! - `microsandbox.disk.bytes_read`     — gauge (cumulative bytes)
//! - `microsandbox.disk.bytes_written`  — gauge (cumulative bytes)
//! - `microsandbox.network.bytes_received` — gauge (cumulative bytes)
//! - `microsandbox.network.bytes_sent`     — gauge (cumulative bytes)
//! - `microsandbox.uptime`              — gauge (seconds)
//!
//! All cumulative byte counters are emitted as gauges carrying the
//! current cumulative value. Downstream `rate()` queries (Prometheus,
//! PromQL-on-OTel) compute throughput from successive samples. We use
//! gauges rather than monotonic counters because each snapshot already
//! carries an absolute cumulative value, and counter add() semantics
//! would require us to track per-sandbox deltas across runs (an
//! avoidable source of bugs).
//!
//! # Default resource attributes
//!
//! Set automatically; `--resource k=v` overrides individual entries:
//!
//! - `service.name = "microsandbox"`
//! - `service.instance.id = <hostname>` (best-effort)
//!
//! # Identity attributes
//!
//! Every datapoint carries a configurable subset of sandbox identity
//! attributes alongside the metric value:
//!
//! - `sandbox.name`    — emitted by default
//! - `sandbox.id`      — emitted by default
//! - `sandbox.run_id`  — opt-in (high cardinality across sandbox restarts)
//! - `sandbox.pid`     — opt-in (high cardinality across sandbox restarts)

use std::sync::{Arc, Weak};

use futures::future::BoxFuture;
use opentelemetry::metrics::{Counter, Gauge, Meter, MeterProvider};
use opentelemetry::{InstrumentationScope, KeyValue};
use opentelemetry_otlp::{
    Compression, MetricExporter as OtlpMetricExporter, Protocol, WithExportConfig, WithTonicConfig,
};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::metrics::data::ResourceMetrics;
use opentelemetry_sdk::metrics::exporter::PushMetricExporter;
use opentelemetry_sdk::metrics::reader::MetricReader;
use opentelemetry_sdk::metrics::{
    InstrumentKind, ManualReader, Pipeline, SdkMeterProvider, Temporality,
};
use tonic::transport::{Certificate, ClientTlsConfig};

use crate::core::{MetricsExportBatch, MetricsExporter, SandboxMetricSnapshot};
use crate::error::{MetricsCollectorError, MetricsCollectorResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Name reported as `otel.scope.name` for instruments built by this exporter.
const SCOPE_NAME: &str = "microsandbox-metrics-collector";

/// Version reported as `otel.scope.version` for instruments built by this
/// exporter. Tracks the msb version (same as the crate version, since the
/// metrics-collector ships in lockstep with the rest of the workspace) so
/// a Prometheus consumer can tell
/// which `msb-metrics` build emitted a series.
///
/// `otel.scope.schema_url` is intentionally left unset — our metric names
/// (`microsandbox.cpu.utilization`, …) are project-specific and do not
/// conform to a published OpenTelemetry semantic-conventions release, so
/// declaring a schema URL would be misleading.
const SCOPE_VERSION: &str = env!("CARGO_PKG_VERSION");

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// OTLP transport protocol.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OtlpProtocol {
    /// gRPC over HTTP/2 (default OTLP port `4317`).
    #[default]
    Grpc,
    /// HTTP/1.1 + Protobuf body (default OTLP port `4318`).
    HttpProtobuf,
}

/// Optional payload compression for OTLP exports.
///
/// Compression is only wired through on the gRPC transport in
/// the current HTTP/Protobuf build. Selecting [`OtlpCompression::Gzip`]
/// together with [`OtlpProtocol::HttpProtobuf`] returns a build-time error.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OtlpCompression {
    /// No compression. Default; preserves prior behavior.
    #[default]
    None,
    /// gzip. gRPC only.
    Gzip,
}

/// Which sandbox identity attributes to emit on each datapoint.
#[derive(Clone, Copy, Debug)]
struct IdentityAttributes {
    emit_name: bool,
    emit_sandbox_id: bool,
    emit_run_id: bool,
    emit_pid: bool,
}

impl Default for IdentityAttributes {
    /// `sandbox.name` + `sandbox.id` by default. `run_id` / `pid` are
    /// opt-in because they create a fresh series per sandbox restart,
    /// which inflates active-series counts on cardinality-billed
    /// backends.
    fn default() -> Self {
        Self {
            emit_name: true,
            emit_sandbox_id: true,
            emit_run_id: false,
            emit_pid: false,
        }
    }
}

/// Bundle of OTel instruments — built once at `OtelExporter::build` time
/// and reused for every datapoint.
#[derive(Clone)]
struct Instruments {
    cpu_utilization: Gauge<f64>,
    memory_usage: Gauge<u64>,
    memory_limit: Gauge<u64>,
    disk_bytes_read: Gauge<u64>,
    disk_bytes_written: Gauge<u64>,
    network_bytes_received: Gauge<u64>,
    network_bytes_sent: Gauge<u64>,
    uptime: Gauge<f64>,
}

/// Instruments describing the collector's own operation, shipped through
/// the same OTLP pipeline so a user can query
/// `rate(microsandbox_collector_exports_success_total[1m])` to confirm
/// the sidecar is actually flowing.
#[derive(Clone)]
struct SelfInstruments {
    exports_success: Counter<u64>,
    exports_failure: Counter<u64>,
    collections_dropped: Counter<u64>,
    last_success_timestamp: Gauge<f64>,
}

/// OTLP exporter. Ships each export batch's snapshots to the configured
/// endpoint via the OTel SDK + OTLP transport.
///
/// Uses a `ManualReader` rather than a `PeriodicReader`: we already drive
/// cadence from `worker.rs`'s flush ticker, and `PeriodicReader::force_flush`
/// is a sync call that blocks on a oneshot recv and deadlocks the Tokio
/// runtime when invoked from inside an async task. With `ManualReader` we
/// call `reader.collect(&mut rm)` directly and then `otlp.export(&mut rm).await`
/// — both genuinely async-compatible.
pub struct OtelExporter {
    provider: Arc<SdkMeterProvider>,
    reader: SharedManualReader,
    otlp: Arc<OtlpMetricExporter>,
    instruments: Instruments,
    self_instruments: SelfInstruments,
    identity: IdentityAttributes,
}

/// `Arc`-wrapped [`ManualReader`] with a forwarded [`MetricReader`] impl, so
/// the SDK [`SdkMeterProvider`] and the [`OtelExporter`] can both hold the
/// same reader (`with_reader` consumes by value and `ManualReader` is not
/// `Clone`).
#[derive(Debug, Clone)]
struct SharedManualReader(Arc<ManualReader>);

impl MetricReader for SharedManualReader {
    fn register_pipeline(&self, pipeline: Weak<Pipeline>) {
        self.0.register_pipeline(pipeline);
    }
    fn collect(&self, rm: &mut ResourceMetrics) -> OTelSdkResult {
        self.0.collect(rm)
    }
    fn force_flush(&self) -> OTelSdkResult {
        self.0.force_flush()
    }
    fn shutdown_with_timeout(&self, timeout: std::time::Duration) -> OTelSdkResult {
        self.0.shutdown_with_timeout(timeout)
    }
    fn temporality(&self, kind: InstrumentKind) -> Temporality {
        self.0.temporality(kind)
    }
}

/// Builder for [`OtelExporter`]. Endpoint is required; other knobs default
/// to sensible values for direct OTLP gateways (Grafana Cloud, Alloy, etc.).
#[derive(Default)]
pub struct OtelExporterBuilder {
    endpoint: Option<String>,
    protocol: OtlpProtocol,
    compression: OtlpCompression,
    ca_cert_pem: Option<Vec<u8>>,
    headers: Vec<(String, String)>,
    resource_attrs: Vec<KeyValue>,
    identity: IdentityAttributes,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl OtelExporter {
    /// Create a new builder.
    pub fn builder() -> OtelExporterBuilder {
        OtelExporterBuilder::default()
    }
}

impl OtelExporterBuilder {
    /// Required: the OTLP endpoint URL (e.g.
    /// `http://localhost:4317` for local gRPC, or the Grafana Cloud
    /// `otlp-gateway-prod-*.grafana.net/otlp` URL).
    pub fn endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// OTLP transport protocol. Defaults to [`OtlpProtocol::Grpc`].
    pub fn protocol(mut self, protocol: OtlpProtocol) -> Self {
        self.protocol = protocol;
        self
    }

    /// OTLP payload compression. Defaults to [`OtlpCompression::None`].
    /// gzip is meaningful bandwidth saving for direct provider gateways
    /// (Grafana Cloud, Datadog) over the public internet; for a local
    /// collector on the same host the CPU cost outweighs the gain.
    pub fn compression(mut self, compression: OtlpCompression) -> Self {
        self.compression = compression;
        self
    }

    /// PEM-encoded CA certificate to trust when negotiating TLS with the
    /// OTLP endpoint. Added on top of webpki roots, so a corporate gateway
    /// signed by a private CA works without disabling system trust.
    ///
    /// gRPC only — the HTTP transport does not expose a TLS configuration
    /// hook. Passing this with `--protocol=http` is rejected at build time.
    pub fn ca_cert_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.ca_cert_pem = Some(pem.into());
        self
    }

    /// Add an OTLP request header. Repeat to add several. Use for
    /// authentication (`Authorization=Basic …`, `api-key=…`, etc.).
    ///
    /// Headers are applied via the `OTEL_EXPORTER_OTLP_HEADERS` env var
    /// at [`Self::build`] time (this is how opentelemetry-otlp's API
    /// accepts headers without requiring direct tonic access). The env
    /// var is process-wide; subsequent `OtelExporter::build` calls would
    /// overwrite it. For a single `msb-metrics` process running a single
    /// exporter this is fine; if you ever embed multiple exporters in
    /// one process with different headers, set them before constructing
    /// either exporter via the env var directly.
    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((key.into(), value.into()));
        self
    }

    /// Override or add an OTel resource attribute (e.g. `service.name`,
    /// `service.namespace`). Defaults are seeded with `service.name =
    /// "microsandbox"` and a best-effort `service.instance.id` from the
    /// hostname.
    pub fn resource_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.resource_attrs
            .push(KeyValue::new(key.into(), value.into()));
        self
    }

    /// Opt in to emitting `sandbox.run_id` on every datapoint. Off by
    /// default — creates a fresh series per sandbox restart on
    /// cardinality-billed backends.
    pub fn emit_run_id(mut self, enabled: bool) -> Self {
        self.identity.emit_run_id = enabled;
        self
    }

    /// Opt in to emitting `sandbox.pid` on every datapoint. Off by
    /// default — same cardinality concern as `emit_run_id`.
    pub fn emit_pid(mut self, enabled: bool) -> Self {
        self.identity.emit_pid = enabled;
        self
    }

    /// Build the exporter. Validates that an endpoint is set and wires up
    /// the SDK + OTLP transport. Returns an error on validation or
    /// initialization failure.
    pub fn build(self) -> MetricsCollectorResult<OtelExporter> {
        let endpoint = self.endpoint.ok_or_else(|| {
            MetricsCollectorError::InvalidConfig(
                "OtelExporter requires an endpoint; call .endpoint(...)".into(),
            )
        })?;

        apply_headers_env(&self.headers);
        let otlp_exporter = build_otlp_exporter(
            &endpoint,
            self.protocol,
            self.compression,
            self.ca_cert_pem.as_deref(),
        )?;

        let reader = SharedManualReader(Arc::new(
            ManualReader::builder()
                .with_temporality(Temporality::Cumulative)
                .build(),
        ));

        let resource = build_resource(self.resource_attrs);

        let provider = SdkMeterProvider::builder()
            .with_reader(reader.clone())
            .with_resource(resource)
            .build();

        let scope = InstrumentationScope::builder(SCOPE_NAME)
            .with_version(SCOPE_VERSION)
            .build();
        let meter = provider.meter_with_scope(scope);
        let instruments = build_instruments(&meter);
        let self_instruments = build_self_instruments(&meter);

        Ok(OtelExporter {
            provider: Arc::new(provider),
            reader,
            otlp: Arc::new(otlp_exporter),
            instruments,
            self_instruments,
            identity: self.identity,
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl MetricsExporter for OtelExporter {
    fn export(
        &self,
        batch: Arc<MetricsExportBatch>,
    ) -> BoxFuture<'static, MetricsCollectorResult<()>> {
        let instruments = self.instruments.clone();
        let self_instruments = self.self_instruments.clone();
        let reader = self.reader.clone();
        let otlp = self.otlp.clone();
        let identity = self.identity;

        Box::pin(async move {
            // Self-observability: count drops surfaced from the worker
            // buffer first, so even a fully-empty batch (no sandbox
            // snapshots) still ships the drop counter.
            if batch.dropped_collection_count > 0 {
                self_instruments
                    .collections_dropped
                    .add(batch.dropped_collection_count, &[]);
            }

            if batch.collections.is_empty() {
                let result = export_recorded_metrics(&reader, &otlp).await;
                record_export_outcome(&self_instruments, &result);
                return result;
            }

            // Synchronous OTel gauges use LastValue aggregation. Record and
            // export one collection at a time so a buffered flush preserves
            // every collected sample instead of collapsing to the final value.
            for collection in &batch.collections {
                for snapshot in &collection.sandboxes {
                    let attrs = build_attributes(snapshot, &identity);
                    record_snapshot(&instruments, snapshot, &attrs);
                }

                let result = export_recorded_metrics(&reader, &otlp).await;
                record_export_outcome(&self_instruments, &result);
                result?;
            }

            Ok(())
        })
    }

    fn shutdown(&self) -> BoxFuture<'static, MetricsCollectorResult<()>> {
        let provider = self.provider.clone();
        Box::pin(async move {
            // ManualReader's shutdown is a non-blocking bool flip, so
            // provider.shutdown() does not have the PeriodicReader deadlock.
            provider
                .shutdown()
                .map_err(|e| MetricsCollectorError::Custom(format!("otel shutdown failed: {e}")))?;
            Ok(())
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Construct the OTLP transport-level exporter.
fn build_otlp_exporter(
    endpoint: &str,
    protocol: OtlpProtocol,
    compression: OtlpCompression,
    ca_cert_pem: Option<&[u8]>,
) -> MetricsCollectorResult<OtlpMetricExporter> {
    if matches!(protocol, OtlpProtocol::HttpProtobuf) && ca_cert_pem.is_some() {
        return Err(MetricsCollectorError::InvalidConfig(
            "custom CA certificate is currently supported only with --protocol=grpc; \
             opentelemetry-otlp has no TLS configuration hook on the HTTP transport"
                .into(),
        ));
    }
    if matches!(protocol, OtlpProtocol::HttpProtobuf)
        && matches!(compression, OtlpCompression::Gzip)
    {
        return Err(MetricsCollectorError::InvalidConfig(
            "gzip compression is currently supported only with --protocol=grpc; \
             the HTTP transport was not built with gzip support"
                .into(),
        ));
    }
    let result = match protocol {
        OtlpProtocol::Grpc => {
            let mut builder = OtlpMetricExporter::builder()
                .with_tonic()
                .with_endpoint(endpoint)
                .with_temporality(Temporality::Cumulative);
            if matches!(compression, OtlpCompression::Gzip) {
                builder = builder.with_compression(Compression::Gzip);
            }
            if let Some(pem) = ca_cert_pem {
                let tls = ClientTlsConfig::new()
                    .with_webpki_roots()
                    .ca_certificate(Certificate::from_pem(pem));
                builder = builder.with_tls_config(tls);
            }
            builder.build()
        }
        OtlpProtocol::HttpProtobuf => OtlpMetricExporter::builder()
            .with_http()
            .with_endpoint(endpoint)
            .with_protocol(Protocol::HttpBinary)
            .with_temporality(Temporality::Cumulative)
            .build(),
    };
    result.map_err(|e| MetricsCollectorError::Custom(format!("otel exporter build failed: {e}")))
}

/// Pull recorded points out of the SDK pipeline and ship them. `collect`
/// populates resource + scope metrics synchronously; the OTLP transport export
/// is async.
async fn export_recorded_metrics(
    reader: &SharedManualReader,
    otlp: &OtlpMetricExporter,
) -> MetricsCollectorResult<()> {
    let mut rm = ResourceMetrics::default();
    reader
        .collect(&mut rm)
        .map_err(|e| MetricsCollectorError::Custom(format!("otel reader.collect failed: {e}")))?;
    otlp.export(&rm)
        .await
        .map_err(|e| MetricsCollectorError::Custom(format!("otel exporter.export failed: {e}")))?;
    Ok(())
}

/// Record exporter self-observability after the transport returns. These
/// cumulative points ship on the next successful OTLP request.
fn record_export_outcome(instruments: &SelfInstruments, result: &MetricsCollectorResult<()>) {
    match result {
        Ok(()) => {
            instruments.exports_success.add(1, &[]);
            if let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                instruments
                    .last_success_timestamp
                    .record(now.as_secs_f64(), &[]);
            }
        }
        Err(_) => instruments.exports_failure.add(1, &[]),
    }
}

/// Apply caller-supplied `--header k=v` pairs by writing them into the
/// `OTEL_EXPORTER_OTLP_HEADERS` env var that opentelemetry-otlp reads
/// internally. Process-wide; see the doc comment on
/// [`OtelExporterBuilder::header`] for the multi-exporter caveat.
fn apply_headers_env(headers: &[(String, String)]) {
    if headers.is_empty() {
        return;
    }
    let header_str = headers
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(",");
    // SAFETY: set_var is unsafe because env vars are process-wide and
    // not synchronized. Acceptable here because the builder is called
    // once at process startup before any other thread reads OTLP env
    // vars.
    unsafe { std::env::set_var("OTEL_EXPORTER_OTLP_HEADERS", header_str) };
}

/// Build the OTel `Resource` with default attributes merged with caller
/// overrides. Caller-supplied attributes win on duplicate keys (Resource
/// merges by latest-wins).
fn build_resource(overrides: Vec<KeyValue>) -> Resource {
    let mut attrs = default_resource_attributes();
    attrs.extend(overrides);
    // 0.32 closed `Resource::new`; build via `builder_empty` so we don't
    // merge in the SDK's own default detectors (we set service.name and
    // service.instance.id ourselves).
    Resource::builder_empty().with_attributes(attrs).build()
}

/// Default resource attributes — `service.name` and best-effort
/// `service.instance.id` derived from the host name.
fn default_resource_attributes() -> Vec<KeyValue> {
    let mut attrs = vec![KeyValue::new("service.name", "microsandbox")];
    if let Some(hostname) = hostname() {
        attrs.push(KeyValue::new("service.instance.id", hostname));
    }
    attrs
}

/// Best-effort hostname read. Falls back to `None` if neither the POSIX
/// nor Windows env vars are set.
fn hostname() -> Option<String> {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .ok()
}

/// Build the self-observability instruments shipped alongside the
/// per-sandbox series. These describe what the collector itself is doing
/// so a user can confirm the sidecar is actually flowing.
fn build_self_instruments(meter: &Meter) -> SelfInstruments {
    SelfInstruments {
        exports_success: meter
            .u64_counter("microsandbox.collector.exports.success")
            .with_description("Successful OTLP exports since process start")
            .with_unit("1")
            .build(),
        exports_failure: meter
            .u64_counter("microsandbox.collector.exports.failure")
            .with_description("Failed OTLP exports since process start")
            .with_unit("1")
            .build(),
        collections_dropped: meter
            .u64_counter("microsandbox.collector.collections.dropped")
            .with_description(
                "Collections dropped from the per-exporter buffer due to overflow \
                 (drop-oldest, see --max-buffered)",
            )
            .with_unit("1")
            .build(),
        last_success_timestamp: meter
            .f64_gauge("microsandbox.collector.last_success_timestamp")
            .with_description("Unix epoch seconds at the last successful OTLP export")
            .with_unit("s")
            .build(),
    }
}

/// Build the bundle of instruments from the meter.
fn build_instruments(meter: &Meter) -> Instruments {
    Instruments {
        cpu_utilization: meter
            .f64_gauge("microsandbox.cpu.utilization")
            .with_description(
                "Process CPU usage as a ratio of vCPU-seconds per wall-second. \
                 A 2-vCPU sandbox at full load reports 2.0; divide by allocated \
                 vCPUs for a 0..1 fraction.",
            )
            .with_unit("1")
            .build(),
        memory_usage: meter
            .u64_gauge("microsandbox.memory.usage")
            .with_description("Resident memory usage")
            .with_unit("By")
            .build(),
        memory_limit: meter
            .u64_gauge("microsandbox.memory.limit")
            .with_description("Configured guest memory limit")
            .with_unit("By")
            .build(),
        disk_bytes_read: meter
            .u64_gauge("microsandbox.disk.bytes_read")
            .with_description("Cumulative disk bytes read by the sandbox process")
            .with_unit("By")
            .build(),
        disk_bytes_written: meter
            .u64_gauge("microsandbox.disk.bytes_written")
            .with_description("Cumulative disk bytes written by the sandbox process")
            .with_unit("By")
            .build(),
        network_bytes_received: meter
            .u64_gauge("microsandbox.network.bytes_received")
            .with_description("Cumulative network bytes delivered from the runtime to the guest")
            .with_unit("By")
            .build(),
        network_bytes_sent: meter
            .u64_gauge("microsandbox.network.bytes_sent")
            .with_description(
                "Cumulative network bytes transmitted from the guest into the runtime",
            )
            .with_unit("By")
            .build(),
        uptime: meter
            .f64_gauge("microsandbox.uptime")
            .with_description("Sandbox uptime at the moment of sampling")
            .with_unit("s")
            .build(),
    }
}

/// Build the per-snapshot attribute set according to the configured
/// `IdentityAttributes`.
fn build_attributes(
    snapshot: &SandboxMetricSnapshot,
    identity: &IdentityAttributes,
) -> Vec<KeyValue> {
    let mut attrs = Vec::with_capacity(4);
    if identity.emit_name {
        attrs.push(KeyValue::new("sandbox.name", snapshot.name.clone()));
    }
    if identity.emit_sandbox_id {
        attrs.push(KeyValue::new("sandbox.id", i64::from(snapshot.sandbox_id)));
    }
    if identity.emit_run_id {
        attrs.push(KeyValue::new("sandbox.run_id", i64::from(snapshot.run_id)));
    }
    if identity.emit_pid {
        attrs.push(KeyValue::new("sandbox.pid", i64::from(snapshot.pid)));
    }
    attrs
}

/// Record one snapshot's metrics across all instruments.
fn record_snapshot(
    instruments: &Instruments,
    snapshot: &SandboxMetricSnapshot,
    attrs: &[KeyValue],
) {
    let m = &snapshot.metrics;
    // cpu_percent is a 0..100 percentage in the source; OTel convention
    // for `*.utilization` is a 0..1 ratio.
    instruments
        .cpu_utilization
        .record(f64::from(m.cpu_percent) / 100.0, attrs);
    instruments.memory_usage.record(m.memory_bytes, attrs);
    instruments.memory_limit.record(m.memory_limit_bytes, attrs);
    instruments.disk_bytes_read.record(m.disk_read_bytes, attrs);
    instruments
        .disk_bytes_written
        .record(m.disk_write_bytes, attrs);
    instruments
        .network_bytes_received
        .record(m.net_rx_bytes, attrs);
    instruments.network_bytes_sent.record(m.net_tx_bytes, attrs);
    instruments.uptime.record(m.uptime.as_secs_f64(), attrs);
}

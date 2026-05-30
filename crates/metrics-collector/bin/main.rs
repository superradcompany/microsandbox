//! `msb-metrics` — sibling-process metrics collector that reads the
//! shared-memory registry and ships data to backends.
//!
//! Usage:
//!
//! ```text
//! msb-metrics otel --endpoint=http://localhost:4317
//! ```
//!
//! Deployment constraints: must run as the same Unix user that owns
//! the `$MSB_HOME` directory (the shm registry is mode `0600`).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Context;
use axum::Router;
use axum::http::StatusCode;
use axum::routing::get;
use clap::{Args, Parser, Subcommand, ValueEnum};
use microsandbox_metrics_collector::MetricsCollector;
use microsandbox_metrics_collector::exporters::{
    OtelExporter, OtlpCompression, OtlpProtocol, StdoutExporter,
};
use tracing::info;
use tracing_subscriber::EnvFilter;

//--------------------------------------------------------------------------------------------------
// CLI definition
//--------------------------------------------------------------------------------------------------

#[derive(Debug, Parser)]
#[command(
    name = "msb-metrics",
    about = "microsandbox metrics collector",
    long_about = "Sibling-process metrics collector that reads the microsandbox shared-memory registry and ships data to OTel-compatible backends.\n\nMust run as the same Unix user with the same $MSB_HOME as the msb runtime.",
    version
)]
struct Cli {
    /// Logging verbosity. Overridden by `RUST_LOG` if that env var is set.
    #[arg(long, value_enum, default_value_t = LogLevel::Info, global = true)]
    log_level: LogLevel,

    /// Log output format. `text` is the default human-readable
    /// `tracing` formatter; `json` emits one JSON object per line, for
    /// shipping `msb-metrics`'s own logs into the same pipeline as
    /// everything else.
    #[arg(long, value_enum, default_value_t = LogFormat::Text, global = true)]
    log_format: LogFormat,

    /// Bind a health-check HTTP server to this address (e.g.
    /// `127.0.0.1:9095`, `0.0.0.0:9095`). Exposes `/healthz` (liveness;
    /// `200 OK` once the binary is running) and `/readyz` (readiness;
    /// `200 OK` once the metrics collector has successfully attached to
    /// shm and started its worker loop). Intended for systemd / Kubernetes
    /// / Nomad probes. Omit to leave the server off entirely.
    #[arg(long, value_name = "ADDR", global = true)]
    http_listen: Option<SocketAddr>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Ship metrics over OTLP to an OpenTelemetry-compatible endpoint
    /// (Grafana Cloud, Grafana Alloy, otel-collector, …).
    Otel(OtelArgs),
    /// Print each metrics batch to stdout. For local inspection of what
    /// `msb-metrics` is reading from shm without standing up an OTLP
    /// receiver. Output format is human-readable and not a stable
    /// contract.
    Stdout(StdoutArgs),
}

#[derive(Debug, Args)]
struct OtelArgs {
    /// OTLP endpoint URL (e.g. `http://localhost:4317` for local gRPC, or
    /// the Grafana Cloud OTLP gateway URL).
    #[arg(long)]
    endpoint: String,

    /// OTLP transport protocol.
    #[arg(long, value_enum, default_value_t = OtlpProtocolArg::Grpc)]
    protocol: OtlpProtocolArg,

    /// OTLP payload compression. Currently gRPC-only; `--compression=gzip`
    /// combined with `--protocol=http` is rejected at startup.
    #[arg(long, value_enum, default_value_t = OtlpCompressionArg::None)]
    compression: OtlpCompressionArg,

    /// Path to a PEM-encoded CA certificate trusted when negotiating TLS
    /// with the OTLP endpoint. Added on top of webpki roots, so a
    /// corporate gateway signed by a private CA works without disabling
    /// system trust. gRPC only; rejected at startup with `--protocol=http`.
    #[arg(long, value_name = "PATH")]
    ca_cert: Option<PathBuf>,

    /// OTLP request header. Repeat to add several. Format: `KEY=VALUE`.
    /// Use for authentication (e.g. `--header Authorization=Basic ...`,
    /// `--header api-key=...`).
    #[arg(long = "header", value_name = "KEY=VALUE", value_parser = parse_kv)]
    headers: Vec<(String, String)>,

    /// Override or add an OTel resource attribute. Repeat. Format: `KEY=VALUE`.
    /// Defaults already include `service.name=microsandbox` and a best-effort
    /// `service.instance.id` from the hostname.
    #[arg(long = "resource", value_name = "KEY=VALUE", value_parser = parse_kv)]
    resources: Vec<(String, String)>,

    /// Emit `sandbox.run_id` on each datapoint. Off by default: creates a
    /// fresh series per sandbox restart on cardinality-billed backends.
    #[arg(long)]
    emit_run_id: bool,

    /// Emit `sandbox.pid` on each datapoint. Off by default: same
    /// cardinality concern as `--emit-run-id`.
    #[arg(long)]
    emit_pid: bool,

    #[command(flatten)]
    collector: CollectorOpts,
}

#[derive(Debug, Args)]
struct StdoutArgs {
    #[command(flatten)]
    collector: CollectorOpts,
}

/// Knobs shared by every exporter subcommand.
#[derive(Debug, Args)]
struct CollectorOpts {
    /// Interval between shared-memory metrics reads. Accepts human-readable
    /// durations like `1s`, `500ms`, `2m`.
    #[arg(long, value_parser = humantime::parse_duration, default_value = "1s")]
    collect_interval: Duration,

    /// Per-exporter scheduled flush interval.
    #[arg(long, value_parser = humantime::parse_duration, default_value = "10s")]
    flush_interval: Duration,

    /// Per-exporter buffer cap (number of collections held before the
    /// oldest is dropped on overflow).
    #[arg(long, default_value_t = 60)]
    max_buffered: usize,

    /// Per-exporter timeout for a single export call.
    #[arg(long, value_parser = humantime::parse_duration, default_value = "30s")]
    export_timeout: Duration,

    /// `MSB_HOME` directory. Defaults to `$MSB_HOME` if set, otherwise
    /// `~/.microsandbox`. Used to derive the shm registry name.
    #[arg(long)]
    msb_home: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OtlpProtocolArg {
    /// gRPC over HTTP/2 (default OTLP port `4317`).
    Grpc,
    /// HTTP/1.1 + Protobuf body (default OTLP port `4318`).
    Http,
}

impl From<OtlpProtocolArg> for OtlpProtocol {
    fn from(value: OtlpProtocolArg) -> Self {
        match value {
            OtlpProtocolArg::Grpc => Self::Grpc,
            OtlpProtocolArg::Http => Self::HttpProtobuf,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OtlpCompressionArg {
    /// No compression. Default; preserves prior behavior.
    None,
    /// gzip. gRPC-only.
    Gzip,
}

impl From<OtlpCompressionArg> for OtlpCompression {
    fn from(value: OtlpCompressionArg) -> Self {
        match value {
            OtlpCompressionArg::None => Self::None,
            OtlpCompressionArg::Gzip => Self::Gzip,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Entry point
//--------------------------------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.log_level, cli.log_format);

    let ready = Arc::new(AtomicBool::new(false));
    let health_task = match cli.http_listen {
        Some(addr) => Some(spawn_health_server(addr, ready.clone()).await?),
        None => None,
    };

    let result = match cli.command {
        Command::Otel(args) => run_otel(args, ready.clone()).await,
        Command::Stdout(args) => run_stdout(args, ready.clone()).await,
    };

    if let Some(handle) = health_task {
        handle.abort();
        let _ = handle.await;
    }
    result
}

//--------------------------------------------------------------------------------------------------
// Subcommand handlers
//--------------------------------------------------------------------------------------------------

async fn run_otel(args: OtelArgs, ready: Arc<AtomicBool>) -> anyhow::Result<()> {
    let registry_name = resolve_registry_name(args.collector.msb_home.as_deref())?;
    info!(registry = %registry_name, endpoint = %args.endpoint, "starting msb-metrics otel");

    let mut exporter_builder = OtelExporter::builder()
        .endpoint(&args.endpoint)
        .protocol(args.protocol.into())
        .compression(args.compression.into())
        .emit_run_id(args.emit_run_id)
        .emit_pid(args.emit_pid);
    if let Some(path) = args.ca_cert.as_deref() {
        let pem = std::fs::read(path)
            .with_context(|| format!("read --ca-cert from {}", path.display()))?;
        exporter_builder = exporter_builder.ca_cert_pem(pem);
    }
    for (k, v) in &args.headers {
        exporter_builder = exporter_builder.header(k, v);
    }
    for (k, v) in &args.resources {
        exporter_builder = exporter_builder.resource_attribute(k, v);
    }
    let exporter = exporter_builder.build().context("build OTel exporter")?;

    let collector = MetricsCollector::builder(registry_name)
        .collect_interval(args.collector.collect_interval)
        .flush_interval(args.collector.flush_interval)
        .max_buffered_collections(args.collector.max_buffered)
        .export_timeout(args.collector.export_timeout)
        .register(exporter)
        .build()
        .context("build metrics collector")?;

    let handle = collector.start().await.context("start metrics collector")?;
    ready.store(true, Ordering::SeqCst);
    info!("msb-metrics started; press Ctrl+C to shut down");

    wait_for_shutdown_signal().await;
    info!("shutdown signal received; draining buffers");
    ready.store(false, Ordering::SeqCst);

    handle
        .shutdown()
        .await
        .context("shutdown metrics collector")?;
    info!("msb-metrics stopped cleanly");
    Ok(())
}

async fn run_stdout(args: StdoutArgs, ready: Arc<AtomicBool>) -> anyhow::Result<()> {
    let registry_name = resolve_registry_name(args.collector.msb_home.as_deref())?;
    info!(registry = %registry_name, "starting msb-metrics stdout");

    let exporter = StdoutExporter::new();
    let collector = MetricsCollector::builder(registry_name)
        .collect_interval(args.collector.collect_interval)
        .flush_interval(args.collector.flush_interval)
        .max_buffered_collections(args.collector.max_buffered)
        .export_timeout(args.collector.export_timeout)
        .register(exporter)
        .build()
        .context("build metrics collector")?;

    let handle = collector.start().await.context("start metrics collector")?;
    ready.store(true, Ordering::SeqCst);
    info!("msb-metrics started; press Ctrl+C to shut down");

    wait_for_shutdown_signal().await;
    info!("shutdown signal received; draining buffers");
    ready.store(false, Ordering::SeqCst);

    handle
        .shutdown()
        .await
        .context("shutdown metrics collector")?;
    info!("msb-metrics stopped cleanly");
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Health server
//--------------------------------------------------------------------------------------------------

/// Bind a tiny axum server exposing `/healthz` (always 200 once the
/// process is running) and `/readyz` (200 when the metrics collector
/// has successfully attached to shm and started its worker loop). Both
/// endpoints respond with `text/plain` bodies (`ok` / `not ready`),
/// which is the convention systemd and k8s readiness probes treat
/// as opaque payload anyway.
async fn spawn_health_server(
    addr: SocketAddr,
    ready: Arc<AtomicBool>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let liveness = || async { (StatusCode::OK, "ok") };
    let readiness = {
        let ready = ready.clone();
        move || {
            let ready = ready.clone();
            async move {
                if ready.load(Ordering::SeqCst) {
                    (StatusCode::OK, "ok")
                } else {
                    (StatusCode::SERVICE_UNAVAILABLE, "not ready")
                }
            }
        }
    };
    let app = Router::new()
        .route("/healthz", get(liveness))
        .route("/readyz", get(readiness));

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind health server on {addr}"))?;
    let bound = listener
        .local_addr()
        .unwrap_or_else(|_| "<unknown>".parse().unwrap());
    info!(http_listen = %bound, "health server listening");

    Ok(tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, app).await {
            tracing::warn!(%error, "health server exited");
        }
    }))
}

//--------------------------------------------------------------------------------------------------
// Helpers
//--------------------------------------------------------------------------------------------------

/// Initialize the tracing subscriber. `RUST_LOG` wins if set, else uses the
/// CLI flag as a default for both `msb_metrics` and the collector crate.
fn init_tracing(level: LogLevel, format: LogFormat) {
    let default_directive = format!(
        "msb_metrics={lvl},microsandbox_metrics_collector={lvl}",
        lvl = level.as_str()
    );
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_directive));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);
    match format {
        LogFormat::Text => builder.init(),
        LogFormat::Json => builder.json().init(),
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum LogFormat {
    /// Human-readable tracing output. Default.
    Text,
    /// Newline-delimited JSON.
    Json,
}

/// Derive the shm registry name from `--msb-home` (or env/default).
///
/// Mirrors `microsandbox::config::Config::metrics_registry_shm_name`:
/// `{METRICS_SHM_PREFIX}-{stable_hash(home)}-v1`.
fn resolve_registry_name(msb_home: Option<&std::path::Path>) -> anyhow::Result<String> {
    let home = match msb_home {
        Some(p) => p.to_path_buf(),
        None => match std::env::var_os("MSB_HOME") {
            Some(p) => PathBuf::from(p),
            None => dirs::home_dir()
                .ok_or_else(|| anyhow::anyhow!("could not resolve $HOME for default --msb-home"))?
                .join(".microsandbox"),
        },
    };
    let home_hash = microsandbox_utils::stable_hash_path(&home);
    Ok(format!(
        "{prefix}-{hash}-v1",
        prefix = microsandbox_utils::METRICS_SHM_PREFIX,
        hash = home_hash,
    ))
}

/// Wait for SIGINT or SIGTERM (on Unix) / Ctrl+C (everywhere else).
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = sigterm.recv() => {}
                }
            }
            Err(error) => {
                tracing::warn!(%error, "failed to install SIGTERM handler; relying on Ctrl+C only");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn parse_kv(s: &str) -> Result<(String, String), String> {
    let (k, v) = s
        .split_once('=')
        .ok_or_else(|| format!("expected KEY=VALUE, got {s:?}"))?;
    if k.is_empty() {
        return Err(format!("empty key in {s:?}"));
    }
    Ok((k.to_string(), v.to_string()))
}

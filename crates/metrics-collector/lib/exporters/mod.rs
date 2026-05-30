//! Built-in [`MetricsExporter`](crate::MetricsExporter) implementations.
//!
//! Each backend lives in its own submodule. Add a new file here per
//! exporter (Prometheus, Datadog, statsd, …) and surface it from this
//! module's `pub use` block plus the binary's clap subcommands.

pub mod otel;
pub mod stdout;

pub use otel::{OtelExporter, OtelExporterBuilder, OtlpCompression, OtlpProtocol};
pub use stdout::StdoutExporter;

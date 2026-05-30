//! Integration tests for the [`OtelExporter`].
//!
//! These exercise builder validation paths that don't need a live OTLP
//! receiver (endpoint required, protocol/compression mismatch, etc.) so
//! they stay deterministic in CI. End-to-end coverage with a real
//! receiver happens in the dev loop documented in
//! `docs/observability/deep-dive.mdx`.

use microsandbox_metrics_collector::MetricsCollectorError;
use microsandbox_metrics_collector::exporters::{OtelExporter, OtlpCompression, OtlpProtocol};

#[test]
fn build_requires_endpoint() {
    match OtelExporter::builder().build() {
        Ok(_) => panic!("endpoint should be required"),
        Err(MetricsCollectorError::InvalidConfig(_)) => {}
        Err(other) => panic!("expected InvalidConfig, got: {other:?}"),
    }
}

#[tokio::test]
async fn grpc_no_compression_builds() {
    assert!(
        OtelExporter::builder()
            .endpoint("http://127.0.0.1:65535")
            .protocol(OtlpProtocol::Grpc)
            .compression(OtlpCompression::None)
            .build()
            .is_ok(),
        "gRPC + no compression should construct without network"
    );
}

#[tokio::test]
async fn grpc_gzip_builds() {
    assert!(
        OtelExporter::builder()
            .endpoint("http://127.0.0.1:65535")
            .protocol(OtlpProtocol::Grpc)
            .compression(OtlpCompression::Gzip)
            .build()
            .is_ok(),
        "gRPC + gzip is supported in opentelemetry-otlp 0.27"
    );
}

#[test]
fn http_no_compression_builds() {
    assert!(
        OtelExporter::builder()
            .endpoint("http://127.0.0.1:65535/v1/metrics")
            .protocol(OtlpProtocol::HttpProtobuf)
            .compression(OtlpCompression::None)
            .build()
            .is_ok(),
        "HTTP/Protobuf + no compression should construct without network"
    );
}

#[test]
fn http_gzip_rejected_at_build() {
    match OtelExporter::builder()
        .endpoint("http://127.0.0.1:65535/v1/metrics")
        .protocol(OtlpProtocol::HttpProtobuf)
        .compression(OtlpCompression::Gzip)
        .build()
    {
        Ok(_) => panic!("HTTP + gzip should be rejected: no with_compression on HTTP transport"),
        Err(MetricsCollectorError::InvalidConfig(msg)) => assert!(
            msg.contains("gzip") && msg.contains("grpc"),
            "error should explain the protocol mismatch, got: {msg}"
        ),
        Err(other) => panic!("expected InvalidConfig, got: {other:?}"),
    }
}

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
        "gRPC + gzip is supported by the configured opentelemetry-otlp build"
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

// A minimal self-signed PEM, just enough for Certificate::from_pem
// to accept the input. We never speak TLS in these tests; the bytes
// only have to parse.
const TEST_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIB1jCCAXygAwIBAgIUaP0RZuhuKpf2egqXLkjt4mn50jcwCgYIKoZIzj0EAwIw
MzELMAkGA1UEBhMCVVMxEjAQBgNVBAoMCW1zYi10ZXN0czEQMA4GA1UEAwwHbXNi
LWNhMB4XDTI1MDEwMTAwMDAwMFoXDTM1MDEwMTAwMDAwMFowMzELMAkGA1UEBhMC
VVMxEjAQBgNVBAoMCW1zYi10ZXN0czEQMA4GA1UEAwwHbXNiLWNhMFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEK/Q1f8KbQyZkRZUEzNiKkVAwfYbMlAqLfHvCgwn4
nL+EI9JEvfgX1l0xnNnX2RH0w8L0aB7gQ8oUNzCpwYjbX6NTMFEwHQYDVR0OBBYE
FFcwCWMmDQEksU6Y3K3I9lvy6hJBMB8GA1UdIwQYMBaAFFcwCWMmDQEksU6Y3K3I
9lvy6hJBMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgZA6OYrIu
RGKZ0pY3kcoYbBpJ0fFwUlGmpkAj9OAGoVwCIQClSqfXk4Q/n2xLg3DEFTRgKQVo
PCG3QMS1NHUUM8z+rg==
-----END CERTIFICATE-----
";

// (No happy-path build test for gRPC + --ca-cert: when TLS is configured,
// tonic's channel resolution at build time hits the network, which makes
// the test depend on environment behavior. The CLI-level integration test
// in `tests/cli.rs::missing_ca_cert_file_errors_cleanly` covers the
// startup wiring; the InvalidConfig test below covers the protocol guard.)

#[test]
fn http_with_ca_cert_rejected_at_build() {
    match OtelExporter::builder()
        .endpoint("https://127.0.0.1:65535/v1/metrics")
        .protocol(OtlpProtocol::HttpProtobuf)
        .ca_cert_pem(TEST_PEM.as_bytes())
        .build()
    {
        Ok(_) => panic!("HTTP + ca-cert should be rejected"),
        Err(MetricsCollectorError::InvalidConfig(msg)) => assert!(
            msg.contains("CA certificate") && msg.contains("grpc"),
            "error should explain protocol mismatch, got: {msg}"
        ),
        Err(other) => panic!("expected InvalidConfig, got: {other:?}"),
    }
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

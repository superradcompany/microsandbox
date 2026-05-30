//! Integration tests for the `msb-metrics` binary's command-line surface.
//!
//! Each test spawns the actual built binary via `CARGO_BIN_EXE_msb-metrics`
//! and asserts on its `--help` / `--version` / clap-error output. Runtime
//! behavior (live shipping, log format on stderr) is covered separately
//! by the dev loop documented in `docs/observability/deep-dive.mdx`; trying
//! to assert on stderr lines emitted by an actively-running binary makes
//! the test racy on slower CI hosts without earning much coverage.

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_msb-metrics")
}

#[test]
fn help_lists_subcommands_and_global_flags() {
    let out = Command::new(bin())
        .arg("--help")
        .output()
        .expect("spawn msb-metrics --help");
    assert!(out.status.success(), "--help should exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("otel"), "help should list the otel subcommand");
    for flag in ["--log-level", "--log-format"] {
        assert!(stdout.contains(flag), "expected `{flag}` in --help output");
    }
}

#[test]
fn version_prints_crate_version() {
    let out = Command::new(bin())
        .arg("--version")
        .output()
        .expect("spawn msb-metrics --version");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(env!("CARGO_PKG_VERSION")),
        "expected crate version in --version output, got: {stdout}"
    );
}

#[test]
fn otel_help_lists_all_flags() {
    let out = Command::new(bin())
        .args(["otel", "--help"])
        .output()
        .expect("spawn msb-metrics otel --help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for flag in [
        "--endpoint",
        "--protocol",
        "--compression",
        "--ca-cert",
        "--header",
        "--resource",
        "--emit-run-id",
        "--emit-pid",
        "--collect-interval",
        "--flush-interval",
        "--max-buffered",
        "--export-timeout",
        "--msb-home",
    ] {
        assert!(
            stdout.contains(flag),
            "expected `{flag}` in `otel --help` output"
        );
    }
}

#[test]
fn missing_endpoint_errors_cleanly() {
    let out = Command::new(bin())
        .args(["otel"])
        .output()
        .expect("spawn msb-metrics otel");
    assert!(!out.status.success(), "missing --endpoint should fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--endpoint"),
        "clap error should name the missing flag, got: {stderr}"
    );
}

#[test]
fn rejects_unknown_log_format() {
    let out = Command::new(bin())
        .args(["--log-format=jsom", "otel", "--endpoint=http://x"])
        .output()
        .expect("spawn with bad --log-format");
    assert!(!out.status.success(), "bad enum value should fail");
}

#[test]
fn missing_ca_cert_file_errors_cleanly() {
    let out = Command::new(bin())
        .args([
            "otel",
            "--endpoint=https://127.0.0.1:65535",
            "--ca-cert=/nonexistent/path/to/ca.pem",
        ])
        .output()
        .expect("spawn msb-metrics with bad --ca-cert");
    assert!(!out.status.success(), "missing ca-cert file should fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--ca-cert") || stderr.contains("ca.pem"),
        "error should mention --ca-cert or the bad path, got: {stderr}"
    );
}

#[test]
fn accepts_log_format_text_and_json_in_parse() {
    for fmt in ["text", "json"] {
        // `--help` after a global flag is the cheapest way to prove clap
        // accepts the value without standing the runtime up.
        let out = Command::new(bin())
            .args([&format!("--log-format={fmt}"), "--help"])
            .output()
            .expect("spawn msb-metrics --log-format=… --help");
        assert!(
            out.status.success(),
            "--log-format={fmt} should be accepted by clap"
        );
    }
}

//! Integration tests for the `msb-metrics` binary's command-line surface.
//!
//! Each test spawns the actual built binary via `CARGO_BIN_EXE_msb-metrics`
//! and asserts on its `--help` / `--version` / clap-error output. Runtime
//! behavior (live shipping, log format on stderr) is covered separately
//! by the dev loop documented in `docs/observability/deep-dive.mdx`; trying
//! to assert on stderr lines emitted by an actively-running binary makes
//! the test racy on slower CI hosts without earning much coverage.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::thread::sleep;
use std::time::{Duration, Instant};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_msb-metrics")
}

/// Pick an unused ephemeral port for this test process. Tests run in
/// parallel so a hardcoded port races. We assume nothing else binds in
/// the 30000-40000 range during the test run; if that bites us we can
/// switch to a real port-allocation library.
fn next_test_port() -> u16 {
    static SEQ: AtomicU16 = AtomicU16::new(30100);
    SEQ.fetch_add(1, Ordering::SeqCst)
}

/// Send `GET <path>` on a fresh TCP connection and return the bytes of
/// the first response line (e.g. `b"HTTP/1.1 200 OK\r\n"`).
fn http_get_status_line(addr: &str, path: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect_timeout(
        &addr.parse().expect("addr parses"),
        Duration::from_secs(2),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    write!(stream, "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf)?;
    Ok(buf.lines().next().unwrap_or("").to_string())
}

/// Poll `addr` until a TCP connect succeeds or the deadline passes.
/// Returns true when the listener answered.
fn wait_for_listener(addr: &str, deadline: Duration) -> bool {
    let stop = Instant::now() + deadline;
    while Instant::now() < stop {
        if TcpStream::connect_timeout(
            &addr.parse().expect("addr parses"),
            Duration::from_millis(200),
        )
        .is_ok()
        {
            return true;
        }
        sleep(Duration::from_millis(100));
    }
    false
}

/// RAII wrapper that kills the spawned binary on drop, so a failed assert
/// doesn't leak a `target/debug/msb-metrics` into the next test run.
struct Killer(Child);
impl Drop for Killer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn help_lists_subcommands_and_global_flags() {
    let out = Command::new(bin())
        .arg("--help")
        .output()
        .expect("spawn msb-metrics --help");
    assert!(out.status.success(), "--help should exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    for sub in ["otel", "stdout"] {
        assert!(stdout.contains(sub), "help should list the `{sub}` subcommand");
    }
    for flag in ["--log-level", "--log-format"] {
        assert!(stdout.contains(flag), "expected `{flag}` in --help output");
    }
}

#[test]
fn stdout_help_lists_collector_flags_only() {
    let out = Command::new(bin())
        .args(["stdout", "--help"])
        .output()
        .expect("spawn msb-metrics stdout --help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Shared CollectorOpts surface.
    for flag in [
        "--collect-interval",
        "--flush-interval",
        "--max-buffered",
        "--export-timeout",
        "--msb-home",
    ] {
        assert!(
            stdout.contains(flag),
            "expected `{flag}` in `stdout --help` output"
        );
    }
    // OTLP-specific flags shouldn't leak into stdout's surface.
    for absent in ["--endpoint", "--protocol", "--compression", "--ca-cert"] {
        assert!(
            !stdout.contains(absent),
            "stdout subcommand should not expose `{absent}`, but it did: {stdout}"
        );
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
fn http_listen_serves_healthz_and_readyz() {
    let port = next_test_port();
    let addr = format!("127.0.0.1:{port}");
    let child = Command::new(bin())
        .args([
            "--http-listen",
            &addr,
            "stdout",
            "--collect-interval=1s",
            "--flush-interval=5s",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn msb-metrics with --http-listen");
    let _guard = Killer(child);

    assert!(
        wait_for_listener(&addr, Duration::from_secs(5)),
        "health server should bind {addr} within 5s"
    );

    let healthz = http_get_status_line(&addr, "/healthz").expect("GET /healthz");
    assert!(
        healthz.starts_with("HTTP/1.1 200"),
        "/healthz should be 200, got: {healthz}"
    );

    let readyz = http_get_status_line(&addr, "/readyz").expect("GET /readyz");
    assert!(
        readyz.starts_with("HTTP/1.1 200"),
        "/readyz should be 200 once the collector started, got: {readyz}"
    );

    // Unknown path returns 404 (axum default).
    let bogus = http_get_status_line(&addr, "/bogus").expect("GET /bogus");
    assert!(
        bogus.starts_with("HTTP/1.1 404"),
        "unknown path should 404, got: {bogus}"
    );
}

#[test]
fn http_listen_help_lists_flag() {
    let out = Command::new(bin())
        .arg("--help")
        .output()
        .expect("spawn msb-metrics --help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("--http-listen"),
        "--http-listen should be in --help, got: {stdout}"
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

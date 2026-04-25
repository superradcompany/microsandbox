//! Integration tests for TLS interception.
//!
//! These tests require KVM (or libkrun on macOS). The `#[msb_test]` attribute
//! marks them `#[ignore]`, so plain `cargo test --workspace` skips them. Run
//! them via:
//!
//!     cargo nextest run -p microsandbox --tests --run-ignored=only
//!
//! Set `MSB_TEST_ISOLATE_HOME=1` (CI does this) to give each test its own
//! `~/.microsandbox` so they can run in parallel without sharing the sqlite
//! db, image cache, or sandbox namespace.

use microsandbox::Sandbox;
use test_utils::msb_test;

/// Covers the default TLS-interception path:
/// - Node.js fetch over TLS 1.3: guards against a past deadlock where
///   application data piggybacked on the TLS Finished message was never
///   drained from the handshake buffer.
/// - wget (busybox, typically TLS 1.2) as a non-Node baseline.
///
/// Both probes run against a single sandbox to avoid paying two image-pull
/// and VM-boot costs in CI.
#[msb_test]
async fn tls_intercept_handshake() {
    let name = "tls-test-intercept";
    let sandbox = Sandbox::builder(name)
        .image("node:alpine")
        .cpus(1)
        .memory(512)
        .network(|n| n.tls(|t| t))
        .replace()
        .create()
        .await
        .expect("failed to create sandbox");

    let node_fetch = sandbox
        .shell(concat!(
            "node -e \"",
            "setTimeout(() => { process.exit(1); }, 15000);",
            "fetch('https://example.com')",
            ".then(r => { console.log(r.status); process.exit(0); })",
            ".catch(e => { console.error(e.message); process.exit(1); });",
            "\""
        ))
        .await
        .expect("node fetch shell failed");
    let node_stdout = node_fetch.stdout().expect("invalid utf8");
    assert_eq!(
        node_stdout.trim(),
        "200",
        "node fetch via TLS intercept failed: {node_stdout} (stderr: {})",
        node_fetch.stderr().unwrap_or_default()
    );

    let wget = sandbox
        .shell("wget -q -O /dev/null --timeout=10 https://example.com && echo OK || echo FAIL")
        .await
        .expect("wget shell failed");
    let wget_stdout = wget.stdout().expect("invalid utf8");
    assert_eq!(
        wget_stdout.trim(),
        "OK",
        "wget via TLS intercept failed: {wget_stdout} (stderr: {})",
        wget.stderr().unwrap_or_default()
    );

    sandbox.stop_and_wait().await.expect("failed to stop");
    Sandbox::remove(name).await.expect("failed to remove");
}

/// Verify TLS bypass domains skip interception and still connect.
#[msb_test]
async fn tls_bypass_domain_connects() {
    let name = "tls-test-bypass";
    let sandbox = Sandbox::builder(name)
        .image("node:alpine")
        .cpus(1)
        .memory(512)
        .network(|n| n.tls(|t| t.bypass("example.com")))
        .replace()
        .create()
        .await
        .expect("failed to create sandbox");

    let output = sandbox
        .shell(concat!(
            "node -e \"",
            "setTimeout(() => process.exit(1), 15000);",
            "fetch('https://example.com')",
            ".then(r => { console.log(r.status); process.exit(0); })",
            ".catch(e => { console.error(e.message); process.exit(1); });",
            "\""
        ))
        .await
        .expect("shell failed");

    let stdout = output.stdout().expect("invalid utf8");
    assert_eq!(
        stdout.trim(),
        "200",
        "bypass domain fetch failed: {stdout} (stderr: {})",
        output.stderr().unwrap_or_default()
    );

    sandbox.stop_and_wait().await.expect("failed to stop");
    Sandbox::remove(name).await.expect("failed to remove");
}

//! Integration tests for TLS interception.
//!
//! These tests require KVM (or libkrun on macOS) and are `#[ignore]` by
//! default so they don't run in `cargo test --workspace`. Run them
//! explicitly with `cargo test -p microsandbox -- --ignored`.

use microsandbox::Sandbox;

/// Regression test for #542: Node.js fetch over TLS 1.3 used to deadlock
/// because application data piggybacked on the TLS Finished message was
/// never drained from the handshake buffer.
#[tokio::test]
#[ignore]
async fn tls13_node_fetch_does_not_hang() {
    let name = "tls-test-node13";
    let sandbox = Sandbox::builder(name)
        .image("node")
        .cpus(1)
        .memory(512)
        .network(|n| n.tls(|t| t))
        .replace()
        .create()
        .await
        .expect("failed to create sandbox");

    let output = sandbox
        .shell(concat!(
            "node -e \"",
            "setTimeout(() => { process.exit(1); }, 15000);",
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
        "expected HTTP 200, got: {stdout} (stderr: {})",
        output.stderr().unwrap_or_default()
    );

    sandbox.stop_and_wait().await.expect("failed to stop");
    Sandbox::remove(name).await.expect("failed to remove");
}

/// Verify HTTPS works through the TLS interception proxy using wget
/// (covers non-Node.js clients that typically use TLS 1.2).
#[tokio::test]
#[ignore]
async fn tls_intercept_wget_https() {
    let name = "tls-test-wget";
    let sandbox = Sandbox::builder(name)
        .image("alpine")
        .cpus(1)
        .memory(512)
        .network(|n| n.tls(|t| t))
        .replace()
        .create()
        .await
        .expect("failed to create sandbox");

    let output = sandbox
        .shell("wget -q -O /dev/null --timeout=10 https://example.com && echo OK || echo FAIL")
        .await
        .expect("shell failed");

    let stdout = output.stdout().expect("invalid utf8");
    assert_eq!(stdout.trim(), "OK", "wget HTTPS failed: {stdout}");

    sandbox.stop_and_wait().await.expect("failed to stop");
    Sandbox::remove(name).await.expect("failed to remove");
}

/// Verify TLS bypass domains skip interception and still connect.
#[tokio::test]
#[ignore]
async fn tls_bypass_domain_connects() {
    let name = "tls-test-bypass";
    let sandbox = Sandbox::builder(name)
        .image("node")
        .cpus(1)
        .memory(512)
        .network(|n| n.tls(|t| t.bypass("example.com")))
        .replace()
        .create()
        .await
        .expect("failed to create sandbox");

    // Bypassed domain should connect directly (no MITM cert).
    let output = sandbox
        .shell("curl -s -o /dev/null -w '%{http_code}' --max-time 10 https://example.com")
        .await
        .expect("shell failed");

    let stdout = output.stdout().expect("invalid utf8");
    assert_eq!(
        stdout.trim(),
        "200",
        "bypass domain failed (stderr: {})",
        output.stderr().unwrap_or_default()
    );

    sandbox.stop_and_wait().await.expect("failed to stop");
    Sandbox::remove(name).await.expect("failed to remove");
}

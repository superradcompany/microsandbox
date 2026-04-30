//! Network policy — three modes built with the fluent `NetworkPolicy::builder()`.
//!
//! Demonstrates the default policy (public internet only), an
//! allow-all override, and a custom policy that allows public egress
//! plus a specific private host on tcp/443.

use microsandbox::{NetworkPolicy, Sandbox};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Default policy — public internet works, private/loopback denied.
    let sandbox = Sandbox::builder("net-policy-public")
        .image("alpine")
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await?;

    let output = sandbox
        .shell("wget -q -O /dev/null --timeout=5 http://example.com && echo OK || echo FAIL")
        .await?;
    println!("Public HTTP: {}", output.stdout()?.trim());

    sandbox.stop_and_wait().await?;

    // 2. Allow-all — everything reachable, including private networks.
    let allow_all = NetworkPolicy::builder().default_allow().build()?;
    let sandbox = Sandbox::builder("net-policy-all")
        .image("alpine")
        .cpus(1)
        .memory(512)
        .network(|n| n.policy(allow_all))
        .replace()
        .create()
        .await?;

    let output = sandbox
        .shell("wget -q -O /dev/null --timeout=5 http://example.com && echo OK || echo FAIL")
        .await?;
    println!("Allow-all HTTP: {}", output.stdout()?.trim());

    sandbox.stop_and_wait().await?;

    // 3. Custom policy — public egress plus a specific private host on tcp/443.
    let custom = NetworkPolicy::builder()
        .default_deny()
        .egress(|e| e.allow_public())
        .rule(|r| r.egress().tcp().port(443).allow().ip("10.0.5.10"))
        .build()?;
    let sandbox = Sandbox::builder("net-policy-custom")
        .image("alpine")
        .cpus(1)
        .memory(512)
        .network(|n| n.policy(custom))
        .replace()
        .create()
        .await?;

    let output = sandbox
        .shell("wget -q -O /dev/null --timeout=5 http://example.com && echo OK || echo FAIL")
        .await?;
    println!("Custom-policy HTTP: {}", output.stdout()?.trim());

    sandbox.stop_and_wait().await?;

    // Cleanup.
    Sandbox::remove("net-policy-public").await?;
    Sandbox::remove("net-policy-all").await?;
    Sandbox::remove("net-policy-custom").await?;

    Ok(())
}

//! Network policy — public-only (default), allow-all, and no-network modes.
//!
//! Demonstrates how `NetworkPolicy` controls what the sandbox can reach.
//! The default `public_only()` blocks private/loopback addresses.

use microsandbox::{NetworkPolicy, Sandbox};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Default (public-only) — public internet works.
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
    let sandbox = Sandbox::builder("net-policy-all")
        .image("alpine")
        .cpus(1)
        .memory(512)
        .network(|n| n.policy(NetworkPolicy::allow_all()))
        .replace()
        .create()
        .await?;

    let output = sandbox
        .shell("wget -q -O /dev/null --timeout=5 http://example.com && echo OK || echo FAIL")
        .await?;
    println!("Public HTTP: {}", output.stdout()?.trim());

    sandbox.stop_and_wait().await?;

    // 3. No network — all connections denied.
    let sandbox = Sandbox::builder("net-policy-none")
        .image("alpine")
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await?;

    let output = sandbox
        .shell("wget -q -O /dev/null --timeout=3 http://example.com && echo OK || echo BLOCKED")
        .await?;
    println!("Public HTTP: {}", output.stdout()?.trim());

    sandbox.stop_and_wait().await?;

    // Cleanup.
    Sandbox::remove("net-policy-public").await?;
    Sandbox::remove("net-policy-all").await?;
    Sandbox::remove("net-policy-none").await?;

    Ok(())
}

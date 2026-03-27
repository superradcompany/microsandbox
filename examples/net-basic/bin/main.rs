//! Basic networking — DNS resolution, HTTP fetch, and interface status.
//!
//! Demonstrates that a sandbox has outbound internet connectivity out of
//! the box via the smoltcp in-process networking stack.

use microsandbox::sandbox::Sandbox;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = Sandbox::builder("net-basic")
        .image("alpine:latest")
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await?;

    // DNS resolution.
    let output = sandbox.shell("nslookup example.com 2>&1 | head -8").await?;
    println!("DNS:\n{}", output.stdout()?);

    // HTTP fetch.
    let output = sandbox
        .shell("wget -q -O - http://example.com 2>&1 | head -3")
        .await?;
    println!("HTTP:\n{}", output.stdout()?);

    // Interface status.
    let output = sandbox.shell("ip addr show eth0").await?;
    println!("Interface:\n{}", output.stdout()?);

    sandbox.stop_and_wait().await?;
    Ok(())
}

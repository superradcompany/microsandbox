//! Domain filtering — block specific domains and suffixes via policy
//! rules.
//!
//! Demonstrates domain blocking through the network policy: blocked
//! domains get REFUSED at the DNS forwarder; allowed domains resolve
//! normally.

use microsandbox::{NetworkPolicy, Sandbox};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy = NetworkPolicy::builder()
        .default_allow()
        .rule(|r| r.egress().deny().domain("blocked.example.com"))
        .rule(|r| r.egress().deny().domain_suffix(".evil.com"))
        .build()?;

    let sandbox = Sandbox::builder("net-dns")
        .image("alpine")
        .cpus(1)
        .memory(512)
        .network(|n| n.policy(policy))
        .replace()
        .create()
        .await?;

    // Allowed domain resolves normally.
    let output = sandbox
        .shell("nslookup example.com 2>&1 | grep -c Address || echo 0")
        .await?;
    println!("example.com: {} address(es)", output.stdout()?.trim());

    // Exact-match blocked domain fails.
    let output = sandbox
        .shell("nslookup blocked.example.com 2>&1 && echo RESOLVED || echo BLOCKED")
        .await?;
    println!(
        "blocked.example.com: {}",
        last_line(output.stdout()?.trim())
    );

    // Suffix-match blocked domain fails.
    let output = sandbox
        .shell("nslookup anything.evil.com 2>&1 && echo RESOLVED || echo BLOCKED")
        .await?;
    println!("anything.evil.com: {}", last_line(output.stdout()?.trim()));

    // Unrelated domain still works.
    let output = sandbox
        .shell("nslookup cloudflare.com 2>&1 | grep -c Address || echo 0")
        .await?;
    println!("cloudflare.com: {} address(es)", output.stdout()?.trim());

    sandbox.stop_and_wait().await?;
    Sandbox::remove("net-dns").await?;

    Ok(())
}

fn last_line(s: &str) -> &str {
    s.lines().last().unwrap_or(s)
}

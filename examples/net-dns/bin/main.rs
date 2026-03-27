//! DNS filtering — block specific domains and suffixes.
//!
//! Demonstrates the DNS interceptor's domain blocking. Blocked domains
//! get a SERVFAIL response; allowed domains resolve normally.

use microsandbox::sandbox::Sandbox;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = Sandbox::builder("net-dns")
        .image("alpine:latest")
        .cpus(1)
        .memory(512)
        .network(|n| {
            n.block_domain("blocked.example.com")
                .block_domain_suffix(".evil.com")
        })
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

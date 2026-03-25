//! Secret injection — placeholder substitution in TLS-intercepted requests.
//!
//! Demonstrates:
//! 1. Secret env vars are auto-exposed with placeholder values.
//! 2. HTTPS to the allowed host works (placeholder substituted transparently).
//! 3. HTTPS to a disallowed host with the placeholder is BLOCKED (violation).

use microsandbox::sandbox::Sandbox;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Secret configured via shorthand. TLS interception auto-enabled.
    // Placeholder auto-generated as $MSB_API_KEY.
    let sandbox = Sandbox::builder("net-secrets")
        .image("alpine:latest")
        .cpus(1)
        .memory(512)
        .secret_env("API_KEY", "sk-real-secret-123", "example.com")
        .overwrite()
        .create()
        .await?;

    // 1. Env var auto-set — guest only sees the placeholder.
    let output = sandbox.shell("echo $API_KEY").await?;
    let placeholder = output.stdout()?.trim().to_string();
    println!("Guest env: API_KEY={placeholder}");

    // 2. HTTPS to allowed host — proxy substitutes secret, request succeeds.
    let output = sandbox
        .shell("wget -q -O /dev/null --timeout=10 https://example.com && echo OK || echo FAIL")
        .await?;
    println!(
        "HTTPS to example.com (allowed): {}",
        output.stdout()?.trim()
    );

    // 3. HTTPS to disallowed host WITH placeholder in header — BLOCKED.
    let output = sandbox
        .shell(concat!(
            "wget -q -O /dev/null --timeout=5 ",
            "--header='Authorization: Bearer $MSB_API_KEY' ",
            "https://cloudflare.com 2>&1 && echo OK || echo BLOCKED",
        ))
        .await?;
    println!(
        "HTTPS to cloudflare.com with placeholder (disallowed): {}",
        output.stdout()?.trim().lines().last().unwrap_or("?"),
    );

    sandbox.stop_and_wait().await?;
    Sandbox::remove("net-secrets").await?;

    Ok(())
}

//! Secret injection — placeholder substitution in TLS-intercepted requests.

use microsandbox::Sandbox;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // `secret_env` auto-enables TLS interception; placeholder is `$MSB_API_KEY`.
    let sandbox = Sandbox::builder("net-secrets")
        .image("alpine")
        .cpus(1)
        .memory(512)
        .secret_env("API_KEY", "sk-real-secret-123", "example.com")
        .replace()
        .create()
        .await?;

    // Guest only sees the placeholder, never the real value.
    let output = sandbox.shell("echo $API_KEY").await?;
    let placeholder = output.stdout()?.trim().to_string();
    println!("Guest env: API_KEY={placeholder}");

    // Allowed host: the TLS proxy substitutes the placeholder for the real
    // secret in-flight, so the request goes through.
    let output = sandbox
        .shell("wget -q -O /dev/null --timeout=10 https://example.com && echo OK || echo FAIL")
        .await?;
    println!(
        "HTTPS to example.com (allowed): {}",
        output.stdout()?.trim()
    );

    // Disallowed host: the placeholder leaving for the wrong destination
    // is a violation, so the proxy blocks the request.
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

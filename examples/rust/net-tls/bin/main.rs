//! TLS interception — MITM proxy with per-domain certificate generation.

use microsandbox::Sandbox;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = Sandbox::builder("net-tls")
        .image("alpine")
        .cpus(1)
        .memory(512)
        .network(|n| n.tls(|t| t.bypass("*.bypass-example.com")))
        .replace()
        .create()
        .await?;

    let output = sandbox
        .shell("ls /.msb/tls/ca.pem 2>&1 && echo FOUND || echo MISSING")
        .await?;
    println!(
        "CA cert: {}",
        output.stdout()?.trim().lines().last().unwrap_or("?")
    );

    let output = sandbox.shell("echo $SSL_CERT_FILE").await?;
    println!("SSL_CERT_FILE: {}", output.stdout()?.trim());

    let output = sandbox
        .shell("grep -c 'BEGIN CERTIFICATE' /etc/ssl/certs/ca-certificates.crt")
        .await?;
    println!("Certs in bundle: {}", output.stdout()?.trim());

    // Plain HTTP is unaffected by interception.
    let output = sandbox
        .shell("wget -q -O /dev/null --timeout=5 http://example.com && echo OK || echo FAIL")
        .await?;
    println!("\nHTTP: {}", output.stdout()?.trim());

    // HTTPS through the interception proxy. The guest's trust store has
    // the sandbox CA, so wget's default cert validation succeeds.
    let output = sandbox
        .shell("wget -q -O /dev/null --timeout=10 https://example.com 2>&1 && echo OK || echo FAIL")
        .await?;
    println!("HTTPS (intercepted): {}", output.stdout()?.trim());

    // Same path with cert validation disabled — exercises the TCP-only
    // bypass that fires when the client doesn't validate.
    let output = sandbox
        .shell("wget --no-check-certificate -q -O /dev/null --timeout=10 https://example.com 2>&1 && echo OK || echo FAIL")
        .await?;
    println!("HTTPS (no-verify): {}", output.stdout()?.trim());

    sandbox.stop_and_wait().await?;
    Sandbox::remove("net-tls").await?;

    Ok(())
}

//! Port publishing — expose a guest HTTP server on a host port.
//!
//! Starts a simple HTTP server inside the sandbox and publishes it
//! to the host via `.port(host, guest)`.

use microsandbox::Sandbox;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Creating sandbox with published port 8080 → 80");

    let sandbox = Sandbox::builder("net-ports")
        .image("alpine:latest")
        .cpus(1)
        .memory(512)
        .port(8080, 80)
        .replace()
        .create()
        .await?;

    // Start a tiny HTTP responder using BusyBox nc. Alpine's BusyBox build in
    // this image does not include the httpd applet.
    let output = sandbox
        .shell(
            "(while true; do printf 'HTTP/1.1 200 OK\\r\\nContent-Length: 24\\r\\nConnection: close\\r\\n\\r\\nHello from microsandbox!' | nc -l -p 80; done) >/tmp/net-ports.log 2>&1 & echo ok",
        )
        .await?;

    println!(
        "HTTP server started with BusyBox nc: {}",
        output.stdout()?.trim()
    );

    // Fetch from the host side via the published port.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;
    match client.get("http://127.0.0.1:8080/index.html").send().await {
        Ok(resp) => println!("Host-side:  {}", resp.text().await?.trim()),
        Err(e) => eprintln!("Host-side:  could not reach guest server: {e}"),
    }

    // Stop the sandbox.
    sandbox.stop_and_wait().await?;
    println!("Sandbox stopped.");
    Ok(())
}

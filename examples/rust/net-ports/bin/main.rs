//! Port publishing — expose a guest HTTP server on a host port.

use microsandbox::Sandbox;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = Sandbox::builder("net-ports")
        .image("alpine")
        .cpus(1)
        .memory(512)
        .port(8080, 80)
        .replace()
        .create()
        .await?;

    // Alpine BusyBox doesn't ship the httpd applet; use nc instead.
    let output = sandbox
        .shell(
            "(while true; do printf 'HTTP/1.1 200 OK\\r\\nContent-Length: 24\\r\\nConnection: close\\r\\n\\r\\nHello from microsandbox!' | nc -l -p 80; done) >/tmp/net-ports.log 2>&1 & echo ok",
        )
        .await?;

    println!("HTTP server started: {}", output.stdout()?.trim());

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;
    match client.get("http://127.0.0.1:8080/index.html").send().await {
        Ok(resp) => println!("Host-side:  {}", resp.text().await?.trim()),
        Err(e) => eprintln!("Host-side:  could not reach guest server: {e}"),
    }

    sandbox.stop_and_wait().await?;
    Ok(())
}

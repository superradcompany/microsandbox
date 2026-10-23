//! Body secret injection — placeholder substituted in HTTP body by the TLS proxy.

mod sandbox;
mod server;

use microsandbox::Sandbox;
use std::net::{IpAddr, UdpSocket};

const HOSTNAME: &str = "mock-api";
const PORT: u16 = 4443;
const SECRET: &str = "sk-real-secret-value-12345";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host_ip = local_ip().to_string();

    let handle = server::spawn(HOSTNAME, PORT, SECRET).await?;
    println!("[server] Listening on https://{host_ip}:{PORT}");

    let sb = sandbox::create(SECRET, HOSTNAME, PORT, &handle.ca_cert_path).await?;

    let response = sandbox::post_secret(&sb, HOSTNAME, &host_ip, PORT).await?;
    sb.stop().await?;
    Sandbox::remove("net-secrets-body").await?;

    let confirmation: serde_json::Value = serde_json::from_str(&response)?;
    if confirmation
        .get("received_key")
        .and_then(|value| value.as_bool())
        != Some(true)
    {
        return Err(std::io::Error::other("secret substitution failed").into());
    }
    println!("[guest]  Secret substitution confirmed");

    Ok(())
}

/// Detect a local non-loopback IP by briefly opening a UDP socket.
fn local_ip() -> IpAddr {
    let socket = UdpSocket::bind("0.0.0.0:0").expect("bind failed");
    socket.connect("8.8.8.8:80").expect("connect failed");
    socket.local_addr().expect("local_addr failed").ip()
}

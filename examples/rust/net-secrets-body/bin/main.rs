//! Body secret injection — placeholder substituted in HTTP body by the TLS proxy.
//!
//! Spins up a self-signed HTTPS server in the same process, creates a sandbox
//! with a body-injected secret, and has the guest POST the placeholder.
//! The server logs the real secret it receives; the guest only ever sees the placeholder.

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

    let handle = server::spawn(HOSTNAME, PORT).await?;
    println!("[server] Listening on https://{host_ip}:{PORT}");

    let sb = sandbox::create(SECRET, HOSTNAME, PORT, &handle.ca_cert_path).await?;

    // Guest sees only the placeholder.
    let out = sb.shell("echo $API_KEY").await?;
    println!("[guest]  API_KEY = {}", out.stdout()?.trim());

    // Guest POSTs the placeholder in a JSON body — the TLS proxy substitutes the real secret.
    let response = sandbox::post_secret(&sb, HOSTNAME, &host_ip, PORT).await?;
    println!("[guest]  Server responded: {response}");

    sb.stop_and_wait().await?;
    Sandbox::remove("net-secrets-body").await?;
    println!("[host]   Done.");

    Ok(())
}

/// Detect a local non-loopback IP by briefly opening a UDP socket.
fn local_ip() -> IpAddr {
    let socket = UdpSocket::bind("0.0.0.0:0").expect("bind failed");
    socket.connect("8.8.8.8:80").expect("connect failed");
    socket.local_addr().expect("local_addr failed").ip()
}

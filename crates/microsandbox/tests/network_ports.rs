//! Integration tests for published ports.
//!
//! These tests require KVM (or libkrun on macOS). The `#[msb_test]` attribute
//! marks them `#[ignore]`, so plain `cargo test --workspace` skips them.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use microsandbox::{NetworkPolicy, Sandbox};
use test_utils::msb_test;
use tokio::net::UdpSocket;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

#[msb_test]
async fn udp_published_port_round_trips() {
    let name = "network-ports-udp";
    let host_port = reserve_udp_port().await;
    let guest_port = 5353;

    let sandbox = Sandbox::builder(name)
        .image("mirror.gcr.io/library/node:alpine")
        .cpus(1)
        .memory(512)
        .port_udp(host_port, guest_port)
        .replace()
        .network(|n| n.policy(NetworkPolicy::allow_all()))
        .create()
        .await
        .expect("create sandbox");

    sandbox
        .shell(format!(
            "node -e \"{}\" >/tmp/udp-echo.log 2>&1 & echo ready",
            udp_echo_server_js(guest_port)
        ))
        .await
        .expect("start UDP echo server");
    let guest_probe = sandbox
        .shell(format!("node -e \"{}\"", udp_echo_client_js(guest_port)))
        .await
        .expect("probe UDP echo server inside guest");
    assert_eq!(
        guest_probe.stdout().unwrap_or_default().trim(),
        "guest:probe"
    );

    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("bind host UDP client");
    let server = SocketAddr::from((Ipv4Addr::LOCALHOST, host_port));
    let mut buf = [0u8; 64];
    let mut received = None;

    for _ in 0..20 {
        socket
            .send_to(b"ping", server)
            .await
            .expect("send UDP datagram");
        match tokio::time::timeout(Duration::from_millis(250), socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => {
                received = Some(buf[..n].to_vec());
                break;
            }
            _ => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }

    let diagnostics = if received.is_none() {
        sandbox
            .shell("cat /tmp/udp-echo.log 2>/dev/null || true; ip addr show dev eth0 || true")
            .await
            .ok()
            .and_then(|output| output.stdout().ok())
            .unwrap_or_default()
    } else {
        String::new()
    };

    sandbox.stop_and_wait().await.expect("stop");
    let _ = Sandbox::remove(name).await;

    assert_eq!(
        received.as_deref(),
        Some(b"guest:ping".as_slice()),
        "UDP echo diagnostics:\n{diagnostics}",
    );
}

async fn reserve_udp_port() -> u16 {
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("reserve UDP port");
    socket.local_addr().expect("local UDP addr").port()
}

fn udp_echo_server_js(port: u16) -> String {
    format!(
        "const d=require('dgram');\
         const s=d.createSocket('udp4');\
         s.on('message',(m,r)=>s.send(Buffer.concat([Buffer.from('guest:'),m]),r.port,r.address));\
         s.bind({port},'0.0.0.0');\
         setInterval(()=>{{}},1000);"
    )
}

fn udp_echo_client_js(port: u16) -> String {
    format!(
        "const d=require('dgram');\
         const s=d.createSocket('udp4');\
         s.on('message',m=>{{console.log(m.toString());s.close();}});\
         s.send(Buffer.from('probe'),{port},'127.0.0.1');\
         setTimeout(()=>process.exit(1),2000);"
    )
}

//! Integration tests for published ports.
//!
//! These tests require KVM (or libkrun on macOS). The `#[msb_test]` attribute
//! marks them `#[ignore]`, so plain `cargo test --workspace` skips them.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use microsandbox::{MicrosandboxError, MicrosandboxResult, NetworkPolicy, Sandbox, Snapshot};
use test_utils::msb_test;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const UDP_ECHO_LOG_PATH: &str = "/tmp/udp-echo.log";
const UDP_ECHO_READY_PATH: &str = "/tmp/udp-echo.ready";

/// No Content-Length: the client must receive EOF to finish reading.
const CLOSE_DELIMITED_RESPONSE: &[u8] = b"HTTP/1.0 200 OK\r\n\r\nhi";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn stop_and_remove(name: &str) {
    let handle = Sandbox::get(name).await.expect("get");
    handle.stop().await.expect("stop");
    let _ = Sandbox::remove(name).await;
}

async fn remove_bind_test_sandbox(name: &str) {
    match Sandbox::get(name).await {
        Ok(handle) => {
            // Failed startup may already have stopped the runtime.
            let _ = handle.stop().await;
            Sandbox::remove(name)
                .await
                .expect("remove owned test sandbox");
        }
        Err(MicrosandboxError::SandboxNotFound(_)) => {}
        Err(error) => panic!("query owned test sandbox: {error}"),
    }
}

fn assert_bind_refused(result: MicrosandboxResult<Sandbox>, protocol: &str, address: SocketAddr) {
    let error = result
        .err()
        .expect("occupied published port unexpectedly became ready");
    let message = error.to_string();
    assert!(
        message.contains(protocol),
        "missing protocol in startup error: {message}"
    );
    assert!(
        message.contains(&address.to_string()),
        "missing host endpoint in startup error: {message}"
    );
}

/// A successful guest boot must not hide host publication failures.
#[msb_test]
async fn occupied_published_ports_refuse_cold_startup() {
    let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    for (protocol, address) in [
        ("TCP", tcp.local_addr().unwrap()),
        ("UDP", udp.local_addr().unwrap()),
    ] {
        let name = format!("port-bind-{:016x}", rand::random::<u64>());
        let builder = Sandbox::builder(&name)
            .image("mirror.gcr.io/library/alpine")
            .cpus(1)
            .memory(256);
        let result = if protocol == "TCP" {
            builder.port(address.port(), 8000).create().await
        } else {
            builder.port_udp(address.port(), 8000).create().await
        };
        remove_bind_test_sandbox(&name).await;
        assert_bind_refused(result, protocol, address);
    }
}

/// Restore must reserve the destination ports before exposing a ready child.
#[msb_test]
async fn occupied_published_ports_refuse_full_restore() {
    let source_name = format!("port-source-{:016x}", rand::random::<u64>());
    let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let free_port = reserve_tcp_port().await;
    let captured = async {
        let source = Sandbox::builder(&source_name)
            .image("mirror.gcr.io/library/alpine")
            .cpus(1)
            .memory(256)
            .create()
            .await?;
        let output = source
            .shell("printf 'publication-state' > /tmp/port-state")
            .await?;
        if !output.status().success {
            return Err(MicrosandboxError::Io(std::io::Error::other(
                "prepare snapshot state",
            )));
        }
        Snapshot::builder("port-publication")
            .from_sandbox(&source_name)
            .full()
            .create()
            .await
    }
    .await;
    remove_bind_test_sandbox(&source_name).await;
    let snapshot = captured.expect("capture Full snapshot");
    let mut outcomes = Vec::new();
    for (protocol, address) in [
        ("TCP", tcp.local_addr().unwrap()),
        ("UDP", udp.local_addr().unwrap()),
    ] {
        let name = format!("port-restore-{:016x}", rand::random::<u64>());
        let builder = Sandbox::restore_ref(snapshot.reference())
            .name(&name)
            .network_policy(NetworkPolicy::allow_all());
        let result = if protocol == "TCP" {
            builder.port(address.port(), 8000).restore().await
        } else {
            builder.port_udp(address.port(), 8000).restore().await
        };
        remove_bind_test_sandbox(&name).await;
        outcomes.push((result, protocol, address));
    }
    let restored_name = format!("port-free-{:016x}", rand::random::<u64>());
    let success = async {
        let restored = Sandbox::restore_ref(snapshot.reference())
            .name(&restored_name)
            .network_policy(NetworkPolicy::allow_all())
            .port(free_port, 8000)
            .restore()
            .await?;
        let output = restored.shell("cat /tmp/port-state").await?;
        let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, free_port)).await?;
        drop(stream);
        Ok::<_, MicrosandboxError>(output)
    }
    .await;
    remove_bind_test_sandbox(&restored_name).await;
    Snapshot::remove_ref(snapshot.reference(), false)
        .await
        .expect("remove test snapshot");
    for (result, protocol, address) in outcomes {
        assert_bind_refused(result, protocol, address);
    }
    let output = success.expect("restore to an available port");
    assert!(output.status().success);
    assert_eq!(output.stdout().unwrap(), "publication-state");
}

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
            "rm -f {UDP_ECHO_READY_PATH} {UDP_ECHO_LOG_PATH}; \
             node -e \"{}\" >{UDP_ECHO_LOG_PATH} 2>&1 &",
            udp_echo_server_js(guest_port)
        ))
        .await
        .expect("start UDP echo server");
    wait_for_udp_echo_server(&sandbox).await;

    let guest_probe = sandbox
        .shell(format!("node -e \"{}\"", udp_echo_client_js(guest_port)))
        .await
        .expect("probe UDP echo server inside guest");
    let guest_stdout = guest_probe.stdout().unwrap_or_default();
    let guest_stderr = guest_probe.stderr().unwrap_or_default();
    assert!(
        guest_probe.status().success,
        "guest UDP probe failed: stdout=`{guest_stdout}` stderr=`{guest_stderr}` server-log=`{}`",
        read_udp_echo_log(&sandbox).await
    );
    assert_eq!(guest_stdout.trim(), "guest:probe");

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
            .shell(format!(
                "cat {UDP_ECHO_LOG_PATH} 2>/dev/null || true; \
                 ip addr show dev eth0 || true"
            ))
            .await
            .ok()
            .and_then(|output| output.stdout().ok())
            .unwrap_or_default()
    } else {
        String::new()
    };

    stop_and_remove(name).await;

    assert_eq!(
        received.as_deref(),
        Some(b"guest:ping".as_slice()),
        "UDP echo diagnostics:\n{diagnostics}",
    );
}

/// Regression for #1705: close-delimited HTTP must deliver EOF.
#[msb_test]
async fn tcp_published_port_delivers_guest_close_to_host() {
    let name = "network-ports-tcp-guest-close";
    let host_port = reserve_tcp_port().await;
    let guest_port = 8080;

    let sandbox = Sandbox::builder(name)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(512)
        .port(host_port, guest_port)
        .replace()
        .create()
        .await
        .expect("create sandbox");

    sandbox
        .shell(format!(
            "printf 'HTTP/1.0 200 OK\\r\\n\\r\\nhi' | nc -l -p {guest_port} >/dev/null 2>&1 &"
        ))
        .await
        .expect("start one-shot TCP server");
    wait_for_tcp_listener(&sandbox, guest_port).await;

    let result = tokio::time::timeout(Duration::from_secs(10), async {
        let mut stream =
            TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, host_port))).await?;
        let mut body = Vec::new();
        stream.read_to_end(&mut body).await?;
        Ok::<_, std::io::Error>(body)
    })
    .await;

    stop_and_remove(name).await;

    let body = result
        .expect("host client did not see EOF after the guest closed")
        .expect("read from published port");
    assert_eq!(body, CLOSE_DELIMITED_RESPONSE);
}

async fn wait_for_tcp_listener(sandbox: &Sandbox, port: u16) {
    for _ in 0..50 {
        let ready = sandbox
            .shell(format!(
                "netstat -tln 2>/dev/null | grep -q ':{port} ' && echo ready || true"
            ))
            .await
            .expect("check TCP listener readiness");
        if ready.stdout().unwrap_or_default().trim() == "ready" {
            return;
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    panic!("TCP listener on guest port {port} did not become ready");
}

async fn wait_for_udp_echo_server(sandbox: &Sandbox) {
    for _ in 0..50 {
        let ready = sandbox
            .shell(format!(
                "test -f {UDP_ECHO_READY_PATH} && echo ready || true"
            ))
            .await
            .expect("check UDP echo readiness");
        if ready.stdout().unwrap_or_default().trim() == "ready" {
            return;
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    panic!(
        "UDP echo server did not become ready; log:\n{}",
        read_udp_echo_log(sandbox).await
    );
}

async fn read_udp_echo_log(sandbox: &Sandbox) -> String {
    sandbox
        .shell(format!("cat {UDP_ECHO_LOG_PATH} 2>/dev/null || true"))
        .await
        .ok()
        .and_then(|output| output.stdout().ok())
        .unwrap_or_default()
}

async fn reserve_tcp_port() -> u16 {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("reserve TCP port");
    listener.local_addr().expect("local TCP addr").port()
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
         const fs=require('fs');\
         const s=d.createSocket('udp4');\
         s.on('message',(m,r)=>s.send(Buffer.concat([Buffer.from('guest:'),m]),r.port,r.address));\
         s.on('error',e=>{{console.error(e.stack||e);process.exit(1);}});\
         s.bind({port},'0.0.0.0',()=>fs.writeFileSync('{UDP_ECHO_READY_PATH}','ready'));\
         setInterval(()=>{{}},1000);"
    )
}

fn udp_echo_client_js(port: u16) -> String {
    format!(
        "const d=require('dgram');\
         const s=d.createSocket('udp4');\
         const t=setTimeout(()=>process.exit(1),2000);\
         s.on('message',m=>{{clearTimeout(t);console.log(m.toString());s.close(()=>process.exit(0));}});\
         s.send(Buffer.from('probe'),{port},'127.0.0.1');\
         "
    )
}

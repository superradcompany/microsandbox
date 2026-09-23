//! Integration tests for outbound proxy routing.
//!
//! These tests require KVM (or libkrun on macOS). The [`msb_test`] attribute
//! marks them ignored for ordinary workspace test runs.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};

use microsandbox::{Sandbox, SecretSource};
use test_utils::msb_test;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const PASSWORD_ENV: &str = "MSB_TEST_SOCKS5_PROXY_PASSWORD";
const PROXY_USERNAME: &str = "sandbox";
const PROXY_PASSWORD: &str = "proxy-password";
const UDP_TARGET_IP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 10);
const UDP_TARGET_PORT: u16 = 19090;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Minimal authenticated SOCKS5 proxy that serves one UDP association.
struct AuthenticatedUdpProxy {
    address: SocketAddr,
    handle: JoinHandle<io::Result<()>>,
}

/// Removes one test-only host environment variable when dropped.
struct EnvGuard(&'static str);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl AuthenticatedUdpProxy {
    async fn start() -> io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let relay = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let relay_address = relay.local_addr()?;

        let handle = tokio::spawn(async move {
            let (mut control, _) = listener.accept().await?;

            let mut greeting = [0u8; 4];
            control.read_exact(&mut greeting).await?;
            if greeting != [0x05, 0x02, 0x00, 0x02] {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unexpected SOCKS5 greeting: {greeting:?}"),
                ));
            }
            control.write_all(&[0x05, 0x02]).await?;

            let (username, password) = Self::read_credentials(&mut control).await?;
            if username != PROXY_USERNAME || password != PROXY_PASSWORD {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "unexpected SOCKS5 credentials",
                ));
            }
            control.write_all(&[0x01, 0x00]).await?;

            Self::read_command(&mut control).await?;

            let SocketAddr::V4(relay_address) = relay_address else {
                unreachable!("fixture binds an IPv4 relay")
            };
            let mut reply = vec![0x05, 0x00, 0x00, 0x01];
            reply.extend_from_slice(&relay_address.ip().octets());
            reply.extend_from_slice(&relay_address.port().to_be_bytes());
            control.write_all(&reply).await?;

            let mut datagram = [0u8; 128];
            let (received, client) = relay.recv_from(&mut datagram).await?;
            let (header_len, target) = Self::decode_udp_header(&datagram[..received])?;
            if target != SocketAddr::from((UDP_TARGET_IP, UDP_TARGET_PORT))
                || &datagram[header_len..received] != b"ping"
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected proxied UDP datagram",
                ));
            }

            let mut response = datagram[..header_len].to_vec();
            response.extend_from_slice(b"pong");
            relay.send_to(&response, client).await?;
            Ok(())
        });

        Ok(Self { address, handle })
    }

    async fn read_credentials(control: &mut tokio::net::TcpStream) -> io::Result<(String, String)> {
        let version = control.read_u8().await?;
        if version != 0x01 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid username/password authentication version",
            ));
        }
        let username_len = control.read_u8().await? as usize;
        let mut username = vec![0u8; username_len];
        control.read_exact(&mut username).await?;
        let password_len = control.read_u8().await? as usize;
        let mut password = vec![0u8; password_len];
        control.read_exact(&mut password).await?;

        let username = String::from_utf8(username)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let password = String::from_utf8(password)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        Ok((username, password))
    }

    async fn read_command(control: &mut tokio::net::TcpStream) -> io::Result<SocketAddr> {
        let mut request = [0u8; 10];
        control.read_exact(&mut request).await?;
        if request[..4] != [0x05, 0x03, 0x00, 0x01] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected SOCKS5 command: {request:?}"),
            ));
        }
        Ok(SocketAddr::from((
            Ipv4Addr::new(request[4], request[5], request[6], request[7]),
            u16::from_be_bytes([request[8], request[9]]),
        )))
    }

    fn decode_udp_header(datagram: &[u8]) -> io::Result<(usize, SocketAddr)> {
        if datagram.len() < 10 || datagram[..4] != [0x00, 0x00, 0x00, 0x01] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid SOCKS5 UDP datagram",
            ));
        }
        Ok((
            10,
            SocketAddr::from((
                Ipv4Addr::new(datagram[4], datagram[5], datagram[6], datagram[7]),
                u16::from_be_bytes([datagram[8], datagram[9]]),
            )),
        ))
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    async fn join(self) -> io::Result<()> {
        tokio::time::timeout(std::time::Duration::from_secs(10), self.handle)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "proxy fixture timed out"))?
            .map_err(io::Error::other)?
    }
}

impl EnvGuard {
    fn set(name: &'static str, value: &str) -> Self {
        // SAFETY: this test owns a unique environment-variable name.
        unsafe { std::env::set_var(name, value) };
        Self(name)
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        // SAFETY: this test owns a unique environment-variable name.
        unsafe { std::env::remove_var(self.0) };
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[msb_test]
async fn authenticated_socks5_proxy_routes_udp() {
    let proxy = AuthenticatedUdpProxy::start().await.expect("proxy fixture");
    let _password = EnvGuard::set(PASSWORD_ENV, PROXY_PASSWORD);
    let name = "socks5-authenticated-udp";
    let sandbox = Sandbox::builder(name)
        .image("mirror.gcr.io/library/python:3.12-alpine")
        .cpus(1)
        .memory(256)
        .proxy(|p| {
            p.socks5(proxy.address().to_string())
                .credentials(PROXY_USERNAME, SecretSource::env(PASSWORD_ENV))
        })
        .replace()
        .create()
        .await
        .expect("create sandbox");

    let output = sandbox
        .shell(format!(
            "python -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5); s.sendto(b\"ping\", (\"{}\", {})); print(s.recv(4).decode(), end=\"\")'",
            UDP_TARGET_IP, UDP_TARGET_PORT,
        ))
        .await
        .expect("send proxied UDP datagram");
    proxy.join().await.expect("proxy fixture completed");
    assert_eq!(
        output.stdout().expect("UTF-8 stdout"),
        "pong",
        "guest command failed with status {:?} and stderr: {}",
        output.status(),
        output.stderr().expect("UTF-8 stderr"),
    );

    drop(sandbox);
    let handle = Sandbox::get(name).await.expect("get sandbox");
    handle.stop().await.expect("stop sandbox");
    let _ = Sandbox::remove(name).await;
}

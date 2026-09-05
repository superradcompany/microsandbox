//! Host-side TCP destination selection and connection state reporting.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::connection::ProxyConnectState;
use crate::netstack::shared::SharedState;
use crate::proxy::ResolvedOutboundProxy;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const CONNECT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Ordered host-side TCP destinations for one guest connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UpstreamTcpTarget {
    primary: SocketAddr,
    fallback: Option<SocketAddr>,
    proxy: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl UpstreamTcpTarget {
    /// Create a target with no address-family fallback.
    pub(crate) fn direct(primary: SocketAddr) -> Self {
        Self {
            primary,
            fallback: None,
            proxy: None,
        }
    }

    /// Create a target with an alternate address-family destination.
    pub(crate) fn with_fallback(primary: SocketAddr, fallback: SocketAddr) -> Self {
        Self {
            primary,
            fallback: Some(fallback),
            proxy: None,
        }
    }

    /// Return the first host-side address to dial.
    pub(crate) fn primary(&self) -> SocketAddr {
        self.primary
    }

    pub(crate) fn with_proxy(mut self, proxy: Option<&str>) -> Self {
        self.proxy = proxy.map(str::to_owned);
        self
    }

    /// Connect and publish the final outcome to the guest proxy state.
    ///
    /// When `outbound_proxy` is set, it dials `primary` through that proxy
    /// instead of connecting directly; the address-family fallback only
    /// applies to direct dials.
    pub(crate) async fn connect(
        self,
        proxy_connect: &ProxyConnectState,
        shared: &SharedState,
        outbound_proxy: Option<&ResolvedOutboundProxy>,
    ) -> io::Result<TcpStream> {
        let result = match outbound_proxy {
            Some(proxy) => proxy.connect(self.primary).await,
            None => self.dial().await,
        };
        let stream = match result {
            Ok(stream) => stream,
            Err(error) => {
                proxy_connect.mark_upstream_connect_failed();
                shared.proxy_wake.wake();

                return Err(error);
            }
        };

        proxy_connect.mark_connected();

        Ok(stream)
    }

    async fn dial(self) -> io::Result<TcpStream> {
        let primary_error = match self.connect_one(self.primary).await {
            Ok(stream) => return Ok(stream),
            Err(error) => error,
        };

        let Some(fallback) = self.fallback.filter(|_| fallback_eligible(&primary_error)) else {
            return Err(primary_error);
        };

        tracing::debug!(
            primary = %self.primary,
            fallback = %fallback,
            error = %primary_error,
            "primary host loopback connection failed; trying alternate address family"
        );

        self.connect_one(fallback).await.map_err(|fallback_error| {
            let primary = self.primary;
            let message = format!(
                "failed to connect to host loopback {primary} ({primary_error}); alternate \
                     {fallback} also failed ({fallback_error})"
            );

            io::Error::new(fallback_error.kind(), message)
        })
    }

    async fn connect_one(&self, target: SocketAddr) -> io::Result<TcpStream> {
        let Some(proxy) = self.proxy.as_deref() else {
            return TcpStream::connect(target).await;
        };
        let proxy_addr = proxy_addr(proxy)?;
        let mut stream = TcpStream::connect(proxy_addr).await?;
        let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
        stream.write_all(request.as_bytes()).await?;
        let mut response = Vec::with_capacity(128);
        let mut byte = [0u8; 1];
        while response.len() < 8192 && !response.ends_with(b"\r\n\r\n") {
            tokio::time::timeout(CONNECT_RESPONSE_TIMEOUT, stream.read_exact(&mut byte))
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "timed out waiting for upstream CONNECT response",
                    )
                })??;
            response.push(byte[0]);
        }
        let status = response
            .split(|b| b.is_ascii_whitespace())
            .nth(1)
            .and_then(|v| std::str::from_utf8(v).ok())
            .and_then(|v| v.parse::<u16>().ok());
        if !status.is_some_and(|code| (200..300).contains(&code)) {
            return Err(io::Error::other("upstream proxy rejected CONNECT"));
        }
        Ok(stream)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn proxy_addr(value: &str) -> io::Result<SocketAddr> {
    let url = url::Url::parse(value).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid upstream proxy URL: {e}"),
        )
    })?;
    if url.scheme() != "http" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "upstream proxy must use http",
        ));
    }
    let host = url.host_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "upstream proxy URL has no host",
        )
    })?;
    let port = url.port_or_known_default().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "upstream proxy URL has no port",
        )
    })?;
    std::net::ToSocketAddrs::to_socket_addrs(&(host, port))?
        .next()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "upstream proxy host has no addresses",
            )
        })
}

fn fallback_eligible(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::AddrNotAvailable
            | io::ErrorKind::NetworkUnreachable
    )
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use tokio::net::TcpListener;

    use super::super::connection::ProxyConnectStatus;
    use super::*;

    #[tokio::test]
    async fn connect_falls_back_from_ipv6_to_ipv4_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let fallback = SocketAddr::new("127.0.0.1".parse().unwrap(), port);
        let primary = SocketAddr::new("::1".parse().unwrap(), port);
        let target = UpstreamTcpTarget::with_fallback(primary, fallback);
        let proxy_connect = ProxyConnectState::new();
        let shared = SharedState::new(4);

        let stream = target
            .connect(&proxy_connect, &shared, None)
            .await
            .expect("IPv4 loopback fallback should connect");

        assert_eq!(stream.peer_addr().unwrap(), fallback);
        assert_eq!(proxy_connect.status(), ProxyConnectStatus::Connected);
        let _accepted = listener.accept().await.unwrap();
    }
}

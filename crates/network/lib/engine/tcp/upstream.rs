//! Host-side TCP destination selection and connection state reporting.

use std::io;
use std::net::SocketAddr;

use tokio::net::TcpStream;

use super::connection::ProxyConnectState;
use crate::netstack::shared::SharedState;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Ordered host-side TCP destinations for one guest connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UpstreamTcpTarget {
    primary: SocketAddr,
    fallback: Option<SocketAddr>,
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
        }
    }

    /// Create a target with an alternate address-family destination.
    pub(crate) fn with_fallback(primary: SocketAddr, fallback: SocketAddr) -> Self {
        Self {
            primary,
            fallback: Some(fallback),
        }
    }

    /// Return the first host-side address to dial.
    pub(crate) fn primary(self) -> SocketAddr {
        self.primary
    }

    /// Connect and publish the final outcome to the guest proxy state.
    pub(crate) async fn connect(
        self,
        proxy_connect: &ProxyConnectState,
        shared: &SharedState,
    ) -> io::Result<TcpStream> {
        let stream = match self.dial().await {
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
        let primary_error = match TcpStream::connect(self.primary).await {
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

        TcpStream::connect(fallback)
            .await
            .map_err(|fallback_error| {
                let primary = self.primary;
                let message = format!(
                    "failed to connect to host loopback {primary} ({primary_error}); alternate \
                     {fallback} also failed ({fallback_error})"
                );

                io::Error::new(fallback_error.kind(), message)
            })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

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
            .connect(&proxy_connect, &shared)
            .await
            .expect("IPv4 loopback fallback should connect");

        assert_eq!(stream.peer_addr().unwrap(), fallback);
        assert_eq!(proxy_connect.status(), ProxyConnectStatus::Connected);
        let _accepted = listener.accept().await.unwrap();
    }
}

//! HTTP CONNECT outbound proxy builders and transport.

use std::net::AddrParseError;
#[cfg(feature = "engine")]
use std::{io, net::SocketAddr, time::Duration};

#[cfg(feature = "engine")]
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

use super::types::{
    OutboundProxy, OutboundProxyBuildError, OutboundProxyConfig, OutboundProxyProtocol,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "engine")]
const CONNECT_RESPONSE_HEADER_LIMIT: usize = 8192;
#[cfg(feature = "engine")]
const CONNECT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Builds an HTTP CONNECT outbound proxy.
#[derive(Debug, Clone)]
pub struct HttpConnectProxyBuilder {
    address: String,
}

/// HTTP CONNECT wire protocol operations.
#[cfg(feature = "engine")]
pub(super) struct HttpConnectProtocol;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl HttpConnectProxyBuilder {
    /// Creates a builder for the configured proxy address.
    pub(super) fn new(address: impl Into<String>) -> Self {
        Self {
            address: address.into(),
        }
    }
}

#[cfg(feature = "engine")]
impl HttpConnectProtocol {
    /// Opens a TCP tunnel through the configured HTTP proxy.
    pub(super) async fn connect(
        address: SocketAddr,
        destination: SocketAddr,
    ) -> io::Result<TcpStream> {
        let mut stream = TcpStream::connect(address).await?;
        let authority = destination.to_string();
        let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");

        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;

        let status = timeout(
            CONNECT_RESPONSE_TIMEOUT,
            Self::read_connect_response_status(&mut stream),
        )
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "HTTP CONNECT proxy did not complete its response headers within 10 seconds",
            )
        })??;

        if (200..300).contains(&status) {
            return Ok(stream);
        }

        let kind = if status == 407 {
            io::ErrorKind::PermissionDenied
        } else {
            io::ErrorKind::ConnectionRefused
        };

        Err(io::Error::new(
            kind,
            format!("HTTP CONNECT proxy rejected the tunnel with status {status}"),
        ))
    }

    async fn read_connect_response_status(stream: &mut TcpStream) -> io::Result<u16> {
        let mut total_header_bytes = 0;

        loop {
            let mut header = Vec::with_capacity(256);
            loop {
                if total_header_bytes >= CONNECT_RESPONSE_HEADER_LIMIT {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "HTTP CONNECT proxy response headers exceeded 8192 bytes",
                    ));
                }

                header.push(stream.read_u8().await?);
                total_header_bytes += 1;
                if header.ends_with(b"\r\n\r\n") {
                    break;
                }
            }

            let status_end = header
                .windows(2)
                .position(|window| window == b"\r\n")
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "HTTP CONNECT proxy returned an invalid status line",
                    )
                })?;
            let status_line = std::str::from_utf8(&header[..status_end]).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP CONNECT proxy returned a non-ASCII status line",
                )
            })?;
            let mut fields = status_line.split_ascii_whitespace();
            let version = fields.next().unwrap_or_default();

            if version != "HTTP/1.0" && version != "HTTP/1.1" {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP CONNECT proxy returned an invalid HTTP status line",
                ));
            }

            let status = fields
                .next()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "HTTP CONNECT proxy returned a status line without a status code",
                    )
                })?
                .parse::<u16>()
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "HTTP CONNECT proxy returned an invalid status code",
                    )
                })?;

            if (100..200).contains(&status) && status != 101 {
                continue;
            }

            return Ok(status);
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl OutboundProxyConfig for HttpConnectProxyBuilder {
    fn build(self) -> Result<OutboundProxy, OutboundProxyBuildError> {
        let address = self.address.parse().map_err(|source: AddrParseError| {
            OutboundProxyBuildError::InvalidAddress {
                protocol: OutboundProxyProtocol::HttpConnect,
                address: self.address,
                source,
            }
        })?;

        Ok(OutboundProxy::HttpConnect { address })
    }
}

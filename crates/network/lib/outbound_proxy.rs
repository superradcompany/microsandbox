//! Outbound proxy configuration, builders, parsing, and connection dispatch.

use std::fmt;
use std::io;
use std::net::{AddrParseError, SocketAddr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_socks::tcp::{Socks4Stream, Socks5Stream};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Proxy used for outbound sandbox connections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "lowercase")]
#[non_exhaustive]
pub enum OutboundProxy {
    /// A SOCKS4 proxy at the given address.
    Socks4 {
        /// Proxy socket address.
        address: SocketAddr,
        /// Optional user ID sent during the SOCKS4 handshake.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user_id: Option<String>,
    },

    /// A SOCKS5 proxy at the given address.
    Socks5 {
        /// Proxy socket address.
        address: SocketAddr,
    },
}

/// Protocol used by an [`OutboundProxy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum OutboundProxyProtocol {
    /// SOCKS version 4.
    Socks4,
    /// SOCKS version 5.
    Socks5,
}

/// Selects the protocol for an [`OutboundProxy`].
#[derive(Debug, Clone, Copy, Default)]
pub struct OutboundProxyBuilder;

/// Builds a SOCKS4 outbound proxy.
#[derive(Debug, Clone)]
pub struct Socks4ProxyBuilder {
    address: String,
    user_id: Option<String>,
}

/// Builds a SOCKS5 outbound proxy.
#[derive(Debug, Clone)]
pub struct Socks5ProxyBuilder {
    address: String,
}

/// Error returned when building an outbound proxy.
#[derive(Debug, Clone, thiserror::Error)]
pub enum OutboundProxyBuildError {
    /// The proxy address is not a valid socket address.
    #[error("invalid {protocol} proxy address {address:?}: {source}")]
    InvalidAddress {
        /// Proxy protocol whose address was invalid.
        protocol: OutboundProxyProtocol,
        /// Invalid address text.
        address: String,
        /// Socket-address parsing failure.
        #[source]
        source: AddrParseError,
    },

    /// A SOCKS4 user ID is empty, too long, or contains a null byte.
    #[error("invalid SOCKS4 user ID: {reason}")]
    InvalidSocks4UserId {
        /// Explanation of the validation failure.
        reason: &'static str,
    },
}

/// Error returned when parsing an outbound proxy URI.
///
/// URI parsing is intended for string-only interfaces such as the CLI. SDKs
/// should use [`OutboundProxyBuilder`] instead.
#[derive(Debug, Clone, thiserror::Error)]
pub enum OutboundProxyParseError {
    /// The URI does not include a `scheme://` prefix.
    #[error("outbound proxy URI must include a protocol, for example socks5://127.0.0.1:1080")]
    MissingProtocol,

    /// The URI uses a proxy protocol that is not supported yet.
    #[error(
        "unsupported outbound proxy protocol {protocol:?}; supported protocols are socks4:// and socks5://"
    )]
    UnsupportedProtocol {
        /// Unsupported URI scheme.
        protocol: String,
    },

    /// The URI includes credentials, which are not supported.
    #[error("outbound proxy credentials are not supported in the URI")]
    CredentialsNotSupported,

    /// The URI includes a path, query, or fragment.
    #[error("outbound proxy URI must not include a path, query, or fragment")]
    ExtraComponentsNotSupported,

    /// The proxy address is not a valid socket address.
    #[error(transparent)]
    Build(#[from] OutboundProxyBuildError),
}

/// Converts a protocol-specific proxy builder into an [`OutboundProxy`].
///
/// Sandbox-facing builders use this trait to finalize protocol-specific proxy
/// builders and collect their validation errors.
#[doc(hidden)]
pub trait OutboundProxyConfig {
    /// Builds the outbound proxy.
    fn build(self) -> Result<OutboundProxy, OutboundProxyBuildError>;
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl OutboundProxy {
    /// Connects to `destination` through this outbound proxy.
    pub(crate) async fn connect(&self, destination: SocketAddr) -> io::Result<TcpStream> {
        self.validate().map_err(io::Error::other)?;
        match self {
            Self::Socks4 { address, user_id } => match user_id {
                Some(user_id) => {
                    Socks4Stream::connect_with_userid(*address, destination, user_id).await
                }
                None => Socks4Stream::connect(*address, destination).await,
            }
            .map(|stream| stream.into_inner())
            .map_err(io::Error::other),
            Self::Socks5 { address } => Socks5Stream::connect(*address, destination)
                .await
                .map(|stream| stream.into_inner())
                .map_err(io::Error::other),
        }
    }

    fn validate(&self) -> Result<(), OutboundProxyBuildError> {
        match self {
            Self::Socks4 { user_id, .. } => Self::validate_socks4_user_id(user_id.as_deref()),
            Self::Socks5 { .. } => Ok(()),
        }
    }

    fn validate_socks4_user_id(user_id: Option<&str>) -> Result<(), OutboundProxyBuildError> {
        let Some(user_id) = user_id else {
            return Ok(());
        };
        let reason = if user_id.is_empty() {
            "must not be empty"
        } else if user_id.len() > 255 {
            "must be at most 255 bytes"
        } else if user_id.contains('\0') {
            "must not contain a null byte"
        } else {
            return Ok(());
        };

        Err(OutboundProxyBuildError::InvalidSocks4UserId { reason })
    }
}

impl OutboundProxyBuilder {
    /// Creates a protocol selector.
    pub fn new() -> Self {
        Self
    }

    /// Starts building a SOCKS4 outbound proxy.
    pub fn socks4(self, address: impl Into<String>) -> Socks4ProxyBuilder {
        Socks4ProxyBuilder {
            address: address.into(),
            user_id: None,
        }
    }

    /// Starts building a SOCKS5 outbound proxy.
    pub fn socks5(self, address: impl Into<String>) -> Socks5ProxyBuilder {
        Socks5ProxyBuilder {
            address: address.into(),
        }
    }
}

impl Socks4ProxyBuilder {
    /// Sets the optional user ID sent during the SOCKS4 handshake.
    pub fn user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl OutboundProxyConfig for Socks4ProxyBuilder {
    fn build(self) -> Result<OutboundProxy, OutboundProxyBuildError> {
        let address =
            self.address
                .parse()
                .map_err(|source| OutboundProxyBuildError::InvalidAddress {
                    protocol: OutboundProxyProtocol::Socks4,
                    address: self.address,
                    source,
                })?;

        OutboundProxy::validate_socks4_user_id(self.user_id.as_deref())?;
        Ok(OutboundProxy::Socks4 {
            address,
            user_id: self.user_id,
        })
    }
}

impl OutboundProxyConfig for Socks5ProxyBuilder {
    fn build(self) -> Result<OutboundProxy, OutboundProxyBuildError> {
        let address =
            self.address
                .parse()
                .map_err(|source| OutboundProxyBuildError::InvalidAddress {
                    protocol: OutboundProxyProtocol::Socks5,
                    address: self.address,
                    source,
                })?;
        Ok(OutboundProxy::Socks5 { address })
    }
}

impl OutboundProxyConfig for OutboundProxy {
    fn build(self) -> Result<OutboundProxy, OutboundProxyBuildError> {
        self.validate()?;
        Ok(self)
    }
}

impl fmt::Display for OutboundProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Socks4 { address, .. } => write!(f, "socks4://{address}"),
            Self::Socks5 { address } => write!(f, "socks5://{address}"),
        }
    }
}

impl fmt::Display for OutboundProxyProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Socks4 => f.write_str("SOCKS4"),
            Self::Socks5 => f.write_str("SOCKS5"),
        }
    }
}

impl FromStr for OutboundProxy {
    type Err = OutboundProxyParseError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let (protocol, address) = raw
            .split_once("://")
            .ok_or(OutboundProxyParseError::MissingProtocol)?;
        let protocol = match protocol {
            "socks4" => OutboundProxyProtocol::Socks4,
            "socks5" => OutboundProxyProtocol::Socks5,
            protocol => {
                return Err(OutboundProxyParseError::UnsupportedProtocol {
                    protocol: protocol.to_string(),
                });
            }
        };
        if address.contains('@') {
            return Err(OutboundProxyParseError::CredentialsNotSupported);
        }
        if address.contains(['/', '?', '#']) {
            return Err(OutboundProxyParseError::ExtraComponentsNotSupported);
        }
        match protocol {
            OutboundProxyProtocol::Socks4 => {
                Ok(OutboundProxyBuilder::new().socks4(address).build()?)
            }
            OutboundProxyProtocol::Socks5 => {
                Ok(OutboundProxyBuilder::new().socks5(address).build()?)
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::{
        OutboundProxy, OutboundProxyBuildError, OutboundProxyBuilder, OutboundProxyConfig,
        OutboundProxyProtocol,
    };

    #[test]
    fn builder_creates_socks4_proxy_with_optional_user_id() {
        let address = "127.0.0.1:1080".parse().unwrap();
        let without_user_id = OutboundProxyBuilder::new()
            .socks4("127.0.0.1:1080")
            .build()
            .unwrap();
        let with_user_id = OutboundProxyBuilder::new()
            .socks4("127.0.0.1:1080")
            .user_id("sandbox")
            .build()
            .unwrap();

        assert_eq!(
            without_user_id,
            OutboundProxy::Socks4 {
                address,
                user_id: None,
            }
        );
        assert_eq!(
            with_user_id,
            OutboundProxy::Socks4 {
                address,
                user_id: Some("sandbox".to_string()),
            }
        );
    }

    #[test]
    fn builder_creates_socks5_proxy() {
        let proxy = OutboundProxyBuilder::new()
            .socks5("127.0.0.1:1080")
            .build()
            .unwrap();

        assert_eq!(
            proxy,
            OutboundProxy::Socks5 {
                address: "127.0.0.1:1080".parse().unwrap(),
            }
        );
    }

    #[test]
    fn uri_parses_and_formats_for_cli() {
        let socks4: OutboundProxy = "socks4://127.0.0.1:1080".parse().unwrap();
        let socks5: OutboundProxy = "socks5://127.0.0.1:1080".parse().unwrap();

        assert_eq!(
            socks4,
            OutboundProxy::Socks4 {
                address: "127.0.0.1:1080".parse().unwrap(),
                user_id: None,
            }
        );
        assert_eq!(socks4.to_string(), "socks4://127.0.0.1:1080");
        assert_eq!(
            socks5,
            OutboundProxy::Socks5 {
                address: "127.0.0.1:1080".parse().unwrap(),
            }
        );
        assert_eq!(socks5.to_string(), "socks5://127.0.0.1:1080");
    }

    #[test]
    fn uri_rejects_unsupported_forms() {
        for raw in [
            "127.0.0.1:1080",
            "http://127.0.0.1:1080",
            "socks4://user@127.0.0.1:1080",
            "socks5://user@127.0.0.1:1080",
            "socks5://127.0.0.1:1080/path",
            "socks5://127.0.0.1:1080?option=value",
            "socks5://127.0.0.1:1080#fragment",
        ] {
            assert!(raw.parse::<OutboundProxy>().is_err(), "accepted {raw:?}");
        }
    }

    #[test]
    fn builder_rejects_invalid_socks4_user_ids() {
        for user_id in [String::new(), "a\0b".to_string(), "a".repeat(256)] {
            assert!(
                OutboundProxyBuilder::new()
                    .socks4("127.0.0.1:1080")
                    .user_id(user_id)
                    .build()
                    .is_err()
            );
        }
    }

    #[test]
    fn materialized_proxy_rejects_invalid_socks4_user_ids() {
        for user_id in [String::new(), "a\0b".to_string(), "a".repeat(256)] {
            let proxy = OutboundProxy::Socks4 {
                address: "127.0.0.1:1080".parse().unwrap(),
                user_id: Some(user_id),
            };

            assert!(proxy.build().is_err());
        }
    }

    #[test]
    fn invalid_address_error_uses_typed_protocol() {
        let error = OutboundProxyBuilder::new()
            .socks5("not-an-address")
            .build()
            .unwrap_err();

        assert!(matches!(
            error,
            OutboundProxyBuildError::InvalidAddress {
                protocol: OutboundProxyProtocol::Socks5,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn connects_through_socks4_proxy_with_user_id() {
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (mut client, _) = proxy_listener.accept().await.unwrap();

            let mut request = [0u8; 16];
            client.read_exact(&mut request).await.unwrap();
            assert_eq!(request[0], 0x04, "SOCKS version");
            assert_eq!(request[1], 0x01, "CONNECT command");
            assert_eq!(u16::from_be_bytes([request[2], request[3]]), 443);
            assert_eq!(&request[4..8], &[93, 184, 216, 34]);
            assert_eq!(&request[8..], b"sandbox\0");

            client
                .write_all(&[0x00, 0x5a, 0x01, 0xbb, 93, 184, 216, 34])
                .await
                .unwrap();

            let mut buf = [0u8; 5];
            client.read_exact(&mut buf).await.unwrap();
            client.write_all(&buf).await.unwrap();
        });

        let mut stream = OutboundProxy::Socks4 {
            address: proxy_addr,
            user_id: Some("sandbox".to_string()),
        }
        .connect(target)
        .await
        .unwrap();
        stream.write_all(b"hello").await.unwrap();
        let mut echoed = [0u8; 5];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello");

        proxy_task.await.unwrap();
    }

    #[tokio::test]
    async fn connects_through_socks5_proxy() {
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (mut client, _) = proxy_listener.accept().await.unwrap();

            let mut greeting = [0u8; 3];
            client.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            client.write_all(&[0x05, 0x00]).await.unwrap();

            let mut request = [0u8; 10];
            client.read_exact(&mut request).await.unwrap();
            assert_eq!(request[0], 0x05, "SOCKS version");
            assert_eq!(request[1], 0x01, "CONNECT command");
            assert_eq!(request[3], 0x01, "IPv4 address type");
            assert_eq!(&request[4..8], &[93, 184, 216, 34]);
            assert_eq!(u16::from_be_bytes([request[8], request[9]]), 443);

            client
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();

            let mut buf = [0u8; 5];
            client.read_exact(&mut buf).await.unwrap();
            client.write_all(&buf).await.unwrap();
        });

        let mut stream = OutboundProxy::Socks5 {
            address: proxy_addr,
        }
        .connect(target)
        .await
        .unwrap();
        stream.write_all(b"hello").await.unwrap();
        let mut echoed = [0u8; 5];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello");

        proxy_task.await.unwrap();
    }
}

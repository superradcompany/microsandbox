//! Outbound proxy configuration types and parsing.

use std::fmt;
use std::net::{AddrParseError, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::socks::Socks5Credentials;

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
        /// Optional durable username/password authentication configuration.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        credentials: Option<Socks5Credentials>,
    },
}

/// Fully resolved proxy used by the network runtime.
#[doc(hidden)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResolvedOutboundProxy {
    /// A SOCKS4 proxy ready for TCP connections.
    Socks4 {
        /// Proxy socket address.
        address: SocketAddr,
        /// Optional user ID sent during the SOCKS4 handshake.
        user_id: Option<String>,
    },

    /// A SOCKS5 proxy ready for TCP and UDP connections.
    Socks5 {
        /// Proxy socket address.
        address: SocketAddr,
        /// Optional resolved username/password authentication credentials.
        credentials: Option<super::socks::ResolvedSocks5Credentials>,
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

    /// A SOCKS5 username or password is empty or longer than 255 bytes.
    #[error("invalid SOCKS5 credentials: {reason}")]
    InvalidSocks5Credentials {
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

impl ResolvedOutboundProxy {
    /// Selects the configured proxy unless the host-side destination was
    /// rewritten for a host-local connection.
    pub(crate) fn select_for_destination(
        configured: &Option<Arc<Self>>,
        guest_dst: SocketAddr,
        host_dst: SocketAddr,
    ) -> Option<Arc<Self>> {
        if guest_dst == host_dst {
            configured.clone()
        } else {
            None
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Display for OutboundProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Socks4 { address, .. } => write!(f, "socks4://{address}"),
            Self::Socks5 { address, .. } => write!(f, "socks5://{address}"),
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

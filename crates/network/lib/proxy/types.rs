//! Outbound proxy configuration types and parsing.

use std::fmt;
use std::net::{AddrParseError, SocketAddr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use super::http_connect::HttpConnectCredentials;
#[cfg(feature = "engine")]
use super::http_connect::ResolvedHttpConnectEndpoint;
use super::socks::Socks5Credentials;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Proxy used for outbound sandbox connections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "lowercase")]
#[non_exhaustive]
pub enum OutboundProxy {
    /// An HTTP proxy that opens TCP tunnels with CONNECT.
    #[serde(rename = "http_connect")]
    HttpConnect {
        /// Proxy socket address.
        address: SocketAddr,
        /// Optional durable username/password authentication configuration.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        credentials: Option<HttpConnectCredentials>,
    },

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
    /// An HTTP CONNECT proxy ready for TCP connections.
    #[serde(rename = "http_connect")]
    HttpConnect {
        /// Proxy socket address.
        address: SocketAddr,
        /// Optional resolved username/password authentication credentials.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        credentials: Option<super::http_connect::ResolvedHttpConnectCredentials>,
    },

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

    /// An HTTP CONNECT proxy endpoint held only by the network runtime.
    ///
    /// Runtime-only: this generic in-memory leaf transport is never serialized,
    /// so the dial address and credentials cannot enter launch JSON, catalog
    /// state, snapshots, or logs.
    #[cfg(feature = "engine")]
    #[serde(skip)]
    HttpConnectEndpoint {
        /// Runtime-only endpoint used for the CONNECT handshake.
        endpoint: ResolvedHttpConnectEndpoint,
    },
}

/// Credentials resolved at launch for the configured outbound proxy.
#[doc(hidden)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolvedProxyCredentials {
    /// Resolved SOCKS5 username/password credentials.
    Socks5(super::socks::ResolvedSocks5Credentials),
    /// Resolved HTTP CONNECT username/password credentials.
    HttpConnect(super::http_connect::ResolvedHttpConnectCredentials),
}

/// Protocol used by an [`OutboundProxy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum OutboundProxyProtocol {
    /// HTTP CONNECT.
    #[serde(rename = "http_connect")]
    HttpConnect,

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

    /// An HTTP CONNECT username or password is invalid.
    #[error("invalid HTTP CONNECT credentials: {reason}")]
    InvalidHttpConnectCredentials {
        /// Explanation of the validation failure.
        reason: &'static str,
    },

    /// Resolved launch credentials do not match the configured outbound proxy.
    #[error("outbound proxy credential mismatch: {reason}")]
    ProxyCredentialMismatch {
        /// Explanation of the mismatch.
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
        "unsupported outbound proxy protocol {protocol:?}; supported protocols are http://, socks4://, and socks5://"
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

#[cfg(feature = "engine")]
impl ResolvedOutboundProxy {
    /// Returns the protocol this leaf speaks.
    ///
    /// Both HTTP CONNECT representations classify identically, so callers that
    /// need a transport capability never inspect where the endpoint came from.
    pub(crate) fn protocol(&self) -> OutboundProxyProtocol {
        match self {
            Self::HttpConnect { .. } | Self::HttpConnectEndpoint { .. } => {
                OutboundProxyProtocol::HttpConnect
            }
            Self::Socks4 { .. } => OutboundProxyProtocol::Socks4,
            Self::Socks5 { .. } => OutboundProxyProtocol::Socks5,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Display for OutboundProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HttpConnect { address, .. } => write!(f, "http://{address}"),
            Self::Socks4 { address, .. } => write!(f, "socks4://{address}"),
            Self::Socks5 { address, .. } => write!(f, "socks5://{address}"),
        }
    }
}

impl fmt::Display for OutboundProxyProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HttpConnect => f.write_str("HTTP CONNECT"),
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
            "http" => OutboundProxyProtocol::HttpConnect,
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
            OutboundProxyProtocol::HttpConnect => {
                Ok(OutboundProxyBuilder::new().http_connect(address).build()?)
            }
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

#[cfg(all(test, feature = "engine"))]
mod tests {
    use serde_json::json;

    use super::{OutboundProxyProtocol, ResolvedOutboundProxy};
    use crate::proxy::http_connect::{ConnectAddress, ResolvedHttpConnectEndpoint};
    use crate::proxy::{ResolvedHttpConnectCredentials, ResolvedSocks5Credentials};

    /// Golden launch shapes for every configured leaf, independent of the
    /// runtime CONNECT leaf. IPv4 and IPv6 addresses, credential presence and
    /// omission are all frozen here.
    #[test]
    fn configured_resolved_variants_keep_their_wire_shapes() {
        for (proxy, expected) in [
            (
                ResolvedOutboundProxy::HttpConnect {
                    address: "127.0.0.1:3128".parse().unwrap(),
                    credentials: None,
                },
                json!({"http_connect": {"address": "127.0.0.1:3128"}}),
            ),
            (
                ResolvedOutboundProxy::HttpConnect {
                    address: "[2001:db8::1]:3128".parse().unwrap(),
                    credentials: Some(ResolvedHttpConnectCredentials::new("user", "pass")),
                },
                json!({
                    "http_connect": {
                        "address": "[2001:db8::1]:3128",
                        "credentials": {"username": "user", "password": "pass"}
                    }
                }),
            ),
            (
                ResolvedOutboundProxy::Socks4 {
                    address: "127.0.0.1:1080".parse().unwrap(),
                    user_id: None,
                },
                json!({"Socks4": {"address": "127.0.0.1:1080", "user_id": null}}),
            ),
            (
                ResolvedOutboundProxy::Socks4 {
                    address: "[::1]:1080".parse().unwrap(),
                    user_id: Some("sandbox".to_string()),
                },
                json!({"Socks4": {"address": "[::1]:1080", "user_id": "sandbox"}}),
            ),
            (
                ResolvedOutboundProxy::Socks5 {
                    address: "127.0.0.1:1080".parse().unwrap(),
                    credentials: None,
                },
                json!({"Socks5": {"address": "127.0.0.1:1080", "credentials": null}}),
            ),
            (
                ResolvedOutboundProxy::Socks5 {
                    address: "[2001:db8::2]:1080".parse().unwrap(),
                    credentials: Some(ResolvedSocks5Credentials::new("user", "pass")),
                },
                json!({
                    "Socks5": {
                        "address": "[2001:db8::2]:1080",
                        "credentials": {"username": "user", "password": "pass"}
                    }
                }),
            ),
        ] {
            let serialized = serde_json::to_value(&proxy).unwrap();
            assert_eq!(serialized, expected);

            let restored: ResolvedOutboundProxy = serde_json::from_value(serialized).unwrap();
            assert_eq!(restored, proxy);
        }
    }

    /// Both CONNECT representations classify as HTTP CONNECT, so capability
    /// checks never depend on where the endpoint came from.
    #[test]
    fn connect_representations_share_one_protocol_class() {
        let runtime = ResolvedOutboundProxy::HttpConnectEndpoint {
            endpoint: ResolvedHttpConnectEndpoint::new(
                ConnectAddress::Host {
                    name: "proxy.test".to_string(),
                    port: 3128,
                },
                None,
                None,
            ),
        };
        for proxy in [
            ResolvedOutboundProxy::HttpConnect {
                address: "127.0.0.1:3128".parse().unwrap(),
                credentials: None,
            },
            runtime,
        ] {
            assert_eq!(proxy.protocol(), OutboundProxyProtocol::HttpConnect);
        }
        assert_eq!(
            ResolvedOutboundProxy::Socks4 {
                address: "127.0.0.1:1080".parse().unwrap(),
                user_id: None,
            }
            .protocol(),
            OutboundProxyProtocol::Socks4
        );
        assert_eq!(
            ResolvedOutboundProxy::Socks5 {
                address: "127.0.0.1:1080".parse().unwrap(),
                credentials: None,
            }
            .protocol(),
            OutboundProxyProtocol::Socks5
        );
    }
}

//! Outbound proxy configuration and transport implementations.

mod http_connect;
mod socks;
mod types;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "engine")]
pub use crate::tcp::proxy::*;

pub use http_connect::HttpConnectProxyBuilder;
#[doc(hidden)]
pub use socks::ResolvedSocks5Credentials;
pub use socks::{Socks4ProxyBuilder, Socks5Credentials, Socks5ProxyBuilder};
#[doc(hidden)]
pub use types::ResolvedOutboundProxy;
pub use types::{
    OutboundProxy, OutboundProxyBuildError, OutboundProxyBuilder, OutboundProxyConfig,
    OutboundProxyParseError, OutboundProxyProtocol,
};

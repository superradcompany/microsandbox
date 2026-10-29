//! Outbound proxy configuration and transport implementations.

#[cfg(feature = "engine")]
mod ambient;
mod http_connect;
#[cfg(feature = "engine")]
mod routing;
mod socks;
mod types;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "engine")]
pub use crate::tcp::proxy::*;

#[cfg(feature = "engine")]
#[doc(hidden)]
pub use ambient::AmbientHttpProxy;
#[cfg(feature = "engine")]
#[doc(hidden)]
pub use routing::OutboundRouting;

#[doc(hidden)]
pub use http_connect::ResolvedHttpConnectCredentials;
#[doc(hidden)]
#[cfg(feature = "engine")]
pub use http_connect::ResolvedHttpConnectEndpoint;
pub use http_connect::{HttpConnectCredentials, HttpConnectProxyBuilder};
#[doc(hidden)]
pub use socks::ResolvedSocks5Credentials;
pub use socks::{Socks4ProxyBuilder, Socks5Credentials, Socks5ProxyBuilder};
#[doc(hidden)]
pub use types::ResolvedOutboundProxy;
#[doc(hidden)]
pub use types::ResolvedProxyCredentials;
pub use types::{
    OutboundProxy, OutboundProxyBuildError, OutboundProxyBuilder, OutboundProxyConfig,
    OutboundProxyParseError, OutboundProxyProtocol,
};

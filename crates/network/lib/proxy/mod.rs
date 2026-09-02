//! Outbound proxy configuration and transport implementations.

mod socks;
mod types;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use crate::tcp::proxy::*;

#[doc(hidden)]
pub use socks::ResolvedSocks5Credentials;
pub use socks::{Socks4ProxyBuilder, Socks5Credentials, Socks5ProxyBuilder};
#[doc(hidden)]
pub use types::ResolvedOutboundProxy;
pub use types::{
    OutboundProxy, OutboundProxyBuildError, OutboundProxyBuilder, OutboundProxyConfig,
    OutboundProxyParseError, OutboundProxyProtocol,
};

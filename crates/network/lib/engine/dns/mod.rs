//! DNS interception, forwarding, and host resolver implementation.

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub(crate) mod client;
pub(crate) mod common;
pub(crate) mod forwarder;
pub mod interceptor;
pub(crate) mod nameserver;
pub(crate) mod proxies;
#[cfg(windows)]
pub(crate) mod windows_resolver;

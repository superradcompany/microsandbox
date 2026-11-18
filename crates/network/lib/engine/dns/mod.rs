//! DNS interception, forwarding, and host resolver implementation.

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub(crate) mod client;
pub(crate) mod common;
pub(crate) mod forwarder;
pub mod interceptor;
pub(super) mod name_policy;
pub(crate) mod nameserver;
pub(crate) mod proxies;
pub(super) mod response_policy;
#[cfg(windows)]
pub(crate) mod windows_resolver;
mod wire_names;

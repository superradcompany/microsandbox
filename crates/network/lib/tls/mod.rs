//! TLS interception: inline MITM for the smoltcp networking stack.
//!
//! All TCP connections terminate at smoltcp. For intercepted ports, the proxy
//! task does TLS MITM by terminating the guest's TLS with a generated
//! per-domain certificate and re-originating a TLS connection to the real
//! server.

pub(crate) mod ca;
pub(crate) mod certgen;
pub mod config;
pub(crate) mod proxy;
pub(crate) mod sni;
pub mod state;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use config::*;

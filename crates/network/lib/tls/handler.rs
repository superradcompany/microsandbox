//! Intercept handler trait — hook point for the secrets layer.
//!
//! The TLS proxy calls this trait for each intercepted connection's plaintext
//! bytes between TLS termination and re-encryption. The default implementation
//! passes data through unchanged. The secrets layer replaces it with
//! substitution logic.

use std::net::SocketAddr;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Called by the TLS proxy for each intercepted request's plaintext bytes.
///
/// This is an internal trait, not public API. The secrets layer implements it
/// with the substitution engine.
pub trait InterceptHandler: Send + Sync {
    /// Inspect/modify outbound plaintext bytes before re-encryption.
    ///
    /// Returns the (possibly modified) bytes to send to the real server.
    fn on_request(&self, _dst: &SocketAddr, _sni: &str, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }

    /// Inspect/modify inbound plaintext bytes before re-encryption toward guest.
    ///
    /// Returns the (possibly modified) bytes to send to the guest.
    fn on_response(&self, _dst: &SocketAddr, _sni: &str, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }
}

/// No-op handler used when no secrets layer is active.
pub struct NoopHandler;

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl InterceptHandler for NoopHandler {}

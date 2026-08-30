//! TLS configuration models and optional engine state.
//!
//! Configuration types remain available to SDK consumers without the
//! heavyweight networking engine. Enabling `engine` additionally exposes the
//! runtime TLS state while keeping implementation helpers crate-private.

#[cfg(feature = "engine")]
pub use crate::engine::tls::state;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use microsandbox_types::{
    CertCacheConfig, InterceptCaConfig, ScopedUpstreamCaCert, ScopedVerifyUpstream, TlsConfig,
};

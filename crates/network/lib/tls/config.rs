//! TLS interception configuration types.
//!
//! The data types ([`TlsConfig`], [`InterceptCaConfig`], [`CertCacheConfig`])
//! live in the shared `microsandbox-types` crate so the cloud control plane, the
//! SDKs, and this engine speak one contract. This module re-exports them so
//! existing `microsandbox_network::tls::*` paths are unchanged.

pub use microsandbox_types::{
    CertCacheConfig, InterceptCaConfig, ScopedUpstreamCaCert, ScopedVerifyUpstream, TlsConfig,
};

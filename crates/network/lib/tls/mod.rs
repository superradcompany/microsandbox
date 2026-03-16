//! TLS interception: transparent MITM proxy for sandbox egress connections.
//!
//! When enabled, msbnet installs kernel-level redirect rules (nftables on Linux,
//! pf on macOS) that route intercepted TCP connections to a local proxy listener.
//! The proxy terminates guest TLS with a per-domain certificate signed by a
//! microsandbox CA, connects upstream with real TLS, and relays plaintext
//! bidirectionally.
//!
//! All TLS code is behind the `tls` feature flag (default on). When the feature
//! is disabled, `TlsConfig` is a no-op stub that serializes to `{}`.

#[cfg(feature = "tls")]
mod bypass;
#[cfg(feature = "tls")]
mod ca;
#[cfg(feature = "tls")]
mod cache;
#[cfg(feature = "tls")]
mod certgen;
#[cfg(feature = "tls")]
mod config;
#[cfg(feature = "tls")]
mod handler;
#[cfg(feature = "tls")]
mod proxy;
#[cfg(feature = "tls")]
mod redirect;
#[cfg(all(feature = "tls", target_os = "linux"))]
mod redirect_linux;
#[cfg(all(feature = "tls", target_os = "macos"))]
mod redirect_macos;
#[cfg(feature = "tls")]
mod sni;
#[cfg(feature = "tls")]
mod upstream;

#[cfg(feature = "tls")]
pub use bypass::*;
#[cfg(feature = "tls")]
pub use ca::*;
#[cfg(feature = "tls")]
pub use cache::*;
#[cfg(feature = "tls")]
pub use certgen::*;
#[cfg(feature = "tls")]
pub use config::*;
#[cfg(feature = "tls")]
pub use handler::*;
#[cfg(feature = "tls")]
pub use proxy::*;
#[cfg(feature = "tls")]
pub use redirect::*;
#[cfg(feature = "tls")]
pub use sni::*;
#[cfg(feature = "tls")]
pub use upstream::*;

// Stub when tls feature is off — NetworkConfig always compiles.
#[cfg(not(feature = "tls"))]
mod stub {
    /// No-op TLS configuration stub when the `tls` feature is disabled.
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub struct TlsConfig {}

    impl Default for TlsConfig {
        fn default() -> Self {
            Self {}
        }
    }
}

#[cfg(not(feature = "tls"))]
pub use stub::*;

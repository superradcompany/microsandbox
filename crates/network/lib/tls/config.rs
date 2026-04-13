//! TLS interception configuration types.
//!
//! These types configure inline TLS MITM for the smoltcp networking stack.
//! All TCP connections terminate at smoltcp, so TLS interception is handled
//! directly by proxy tasks — no kernel redirect rules needed.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// TLS interception configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Whether TLS interception is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// TCP ports subject to TLS interception (default: `[443]`).
    #[serde(default = "default_intercepted_ports")]
    pub intercepted_ports: Vec<u16>,

    /// Domains to bypass (no MITM). Supports exact match and `*.suffix` wildcards.
    #[serde(default)]
    pub bypass: Vec<String>,

    /// Whether to verify the upstream server's TLS certificate.
    #[serde(default = "default_true")]
    pub verify_upstream: bool,

    /// Drop UDP to intercepted ports when TLS interception is active,
    /// forcing QUIC traffic to fall back to TCP/TLS.
    #[serde(default = "default_true")]
    pub block_quic_on_intercept: bool,

    /// CA certificate PEM files to trust for upstream server verification.
    #[serde(default)]
    pub upstream_ca_cert: Vec<PathBuf>,

    /// Interception CA configuration. The TLS proxy uses this CA to sign
    /// per-domain certs that it presents to the guest during interception.
    #[serde(default, alias = "ca")]
    pub intercept_ca: InterceptCaConfig,

    /// Per-domain certificate cache configuration.
    #[serde(default)]
    pub cache: CertCacheConfig,
}

/// Certificate authority configuration for TLS interception.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InterceptCaConfig {
    /// Path to an existing CA certificate PEM file.
    /// If `None`, a CA is auto-generated and persisted.
    #[serde(default)]
    pub cert_path: Option<PathBuf>,

    /// Path to an existing CA private key PEM file.
    /// If `None`, a key is auto-generated and persisted.
    #[serde(default)]
    pub key_path: Option<PathBuf>,
}

/// Per-domain certificate cache configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertCacheConfig {
    /// Maximum number of cached certificates. Default: 1000.
    #[serde(default = "default_cache_capacity")]
    pub capacity: usize,

    /// Certificate validity duration in hours. Default: 24.
    #[serde(default = "default_cert_validity_hours")]
    pub validity_hours: u64,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            intercepted_ports: default_intercepted_ports(),
            bypass: Vec::new(),
            verify_upstream: true,
            block_quic_on_intercept: true,
            upstream_ca_cert: Vec::new(),
            intercept_ca: InterceptCaConfig::default(),
            cache: CertCacheConfig::default(),
        }
    }
}

impl Default for CertCacheConfig {
    fn default() -> Self {
        Self {
            capacity: default_cache_capacity(),
            validity_hours: default_cert_validity_hours(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn default_true() -> bool {
    true
}

fn default_intercepted_ports() -> Vec<u16> {
    vec![443]
}

fn default_cache_capacity() -> usize {
    1000
}

fn default_cert_validity_hours() -> u64 {
    24
}

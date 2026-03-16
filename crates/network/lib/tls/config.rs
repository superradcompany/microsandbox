use std::path::PathBuf;

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// TLS interception configuration.
///
/// When `enabled` is true, msbnet installs kernel-level redirect rules for
/// `intercepted_ports` and runs a transparent TLS proxy that terminates guest
/// connections with per-domain certificates signed by a microsandbox CA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Whether TLS interception is active.
    #[serde(default)]
    pub enabled: bool,

    /// TCP ports to intercept (default: `[443]`).
    #[serde(default = "default_intercepted_ports")]
    pub intercepted_ports: Vec<u16>,

    /// Domains to bypass (no interception). Supports exact match and
    /// `*.suffix` wildcard patterns.
    #[serde(default)]
    pub bypass: Vec<String>,

    /// Whether to verify upstream server certificates against the host's
    /// system trust store (default: true). Disable only for testing or
    /// internal services with self-signed certs.
    #[serde(default = "default_true")]
    pub verify_upstream: bool,

    /// CA certificate configuration.
    #[serde(default)]
    pub ca: CaConfig,

    /// Certificate cache configuration.
    #[serde(default)]
    pub cache: CertCacheConfig,
}

/// CA certificate configuration.
///
/// By default, msbnet generates a self-signed P-256 EC CA on first use and
/// persists it to `~/.microsandbox/tls/`. User-provided CA paths override
/// generation for corporate PKI integration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaConfig {
    /// Subject CN for the generated CA certificate.
    #[serde(default = "default_ca_cn")]
    pub cn: String,

    /// Validity period in days for the generated CA certificate.
    #[serde(default = "default_ca_validity_days")]
    pub validity_days: u32,

    /// Path to a user-provided CA certificate (PEM). When set together with
    /// `key`, msbnet uses these directly instead of generating a CA.
    #[serde(default)]
    pub cert: Option<PathBuf>,

    /// Path to a user-provided CA private key (PEM).
    #[serde(default)]
    pub key: Option<PathBuf>,
}

/// Certificate cache configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertCacheConfig {
    /// Maximum number of cached per-domain certificates.
    #[serde(default = "default_cache_max_entries")]
    pub max_entries: usize,

    /// TTL in seconds for cached certificates.
    #[serde(default = "default_cache_ttl_secs")]
    pub ttl_secs: u64,
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
            ca: CaConfig::default(),
            cache: CertCacheConfig::default(),
        }
    }
}

impl Default for CaConfig {
    fn default() -> Self {
        Self {
            cn: default_ca_cn(),
            validity_days: default_ca_validity_days(),
            cert: None,
            key: None,
        }
    }
}

impl Default for CertCacheConfig {
    fn default() -> Self {
        Self {
            max_entries: default_cache_max_entries(),
            ttl_secs: default_cache_ttl_secs(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn default_intercepted_ports() -> Vec<u16> {
    vec![443]
}

fn default_true() -> bool {
    true
}

fn default_ca_cn() -> String {
    "Microsandbox CA".to_string()
}

fn default_ca_validity_days() -> u32 {
    365
}

fn default_cache_max_entries() -> usize {
    1000
}

fn default_cache_ttl_secs() -> u64 {
    86400
}

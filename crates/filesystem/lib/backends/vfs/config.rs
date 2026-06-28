//! Configuration for [`VirtualFs`](super::VirtualFs) and launch-time mount knobs.

use std::time::Duration;

/// Cache policy for FUSE open options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachePolicy {
    /// No caching — sets `DIRECT_IO`.
    Never,
    /// Let the kernel decide.
    Auto,
    /// Aggressive caching — sets `KEEP_CACHE`/`CACHE_DIR`.
    Always,
}

/// Serializable cache knobs for a virtual mount carried in launch config.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct VirtualFsMountConfig {
    /// FUSE entry cache timeout in seconds. Defaults to 1 when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_timeout_secs: Option<u64>,
    /// FUSE attribute cache timeout in seconds. Defaults to 1 when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attr_timeout_secs: Option<u64>,
    /// Cache policy: `"never"`, `"auto"`, or `"always"`. Defaults to `"auto"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_policy: Option<String>,
    /// Enable writeback caching. Defaults to `false` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writeback: Option<bool>,
    /// Per-op RPC call timeout in seconds: how long a single FUSE op waits for
    /// the provider before it is failed (surfaced to the guest as `EIO`). A
    /// transport concern rather than a FUSE-cache one, so it is read separately
    /// and does not flow through [`into_virtual_fs_config`](Self::into_virtual_fs_config).
    /// `None` lets the transport apply its built-in default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_timeout_secs: Option<u64>,
}

/// Maximum [`VirtualFsMountConfig::call_timeout_secs`]: one day.
const MAX_CALL_TIMEOUT_SECS: u64 = 86_400;

/// Maximum FUSE entry/attribute cache timeout in seconds.
const MAX_CACHE_TIMEOUT_SECS: u64 = 86_400;

impl VirtualFsMountConfig {
    /// The configured per-op call timeout, if any.
    pub fn call_timeout(&self) -> Option<Duration> {
        self.call_timeout_secs.map(Duration::from_secs)
    }

    /// Validate cache-policy strings and call-timeout bounds before spawn.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(ref policy) = self.cache_policy {
            match policy.as_str() {
                "never" | "auto" | "always" => {}
                other => {
                    return Err(format!("invalid virtual mount cache_policy: {other}"));
                }
            }
        }
        if let Some(secs) = self.call_timeout_secs {
            if secs == 0 {
                return Err(
                    "invalid virtual mount call_timeout_secs: must be positive when set".into(),
                );
            }
            if secs > MAX_CALL_TIMEOUT_SECS {
                return Err(format!(
                    "invalid virtual mount call_timeout_secs: too large (max {MAX_CALL_TIMEOUT_SECS})"
                ));
            }
        }
        for (label, secs) in [
            ("entry_timeout_secs", self.entry_timeout_secs),
            ("attr_timeout_secs", self.attr_timeout_secs),
        ] {
            if let Some(secs) = secs {
                if secs == 0 {
                    return Err(format!(
                        "invalid virtual mount {label}: must be positive when set"
                    ));
                }
                if secs > MAX_CACHE_TIMEOUT_SECS {
                    return Err(format!(
                        "invalid virtual mount {label}: too large (max {MAX_CACHE_TIMEOUT_SECS})"
                    ));
                }
            }
        }
        Ok(())
    }

    /// Convert into a runtime [`VirtualFsConfig`], applying documented defaults.
    pub fn into_virtual_fs_config(self) -> VirtualFsConfig {
        let cache_policy = match self.cache_policy.as_deref() {
            Some("never") => CachePolicy::Never,
            Some("always") => CachePolicy::Always,
            Some("auto") | None => CachePolicy::Auto,
            _ => unreachable!("cache_policy validated before conversion"),
        };
        VirtualFsConfig {
            entry_timeout: Duration::from_secs(self.entry_timeout_secs.unwrap_or(1)),
            attr_timeout: Duration::from_secs(self.attr_timeout_secs.unwrap_or(1)),
            cache_policy,
            writeback: self.writeback.unwrap_or(false),
        }
    }
}

/// Configuration for a [`super::VirtualFs`].
#[derive(Debug, Clone)]
pub struct VirtualFsConfig {
    /// FUSE entry cache timeout.
    pub entry_timeout: Duration,
    /// FUSE attribute cache timeout.
    pub attr_timeout: Duration,
    /// Cache policy.
    pub cache_policy: CachePolicy,
    /// Enable writeback caching.
    pub writeback: bool,
}

impl Default for VirtualFsConfig {
    fn default() -> Self {
        Self {
            entry_timeout: Duration::from_secs(1),
            attr_timeout: Duration::from_secs(1),
            cache_policy: CachePolicy::Auto,
            writeback: false,
        }
    }
}

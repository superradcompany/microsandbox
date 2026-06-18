//! Backend selection: profile + env + config-file resolution.
//!
//! Precedence ladder (each tier wins over the one below):
//!
//! 1. Programmatic: explicit `.backend(b)` on a builder or
//!    `microsandbox::set_default_backend(...)` — handled by the caller, not here.
//! 2. Env: `MSB_BACKEND=local` → local, `MSB_API_URL` + `MSB_API_KEY` → cloud.
//! 3. Env: `MSB_PROFILE=<name>` → look up that profile in the config file.
//! 4. Config: `active_profile` field → use that profile.
//! 5. Fallback: `LocalBackend`.
//!
//! The SDK-level config lives at `~/.microsandbox/config.json` alongside the
//! existing [`LocalConfig`](crate::config::LocalConfig) (paths, DB url,
//! sandbox defaults, …). The two are orthogonal sections of the same file;
//! this module only touches `active_profile` + `profiles`.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::{Backend, CloudBackend, LocalBackend};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// SDK-level configuration loaded from `~/.microsandbox/config.json`.
///
/// `serde(default)` everywhere — a missing file or missing keys are equivalent
/// to defaults. Coexists with [`LocalConfig`](crate::config::LocalConfig) in
/// the same JSON document; serde ignores fields it doesn't know.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SdkConfig {
    /// Profile to use when none is named explicitly. Resolved against
    /// [`SdkConfig::profiles`]. Empty / missing → no active profile (falls
    /// through to local fallback).
    pub active_profile: Option<String>,

    /// Named profiles. Each profile selects a backend and (for cloud) provides
    /// the URL + a credential reference.
    pub profiles: HashMap<String, Profile>,
}

/// A single named profile. Either local (no extra config) or cloud (URL + key
/// reference).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    /// Which backend this profile selects.
    pub backend: ProfileBackend,

    /// Cloud-only: the API endpoint URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// Cloud-only: how to find the API key.
    ///
    /// Forms:
    /// - `keyring:<service>:<name>` — fetched from the OS keychain (requires `keyring` feature).
    /// - `env:<VAR_NAME>` — read from the named env var at resolution time.
    /// - `inline:msb_live_…` — plaintext in the config file. Dev / CI only;
    ///   logged as a warning on load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key_ref: Option<String>,
}

/// Which backend a [`Profile`] selects. String-tagged for human-friendly JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProfileBackend {
    /// Local runtime backend on the calling host.
    Local,
    /// Remote cloud control plane.
    Cloud,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Load `SdkConfig` from the config file at `~/.microsandbox/config.json`.
///
/// Missing file → `Ok(SdkConfig::default())`. Malformed JSON → `Err`.
/// Honours `MSB_CONFIG_PATH` env override for the file path.
pub fn load_sdk_config() -> MicrosandboxResult<SdkConfig> {
    let path = sdk_config_path();
    if !path.exists() {
        return Ok(SdkConfig::default());
    }
    let raw = fs::read_to_string(&path).map_err(|e| {
        MicrosandboxError::InvalidConfig(format!(
            "failed to read SDK config at {}: {e}",
            path.display()
        ))
    })?;
    // Parse with serde's permissive shape — `serde(default)` on SdkConfig means
    // a JSON document that only contains LocalConfig fields produces an empty
    // SdkConfig without error.
    let cfg: SdkConfig = serde_json::from_str(&raw).map_err(|e| {
        MicrosandboxError::InvalidConfig(format!(
            "failed to parse SDK config at {}: {e}",
            path.display()
        ))
    })?;
    Ok(cfg)
}

/// Resolve the default backend according to the Q1 precedence ladder.
///
/// Tiers 2–5 of the ladder (env → profile env → config → local fallback). Tier
/// 1 (programmatic) is handled by `set_default_backend` / per-call `.backend(b)`,
/// not here.
pub fn resolve_default_backend() -> MicrosandboxResult<Arc<dyn Backend>> {
    // Tier 2a: explicit backend kind via env.
    if let Ok(kind) = std::env::var("MSB_BACKEND") {
        match kind.trim().to_ascii_lowercase().as_str() {
            "local" => return Ok(Arc::new(LocalBackend::lazy())),
            "cloud" => {
                // Cloud without explicit URL/key — fall through to profile lookup,
                // since the user may have set MSB_PROFILE separately.
            }
            other => {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "MSB_BACKEND must be 'local' or 'cloud', got {other:?}"
                )));
            }
        }
    }

    // Tier 2b: direct env (MSB_API_URL + MSB_API_KEY) — explicit cloud override.
    if let (Ok(url), Ok(key)) = (std::env::var("MSB_API_URL"), std::env::var("MSB_API_KEY")) {
        let url = url.trim();
        let key = key.trim();
        if !url.is_empty() && !key.is_empty() {
            let cloud = CloudBackend::new(url, key)?;
            return Ok(Arc::new(cloud));
        }
    }

    // Tier 3 / 4: profile selection via env or config file.
    let cfg = load_sdk_config()?;
    let profile_name = std::env::var("MSB_PROFILE")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| cfg.active_profile.clone());

    if let Some(name) = profile_name {
        let profile = cfg.profiles.get(&name).ok_or_else(|| {
            MicrosandboxError::InvalidConfig(format!(
                "active profile {name:?} not found in SDK config"
            ))
        })?;
        return backend_from_profile(&name, profile);
    }

    // Tier 5: local fallback.
    Ok(Arc::new(LocalBackend::lazy()))
}

/// Build a backend instance from a named profile.
fn backend_from_profile(name: &str, profile: &Profile) -> MicrosandboxResult<Arc<dyn Backend>> {
    match profile.backend {
        ProfileBackend::Local => Ok(Arc::new(LocalBackend::lazy())),
        ProfileBackend::Cloud => Ok(Arc::new(cloud_backend_from_profile_parts(name, profile)?)),
    }
}

pub(crate) fn cloud_backend_from_profile(name: &str) -> MicrosandboxResult<CloudBackend> {
    let cfg = load_sdk_config()?;
    let profile = cfg.profiles.get(name).ok_or_else(|| {
        MicrosandboxError::InvalidConfig(format!("profile {name:?} not found in SDK config"))
    })?;
    cloud_backend_from_profile_parts(name, profile)
}

fn cloud_backend_from_profile_parts(
    name: &str,
    profile: &Profile,
) -> MicrosandboxResult<CloudBackend> {
    if profile.backend != ProfileBackend::Cloud {
        return Err(MicrosandboxError::InvalidConfig(format!(
            "profile {name:?} is not a cloud profile"
        )));
    }

    let url = profile.url.as_ref().ok_or_else(|| {
        MicrosandboxError::InvalidConfig(format!(
            "profile {name:?} backend=cloud requires a 'url' field"
        ))
    })?;
    let key_ref = profile.api_key_ref.as_ref().ok_or_else(|| {
        MicrosandboxError::InvalidConfig(format!(
            "profile {name:?} backend=cloud requires an 'api_key_ref' field"
        ))
    })?;
    let api_key = resolve_api_key_ref(name, key_ref)?;
    CloudBackend::new(url.as_str(), api_key)
}

/// Resolve an `api_key_ref` string (`keyring:…` / `env:VAR` / `inline:msb_…`)
/// to the actual API key value.
fn resolve_api_key_ref(profile: &str, key_ref: &str) -> MicrosandboxResult<String> {
    if let Some(rest) = key_ref.strip_prefix("env:") {
        let var = rest.trim();
        if var.is_empty() {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "profile {profile:?}: api_key_ref 'env:' must name an env var"
            )));
        }
        let value = std::env::var(var).map_err(|_| {
            MicrosandboxError::InvalidConfig(format!(
                "profile {profile:?}: env var {var:?} not set"
            ))
        })?;
        let value = value.trim();
        if value.is_empty() {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "profile {profile:?}: env var {var:?} must not be empty"
            )));
        }
        return Ok(value.to_string());
    }
    if let Some(rest) = key_ref.strip_prefix("inline:") {
        let api_key = rest.trim();
        if api_key.is_empty() {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "profile {profile:?}: api_key_ref 'inline:' must include an API key"
            )));
        }
        tracing::warn!(
            profile = %profile,
            "API key stored inline in SDK config — dev/CI only; prefer keyring: or env:"
        );
        return Ok(api_key.to_string());
    }
    if let Some(rest) = key_ref.strip_prefix("keyring:") {
        // Format: keyring:<service>:<name>
        let mut parts = rest.splitn(2, ':');
        let _service = parts.next().filter(|s| !s.is_empty()).ok_or_else(|| {
            MicrosandboxError::InvalidConfig(format!(
                "profile {profile:?}: api_key_ref 'keyring:' requires <service>:<name>"
            ))
        })?;
        let _entry = parts.next().filter(|s| !s.is_empty()).ok_or_else(|| {
            MicrosandboxError::InvalidConfig(format!(
                "profile {profile:?}: api_key_ref 'keyring:<service>:<name>' requires <name>"
            ))
        })?;
        // Keyring lookup is gated by the `keyring` feature on the microsandbox
        // crate. When the feature is enabled, integrate with the existing
        // keyring path (see `crate::config::get_registry_keyring_auth` for the
        // analogous registry-auth code).
        return Err(MicrosandboxError::InvalidConfig(format!(
            "profile {profile:?}: api_key_ref 'keyring:' resolution is not yet wired \
             — use 'env:' or 'inline:' for now"
        )));
    }
    Err(MicrosandboxError::InvalidConfig(format!(
        "profile {profile:?}: api_key_ref must start with 'env:', 'inline:', or 'keyring:' — got {key_ref:?}"
    )))
}

/// Return the SDK config file path. Delegates to [`crate::config::config_path`]
/// so the SDK config and the [`LocalConfig`](crate::config::LocalConfig)
/// always agree on the path (they live in the same JSON document). Honours
/// `MSB_CONFIG_PATH` via that.
fn sdk_config_path() -> PathBuf {
    crate::config::config_path()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sdk_config_parses_minimal() {
        let json = r#"{
            "active_profile": "prod",
            "profiles": {
                "prod": { "backend": "cloud", "url": "https://msb.example.com", "api_key_ref": "env:MSB_API_KEY" }
            }
        }"#;
        let cfg: SdkConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.active_profile.as_deref(), Some("prod"));
        assert_eq!(cfg.profiles.len(), 1);
        let prod = cfg.profiles.get("prod").unwrap();
        assert_eq!(prod.backend, ProfileBackend::Cloud);
        assert_eq!(prod.url.as_deref(), Some("https://msb.example.com"));
        assert_eq!(prod.api_key_ref.as_deref(), Some("env:MSB_API_KEY"));
    }

    #[test]
    fn sdk_config_ignores_unknown_keys() {
        // LocalConfig fields (home, log_level, paths, ...) coexist in the same file.
        let json = r#"{
            "home": "/opt/microsandbox",
            "log_level": "info",
            "active_profile": "local-only",
            "profiles": { "local-only": { "backend": "local" } }
        }"#;
        let cfg: SdkConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.active_profile.as_deref(), Some("local-only"));
    }

    #[test]
    fn sdk_config_handles_empty_object() {
        let cfg: SdkConfig = serde_json::from_str("{}").unwrap();
        assert!(cfg.active_profile.is_none());
        assert!(cfg.profiles.is_empty());
    }

    #[test]
    fn api_key_ref_inline() {
        let key = resolve_api_key_ref("p", "inline:msb_live_abc").unwrap();
        assert_eq!(key, "msb_live_abc");
    }

    #[test]
    fn api_key_ref_inline_trims_and_rejects_empty() {
        let key = resolve_api_key_ref("p", "inline:  msb_live_abc  ").unwrap();
        assert_eq!(key, "msb_live_abc");
        assert!(resolve_api_key_ref("p", "inline:   ").is_err());
    }

    #[test]
    fn api_key_ref_env_when_set() {
        unsafe { std::env::set_var("MSB_TEST_RESOLVE_API_KEY", " msb_test_xyz ") };
        let key = resolve_api_key_ref("p", "env:MSB_TEST_RESOLVE_API_KEY").unwrap();
        assert_eq!(key, "msb_test_xyz");
        unsafe { std::env::remove_var("MSB_TEST_RESOLVE_API_KEY") };
    }

    #[test]
    fn api_key_ref_env_rejects_empty_value() {
        unsafe { std::env::set_var("MSB_TEST_EMPTY_API_KEY", "   ") };
        assert!(resolve_api_key_ref("p", "env:MSB_TEST_EMPTY_API_KEY").is_err());
        unsafe { std::env::remove_var("MSB_TEST_EMPTY_API_KEY") };
    }

    #[test]
    fn api_key_ref_env_missing() {
        unsafe { std::env::remove_var("MSB_TEST_DEFINITELY_NOT_SET") };
        assert!(resolve_api_key_ref("p", "env:MSB_TEST_DEFINITELY_NOT_SET").is_err());
    }

    #[test]
    fn api_key_ref_rejects_unknown_scheme() {
        assert!(resolve_api_key_ref("p", "vault:foo").is_err());
        assert!(resolve_api_key_ref("p", "plaintext").is_err());
    }

    #[test]
    fn api_key_ref_keyring_returns_explicit_error_for_now() {
        // Keyring path is parsed (validates the format) but signals "not yet wired".
        let err = resolve_api_key_ref("p", "keyring:msb:prod").unwrap_err();
        assert!(err.to_string().contains("not yet wired"));
    }

    #[test]
    fn backend_from_local_profile() {
        let p = Profile {
            backend: ProfileBackend::Local,
            url: None,
            api_key_ref: None,
        };
        let b = backend_from_profile("local", &p).unwrap();
        assert_eq!(b.kind(), super::super::BackendKind::Local);
    }

    #[test]
    fn backend_from_cloud_profile_inline_key() {
        let p = Profile {
            backend: ProfileBackend::Cloud,
            url: Some("https://msb.example.com".into()),
            api_key_ref: Some("inline:msb_live_abc".into()),
        };
        let b = backend_from_profile("prod", &p).unwrap();
        assert_eq!(b.kind(), super::super::BackendKind::Cloud);
    }

    #[test]
    fn cloud_backend_from_profile_parts_rejects_local_profile() {
        let p = Profile {
            backend: ProfileBackend::Local,
            url: None,
            api_key_ref: None,
        };
        assert!(cloud_backend_from_profile_parts("local", &p).is_err());
    }

    #[test]
    fn resolve_default_backend_honors_explicit_local_over_cloud_env() {
        unsafe {
            std::env::set_var("MSB_BACKEND", " local ");
            std::env::set_var("MSB_API_URL", "https://msb.example.com");
            std::env::set_var("MSB_API_KEY", "msb_live_abc");
        }

        let b = resolve_default_backend().unwrap();

        unsafe {
            std::env::remove_var("MSB_BACKEND");
            std::env::remove_var("MSB_API_URL");
            std::env::remove_var("MSB_API_KEY");
        }

        assert_eq!(b.kind(), super::super::BackendKind::Local);
    }

    #[test]
    fn backend_from_cloud_profile_missing_url() {
        let p = Profile {
            backend: ProfileBackend::Cloud,
            url: None,
            api_key_ref: Some("inline:msb_live_abc".into()),
        };
        assert!(backend_from_profile("prod", &p).is_err());
    }

    #[test]
    fn backend_from_cloud_profile_missing_key_ref() {
        let p = Profile {
            backend: ProfileBackend::Cloud,
            url: Some("https://msb.example.com".into()),
            api_key_ref: None,
        };
        assert!(backend_from_profile("prod", &p).is_err());
    }
}

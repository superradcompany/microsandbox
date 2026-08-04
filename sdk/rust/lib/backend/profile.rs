//! Backend selection: profile + env + config-file resolution.
//!
//! Precedence ladder (each tier wins over the one below):
//!
//! 1. Programmatic: explicit `.backend(b)` on a builder or
//!    `microsandbox::set_default_backend(...)` — handled by the caller, not here.
//! 2. Env: `MSB_BACKEND=local|cloud` explicitly selects a backend.
//!    `MSB_API_KEY` supplies cloud credentials and `MSB_API_URL` optionally
//!    overrides the hosted API endpoint; neither selects cloud by itself.
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

use super::{Backend, BackendSelectionSource, CloudBackend, LocalBackend};
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

/// A single named profile. Either local (no extra config) or cloud (key
/// reference plus an optional URL override).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    /// Which backend this profile selects.
    pub backend: ProfileBackend,

    /// Cloud-only: API endpoint override. Hosted cloud uses the SDK default.
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

/// Internal result of applying the ambient backend-selection precedence.
///
/// Keeping selection separate from backend construction makes the safety
/// invariant testable: credentials configure Cloud, but never select it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BackendSelection {
    Local,
    DirectCloud,
    Profile { name: String, require_cloud: bool },
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
    // The config is needed for profile selection. An explicit local backend
    // is resolved first so an unrelated malformed config cannot prevent a
    // caller from deliberately choosing Local.
    let backend_kind = std::env::var("MSB_BACKEND").ok();
    let parsed_backend_kind = parse_backend_kind(backend_kind.as_deref())?;
    if parsed_backend_kind == Some(ProfileBackend::Local) {
        return Ok(Arc::new(LocalBackend::lazy_with_selection(
            BackendSelectionSource::MsbBackend,
            None,
        )));
    }

    let api_key = std::env::var("MSB_API_KEY").ok();
    if parsed_backend_kind == Some(ProfileBackend::Cloud)
        && api_key.as_deref().is_some_and(|key| !key.trim().is_empty())
    {
        let cloud =
            direct_cloud_backend(std::env::var("MSB_API_URL").ok(), api_key)?.ok_or_else(|| {
                MicrosandboxError::InvalidConfig(
                    "MSB_BACKEND=cloud requires a non-empty MSB_API_KEY".into(),
                )
            })?;
        return Ok(Arc::new(
            cloud.with_selection(BackendSelectionSource::MsbBackend, None),
        ));
    }

    let cfg = load_sdk_config()?;
    let env_profile = std::env::var("MSB_PROFILE").ok();
    let selection = select_backend(
        backend_kind.as_deref(),
        api_key.as_deref(),
        env_profile.as_deref(),
        cfg.active_profile.as_deref(),
    )?;

    match selection {
        BackendSelection::Local => Ok(Arc::new(LocalBackend::lazy_with_selection(
            BackendSelectionSource::Default,
            None,
        ))),
        BackendSelection::DirectCloud => {
            let cloud = direct_cloud_backend(std::env::var("MSB_API_URL").ok(), api_key)?
                .ok_or_else(|| {
                    MicrosandboxError::InvalidConfig(
                        "MSB_BACKEND=cloud requires a non-empty MSB_API_KEY".into(),
                    )
                })?;
            Ok(Arc::new(
                cloud.with_selection(BackendSelectionSource::MsbBackend, None),
            ))
        }
        BackendSelection::Profile {
            name,
            require_cloud,
        } => {
            let profile = cfg.profiles.get(&name).ok_or_else(|| {
                MicrosandboxError::InvalidConfig(format!(
                    "active profile {name:?} not found in SDK config"
                ))
            })?;
            if require_cloud && profile.backend != ProfileBackend::Cloud {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "MSB_BACKEND=cloud cannot select local profile {name:?}"
                )));
            }
            let source = if require_cloud {
                BackendSelectionSource::MsbBackend
            } else if env_profile
                .as_deref()
                .map(str::trim)
                .is_some_and(|name| !name.is_empty())
            {
                BackendSelectionSource::MsbProfile
            } else {
                BackendSelectionSource::ActiveProfile
            };
            backend_from_profile(&name, profile, source)
        }
    }
}

/// Parse an explicit backend kind without treating credentials as routing.
fn parse_backend_kind(value: Option<&str>) -> MicrosandboxResult<Option<ProfileBackend>> {
    let Some(value) = value else {
        return Ok(None);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "local" => Ok(Some(ProfileBackend::Local)),
        "cloud" => Ok(Some(ProfileBackend::Cloud)),
        other => Err(MicrosandboxError::InvalidConfig(format!(
            "MSB_BACKEND must be 'local' or 'cloud', got {other:?}"
        ))),
    }
}

/// Apply the ambient selection ladder to already-loaded values.
fn select_backend(
    backend_kind: Option<&str>,
    api_key: Option<&str>,
    env_profile: Option<&str>,
    active_profile: Option<&str>,
) -> MicrosandboxResult<BackendSelection> {
    let backend_kind = parse_backend_kind(backend_kind)?;
    if backend_kind == Some(ProfileBackend::Local) {
        return Ok(BackendSelection::Local);
    }

    let has_api_key = api_key.is_some_and(|key| !key.trim().is_empty());
    if backend_kind == Some(ProfileBackend::Cloud) && has_api_key {
        return Ok(BackendSelection::DirectCloud);
    }

    let profile_name = env_profile
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .or_else(|| {
            active_profile
                .map(str::trim)
                .filter(|name| !name.is_empty())
        });
    if let Some(name) = profile_name {
        return Ok(BackendSelection::Profile {
            name: name.to_string(),
            require_cloud: backend_kind == Some(ProfileBackend::Cloud),
        });
    }

    if backend_kind == Some(ProfileBackend::Cloud) {
        return Err(MicrosandboxError::InvalidConfig(
            "MSB_BACKEND=cloud requires a non-empty MSB_API_KEY or a cloud profile".into(),
        ));
    }

    // A bare API key is credential material, not backend intent.
    Ok(BackendSelection::Local)
}

/// Build a backend instance from a named profile.
fn backend_from_profile(
    name: &str,
    profile: &Profile,
    source: BackendSelectionSource,
) -> MicrosandboxResult<Arc<dyn Backend>> {
    match profile.backend {
        ProfileBackend::Local => Ok(Arc::new(LocalBackend::lazy_with_selection(
            source,
            Some(name.to_string()),
        ))),
        ProfileBackend::Cloud => Ok(Arc::new(
            cloud_backend_from_profile_parts(name, profile)?
                .with_selection(source, Some(name.to_string())),
        )),
    }
}

pub(crate) fn cloud_backend_from_profile(name: &str) -> MicrosandboxResult<CloudBackend> {
    let cfg = load_sdk_config()?;
    let profile = cfg.profiles.get(name).ok_or_else(|| {
        MicrosandboxError::InvalidConfig(format!("profile {name:?} not found in SDK config"))
    })?;
    Ok(cloud_backend_from_profile_parts(name, profile)?
        .with_selection(BackendSelectionSource::Profile, Some(name.to_string())))
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

    let key_ref = profile.api_key_ref.as_ref().ok_or_else(|| {
        MicrosandboxError::InvalidConfig(format!(
            "profile {name:?} backend=cloud requires an 'api_key_ref' field"
        ))
    })?;
    let api_key = resolve_api_key_ref(name, key_ref)?;
    match profile.url.as_deref() {
        Some(url) => CloudBackend::new(url, api_key),
        None => CloudBackend::with_api_key(api_key),
    }
}

/// Resolve direct environment values without reading ambient state. Keeping
/// this construction pure keeps credential parsing independent from backend
/// selection. Callers must explicitly select Cloud before invoking it.
fn direct_cloud_backend(
    api_url: Option<String>,
    api_key: Option<String>,
) -> MicrosandboxResult<Option<CloudBackend>> {
    let Some(api_key) = api_key
        .as_deref()
        .map(str::trim)
        .filter(|api_key| !api_key.is_empty())
    else {
        return Ok(None);
    };

    let api_url = api_url
        .as_deref()
        .map(str::trim)
        .filter(|api_url| !api_url.is_empty());
    let cloud = match api_url {
        Some(api_url) => CloudBackend::new(api_url, api_key)?,
        None => CloudBackend::with_api_key(api_key)?,
    };
    Ok(Some(cloud))
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
        let _env_guard = crate::test_support::lock_env();
        // SAFETY: every environment-mutating SDK unit test holds the shared lock.
        unsafe { std::env::set_var("MSB_TEST_RESOLVE_API_KEY", " msb_test_xyz ") };
        let key = resolve_api_key_ref("p", "env:MSB_TEST_RESOLVE_API_KEY").unwrap();
        assert_eq!(key, "msb_test_xyz");
        unsafe { std::env::remove_var("MSB_TEST_RESOLVE_API_KEY") };
    }

    #[test]
    fn api_key_ref_env_rejects_empty_value() {
        let _env_guard = crate::test_support::lock_env();
        // SAFETY: every environment-mutating SDK unit test holds the shared lock.
        unsafe { std::env::set_var("MSB_TEST_EMPTY_API_KEY", "   ") };
        assert!(resolve_api_key_ref("p", "env:MSB_TEST_EMPTY_API_KEY").is_err());
        unsafe { std::env::remove_var("MSB_TEST_EMPTY_API_KEY") };
    }

    #[test]
    fn api_key_ref_env_missing() {
        let _env_guard = crate::test_support::lock_env();
        // SAFETY: every environment-mutating SDK unit test holds the shared lock.
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
        let b = backend_from_profile("local", &p, BackendSelectionSource::MsbProfile).unwrap();
        assert_eq!(b.kind(), super::super::BackendKind::Local);
        assert_eq!(b.info().source, BackendSelectionSource::MsbProfile);
        assert_eq!(b.info().profile.as_deref(), Some("local"));
    }

    #[test]
    fn backend_from_cloud_profile_inline_key() {
        let p = Profile {
            backend: ProfileBackend::Cloud,
            url: Some("https://msb.example.com".into()),
            api_key_ref: Some("inline:msb_live_abc".into()),
        };
        let b = backend_from_profile("prod", &p, BackendSelectionSource::ActiveProfile).unwrap();
        assert_eq!(b.kind(), super::super::BackendKind::Cloud);
        assert_eq!(b.info().source, BackendSelectionSource::ActiveProfile);
        assert_eq!(b.info().profile.as_deref(), Some("prod"));
    }

    #[test]
    fn direct_cloud_env_uses_default_url_with_api_key_only() {
        let cloud = direct_cloud_backend(None, Some(" msb_live_abc ".into()))
            .unwrap()
            .unwrap();
        assert_eq!(cloud.url(), super::super::DEFAULT_CLOUD_API_URL);
    }

    #[test]
    fn direct_cloud_env_does_not_dispatch_from_url_alone() {
        assert!(
            direct_cloud_backend(Some("https://msb.example.com".into()), None)
                .unwrap()
                .is_none()
        );
        assert!(
            direct_cloud_backend(Some("https://msb.example.com".into()), Some("   ".into()))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn credentials_alone_do_not_select_cloud() {
        assert_eq!(
            select_backend(None, Some("msb_live_abc"), None, None).unwrap(),
            BackendSelection::Local
        );
        assert_eq!(
            select_backend(None, Some("msb_live_abc"), None, Some("local-profile")).unwrap(),
            BackendSelection::Profile {
                name: "local-profile".into(),
                require_cloud: false,
            }
        );
    }

    #[test]
    fn explicit_cloud_uses_direct_credentials() {
        assert_eq!(
            select_backend(Some("cloud"), Some("msb_live_abc"), None, None).unwrap(),
            BackendSelection::DirectCloud
        );
    }

    #[test]
    fn explicit_cloud_without_credentials_or_profile_fails() {
        let err = select_backend(Some("cloud"), None, None, None).unwrap_err();
        assert!(err.to_string().contains("requires a non-empty MSB_API_KEY"));
    }

    #[test]
    fn explicit_local_wins_over_credentials_and_profiles() {
        assert_eq!(
            select_backend(
                Some("local"),
                Some("msb_live_abc"),
                Some("cloud-profile"),
                Some("other-profile"),
            )
            .unwrap(),
            BackendSelection::Local
        );
    }

    #[test]
    fn profile_selection_is_explicit_backend_intent() {
        assert_eq!(
            select_backend(None, None, Some("staging"), Some("prod")).unwrap(),
            BackendSelection::Profile {
                name: "staging".into(),
                require_cloud: false,
            }
        );
        assert_eq!(
            select_backend(None, None, None, Some("prod")).unwrap(),
            BackendSelection::Profile {
                name: "prod".into(),
                require_cloud: false,
            }
        );
    }

    #[test]
    fn explicit_cloud_requires_selected_profile_to_be_cloud() {
        assert_eq!(
            select_backend(Some("cloud"), None, Some("prod"), None).unwrap(),
            BackendSelection::Profile {
                name: "prod".into(),
                require_cloud: true,
            }
        );
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
        let _env_guard = crate::test_support::lock_env();
        // SAFETY: every environment-mutating SDK unit test holds the shared lock.
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
        assert_eq!(b.info().source, BackendSelectionSource::MsbBackend);
    }

    #[test]
    fn explicit_cloud_without_credentials_fails_closed() {
        let _env_guard = crate::test_support::lock_env();
        // SAFETY: every environment-mutating SDK unit test holds the shared lock.
        unsafe {
            std::env::set_var("MSB_BACKEND", "cloud");
            std::env::remove_var("MSB_API_KEY");
            std::env::remove_var("MSB_PROFILE");
            std::env::set_var("MSB_CONFIG_PATH", "/definitely/missing/msb-config.json");
        }

        let error = match resolve_default_backend() {
            Ok(_) => panic!("explicit cloud selection must not fall back to local"),
            Err(error) => error,
        };

        unsafe {
            std::env::remove_var("MSB_BACKEND");
            std::env::remove_var("MSB_CONFIG_PATH");
        }

        assert!(error.to_string().contains("MSB_BACKEND=cloud requires"));
    }

    #[test]
    fn backend_from_cloud_profile_missing_url_uses_default() {
        let p = Profile {
            backend: ProfileBackend::Cloud,
            url: None,
            api_key_ref: Some("inline:msb_live_abc".into()),
        };
        let cloud = cloud_backend_from_profile_parts("prod", &p).unwrap();
        assert_eq!(cloud.url(), super::super::DEFAULT_CLOUD_API_URL);
    }

    #[test]
    fn backend_from_cloud_profile_missing_key_ref() {
        let p = Profile {
            backend: ProfileBackend::Cloud,
            url: Some("https://msb.example.com".into()),
            api_key_ref: None,
        };
        assert!(backend_from_profile("prod", &p, BackendSelectionSource::ActiveProfile).is_err());
    }
}

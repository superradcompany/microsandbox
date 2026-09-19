//! Backend selection: profile + env + config-file resolution.
//!
//! Managed `active_profile` overrides the ambient selection below; managed profile entries
//! replace matching user entries during resolution. Explicit backend objects retain their identity.
//!
//! Ordinary precedence ladder (each tier wins over the one below):
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
//! Profile fields are part of [`GlobalConfig`](crate::config::GlobalConfig), loaded from the
//! same document as local execution settings.

use std::{path::Path, sync::Arc};

use serde::{Deserialize, Serialize};

use super::Backend;
#[cfg(feature = "cloud")]
use super::BackendSelectionSource;
#[cfg(feature = "local")]
use super::LocalBackend;
#[cfg(feature = "cloud")]
use super::{CloudBackend, CloudBackendBuilder};
#[cfg(feature = "cloud")]
use crate::{MicrosandboxError, config::layers::BackendConfig};
use crate::{MicrosandboxResult, config::backend::BackendSelection};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

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

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Profile {
    /// Resolve this profile's connection settings before backend construction.
    #[cfg(feature = "cloud")]
    pub(crate) fn cloud_builder(&self, name: &str) -> MicrosandboxResult<CloudBackendBuilder> {
        if self.backend != ProfileBackend::Cloud {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "profile {name:?} is not a cloud profile"
            )));
        }

        let key_ref = self.api_key_ref.as_ref().ok_or_else(|| {
            MicrosandboxError::InvalidConfig(format!(
                "profile {name:?} backend=cloud requires an 'api_key_ref' field"
            ))
        })?;

        let api_key = resolve_api_key_ref(name, key_ref)?;
        let mut builder = CloudBackend::builder().api_key(api_key);
        if let Some(url) = &self.url {
            builder = builder.url(url);
        }
        Ok(builder)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Resolve the default backend according to the Q1 precedence ladder.
///
/// Tiers 2–5 of the ladder (env → profile env → config → local fallback). Tier
/// 1 (programmatic) is handled by `set_default_backend` / per-call `.backend(b)`,
/// not here.
pub fn resolve_default_backend() -> MicrosandboxResult<Arc<dyn Backend>> {
    resolve_default_backend_from(&crate::config::config_path(), None)
}

fn resolve_default_backend_from(
    user_path: &Path,
    managed_path: Option<&Path>,
) -> MicrosandboxResult<Arc<dyn Backend>> {
    let (selection, source, config) = BackendSelection::resolve(user_path, managed_path)?;
    #[cfg(not(feature = "local"))]
    let _ = (&source, &config);
    match selection {
        #[cfg(not(feature = "local"))]
        BackendSelection::Local { .. } => Err(crate::config::backend::feature_disabled("local")),
        #[cfg(feature = "local")]
        BackendSelection::Local { profile } => Ok(Arc::new(LocalBackend::from_backend_config(
            config.prepare_for_local_backend(Default::default())?,
            source,
            profile,
        ))),

        #[cfg(feature = "cloud")]
        BackendSelection::Cloud { profile: None } => Ok(Arc::new(
            CloudBackendBuilder::from_env()?
                .config_sources(config)
                .build()?
                .with_selection_metadata(source, None),
        )),

        #[cfg(feature = "cloud")]
        BackendSelection::Cloud {
            profile: Some((name, builder)),
        } => Ok(Arc::new(
            builder
                .config_sources(config)
                .build()?
                .with_selection_metadata(source, Some(name)),
        )),
    }
}

#[cfg(feature = "cloud")]
pub(crate) fn cloud_backend_from_profile(name: &str) -> MicrosandboxResult<CloudBackend> {
    let config = BackendConfig::load()?;
    let resolved = config.global_layers().build();
    let profile = resolved
        .get_profiles()
        .and_then(|profiles| profiles.get(name))
        .ok_or_else(|| {
            MicrosandboxError::InvalidConfig(format!("profile {name:?} not found in global config"))
        })?;
    Ok(profile
        .cloud_builder(name)?
        .config_sources(config)
        .build()?
        .with_selection_metadata(BackendSelectionSource::Profile, Some(name.to_string())))
}

/// Resolve an `api_key_ref` string (`keyring:…` / `env:VAR` / `inline:msb_…`)
/// to the actual API key value.
#[cfg(feature = "cloud")]
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

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{GlobalConfig, GlobalConfigPatch};

    #[test]
    fn global_config_parses_profiles() {
        let json = r#"{
            "active_profile": "prod",
            "profiles": {
                "prod": { "backend": "cloud", "url": "https://msb.example.com", "api_key_ref": "env:MSB_API_KEY" }
            }
        }"#;
        let cfg: GlobalConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.active_profile.as_deref(), Some("prod"));
        assert_eq!(cfg.profiles.len(), 1);
        let prod = cfg.profiles.get("prod").unwrap();
        assert_eq!(prod.backend, ProfileBackend::Cloud);
        assert_eq!(prod.url.as_deref(), Some("https://msb.example.com"));
        assert_eq!(prod.api_key_ref.as_deref(), Some("env:MSB_API_KEY"));
    }

    #[test]
    fn global_config_contains_profiles_and_local_settings() {
        let json = r#"{
            "home": "/opt/microsandbox",
            "log_level": "info",
            "active_profile": "local-only",
            "profiles": { "local-only": { "backend": "local" } }
        }"#;
        let cfg: GlobalConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.active_profile.as_deref(), Some("local-only"));
        assert_eq!(
            cfg.home.as_deref(),
            Some(std::path::Path::new("/opt/microsandbox"))
        );
    }

    #[test]
    fn global_config_defaults_to_no_profiles() {
        let cfg: GlobalConfig = serde_json::from_str("{}").unwrap();
        assert!(cfg.active_profile.is_none());
        assert!(cfg.profiles.is_empty());
    }

    #[test]
    #[cfg(feature = "cloud")]
    fn api_key_ref_inline() {
        let key = resolve_api_key_ref("p", "inline:msb_live_abc").unwrap();
        assert_eq!(key, "msb_live_abc");
    }

    #[test]
    fn config_loader_reads_user_values_and_reports_invalid_versions() {
        let _env_guard = crate::test_support::lock_env();
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.json");
        let raw = r#"{"version":1,"active_profile":"saved","profiles":{"saved":{"backend":"local"}},"sandbox_defaults":{"cpus":2}}"#;
        std::fs::write(&path, raw).unwrap();
        let previous = std::env::var_os("MSB_CONFIG_PATH");
        // SAFETY: environment-mutating SDK tests hold the shared lock.
        unsafe { std::env::set_var("MSB_CONFIG_PATH", &path) };
        let loaded = GlobalConfigPatch::load();
        let saved = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, r#"{"version":2}"#).unwrap();
        let future = GlobalConfigPatch::load();
        std::fs::write(&path, r#"{"version":1,"profiles":false}"#).unwrap();
        let malformed = GlobalConfigPatch::load();
        unsafe {
            match previous {
                Some(value) => std::env::set_var("MSB_CONFIG_PATH", value),
                None => std::env::remove_var("MSB_CONFIG_PATH"),
            }
        }
        let cfg = loaded.unwrap();
        assert_eq!(
            cfg.active_profile.as_ref().and_then(Option::as_deref),
            Some("saved")
        );
        assert_eq!(cfg.get_profiles().unwrap().len(), 1);
        assert_eq!(saved, raw);
        assert!(future.unwrap_err().to_string().contains("version 1"));
        assert!(
            malformed
                .unwrap_err()
                .to_string()
                .contains(&path.display().to_string())
        );
    }

    #[cfg(feature = "cloud")]
    #[test]
    fn api_key_ref_inline_trims_and_rejects_empty() {
        let key = resolve_api_key_ref("p", "inline:  msb_live_abc  ").unwrap();
        assert_eq!(key, "msb_live_abc");
        assert!(resolve_api_key_ref("p", "inline:   ").is_err());
    }

    #[test]
    #[cfg(feature = "cloud")]
    fn api_key_ref_env_when_set() {
        let _env_guard = crate::test_support::lock_env();
        // SAFETY: every environment-mutating SDK unit test holds the shared lock.
        unsafe { std::env::set_var("MSB_TEST_RESOLVE_API_KEY", " msb_test_xyz ") };
        let key = resolve_api_key_ref("p", "env:MSB_TEST_RESOLVE_API_KEY").unwrap();
        assert_eq!(key, "msb_test_xyz");
        unsafe { std::env::remove_var("MSB_TEST_RESOLVE_API_KEY") };
    }

    #[test]
    #[cfg(feature = "cloud")]
    fn api_key_ref_env_rejects_empty_value() {
        let _env_guard = crate::test_support::lock_env();
        // SAFETY: every environment-mutating SDK unit test holds the shared lock.
        unsafe { std::env::set_var("MSB_TEST_EMPTY_API_KEY", "   ") };
        assert!(resolve_api_key_ref("p", "env:MSB_TEST_EMPTY_API_KEY").is_err());
        unsafe { std::env::remove_var("MSB_TEST_EMPTY_API_KEY") };
    }

    #[test]
    #[cfg(feature = "cloud")]
    fn api_key_ref_env_missing() {
        let _env_guard = crate::test_support::lock_env();
        // SAFETY: every environment-mutating SDK unit test holds the shared lock.
        unsafe { std::env::remove_var("MSB_TEST_DEFINITELY_NOT_SET") };
        assert!(resolve_api_key_ref("p", "env:MSB_TEST_DEFINITELY_NOT_SET").is_err());
    }

    #[test]
    #[cfg(feature = "cloud")]
    fn api_key_ref_rejects_unknown_scheme() {
        assert!(resolve_api_key_ref("p", "vault:foo").is_err());
        assert!(resolve_api_key_ref("p", "plaintext").is_err());
    }

    #[test]
    #[cfg(feature = "cloud")]
    fn api_key_ref_keyring_returns_explicit_error_for_now() {
        // Keyring path is parsed (validates the format) but signals "not yet wired".
        let err = resolve_api_key_ref("p", "keyring:msb:prod").unwrap_err();
        assert!(err.to_string().contains("not yet wired"));
    }

    #[cfg(feature = "cloud")]
    #[cfg(feature = "local")]
    #[test]
    fn managed_file_controls_selection_and_invalid_policy_blocks_cloud() {
        let _env_guard = crate::test_support::lock_env();
        let dir = tempfile::tempdir().unwrap();
        let user = dir.path().join("config.json");
        let managed = dir.path().join("managed.json");
        let previous = [
            "MSB_BACKEND",
            "MSB_API_KEY",
            "MSB_PROFILE",
            "MSB_CONFIG_PATH",
        ]
        .map(|name| (name, std::env::var_os(name)));
        let _restore = scopeguard::guard(previous, |previous| {
            for (name, value) in previous {
                // SAFETY: the shared environment lock is still held.
                unsafe {
                    match value {
                        Some(value) => std::env::set_var(name, value),
                        None => std::env::remove_var(name),
                    }
                }
            }
        });
        // SAFETY: environment-dependent tests hold the shared lock.
        unsafe {
            std::env::set_var("MSB_CONFIG_PATH", &user);
            std::env::set_var("MSB_BACKEND", "cloud");
            std::env::set_var("MSB_API_KEY", "msb_test_managed");
            std::env::remove_var("MSB_PROFILE");
        }
        std::fs::write(
            &managed,
            r#"{"overrides":{
            "active_profile":"company",
            "profiles":{"company":{"backend":"local"}},
            "sandbox_defaults":{"cpus":2}
        }}"#,
        )
        .unwrap();
        let backend = resolve_default_backend_from(&user, Some(&managed)).unwrap();
        assert_eq!(backend.info().profile.as_deref(), Some("company"));
        assert_eq!(
            backend.as_local().unwrap().config().sandbox_defaults.cpus,
            2
        );

        std::fs::write(&managed, "invalid").unwrap();
        let error = resolve_default_backend_from(&user, Some(&managed))
            .err()
            .unwrap();
        assert!(error.to_string().contains(&managed.display().to_string()));

        // Cloud retains user settings too, so malformed input must fail construction.
        std::fs::write(&managed, "{}").unwrap();
        std::fs::write(&user, "invalid").unwrap();
        let error = resolve_default_backend_from(&user, Some(&managed))
            .err()
            .unwrap();
        assert!(error.to_string().contains(&user.display().to_string()));
        for result in [
            CloudBackend::new("https://cloud.example", "test-key"),
            CloudBackend::with_api_key("test-key"),
            CloudBackend::from_env(),
        ] {
            assert!(
                result
                    .err()
                    .unwrap()
                    .to_string()
                    .contains(&user.display().to_string())
            );
        }
        std::fs::write(&user, r#"{"sandbox_defaults":{"cpus":6}}"#).unwrap();
        std::fs::write(&managed, r#"{"overrides":{"sandbox_defaults":{"cpus":2}}}"#).unwrap();
        let backend = resolve_default_backend_from(&user, Some(&managed)).unwrap();
        let sources = BackendConfig::for_backend(backend.as_ref()).unwrap();
        assert_eq!(sources.resolved_config().sandbox_defaults.cpus, 2);
    }

    #[cfg(all(feature = "local", feature = "cloud"))]
    #[test]
    fn resolved_profiles_preserve_metadata_and_validate_only_local_defaults() {
        let _env_guard = crate::test_support::lock_env();
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.json");
        let mut config = serde_json::json!({
            "active_profile": "prod",
            "profiles": {
                "local": {"backend": "local"},
                "prod": {
                    "backend": "cloud",
                    "url": "https://msb.example.com",
                    "api_key_ref": "inline:msb_test_abc"
                }
            }
        });
        std::fs::write(&path, config.to_string()).unwrap();
        let previous = ["MSB_BACKEND", "MSB_API_KEY", "MSB_PROFILE"]
            .map(|name| (name, std::env::var_os(name)));
        // SAFETY: every environment-mutating SDK unit test holds the shared lock.
        unsafe {
            std::env::remove_var("MSB_BACKEND");
            std::env::remove_var("MSB_API_KEY");
        }
        let backends = [Some("local"), Some("prod"), None].map(|profile| {
            unsafe {
                match profile {
                    Some(name) => std::env::set_var("MSB_PROFILE", name),
                    None => std::env::remove_var("MSB_PROFILE"),
                }
            }
            (
                profile,
                resolve_default_backend_from(&path, Some(&temp.path().join("managed.json"))),
            )
        });
        config["sandbox_defaults"] = serde_json::json!({"placement_profile": "missing"});
        std::fs::write(&path, config.to_string()).unwrap();
        let cloud_with_invalid_local_defaults =
            resolve_default_backend_from(&path, Some(&temp.path().join("managed.json")));
        unsafe { std::env::set_var("MSB_PROFILE", "local") };
        let local_with_invalid_defaults =
            resolve_default_backend_from(&path, Some(&temp.path().join("managed.json")));
        for (name, value) in previous {
            unsafe {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
        for (profile, backend) in backends {
            let backend = backend.unwrap();
            let info = backend.info();
            assert_eq!(info.profile.as_deref(), Some(profile.unwrap_or("prod")));
            assert_eq!(
                info.source,
                if profile.is_some() {
                    BackendSelectionSource::MsbProfile
                } else {
                    BackendSelectionSource::ActiveProfile
                }
            );
            if profile == Some("local") {
                assert_eq!(info.kind, super::super::BackendKind::Local);
            } else {
                assert_eq!(info.kind, super::super::BackendKind::Cloud);
                assert_eq!(info.api_url.as_deref(), Some("https://msb.example.com"));
            }
        }
        assert_eq!(
            cloud_with_invalid_local_defaults.unwrap().kind(),
            super::super::BackendKind::Cloud
        );
        assert!(
            local_with_invalid_defaults
                .err()
                .unwrap()
                .to_string()
                .contains("placement profile `missing`")
        );
    }

    #[cfg(feature = "cloud")]
    #[test]
    fn cloud_profile_builder_rejects_local_profile() {
        let p = Profile {
            backend: ProfileBackend::Local,
            url: None,
            api_key_ref: None,
        };
        assert!(p.cloud_builder("local").is_err());
    }

    #[cfg(all(feature = "local", feature = "cloud"))]
    #[test]
    fn resolve_default_backend_honors_explicit_backend_over_cloud_env() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.json");
        let _env_guard = crate::test_support::lock_env();
        // SAFETY: every environment-mutating SDK unit test holds the shared lock.
        unsafe {
            std::env::set_var("MSB_BACKEND", " local ");
            std::env::set_var("MSB_API_URL", "https://msb.example.com");
            std::env::set_var("MSB_API_KEY", "msb_live_abc");
        }

        let local = resolve_default_backend_from(&path, Some(&temp.path().join("managed.json")));
        unsafe { std::env::set_var("MSB_BACKEND", "cloud") };
        let cloud = resolve_default_backend_from(&path, Some(&temp.path().join("managed.json")));

        unsafe {
            std::env::remove_var("MSB_BACKEND");
            std::env::remove_var("MSB_API_URL");
            std::env::remove_var("MSB_API_KEY");
        }

        let local = local.unwrap();
        assert_eq!(local.kind(), super::super::BackendKind::Local);
        assert_eq!(local.info().source, BackendSelectionSource::MsbBackend);
        let cloud = cloud.unwrap();
        assert_eq!(cloud.kind(), super::super::BackendKind::Cloud);
        assert_eq!(cloud.info().source, BackendSelectionSource::MsbBackend);
        assert_eq!(cloud.info().profile, None);
    }

    #[cfg(feature = "cloud")]
    #[test]
    fn explicit_cloud_without_credentials_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.json");
        let _env_guard = crate::test_support::lock_env();
        // SAFETY: every environment-mutating SDK unit test holds the shared lock.
        unsafe {
            std::env::set_var("MSB_BACKEND", "cloud");
            std::env::remove_var("MSB_API_KEY");
            std::env::remove_var("MSB_PROFILE");
        }

        let error =
            match resolve_default_backend_from(&path, Some(&temp.path().join("managed.json"))) {
                Ok(_) => panic!("explicit cloud selection must not fall back to local"),
                Err(error) => error,
            };

        unsafe {
            std::env::remove_var("MSB_BACKEND");
        }

        assert!(error.to_string().contains("MSB_BACKEND=cloud requires"));
    }

    #[test]
    #[cfg(feature = "cloud")]
    fn backend_from_cloud_profile_missing_url_uses_default() {
        let p = Profile {
            backend: ProfileBackend::Cloud,
            url: None,
            api_key_ref: Some("inline:msb_live_abc".into()),
        };
        let cloud = p
            .cloud_builder("prod")
            .unwrap()
            .config_sources(BackendConfig::new(Default::default(), Default::default()))
            .build()
            .unwrap();
        assert_eq!(cloud.url(), super::super::DEFAULT_CLOUD_API_URL);
    }

    #[test]
    #[cfg(feature = "cloud")]
    fn backend_from_cloud_profile_missing_key_ref() {
        let p = Profile {
            backend: ProfileBackend::Cloud,
            url: Some("https://msb.example.com".into()),
            api_key_ref: None,
        };
        assert!(p.cloud_builder("prod").is_err());
    }
}

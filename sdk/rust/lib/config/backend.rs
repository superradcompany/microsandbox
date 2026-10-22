//! Select backends and manage saved profile preferences.

use std::{collections::HashMap, path::Path};

use microsandbox_types::ConfigPatch;
use serde::Serialize;

use super::{GlobalConfigPatch, layers::BackendConfig, persistence::ManagedConfig};
use crate::backend::{BackendInfo, BackendKind, BackendSelectionSource, Profile, ProfileBackend};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Backend identity after applying selection precedence, without resolving credentials.
///
/// Keeping selection separate from backend construction makes the safety
/// invariant testable: credentials configure Cloud, but never select it.
pub(crate) enum BackendSelection {
    /// Local settings come from the resolved layers; retain the profile name for diagnostics.
    Local { profile: Option<String> },
    /// A named cloud profile, or ambient cloud settings without a profile.
    Cloud { profile: Option<String> },
}

/// Configured profiles and effective selection, without resolving credentials or creating a backend.
#[derive(Debug, Serialize)]
pub struct BackendContext {
    /// Profiles sorted by name, including prohibited and incomplete entries.
    pub profiles: Vec<ContextProfile>,
    /// Selected identity, even when policy prohibits using it. Absent if selection itself failed.
    pub selected: Option<BackendInfo>,
    /// Why the selected backend cannot be used. Credentials are not probed by this inspection.
    pub selection_error: Option<String>,
    /// Saved user preference, before environment and managed selection are applied.
    pub saved_profile: Option<String>,
    /// Whether environment or managed settings override the saved preference.
    pub preference_overridden: bool,
    /// Effective restriction; absent means both backend kinds are permitted.
    pub allowed_backends: Option<Vec<BackendKind>>,
}

/// Public profile metadata. Credential values and references are never included.
#[derive(Debug, Serialize)]
pub struct ContextProfile {
    /// Profile name used by `msb context use`.
    pub name: String,
    /// Backend selected by this profile.
    pub kind: BackendKind,
    /// Whether effective device policy permits this backend.
    pub allowed: bool,
    /// Whether this SDK build includes the backend.
    pub available: bool,
    /// Whether a cloud credential reference is configured; its value is never resolved here.
    /// Always true for local profiles, which need no credentials.
    pub credentials_configured: bool,
}

#[derive(Clone, ConfigPatch)]
struct SelectionConfig {
    #[config_patch(nullable)]
    backend: Option<String>,
    #[config_patch(nullable)]
    profile: Option<String>,
    #[config_patch(merge)]
    profiles: HashMap<String, Profile>,
    source: BackendSelectionSource,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl BackendSelection {
    pub(crate) fn resolve(
        user_path: &Path,
        managed_path: Option<&Path>,
    ) -> MicrosandboxResult<(BackendSelection, BackendSelectionSource, BackendConfig)> {
        let managed = ManagedConfig::load(managed_path)?.overrides;
        let backend = std::env::var("MSB_BACKEND").ok();
        let profile = std::env::var("MSB_PROFILE").ok();
        let api_key = std::env::var("MSB_API_KEY").ok();
        Self::resolve_from(
            user_path,
            managed_path,
            managed,
            backend,
            profile,
            api_key.as_deref(),
            || GlobalConfigPatch::load_from(user_path),
        )
    }

    fn resolve_from(
        user_path: &Path,
        managed_path: Option<&Path>,
        managed: GlobalConfigPatch,
        backend: Option<String>,
        profile: Option<String>,
        api_key: Option<&str>,
        load: impl FnOnce() -> MicrosandboxResult<GlobalConfigPatch>,
    ) -> MicrosandboxResult<(BackendSelection, BackendSelectionSource, BackendConfig)> {
        let global = load()?;
        let (selection, source) = Self::describe(&global, &managed, backend, profile, api_key)?;
        let config =
            BackendConfig::new(global, managed).with_source_files(user_path, managed_path)?;
        selection.validate(&config, source, api_key)?;
        Ok((selection, source, config))
    }

    /// Check policy, build support, and ambient credentials without resolving profile secrets.
    fn validate(
        &self,
        config: &BackendConfig,
        source: BackendSelectionSource,
        api_key: Option<&str>,
    ) -> MicrosandboxResult<()> {
        config.require_backend(self.kind(), Some(source))?;
        self.kind().require_available()?;
        if matches!(self, Self::Cloud { profile: None })
            && api_key.is_none_or(|key| key.trim().is_empty())
        {
            return Err(MicrosandboxError::InvalidConfig(
                "MSB_BACKEND=cloud requires a non-empty MSB_API_KEY or a cloud profile".into(),
            ));
        }
        Ok(())
    }

    /// Describe selection using captured inputs; never read a profile's credentials.
    fn describe(
        global: &GlobalConfigPatch,
        managed: &GlobalConfigPatch,
        backend: Option<String>,
        profile: Option<String>,
        api_key: Option<&str>,
    ) -> MicrosandboxResult<(Self, BackendSelectionSource)> {
        let mut overrides = SelectionConfigPatch::new();
        if let Some(profile) = profile.filter(|value| !value.trim().is_empty()) {
            overrides.profile_mut(profile.trim().to_owned());
            overrides.source_mut(BackendSelectionSource::MsbProfile);
        }
        if let Some(backend) = backend {
            overrides.backend_mut(backend);
            overrides.source_mut(BackendSelectionSource::MsbBackend);
        }

        overrides.profiles = managed.profiles.clone();

        if let Some(profile) = &managed.active_profile {
            overrides.set_profile_mut(profile.clone());
            let named = profile
                .as_deref()
                .is_some_and(|name| !name.trim().is_empty());
            if named {
                overrides.set_backend_mut(None);
            }
            if named || overrides.backend.is_none() {
                overrides.source_mut(BackendSelectionSource::ActiveProfile);
            }
        }

        let kind = Self::parse_kind(overrides.backend.as_ref().and_then(Option::as_deref))?;
        let source = if global
            .active_profile
            .as_ref()
            .and_then(Option::as_deref)
            .is_some_and(|name| !name.trim().is_empty())
        {
            BackendSelectionSource::ActiveProfile
        } else {
            BackendSelectionSource::Default
        };

        let mut saved = SelectionConfigPatch::new().source(source);
        if let Some(profile) = &global.active_profile {
            saved.set_profile_mut(profile.clone());
        }

        saved.profiles = global.profiles.clone();
        let selection = saved.overlay(overrides).into_config();
        let backend = Self::select(
            kind,
            api_key,
            selection.profile.as_deref(),
            &selection.profiles,
        )?;

        Ok((backend, selection.source))
    }

    fn kind(&self) -> BackendKind {
        match self {
            Self::Local { .. } => BackendKind::Local,
            Self::Cloud { .. } => BackendKind::Cloud,
        }
    }

    fn profile(&self) -> Option<&str> {
        match self {
            Self::Local { profile } | Self::Cloud { profile } => profile.as_deref(),
        }
    }

    /// Parse an explicit backend kind without treating credentials as routing.
    fn parse_kind(value: Option<&str>) -> MicrosandboxResult<Option<ProfileBackend>> {
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
    fn select(
        backend_kind: Option<ProfileBackend>,
        api_key: Option<&str>,
        profile: Option<&str>,
        profiles: &HashMap<String, Profile>,
    ) -> MicrosandboxResult<Self> {
        if backend_kind == Some(ProfileBackend::Local) {
            return Ok(Self::Local { profile: None });
        }

        let has_api_key = api_key.is_some_and(|key| !key.trim().is_empty());
        if backend_kind == Some(ProfileBackend::Cloud) && has_api_key {
            return Ok(Self::Cloud { profile: None });
        }

        let profile_name = profile.map(str::trim).filter(|name| !name.is_empty());
        if let Some(name) = profile_name {
            let profile = profiles.get(name).ok_or_else(|| {
                MicrosandboxError::InvalidConfig(format!(
                    "active profile {name:?} not found in global config"
                ))
            })?;
            if backend_kind == Some(ProfileBackend::Cloud)
                && profile.backend != ProfileBackend::Cloud
            {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "MSB_BACKEND=cloud cannot select local profile {name:?}"
                )));
            }
            return Ok(match profile.backend {
                ProfileBackend::Local => Self::Local {
                    profile: Some(name.to_string()),
                },
                ProfileBackend::Cloud => Self::Cloud {
                    profile: Some(name.to_string()),
                },
            });
        }

        if backend_kind == Some(ProfileBackend::Cloud) {
            return Ok(Self::Cloud { profile: None });
        }

        // A bare API key is credential material, not backend intent.
        Ok(Self::Local { profile: None })
    }
}

impl BackendContext {
    /// Inspect saved profiles and ambient selection without contacting a backend or credential store.
    pub fn load() -> MicrosandboxResult<Self> {
        Self::load_from(&super::config_path(), None)
    }

    /// Save an allowed named profile as the user preference without resolving its credentials.
    /// Environment and managed selection can still override this preference.
    pub fn use_profile(name: &str) -> MicrosandboxResult<Self> {
        Self::save_profile_preference(&super::config_path(), None, Some(name))
    }

    /// Remove the saved user preference. Environment and administrator settings remain effective.
    pub fn reset() -> MicrosandboxResult<Self> {
        Self::save_profile_preference(&super::config_path(), None, None)
    }

    fn load_from(user_path: &Path, managed_path: Option<&Path>) -> MicrosandboxResult<Self> {
        Self::from_configs(
            GlobalConfigPatch::load_from(user_path)?,
            ManagedConfig::load(managed_path)?.overrides,
            user_path,
            managed_path,
        )
    }

    fn save_profile_preference(
        user_path: &Path,
        managed_path: Option<&Path>,
        name: Option<&str>,
    ) -> MicrosandboxResult<Self> {
        let mut user = GlobalConfigPatch::load_from(user_path)?;
        let managed = ManagedConfig::load(managed_path)?.overrides;
        let config = BackendConfig::new(user.clone(), managed.clone())
            .with_source_files(user_path, managed_path)?;
        config.validate_backend_policy()?;
        if let Some(name) = name {
            let profile = config.resolved_config().profiles.get(name).ok_or_else(|| {
                MicrosandboxError::InvalidConfig(format!("profile {name:?} not found in config"))
            })?;
            let kind = BackendKind::from(profile.backend);
            config.require_backend(kind, Some(BackendSelectionSource::Profile))?;
            kind.require_available()?;
            user.active_profile_mut(name.to_owned());
        } else {
            user.clear_active_profile_mut();
        }
        let context = Self::from_configs(user.clone(), managed, user_path, managed_path)?;
        user.save_to(user_path)?;
        Ok(context)
    }

    fn from_configs(
        user: GlobalConfigPatch,
        managed: GlobalConfigPatch,
        user_path: &Path,
        managed_path: Option<&Path>,
    ) -> MicrosandboxResult<Self> {
        let config = BackendConfig::new(user.clone(), managed.clone())
            .with_source_files(user_path, managed_path)?;
        config.validate_backend_policy()?;
        let resolved = config.resolved_config();
        let mut profiles = resolved
            .profiles
            .iter()
            .map(|(name, profile)| {
                let kind = BackendKind::from(profile.backend);
                ContextProfile {
                    name: name.clone(),
                    kind,
                    allowed: config.require_backend(kind, None).is_ok(),
                    available: kind.is_available(),
                    credentials_configured: kind == BackendKind::Local
                        || profile.api_key_ref.is_some(),
                }
            })
            .collect::<Vec<_>>();
        profiles.sort_by(|a, b| a.name.cmp(&b.name));

        let backend = std::env::var("MSB_BACKEND").ok();
        let profile = std::env::var("MSB_PROFILE").ok();
        let api_key = std::env::var("MSB_API_KEY").ok();
        let preference_overridden = managed.active_profile.is_some()
            || backend.is_some()
            || profile.as_ref().is_some_and(|name| !name.trim().is_empty());
        let selection =
            BackendSelection::describe(&user, &managed, backend, profile, api_key.as_deref());
        let (selected, selection_error) = match selection {
            Ok((selection, source)) => {
                let kind = selection.kind();
                let error = selection
                    .validate(&config, source, api_key.as_deref())
                    .err()
                    .map(|error| error.to_string());
                let info = BackendInfo {
                    kind,
                    api_url: None,
                    source,
                    profile: selection.profile().map(str::to_owned),
                };
                (Some(info), error)
            }
            Err(error) => (None, Some(error.to_string())),
        };
        Ok(Self {
            profiles,
            selected,
            selection_error,
            saved_profile: user.active_profile.flatten(),
            preference_overridden,
            allowed_backends: resolved.allowed_backends.clone(),
        })
    }
}

/// Report a backend selected at runtime but omitted from this SDK build.
pub(crate) fn feature_disabled(feature: &str) -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(format!(
        "the {feature} backend is not available; rebuild microsandbox with the {feature:?} feature"
    ))
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for SelectionConfig {
    fn default() -> Self {
        Self {
            backend: None,
            profile: None,
            profiles: HashMap::new(),
            source: BackendSelectionSource::Default,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GlobalConfig;

    #[test]
    fn prohibited_selection_fails_before_profile_credentials_are_resolved() {
        let user = serde_json::from_str(
            r#"{
            "active_profile":"work",
            "profiles":{"work":{"backend":"cloud","api_key_ref":"keyring:unresolved"}}
        }"#,
        )
        .unwrap();
        let managed = GlobalConfigPatch::new().allowed_backends(vec![BackendKind::Local]);
        let error = BackendSelection::resolve_from(
            Path::new("config.json"),
            Some(Path::new("managed.json")),
            managed,
            None,
            None,
            None,
            || Ok(user),
        )
        .err()
        .unwrap()
        .to_string();
        assert!(
            error.contains("cloud backend selected by active_profile is disabled"),
            "{error}"
        );
        assert!(error.contains("managed config"));
        assert!(error.contains("managed.json"));
        assert!(!error.contains("keyring"));
    }

    #[cfg(feature = "local")]
    #[test]
    fn managed_context_selection_and_sparse_preference_writes() {
        let _lock = crate::test_support::lock_env();
        let _env = SelectionEnvironment::clear();
        let dir = tempfile::tempdir().unwrap();
        let user = dir.path().join("config.json");
        let managed = dir.path().join("managed.json");
        std::fs::write(
            &user,
            r#"{
            "active_profile":"missing",
            "sandbox_defaults":{"cpus":3},
            "profiles":{"personal":{"backend":"local"},"work":{"backend":"cloud"}}
        }"#,
        )
        .unwrap();
        std::fs::write(
            &managed,
            r#"{"overrides":{
            "active_profile":"personal", "allowed_backends":["local"]
        }}"#,
        )
        .unwrap();

        let before = std::fs::read(&user).unwrap();
        let context = BackendContext::load_from(&user, Some(&managed)).unwrap();
        assert_eq!(
            context.selected.unwrap().profile.as_deref(),
            Some("personal")
        );
        assert!(context.preference_overridden);
        assert!(
            !context
                .profiles
                .iter()
                .find(|p| p.name == "work")
                .unwrap()
                .allowed
        );
        assert!(
            BackendContext::save_profile_preference(&user, Some(&managed), Some("work")).is_err()
        );
        assert_eq!(std::fs::read(&user).unwrap(), before);

        let context =
            BackendContext::save_profile_preference(&user, Some(&managed), Some("personal"))
                .unwrap();
        assert_eq!(context.saved_profile.as_deref(), Some("personal"));
        let saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&user).unwrap()).unwrap();
        assert_eq!(saved["sandbox_defaults"], serde_json::json!({"cpus":3}));
        assert!(saved.get("allowed_backends").is_none());
        assert!(saved.get("home").is_none());

        let context = BackendContext::save_profile_preference(&user, Some(&managed), None).unwrap();
        assert_eq!(context.saved_profile, None);
        assert_eq!(
            context.selected.unwrap().profile.as_deref(),
            Some("personal")
        );
        let saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&user).unwrap()).unwrap();
        assert!(saved.get("active_profile").is_none());
        assert_eq!(saved["sandbox_defaults"], serde_json::json!({"cpus":3}));

        std::fs::write(&managed, r#"{"overrides":{"allowed_backends":[]}}"#).unwrap();
        let before = std::fs::read(&user).unwrap();
        let error = BackendContext::load_from(&user, Some(&managed))
            .unwrap_err()
            .to_string();
        assert!(error.contains("managed config"), "{error}");
        assert!(error.contains(managed.to_str().unwrap()), "{error}");
        assert!(BackendContext::save_profile_preference(&user, Some(&managed), None).is_err());
        assert_eq!(std::fs::read(&user).unwrap(), before);
    }

    #[test]
    fn context_inspection_reports_invalid_selection_without_exposing_credentials() {
        let _lock = crate::test_support::lock_env();
        let _env = SelectionEnvironment::clear();
        let dir = tempfile::tempdir().unwrap();
        let user_path = dir.path().join("config.json");
        let managed_path = dir.path().join("managed.json");
        let mut user: GlobalConfigPatch = serde_json::from_str(
            r#"{
            "active_profile":"missing",
            "profiles":{
                "a":{"backend":"cloud"},
                "b":{"backend":"cloud","api_key_ref":"env:DO_NOT_RESOLVE_THIS"},
                "c":{"backend":"cloud","api_key_ref":"keyring:DO_NOT_RESOLVE_THIS"},
                "d":{"backend":"cloud","api_key_ref":"inline:NEVER_PRINT_THIS"}
            }
        }"#,
        )
        .unwrap();
        let context = BackendContext::from_configs(
            user.clone(),
            Default::default(),
            &user_path,
            Some(&managed_path),
        )
        .unwrap();
        assert!(context.selected.is_none());
        assert!(context.selection_error.unwrap().contains("not found"));
        assert_eq!(
            context
                .profiles
                .iter()
                .map(|p| p.name.as_str())
                .collect::<Vec<_>>(),
            ["a", "b", "c", "d"]
        );

        for name in ["a", "b", "c", "d"] {
            user.active_profile_mut(name.to_owned());
            let context = BackendContext::from_configs(
                user.clone(),
                Default::default(),
                &user_path,
                Some(&managed_path),
            )
            .unwrap();
            assert_eq!(
                context.selected.as_ref().unwrap().profile.as_deref(),
                Some(name)
            );
            assert_eq!(context.selection_error.is_none(), cfg!(feature = "cloud"));
            let output = serde_json::to_string(&context).unwrap();
            assert!(!output.contains("DO_NOT_RESOLVE_THIS"));
            assert!(!output.contains("NEVER_PRINT_THIS"));
            assert!(!output.contains("api_key_ref"));
        }

        // An environment selector remains effective after saving a different preference.
        unsafe { std::env::set_var("MSB_BACKEND", "local") };
        let context =
            BackendContext::from_configs(user, Default::default(), &user_path, Some(&managed_path))
                .unwrap();
        assert!(context.preference_overridden);
        assert_eq!(context.selected.unwrap().kind, BackendKind::Local);
    }

    #[test]
    fn selection_rejects_backends_missing_from_this_build() {
        for (kind, available) in [
            ("local", cfg!(feature = "local")),
            ("cloud", cfg!(feature = "cloud")),
        ] {
            let result = BackendSelection::resolve_from(
                Path::new("config.json"),
                Some(Path::new("managed.json")),
                Default::default(),
                Some(kind.into()),
                None,
                Some("test-key"),
                || Ok(GlobalConfigPatch::new()),
            );

            if available {
                assert_eq!(result.unwrap().0.kind().as_str(), kind);
            } else {
                let error = result.err().unwrap().to_string();
                assert!(error.contains(&format!("the {kind} backend is not available")));
            }
        }
    }

    struct SelectionEnvironment(Vec<(&'static str, Option<std::ffi::OsString>)>);

    impl SelectionEnvironment {
        fn clear() -> Self {
            let saved = ["MSB_BACKEND", "MSB_PROFILE", "MSB_API_KEY"].map(|name| {
                let value = std::env::var_os(name);
                // SAFETY: callers hold the shared environment lock until this guard drops.
                unsafe { std::env::remove_var(name) };
                (name, value)
            });
            Self(saved.into())
        }
    }

    impl Drop for SelectionEnvironment {
        fn drop(&mut self) {
            for (name, value) in &self.0 {
                // SAFETY: the caller still holds the shared environment lock.
                unsafe {
                    match value {
                        Some(value) => std::env::set_var(name, value),
                        None => std::env::remove_var(name),
                    }
                }
            }
        }
    }

    #[cfg(feature = "local")]
    #[test]
    fn managed_clear_removes_profiles_without_suppressing_backend_errors() {
        for value in [
            serde_json::Value::Null,
            serde_json::json!(""),
            serde_json::json!(" "),
        ] {
            let managed: GlobalConfigPatch =
                serde_json::from_value(serde_json::json!({"active_profile":value})).unwrap();
            let (selection, source, _) = BackendSelection::resolve_from(
                Path::new("config.json"),
                Some(Path::new("managed.json")),
                managed.clone(),
                None,
                Some("environment".into()),
                Some("unused"),
                || Ok(GlobalConfigPatch::new().active_profile("saved".into())),
            )
            .unwrap();
            assert!(matches!(
                selection,
                BackendSelection::Local { profile: None }
            ));
            assert_eq!(source, BackendSelectionSource::ActiveProfile);
            assert!(
                BackendSelection::resolve_from(
                    Path::new("config.json"),
                    Some(Path::new("managed.json")),
                    managed.clone(),
                    Some("invalid".into()),
                    None,
                    None,
                    || Ok(GlobalConfigPatch::new())
                )
                .is_err()
            );
            assert!(
                BackendSelection::resolve_from(
                    Path::new("config.json"),
                    Some(Path::new("managed.json")),
                    managed,
                    Some("cloud".into()),
                    None,
                    None,
                    || Ok(GlobalConfigPatch::new())
                )
                .is_err()
            );
        }
    }

    #[test]
    fn explicit_local_reports_malformed_user_config() {
        let result = BackendSelection::resolve_from(
            Path::new("config.json"),
            Some(Path::new("managed.json")),
            Default::default(),
            Some("local".into()),
            None,
            None,
            || {
                Err(MicrosandboxError::InvalidConfig(
                    "malformed user config".into(),
                ))
            },
        );
        assert!(
            matches!(result, Err(MicrosandboxError::InvalidConfig(message)) if message == "malformed user config")
        );
    }

    #[cfg(feature = "local")]
    #[test]
    fn managed_profile_overrides_invalid_environment_and_replaces_profile_entry() {
        let managed = serde_json::from_str(
            r#"{
            "active_profile":"work", "profiles":{"work":{"backend":"local"}}
        }"#,
        )
        .unwrap();
        let (selection, source, global) = BackendSelection::resolve_from(
            Path::new("config.json"),
            Some(Path::new("managed.json")),
            managed,
            Some("invalid".into()),
            Some("other".into()),
            Some("cloud-key"),
            || {
                Ok(serde_json::from_str(
                    r#"{
                "active_profile":"other",
                "profiles":{"work":{"backend":"cloud","api_key_ref":"inline:unused"}}
            }"#,
                )
                .unwrap())
            },
        )
        .unwrap();
        assert!(matches!(
            selection,
            BackendSelection::Local { profile: Some(name) } if name == "work"
        ));
        assert_eq!(source, BackendSelectionSource::ActiveProfile);
        assert_eq!(
            global.resolved_config().profiles["work"].backend,
            ProfileBackend::Local
        );
        assert_eq!(global.resolved_config().profiles["work"].api_key_ref, None);
    }

    #[cfg(feature = "cloud")]
    #[test]
    fn managed_clear_preserves_explicit_backend_selection() {
        for value in [serde_json::Value::Null, serde_json::json!("")] {
            let managed =
                serde_json::from_value(serde_json::json!({"active_profile":value})).unwrap();
            let (selection, source, _) = BackendSelection::resolve_from(
                Path::new("config.json"),
                Some(Path::new("managed.json")),
                managed,
                Some("cloud".into()),
                Some("other".into()),
                Some("key"),
                || Ok(GlobalConfigPatch::new().active_profile("saved".into())),
            )
            .unwrap();
            assert!(matches!(
                selection,
                BackendSelection::Cloud { profile: None }
            ));
            assert_eq!(source, BackendSelectionSource::MsbBackend);
        }
    }

    #[cfg(feature = "local")]
    #[test]
    fn profile_selection_preserves_map_merge_and_replacement() {
        let additional: GlobalConfigPatch =
            serde_json::from_str(r#"{"profiles":{"other":{"backend":"local"}}}"#).unwrap();
        for (managed, should_find_profile) in [
            (additional.clone(), true),
            (
                GlobalConfigPatch::new()
                    .replace_profiles(additional.get_profiles().unwrap().clone()),
                false,
            ),
            (
                GlobalConfigPatch::new().replace_profiles(HashMap::new()),
                false,
            ),
        ] {
            let result = BackendSelection::resolve_from(
                Path::new("config.json"),
                Some(Path::new("managed.json")),
                managed,
                None,
                None,
                None,
                || {
                    Ok(serde_json::from_str(
                        r#"{"active_profile":"work","profiles":{"work":{"backend":"local"}}}"#,
                    )
                    .unwrap())
                },
            );
            if should_find_profile {
                assert!(matches!(
                    result.unwrap().0,
                    BackendSelection::Local { profile: Some(name) } if name == "work"
                ));
            } else {
                assert!(matches!(
                    result,
                    Err(MicrosandboxError::InvalidConfig(message))
                        if message.contains("active profile \"work\" not found")
                ));
            }
        }
    }

    #[cfg(feature = "local")]
    #[test]
    fn local_construction_uses_the_configuration_loaded_during_selection() {
        let home = tempfile::tempdir().unwrap();
        let mut loads = 0;
        let (selection, source, layers) = BackendSelection::resolve_from(
            Path::new("config.json"),
            Some(Path::new("managed.json")),
            Default::default(),
            Some("local".into()),
            None,
            None,
            || {
                loads += 1;
                Ok(GlobalConfigPatch::new().home(home.path().to_path_buf()))
            },
        )
        .unwrap();
        assert!(matches!(
            selection,
            BackendSelection::Local { profile: None }
        ));
        let backend = crate::backend::LocalBackend::from_backend_config(
            layers
                .prepare_for_local_backend(Default::default())
                .unwrap(),
            source,
            None,
        );
        assert_eq!(loads, 1);
        assert_eq!(backend.config().home(), home.path());
    }

    #[cfg(all(feature = "local", feature = "cloud"))]
    #[test]
    fn ordinary_explicit_routing_and_profile_sources_are_preserved() {
        for (kind, key) in [("local", None), ("cloud", Some("key"))] {
            let (selection, source, _) = BackendSelection::resolve_from(
                Path::new("config.json"),
                Some(Path::new("managed.json")),
                Default::default(),
                Some(kind.into()),
                None,
                key,
                || Ok(GlobalConfigPatch::default()),
            )
            .unwrap();
            assert!(matches!(
                (kind, selection),
                ("local", BackendSelection::Local { profile: None })
                    | ("cloud", BackendSelection::Cloud { profile: None })
            ));
            assert_eq!(source, BackendSelectionSource::MsbBackend);
        }
        let (selection, source, _) = BackendSelection::resolve_from(
            Path::new("config.json"),
            Some(Path::new("managed.json")),
            Default::default(),
            None,
            Some(" env-profile ".into()),
            Some("key"),
            || {
                Ok(
                    serde_json::from_str(r#"{"profiles":{"env-profile":{"backend":"local"}}}"#)
                        .unwrap(),
                )
            },
        )
        .unwrap();
        assert!(matches!(
            selection,
            BackendSelection::Local { profile: Some(name) } if name == "env-profile"
        ));
        assert_eq!(source, BackendSelectionSource::MsbProfile);
    }

    fn select_backend(
        backend: Option<&str>,
        api_key: Option<&str>,
        env_profile: Option<&str>,
        active_profile: Option<&str>,
    ) -> MicrosandboxResult<BackendSelection> {
        BackendSelection::resolve_from(
            Path::new("config.json"),
            Some(Path::new("managed.json")),
            Default::default(),
            backend.map(str::to_owned),
            env_profile.map(str::to_owned),
            api_key,
            || {
                Ok(GlobalConfig {
                    active_profile: active_profile.map(str::to_owned),
                    profiles: serde_json::from_str(
                        r#"{
                            "local-profile":{"backend":"local"},
                            "staging":{"backend":"cloud","url":"https://staging.example.com","api_key_ref":"inline:staging-key"},
                            "prod":{"backend":"cloud","url":"https://prod.example.com","api_key_ref":"inline:prod-key"}
                        }"#,
                    )
                    .unwrap(),
                    ..Default::default()
                }.into())
            },
        )
        .map(|(selection, _, _)| selection)
    }

    #[cfg(feature = "local")]
    #[test]
    fn credentials_alone_do_not_select_cloud() {
        assert!(matches!(
            select_backend(None, Some("msb_live_abc"), None, None).unwrap(),
            BackendSelection::Local { profile: None }
        ));
        assert!(matches!(
            select_backend(None, Some("msb_live_abc"), None, Some("local-profile")).unwrap(),
            BackendSelection::Local { profile: Some(name) } if name == "local-profile"
        ));
    }

    #[cfg(feature = "cloud")]
    #[test]
    fn explicit_cloud_uses_environment_credentials() {
        for profile in [None, Some("missing")] {
            assert!(matches!(
                select_backend(Some("cloud"), Some("msb_live_abc"), profile, None).unwrap(),
                BackendSelection::Cloud { profile: None }
            ));
        }
    }

    #[cfg(feature = "cloud")]
    #[test]
    fn explicit_cloud_without_credentials_or_profile_fails() {
        let err = select_backend(Some("cloud"), None, None, None)
            .err()
            .unwrap();
        assert!(err.to_string().contains("requires a non-empty MSB_API_KEY"));
    }

    #[cfg(feature = "local")]
    #[test]
    fn explicit_local_wins_over_credentials_and_profiles() {
        assert!(matches!(
            select_backend(
                Some("local"),
                Some("msb_live_abc"),
                Some("cloud-profile"),
                Some("other-profile"),
            )
            .unwrap(),
            BackendSelection::Local { profile: None }
        ));
    }

    #[cfg(feature = "cloud")]
    #[test]
    fn profile_selection_is_explicit_backend_intent() {
        for (env_profile, expected) in [(Some("staging"), "staging"), (None, "prod")] {
            let BackendSelection::Cloud {
                profile: Some(name),
            } = select_backend(None, None, env_profile, Some("prod")).unwrap()
            else {
                panic!("expected resolved cloud settings");
            };
            assert_eq!(name, expected);
        }
    }

    #[cfg(feature = "cloud")]
    #[test]
    fn explicit_cloud_requires_selected_profile_to_be_cloud() {
        assert!(matches!(
            select_backend(Some("cloud"), None, Some("prod"), None).unwrap(),
            BackendSelection::Cloud { profile: Some(name) } if name == "prod"
        ));
        for (env_profile, active_profile) in
            [(Some("local-profile"), None), (None, Some("local-profile"))]
        {
            let error = select_backend(Some("cloud"), None, env_profile, active_profile)
                .err()
                .unwrap();
            assert!(
                error
                    .to_string()
                    .contains("cannot select local profile \"local-profile\"")
            );
        }
    }

    #[test]
    fn missing_profile_fails_during_selection() {
        let error = select_backend(None, None, Some("missing"), None)
            .err()
            .unwrap();
        assert!(
            error
                .to_string()
                .contains("active profile \"missing\" not found")
        );
    }

    #[cfg(feature = "cloud")]
    #[test]
    fn cloud_profile_settings_are_resolved_after_managed_overrides() {
        let _env_guard = crate::test_support::lock_env();
        let previous = std::env::var_os("MSB_TEST_MANAGED_PROFILE_KEY");
        // SAFETY: every environment-mutating SDK unit test holds the shared lock.
        unsafe { std::env::set_var("MSB_TEST_MANAGED_PROFILE_KEY", "managed-key") };
        let managed = serde_json::from_str(
            r#"{"profiles":{"work":{"backend":"cloud","api_key_ref":"env:MSB_TEST_MANAGED_PROFILE_KEY"}}}"#,
        )
        .unwrap();
        let selection = BackendSelection::resolve_from(
            Path::new("config.json"),
            Some(Path::new("managed.json")),
            managed,
            None,
            None,
            None,
            || {
                Ok(serde_json::from_str(
                    r#"{
                    "active_profile":"work",
                    "profiles":{"work":{
                        "backend":"cloud",
                        "url":"https://user.example.com",
                        "api_key_ref":"inline:   "
                    }}
                }"#,
                )
                .unwrap())
            },
        );
        let cloud = selection.map(|(selection, source, config)| match selection {
            BackendSelection::Cloud {
                profile: Some(name),
            } => {
                let builder = config.resolved_config().profiles[&name]
                    .cloud_builder(&name)
                    .unwrap();
                Some((name, source, builder.config_sources(config).build()))
            }
            _ => None,
        });
        unsafe {
            match previous {
                Some(value) => std::env::set_var("MSB_TEST_MANAGED_PROFILE_KEY", value),
                None => std::env::remove_var("MSB_TEST_MANAGED_PROFILE_KEY"),
            }
        }
        let (name, source, cloud) = cloud.unwrap().expect("expected resolved cloud settings");
        assert_eq!(name, "work");
        assert_eq!(source, BackendSelectionSource::ActiveProfile);
        assert_eq!(cloud.unwrap().url(), crate::backend::DEFAULT_CLOUD_API_URL);
    }

    #[cfg(feature = "cloud")]
    #[test]
    fn selection_does_not_resolve_cloud_credentials() {
        for key_ref in [None, Some("inline:   ")] {
            let result = BackendSelection::resolve_from(
                Path::new("config.json"),
                Some(Path::new("managed.json")),
                Default::default(),
                None,
                Some("work".into()),
                None,
                || {
                    Ok(serde_json::from_value(serde_json::json!({
                        "profiles": {"work": {"backend": "cloud", "api_key_ref": key_ref}}
                    }))
                    .unwrap())
                },
            );
            let (selection, _, config) = result.unwrap();
            assert!(
                matches!(selection, BackendSelection::Cloud { profile: Some(name) } if name == "work")
            );
            assert!(
                config.resolved_config().profiles["work"]
                    .cloud_builder("work")
                    .is_err()
            );
        }
    }
}

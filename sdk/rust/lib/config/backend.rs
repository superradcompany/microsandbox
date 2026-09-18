//! Collapse ambient backend-selection inputs before constructing a backend.

use std::{collections::HashMap, path::Path};

use microsandbox_types::ConfigPatch;

use super::{GlobalConfigPatch, layers::BackendConfig, persistence::ManagedConfig};
#[cfg(feature = "cloud")]
use crate::backend::CloudBackendBuilder;
use crate::backend::{BackendSelectionSource, Profile, ProfileBackend};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Backend settings after applying selection precedence and resolving any named profile.
///
/// Keeping selection separate from backend construction makes the safety
/// invariant testable: credentials configure Cloud, but never select it.
pub(crate) enum BackendSelection {
    /// Local settings come from the resolved layers; retain the profile name for diagnostics.
    Local { profile: Option<String> },
    /// Resolved connection settings and a profile name, or environment settings without a profile.
    #[cfg(feature = "cloud")]
    Cloud {
        profile: Option<(String, CloudBackendBuilder)>,
    },
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
        Self::resolve_from(managed, backend, profile, api_key.as_deref(), || {
            GlobalConfigPatch::load_from(user_path)
        })
    }

    fn resolve_from(
        managed: GlobalConfigPatch,
        backend: Option<String>,
        profile: Option<String>,
        api_key: Option<&str>,
        load: impl FnOnce() -> MicrosandboxResult<GlobalConfigPatch>,
    ) -> MicrosandboxResult<(BackendSelection, BackendSelectionSource, BackendConfig)> {
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

        // Both backends retain device settings for sandbox creation and host-side SSH.
        let kind = Self::parse_kind(overrides.backend.as_ref().and_then(Option::as_deref))?;
        let global = load()?;

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

        Ok((
            backend,
            selection.source,
            BackendConfig::new(global, managed),
        ))
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
            #[cfg(feature = "cloud")]
            return Ok(Self::Cloud { profile: None });
            #[cfg(not(feature = "cloud"))]
            return Err(feature_disabled("cloud"));
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
                ProfileBackend::Cloud => {
                    #[cfg(feature = "cloud")]
                    {
                        Self::Cloud {
                            profile: Some((name.to_string(), profile.cloud_builder(name)?)),
                        }
                    }
                    #[cfg(not(feature = "cloud"))]
                    return Err(feature_disabled("cloud"));
                }
            });
        }

        if backend_kind == Some(ProfileBackend::Cloud) {
            return Err(MicrosandboxError::InvalidConfig(
                "MSB_BACKEND=cloud requires a non-empty MSB_API_KEY or a cloud profile".into(),
            ));
        }

        // A bare API key is credential material, not backend intent.
        Ok(Self::Local { profile: None })
    }
}

/// Report a backend selected at runtime but omitted from this SDK build.
#[cfg(not(all(feature = "local", feature = "cloud")))]
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
    fn managed_clear_removes_profiles_without_suppressing_backend_errors() {
        for value in [
            serde_json::Value::Null,
            serde_json::json!(""),
            serde_json::json!(" "),
        ] {
            let managed: GlobalConfigPatch =
                serde_json::from_value(serde_json::json!({"active_profile":value})).unwrap();
            let (selection, source, _) = BackendSelection::resolve_from(
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
                    managed.clone(),
                    Some("invalid".into()),
                    None,
                    None,
                    || Ok(GlobalConfigPatch::new())
                )
                .is_err()
            );
            assert!(
                BackendSelection::resolve_from(managed, Some("cloud".into()), None, None, || Ok(
                    GlobalConfigPatch::new()
                ))
                .is_err()
            );
        }
    }

    #[test]
    fn explicit_local_reports_malformed_user_config() {
        let result = BackendSelection::resolve_from(
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

    #[test]
    fn managed_profile_overrides_invalid_environment_and_replaces_profile_entry() {
        let managed = serde_json::from_str(
            r#"{
            "active_profile":"work", "profiles":{"work":{"backend":"local"}}
        }"#,
        )
        .unwrap();
        let (selection, source, global) = BackendSelection::resolve_from(
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
            let result = BackendSelection::resolve_from(managed, None, None, None, || {
                Ok(serde_json::from_str(
                    r#"{"active_profile":"work","profiles":{"work":{"backend":"local"}}}"#,
                )
                .unwrap())
            });
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

    #[cfg(feature = "cloud")]
    #[test]
    fn ordinary_explicit_routing_and_profile_sources_are_preserved() {
        for (kind, key) in [("local", None), ("cloud", Some("key"))] {
            let (selection, source, _) = BackendSelection::resolve_from(
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

    #[test]
    fn explicit_cloud_without_credentials_or_profile_fails() {
        let err = select_backend(Some("cloud"), None, None, None)
            .err()
            .unwrap();
        assert!(err.to_string().contains("requires a non-empty MSB_API_KEY"));
    }

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
        for (env_profile, expected, url) in [
            (Some("staging"), "staging", "https://staging.example.com"),
            (None, "prod", "https://prod.example.com"),
        ] {
            let BackendSelection::Cloud {
                profile: Some((name, builder)),
            } = select_backend(None, None, env_profile, Some("prod")).unwrap()
            else {
                panic!("expected resolved cloud settings");
            };
            assert_eq!(name, expected);
            let cloud = builder
                .config_sources(BackendConfig::new(Default::default(), Default::default()))
                .build()
                .unwrap();
            assert_eq!(cloud.url(), url);
        }
    }

    #[cfg(feature = "cloud")]
    #[test]
    fn explicit_cloud_requires_selected_profile_to_be_cloud() {
        assert!(matches!(
            select_backend(Some("cloud"), None, Some("prod"), None).unwrap(),
            BackendSelection::Cloud { profile: Some((name, _)) } if name == "prod"
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
        let selection = BackendSelection::resolve_from(managed, None, None, None, || {
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
        });
        // Construction must use the key captured during selection, without another env lookup.
        unsafe { std::env::remove_var("MSB_TEST_MANAGED_PROFILE_KEY") };
        let cloud = selection.map(|(selection, source, config)| match selection {
            BackendSelection::Cloud {
                profile: Some((name, builder)),
            } => Some((name, source, builder.config_sources(config).build())),
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
    fn invalid_cloud_profile_credentials_fail_during_selection() {
        for key_ref in [None, Some("inline:   ")] {
            let result = BackendSelection::resolve_from(
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
            assert!(matches!(result, Err(MicrosandboxError::InvalidConfig(_))));
        }
    }
}

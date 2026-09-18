//! Read and write versioned user configuration and load machine-wide managed overrides.

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use serde::Deserialize;
use serde_json::{Map, Value};

use super::GlobalConfigPatch;
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Deserialize)]
pub(super) struct ManagedConfig {
    #[serde(default = "ManagedConfig::default_version")]
    version: u64,
    #[serde(default)]
    pub(super) overrides: GlobalConfigPatch,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl GlobalConfigPatch {
    /// Read saved user settings from [`super::config_path`], preserving omitted fields and clears.
    /// A missing file returns an empty patch. Defaults and managed overrides are applied later.
    pub fn load() -> MicrosandboxResult<Self> {
        Self::load_from(&super::config_path())
    }

    /// Read saved user settings from a specific path, or return an empty patch if it is missing.
    pub(super) fn load_from(path: &Path) -> MicrosandboxResult<Self> {
        serde_json::from_value(Self::read_json(path)?).map_err(|error| {
            MicrosandboxError::InvalidConfig(format!(
                "failed to parse config `{}`: {error}",
                path.display()
            ))
        })
    }

    /// Save this user-config patch to [`super::config_path`].
    /// Omitted settings are removed from the saved configuration; explicit clears are preserved.
    pub fn save(&self) -> MicrosandboxResult<()> {
        self.save_to(&super::config_path())
    }

    /// Save this user-config patch as version 1, without filling in defaults.
    /// Replaces the saved settings with this patch, discarding unrecognized fields.
    pub(super) fn save_to(&self, path: &Path) -> MicrosandboxResult<()> {
        // Refuse to overwrite an invalid or unsupported saved configuration.
        Self::load_from(path)?;

        let mut saved = serde_json::to_value(self)?;
        saved
            .as_object_mut()
            .expect("GlobalConfigPatch is an object")
            .insert("version".into(), 1.into());
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                MicrosandboxError::Custom(format!(
                    "failed to create config directory `{}`: {error}",
                    parent.display()
                ))
            })?;
        }
        fs::write(path, format!("{}\n", serde_json::to_string_pretty(&saved)?)).map_err(
            |error| {
                MicrosandboxError::Custom(format!(
                    "failed to write config `{}`: {error}",
                    path.display()
                ))
            },
        )?;
        Ok(())
    }

    fn read_json(path: &Path) -> MicrosandboxResult<Value> {
        let raw = match fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Value::Object(Map::new()));
            }
            Err(error) => {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "failed to read config `{}`: {error}",
                    path.display()
                )));
            }
        };
        let value: Value = serde_json::from_str(&raw).map_err(|error| {
            MicrosandboxError::InvalidConfig(format!(
                "failed to parse config `{}`: {error}",
                path.display()
            ))
        })?;
        if !value.is_object()
            || value
                .get("version")
                .is_some_and(|version| version.as_u64() != Some(1))
        {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "config `{}` requires an object with version 1 (defaults to 1 when omitted)",
                path.display()
            )));
        }
        Ok(value)
    }
}

impl ManagedConfig {
    /// Internal path injection for tests; production callers use the system path.
    pub(super) fn load(path: Option<&Path>) -> MicrosandboxResult<Self> {
        let owner_uid = 0;
        // Explicit test paths use the test user's ownership; the system path
        // still requires root. Both paths run the same permission checks.
        #[cfg(all(test, unix))]
        let owner_uid = if path.is_some() {
            // SAFETY: geteuid has no preconditions or side effects.
            unsafe { libc::geteuid() }
        } else {
            owner_uid
        };
        match path {
            Some(path) => Self::load_from(path, owner_uid),
            None => Self::load_from(&Self::path()?, owner_uid),
        }
    }

    fn load_from(path: &Path, _owner_uid: u32) -> MicrosandboxResult<Self> {
        let raw = match fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    version: Self::default_version(),
                    overrides: GlobalConfigPatch::default(),
                });
            }
            Err(error) => {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "failed to read managed config `{}`: {error}",
                    path.display()
                )));
            }
        };

        #[cfg(unix)]
        Self::validate_permissions(path, _owner_uid)?;
        let mut ignored = BTreeSet::new();
        let mut deserializer = serde_json::Deserializer::from_str(&raw);
        let config: Self = serde_ignored::deserialize(&mut deserializer, |key| {
            ignored.insert(key.to_string());
        })
        .and_then(|config| {
            deserializer.end()?;
            Ok(config)
        })
        .map_err(|error| {
            MicrosandboxError::InvalidConfig(format!(
                "invalid managed config `{}`: {error}",
                path.display()
            ))
        })?;

        // Serde also accepts structs as arrays; config files must be objects.
        if !raw.trim_start().starts_with('{') || config.version != 1 {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "invalid managed config `{}`: requires an object with version 1 (defaults to 1 when omitted)",
                path.display()
            )));
        }
        if !ignored.is_empty() {
            tracing::warn!(path = %path.display(), keys = ?ignored,
                "unrecognized managed config keys were ignored");
        }
        Ok(config)
    }

    #[cfg(unix)]
    fn validate_permissions(path: &Path, owner_uid: u32) -> MicrosandboxResult<()> {
        // These basic Unix checks do not inspect ACLs or the full ancestor chain.
        for path in std::iter::once(path).chain(path.parent()) {
            let metadata = fs::metadata(path).map_err(|error| {
                MicrosandboxError::InvalidConfig(format!(
                    "failed to check managed config permissions on `{}`: {error}",
                    path.display()
                ))
            })?;
            if metadata.uid() != owner_uid || metadata.mode() & 0o022 != 0 {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "unsafe managed config permissions on `{}`: expected owner uid \
                    {owner_uid} and no group or world write access, found uid {} and \
                    mode {:04o}; ask an administrator to correct ownership and permissions",
                    path.display(),
                    metadata.uid(),
                    metadata.mode() & 0o7777,
                )));
            }
        }
        Ok(())
    }

    fn path() -> MicrosandboxResult<PathBuf> {
        #[cfg(target_os = "macos")]
        {
            Ok(PathBuf::from(
                "/Library/Application Support/microsandbox/managed.json",
            ))
        }
        #[cfg(target_os = "linux")]
        {
            Ok(PathBuf::from("/etc/microsandbox/managed.json"))
        }
        #[cfg(windows)]
        {
            use std::{ffi::OsString, os::windows::ffi::OsStringExt, ptr};
            use windows_sys::Win32::{
                System::Com::CoTaskMemFree,
                UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath},
            };
            let mut raw = ptr::null_mut();
            // SAFETY: the API returns an allocated, NUL-terminated path. Copy it before freeing it.
            unsafe {
                if SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, ptr::null_mut(), &mut raw) < 0 {
                    return Err(MicrosandboxError::InvalidConfig(
                        "cannot resolve ProgramData".into(),
                    ));
                }
                let mut len = 0;
                while *raw.add(len) != 0 {
                    len += 1;
                }
                let path = PathBuf::from(OsString::from_wide(std::slice::from_raw_parts(raw, len)));
                CoTaskMemFree(raw.cast());
                Ok(path.join("microsandbox").join("managed.json"))
            }
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
        {
            Err(MicrosandboxError::InvalidConfig(
                "managed configuration is unsupported on this platform".into(),
            ))
        }
    }

    fn default_version() -> u64 {
        1
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::config::{GlobalConfig, RegistryAuthEntry, RegistryCredentialStore, RegistryEntry};

    use super::*;

    #[cfg(unix)]
    #[test]
    fn managed_permissions_reject_wrong_ownership_and_writable_paths() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("managed.json");
        fs::write(&path, r#"{"overrides":{"sandbox_defaults":{"cpus":2}}}"#).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let owner_uid = fs::metadata(&path).unwrap().uid();
        assert_eq!(
            ManagedConfig::load_from(&path, owner_uid)
                .unwrap()
                .overrides
                .sandbox_defaults
                .cpus,
            Some(2)
        );

        // Vary the required owner so this also exercises rejection when run as root.
        let error = ManagedConfig::load_from(&path, owner_uid.wrapping_add(1))
            .err()
            .unwrap()
            .to_string();
        assert!(
            error.contains("unsafe managed config permissions"),
            "{error}"
        );
        assert!(error.contains(&path.display().to_string()), "{error}");
        if owner_uid != 0 {
            assert!(ManagedConfig::load_from(&path, 0).is_err());
        }

        for (unsafe_path, mode, safe_mode) in [
            (path.as_path(), 0o664, 0o644),
            (path.as_path(), 0o646, 0o644),
            (directory.path(), 0o775, 0o755),
            (directory.path(), 0o757, 0o755),
        ] {
            fs::set_permissions(unsafe_path, fs::Permissions::from_mode(mode)).unwrap();
            let result = ManagedConfig::load_from(&path, owner_uid);
            fs::set_permissions(unsafe_path, fs::Permissions::from_mode(safe_mode)).unwrap();
            let error = result
                .err()
                .expect("unsafe policy must be rejected")
                .to_string();
            assert!(
                error.contains("unsafe managed config permissions"),
                "{error}"
            );
            assert!(
                error.contains(&unsafe_path.display().to_string()),
                "{error}"
            );
            assert!(error.contains("ask an administrator"), "{error}");
        }
        assert!(ManagedConfig::load_from(&path, owner_uid).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn managed_permission_inspection_errors_are_fatal() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("missing.json");
        let error = ManagedConfig::validate_permissions(&path, 0)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("failed to check managed config permissions"),
            "{error}"
        );
        assert!(error.contains(&path.display().to_string()), "{error}");
        // An absent policy remains optional; this is distinct from a failed
        // permission check on a policy that was read successfully.
        assert!(
            ManagedConfig::load_from(&path, 0)
                .unwrap()
                .overrides
                .is_empty()
        );
    }

    #[test]
    fn unknown_managed_keys_warn_without_logging_values() {
        // Tracing caches callsite interest globally. Isolate log capture from other
        // tests loading managed files before this thread installs its subscriber.
        const CHILD: &str = "MSB_TEST_MANAGED_WARNING_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "config::persistence::tests::unknown_managed_keys_warn_without_logging_values",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let policy_dir = dir.path().join("policy");
        fs::create_dir(&policy_dir).unwrap();
        let path = policy_dir.join("managed.json");
        let log = tempfile::NamedTempFile::new().unwrap();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(log.reopen().unwrap())
            .finish();

        let _subscriber = tracing::subscriber::set_default(subscriber);
        ManagedConfig::load(Some(&path)).unwrap();
        assert!(fs::read_to_string(log.path()).unwrap().is_empty());
        fs::write(&path, r#"{"overrides":{"sandbox_defaults":{"cpus":2}}}"#).unwrap();
        ManagedConfig::load(Some(&path)).unwrap();
        assert!(
            !fs::read_to_string(log.path())
                .unwrap()
                .contains("unrecognized managed config keys")
        );

        fs::write(
            &path,
            r#"{
            "future": "secret-value",
            "overrides": {
                "sandbox_defaults": {"cpus": 3, "workdir": null, "cpu_typo": 4},
                "profiles": {"prod": {"backend": "local", "future_profile": true}},
                "registries": {"hosts": {"ghcr.io": {"insecure": false, "future_host": true}}}
            }
        }"#,
        )
        .unwrap();

        let config = ManagedConfig::load(Some(&path)).unwrap();
        assert_eq!(config.overrides.sandbox_defaults.cpus, Some(3));
        assert_eq!(config.overrides.sandbox_defaults.workdir, Some(None));
        let output = fs::read_to_string(log.path()).unwrap();
        assert!(output.contains("WARN"), "{output}");
        assert!(
            output.contains("unrecognized managed config keys"),
            "{output}"
        );
        for key in [
            "future",
            "overrides.sandbox_defaults.cpu_typo",
            "overrides.profiles.prod.future_profile",
            "overrides.registries.hosts.ghcr.io.future_host",
        ] {
            assert!(output.contains(key), "missing {key}: {output}");
        }
        assert!(!output.contains("secret-value"));
        assert!(output.contains(&path.display().to_string()));
    }

    #[test]
    fn saving_discards_nested_unknown_fields_and_deleted_values() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(&path, r#"{
            "sandbox_defaults":{"cpus":2,"future_flag":true,"oci":{"future_disk":4}},
            "paths":{"future_path":"keep"},
            "profiles":{"keep":{"backend":"local","future":1},"remove":{"backend":"local","future":2}},
            "registries":{"hosts":{
                "keep":{"insecure":true,"future_host":3,"auth":{"username":"old","future_auth":4}},
                "remove":{"future_host":5}
            }}
        }"#).unwrap();
        let mut patch = GlobalConfigPatch::load_from(&path).unwrap();
        patch.sandbox_defaults.clear_cpus_mut();
        patch.get_profiles_mut().remove("remove");
        patch.registries.get_hosts_mut().remove("remove");
        patch
            .registries
            .get_hosts_mut()
            .get_mut("keep")
            .unwrap()
            .auth = Some(None);
        patch.save_to(&path).unwrap();
        let saved = GlobalConfigPatch::read_json(&path).unwrap();
        assert!(saved.get("sandbox_defaults").is_none());
        assert!(saved.get("paths").is_none());
        assert_eq!(saved["profiles"]["keep"]["backend"], "local");
        assert!(saved["profiles"]["keep"].get("future").is_none());
        assert!(saved["profiles"].get("remove").is_none());
        assert_eq!(saved["registries"]["hosts"]["keep"]["insecure"], true);
        assert!(
            saved["registries"]["hosts"]["keep"]
                .get("future_host")
                .is_none()
        );
        assert!(saved["registries"]["hosts"]["keep"]["auth"].is_null());
        assert!(saved["registries"]["hosts"].get("remove").is_none());
        // Removing the optional auth entirely also must not resurrect its unknown children.
        patch
            .registries
            .get_hosts_mut()
            .get_mut("keep")
            .unwrap()
            .auth = None;
        patch.save_to(&path).unwrap();
        assert!(
            GlobalConfigPatch::read_json(&path).unwrap()["registries"]["hosts"]["keep"]
                .get("auth")
                .is_none()
        );
    }

    #[test]
    fn saving_user_patch_keeps_defaults_absent_and_preserves_clears() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(
            &path,
            r#"{"future":{"enabled":true},"sandbox_defaults":{"workdir":null}}"#,
        )
        .unwrap();
        let mut patch = GlobalConfigPatch::load_from(&path).unwrap();
        patch.registries.get_hosts_mut().insert(
            "registry.example".into(),
            RegistryEntry {
                auth: Some(RegistryAuthEntry {
                    username: "employee".into(),
                    store: Some(RegistryCredentialStore::Keyring),
                    password_env: None,
                    secret_name: None,
                }),
                ..Default::default()
            }
            .into(),
        );
        patch.save_to(&path).unwrap();
        let saved = GlobalConfigPatch::read_json(&path).unwrap();
        assert_eq!(saved["version"], 1);
        assert!(saved.get("future").is_none());
        assert_eq!(
            saved["sandbox_defaults"],
            serde_json::json!({"workdir":null})
        );
        assert!(saved.get("home").is_none());
        assert!(saved.get("database").is_none());
        assert!(saved.get("paths").is_none());
        let loaded = GlobalConfigPatch::load_from(&path).unwrap();
        assert_eq!(loaded.sandbox_defaults.workdir, Some(None));
        assert_eq!(loaded.sandbox_defaults.cpus, None);

        patch.sandbox_defaults.clear_workdir_mut();
        patch
            .registries
            .get_hosts_mut()
            .get_mut("registry.example")
            .unwrap()
            .auth = Some(None);
        patch.save_to(&path).unwrap();
        let saved = GlobalConfigPatch::read_json(&path).unwrap();
        assert!(saved.get("sandbox_defaults").is_none());
        assert!(saved["registries"]["hosts"]["registry.example"]["auth"].is_null());
        assert!(saved.get("future").is_none());
    }

    #[test]
    fn saved_patch_uses_custom_serializers_without_filling_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        for interval in [0, 2500] {
            let expected = serde_json::json!({
                "version":1,
                "deployment_profile":"multi-tenant",
                "sandbox_defaults":{"metrics_sample_interval_ms":interval}
            });
            let patch: GlobalConfigPatch = serde_json::from_value(serde_json::json!({
                "deployment_profile":"multi_tenant",
                "sandbox_defaults":{"metrics_sample_interval_ms":interval}
            }))
            .unwrap();
            patch.save_to(&path).unwrap();
            assert_eq!(GlobalConfigPatch::read_json(&path).unwrap(), expected);
            let loaded = GlobalConfigPatch::load_from(&path).unwrap();
            assert_eq!(loaded.deployment_profile, patch.deployment_profile);
            assert_eq!(
                loaded.sandbox_defaults.metrics_sample_interval_ms,
                patch.sandbox_defaults.metrics_sample_interval_ms
            );
        }
    }

    #[test]
    fn saving_an_empty_patch_writes_only_the_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/config.json");
        GlobalConfigPatch::new().save_to(&path).unwrap();
        assert_eq!(
            GlobalConfigPatch::read_json(&path).unwrap(),
            serde_json::json!({"version":1})
        );
        assert!(GlobalConfigPatch::load_from(&path).unwrap().is_empty());
    }

    #[test]
    fn config_files_preserve_omission_null_and_ignore_unknown_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        let missing = GlobalConfigPatch::load_from(&path).unwrap();
        assert_eq!(missing.sandbox_defaults.cpus, None);
        assert_eq!(missing.sandbox_defaults.workdir, None);
        fs::write(
            &path,
            r#"{
            "version": 1,
            "future": {"unused": true},
            "sandbox_defaults": {"cpus": 3, "workdir": null, "future": true,
                "oci": {"future": true}},
            "paths": {"future": true},
            "registries": {"hosts": {"example.test": {"future": true}}}
        }"#,
        )
        .unwrap();
        let patch = GlobalConfigPatch::load_from(&path).unwrap();
        assert_eq!(patch.sandbox_defaults.cpus, Some(3));
        assert_eq!(patch.sandbox_defaults.workdir, Some(None));
        assert_eq!(patch.sandbox_defaults.shell, None);
        assert_eq!(patch.sandbox_defaults.metrics_sample_interval_ms, None);
        assert_eq!(patch.sandbox_defaults.oci.root_disk, None);
        assert_eq!(patch.paths.cache, None);
        assert_eq!(patch.log_level, None);
        assert_eq!(patch.deployment_profile, None);

        fs::write(
            &path,
            r#"{"future":true,"overrides":{"sandbox_defaults":{"cpus":3,"workdir":null,"future":true}}}"#,
        )
        .unwrap();
        let managed = ManagedConfig::load(Some(&path)).unwrap();
        assert_eq!(managed.overrides.sandbox_defaults.cpus, Some(3));
        assert_eq!(managed.overrides.sandbox_defaults.workdir, Some(None));
        assert_eq!(managed.overrides.sandbox_defaults.shell, None);
    }

    #[test]
    fn user_patch_keeps_known_field_and_version_validation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        for raw in [
            r#"{"version":2}"#,
            r#"{"version":null}"#,
            r#"{"version":"1"}"#,
            r#"{"sandbox_defaults":{"cpus":"three","unused":true}}"#,
            r#"{"sandbox_defaults":{"cpus":null}}"#,
            r#"{"sandbox_defaults":{"oci":{"root_disk":{"kind":"unknown"}}}}"#,
            r#"{"log_level":"unknown"}"#,
            "[]",
            "broken",
        ] {
            fs::write(&path, raw).unwrap();
            assert!(
                GlobalConfigPatch::load_from(&path).is_err(),
                "accepted {raw}"
            );
        }
    }

    #[cfg(feature = "local")]
    #[test]
    fn sparse_user_file_allows_image_defaults_and_explicit_clear() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        let image = microsandbox_image::ImageConfig {
            working_dir: Some("/image".into()),
            ..Default::default()
        };
        for (raw, expected) in [
            (r#"{"sandbox_defaults":{"cpus":2}}"#, Some("/image")),
            (r#"{"sandbox_defaults":{"cpus":2,"workdir":null}}"#, None),
        ] {
            fs::write(&path, raw).unwrap();
            let layers = crate::config::layers::BackendConfig::new(
                GlobalConfigPatch::load_from(&path).unwrap(),
                Default::default(),
            );
            let config = crate::sandbox::SandboxBuilder::new("from-file")
                .image("alpine")
                .finish(
                    Some(&layers),
                    Some(crate::SandboxConfigPatch::from_image(&image)),
                )
                .unwrap();
            assert_eq!(config.spec.resources.cpus, 2);
            assert_eq!(config.spec.runtime.workdir.as_deref(), expected);
        }
    }

    #[test]
    fn released_unversioned_config_loads_and_saves_with_profiles_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(
            &path,
            include_str!("../../tests/fixtures/config/v0.6.16.json"),
        )
        .unwrap();
        let patch = GlobalConfigPatch::load_from(&path).unwrap();
        let mut resolved = GlobalConfig::default();
        patch.apply_to(&mut resolved);
        assert_eq!(
            serde_json::to_value(resolved).unwrap(),
            serde_json::to_value(
                serde_json::from_value::<GlobalConfig>(
                    GlobalConfigPatch::read_json(&path).unwrap()
                )
                .unwrap()
            )
            .unwrap(),
        );
        let value = GlobalConfigPatch::read_json(&path).unwrap();
        let profiles = value["profiles"].clone();
        let mut config = GlobalConfigPatch::load_from(&path).unwrap();
        assert_eq!(config.sandbox_defaults.cpus, Some(2));
        config.save_to(&path).unwrap();
        let saved = GlobalConfigPatch::read_json(&path).unwrap();
        assert_eq!(saved["version"], 1);
        assert_eq!(saved["profiles"], profiles);
        assert_eq!(
            serde_json::from_value::<GlobalConfig>(saved)
                .unwrap()
                .active_profile
                .as_deref(),
            Some("prod")
        );

        // Saving a user patch must persist removals from the profiles map.
        config.active_profile = Some(None);
        config.get_profiles_mut().remove("prod");
        config.save_to(&path).unwrap();
        let saved = GlobalConfigPatch::read_json(&path).unwrap();
        assert!(saved["active_profile"].is_null());
        assert!(saved["profiles"].get("prod").is_none());
        assert!(saved["profiles"].get("local").is_some());
    }

    #[test]
    fn invalid_or_future_versions_are_not_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        for raw in [
            r#"{"version":2}"#,
            r#"{"version":null}"#,
            r#"{"version":"1"}"#,
            "[]",
            "broken",
        ] {
            fs::write(&path, raw).unwrap();
            assert!(GlobalConfigPatch::load_from(&path).is_err());
            assert!(GlobalConfigPatch::default().save_to(&path).is_err());
            assert_eq!(fs::read_to_string(&path).unwrap(), raw);
        }
    }

    #[test]
    fn managed_file_is_optional_but_invalid_files_fail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("managed.json");
        assert!(ManagedConfig::load(Some(&path)).is_ok());
        assert!(ManagedConfig::load(Some(dir.path())).is_err());
        for raw in [
            "{}",
            r#"{"overrides":{}}"#,
            r#"{"version":1}"#,
            r#"{"future":1}"#,
            r#"{"version":1,"overrides":{"future":1}}"#,
            r#"{"version":1,"overrides":{"database":{"future":1}}}"#,
        ] {
            fs::write(&path, raw).unwrap();
            let managed = ManagedConfig::load(Some(&path)).unwrap();
            assert_eq!(managed.version, 1);
            assert!(managed.overrides.is_empty());
        }
        for raw in [
            "",
            "{} {}",
            "{} trailing",
            "[]",
            "[1, {}]",
            r#"{"version":0}"#,
            r#"{"version":2}"#,
            r#"{"version":null}"#,
            r#"{"version":"1"}"#,
            r#"{"version":true}"#,
            r#"{"version":1.0}"#,
            r#"{"version":1,"overrides":null}"#,
            r#"{"version":1,"overrides":{"database":{"max_connections":"three"}}}"#,
            r#"{"version":1,"overrides":{"sandbox_defaults":{"cpus":null}}}"#,
            r#"{"version":1,"overrides":{"sandbox_defaults":{"outbound_proxy":{"protocol":"http","address":"127.0.0.1:1080"}}}}"#,
        ] {
            fs::write(&path, raw).unwrap();
            assert!(ManagedConfig::load(Some(&path)).is_err(), "{raw}");
        }
    }

    #[test]
    fn omitted_managed_version_uses_v1_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("managed.json");
        for raw in [
            r#"{"overrides":{"sandbox_defaults":{"cpus":2,"workdir":null}}}"#,
            r#"{"version":1,"overrides":{"sandbox_defaults":{"cpus":2,"workdir":null}}}"#,
        ] {
            fs::write(&path, raw).unwrap();
            let managed = ManagedConfig::load(Some(&path)).unwrap();
            assert_eq!(managed.version, 1);
            let mut config = GlobalConfig::default();
            config.sandbox_defaults.cpus = 4;
            config.sandbox_defaults.workdir = Some("/user".into());
            managed.overrides.apply_to(&mut config);
            assert_eq!(config.sandbox_defaults.cpus, 2);
            assert_eq!(config.sandbox_defaults.workdir, None);
        }
    }

    #[test]
    fn managed_global_fields_are_sparse_and_use_existing_value_types() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("managed.json");
        let mut config = GlobalConfig::default();
        config.paths.cache = Some("/user/cache".into());
        config.paths.volumes = Some("/user/volumes".into());
        config.sandbox_defaults.workdir = Some("/user".into());
        fs::write(&path, r#"{"version":1,"overrides":{
            "home":"/admin/home","paths":{"cache":null},"database":{"max_connections":3},
            "sandbox_defaults":{"workdir":null,"metrics_sample_interval_ms":0,"oci":{"root_disk":{"kind":"tmpfs","size_mib":2048}}},
            "runtime":{"block_writeback":{"mode":"off"}},"deployment_profile":"multi-tenant",
            "ssh":{"inactivity_timeout_secs":42},"metrics":{"capacity":128},
            "registries":{"hosts":{"example.com":{"insecure":false}}}
        }}"#).unwrap();
        let managed = ManagedConfig::load(Some(&path)).unwrap();
        managed.overrides.apply_to(&mut config);
        assert_eq!(config.home.as_deref(), Some(Path::new("/admin/home")));
        assert_eq!(config.paths.cache, None);
        assert_eq!(
            config.paths.volumes.as_deref(),
            Some(Path::new("/user/volumes"))
        );
        assert_eq!(config.database.max_connections, 3);
        assert_eq!(config.sandbox_defaults.workdir, None);
        assert_eq!(config.sandbox_defaults.metrics_sample_interval_ms, None);
        assert!(matches!(
            config.sandbox_defaults.oci.root_disk,
            Some(microsandbox_types::RootDisk::Tmpfs {
                size_mib: Some(2048)
            })
        ));
        assert_eq!(
            config.deployment_profile,
            Some(microsandbox_types::DeploymentProfile::MultiTenant)
        );
        assert_eq!(config.ssh.inactivity_timeout_secs, 42);
        assert_eq!(config.metrics.capacity, 128);
        assert!(!config.registries.hosts["example.com"].insecure);
        fs::write(&path, r#"{"version":1,"overrides":{"deployment_profile":null,"sandbox_defaults":{"metrics_sample_interval_ms":null}}}"#).unwrap();
        let clear = ManagedConfig::load(Some(&path)).unwrap();
        clear.overrides.apply_to(&mut config);
        assert_eq!(config.deployment_profile, None);
        assert_eq!(config.sandbox_defaults.metrics_sample_interval_ms, None);
    }

    #[test]
    fn profile_maps_merge_by_key_and_replace_supplied_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("managed.json");
        let mut cfg: GlobalConfig = serde_json::from_str(r#"{"active_profile":"user","profiles":{"user":{"backend":"cloud","url":"https://user.invalid","api_key_ref":"inline:user"},"keep":{"backend":"local"}}}"#).unwrap();
        fs::write(&path, r#"{"version":1,"overrides":{"active_profile":null,"profiles":{"user":{"backend":"local"}}}}"#).unwrap();
        ManagedConfig::load(Some(&path))
            .unwrap()
            .overrides
            .apply_to(&mut cfg);
        assert_eq!(cfg.active_profile, None);
        assert!(cfg.profiles.contains_key("keep"));
        assert_eq!(cfg.profiles["user"].url, None);
        assert_eq!(cfg.profiles["user"].api_key_ref, None);
        assert!(matches!(
            cfg.profiles["user"].backend,
            crate::backend::ProfileBackend::Local
        ));
    }
}

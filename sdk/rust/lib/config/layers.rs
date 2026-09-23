//! Own backend configuration sources and combine typed operation patches.

use std::{
    path::Path,
    sync::{Arc, OnceLock},
};

use super::{
    GlobalConfig, GlobalConfigPatch, OciSandboxDefaultsPatch, PathsConfigPatch,
    persistence::ManagedConfig, registry::RegistrySettingsPatch,
};
#[cfg(feature = "ssh")]
use crate::sandbox::ssh::SshTimeoutPatch;
use crate::{MicrosandboxResult, SandboxConfigPatch};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Own ordinary settings, managed policy, and the cached backend configuration.
#[derive(Clone)]
pub(crate) struct BackendConfig {
    defaults: GlobalConfigPatch,
    managed: GlobalConfigPatch,
    resolved: OnceLock<Arc<GlobalConfig>>,
}

/// Forward to each SDK patch's generated overlay implementation.
pub(crate) trait Overlay {
    fn overlay(self, higher: Self) -> Self;
}

/// Combine base, backend defaults, operation options, and managed policy.
/// Obtain this builder from `BackendConfig` so policy is included automatically.
pub(crate) struct ConfigLayers<P> {
    base: P,
    defaults: P,
    options: P,
    managed: P,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl BackendConfig {
    /// Borrow the settings captured by the sandbox's backend, independent of ambient routing.
    pub(crate) fn for_backend(backend: &dyn crate::backend::Backend) -> Option<&Self> {
        #[cfg(feature = "local")]
        if let Some(local) = backend.as_local() {
            return Some(local.config_sources());
        }
        #[cfg(feature = "cloud")]
        if let Some(cloud) = backend.as_cloud() {
            return Some(cloud.config_sources());
        }
        let _ = backend;
        None
    }

    /// Capture explicit ordinary and managed sources without reading files.
    pub(crate) fn new(defaults: GlobalConfigPatch, managed: GlobalConfigPatch) -> Self {
        Self {
            defaults,
            managed,
            resolved: OnceLock::new(),
        }
    }

    /// Read the user config (honoring `MSB_CONFIG_PATH`) and system managed config.
    pub(crate) fn load() -> MicrosandboxResult<Self> {
        Self::load_from(&super::config_path(), None)
    }

    /// Tests can supply a managed path instead of reading the machine's policy.
    pub(crate) fn load_from(path: &Path, managed_path: Option<&Path>) -> MicrosandboxResult<Self> {
        Ok(Self::new(
            GlobalConfigPatch::load_from(path)?,
            ManagedConfig::load(managed_path)?.overrides,
        ))
    }

    /// Prepare local settings once, then validate and cache the complete result.
    /// Cloud profile lookup does not prepare local runtime paths or validate local defaults.
    pub(crate) fn prepare_for_local_backend(
        mut self,
        builder: GlobalConfigPatch,
    ) -> MicrosandboxResult<Self> {
        let builtins = GlobalConfigPatch::from_present_fields(GlobalConfig::default());
        let runtime_paths = PathsConfigPatch::from_env_or_sdk();
        self.defaults = Self::compose_defaults(builtins, self.defaults, builder, runtime_paths);
        self.resolved.take();
        self.resolved_config().validate_sandbox_defaults()?;
        Ok(self)
    }

    /// Order the ordinary inputs before operation options and managed policy are applied.
    fn compose_defaults(
        builtins: GlobalConfigPatch,
        user: GlobalConfigPatch,
        builder: GlobalConfigPatch,
        runtime_paths: PathsConfigPatch,
    ) -> GlobalConfigPatch {
        builtins
            .overlay(user)
            .overlay(builder)
            .overlay(GlobalConfigPatch::new().paths(runtime_paths))
    }

    /// Borrow the complete backend settings, reusing the result for this captured set of sources.
    pub(crate) fn resolved_config(&self) -> &Arc<GlobalConfig> {
        self.resolved
            .get_or_init(|| Arc::new(self.global_layers().build().into_config()))
    }

    /// Supply the stored settings with administrator overrides already included.
    pub(crate) fn global_layers(&self) -> ConfigLayers<GlobalConfigPatch> {
        ConfigLayers::new(self.defaults.clone(), self.managed.clone())
    }

    /// Supply sandbox defaults and policy; the caller adds image metadata and request options.
    pub(crate) fn sandbox_layers(&self) -> ConfigLayers<SandboxConfigPatch> {
        ConfigLayers::new(
            SandboxConfigPatch::from_defaults(&self.defaults),
            SandboxConfigPatch::from_managed(&self.managed),
        )
    }

    /// Supply registry settings and auth policy for the requested host.
    pub(crate) fn registry_layers(&self, hostname: &str) -> ConfigLayers<RegistrySettingsPatch> {
        ConfigLayers::new(
            RegistrySettingsPatch::from_defaults(&self.defaults, hostname),
            RegistrySettingsPatch::from_managed(&self.managed, hostname),
        )
    }

    /// Include the built-in SSH timeout, saved settings, and managed overrides.
    #[cfg(feature = "ssh")]
    pub(crate) fn ssh_layers(&self) -> ConfigLayers<SshTimeoutPatch> {
        ConfigLayers::new(
            SshTimeoutPatch::from_global(&self.defaults),
            SshTimeoutPatch::from_global(&self.managed),
        )
        .base(SshTimeoutPatch::builtin())
    }

    /// Supply managed disk policy; user fallback remains at the existing rootfs stages.
    pub(crate) fn root_disk_layers(&self) -> ConfigLayers<OciSandboxDefaultsPatch> {
        ConfigLayers::new(
            OciSandboxDefaultsPatch::new(),
            OciSandboxDefaultsPatch::from_managed(&self.managed),
        )
    }
}

impl<P: Overlay + Default> ConfigLayers<P> {
    /// Only configuration factories select the ordinary and managed sources.
    fn new(defaults: P, managed: P) -> Self {
        Self {
            base: P::default(),
            defaults,
            options: P::default(),
            managed,
        }
    }

    /// Custom backends without captured device settings supply their own configuration behavior.
    pub(crate) fn unmanaged() -> Self {
        Self::new(P::default(), P::default())
    }

    /// Set the lowest-priority input, such as image metadata or a built-in timeout.
    pub(crate) fn base(mut self, base: P) -> Self {
        self.base = base;
        self
    }

    /// Set request options above backend defaults and below managed policy.
    pub(crate) fn options(mut self, options: P) -> Self {
        self.options = options;
        self
    }

    /// Return the combined patch without filling defaults or validating values.
    pub(crate) fn build(self) -> P {
        self.base
            .overlay(self.defaults)
            .overlay(self.options)
            .overlay(self.managed)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Overlay for GlobalConfigPatch {
    fn overlay(self, higher: Self) -> Self {
        self.overlay(higher)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SandboxDefaultsPatch;
    use microsandbox_types::{RootDisk, SandboxResourcesPatch, SandboxSpecPatch};

    #[test]
    fn local_preparation_validates_after_later_layers_supply_referenced_profiles() {
        let user = serde_json::from_str(r#"{"sandbox_defaults":{"placement_profile":"latency"}}"#)
            .unwrap();
        let layers = BackendConfig::new(user, Default::default());
        assert!(
            layers
                .clone()
                .prepare_for_local_backend(Default::default())
                .is_err()
        );

        let profiles = serde_json::from_str(
            r#"{
                "runtime": {
                    "placement_profiles": {
                        "latency": {
                            "numa": {"mode":"prefer_single"},
                            "memory": {"mode":"follow_cpu"}
                        }
                    }
                }
            }"#,
        )
        .unwrap();
        let layers = layers.prepare_for_local_backend(profiles).unwrap();
        assert!(layers.resolved.get().is_some());
        assert_eq!(
            layers
                .resolved_config()
                .resolve_placement_profile("latency")
                .unwrap()
                .numa,
            microsandbox_types::NumaPlacement::PreferSingle,
        );
    }

    #[test]
    fn local_preparation_validates_the_managed_result_after_explicit_clears() {
        let user = serde_json::from_str(r#"{"sandbox_defaults":{"oci":{"upper_size_mib":1024}}}"#)
            .unwrap();
        let layers = BackendConfig::new(user, serde_json::from_str(
                r#"{"sandbox_defaults":{"oci":{"root_disk":{"kind":"tmpfs"},"upper_size_mib":null}}}"#,
            )
            .unwrap());
        let layers = layers
            .prepare_for_local_backend(Default::default())
            .unwrap();
        assert_eq!(
            layers.resolved_config().sandbox_defaults.oci.upper_size_mib,
            None
        );
        assert!(matches!(
            layers.resolved_config().sandbox_defaults.oci.root_disk,
            Some(RootDisk::Tmpfs { .. }),
        ));
    }

    #[test]
    fn local_preparation_rejects_invalid_final_defaults_before_creating_files() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("not-created");
        let persisted = GlobalConfig {
            home: Some(home.clone()),
            ..Default::default()
        };
        let managed = serde_json::from_str(
            r#"{
            "sandbox_defaults":{"oci":{"root_disk":{"kind":"tmpfs"},"upper_size_mib":1024}}
        }"#,
        )
        .unwrap();
        let layers = BackendConfig::new(persisted.into(), managed);
        let result = layers.prepare_for_local_backend(Default::default());
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("mutually exclusive")
        );
        assert!(!home.exists());
    }

    #[test]
    fn config_cache_tracks_layer_changes_and_preserves_existing_handles() {
        let user =
            serde_json::from_str(r#"{"sandbox_defaults":{"cpus":2,"memory_mib":256}}"#).unwrap();
        let managed = serde_json::from_str(r#"{"sandbox_defaults":{"cpus":8}}"#).unwrap();
        let mut layers = BackendConfig::new(user, managed);
        let original = layers.resolved_config().clone();
        assert!(Arc::ptr_eq(&original, layers.resolved_config()));
        assert_eq!(original.sandbox_defaults.cpus, 8);

        layers = layers
            .prepare_for_local_backend(
                serde_json::from_str(r#"{"sandbox_defaults":{"cpus":4,"memory_mib":512}}"#)
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(layers.resolved_config().sandbox_defaults.cpus, 8);
        assert_eq!(layers.resolved_config().sandbox_defaults.memory_mib, 512);
        assert_eq!(original.sandbox_defaults.memory_mib, 256);

        let mut replacement = BackendConfig::new(
            layers.defaults.clone(),
            serde_json::from_str(r#"{"sandbox_defaults":{"cpus":16}}"#).unwrap(),
        );
        assert_eq!(replacement.resolved_config().sandbox_defaults.cpus, 16);
        replacement = replacement
            .prepare_for_local_backend(
                serde_json::from_str(r#"{"sandbox_defaults":{"memory_mib":1024}}"#).unwrap(),
            )
            .unwrap();
        assert_eq!(
            replacement.resolved_config().sandbox_defaults.memory_mib,
            1024
        );
        assert_eq!(layers.resolved_config().sandbox_defaults.cpus, 8);
        assert_eq!(layers.resolved_config().sandbox_defaults.memory_mib, 512);
    }

    #[test]
    fn operation_options_preserve_managed_precedence_and_cached_config() {
        let user =
            serde_json::from_str(r#"{"sandbox_defaults":{"cpus":2,"memory_mib":256}}"#).unwrap();
        let managed = serde_json::from_str(r#"{"sandbox_defaults":{"memory_mib":512}}"#).unwrap();
        let layers = BackendConfig::new(user, managed);
        let cached = layers.resolved_config().clone();
        let options = SandboxConfigPatch::new().spec(
            SandboxSpecPatch::new()
                .resources(SandboxResourcesPatch::new().cpus(4).memory_mib(1024)),
        );
        let sandbox = layers
            .sandbox_layers()
            .base(Default::default())
            .options(options)
            .build()
            .into_config();
        assert_eq!(sandbox.spec.resources.cpus, 4);
        assert_eq!(sandbox.spec.resources.memory_mib, 512);
        assert_eq!(layers.resolved_config().sandbox_defaults.cpus, 2);
        assert_eq!(layers.resolved_config().sandbox_defaults.memory_mib, 512);
        assert!(Arc::ptr_eq(&cached, layers.resolved_config()));
    }

    #[cfg(feature = "local")]
    #[test]
    fn runtime_paths_are_captured_once_below_managed_overrides() {
        let _guard = crate::test_support::lock_env();
        let previous = ["MSB_PATH", "MSB_LIBKRUNFW_PATH", "MSB_AGENTD_PATH"]
            .map(|name| (name, std::env::var_os(name)));
        let _restore = scopeguard::guard(previous, |previous| {
            for (name, value) in previous {
                // SAFETY: the shared lock remains held through restoration.
                unsafe {
                    match value {
                        Some(value) => std::env::set_var(name, value),
                        None => std::env::remove_var(name),
                    }
                }
            }
        });
        let directory = tempfile::tempdir().unwrap();
        let environment = directory.path().join("environment");
        let administrator = directory.path().join("administrator");
        for directory in [&environment, &administrator] {
            std::fs::create_dir(directory).unwrap();
            std::fs::write(directory.join("msb"), b"fixture").unwrap();
            std::fs::write(
                directory.join(microsandbox_utils::libkrunfw_filename(std::env::consts::OS)),
                b"fixture",
            )
            .unwrap();
        }
        // SAFETY: environment-mutating tests hold the shared lock.
        unsafe {
            std::env::set_var("MSB_PATH", environment.join("msb"));
            std::env::remove_var("MSB_LIBKRUNFW_PATH");
            std::env::set_var("MSB_AGENTD_PATH", "environment-agentd");
        }
        let ordinary = BackendConfig::new(Default::default(), Default::default())
            .prepare_for_local_backend(Default::default())
            .unwrap();
        let managed = serde_json::from_value(serde_json::json!({"paths": {
            "msb": administrator.join("msb"), "libkrunfw": null, "agentd": null
        }}))
        .unwrap();
        let enforced = BackendConfig::new(Default::default(), managed)
            .prepare_for_local_backend(Default::default())
            .unwrap();
        // Changing ambient paths after construction cannot bypass the captured policy.
        unsafe {
            std::env::set_var("MSB_PATH", "changed-msb");
            std::env::set_var("MSB_AGENTD_PATH", "changed-agentd");
        }
        assert_eq!(
            ordinary.resolved_config().resolve_msb_path().unwrap(),
            environment.join("msb")
        );
        assert_eq!(
            enforced.resolved_config().resolve_msb_path().unwrap(),
            administrator.join("msb")
        );
        assert_eq!(
            enforced
                .resolved_config()
                .resolve_libkrunfw_path()
                .unwrap()
                .canonicalize()
                .unwrap(),
            administrator
                .join(microsandbox_utils::libkrunfw_filename(std::env::consts::OS))
                .canonicalize()
                .unwrap()
        );
        assert_eq!(enforced.resolved_config().paths.libkrunfw, None);
        assert_eq!(
            ordinary.resolved_config().paths.agentd.as_deref(),
            Some(Path::new("environment-agentd"))
        );
        assert_eq!(enforced.resolved_config().paths.agentd, None);
    }

    #[test]
    fn ordinary_inputs_keep_their_precedence_and_omission() {
        let _guard = crate::test_support::lock_env();
        let previous = std::env::var_os("MSB_PATH");
        // SAFETY: environment-mutating tests hold the shared lock.
        unsafe { std::env::remove_var("MSB_PATH") };
        for (user, builder, cpus, path) in [
            (r#"{}"#, r#"{}"#, super::super::DEFAULT_CPUS, None),
            (
                r#"{"sandbox_defaults":{"cpus":2},"paths":{"msb":"user"}}"#,
                r#"{}"#,
                2,
                Some("user"),
            ),
            (
                r#"{"sandbox_defaults":{"cpus":2},"paths":{"msb":"user"}}"#,
                r#"{"sandbox_defaults":{"cpus":4},"paths":{"msb":"builder"}}"#,
                4,
                Some("builder"),
            ),
            (
                r#"{"paths":{"msb":"user"}}"#,
                r#"{"paths":{"msb":null}}"#,
                super::super::DEFAULT_CPUS,
                None,
            ),
        ] {
            let layers =
                BackendConfig::new(serde_json::from_str(user).unwrap(), Default::default());
            let layers = layers
                .prepare_for_local_backend(serde_json::from_str(builder).unwrap())
                .unwrap();
            assert_eq!(layers.resolved_config().sandbox_defaults.cpus, cpus);
            assert_eq!(
                layers.resolved_config().paths.msb.as_deref(),
                path.map(std::path::Path::new)
            );
            // Built-in None must stay omitted so image workdir can be inherited.
            assert_eq!(layers.defaults.sandbox_defaults.workdir, None);
        }
        unsafe {
            match previous {
                Some(value) => std::env::set_var("MSB_PATH", value),
                None => std::env::remove_var("MSB_PATH"),
            }
        }
    }

    #[test]
    fn runtime_paths_prefer_environment_to_sdk_in_an_isolated_process() {
        const CHILD: &str = "MSB_LAYERING_PATH_TEST";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("runtime_paths_prefer_environment_to_sdk_in_an_isolated_process")
                .arg("--nocapture")
                .env(CHILD, "1")
                .env_remove("MSB_PATH")
                .env_remove("MSB_LIBKRUNFW_PATH")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let _guard = crate::test_support::lock_env();
        let dir = tempfile::tempdir().unwrap();
        let firmware = dir.path().join("sdk-firmware");
        std::fs::write(&firmware, b"fixture").unwrap();
        crate::config::set_sdk_msb_path("sdk-msb");
        crate::config::set_sdk_libkrunfw_path(&firmware);
        let user = || {
            serde_json::from_str(r#"{"paths":{"msb":"user-msb","libkrunfw":"user-firmware"}}"#)
                .unwrap()
        };
        let sdk = BackendConfig::new(user(), Default::default())
            .prepare_for_local_backend(Default::default())
            .unwrap();
        assert_eq!(
            sdk.resolved_config().paths.msb.as_deref(),
            Some(Path::new("sdk-msb"))
        );
        assert_eq!(
            sdk.resolved_config().paths.libkrunfw.as_deref(),
            Some(firmware.as_path())
        );
        // SAFETY: this isolated test process holds the environment lock.
        unsafe {
            std::env::set_var("MSB_PATH", "env-msb");
            std::env::set_var("MSB_LIBKRUNFW_PATH", "env-firmware");
        }
        let env = BackendConfig::new(user(), Default::default())
            .prepare_for_local_backend(Default::default())
            .unwrap();
        let managed = BackendConfig::new(
            user(),
            serde_json::from_str(r#"{"paths":{"msb":"admin-msb","libkrunfw":null}}"#).unwrap(),
        )
        .prepare_for_local_backend(Default::default())
        .unwrap();
        assert_eq!(
            env.resolved_config().paths.msb.as_deref(),
            Some(Path::new("env-msb"))
        );
        assert_eq!(
            env.resolved_config().paths.libkrunfw.as_deref(),
            Some(Path::new("env-firmware"))
        );
        assert_eq!(
            managed.resolved_config().paths.msb.as_deref(),
            Some(Path::new("admin-msb"))
        );
        assert_eq!(managed.resolved_config().paths.libkrunfw, None);
        assert_eq!(
            sdk.resolved_config().paths.msb.as_deref(),
            Some(Path::new("sdk-msb"))
        );
    }

    #[test]
    fn named_slots_keep_precedence_regardless_of_setter_order() {
        let cpus = |value| {
            let mut patch = GlobalConfigPatch::new();
            if let Some(value) = value {
                patch.sandbox_defaults = SandboxDefaultsPatch::new().cpus(value);
            }
            patch
        };
        for (defaults, options, managed, expected) in [
            (None, None, None, 1),
            (Some(2), None, None, 2),
            (Some(2), Some(3), None, 3),
            (Some(2), Some(3), Some(4), 4),
        ] {
            let backend = BackendConfig::new(cpus(defaults), cpus(managed));
            let forward = backend
                .global_layers()
                .base(cpus(Some(1)))
                .options(cpus(options))
                .build();
            let reverse = backend
                .global_layers()
                .options(cpus(options))
                .base(cpus(Some(1)))
                .build();
            assert_eq!(forward.sandbox_defaults.cpus, Some(expected));
            assert_eq!(reverse.sandbox_defaults.cpus, Some(expected));
        }
    }

    #[test]
    fn combined_patch_retains_clears_and_collection_replacement() {
        use crate::config::{GlobalConfig, RegistriesConfigPatch, RegistryEntryPatch};
        use std::collections::HashMap;

        let user = GlobalConfigPatch::new()
            .sandbox_defaults(SandboxDefaultsPatch::new().workdir("/user".into()));
        let managed = GlobalConfigPatch::new()
            .sandbox_defaults(SandboxDefaultsPatch::new().set_workdir(None))
            .registries(RegistriesConfigPatch::new().replace_hosts(HashMap::from([(
                "admin.example".into(),
                RegistryEntryPatch::new().insecure(false),
            )])));
        let backend = BackendConfig::new(user, managed);
        let combined = backend.global_layers().build();
        assert_eq!(combined.sandbox_defaults.workdir, Some(None));

        // Applying the combined patch later must still remove earlier map entries.
        let mut earlier: GlobalConfig = serde_json::from_str(
            r#"{
            "registries":{"hosts":{"old.example":{"insecure":true}}},
            "sandbox_defaults":{"workdir":"/earlier"}
        }"#,
        )
        .unwrap();
        combined.apply_to(&mut earlier);
        assert_eq!(earlier.sandbox_defaults.workdir, None);
        assert_eq!(earlier.registries.hosts.len(), 1);
        assert!(!earlier.registries.hosts["admin.example"].insecure);
    }
}

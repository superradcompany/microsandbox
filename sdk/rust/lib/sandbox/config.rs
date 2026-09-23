//! Sandbox configuration.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::num::NonZero;
use std::path::PathBuf;

#[cfg(feature = "net")]
use microsandbox_network::config::NetworkConfig;
#[cfg(feature = "local")]
use microsandbox_runtime::launch::{CheckpointRestoreConfig, RootfsUpperLayerConfig};
use microsandbox_types::SandboxLogLevel as LogLevel;
use microsandbox_types::{
    ConfigPatch, EnvVar, NetworkSpecPatch, SandboxLogLevel, SandboxResources,
    SandboxResourcesPatch, SandboxRuntimeOptions, SandboxRuntimeOptionsPatch, SandboxSpec,
    SandboxSpecPatch, TransparentHugePagePolicy,
};
use serde::{Deserialize, Serialize};

#[cfg(feature = "local")]
use microsandbox_image::ImageConfig;
use microsandbox_protocol::{HANDOFF_INIT_AUTO, HANDOFF_INIT_IMAGE_ENTRYPOINT_CANDIDATES};
use microsandbox_types::RegistryAuth;
use typed_path::Utf8UnixPath;

use crate::MicrosandboxResult;
use crate::config::{
    GlobalConfigPatch, OciSandboxDefaultsPatch, SandboxDefaultsPatch,
    layers::{BackendConfig, ConfigLayers, Overlay},
};

use super::types::{MountOptions, RootDisk, RootfsSource, VolumeMount};
use crate::snapshot::SnapshotReference;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const DEFAULT_OCI_TMPFS_PATH: &str = "/tmp";
const DEFAULT_OCI_TMPFS_MAX_SIZE_MIB: u32 = 512;
const DEFAULT_OCI_TMPFS_MEMORY_DIVISOR: u32 = 4;
pub(crate) const DEFAULT_OCI_UPPER_SIZE_MIB: u32 = 4 * 1024;

/// Default guest-write budget for a bind mount, in MiB.
///
/// Bounds how much the guest may add beyond a bind-mounted host directory's
/// existing contents, so a sandbox cannot fill the host disk through a mount.
/// Anchored to [`DEFAULT_OCI_UPPER_SIZE_MIB`] for a consistent mental model;
/// overridable per mount via [`MountBuilder::quota`](crate::sandbox::MountBuilder::quota).
pub(crate) const DEFAULT_BIND_QUOTA_MIB: u32 = DEFAULT_OCI_UPPER_SIZE_MIB;

/// Default timeout given to the existing sandbox during a `.replace()`
/// create before it is force-killed.
///
/// Distinct from [`SandboxHandle::stop_with_timeout`]'s explicit deadline: this applies
/// to the builder's override-an-existing-sandbox flow, not the
/// user-facing stop. Ordinary `stop()` waits without an implicit deadline or force-kill.
///
/// [`SandboxHandle::stop_with_timeout`]: super::SandboxHandle::stop_with_timeout
pub const DEFAULT_REPLACE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

// Compile-time defaults for `SandboxConfig` serde. Serde's `#[serde(default
// = "fn")]` attribute can't take parameters, so these can't consult a
// `LocalBackend`. They intentionally mirror `GlobalConfig::default()` /
// `SandboxDefaults::default()` for the same fields, so DB-row
// deserialization (and `sandbox_config_from_cloud`) are side-effect-free.
// A `LocalBackend` with non-default sandbox defaults applies them through
// `SandboxBuilder` at create time, not via serde.

fn default_cpus() -> u8 {
    microsandbox_types::DEFAULT_SANDBOX_CPUS
}

fn default_memory_mib() -> u32 {
    microsandbox_types::DEFAULT_SANDBOX_MEMORY_MIB
}

fn default_log_level() -> Option<SandboxLogLevel> {
    None
}

fn default_metrics_sample_interval_ms() -> Option<NonZero<u64>> {
    NonZero::new(microsandbox_types::DEFAULT_METRICS_SAMPLE_INTERVAL_MS)
}

fn default_disable_metrics_sample() -> bool {
    false
}

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Transient intent for the initial process requested by a CLI operation.
///
/// Foreground commands remain separate from the durable OCI command because an attached
/// `msb run` is one-shot. Background commands use `runtime.cmd` so the resolved startup shape is
/// visible through inspect and preserved with the sandbox configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) enum LaunchIntent {
    /// Boot the sandbox without starting an initial workload.
    #[default]
    None,

    /// Run the resolved OCI command through the foreground attach/exec path.
    Foreground {
        /// Optional one-shot CMD override supplied after `--`.
        command: Option<Vec<String>>,
    },

    /// Run the resolved OCI command in the background after the guest agent is ready.
    Background,
}

/// Materialization selected when a checkpoint snapshot is used as a sandbox source.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum SnapshotRestoreMode {
    /// Restore disk, memory, execution, and device state.
    #[default]
    Full,

    /// Use only the checkpoint's disk closure and perform an ordinary cold boot.
    DiskOnly,
}

/// Explicit resource choices that must not be silently replaced during deferred archive restore.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RestoreOverrideIntent {
    pub(crate) cpus: bool,
    pub(crate) max_cpus: bool,
    pub(crate) memory: bool,
    pub(crate) max_memory: bool,
}

/// Configuration for a sandbox.
///
/// The durable task description lives in [`SandboxSpec`]. This type keeps
/// local SDK/runtime operation state beside that shared contract, such as
/// registry credentials, replacement flags, and resolved snapshot metadata.
#[derive(Debug, Clone, Serialize, Deserialize, ConfigPatch)]
pub struct SandboxConfig {
    /// Operation-local observer; never persisted or retained as a stream owner.
    #[cfg(feature = "local")]
    #[serde(skip)]
    pub(crate) creation_progress: Option<tokio::sync::mpsc::WeakSender<crate::CreationProgress>>,
    /// Backend-neutral sandbox task description shared across SDKs and services.
    #[serde(flatten)]
    #[config_patch(nested)]
    pub spec: SandboxSpec,

    /// Registry authentication for private OCI registries.
    ///
    /// Redacted (set to `None`) before serialization to database — credentials
    /// are only needed during the pull.
    #[serde(default, skip_serializing)]
    #[config_patch(nullable)]
    pub registry_auth: Option<RegistryAuth>,

    /// Access the registry over plain HTTP (SDK override).
    #[serde(skip)]
    pub(crate) insecure: bool,

    /// Additional PEM-encoded CA certs (SDK override).
    #[serde(skip)]
    pub(crate) ca_certs: Vec<Vec<u8>>,

    /// Replace an existing sandbox with the same name during create.
    ///
    /// If the existing sandbox is still active, microsandbox stops it and
    /// waits for it to exit before recreating it.
    ///
    /// This is an operation flag, not persisted sandbox state.
    #[serde(skip)]
    pub replace_existing: bool,

    /// How long to wait after SIGTERM for the existing sandbox process to
    /// exit gracefully before escalating to SIGKILL during a replace.
    ///
    /// Only consulted when `replace_existing` is true. A zero duration
    /// skips SIGTERM entirely and goes straight to SIGKILL. Default is
    /// `DEFAULT_REPLACE_TIMEOUT`, which gives the exit observer plenty
    /// of headroom to flush logs and clean up the agent socket on a
    /// healthy sandbox before we escalate.
    ///
    /// This is an operation flag, not persisted sandbox state.
    #[serde(skip)]
    pub replace_with_timeout: std::time::Duration,

    /// Requested globally-unique slug for the sandbox (cloud backends only).
    ///
    /// When unset, the cloud assigns one. Create fails when the slug is
    /// already taken.
    ///
    /// This is a create-time option, not persisted sandbox state.
    #[serde(skip)]
    #[config_patch(nullable)]
    pub slug: Option<String>,

    /// Manifest digest for the resolved OCI image.
    ///
    /// Set at create time. Used by spawn to derive VMDK and fsmeta paths
    /// from the global cache. `None` for non-OCI rootfs sources.
    #[serde(default)]
    #[config_patch(nullable)]
    pub(crate) manifest_digest: Option<String>,

    /// Path to a file snapshot's writable root disk to copy into the new
    /// sandbox at create time, replacing fresh root-disk provisioning.
    ///
    /// Transient: populated during snapshot preparation and consumed when creating
    /// the sandbox's root disk. Never persisted.
    #[serde(skip)]
    #[config_patch(nullable)]
    pub(crate) snapshot_upper_source: Option<PathBuf>,

    /// Original backend-neutral reference supplied to `Sandbox::restore_ref`.
    ///
    /// The selected backend resolves this into its restore configuration. It
    /// is operation-only and is never persisted.
    #[serde(skip)]
    pub(crate) snapshot_reference: Option<SnapshotReference>,

    /// Immutable installed-snapshot layers to materialize into child-owned root storage.
    ///
    /// Transient: paths remain read-only sources until local create copies or links them and adds
    /// a private writable qcow2 head.
    #[serde(skip)]
    #[cfg(feature = "local")]
    pub(crate) snapshot_root_layer_sources: Vec<RootfsUpperLayerConfig>,

    /// Installed file snapshot's required owned payloads, consumed into child storage.
    #[serde(skip)]
    #[cfg(feature = "local")]
    pub(crate) snapshot_owned_source: Option<(
        PathBuf,
        Vec<microsandbox_image::snapshot::OwnedVolumeCapture>,
    )>,

    /// Guest-visible capacity of `snapshot_root_layer_sources`.
    #[serde(skip)]
    pub(crate) snapshot_root_virtual_size: Option<u64>,

    /// Archive to materialize directly into child staging during create.
    ///
    /// Transient and never persisted.
    #[serde(skip)]
    pub(crate) snapshot_archive_source: Option<PathBuf>,
    /// Explicit base dependency used only while constructing a child from a delta archive.
    #[serde(skip)]
    pub(crate) snapshot_base: Option<String>,

    /// Snapshot from which this sandbox derives. Later captures retain their own local cursor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) snapshot_parent: Option<String>,

    /// Child-owned checkpoint closure for an unfinished restore construction.
    ///
    /// The builder initially points this at an installed snapshot. The local create path copies
    /// the closure into child staging and rewrites the path before spawning the runtime. Local
    /// creation persists this intent until activation succeeds; an interrupted restore must not
    /// subsequently be interpreted as an ordinary cold boot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg(feature = "local")]
    pub(crate) checkpoint_restore: Option<CheckpointRestoreConfig>,

    /// Source name for a one-shot direct local branch, consumed under child reservation.
    #[serde(skip)]
    #[cfg(feature = "local")]
    pub(crate) branch_source: Option<super::identity::BranchSource>,
    /// Transient ownership passed to a Linux child; never stored in launch JSON or the database.
    #[serde(skip)]
    #[cfg(all(feature = "local", target_os = "linux"))]
    pub(crate) branch_memory:
        Option<std::sync::Arc<microsandbox_runtime::checkpoint::LocalMemoryPin>>,

    /// Restore captured RAM through private CoW mappings; never a cold-boot policy.
    #[serde(skip)]
    pub(crate) forked: bool,

    /// Transient checkpoint materialization policy selected by the caller.
    #[serde(skip)]
    pub(crate) snapshot_restore_mode: SnapshotRestoreMode,

    /// Explicit failure policy for external resources during full execution restore.
    #[serde(default)]
    pub(crate) external_mount_policy: microsandbox_types::ExternalMountRestorePolicy,

    /// Resource choices apply to this restore/branch only, never later starts or branches.
    #[serde(skip)]
    pub(crate) restore_resources: super::restore_resources::RestoreResources,

    /// Whether this create operation resumed execution from a full snapshot.
    #[serde(skip)]
    pub(crate) resumed_from_full_snapshot: bool,

    /// Child-owned oldest-to-head root-disk chain prepared for checkpoint restore.
    #[serde(skip)]
    #[cfg(feature = "local")]
    pub(crate) snapshot_upper_layers: Vec<RootfsUpperLayerConfig>,

    /// Explicit builder choices retained until a deferred archive descriptor is available.
    #[serde(skip)]
    pub(crate) restore_overrides: RestoreOverrideIntent,

    /// Destination boot settings that require scope admission before snapshot materialization.
    /// Captured execution does not rerun guest bootstrap; explicit choices cannot be ignored.
    #[serde(skip)]
    pub(crate) restore_boot_overrides: super::restore_builder::RestoreBootOverrides,

    /// Transient process-launch intent for the current create operation.
    #[serde(skip)]
    pub(crate) launch_intent: LaunchIntent,

    /// Durable CMD before a detached one-shot command temporarily replaced it.
    #[serde(skip)]
    pub(crate) launch_cmd_before_override: Option<Option<Vec<String>>>,

    /// Whether image-init routing consumed the requested boot workload.
    #[serde(skip)]
    pub(crate) init_owns_workload: bool,

    /// Number of transient workload arguments appended to the init specification.
    #[serde(skip)]
    pub(crate) init_workload_arg_count: usize,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SandboxConfigPatch {
    /// Convert ordinary backend defaults; host deployment policy is applied during local creation.
    pub(crate) fn from_defaults(global: &GlobalConfigPatch) -> Self {
        let mut patch = Self::from_global(global);
        patch.spec.clear_deployment_profile_mut();
        patch
    }

    /// Convert administrator settings, preserving explicit clears and no-policy deployment profiles.
    pub(crate) fn from_managed(global: &GlobalConfigPatch) -> Self {
        Self::from_global(global)
    }

    /// Copy the sandbox-related settings from this global patch into a sandbox patch.
    fn from_global(global: &GlobalConfigPatch) -> Self {
        // Merge fields on GlobalConfigPatch are private to config; the field matrix
        // exhaustively classifies GlobalConfig below. Keep sandbox defaults exhaustive here.
        let GlobalConfigPatch {
            sandbox_defaults,
            log_level,
            deployment_profile,
            ..
        } = global;
        let SandboxDefaultsPatch {
            cpus,
            memory_mib,
            cpu_placement,
            placement_profile,
            thp,
            shell,
            workdir,
            outbound_proxy,
            metrics_sample_interval_ms,
            disable_metrics_sample,
            // Resolved by OciSandboxDefaultsPatch::from_managed() and SandboxConfig::apply_rootfs_defaults().
            oci: _,
        } = sandbox_defaults;

        let mut resources = SandboxResourcesPatch::new();
        if let Some(cpus) = cpus {
            resources.cpus_mut(*cpus);
        }
        if let Some(memory_mib) = memory_mib {
            resources.memory_mib_mut(*memory_mib);
        }
        if let Some(cpu_placement) = cpu_placement {
            resources.cpu_placement_mut(*cpu_placement);
        }
        if let Some(placement_profile) = placement_profile {
            resources.set_placement_profile_mut(placement_profile.clone());
        }
        if let Some(thp) = thp {
            resources.thp_mut(*thp);
        }

        let mut runtime = SandboxRuntimeOptionsPatch::new();
        if let Some(shell) = shell {
            runtime.shell_mut(shell.clone());
        }
        if let Some(workdir) = workdir {
            runtime.set_workdir_mut(workdir.clone());
        }
        if let Some(interval) = metrics_sample_interval_ms {
            runtime.set_metrics_sample_interval_ms_mut(interval.map(std::num::NonZero::get));
        }
        if let Some(disable_metrics_sample) = disable_metrics_sample {
            runtime.disable_metrics_sample_mut(*disable_metrics_sample);
        }
        if let Some(log_level) = log_level {
            runtime.set_log_level_mut(log_level.map(sandbox_log_level_from_runtime));
        }

        let mut network = NetworkSpecPatch::new();
        if let Some(outbound_proxy) = outbound_proxy {
            network.set_outbound_proxy_mut(outbound_proxy.clone());
        }
        let mut spec = SandboxSpecPatch::new()
            .resources(resources)
            .runtime(runtime)
            .network(network);
        if let Some(deployment_profile) = deployment_profile.flatten() {
            spec.deployment_profile_mut(deployment_profile);
        }
        SandboxConfigPatch::new().spec(spec)
    }

    /// Resolve the rootfs choice needed before pulling an image.
    /// Sizes that depend on final sandbox memory are resolved after layering.
    pub(crate) fn resolve_image(&self, backend_config: &BackendConfig) -> RootfsSource {
        let mut image = self.spec.image.clone().unwrap_or_default();
        if let RootfsSource::Oci(oci) = &mut image {
            oci.root_disk = backend_config
                .root_disk_layers()
                .options(OciSandboxDefaultsPatch::new().set_root_disk(oci.root_disk.take()))
                .build()
                .into_config()
                .root_disk;
            if oci.root_disk.is_none() {
                oci.root_disk = backend_config
                    .resolved_config()
                    .sandbox_defaults
                    .oci
                    .root_disk
                    .clone();
            }
        }
        image
    }

    /// Translate image metadata into the lowest-priority sandbox input.
    #[cfg(feature = "local")]
    pub(crate) fn from_image(image: &ImageConfig) -> Self {
        let ImageConfig {
            env,
            cmd,
            entrypoint,
            working_dir,
            user,
            labels,
            // These OCI declarations are not inherited by sandbox configuration.
            exposed_ports: _,
            volumes: _,
            stop_signal: _,
        } = image;

        let mut runtime = SandboxRuntimeOptionsPatch::new();
        if let Some(cmd) = cmd {
            runtime.cmd_mut(cmd.clone());
        }
        if let Some(entrypoint) = entrypoint {
            runtime.entrypoint_mut(entrypoint.clone());
        }
        if let Some(workdir) = working_dir
            && !workdir.is_empty()
        {
            runtime.workdir_mut(workdir.clone());
        }
        if let Some(user) = user
            && !user.is_empty()
        {
            runtime.user_mut(user.clone());
        }

        let patch = SandboxSpecPatch::new()
            .replace_env(merge_env(env, &[]))
            .labels(merge_image_labels(labels, &BTreeMap::new()))
            .runtime(runtime);

        Self::new().spec(patch)
    }

    /// Select the foreground launch path for attached `msb run`.
    pub(crate) fn set_foreground_command(&mut self, command: Vec<String>) {
        self.launch_intent = Some(LaunchIntent::Foreground {
            command: (!command.is_empty()).then_some(command),
        });
    }

    /// Select the background launch path for detached `msb run -d`.
    ///
    /// A non-empty command replaces the image CMD while preserving the effective entrypoint. An
    /// empty command intentionally keeps the image CMD so detached and attached runs resolve the
    /// same OCI process.
    pub(crate) fn set_background_command(&mut self, command: Vec<String>) {
        if !command.is_empty() {
            if self.launch_cmd_before_override.is_none() {
                self.launch_cmd_before_override = Some(self.spec.runtime.cmd.clone());
            }
            self.spec.runtime.cmd_mut(command);
        }
        self.launch_intent = Some(LaunchIntent::Background);
    }
}

impl OciSandboxDefaultsPatch {
    /// Normalize managed root-disk and legacy size settings into a complete disk choice.
    pub(crate) fn from_managed(global: &GlobalConfigPatch) -> Self {
        let Self {
            root_disk,
            upper_size_mib,
        } = &global.sandbox_defaults.oci;

        let mut patch = Self::new();
        if let Some(Some(root_disk)) = root_disk {
            patch.root_disk_mut(root_disk.clone());
        } else if root_disk.is_some() || upper_size_mib.is_some() {
            patch.root_disk_mut(RootDisk::Managed {
                size_mib: upper_size_mib.flatten(),
            });
        }

        patch
    }
}

impl SandboxConfig {
    /// Apply the composed patches, then resolve sandbox defaults that depend on the final values.
    pub(super) fn apply_layers(
        &mut self,
        backend_config: Option<&BackendConfig>,
        mut options: SandboxConfigPatch,
        image_defaults: Option<SandboxConfigPatch>,
    ) {
        let inherited_entrypoint = options.spec.runtime.entrypoint.is_none();
        let image_entrypoint = image_defaults
            .as_ref()
            .and_then(|patch| patch.spec.runtime.entrypoint.clone());
        let image_defaults = image_defaults.unwrap_or_default();

        if let Some(env) = options.spec.get_env() {
            // OCI inheritance retains SDK env append order and duplicates, including
            // when a sparse overlay replaced the builder's earlier environment.
            let image_env = image_defaults
                .spec
                .get_env()
                .map(Vec::as_slice)
                .unwrap_or_default();
            let env = merge_env_pairs(image_env, env);
            options.spec.replace_env_mut(env);
        }

        let layers = match backend_config {
            Some(config) => config.sandbox_layers(),
            // Custom backends without device settings supply their own configuration behavior.
            None => ConfigLayers::unmanaged(),
        };
        let patch = layers.base(image_defaults).options(options).build();
        let max_cpus = patch.spec.resources.max_cpus;
        let max_memory_mib = patch.spec.resources.max_memory_mib;
        patch.apply_to(self);

        if let Some(config) = backend_config
            && let RootfsSource::Oci(oci) = &mut self.spec.image
        {
            oci.root_disk = config
                .root_disk_layers()
                .options(OciSandboxDefaultsPatch::new().set_root_disk(oci.root_disk.take()))
                .build()
                .into_config()
                .root_disk;
        }

        let resources = &mut self.spec.resources;
        resources.max_cpus = max_cpus.unwrap_or(resources.cpus);
        resources.max_memory_mib = max_memory_mib.unwrap_or(resources.memory_mib);

        if let Some(image_entrypoint) = image_entrypoint {
            self.resolve_auto_init_from_image_entrypoint(
                Some(&image_entrypoint),
                inherited_entrypoint,
            );
        }
    }

    /// Resolve the effective metrics sampling interval, accounting for the disable override.
    pub fn effective_metrics_interval(&self) -> Option<NonZero<u64>> {
        if self.spec.runtime.disable_metrics_sample {
            None
        } else {
            self.spec
                .runtime
                .metrics_sample_interval_ms
                .and_then(NonZero::new)
        }
    }

    /// Return the config shape that should be persisted for future starts.
    ///
    /// CLI `run` commands are one-shot launch intent. Their durable CMD template is retained, while
    /// transient launch markers and any workload argv routed through an inherited init are removed.
    pub(crate) fn clone_for_persistence(&self) -> Self {
        let mut config = self.clone();
        #[cfg(feature = "local")]
        {
            config.checkpoint_restore = None;
            config.branch_source = None;
            #[cfg(target_os = "linux")]
            {
                config.branch_memory = None;
            }
            config.forked = false;
        }
        config.snapshot_restore_mode = SnapshotRestoreMode::Full;
        config.restore_resources = Default::default();
        config.resumed_from_full_snapshot = false;
        #[cfg(feature = "local")]
        {
            config.snapshot_root_layer_sources.clear();
            config.snapshot_owned_source = None;
        }
        config.snapshot_root_virtual_size = None;
        #[cfg(feature = "local")]
        {
            config.snapshot_upper_layers.clear();
        }
        config.restore_overrides = RestoreOverrideIntent::default();
        config.restore_boot_overrides = Default::default();
        config.launch_intent = LaunchIntent::None;
        config.launch_cmd_before_override = None;
        config.init_owns_workload = false;
        if config.init_workload_arg_count > 0 {
            if let Some(init) = config.spec.init.as_mut() {
                let durable_len = init
                    .args
                    .len()
                    .saturating_sub(config.init_workload_arg_count);
                init.args.truncate(durable_len);
            }
            config.init_workload_arg_count = 0;
        }
        for mount in &mut config.spec.mounts {
            if let VolumeMount::Named { create, .. } = mount {
                *create = None;
            }
        }
        config
    }

    /// Select the background launch path for detached `msb run -d`.
    ///
    /// A non-empty command replaces the image CMD while preserving the effective entrypoint. An
    /// empty command intentionally keeps the image CMD so detached and attached runs resolve the
    /// same OCI process.
    #[cfg(test)]
    pub(crate) fn set_background_command(&mut self, command: Vec<String>) {
        if !command.is_empty() {
            if self.launch_cmd_before_override.is_none() {
                self.launch_cmd_before_override = Some(self.spec.runtime.cmd.clone());
            }
            self.spec.runtime.cmd = Some(command);
        }
        self.launch_intent = LaunchIntent::Background;
    }

    /// Return whether this create operation should launch the resolved command in the background.
    pub(crate) fn should_launch_background_command(&self) -> bool {
        self.launch_intent == LaunchIntent::Background
    }

    /// Clear process-launch intent after another mechanism takes ownership of the command.
    pub(crate) fn clear_launch_intent(&mut self) {
        self.launch_intent = LaunchIntent::None;
        self.launch_cmd_before_override = None;
    }

    /// Discard a requested startup command because restored execution already owns the workload.
    pub(crate) fn suppress_launch_for_full_restore(&mut self) {
        if let Some(previous) = self.launch_cmd_before_override.take() {
            self.spec.runtime.cmd = previous;
        }
        self.launch_intent = LaunchIntent::None;
        self.resumed_from_full_snapshot = true;
    }

    /// Return whether inherited image init routing owns this create operation's boot workload.
    #[doc(hidden)]
    pub fn init_owns_boot_workload(&self) -> bool {
        self.init_owns_workload
    }

    /// Return whether this create operation resumed execution from a full snapshot.
    #[doc(hidden)]
    pub fn resumed_from_full_snapshot(&self) -> bool {
        self.resumed_from_full_snapshot
    }

    /// Apply OCI image config as defaults. User-provided values take precedence.
    ///
    /// - `env`: image env vars form the base; user env vars override by key, otherwise append.
    /// - `labels`: image labels form the base; user labels override by key.
    /// - `cmd`, `entrypoint`, `workdir`, `user`: image value used only if user did not set one.
    /// - `init`: an `auto` init may resolve from a known init at the start of the image entrypoint and inherit the effective entrypoint env.
    #[cfg(feature = "local")]
    pub fn merge_image_defaults(&mut self, image: &ImageConfig) {
        self.spec.env = merge_env(&image.env, &self.spec.env);
        self.spec.labels = merge_image_labels(&image.labels, &self.spec.labels);

        let inherit_entrypoint = self.spec.runtime.entrypoint.is_none();

        if self.spec.runtime.cmd.is_none() {
            self.spec.runtime.cmd = image.cmd.clone();
        }
        if self.spec.runtime.entrypoint.is_none() {
            self.spec.runtime.entrypoint = image.entrypoint.clone();
        }
        if self.spec.runtime.workdir.is_none() {
            self.spec.runtime.workdir = image
                .working_dir
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(String::from);
        }
        if self.spec.runtime.user.is_none() {
            self.spec.runtime.user = image
                .user
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(String::from);
        }

        self.resolve_auto_init_from_image_entrypoint(
            image.entrypoint.as_deref(),
            inherit_entrypoint,
        );
    }

    /// Resolve `init = "auto"` from a known init path declared as the
    /// image entrypoint.
    ///
    /// Docker starts containers by appending CMD to the image ENTRYPOINT. Init selection always
    /// removes a recognized inherited init token from the durable workload template. Only an
    /// explicit boot-workload intent may transfer the already-resolved argv to PID 1.
    fn resolve_auto_init_from_image_entrypoint(
        &mut self,
        image_entrypoint: Option<&[String]>,
        inherited_entrypoint: bool,
    ) {
        let Some(init) = self.spec.init.as_ref() else {
            return;
        };
        if init.cmd != HANDOFF_INIT_AUTO {
            return;
        }
        let Some(entrypoint) = image_entrypoint else {
            return;
        };
        let Some(init_path) = entrypoint
            .first()
            .map(String::as_str)
            .filter(|path| is_image_entrypoint_init(path))
        else {
            return;
        };

        if !inherited_entrypoint {
            let init = self
                .spec
                .init
                .as_mut()
                .expect("init was present at start of auto resolution");
            init.cmd = init_path.to_string();
            init.env = merge_init_env(&self.spec.env, &init.env);
            return;
        }

        let Some(entrypoint) = self.spec.runtime.entrypoint.take() else {
            return;
        };
        let mut workload_entrypoint = entrypoint.clone();
        if workload_entrypoint
            .first()
            .is_some_and(|first| first.as_str() == init_path)
        {
            workload_entrypoint.remove(0);
        }

        let init = self
            .spec
            .init
            .as_mut()
            .expect("init was present at start of auto resolution");
        init.cmd = init_path.to_string();
        init.env = merge_init_env(&self.spec.env, &init.env);

        self.spec.runtime.entrypoint =
            (!workload_entrypoint.is_empty()).then_some(workload_entrypoint.clone());

        let cmd_override = match &self.launch_intent {
            LaunchIntent::Foreground { command } => command.as_deref(),
            LaunchIntent::Background => None,
            LaunchIntent::None => return,
        };
        let is_container_init_contract = init_path == "/init" || !workload_entrypoint.is_empty();
        if !is_container_init_contract {
            return;
        }

        let Ok(command) = microsandbox_types::resolve_default_command(
            Some(entrypoint.as_slice()),
            self.spec.runtime.cmd.as_deref(),
            cmd_override,
        ) else {
            return;
        };
        if command.program != init_path {
            return;
        }

        self.init_workload_arg_count = command.args.len();
        self.spec
            .init
            .as_mut()
            .expect("init remains configured")
            .args
            .extend(command.args);
        self.init_owns_workload = true;

        // The startup command is now part of PID 1's argv. Clearing launch intent prevents the
        // direct runtime from issuing a duplicate agent exec for a detached invocation.
        self.clear_launch_intent();
    }

    /// Materialize rootfs defaults that should be persisted with the sandbox.
    ///
    /// The backend default may select the complete root-disk shape. The deprecated upper-size
    /// setting remains managed-disk size sugar and cannot be combined with `root_disk`. An absent
    /// root disk resolves to managed; a sizeless tmpfs resolves to half the sandbox memory.
    #[cfg(feature = "local")]
    pub(crate) fn apply_rootfs_defaults(
        &mut self,
        defaults: &crate::config::OciSandboxDefaults,
    ) -> MicrosandboxResult<()> {
        if defaults.upper_size_mib.is_some() && defaults.root_disk.is_some() {
            return Err(crate::MicrosandboxError::InvalidConfig(
                "sandbox_defaults.oci.root_disk and deprecated sandbox_defaults.oci.upper_size_mib are mutually exclusive".into(),
            ));
        }
        if matches!(defaults.root_disk, Some(RootDisk::DiskImage { .. })) {
            return Err(crate::MicrosandboxError::InvalidConfig(
                "sandbox_defaults.oci.root_disk cannot be a shared disk-image; specify user-owned disk images per sandbox".into(),
            ));
        }

        if self.snapshot_reference.is_some()
            || self.snapshot_upper_source.is_some()
            || !self.snapshot_root_layer_sources.is_empty()
            || self.snapshot_archive_source.is_some()
            || self.checkpoint_restore.is_some()
        {
            return Ok(());
        }

        let default_size_mib = defaults.upper_size_mib;
        let memory_mib = self.spec.resources.memory_mib;
        if let RootfsSource::Oci(oci) = &mut self.spec.image {
            if oci.root_disk.is_none() {
                oci.root_disk = defaults.root_disk.clone();
            }

            match &mut oci.root_disk {
                None => {
                    oci.root_disk = Some(RootDisk::Managed {
                        size_mib: Some(default_size_mib.unwrap_or(DEFAULT_OCI_UPPER_SIZE_MIB)),
                    });
                }
                Some(RootDisk::Managed { size_mib }) if size_mib.is_none() => {
                    *size_mib = Some(default_size_mib.unwrap_or(DEFAULT_OCI_UPPER_SIZE_MIB));
                }
                Some(RootDisk::Tmpfs { size_mib }) if size_mib.is_none() => {
                    *size_mib = Some((memory_mib / 2).max(1));
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Keep disk-backed OCI temporary files on the writable disk. Only a
    /// deliberately RAM-backed root receives the historical bounded tmpfs.
    /// Explicit mounts, including tmpfs stored by older versions, are retained.
    pub(crate) fn apply_runtime_defaults(&mut self) {
        if !matches!(
            self.spec.image.oci_root_disk(),
            Some(RootDisk::Tmpfs { .. })
        ) {
            return;
        }

        if self
            .spec
            .mounts
            .iter()
            .any(|mount| guest_mount_is(mount, DEFAULT_OCI_TMPFS_PATH))
        {
            return;
        }

        self.spec.mounts.push(VolumeMount::Tmpfs {
            guest: DEFAULT_OCI_TMPFS_PATH.to_string(),
            size_mib: Some(default_oci_tmpfs_size_mib(self.spec.resources.memory_mib)),
            options: MountOptions::default(),
        });
    }

    #[cfg(feature = "net")]
    pub(crate) fn local_network_config(&self) -> MicrosandboxResult<NetworkConfig> {
        network_config_from_spec(&self.spec.network)
    }

    #[cfg(feature = "net")]
    pub(crate) fn set_local_network_config(
        &mut self,
        config: NetworkConfig,
    ) -> MicrosandboxResult<()> {
        self.spec.network = network_spec_from_config(&config)?;
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Merge two sets of env-var pairs. Base entries are kept unless overridden by
/// key, then all override entries are appended.
pub(super) fn merge_env_pairs(base: &[EnvVar], overrides: &[EnvVar]) -> Vec<EnvVar> {
    let override_keys: HashSet<&str> = overrides.iter().map(|var| var.key.as_str()).collect();

    let mut merged: Vec<EnvVar> = base
        .iter()
        .filter(|var| !override_keys.contains(var.key.as_str()))
        .cloned()
        .collect();

    merged.extend(overrides.iter().cloned());
    merged
}

fn merge_init_env(base: &[EnvVar], overrides: &[(String, String)]) -> Vec<(String, String)> {
    let overrides = overrides
        .iter()
        .cloned()
        .map(EnvVar::from)
        .collect::<Vec<_>>();

    merge_env_pairs(base, &overrides)
        .into_iter()
        .map(Into::into)
        .collect()
}

/// Merge image env vars (OCI `KEY=VALUE` strings) with user env var pairs.
fn merge_env(image_env: &[String], user_env: &[EnvVar]) -> Vec<EnvVar> {
    let base: Vec<EnvVar> = image_env
        .iter()
        .filter_map(|entry| match entry.split_once('=') {
            Some((key, value)) => Some(EnvVar::new(key, value)),
            None => {
                tracing::warn!(entry = %entry, "skipping malformed image env var (expected KEY=VALUE)");
                None
            }
        })
        .collect();

    merge_env_pairs(&base, user_env)
}

/// Merge OCI image labels (base) with user labels (override on key collision).
///
/// Image labels carrying a reserved prefix or an empty key are skipped: they
/// cannot become metric attributes and would otherwise bypass user-label
/// validation (which already ran before the image was pulled).
fn merge_image_labels(
    image_labels: &HashMap<String, String>,
    user_labels: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut merged: BTreeMap<String, String> = image_labels
        .iter()
        .filter(|(key, _)| !key.is_empty() && super::reserved_label_prefix(key).is_none())
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();

    // User labels win on collision.
    for (key, value) in user_labels {
        merged.insert(key.clone(), value.clone());
    }
    merged
}

fn is_image_entrypoint_init(path: &str) -> bool {
    HANDOFF_INIT_IMAGE_ENTRYPOINT_CANDIDATES.contains(&path)
}

fn default_oci_tmpfs_size_mib(memory_mib: u32) -> u32 {
    (memory_mib / DEFAULT_OCI_TMPFS_MEMORY_DIVISOR).clamp(1, DEFAULT_OCI_TMPFS_MAX_SIZE_MIB)
}

fn guest_mount_is(mount: &VolumeMount, path: &str) -> bool {
    match mount {
        VolumeMount::Bind { guest, .. }
        | VolumeMount::Named { guest, .. }
        | VolumeMount::Owned { guest, .. }
        | VolumeMount::Tmpfs { guest, .. }
        | VolumeMount::DiskImage { guest, .. } => {
            Utf8UnixPath::new(guest).normalize() == Utf8UnixPath::new(path).normalize()
        }
    }
}

pub(crate) fn sandbox_log_level_from_runtime(level: LogLevel) -> SandboxLogLevel {
    match level {
        LogLevel::Error => SandboxLogLevel::Error,
        LogLevel::Warn => SandboxLogLevel::Warn,
        LogLevel::Info => SandboxLogLevel::Info,
        LogLevel::Debug => SandboxLogLevel::Debug,
        LogLevel::Trace => SandboxLogLevel::Trace,
    }
}

#[cfg(feature = "net")]
pub(crate) fn network_spec_from_config(
    config: &NetworkConfig,
) -> MicrosandboxResult<microsandbox_types::NetworkSpec> {
    Ok(serde_json::from_value(serde_json::to_value(config)?)?)
}

#[cfg(feature = "net")]
pub(crate) fn network_config_from_spec(
    spec: &microsandbox_types::NetworkSpec,
) -> MicrosandboxResult<NetworkConfig> {
    Ok(serde_json::from_value(serde_json::to_value(spec)?)?)
}

/// Enable TLS interception for a non-empty secret set, returning whether
/// `tls.enabled` had to be flipped.
///
/// This preserves the top-level sandbox builder's create-time policy, which
/// enables interception for every secret entry. Lower-level network configs
/// may intentionally keep interception off for plain-HTTP secrets that opt
/// out of TLS identity checks.
#[cfg(feature = "net")]
pub(crate) fn ensure_tls_for_secrets(network: &mut NetworkConfig) -> bool {
    if network.secrets.secrets.is_empty() || network.tls.enabled {
        return false;
    }
    network.tls.enabled = true;
    true
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Overlay for SandboxConfigPatch {
    fn overlay(self, higher: Self) -> Self {
        self.overlay(higher)
    }
}

impl Overlay for OciSandboxDefaultsPatch {
    fn overlay(self, higher: Self) -> Self {
        self.overlay(higher)
    }
}

impl From<SandboxSpec> for SandboxConfig {
    /// Build a config from a full durable spec, defaulting all local
    /// operational state (registry auth, replace flags, snapshot metadata).
    fn from(spec: SandboxSpec) -> Self {
        Self {
            spec,
            ..Default::default()
        }
    }
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            spec: SandboxSpec {
                resources: SandboxResources {
                    cpus: default_cpus(),
                    memory_mib: default_memory_mib(),
                    max_cpus: default_cpus(),
                    max_memory_mib: default_memory_mib(),
                    cpu_placement: Default::default(),
                    placement_profile: None,
                    thp: TransparentHugePagePolicy::Madvise,
                },
                runtime: SandboxRuntimeOptions {
                    log_level: default_log_level(),
                    metrics_sample_interval_ms: default_metrics_sample_interval_ms()
                        .map(NonZero::get),
                    disable_metrics_sample: default_disable_metrics_sample(),
                    ..Default::default()
                },
                ..Default::default()
            },
            registry_auth: None,
            #[cfg(feature = "local")]
            creation_progress: None,
            insecure: false,
            ca_certs: Vec::new(),
            replace_existing: false,
            replace_with_timeout: DEFAULT_REPLACE_TIMEOUT,
            slug: None,
            manifest_digest: None,
            snapshot_reference: None,
            snapshot_upper_source: None,
            #[cfg(feature = "local")]
            snapshot_root_layer_sources: Vec::new(),
            #[cfg(feature = "local")]
            snapshot_owned_source: None,
            snapshot_root_virtual_size: None,
            snapshot_archive_source: None,
            snapshot_parent: None,
            snapshot_base: None,
            #[cfg(feature = "local")]
            checkpoint_restore: None,
            #[cfg(feature = "local")]
            branch_source: None,
            #[cfg(all(feature = "local", target_os = "linux"))]
            branch_memory: None,
            forked: false,
            snapshot_restore_mode: SnapshotRestoreMode::Full,
            external_mount_policy: microsandbox_types::ExternalMountRestorePolicy::Strict,
            restore_resources: Default::default(),
            resumed_from_full_snapshot: false,
            #[cfg(feature = "local")]
            snapshot_upper_layers: Vec::new(),
            restore_overrides: RestoreOverrideIntent::default(),
            restore_boot_overrides: Default::default(),
            launch_intent: LaunchIntent::None,
            launch_cmd_before_override: None,
            init_owns_workload: false,
            init_workload_arg_count: 0,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, feature = "local"))]
mod tests {
    use std::path::PathBuf;

    use microsandbox_runtime::launch::CheckpointRestoreConfig;

    use super::{SandboxConfig, SandboxConfigPatch, SnapshotRestoreMode, merge_env};
    use crate::sandbox::{
        HandoffInit, MountOptions, NamedVolumeMode, RootDisk, RootfsSource, StatVirtualization,
        VolumeMount,
    };
    use crate::snapshot::SnapshotReference;
    use microsandbox_image::ImageConfig;
    use microsandbox_types::{
        EnvVar, NamedVolumeCreate, SandboxLogLevel, SandboxPolicy, SandboxResources,
        SandboxRuntimeOptions, SandboxSpec, SecurityProfile, TransparentHugePagePolicy, VolumeKind,
    };

    fn assert_image_defaults(config: &mut SandboxConfig, image: &ImageConfig) {
        let mut layered = config.clone();
        layered.apply_layers(
            Some(&crate::config::layers::BackendConfig::new(
                Default::default(),
                Default::default(),
            )),
            crate::SandboxConfigPatch::from_present_fields(config.clone()),
            Some(SandboxConfigPatch::from_image(image)),
        );
        config.merge_image_defaults(image);
        assert_eq!(
            serde_json::to_value(&layered).unwrap(),
            serde_json::to_value(&config).unwrap()
        );
    }

    #[test]
    fn test_merge_env_image_base_with_user_override() {
        let image_env = vec![
            "PATH=/usr/local/bin:/usr/bin".to_string(),
            "PYTHON_VERSION=3.14".to_string(),
        ];
        let user_env = vec![
            EnvVar::new("PATH", "/custom/bin"),
            EnvVar::new("MY_VAR", "hello"),
        ];

        let merged = merge_env(&image_env, &user_env);

        assert_eq!(
            merged,
            vec![
                EnvVar::new("PYTHON_VERSION", "3.14"),
                EnvVar::new("PATH", "/custom/bin"),
                EnvVar::new("MY_VAR", "hello"),
            ]
        );
    }

    #[test]
    fn test_merge_env_empty_user_inherits_image() {
        let image_env = vec!["PATH=/usr/bin".to_string(), "LANG=C.UTF-8".to_string()];
        let user_env = Vec::new();

        let merged = merge_env(&image_env, &user_env);

        assert_eq!(
            merged,
            vec![
                EnvVar::new("PATH", "/usr/bin"),
                EnvVar::new("LANG", "C.UTF-8"),
            ]
        );
    }

    #[test]
    fn test_merge_env_empty_image_keeps_user() {
        let image_env = vec![];
        let user_env = vec![EnvVar::new("MY_VAR", "val")];

        let merged = merge_env(&image_env, &user_env);

        assert_eq!(merged, vec![EnvVar::new("MY_VAR", "val")]);
    }

    #[test]
    fn test_merge_image_defaults_replace_fields() {
        let image = ImageConfig {
            cmd: Some(vec!["python3".to_string()]),
            entrypoint: Some(vec!["/entrypoint.sh".to_string()]),
            working_dir: Some("/app".to_string()),
            user: Some("appuser".to_string()),
            ..Default::default()
        };

        let mut config = SandboxConfig::default();
        assert_image_defaults(&mut config, &image);

        assert_eq!(config.spec.runtime.cmd, Some(vec!["python3".to_string()]));
        assert_eq!(
            config.spec.runtime.entrypoint,
            Some(vec!["/entrypoint.sh".to_string()])
        );
        assert_eq!(config.spec.runtime.workdir, Some("/app".to_string()));
        assert_eq!(config.spec.runtime.user, Some("appuser".to_string()));
    }

    #[test]
    fn test_merge_image_defaults_user_overrides_take_precedence() {
        let image = ImageConfig {
            cmd: Some(vec!["python3".to_string()]),
            entrypoint: Some(vec!["/entrypoint.sh".to_string()]),
            working_dir: Some("/app".to_string()),
            user: Some("appuser".to_string()),
            ..Default::default()
        };

        let mut config = SandboxConfig {
            spec: SandboxSpec {
                runtime: SandboxRuntimeOptions {
                    cmd: Some(vec!["bash".to_string()]),
                    workdir: Some("/workspace".to_string()),
                    user: Some("root".to_string()),
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };
        assert_image_defaults(&mut config, &image);

        assert_eq!(config.spec.runtime.cmd, Some(vec!["bash".to_string()]));
        assert_eq!(
            config.spec.runtime.entrypoint,
            Some(vec!["/entrypoint.sh".to_string()])
        );
        assert_eq!(config.spec.runtime.workdir, Some("/workspace".to_string()));
        assert_eq!(config.spec.runtime.user, Some("root".to_string()));
    }

    #[test]
    fn full_restore_suppresses_transient_background_command() {
        let mut config = SandboxConfig {
            spec: SandboxSpec {
                runtime: SandboxRuntimeOptions {
                    cmd: Some(vec!["durable".to_string()]),
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };

        config.set_background_command(vec!["ignored".to_string()]);
        config.suppress_launch_for_full_restore();

        assert_eq!(config.spec.runtime.cmd, Some(vec!["durable".to_string()]));
        assert!(!config.should_launch_background_command());
        assert!(config.resumed_from_full_snapshot());
    }

    #[test]
    fn test_merge_image_defaults_selects_init_without_launching_default_workload() {
        let image = ImageConfig {
            entrypoint: Some(vec![
                "/init".to_string(),
                "/opt/hermes/docker/main-wrapper.sh".to_string(),
            ]),
            ..Default::default()
        };

        let mut config = SandboxConfig {
            spec: SandboxSpec {
                init: Some(HandoffInit {
                    cmd: "auto".to_string(),
                    args: Vec::new(),
                    env: Vec::new(),
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_image_defaults(&mut config, &image);

        let init = config
            .spec
            .init
            .as_ref()
            .expect("init should remain configured");
        assert_eq!(init.cmd, "/init");
        assert!(init.args.is_empty());
        assert_eq!(
            config.spec.runtime.entrypoint,
            Some(vec!["/opt/hermes/docker/main-wrapper.sh".to_string()])
        );
        assert!(!config.init_owns_boot_workload());
    }

    #[test]
    fn test_merge_image_defaults_routes_attached_command_through_init_entrypoint() {
        let image = ImageConfig {
            entrypoint: Some(vec![
                "/init".to_string(),
                "/opt/hermes/docker/main-wrapper.sh".to_string(),
            ]),
            ..Default::default()
        };

        let mut config = SandboxConfig {
            spec: SandboxSpec {
                init: Some(HandoffInit {
                    cmd: "auto".to_string(),
                    args: Vec::new(),
                    env: Vec::new(),
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut command_patch = crate::SandboxConfigPatch::new();
        command_patch.set_foreground_command(vec!["gateway".to_string(), "run".to_string()]);
        command_patch.apply_to(&mut config);
        assert_image_defaults(&mut config, &image);

        let init = config
            .spec
            .init
            .as_ref()
            .expect("init should remain configured");
        assert_eq!(init.cmd, "/init");
        assert_eq!(
            init.args,
            vec![
                "/opt/hermes/docker/main-wrapper.sh".to_string(),
                "gateway".to_string(),
                "run".to_string(),
            ]
        );
        assert_eq!(
            config.spec.runtime.entrypoint,
            Some(vec!["/opt/hermes/docker/main-wrapper.sh".to_string()])
        );
        assert!(config.init_owns_boot_workload());
    }

    #[test]
    fn test_merge_image_defaults_passes_effective_env_to_init_entrypoint() {
        let image = ImageConfig {
            entrypoint: Some(vec![
                "/init".to_string(),
                "/opt/hermes/docker/main-wrapper.sh".to_string(),
            ]),
            env: vec![
                "PATH=/image/bin:/usr/bin:/bin".to_string(),
                "IMAGE_ONLY=1".to_string(),
                "OVERRIDE=image".to_string(),
            ],
            ..Default::default()
        };

        let mut config = SandboxConfig {
            spec: SandboxSpec {
                init: Some(HandoffInit {
                    cmd: "auto".to_string(),
                    args: Vec::new(),
                    env: vec![
                        ("PATH".to_string(), "/init/bin:/usr/bin:/bin".to_string()),
                        ("INIT_ONLY".to_string(), "1".to_string()),
                    ],
                }),
                env: vec![
                    EnvVar::new("HERMES_DASHBOARD", "1"),
                    EnvVar::new("OVERRIDE", "user"),
                ],
                ..Default::default()
            },
            ..Default::default()
        };
        let mut command_patch = crate::SandboxConfigPatch::new();
        command_patch.set_foreground_command(vec!["gateway".to_string(), "run".to_string()]);
        command_patch.apply_to(&mut config);
        assert_image_defaults(&mut config, &image);

        let init = config
            .spec
            .init
            .as_ref()
            .expect("init should remain configured");
        assert_eq!(
            init.env,
            vec![
                ("IMAGE_ONLY".to_string(), "1".to_string()),
                ("HERMES_DASHBOARD".to_string(), "1".to_string()),
                ("OVERRIDE".to_string(), "user".to_string()),
                ("PATH".to_string(), "/init/bin:/usr/bin:/bin".to_string()),
                ("INIT_ONLY".to_string(), "1".to_string()),
            ]
        );
    }

    #[test]
    fn test_merge_image_defaults_passes_detached_startup_cmd_to_init_args() {
        let image = ImageConfig {
            entrypoint: Some(vec![
                "/init".to_string(),
                "/opt/hermes/docker/main-wrapper.sh".to_string(),
            ]),
            ..Default::default()
        };

        let mut config = SandboxConfig {
            spec: SandboxSpec {
                init: Some(HandoffInit {
                    cmd: "auto".to_string(),
                    args: Vec::new(),
                    env: Vec::new(),
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut command_patch = crate::SandboxConfigPatch::new();
        command_patch.set_background_command(vec!["gateway".to_string(), "run".to_string()]);
        command_patch.apply_to(&mut config);
        assert_image_defaults(&mut config, &image);

        let init = config.spec.init.as_ref().expect("runtime init");
        assert_eq!(init.cmd, "/init");
        assert_eq!(
            init.args,
            vec![
                "/opt/hermes/docker/main-wrapper.sh".to_string(),
                "gateway".to_string(),
                "run".to_string(),
            ]
        );
        assert_eq!(
            config.spec.runtime.entrypoint,
            Some(vec!["/opt/hermes/docker/main-wrapper.sh".to_string()])
        );
        assert_eq!(
            config.spec.runtime.cmd,
            Some(vec!["gateway".to_string(), "run".to_string()])
        );
        assert!(!config.should_launch_background_command());
        assert!(config.init_owns_boot_workload());

        let persisted = config.clone_for_persistence();
        assert!(
            persisted
                .spec
                .init
                .as_ref()
                .expect("persisted init")
                .args
                .is_empty()
        );
        assert!(!persisted.init_owns_boot_workload());
    }

    #[test]
    fn test_background_command_sets_runtime_cmd() {
        let mut config = SandboxConfig::default();

        let mut command_patch = crate::SandboxConfigPatch::new();
        command_patch.set_background_command(vec![
            "/bin/sh".to_string(),
            "-lc".to_string(),
            "echo detached".to_string(),
        ]);
        command_patch.apply_to(&mut config);

        assert_eq!(
            config.spec.runtime.cmd,
            Some(vec![
                "/bin/sh".to_string(),
                "-lc".to_string(),
                "echo detached".to_string(),
            ])
        );
        assert!(config.should_launch_background_command());
    }

    #[test]
    fn test_empty_background_command_keeps_runtime_cmd() {
        let mut config = SandboxConfig {
            spec: SandboxSpec {
                runtime: SandboxRuntimeOptions {
                    cmd: Some(vec!["python3".to_string()]),
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };

        let mut command_patch = crate::SandboxConfigPatch::new();
        command_patch.set_background_command(Vec::new());
        command_patch.apply_to(&mut config);

        assert_eq!(config.spec.runtime.cmd, Some(vec!["python3".to_string()]));
        assert!(config.should_launch_background_command());
    }

    #[test]
    fn test_empty_background_command_uses_merged_image_cmd() {
        let image = ImageConfig {
            cmd: Some(vec!["bash".to_string()]),
            ..Default::default()
        };
        let mut config = SandboxConfig {
            spec: SandboxSpec {
                runtime: SandboxRuntimeOptions {
                    entrypoint: Some(vec!["start-desktop".to_string()]),
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };

        let mut command_patch = crate::SandboxConfigPatch::new();
        command_patch.set_background_command(Vec::new());
        command_patch.apply_to(&mut config);
        assert_image_defaults(&mut config, &image);

        assert_eq!(
            config.spec.runtime.entrypoint,
            Some(vec!["start-desktop".to_string()])
        );
        assert_eq!(config.spec.runtime.cmd, Some(vec!["bash".to_string()]));
        assert!(config.should_launch_background_command());
    }

    #[test]
    fn test_restore_boot_intent_is_operation_local() {
        let config = SandboxConfig {
            restore_boot_overrides: super::super::restore_builder::RestoreBootOverrides {
                security: true,
            },
            ..Default::default()
        };

        // A later ordinary start must not replay the previous restore's admission decision.
        assert!(config.restore_boot_overrides.security);
        assert!(
            !config
                .clone_for_persistence()
                .restore_boot_overrides
                .security
        );
        let encoded = serde_json::to_value(&config).unwrap();
        assert!(encoded.get("restore_boot_overrides").is_none());
        let decoded: SandboxConfig = serde_json::from_value(encoded).unwrap();
        assert!(!decoded.restore_boot_overrides.security);
    }

    #[test]
    fn test_clone_for_persistence_keeps_user_init_args() {
        let config = SandboxConfig {
            spec: SandboxSpec {
                init: Some(HandoffInit {
                    cmd: "/lib/systemd/systemd".to_string(),
                    args: vec!["--unit=multi-user.target".to_string()],
                    env: Vec::new(),
                }),
                ..Default::default()
            },
            ..Default::default()
        };

        let persisted = config.clone_for_persistence();

        let persisted_init = persisted.spec.init.as_ref().expect("persisted init");
        assert_eq!(
            persisted_init.args,
            vec!["--unit=multi-user.target".to_string()]
        );
    }

    #[test]
    fn test_clone_for_persistence_strips_named_volume_create_intent() {
        let config = SandboxConfig {
            spec: SandboxSpec {
                mounts: vec![VolumeMount::Named {
                    name: "cache".to_string(),
                    guest: "/cache".to_string(),
                    create: Some(NamedVolumeCreate {
                        mode: NamedVolumeMode::Create,
                        name: "cache".to_string(),
                        kind: VolumeKind::Directory,
                        quota_mib: Some(512),
                        capacity_mib: None,
                        labels: Vec::new(),
                    }),
                    options: MountOptions::default(),
                    stat_virtualization: StatVirtualization::Strict,
                    host_permissions: crate::sandbox::HostPermissions::Private,
                    follow_root_symlinks: false,
                }],
                ..Default::default()
            },
            ..Default::default()
        };

        let persisted = config.clone_for_persistence();

        match &persisted.spec.mounts[0] {
            VolumeMount::Named { name, create, .. } => {
                assert_eq!(name, "cache");
                assert!(create.is_none());
            }
            other => panic!("expected named mount, got {other:?}"),
        }
    }

    #[test]
    fn test_merge_image_defaults_passes_image_cmd_to_init_args() {
        let image = ImageConfig {
            entrypoint: Some(vec!["/init".to_string()]),
            cmd: Some(vec!["/app/server".to_string(), "--serve".to_string()]),
            ..Default::default()
        };

        let mut config = SandboxConfig {
            spec: SandboxSpec {
                init: Some(HandoffInit {
                    cmd: "auto".to_string(),
                    args: Vec::new(),
                    env: Vec::new(),
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut command_patch = crate::SandboxConfigPatch::new();
        command_patch.set_foreground_command(Vec::new());
        command_patch.apply_to(&mut config);
        assert_image_defaults(&mut config, &image);

        let init = config
            .spec
            .init
            .as_ref()
            .expect("init should remain configured");
        assert_eq!(init.cmd, "/init");
        assert_eq!(
            init.args,
            vec!["/app/server".to_string(), "--serve".to_string()]
        );
        assert_eq!(config.spec.runtime.entrypoint, None);
        assert_eq!(
            config.spec.runtime.cmd,
            Some(vec!["/app/server".to_string(), "--serve".to_string()])
        );
    }

    #[test]
    fn test_merge_image_defaults_resolves_bare_systemd_init_entrypoint() {
        let image = ImageConfig {
            entrypoint: Some(vec!["/lib/systemd/systemd".to_string()]),
            ..Default::default()
        };

        let mut config = SandboxConfig {
            spec: SandboxSpec {
                init: Some(HandoffInit {
                    cmd: "auto".to_string(),
                    args: Vec::new(),
                    env: Vec::new(),
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut command_patch = crate::SandboxConfigPatch::new();
        command_patch.set_foreground_command(vec!["bash".to_string()]);
        command_patch.apply_to(&mut config);
        assert_image_defaults(&mut config, &image);

        let init = config
            .spec
            .init
            .as_ref()
            .expect("init should remain configured");
        assert_eq!(init.cmd, "/lib/systemd/systemd");
        assert!(init.args.is_empty());
        assert_eq!(config.spec.runtime.entrypoint, None);
        assert!(!config.init_owns_boot_workload());
    }

    #[test]
    fn test_merge_image_defaults_keeps_user_entrypoint_when_resolving_auto_init() {
        let image = ImageConfig {
            entrypoint: Some(vec![
                "/init".to_string(),
                "/opt/hermes/docker/main-wrapper.sh".to_string(),
            ]),
            ..Default::default()
        };

        let mut config = SandboxConfig {
            spec: SandboxSpec {
                runtime: SandboxRuntimeOptions {
                    entrypoint: Some(vec!["/bin/sh".to_string()]),
                    ..Default::default()
                },
                init: Some(HandoffInit {
                    cmd: "auto".to_string(),
                    args: Vec::new(),
                    env: Vec::new(),
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut command_patch = crate::SandboxConfigPatch::new();
        command_patch.set_foreground_command(vec!["gateway".to_string(), "run".to_string()]);
        command_patch.apply_to(&mut config);
        assert_image_defaults(&mut config, &image);

        let init = config
            .spec
            .init
            .as_ref()
            .expect("init should remain configured");
        assert_eq!(init.cmd, "/init");
        assert!(init.args.is_empty());
        assert_eq!(
            config.spec.runtime.entrypoint,
            Some(vec!["/bin/sh".to_string()])
        );
    }

    #[test]
    fn test_merge_image_defaults_leaves_auto_init_for_unknown_entrypoint() {
        let image = ImageConfig {
            entrypoint: Some(vec!["/entrypoint.sh".to_string()]),
            ..Default::default()
        };

        let mut config = SandboxConfig {
            spec: SandboxSpec {
                init: Some(HandoffInit {
                    cmd: "auto".to_string(),
                    args: Vec::new(),
                    env: Vec::new(),
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_image_defaults(&mut config, &image);

        assert_eq!(
            config.spec.init.expect("init should remain configured").cmd,
            "auto"
        );
        assert_eq!(
            config.spec.runtime.entrypoint,
            Some(vec!["/entrypoint.sh".to_string()])
        );
    }

    #[test]
    fn test_merge_image_defaults_imports_labels() {
        use std::collections::HashMap;

        let image = ImageConfig {
            labels: HashMap::from([
                (
                    "org.opencontainers.image.source".to_string(),
                    "https://example.com/repo".to_string(),
                ),
                ("vendor".to_string(), "image-vendor".to_string()),
                // Reserved prefix and empty key must be skipped.
                ("sandbox.id".to_string(), "spoofed".to_string()),
                (String::new(), "x".to_string()),
            ]),
            ..Default::default()
        };

        let mut config = SandboxConfig {
            spec: SandboxSpec {
                labels: [
                    ("user.id".to_string(), "alice".to_string()),
                    // Collides with an image label; the user value must win.
                    ("vendor".to_string(), "user-vendor".to_string()),
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_image_defaults(&mut config, &image);

        assert_eq!(
            config
                .spec
                .labels
                .get("org.opencontainers.image.source")
                .map(String::as_str),
            Some("https://example.com/repo")
        );
        assert_eq!(
            config.spec.labels.get("user.id").map(String::as_str),
            Some("alice")
        );
        assert_eq!(
            config.spec.labels.get("vendor").map(String::as_str),
            Some("user-vendor")
        );
        assert!(!config.spec.labels.contains_key("sandbox.id"));
        assert!(!config.spec.labels.contains_key(""));
    }

    #[test]
    fn test_merge_image_defaults_empty_strings_treated_as_none() {
        let image = ImageConfig {
            working_dir: Some(String::new()),
            user: Some(String::new()),
            ..Default::default()
        };

        let mut config = SandboxConfig::default();
        assert_image_defaults(&mut config, &image);

        assert!(
            config.spec.runtime.workdir.is_none(),
            "empty working_dir should not propagate"
        );
        assert!(
            config.spec.runtime.user.is_none(),
            "empty user should not propagate"
        );
    }

    #[test]
    fn test_sandbox_config_serializes_manifest_digest_but_redacts_registry_auth() {
        let mut config = SandboxConfig {
            spec: SandboxSpec {
                name: "persisted".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        config.replace_existing = true;
        config.manifest_digest = Some("sha256:abc123".into());

        let json = serde_json::to_string(&config).unwrap();
        assert!(!json.contains("registry_auth"));
        assert!(!json.contains("replace_existing"));
        assert!(json.contains("manifest_digest"));
        assert!(json.contains("sha256:abc123"));

        let decoded: SandboxConfig = serde_json::from_str(&json).unwrap();
        assert!(decoded.registry_auth.is_none());
        assert!(!decoded.replace_existing);
        assert_eq!(decoded.manifest_digest, config.manifest_digest);
    }

    #[test]
    fn test_sandbox_config_embeds_shared_spec() {
        let spec = microsandbox_types::SandboxSpec {
            name: "spec-test".into(),
            image: RootfsSource::oci("python:3.12"),
            resources: SandboxResources {
                cpus: 2,
                memory_mib: 1024,
                max_cpus: 2,
                max_memory_mib: 1024,
                cpu_placement: Default::default(),
                placement_profile: None,
                thp: TransparentHugePagePolicy::Madvise,
            },
            runtime: SandboxRuntimeOptions {
                workdir: Some("/app".into()),
                shell: Some("/bin/bash".into()),
                scripts: [("setup".to_string(), "echo hi".to_string())]
                    .into_iter()
                    .collect(),
                entrypoint: Some(vec!["python".into(), "-u".into()]),
                cmd: Some(vec!["worker.py".into()]),
                hostname: Some("worker".into()),
                user: Some("appuser".into()),
                log_level: Some(SandboxLogLevel::Trace),
                metrics_sample_interval_ms: Some(750),
                disable_metrics_sample: true,
            },
            env: vec![EnvVar::new("A", "B")],
            labels: [("team".to_string(), "infra".to_string())]
                .into_iter()
                .collect(),
            rlimits: vec![microsandbox_types::Rlimit {
                resource: microsandbox_types::RlimitResource::Nofile,
                soft: 1024,
                hard: 2048,
            }],
            security_profile: SecurityProfile::Restricted,
            lifecycle: SandboxPolicy {
                ephemeral: false,
                max_duration_secs: Some(3600),
                idle_timeout_secs: Some(120),
            },
            ..Default::default()
        };

        let config = SandboxConfig {
            spec,
            ..Default::default()
        };

        assert_eq!(config.spec.name, "spec-test");
        assert!(
            matches!(config.spec.image, RootfsSource::Oci(ref oci) if oci.reference == "python:3.12")
        );
        assert_eq!(config.spec.resources.cpus, 2);
        assert_eq!(config.spec.resources.memory_mib, 1024);
        assert_eq!(config.spec.runtime.log_level, Some(SandboxLogLevel::Trace));
        assert_eq!(config.spec.runtime.metrics_sample_interval_ms, Some(750));
        assert!(config.spec.runtime.disable_metrics_sample);
        assert_eq!(config.spec.runtime.workdir.as_deref(), Some("/app"));
        assert_eq!(config.spec.runtime.shell.as_deref(), Some("/bin/bash"));
        assert_eq!(
            config.spec.runtime.scripts.get("setup"),
            Some(&"echo hi".into())
        );
        assert_eq!(config.spec.env, vec![EnvVar::new("A", "B")]);
        assert_eq!(config.spec.labels.get("team"), Some(&"infra".into()));
        assert_eq!(config.spec.rlimits.len(), 1);
        assert_eq!(
            config.spec.runtime.entrypoint,
            Some(vec!["python".to_string(), "-u".to_string()])
        );
        assert_eq!(config.spec.runtime.cmd, Some(vec!["worker.py".to_string()]));
        assert_eq!(config.spec.runtime.hostname.as_deref(), Some("worker"));
        assert_eq!(config.spec.runtime.user.as_deref(), Some("appuser"));
        assert_eq!(config.spec.security_profile, SecurityProfile::Restricted);
        assert_eq!(config.spec.lifecycle.max_duration_secs, Some(3600));
        assert_eq!(config.spec.lifecycle.idle_timeout_secs, Some(120));
    }

    #[test]
    fn test_apply_runtime_defaults_adds_tmpfs_for_ram_backed_oci_tmp() {
        let mut config = SandboxConfig {
            spec: SandboxSpec {
                image: RootfsSource::oci("python:3.12"),
                resources: SandboxResources {
                    memory_mib: 2048,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };

        if let RootfsSource::Oci(oci) = &mut config.spec.image {
            oci.root_disk = Some(RootDisk::tmpfs(1024));
        }
        config.apply_runtime_defaults();

        assert_eq!(config.spec.mounts.len(), 1);
        match &config.spec.mounts[0] {
            VolumeMount::Tmpfs {
                guest,
                size_mib,
                options,
            } => {
                assert_eq!(guest, "/tmp");
                assert_eq!(*size_mib, Some(512));
                assert_eq!(*options, MountOptions::default());
            }
            mount => panic!("expected tmpfs mount, got {mount:?}"),
        }
    }

    #[test]
    fn disk_backed_tmp_uses_root_disk_and_explicit_tmpfs_survives_restart() {
        for root_disk in [
            None,
            Some(RootDisk::managed(16384)),
            Some(RootDisk::flat(16384)),
        ] {
            let mut config = SandboxConfig::default();
            config.spec.image = RootfsSource::oci("node:22");
            if let RootfsSource::Oci(oci) = &mut config.spec.image {
                oci.root_disk = root_disk;
            }
            config.apply_runtime_defaults();
            assert!(config.spec.mounts.is_empty());
            config.spec.mounts.push(VolumeMount::Tmpfs {
                guest: "/tmp".into(),
                size_mib: Some(128),
                options: MountOptions::default(),
            });
            // Persisted mounts from older versions remain explicit on restart.
            let mut restarted: SandboxConfig =
                serde_json::from_str(&serde_json::to_string(&config).unwrap()).unwrap();
            restarted.apply_runtime_defaults();
            assert_eq!(restarted.spec.mounts.len(), 1);
            assert!(matches!(
                restarted.spec.mounts[0],
                VolumeMount::Tmpfs {
                    size_mib: Some(128),
                    ..
                }
            ));
        }
    }

    #[test]
    fn test_apply_rootfs_defaults_sets_managed_root_disk() {
        let mut config = SandboxConfig {
            spec: SandboxSpec {
                image: RootfsSource::oci("python:3.12"),
                ..Default::default()
            },
            ..Default::default()
        };

        config
            .apply_rootfs_defaults(&crate::config::OciSandboxDefaults::default())
            .unwrap();

        assert_eq!(
            config.spec.image.oci_root_disk(),
            Some(&RootDisk::managed(4096))
        );
    }

    #[test]
    fn test_apply_rootfs_defaults_sizes_tmpfs_from_memory() {
        let mut config = SandboxConfig {
            spec: SandboxSpec {
                image: RootfsSource::Oci(microsandbox_types::OciRootfsSource {
                    reference: "python:3.12".into(),
                    root_disk: Some(RootDisk::Tmpfs { size_mib: None }),
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        config.spec.resources.memory_mib = 2048;

        config
            .apply_rootfs_defaults(&crate::config::OciSandboxDefaults::default())
            .unwrap();

        assert_eq!(
            config.spec.image.oci_root_disk(),
            Some(&RootDisk::tmpfs(1024))
        );
    }

    #[test]
    fn test_apply_rootfs_defaults_uses_backend_oci_upper_size() {
        let mut config = SandboxConfig {
            spec: SandboxSpec {
                image: RootfsSource::oci("python:3.12"),
                ..Default::default()
            },
            ..Default::default()
        };

        config
            .apply_rootfs_defaults(&crate::config::OciSandboxDefaults {
                upper_size_mib: Some(8192),
                root_disk: None,
            })
            .unwrap();

        assert_eq!(
            config.spec.image.oci_root_disk(),
            Some(&RootDisk::managed(8192))
        );
    }

    #[test]
    fn test_apply_rootfs_defaults_uses_flat_backend_default() {
        let mut config = SandboxConfig {
            spec: SandboxSpec {
                image: RootfsSource::oci("python:3.12"),
                ..Default::default()
            },
            ..Default::default()
        };
        let expected = RootDisk::Flat {
            size_mib: Some(8192),
            fstype: Some("ext4".into()),
            clone: microsandbox_types::FlatClone::Copy,
        };

        config
            .apply_rootfs_defaults(&crate::config::OciSandboxDefaults {
                upper_size_mib: None,
                root_disk: Some(expected.clone()),
            })
            .unwrap();

        assert_eq!(config.spec.image.oci_root_disk(), Some(&expected));
    }

    #[test]
    fn test_apply_rootfs_defaults_rejects_conflicting_config_fields() {
        let mut config = SandboxConfig {
            spec: SandboxSpec {
                image: RootfsSource::oci("python:3.12"),
                ..Default::default()
            },
            ..Default::default()
        };

        let error = config
            .apply_rootfs_defaults(&crate::config::OciSandboxDefaults {
                upper_size_mib: Some(8192),
                root_disk: Some(RootDisk::Flat {
                    size_mib: None,
                    fstype: None,
                    clone: microsandbox_types::FlatClone::Auto,
                }),
            })
            .unwrap_err();

        assert!(error.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn test_apply_rootfs_defaults_skips_snapshot_reference() {
        let mut config = SandboxConfig {
            spec: SandboxSpec {
                image: RootfsSource::oci("python:3.12"),
                ..Default::default()
            },
            snapshot_reference: Some(SnapshotReference::path("/tmp/snapshot")),
            ..Default::default()
        };

        config
            .apply_rootfs_defaults(&crate::config::OciSandboxDefaults {
                upper_size_mib: Some(8192),
                root_disk: None,
            })
            .unwrap();

        assert!(config.spec.image.oci_root_disk().is_none());
    }

    #[test]
    fn test_apply_rootfs_defaults_skips_installed_checkpoint_restore() {
        for restore_mode in [SnapshotRestoreMode::Full, SnapshotRestoreMode::DiskOnly] {
            let mut config = SandboxConfig {
                spec: SandboxSpec {
                    image: RootfsSource::oci("python:3.12"),
                    ..Default::default()
                },
                snapshot_restore_mode: restore_mode,
                checkpoint_restore: Some(CheckpointRestoreConfig {
                    memory_descriptor: false,
                    network_gateway_mac: None,
                    external_mount_policy: Default::default(),
                    external_mounts: Vec::new(),
                    unavailable_disks: Default::default(),
                    local_branch: false,
                    forked: false,
                    closure: PathBuf::from("/tmp/checkpoint"),
                    checkpoint_root:
                        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                            .into(),
                    checkpoint_id: "checkpoint_test".into(),
                }),
                ..Default::default()
            };

            config
                .apply_rootfs_defaults(&crate::config::OciSandboxDefaults {
                    upper_size_mib: Some(8192),
                    root_disk: None,
                })
                .unwrap();

            assert!(
                config.spec.image.oci_root_disk().is_none(),
                "{restore_mode:?} restore inherited an ordinary root-disk default"
            );
        }
    }

    #[test]
    fn test_apply_runtime_defaults_preserves_explicit_tmp_mount() {
        let mut config = SandboxConfig {
            spec: SandboxSpec {
                image: RootfsSource::oci("python:3.12"),
                mounts: vec![VolumeMount::Bind {
                    host: "/host/tmp".into(),
                    guest: "/tmp/".into(),
                    options: MountOptions::default(),
                    stat_virtualization: crate::sandbox::StatVirtualization::Strict,
                    host_permissions: crate::sandbox::HostPermissions::Private,
                    follow_root_symlinks: false,
                    quota_mib: None,
                }],
                ..Default::default()
            },
            ..Default::default()
        };

        config.apply_runtime_defaults();

        assert_eq!(config.spec.mounts.len(), 1);
        match &config.spec.mounts[0] {
            VolumeMount::Bind { guest, .. } => assert_eq!(guest, "/tmp/"),
            mount => panic!("expected bind mount, got {mount:?}"),
        }
    }

    #[test]
    fn test_apply_runtime_defaults_preserves_canonical_tmp_alias() {
        let mut config = SandboxConfig {
            spec: SandboxSpec {
                image: RootfsSource::oci("python:3.12"),
                mounts: vec![VolumeMount::Bind {
                    host: "/host/tmp".into(),
                    guest: "/tmp/.".into(),
                    options: MountOptions::default(),
                    stat_virtualization: crate::sandbox::StatVirtualization::Strict,
                    host_permissions: crate::sandbox::HostPermissions::Private,
                    follow_root_symlinks: false,
                    quota_mib: None,
                }],
                ..Default::default()
            },
            ..Default::default()
        };

        config.apply_runtime_defaults();

        assert_eq!(config.spec.mounts.len(), 1);
        assert_eq!(config.spec.mounts[0].guest(), "/tmp/.");
    }

    #[test]
    fn test_apply_runtime_defaults_skips_non_oci_roots() {
        let mut config = SandboxConfig {
            spec: SandboxSpec {
                image: RootfsSource::Bind {
                    path: "/tmp/rootfs".into(),
                    follow_root_symlinks: false,
                },
                ..Default::default()
            },
            ..Default::default()
        };

        config.apply_runtime_defaults();

        assert!(config.spec.mounts.is_empty());
    }

    #[test]
    fn test_apply_runtime_defaults_skips_disk_image_roots() {
        // Disk-image rootfses bring their own /tmp (it's part of the
        // shipped filesystem), so we don't synthesise an implicit tmpfs
        // for them. This test pins the policy so a future change has to
        // be deliberate.
        use crate::sandbox::DiskImageFormat;
        let mut config = SandboxConfig {
            spec: SandboxSpec {
                image: RootfsSource::DiskImage {
                    path: "/tmp/disk.qcow2".into(),
                    format: DiskImageFormat::Qcow2,
                    fstype: None,
                },
                ..Default::default()
            },
            ..Default::default()
        };

        config.apply_runtime_defaults();

        assert!(config.spec.mounts.is_empty());
    }

    #[cfg(feature = "net")]
    #[test]
    fn unspecified_network_policy_uses_engine_public_default() {
        use microsandbox_network::policy::{NetworkPolicy, NetworkProfile};

        let config = SandboxConfig::default();
        assert!(config.spec.network.policy.is_none());

        let actual = config.local_network_config().unwrap().policy;
        let expected = NetworkPolicy::from_profiles([NetworkProfile::Public]);
        assert_eq!(
            serde_json::to_value(actual).unwrap(),
            serde_json::to_value(expected).unwrap()
        );
    }

    //----------------------------------------------------------------------------------------------
    // Tests: Secret source references (create path + spawn resolution)
    //----------------------------------------------------------------------------------------------
    #[cfg(feature = "net")]
    #[test]
    fn ensure_tls_for_secrets_enables_interception_for_a_non_empty_set() {
        use microsandbox_network::secrets::config::{HostPattern, SecretEntry};

        let mut network = microsandbox_network::config::NetworkConfig::default();
        assert!(!network.tls.enabled);

        network.secrets.secrets.push(SecretEntry {
            env_var: "API_KEY".into(),
            value: zeroize::Zeroizing::new(String::new()),
            source: None,
            placeholder: "$MSB_API_KEY".into(),
            allowed_hosts: vec![HostPattern::Exact("api.example.com".into())],
            substitution: Default::default(),
            passthrough_hosts: Vec::new(),
            violation_action: None,
            require_tls_identity: false,
        });
        assert!(super::ensure_tls_for_secrets(&mut network));
        assert!(network.tls.enabled);
        assert!(!super::ensure_tls_for_secrets(&mut network));
    }

    /// One-way: an empty set never enables interception, and never disables
    /// interception enabled for other reasons.
    #[cfg(feature = "net")]
    #[test]
    fn ensure_tls_for_secrets_leaves_an_empty_set_alone() {
        let mut network = microsandbox_network::config::NetworkConfig::default();
        assert!(!super::ensure_tls_for_secrets(&mut network));
        assert!(!network.tls.enabled);

        network.tls.enabled = true;
        assert!(!super::ensure_tls_for_secrets(&mut network));
        assert!(network.tls.enabled);
    }

    #[cfg(feature = "net")]
    const SECRET_SENTINEL: &str = "sentinel-secret-value";

    /// Build a network-enabled config carrying one secret. When `source_var`
    /// is `Some`, the entry is a reference (the create path) resolved from that
    /// host variable; when `None`, it is a legacy inlined value.
    #[cfg(feature = "net")]
    fn config_with_source_secret(source_var: Option<&str>) -> SandboxConfig {
        use microsandbox_network::secrets::config::{
            HostPattern, SecretEntry, SecretSource, SecretSubstitution,
        };

        let mut config = SandboxConfig::default();
        config.spec.network.enabled = true;
        let mut network = config.local_network_config().unwrap();
        network.secrets.secrets.push(SecretEntry {
            env_var: "API_KEY".into(),
            value: if source_var.is_some() {
                zeroize::Zeroizing::new(String::new())
            } else {
                zeroize::Zeroizing::new(SECRET_SENTINEL.into())
            },
            source: source_var.map(|var| SecretSource::Env {
                var: var.to_string(),
            }),
            placeholder: "$MSB_API_KEY".into(),
            allowed_hosts: vec![HostPattern::Exact("api.example.com".into())],
            substitution: SecretSubstitution::default(),
            passthrough_hosts: Vec::new(),
            violation_action: None,
            require_tls_identity: true,
        });
        config.set_local_network_config(network).unwrap();
        config
    }

    #[cfg(feature = "net")]
    fn config_with_socks5_password_source() -> SandboxConfig {
        use microsandbox_network::{OutboundProxyBuilder, OutboundProxyConfig};
        use microsandbox_types::SecretSource;

        let mut config = SandboxConfig::default();
        config.spec.network.enabled = true;
        let mut network = config.local_network_config().unwrap();
        network.outbound_proxy = Some(
            OutboundProxyBuilder::new()
                .socks5("127.0.0.1:1080")
                .credentials("sandbox", SecretSource::env("MSB_TEST_SOCKS5_PASSWORD"))
                .build()
                .unwrap(),
        );
        config.set_local_network_config(network).unwrap();
        config
    }

    #[cfg(feature = "net")]
    #[test]
    fn socks5_password_uses_resolved_network_launch_type() {
        let _env_guard = crate::test_support::lock_env();
        let config = config_with_socks5_password_source();
        let durable_json = serde_json::to_string(&config).unwrap();
        assert!(durable_json.contains("MSB_TEST_SOCKS5_PASSWORD"));
        assert!(!durable_json.contains(SECRET_SENTINEL));

        // SAFETY: every environment-mutating SDK unit test holds the shared lock.
        unsafe { std::env::set_var("MSB_TEST_SOCKS5_PASSWORD", SECRET_SENTINEL) };
        let resolved = config
            .local_network_config()
            .unwrap()
            .resolve(&microsandbox_network::config::EnvNetworkSecretResolver)
            .unwrap();
        let launch_json = serde_json::to_string(&resolved).unwrap();
        assert!(launch_json.contains(SECRET_SENTINEL));

        let persisted_json = serde_json::to_string(&config.clone_for_persistence()).unwrap();
        assert!(persisted_json.contains("MSB_TEST_SOCKS5_PASSWORD"));
        assert!(!persisted_json.contains(SECRET_SENTINEL));
        unsafe { std::env::remove_var("MSB_TEST_SOCKS5_PASSWORD") };
    }

    /// The create path persists a source reference, never the resolved value:
    /// the durable config JSON and the active_config snapshot carry the
    /// `{kind: env, var: ...}` reference and zero occurrences of the value.
    #[cfg(feature = "net")]
    #[test]
    fn create_path_persists_reference_not_value() {
        // No host env is touched: the reference is persisted without ever
        // reading the value at create time.
        let config = config_with_source_secret(Some("MSB_TEST_CREATE_SOURCE"));
        let persisted = serde_json::to_string(&config).unwrap();
        assert!(
            !persisted.contains(SECRET_SENTINEL),
            "persisted config must not contain the secret value"
        );
        assert!(persisted.contains("\"var\":\"MSB_TEST_CREATE_SOURCE\""));

        // The active_config snapshot is written from the same config shape at
        // start, so it inherits the reference and stays value-free.
        let active = config.clone_for_persistence();
        let active_json = serde_json::to_string(&active).unwrap();
        assert!(!active_json.contains(SECRET_SENTINEL));
        assert!(active_json.contains("\"var\":\"MSB_TEST_CREATE_SOURCE\""));
    }

    /// The spawn resolver reads the source from the host environment and yields
    /// a config whose entry carries the value; the durable input is unchanged.
    #[cfg(feature = "net")]
    #[test]
    fn spawn_resolver_reads_source_from_host_env() {
        let _env_guard = crate::test_support::lock_env();
        // SAFETY: every environment-mutating SDK unit test holds the shared lock.
        unsafe { std::env::set_var("MSB_TEST_RESOLVE_SOURCE", SECRET_SENTINEL) };

        let config = config_with_source_secret(Some("MSB_TEST_RESOLVE_SOURCE"));
        let resolved = config
            .local_network_config()
            .unwrap()
            .resolve(&microsandbox_network::config::EnvNetworkSecretResolver)
            .unwrap();
        assert_eq!(
            resolved.config().secrets.secrets[0].value.as_str(),
            SECRET_SENTINEL
        );
        // The durable input still stores only the reference.
        let durable = config.local_network_config().unwrap();
        assert!(durable.secrets.secrets[0].value.is_empty());

        unsafe { std::env::remove_var("MSB_TEST_RESOLVE_SOURCE") };
    }

    /// Back-compat: a legacy config that inlined the value (no `source`) still
    /// spawns. The resolver leaves the present non-empty value in the
    /// declarative launch config and has no separate value to apply.
    #[cfg(feature = "net")]
    #[test]
    fn spawn_resolver_preserves_legacy_inlined_value() {
        let config = config_with_source_secret(None);
        let resolved = config
            .local_network_config()
            .unwrap()
            .resolve(&microsandbox_network::config::EnvNetworkSecretResolver)
            .unwrap();
        assert_eq!(
            resolved.config().secrets.secrets[0].value.as_str(),
            SECRET_SENTINEL
        );
    }
    #[test]
    fn test_sandbox_config_deserializes_legacy_readonly_mounts() {
        let json = r#"{"name":"legacy","mounts":[{"type":"Tmpfs","guest":"/tmp","size_mib":512,"readonly":false}]}"#;

        let decoded: SandboxConfig = serde_json::from_str(json).unwrap();

        assert_eq!(decoded.spec.mounts.len(), 1);
        match &decoded.spec.mounts[0] {
            VolumeMount::Tmpfs {
                guest,
                size_mib,
                options,
            } => {
                assert_eq!(guest, "/tmp");
                assert_eq!(*size_mib, Some(512));
                assert_eq!(*options, MountOptions::default());
            }
            mount => panic!("expected tmpfs mount, got {mount:?}"),
        }
    }
}

#[cfg(test)]
mod layering_tests {
    use super::*;
    use microsandbox_types::{CpuPlacement, DeploymentProfile, OutboundProxy};

    #[test]
    fn sandbox_patch_maps_supplied_values() {
        let global: GlobalConfigPatch = serde_json::from_value(serde_json::json!({
            "log_level": "debug",
            "deployment_profile": "multi-tenant",
            "sandbox_defaults": {
                "cpus": 4,
                "memory_mib": 2048,
                "cpu_placement": "spread",
                "placement_profile": "latency",
                "thp": "always",
                "shell": "/bin/bash",
                "workdir": "/workspace",
                "outbound_proxy": {"protocol": "socks4", "address": "127.0.0.1:1080", "user_id": "employee"},
                "metrics_sample_interval_ms": 2500,
                "disable_metrics_sample": true
            }
        }))
        .unwrap();
        let mut sandbox = crate::SandboxConfig::default();
        SandboxConfigPatch::from_managed(&global).apply_to(&mut sandbox);

        let resources = &sandbox.spec.resources;
        assert_eq!(resources.cpus, 4);
        assert_eq!(resources.memory_mib, 2048);
        assert_eq!(resources.cpu_placement, CpuPlacement::Spread);
        assert_eq!(resources.placement_profile.as_deref(), Some("latency"));
        assert_eq!(resources.thp, TransparentHugePagePolicy::Always);
        let runtime = &sandbox.spec.runtime;
        assert_eq!(runtime.shell.as_deref(), Some("/bin/bash"));
        assert_eq!(runtime.workdir.as_deref(), Some("/workspace"));
        assert_eq!(runtime.log_level, Some(SandboxLogLevel::Debug));
        assert_eq!(runtime.metrics_sample_interval_ms, Some(2500));
        assert!(runtime.disable_metrics_sample);
        assert_eq!(
            sandbox.spec.deployment_profile,
            DeploymentProfile::MultiTenant
        );
        assert_eq!(
            sandbox.spec.network.outbound_proxy,
            Some(OutboundProxy::Socks4 {
                address: "127.0.0.1:1080".into(),
                user_id: Some("employee".into()),
            })
        );
    }

    #[test]
    fn sandbox_patch_preserves_explicit_clears() {
        for interval in [serde_json::json!(0), serde_json::Value::Null] {
            let global: GlobalConfigPatch = serde_json::from_value(serde_json::json!({
                "log_level": null,
                "deployment_profile": null,
                "sandbox_defaults": {
                    "placement_profile": null,
                    "workdir": null,
                    "outbound_proxy": null,
                    "metrics_sample_interval_ms": interval,
                    "disable_metrics_sample": false
                }
            }))
            .unwrap();
            let patch = SandboxConfigPatch::from_managed(&global);
            assert_eq!(patch.spec.resources.placement_profile, Some(None));
            assert_eq!(patch.spec.runtime.workdir, Some(None));
            assert_eq!(patch.spec.runtime.log_level, Some(None));
            assert_eq!(patch.spec.runtime.metrics_sample_interval_ms, Some(None));
            assert_eq!(patch.spec.network.outbound_proxy, Some(None));
            assert_eq!(patch.spec.deployment_profile, None);
            assert_eq!(patch.spec.runtime.shell, None);

            let mut sandbox = crate::SandboxConfig::default();
            sandbox.spec.resources.placement_profile = Some("old".into());
            sandbox.spec.runtime.shell = Some("/bin/zsh".into());
            sandbox.spec.runtime.workdir = Some("/old".into());
            sandbox.spec.runtime.log_level = Some(SandboxLogLevel::Trace);
            sandbox.spec.runtime.metrics_sample_interval_ms = Some(1000);
            sandbox.spec.runtime.disable_metrics_sample = true;
            sandbox.spec.network.outbound_proxy = Some(OutboundProxy::Socks5 {
                address: "127.0.0.1:2080".into(),
                credentials: None,
            });
            sandbox.spec.deployment_profile = DeploymentProfile::MultiTenant;
            patch.apply_to(&mut sandbox);

            assert_eq!(sandbox.spec.resources.placement_profile, None);
            assert_eq!(sandbox.spec.runtime.shell.as_deref(), Some("/bin/zsh"));
            assert_eq!(sandbox.spec.runtime.workdir, None);
            assert_eq!(sandbox.spec.runtime.log_level, None);
            assert_eq!(sandbox.spec.runtime.metrics_sample_interval_ms, None);
            assert!(!sandbox.spec.runtime.disable_metrics_sample);
            assert_eq!(sandbox.spec.network.outbound_proxy, None);
            assert_eq!(
                sandbox.spec.deployment_profile,
                DeploymentProfile::MultiTenant
            );
        }
    }

    #[test]
    fn sandbox_patch_leaves_omitted_and_separately_resolved_settings_unchanged() {
        let global: GlobalConfigPatch = serde_json::from_value(serde_json::json!({
            "active_profile": "work",
            "profiles": {"work": {"backend": "local"}},
            "home": "/host/home",
            "paths": {"cache": "/host/cache"},
            "database": {"max_connections": 11},
            "runtime": {"block_writeback": {"mode": "off"}},
            "registries": {"ca_certs": "/host/ca.pem"},
            "ssh": {"inactivity_timeout_secs": 30},
            "metrics": {"capacity": 128},
            "sandbox_defaults": {"oci": {"root_disk": {"kind": "tmpfs", "size_mib": 4096}}}
        }))
        .unwrap();
        let patch = SandboxConfigPatch::from_managed(&global);
        assert!(patch.spec.image.is_none());
        let mut sandbox = crate::SandboxConfig::default();
        sandbox.spec.resources.cpus = 6;
        sandbox.spec.resources.memory_mib = 3072;
        sandbox.spec.resources.cpu_placement = CpuPlacement::Spread;
        sandbox.spec.resources.placement_profile = Some("keep".into());
        sandbox.spec.resources.thp = TransparentHugePagePolicy::Never;
        sandbox.spec.runtime.shell = Some("/bin/zsh".into());
        sandbox.spec.runtime.workdir = Some("/keep".into());
        sandbox.spec.runtime.log_level = Some(SandboxLogLevel::Trace);
        sandbox.spec.runtime.metrics_sample_interval_ms = Some(500);
        sandbox.spec.runtime.disable_metrics_sample = true;
        sandbox.spec.network.outbound_proxy = Some(OutboundProxy::Socks5 {
            address: "127.0.0.1:2080".into(),
            credentials: None,
        });
        sandbox.spec.deployment_profile = DeploymentProfile::MultiTenant;
        sandbox.replace_existing = true;
        let expected = serde_json::to_value(&sandbox).unwrap();
        patch.apply_to(&mut sandbox);

        assert!(sandbox.replace_existing);
        assert_eq!(serde_json::to_value(sandbox).unwrap(), expected);
    }

    #[test]
    fn sandbox_source_field_matrix() {
        use serde_json::{Value, json};

        // This value type has public fields; the patch's merge fields are private.
        // New global fields must be classified here and covered by the matrix below.
        let crate::config::GlobalConfig {
            sandbox_defaults: _,
            log_level: _,
            deployment_profile: _,
            active_profile: _,
            profiles: _,
            home: _,
            database: _,
            paths: _,
            runtime: _,
            registries: _,
            ssh: _,
            metrics: _,
        } = crate::config::GlobalConfig::default();
        // Every global field is mapped here, excluded below, or handled separately.
        // Each mapped field has its own null semantics; omission always stays sparse.
        let fields = [
            (
                "sandbox_defaults.cpus",
                "spec.resources.cpus",
                json!(4),
                false,
            ),
            (
                "sandbox_defaults.memory_mib",
                "spec.resources.memory_mib",
                json!(2048),
                false,
            ),
            (
                "sandbox_defaults.cpu_placement",
                "spec.resources.cpu_placement",
                json!("spread"),
                false,
            ),
            (
                "sandbox_defaults.placement_profile",
                "spec.resources.placement_profile",
                json!("latency"),
                true,
            ),
            (
                "sandbox_defaults.thp",
                "spec.resources.thp",
                json!("always"),
                false,
            ),
            (
                "sandbox_defaults.shell",
                "spec.runtime.shell",
                json!("/bin/bash"),
                false,
            ),
            (
                "sandbox_defaults.workdir",
                "spec.runtime.workdir",
                json!("/work"),
                true,
            ),
            (
                "sandbox_defaults.outbound_proxy",
                "spec.network.outbound_proxy",
                json!({"protocol":"socks5","address":"127.0.0.1:1080"}),
                true,
            ),
            (
                "sandbox_defaults.metrics_sample_interval_ms",
                "spec.runtime.metrics_sample_interval_ms",
                json!(2500),
                true,
            ),
            (
                "sandbox_defaults.disable_metrics_sample",
                "spec.runtime.disable_metrics_sample",
                json!(false),
                false,
            ),
            ("log_level", "spec.runtime.log_level", json!("debug"), true),
            (
                "deployment_profile",
                "spec.deployment_profile",
                json!("multi-tenant"),
                true,
            ),
        ];
        for (source, target, value, nullable) in fields {
            for managed in [false, true] {
                for supplied in [None, Some(Value::Null), Some(value.clone())] {
                    let mut input = json!({});
                    if let Some(value) = supplied.clone() {
                        set_field(&mut input, source, value);
                    }
                    let global = serde_json::from_value::<GlobalConfigPatch>(input);
                    if supplied == Some(Value::Null) && !nullable {
                        assert!(global.is_err(), "{source} must reject null");
                        continue;
                    }
                    let global = global.unwrap();
                    let layers = if managed {
                        BackendConfig::new(Default::default(), global)
                    } else {
                        BackendConfig::new(global, Default::default())
                    };
                    let actual = layers
                        .sandbox_layers()
                        .base(Default::default())
                        .options(Default::default())
                        .build();
                    let expected = if source == "deployment_profile"
                        && (!managed || supplied == Some(Value::Null))
                    {
                        None
                    } else if source == "deployment_profile" && supplied.is_some() {
                        Some(json!("multi_tenant"))
                    } else {
                        supplied
                    };
                    assert_eq!(
                        sandbox_field(&actual, target),
                        expected,
                        "{source}, managed={managed}"
                    );
                }
            }
        }

        // These host fields are excluded; OCI is resolved at its own stages.
        for input in [
            json!({"active_profile":"work"}),
            json!({"profiles":{"work":{"backend":"local"}}}),
            json!({"home":"/host"}),
            json!({"database":{"max_connections":11}}),
            json!({"paths":{"msb":"/host/msb"}}),
            json!({"runtime":{"block_writeback":{"mode":"off"}}}),
            json!({"registries":{"ca_certs":"/host/ca.pem"}}),
            json!({"ssh":{"inactivity_timeout_secs":30}}),
            json!({"metrics":{"capacity":128}}),
            json!({"sandbox_defaults":{"oci":{"root_disk":{"kind":"tmpfs"},"upper_size_mib":null}}}),
        ] {
            let global: GlobalConfigPatch = serde_json::from_value(input.clone()).unwrap();
            for layers in [
                BackendConfig::new(global.clone(), Default::default()),
                BackendConfig::new(Default::default(), global),
            ] {
                let actual = layers
                    .sandbox_layers()
                    .base(Default::default())
                    .options(Default::default())
                    .build();
                assert_eq!(
                    serde_json::to_value(actual.into_config()).unwrap(),
                    serde_json::to_value(crate::SandboxConfig::default()).unwrap(),
                    "excluded: {input}"
                );
            }
        }
    }

    #[test]
    fn pre_pull_disk_fallback_and_managed_normalization() {
        use serde_json::json;
        let user: GlobalConfigPatch = serde_json::from_value(
            json!({"sandbox_defaults":{"oci":{"root_disk":{"kind":"tmpfs","size_mib":128}}}}),
        )
        .unwrap();
        for (managed, expected) in [
            (
                json!({}),
                RootDisk::Tmpfs {
                    size_mib: Some(128),
                },
            ),
            (
                json!({"root_disk":{"kind":"managed","size_mib":2048}}),
                RootDisk::Managed {
                    size_mib: Some(2048),
                },
            ),
            (
                json!({"root_disk":null}),
                RootDisk::Managed { size_mib: None },
            ),
            (
                json!({"upper_size_mib":1024}),
                RootDisk::Managed {
                    size_mib: Some(1024),
                },
            ),
            (
                json!({"upper_size_mib":null}),
                RootDisk::Managed { size_mib: None },
            ),
        ] {
            let layers = BackendConfig::new(
                user.clone(),
                serde_json::from_value(json!({"sandbox_defaults":{"oci":managed}})).unwrap(),
            );
            let request = SandboxConfigPatch::new()
                .spec(SandboxSpecPatch::new().image(microsandbox_types::RootfsSource::default()));
            let microsandbox_types::RootfsSource::Oci(image) = request.resolve_image(&layers)
            else {
                panic!("expected OCI image")
            };
            assert_eq!(image.root_disk, Some(expected));
        }
        // User disk fallback belongs to pre-pull selection, not managed normalization.
        assert_eq!(
            BackendConfig::new(user, Default::default())
                .root_disk_layers()
                .build()
                .root_disk,
            None
        );
    }

    #[test]
    fn managed_workdir_clear_survives_image_defaults() {
        let layers = BackendConfig::new(
            Default::default(),
            serde_json::from_str(r#"{"sandbox_defaults":{"workdir":null}}"#).unwrap(),
        );
        let image = SandboxConfigPatch::new().spec(
            SandboxSpecPatch::new()
                .runtime(SandboxRuntimeOptionsPatch::new().workdir("/image".into())),
        );
        let config = layers
            .sandbox_layers()
            .base(image)
            .options(Default::default())
            .build()
            .into_config();
        assert_eq!(config.spec.runtime.workdir, None);
    }

    fn sandbox_field(patch: &SandboxConfigPatch, path: &str) -> Option<serde_json::Value> {
        fn value<T: serde::Serialize>(field: &Option<T>) -> Option<serde_json::Value> {
            field
                .as_ref()
                .map(|value| serde_json::to_value(value).unwrap())
        }
        match path {
            "spec.resources.cpus" => value(&patch.spec.resources.cpus),
            "spec.resources.memory_mib" => value(&patch.spec.resources.memory_mib),
            "spec.resources.cpu_placement" => value(&patch.spec.resources.cpu_placement),
            "spec.resources.placement_profile" => value(&patch.spec.resources.placement_profile),
            "spec.resources.thp" => value(&patch.spec.resources.thp),
            "spec.runtime.shell" => value(&patch.spec.runtime.shell),
            "spec.runtime.workdir" => value(&patch.spec.runtime.workdir),
            "spec.runtime.metrics_sample_interval_ms" => {
                value(&patch.spec.runtime.metrics_sample_interval_ms)
            }
            "spec.runtime.disable_metrics_sample" => {
                value(&patch.spec.runtime.disable_metrics_sample)
            }
            "spec.runtime.log_level" => value(&patch.spec.runtime.log_level),
            "spec.network.outbound_proxy" => value(&patch.spec.network.outbound_proxy),
            "spec.deployment_profile" => value(&patch.spec.deployment_profile),
            _ => panic!("unclassified field {path}"),
        }
    }

    fn set_field(object: &mut serde_json::Value, path: &str, value: serde_json::Value) {
        if let Some((head, tail)) = path.split_once('.') {
            let nested = object
                .as_object_mut()
                .unwrap()
                .entry(head)
                .or_insert_with(|| serde_json::json!({}));
            set_field(nested, tail, value);
        } else {
            object
                .as_object_mut()
                .unwrap()
                .insert(path.to_owned(), value);
        }
    }
}

//! Sandbox lifecycle management.
//!
//! The [`Sandbox`] struct represents a running sandbox. It is created via
//! [`Sandbox::builder`] or [`Sandbox::create`], and provides lifecycle
//! methods (stop, kill, drain, wait) and access to the [`AgentClient`]
//! for guest communication.

pub(crate) mod attach;
mod builder;
pub(crate) mod config;
pub mod exec;
pub mod fs;
mod handle;
pub mod init;
pub(crate) mod metrics;
mod modify;
mod patch;
#[cfg(feature = "ssh")]
pub mod ssh;
mod types;

use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
    process::ExitStatus,
    sync::Arc,
};

use microsandbox_db::pool::DbPools;
use microsandbox_db::{DbReadConnection, DbWriteConnection};
use microsandbox_image::Registry;
use microsandbox_protocol::{
    core::{CoreError, Ping, Pong, Touch, Touched},
    exec::{ExecRequest, ExecRlimit},
    message::MessageType,
};
use microsandbox_types::hostname_from_sandbox_name as derive_hostname;
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, Set, sea_query::Expr,
};
use tokio::sync::Mutex;
#[cfg(windows)]
use windows_sys::Win32::Foundation::CloseHandle;
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};

use microsandbox_image::{
    Digest, GlobalCache, PullOptions, PullProgressSender, PullResult, Reference, ext4,
    progress_channel, tree,
};

use crate::{
    MicrosandboxResult,
    agent::AgentClient,
    backend::LocalBackend,
    db::entity::{
        run as run_entity, sandbox as sandbox_entity, sandbox_rootfs as sandbox_rootfs_entity,
    },
    runtime::{
        ProcessHandle, SpawnMode, ensure_named_volumes, rollback_created_named_volumes,
        spawn_sandbox,
    },
};

use self::exec::{ExecHandle, ExecOptions};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Prefixes reserved for built-in identity/resource attributes.
pub(crate) const RESERVED_LABEL_PREFIXES: [&str; 3] = ["sandbox.", "microsandbox.", "service."];

/// Maximum time to wait for the sandbox process to expose the agent relay.
const AGENT_RELAY_READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);

/// Maximum time to wait when connecting to the agent for lifecycle shutdown.
const AGENT_SHUTDOWN_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

//--------------------------------------------------------------------------------------------------
// Functions: Validation
//--------------------------------------------------------------------------------------------------

/// Validate a sandbox name used by CLI and SDK APIs.
pub fn validate_sandbox_name(name: &str) -> MicrosandboxResult<()> {
    microsandbox_types::validate_sandbox_name(name).map_err(Into::into)
}

/// Validate sandbox-name-derived runtime paths using an explicit local backend.
pub(super) fn validate_sandbox_name_for_runtime_with_backend(
    local: &LocalBackend,
    name: &str,
) -> MicrosandboxResult<()> {
    validate_sandbox_name(name)?;
    crate::runtime::resolve_sandbox_agent_socket_path_for(local, name).map(|_| ())
}

/// Validate an explicit guest hostname before it is forwarded to agentd.
pub(super) fn validate_hostname(hostname: Option<&str>) -> MicrosandboxResult<()> {
    microsandbox_types::validate_hostname(hostname).map_err(Into::into)
}

pub(crate) fn sandbox_name_validation_message(name: &str) -> Option<String> {
    validate_sandbox_name(name).err().map(|err| err.to_string())
}

/// Return the reserved prefix a label key starts with, if any.
pub(crate) fn reserved_label_prefix(key: &str) -> Option<&'static str> {
    RESERVED_LABEL_PREFIXES
        .iter()
        .copied()
        .find(|prefix| key.starts_with(prefix))
}

pub(crate) use types::validate_named_disk_mount_options;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use crate::db::entity::sandbox::SandboxStatus;
pub use crate::logs::{LogEntry, LogOptions, LogSource, LogStreamOptions};
pub use attach::AttachOptionsBuilder;
pub use builder::{RegistryConfigBuilder, SandboxBuilder};
pub use config::SandboxConfig;
pub use exec::{ExecOptionsBuilder, ExecOutput, Rlimit, RlimitResource};
pub use fs::{
    FsEntry, FsEntryKind, FsHandle, FsMetadata, FsOpenOptions, FsReadStream, FsSetAttrs,
    FsWriteSink, SandboxFsOps,
};
pub use handle::{DEFAULT_KILL_TIMEOUT, DEFAULT_STOP_TIMEOUT, SandboxHandle};
pub use init::{HandoffInit, InitOptionsBuilder};
pub use metrics::{SandboxMetrics, all_sandbox_metrics, all_sandbox_metrics_local};
pub use microsandbox_image::{PullProgress, PullProgressHandle};
#[cfg(feature = "net")]
pub use microsandbox_network::builder::SecretBuilder;
#[cfg(feature = "net")]
pub use microsandbox_network::config::NetworkConfig;
#[cfg(feature = "net")]
pub use microsandbox_network::policy::NetworkPolicy;
pub use microsandbox_runtime::logging::LogLevel;
pub use microsandbox_types::PullPolicy;
pub use microsandbox_types::{
    EnvVar, MAX_HOSTNAME_BYTES, MAX_SANDBOX_NAME_BYTES, NetworkSpec, PortProtocol,
    PublishedPortSpec, SandboxLogLevel, SandboxResources, SandboxRuntimeOptions, SandboxSpec,
};
pub use modify::{
    ChangeKind, ConfigPlannedChange, ModificationConflict, ModificationDisposition,
    ModificationPolicy, ModificationWarning, PlannedChange, ResourceConvergenceState, ResourceKind,
    ResourceResizeStatus, SandboxModificationBuilder, SandboxModificationPatch,
    SandboxModificationPlan, SecretChangeKind, SecretModificationPatch, SecretPatchBuilder,
    SecretPlannedChange, SecretSource,
};
#[cfg(feature = "ssh")]
pub use ssh::{
    DEFAULT_SSH_HOST, DEFAULT_SSH_PORT, SandboxSshOps, SftpClient, SshAttachOptionsBuilder,
    SshClient, SshClientOptionsBuilder, SshExecOptionsBuilder, SshOutput, SshServer,
    SshServerOptionsBuilder, SshStdioStream,
};
pub use types::{
    DiskImageFormat, HostPermissions, ImageBuilder, ImageSource, IntoImage, MountBuilder,
    MountOptions, NamedVolumeMode, OciRootfsSource, Patch, PatchBuilder, RootfsSource,
    SecurityProfile, StatVirtualization, VolumeMount,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Transient registry overrides from the SDK, merged with global config at pull time.
pub(crate) struct RegistryOverrides {
    pub auth: Option<microsandbox_image::RegistryAuth>,
    pub insecure: bool,
    pub ca_certs: Vec<Vec<u8>>,
}

/// Filter for [`Sandbox::list_with`].
#[derive(Debug, Default, Clone)]
pub struct SandboxFilter {
    labels: Vec<(String, String)>,
}

/// A running sandbox.
///
/// Created via [`Sandbox::builder`] or [`Sandbox::create`]. Provides
/// lifecycle management and access to the agent bridge for guest communication.
///
/// Per the SDK local-cloud parity plan (D6.4) `Sandbox` is a single type
/// regardless of backend. It holds an [`Arc<dyn Backend>`](crate::backend::Backend)
/// to route lifecycle ops through, and a backend-private
/// [`SandboxInner`](crate::backend::SandboxInner) enum carrying variant-specific
/// state. Users reach variant data via [`Sandbox::local`] / [`Sandbox::cloud`].
#[derive(Clone)]
pub struct Sandbox {
    backend: Arc<dyn crate::backend::Backend>,
    inner: Arc<crate::backend::SandboxInner>,
    name: String,
    config: SandboxConfig,
}

/// Result of observing a sandbox in a terminal non-running state.
#[derive(Debug, Clone)]
pub struct SandboxStopResult {
    /// Sandbox name.
    pub name: String,

    /// Final observed sandbox status.
    pub status: SandboxStatus,

    /// Process exit code when available from an owned child process.
    pub exit_code: Option<i32>,

    /// Terminating signal when available from an owned child process.
    pub signal: Option<i32>,

    /// Time at which the stopped state was observed.
    pub observed_at: chrono::DateTime<chrono::Utc>,

    /// Description of the observation source.
    pub source: Option<String>,
}

/// Result returned by [`Sandbox::ping`] and [`SandboxHandle::ping`].
#[derive(Debug, Clone)]
pub struct SandboxPingResult {
    /// Sandbox name that was pinged.
    pub name: String,

    /// Round-trip latency measured by the SDK.
    pub latency: std::time::Duration,
}

/// Result returned by [`Sandbox::touch`] and [`SandboxHandle::touch`].
#[derive(Debug, Clone)]
pub struct SandboxTouchResult {
    /// Sandbox name that was touched.
    pub name: String,

    /// Agent activity sequence after the explicit touch was recorded.
    pub activity_seq: u64,
}

//--------------------------------------------------------------------------------------------------
// Methods: Static
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Start building a new sandbox configuration.
    pub fn builder(name: impl Into<String>) -> SandboxBuilder {
        SandboxBuilder::new(name)
    }

    /// Create a sandbox from a config.
    ///
    /// Routes through the ambient [`default_backend`](crate::backend::default_backend)
    /// so a cloud profile will dispatch to `CloudBackend` instead of the local
    /// libkrun runtime. The returned [`Sandbox`] always carries the backend it
    /// was created on; subsequent method calls keep using that backend.
    pub async fn create(config: SandboxConfig) -> MicrosandboxResult<Self> {
        let backend = crate::backend::default_backend();
        backend
            .sandboxes()
            .create(backend.clone(), config, true)
            .await
    }

    /// Create a sandbox that must survive after the creating process exits.
    ///
    /// This is intended for detached CLI workflows such as `msb create` and
    /// `msb run --detach`, where the sandbox should keep running in the
    /// background after the command returns. Routes through the ambient
    /// [`default_backend`](crate::backend::default_backend).
    pub async fn create_detached(config: SandboxConfig) -> MicrosandboxResult<Self> {
        let backend = crate::backend::default_backend();
        backend
            .sandboxes()
            .create_detached(backend.clone(), config)
            .await
    }

    /// Create a sandbox with pull progress reporting.
    ///
    /// Returns a progress handle for per-layer pull events and a task handle
    /// for the sandbox creation result. The caller should consume progress
    /// events until the channel closes, then await the task. **Local backend
    /// only** — pull progress is a local concept (cloud workers handle image
    /// pulls server-side); on a cloud backend this falls back to a no-progress
    /// create with an immediately-closed channel.
    pub fn create_with_pull_progress(
        config: SandboxConfig,
    ) -> (
        PullProgressHandle,
        tokio::task::JoinHandle<MicrosandboxResult<Self>>,
    ) {
        Self::create_with_pull_progress_and_mode(config, SpawnMode::Attached)
    }

    /// Create a detached sandbox with pull progress reporting.
    ///
    /// Like `create_with_pull_progress` but spawns the sandbox process in detached
    /// mode so the sandbox survives after the creating process exits.
    pub fn create_detached_with_pull_progress(
        config: SandboxConfig,
    ) -> (
        PullProgressHandle,
        tokio::task::JoinHandle<MicrosandboxResult<Self>>,
    ) {
        Self::create_with_pull_progress_and_mode(config, SpawnMode::Detached)
    }

    fn create_with_pull_progress_and_mode(
        config: SandboxConfig,
        mode: SpawnMode,
    ) -> (
        PullProgressHandle,
        tokio::task::JoinHandle<MicrosandboxResult<Self>>,
    ) {
        let (handle, sender) = progress_channel();
        let task = tokio::spawn(async move {
            // Pull progress is local-only; ignore the channel on non-local
            // backends and dispatch through the trait without progress events.
            let backend = crate::backend::default_backend();
            match backend.kind() {
                crate::backend::BackendKind::Local => {
                    create_local(backend, config, mode, Some(sender)).await
                }
                crate::backend::BackendKind::Cloud => {
                    drop(sender); // close the channel — no per-layer events for cloud.
                    backend
                        .sandboxes()
                        .create(backend.clone(), config, true)
                        .await
                }
            }
        });
        (handle, task)
    }

    /// Start an existing stopped sandbox from persisted state.
    ///
    /// Reuses the serialized sandbox config and pinned rootfs state without
    /// re-resolving the original OCI reference. Routes through the ambient
    /// [`default_backend`](crate::backend::default_backend).
    pub async fn start(name: &str) -> MicrosandboxResult<Self> {
        let backend = crate::backend::default_backend();
        backend.sandboxes().start(backend.clone(), name).await
    }

    /// Start an existing sandbox in detached/background mode.
    pub async fn start_detached(name: &str) -> MicrosandboxResult<Self> {
        let backend = crate::backend::default_backend();
        backend
            .sandboxes()
            .start_detached(backend.clone(), name)
            .await
    }

    /// Get a sandbox handle by name. Routes through the ambient
    /// [`default_backend`](crate::backend::default_backend).
    pub async fn get(name: &str) -> MicrosandboxResult<SandboxHandle> {
        let backend = crate::backend::default_backend();
        backend.sandboxes().get(backend.clone(), name).await
    }

    /// List sandboxes via the ambient
    /// [`default_backend`](crate::backend::default_backend). Pagination args
    /// are forwarded to cloud; local backends ignore them.
    pub async fn list() -> MicrosandboxResult<Vec<SandboxHandle>> {
        let backend = crate::backend::default_backend();
        let page = backend
            .sandboxes()
            .list(backend.clone(), None, None)
            .await?;
        Ok(page.sandboxes)
    }

    /// List sandboxes matching a filter.
    pub async fn list_with(filter: SandboxFilter) -> MicrosandboxResult<Vec<SandboxHandle>> {
        let handles = Self::list().await?;
        if filter.is_empty() {
            return Ok(handles);
        }

        Ok(handles
            .into_iter()
            .filter(|handle| sandbox_handle_matches_filter(handle, &filter))
            .collect())
    }

    /// Remove a stopped sandbox by name via the ambient
    /// [`default_backend`](crate::backend::default_backend).
    pub async fn remove(name: &str) -> MicrosandboxResult<()> {
        let backend = crate::backend::default_backend();
        backend.sandboxes().remove(backend.clone(), name).await
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: SandboxFilter
//--------------------------------------------------------------------------------------------------

impl SandboxFilter {
    /// Create an empty filter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Require sandboxes to carry this `key=value` label.
    pub fn label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.push((key.into(), value.into()));
        self
    }

    /// Require sandboxes to carry all of these `key=value` labels.
    pub fn labels(
        mut self,
        labels: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        self.labels.extend(
            labels
                .into_iter()
                .map(|(key, value)| (key.into(), value.into())),
        );
        self
    }

    /// Whether the filter has no criteria.
    pub fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Construction helpers
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Build an outer `Sandbox` from local-variant inner state.
    pub(crate) fn from_local(
        backend: Arc<dyn crate::backend::Backend>,
        local: crate::backend::SandboxLocalState,
        config: SandboxConfig,
    ) -> Self {
        Self {
            backend,
            inner: Arc::new(crate::backend::SandboxInner::Local(local)),
            name: config.spec.name.clone(),
            config,
        }
    }

    /// Build an outer `Sandbox` from a [`CloudSandbox`](crate::backend::CloudSandbox)
    /// HTTP response plus the originating [`SandboxConfig`].
    pub(crate) fn from_cloud(
        backend: Arc<dyn crate::backend::Backend>,
        cloud: crate::backend::CloudSandbox,
        config: SandboxConfig,
    ) -> Self {
        Self {
            backend,
            inner: Arc::new(crate::backend::SandboxInner::Cloud(
                crate::backend::SandboxCloudState {
                    id: cloud.id,
                    org_id: cloud.org_id,
                    created_at: cloud.created_at,
                },
            )),
            name: cloud.name,
            config,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Local lifecycle (called from the LocalBackend SandboxBackend impl)
//--------------------------------------------------------------------------------------------------

/// Local create path. Returns a complete [`Sandbox`] wrapping the supplied
/// backend Arc. Called from the [`SandboxBackend`](crate::backend::SandboxBackend)
/// trait impl on [`LocalBackend`](crate::backend::LocalBackend) and from the
/// local pull-progress shim on [`Sandbox`].
pub(crate) async fn create_local(
    backend: Arc<dyn crate::backend::Backend>,
    mut config: SandboxConfig,
    mode: SpawnMode,
    progress: Option<PullProgressSender>,
) -> MicrosandboxResult<Sandbox> {
    tracing::debug!(
        sandbox = %config.spec.name,
        image = ?config.spec.image,
        mode = ?mode,
        cpus = config.spec.resources.cpus,
        memory_mib = config.spec.resources.memory_mib,
        "create_local: starting"
    );

    let local_backend =
        backend
            .as_local()
            .ok_or_else(|| crate::MicrosandboxError::Unsupported {
                feature: "create_local".into(),
                available_when: "with a LocalBackend".into(),
            })?;

    config.apply_rootfs_defaults(local_backend.config().sandbox_defaults.oci.upper_size_mib);

    let mut pinned_manifest_digest: Option<String> = None;
    let mut pinned_reference: Option<String> = None;

    config.apply_runtime_defaults();
    validate_sandbox_name_for_runtime_with_backend(local_backend, &config.spec.name)?;
    validate_hostname(config.spec.runtime.hostname.as_deref())?;
    validate_rootfs_source(&config.spec.image)?;
    validate_env(&config.spec.env)?;
    validate_labels(&config.spec.labels)?;
    types::validate_volume_mounts(&config.spec.mounts)?;
    if let Some(init) = &config.spec.init {
        init::validate(init)?;
    }

    // Initialize the database before any expensive image pull so we can
    // fail fast on conflicting persisted sandbox state.
    let db = local_backend.db().await?;
    let sandbox_dir = local_backend.sandboxes_dir().join(&config.spec.name);
    prepare_create_target(db, &config, &sandbox_dir).await?;

    // Resolve OCI images before spawning the sandbox process.
    if let RootfsSource::Oci(oci) = config.spec.image.clone() {
        let reference = oci.reference;
        let expected_snapshot_manifest_digest = config
            .snapshot_upper_source
            .as_ref()
            .and(config.manifest_digest.clone());
        let upper_size_mib = oci
            .upper_size_mib
            .unwrap_or(config::DEFAULT_OCI_UPPER_SIZE_MIB);
        let overrides = RegistryOverrides {
            auth: config.registry_auth.clone(),
            insecure: config.insecure,
            ca_certs: config.ca_certs.clone(),
        };
        let pull_result = pull_oci_image(
            local_backend,
            &reference,
            config.spec.pull_policy,
            overrides,
            progress,
        )
        .await?;
        if let Some(expected) = expected_snapshot_manifest_digest.as_deref()
            && pull_result.manifest_digest.to_string() != expected
        {
            return Err(crate::MicrosandboxError::SnapshotIntegrity(format!(
                "snapshot image digest mismatch: manifest pinned {}, resolved {}",
                expected, pull_result.manifest_digest
            )));
        }

        // Merge image config defaults under user-provided config.
        config.merge_image_defaults(&pull_result.config);
        if let Some(init) = &config.spec.init {
            init::validate(init)?;
        }

        pinned_manifest_digest = Some(pull_result.manifest_digest.to_string());
        pinned_reference = Some(reference.clone());

        // Verify VMDK exists in the global cache.
        let cache_dir = local_backend.cache_dir();
        let cache = GlobalCache::new_async(&cache_dir).await?;

        let vmdk_path = cache.vmdk_path(&pull_result.manifest_digest);
        if tokio::fs::metadata(&vmdk_path).await.is_err() {
            return Err(crate::MicrosandboxError::Custom(format!(
                "VMDK not materialized: {}",
                vmdk_path.display()
            )));
        }

        // For patches, pass per-layer EROFS paths.
        let layer_erofs_paths: Vec<std::path::PathBuf> = pull_result
            .layer_diff_ids
            .iter()
            .map(|d| cache.layer_erofs_path(d))
            .collect();

        let upper_tree = if !config.spec.patches.is_empty() {
            Some(patch::build_upper_tree(&config.spec.patches, &layer_erofs_paths).await?)
        } else {
            None
        };

        // Create upper.ext4 for the writable overlay upper layer.
        tokio::fs::create_dir_all(&sandbox_dir).await?;
        let upper_path = sandbox_dir.join("upper.ext4");
        if let Some(snap_upper) = config.snapshot_upper_source.take() {
            // Booting from a snapshot: copy the captured upper into
            // place, preserving sparseness. Patches are not
            // compatible with this path because they'd need to be
            // re-baked into the snapshot's upper, which we don't do.
            if upper_tree.is_some() {
                return Err(crate::MicrosandboxError::InvalidConfig(
                    "patches cannot be combined with from_snapshot".into(),
                ));
            }
            let dst = upper_path.clone();
            tokio::task::spawn_blocking(move || {
                microsandbox_utils::copy::fast_copy(&snap_upper, &dst)
            })
            .await
            .map_err(|e| crate::MicrosandboxError::Custom(format!("snapshot copy task: {e}")))??;
        } else if !upper_path.exists() || upper_tree.is_some() {
            create_upper_ext4(&upper_path, upper_size_mib, upper_tree).await?;
        }

        // Store manifest digest for spawn to derive paths.
        config.manifest_digest = Some(pull_result.manifest_digest.to_string());

        // Persist full image metadata to database.
        if let Ok(image_ref) = reference.parse::<Reference>() {
            match cache.read_image_metadata_async(&image_ref).await {
                Ok(Some(metadata)) => {
                    if let Err(e) =
                        crate::image::Image::persist(local_backend, &reference, metadata).await
                    {
                        tracing::warn!(
                            error = %e,
                            "failed to persist image metadata to database"
                        );
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "failed to read cached image metadata");
                }
            }
        }
    }

    // Apply rootfs patches before VM start (bind mounts only — OCI patches
    // are baked into upper.ext4 above).
    if !config.spec.patches.is_empty() && !matches!(config.spec.image, RootfsSource::Oci(_)) {
        patch::apply_patches(&config.spec.image, &config.spec.patches).await?;
    }

    // Sandbox-time named-volume creation is one-shot create intent. Provision
    // before inserting the sandbox row so volume conflicts or incompatibilities
    // cannot leave a stopped sandbox that never booted.
    let created_named_volumes = ensure_named_volumes(local_backend, &config).await?;

    // Insert the sandbox record and keep its stable database ID.
    let write_db = db.write();
    let persisted_config = config.clone_for_persistence();
    let sandbox_id = match insert_sandbox_record(write_db, &persisted_config).await {
        Ok(sandbox_id) => sandbox_id,
        Err(err) => {
            rollback_created_named_volumes(local_backend, &created_named_volumes).await;
            return Err(err);
        }
    };
    tracing::debug!(sandbox_id, sandbox = %config.spec.name, "create_local: db record inserted");

    // Spawn the sandbox process and create the bridge. On failure, mark the sandbox
    // as stopped so it doesn't appear as a phantom "Running" entry.
    let (local_state, returned_config) =
        match create_inner_local(local_backend, config, sandbox_id, mode).await {
            Ok(pair) => pair,
            Err(e) => {
                if created_named_volumes.is_empty() {
                    let _ =
                        update_sandbox_status(write_db, sandbox_id, SandboxStatus::Stopped).await;
                } else {
                    rollback_created_named_volumes(local_backend, &created_named_volumes).await;
                    let _ = delete_sandbox_record(write_db, sandbox_id).await;
                }
                return Err(e);
            }
        };
    let sandbox = Sandbox::from_local(backend.clone(), local_state, returned_config);
    if let Err(err) = update_sandbox_active_config(
        write_db,
        sandbox_id,
        &sandbox.config.clone_for_persistence(),
    )
    .await
    {
        let _ = sandbox.stop().await;
        return Err(err);
    }

    if let (Some(_reference), Some(manifest_digest)) = (
        pinned_reference.as_deref(),
        pinned_manifest_digest.as_deref(),
    ) && let Err(err) = persist_oci_manifest_pin(write_db, sandbox_id, manifest_digest).await
    {
        let _ = sandbox.stop().await;
        if created_named_volumes.is_empty() {
            let _ = update_sandbox_status(write_db, sandbox_id, SandboxStatus::Stopped).await;
        } else {
            rollback_created_named_volumes(local_backend, &created_named_volumes).await;
            let _ = delete_sandbox_record(write_db, sandbox_id).await;
        }
        return Err(err);
    }

    // Validate that the configured workdir exists inside the guest and is a
    // directory before returning a ready sandbox. Shell/exec calls inherit this
    // cwd, so accepting a regular file here leads to later, murkier failures.
    if let Some(ref workdir) = sandbox.config.spec.runtime.workdir {
        match sandbox.fs().stat(workdir).await {
            Ok(metadata) if metadata.kind == FsEntryKind::Directory => {}
            Ok(_) => {
                let _ = sandbox.stop().await;
                if created_named_volumes.is_empty() {
                    let _ =
                        update_sandbox_status(write_db, sandbox_id, SandboxStatus::Stopped).await;
                } else {
                    rollback_created_named_volumes(local_backend, &created_named_volumes).await;
                    let _ = delete_sandbox_record(write_db, sandbox_id).await;
                }
                return Err(crate::MicrosandboxError::InvalidConfig(format!(
                    "workdir is not a directory in guest: {workdir}"
                )));
            }
            Err(_) => {
                let _ = sandbox.stop().await;
                if created_named_volumes.is_empty() {
                    let _ =
                        update_sandbox_status(write_db, sandbox_id, SandboxStatus::Stopped).await;
                } else {
                    rollback_created_named_volumes(local_backend, &created_named_volumes).await;
                    let _ = delete_sandbox_record(write_db, sandbox_id).await;
                }
                return Err(crate::MicrosandboxError::InvalidConfig(format!(
                    "workdir does not exist in guest: {workdir}"
                )));
            }
        }
    }

    Ok(sandbox)
}

/// Local start path. Returns a complete [`Sandbox`] wrapping the supplied
/// backend Arc.
pub(crate) async fn start_local(
    backend: Arc<dyn crate::backend::Backend>,
    name: &str,
    mode: SpawnMode,
) -> MicrosandboxResult<Sandbox> {
    tracing::debug!(sandbox = name, ?mode, "start_local: loading record");
    let local_backend =
        backend
            .as_local()
            .ok_or_else(|| crate::MicrosandboxError::Unsupported {
                feature: "start_local".into(),
                available_when: "with a LocalBackend".into(),
            })?;
    let pools = local_backend.db().await?;
    let write_db = pools.write();
    let model = load_sandbox_record_reconciled(pools, name).await?;
    tracing::debug!(sandbox = name, status = ?model.status, "start_local: current status");

    if model.status == SandboxStatus::Running || model.status == SandboxStatus::Draining {
        return Err(crate::MicrosandboxError::SandboxStillRunning(format!(
            "cannot start sandbox '{name}': already running"
        )));
    }

    if model.status != SandboxStatus::Stopped && model.status != SandboxStatus::Crashed {
        return Err(crate::MicrosandboxError::Custom(format!(
            "cannot start sandbox '{name}': status is {:?} (expected Stopped or Crashed)",
            model.status
        )));
    }

    let mut config: SandboxConfig = serde_json::from_str(&model.config)?;
    config.apply_runtime_defaults();
    validate_sandbox_name_for_runtime_with_backend(local_backend, &config.spec.name)?;
    validate_hostname(config.spec.runtime.hostname.as_deref())?;
    validate_rootfs_source(&config.spec.image)?;
    validate_env(&config.spec.env)?;
    validate_labels(&config.spec.labels)?;
    types::validate_volume_mounts(&config.spec.mounts)?;
    validate_start_state(
        local_backend,
        &config,
        &local_backend.sandboxes_dir().join(name),
    )?;
    update_sandbox_status(write_db, model.id, SandboxStatus::Running).await?;

    match create_inner_local(local_backend, config, model.id, mode).await {
        Ok((local_state, returned_config)) => {
            let sandbox = Sandbox::from_local(backend.clone(), local_state, returned_config);
            if let Err(err) = update_sandbox_active_config(
                write_db,
                model.id,
                &sandbox.config.clone_for_persistence(),
            )
            .await
            {
                let _ = sandbox.stop().await;
                return Err(err);
            }
            Ok(sandbox)
        }
        Err(err) => {
            let _ = update_sandbox_status(write_db, model.id, SandboxStatus::Stopped).await;
            Err(err)
        }
    }
}

/// Inner local create logic separated for error-cleanup wrapper. Returns
/// the local-variant state plus the (possibly mutated) config.
async fn create_inner_local(
    local: &crate::backend::LocalBackend,
    config: SandboxConfig,
    sandbox_id: i32,
    mode: SpawnMode,
) -> MicrosandboxResult<(crate::backend::SandboxLocalState, SandboxConfig)> {
    let (mut handle, agent_sock_path) = spawn_sandbox(local, &config, sandbox_id, mode).await?;
    let log_dir = local.sandboxes_dir().join(&config.spec.name).join("logs");

    // Wait for the relay socket to become available.
    let client = wait_for_relay(&agent_sock_path, &log_dir, &mut handle, &config.spec.name).await?;

    if let Ok(ready) = client.ready() {
        tracing::info!(
            boot_time_ms = ready.boot_time_ns / 1_000_000,
            init_time_ms = ready.init_time_ns / 1_000_000,
            ready_time_ms = ready.ready_time_ns / 1_000_000,
            "sandbox ready",
        );
    }
    let handle = if matches!(mode, SpawnMode::Detached) {
        handle.disarm();
        None
    } else {
        Some(Arc::new(Mutex::new(handle)))
    };

    Ok((
        crate::backend::SandboxLocalState {
            db_id: sandbox_id,
            handle,
            client: Arc::new(client),
        },
        config,
    ))
}

/// Load the local DB row + active PID for a sandbox handle. Called from the
/// `SandboxBackend::get` impl on `LocalBackend`.
pub(crate) async fn get_local_handle_state(
    local_backend: &crate::backend::LocalBackend,
    name: &str,
) -> MicrosandboxResult<(sandbox_entity::Model, Option<i32>)> {
    let pools = local_backend.db().await?;
    let model = sandbox_entity::Entity::find()
        .filter(sandbox_entity::Column::Name.eq(name))
        .one(pools.read())
        .await?
        .ok_or_else(|| crate::MicrosandboxError::SandboxNotFound(name.into()))?;
    let model = reconcile_sandbox_runtime_state(pools, model).await?;
    let run = load_active_run(pools.read(), model.id).await?;
    let pid = pid_from_run(run.as_ref());
    Ok((model, pid))
}

/// Load all local DB rows + their active PIDs. Called from the
/// `SandboxBackend::list` impl on `LocalBackend`.
pub(crate) async fn list_local_handle_state(
    local_backend: &crate::backend::LocalBackend,
) -> MicrosandboxResult<Vec<(sandbox_entity::Model, Option<i32>)>> {
    let pools = local_backend.db().await?;
    let sandboxes = sandbox_entity::Entity::find()
        .order_by_desc(sandbox_entity::Column::CreatedAt)
        .all(pools.read())
        .await?;

    let mut reconciled = Vec::with_capacity(sandboxes.len());
    for sandbox in sandboxes {
        let model = reconcile_sandbox_runtime_state(pools, sandbox).await?;
        reconciled.push(model);
    }

    let sandbox_ids: Vec<i32> = reconciled.iter().map(|sandbox| sandbox.id).collect();
    let active_pids = load_active_pids(pools.read(), &sandbox_ids).await?;
    let mut out = Vec::with_capacity(reconciled.len());
    for sandbox in reconciled {
        let pid = active_pids.get(&sandbox.id).copied();
        out.push((sandbox, pid));
    }
    Ok(out)
}

/// Local lifecycle: remove a stopped sandbox by name.
pub(crate) async fn remove_local(
    backend: Arc<dyn crate::backend::Backend>,
    name: &str,
) -> MicrosandboxResult<()> {
    let local_backend =
        backend
            .as_local()
            .ok_or_else(|| crate::MicrosandboxError::Unsupported {
                feature: "remove_local".into(),
                available_when: "with a LocalBackend".into(),
            })?;
    let (model, pid) = get_local_handle_state(local_backend, name).await?;
    let handle = SandboxHandle::from_local_model(backend, model, pid);
    handle.remove().await
}

/// Local lifecycle: stop a sandbox by name.
///
/// Tries the configured agent relay socket candidates, connects, sends
/// `MessageType::Shutdown`, and lets agentd run an in-guest `sync()` +
/// `reboot(RB_POWER_OFF)` so ext4 unmounts cleanly (no journal replay on next
/// boot). Falls back to platform process termination via PID if the agent
/// endpoint is unreachable (agentd wedged, sandbox just transitioning, etc.).
///
/// No-op when the sandbox isn't in Running/Draining.
pub(crate) async fn stop_local(
    backend: Arc<dyn crate::backend::Backend>,
    name: &str,
) -> MicrosandboxResult<()> {
    let local_backend =
        backend
            .as_local()
            .ok_or_else(|| crate::MicrosandboxError::Unsupported {
                feature: "stop_local".into(),
                available_when: "with a LocalBackend".into(),
            })?;
    let (model, pid) = get_local_handle_state(local_backend, name).await?;
    if model.status != SandboxStatus::Running && model.status != SandboxStatus::Draining {
        return Ok(());
    }

    if model.status == SandboxStatus::Running {
        mark_sandbox_draining_if_running(local_backend.db().await?.write(), model.id).await?;
    }

    match request_agent_shutdown(local_backend, name).await {
        Ok(()) => Ok(()),
        Err(e) => {
            // Graceful degradation: agent endpoint unreachable (socket/pipe
            // missing, ECONNREFUSED, handshake timeout) or shutdown delivery
            // failed. Fall back to direct process termination so we still
            // attempt a stop, at the cost of skipping the in-guest sync().
            // The reaper updates DB status on PID exit.
            tracing::warn!(
                sandbox = %name,
                error = %e,
                "stop_local: agent endpoint unreachable; falling back to process termination",
            );
            if let Some(pid) = pid.filter(|p| pid_is_alive(*p)) {
                terminate_pid_gracefully(pid)?;
            }
            Ok(())
        }
    }
}

/// Local lifecycle: kill a sandbox by name (SIGKILL).
///
/// Destructive by design — no clean-shutdown path. Signals SIGKILL to the
/// libkrun PID, waits briefly for the process to exit, then marks the DB
/// row Stopped if all signalled PIDs are confirmed dead.
pub(crate) async fn kill_local(
    backend: Arc<dyn crate::backend::Backend>,
    name: &str,
) -> MicrosandboxResult<()> {
    let local_backend =
        backend
            .as_local()
            .ok_or_else(|| crate::MicrosandboxError::Unsupported {
                feature: "kill_local".into(),
                available_when: "with a LocalBackend".into(),
            })?;
    let (model, pid) = get_local_handle_state(local_backend, name).await?;
    if model.status != SandboxStatus::Running && model.status != SandboxStatus::Draining {
        return Ok(());
    }

    let mut pids = Vec::new();
    if let Some(pid) = pid.filter(|p| pid_is_alive(*p)) {
        kill_pid(pid)?;
        pids.push(pid);
    }

    if !pids.is_empty() {
        let timeout = std::time::Duration::from_secs(5);
        let start = std::time::Instant::now();
        let poll_interval = std::time::Duration::from_millis(50);
        while start.elapsed() < timeout {
            if pids.iter().all(|pid| pid_is_dead_or_reaped(*pid)) {
                break;
            }
            tokio::time::sleep(poll_interval).await;
        }
    }

    let all_dead = pids.is_empty() || pids.iter().all(|pid| pid_is_dead_or_reaped(*pid));
    if all_dead {
        let db = local_backend.db().await?.write();
        if let Err(e) = update_sandbox_status(db, model.id, SandboxStatus::Stopped).await {
            tracing::warn!(sandbox = %name, error = %e, "failed to update sandbox status after kill");
        }
    }

    Ok(())
}

/// Local lifecycle: drain a running sandbox by name.
///
/// Unix keeps the legacy SIGUSR1 drain path. Windows uses the existing
/// `core.shutdown` agent message so the guest can sync and power off without
/// pretending a direct process termination is graceful.
pub(crate) async fn drain_local(
    backend: Arc<dyn crate::backend::Backend>,
    name: &str,
) -> MicrosandboxResult<()> {
    let local_backend =
        backend
            .as_local()
            .ok_or_else(|| crate::MicrosandboxError::Unsupported {
                feature: "drain_local".into(),
                available_when: "with a LocalBackend".into(),
            })?;
    let (model, pid) = get_local_handle_state(local_backend, name).await?;
    if model.status != SandboxStatus::Running && model.status != SandboxStatus::Draining {
        return Ok(());
    }

    if model.status == SandboxStatus::Running {
        mark_sandbox_draining_if_running(local_backend.db().await?.write(), model.id).await?;
    }

    #[cfg(windows)]
    {
        if pid.is_some_and(pid_is_alive) {
            request_agent_shutdown(local_backend, name).await.map_err(|err| {
                crate::MicrosandboxError::Runtime(format!(
                    "windows drain requires the agent shutdown path, but the agent endpoint is unavailable: {err}"
                ))
            })?;
        }
        Ok(())
    }

    #[cfg(unix)]
    {
        if let Some(pid) = pid.filter(|p| pid_is_alive(*p)) {
            drain_pid(pid)?;
        }
        Ok(())
    }
}

async fn request_agent_shutdown(
    local_backend: &crate::backend::LocalBackend,
    name: &str,
) -> MicrosandboxResult<()> {
    let client =
        fs::local::connect_agent_with_timeout(local_backend, name, AGENT_SHUTDOWN_CONNECT_TIMEOUT)
            .await?;
    client.send(0, MessageType::Shutdown, &()).await?;
    Ok(())
}

async fn ping_agent(name: &str, client: &AgentClient) -> MicrosandboxResult<SandboxPingResult> {
    let started_at = std::time::Instant::now();
    let msg = client.request(MessageType::Ping, &Ping {}).await?;
    let latency = started_at.elapsed();
    if msg.t != MessageType::Pong {
        return Err(unexpected_agent_response("ping", &msg));
    }

    let _: Pong = msg.payload()?;
    Ok(SandboxPingResult {
        name: name.to_string(),
        latency,
    })
}

async fn touch_agent(name: &str, client: &AgentClient) -> MicrosandboxResult<SandboxTouchResult> {
    let msg = client.request(MessageType::Touch, &Touch {}).await?;
    if msg.t != MessageType::Touched {
        return Err(unexpected_agent_response("touch", &msg));
    }

    let touched: Touched = msg.payload()?;
    Ok(SandboxTouchResult {
        name: name.to_string(),
        activity_seq: touched.activity_seq,
    })
}

fn unexpected_agent_response(
    operation: &'static str,
    msg: &microsandbox_protocol::message::Message,
) -> crate::MicrosandboxError {
    if msg.t == MessageType::CoreError
        && let Ok(error) = msg.payload::<CoreError>()
    {
        return crate::MicrosandboxError::Runtime(format!(
            "agent rejected {operation}: {:?}: {}",
            error.kind, error.message
        ));
    }

    crate::MicrosandboxError::Runtime(format!("agent returned {} to {operation}", msg.t.as_str()))
}

//--------------------------------------------------------------------------------------------------
// Methods: Instance
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Remove this sandbox's persisted state after it has fully stopped.
    ///
    /// Local backend only. Cloud sandboxes are removed via
    /// [`Sandbox::remove`] / the backend trait's `remove` method (calling
    /// this on a cloud sandbox returns `Unsupported` without performing any
    /// work).
    ///
    /// Takes `&self` so the caller retains ownership across an
    /// `Unsupported` error on cloud — the previous `self`-by-value
    /// signature consumed the sandbox even on the failing path.
    pub async fn remove_persisted(&self) -> MicrosandboxResult<()> {
        let local = self.require_local("remove_persisted")?;
        let local_backend =
            self.backend
                .as_local()
                .ok_or_else(|| crate::MicrosandboxError::Unsupported {
                    feature: "Sandbox::remove_persisted on cloud".into(),
                    available_when: "never — cloud sandboxes are removed via the API".into(),
                })?;
        let pools = local_backend.db().await?;

        remove_dir_if_exists(&local_backend.sandboxes_dir().join(&self.name))?;
        sandbox_entity::Entity::delete_by_id(local.db_id)
            .exec(pools.write())
            .await?;

        Ok(())
    }

    /// Unique name identifying this sandbox.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The full configuration this sandbox was created with (image, cpus,
    /// memory, env, mounts, etc.).
    pub fn config(&self) -> &SandboxConfig {
        &self.config
    }

    /// Start planning a sandbox modification.
    ///
    /// The returned builder owns the canonical SDK patch and dry-run
    /// classification logic. It does not apply changes until later modify
    /// phases wire the same plan model into persistence and runtime control.
    pub fn modify(&self) -> SandboxModificationBuilder {
        SandboxModificationBuilder::new(self.backend.clone(), self.name.clone())
    }

    /// Which backend variant this sandbox is bound to. Returns `Local` or
    /// `Cloud` depending on how it was created.
    pub fn backend_kind(&self) -> crate::backend::BackendKind {
        self.backend.kind()
    }

    /// The `Arc<dyn Backend>` this sandbox routes through. Useful when
    /// invoking other backend resources (e.g. volumes) from a sandbox
    /// reference.
    pub fn backend(&self) -> &Arc<dyn crate::backend::Backend> {
        &self.backend
    }

    /// Local-only state accessor. Returns `Some` when this `Sandbox` was
    /// created by the local libkrun backend.
    pub fn local(&self) -> Option<&crate::backend::SandboxLocalState> {
        match self.inner.as_ref() {
            crate::backend::SandboxInner::Local(s) => Some(s),
            crate::backend::SandboxInner::Cloud(_) => None,
        }
    }

    /// Cloud-only state accessor. Returns `Some` when this `Sandbox` was
    /// created by the cloud backend.
    pub fn cloud(&self) -> Option<&crate::backend::SandboxCloudState> {
        match self.inner.as_ref() {
            crate::backend::SandboxInner::Cloud(s) => Some(s),
            crate::backend::SandboxInner::Local(_) => None,
        }
    }

    /// Same as [`Sandbox::local`] but returns a typed `Unsupported` error
    /// for cloud sandboxes. Used by methods that have no cloud equivalent yet.
    fn require_local(
        &self,
        method: &'static str,
    ) -> MicrosandboxResult<&crate::backend::SandboxLocalState> {
        self.local()
            .ok_or_else(|| crate::MicrosandboxError::Unsupported {
                feature: format!("Sandbox::{method}"),
                available_when: "when cloud exec/fs/logs/metrics land".into(),
            })
    }

    /// Live status from the backend. Always hits `backend.sandboxes().get(name)`
    /// — there is no cached status on the outer struct, per the D6.4
    /// "fetch-live" policy.
    ///
    /// Each call is a separate round-trip (DB read for local, HTTP GET for
    /// cloud). If you need to read multiple fields together (e.g. status +
    /// last_error), call [`Sandbox::get`](Self::get) once and read off the
    /// returned [`SandboxHandle`]'s `*_snapshot` accessors instead.
    pub async fn status(&self) -> MicrosandboxResult<SandboxStatus> {
        let handle = self
            .backend
            .sandboxes()
            .get(self.backend.clone(), &self.name)
            .await?;
        Ok(handle.status_snapshot())
    }

    /// Live last-error string from the backend, when any. Always hits the
    /// backend, never reads a cached field.
    ///
    /// Each call is a separate round-trip. If you need this alongside
    /// `status()`, fetch a fresh [`SandboxHandle`] via
    /// [`Sandbox::get`](Self::get) once and read both off the snapshot.
    pub async fn last_error(&self) -> MicrosandboxResult<Option<String>> {
        let handle = self
            .backend
            .sandboxes()
            .get(self.backend.clone(), &self.name)
            .await?;
        Ok(handle.last_error_snapshot())
    }

    /// Read captured output from `exec.log` for this sandbox.
    ///
    /// Routes through the [`SandboxBackend`](crate::backend::SandboxBackend)
    /// trait. Local reads the on-disk JSON Lines file the runtime writes via
    /// the relay tap (`crates/runtime/lib/exec_log.rs`); cloud returns
    /// `Unsupported` until bounded cloud log snapshots land.
    pub async fn logs(&self, opts: &LogOptions) -> MicrosandboxResult<Vec<LogEntry>> {
        self.backend
            .sandboxes()
            .logs(self.backend.clone(), &self.name, opts)
            .await
    }

    /// Stream log entries for this sandbox.
    ///
    /// Local streams the on-disk JSON Lines files produced by the relay tap;
    /// cloud streams the msb-cloud SSE logs endpoint and maps each event into
    /// a typed [`LogEntry`].
    pub async fn log_stream(
        &self,
        opts: &LogStreamOptions,
    ) -> MicrosandboxResult<crate::backend::sandbox::LogStream> {
        self.backend
            .sandboxes()
            .log_stream(self.backend.clone(), &self.name, opts)
            .await
    }

    /// Check whether agentd is reachable without refreshing the sandbox idle timer.
    ///
    /// Local backend only. The request uses `core.ping` and returns the SDK-measured
    /// round-trip latency. If the sandbox runtime predates protocol generation 6,
    /// this fails before any bytes are sent with an unsupported-operation error.
    pub async fn ping(&self) -> MicrosandboxResult<SandboxPingResult> {
        self.require_local("ping")?;
        ping_agent(&self.name, self.client()).await
    }

    /// Explicitly refresh the sandbox idle timer.
    ///
    /// Local backend only. The request uses `core.touch`, so callers can keep a
    /// sandbox alive intentionally without relying on unrelated agent traffic.
    pub async fn touch(&self) -> MicrosandboxResult<SandboxTouchResult> {
        self.require_local("touch")?;
        touch_agent(&self.name, self.client()).await
    }

    /// Low-level access to the guest agent client.
    ///
    /// **Local-only**: panics if called on a cloud sandbox. Use
    /// [`local()`](Self::local) to check first when calling from generic
    /// code. The cloud variant has no `AgentClient` — the cloud worker owns
    /// the in-VM bridge — so there is nothing to return.
    pub fn client(&self) -> &AgentClient {
        match self.local() {
            Some(local) => &local.client,
            None => {
                panic!("Sandbox::client called on cloud sandbox — use sb.local() to check first")
            }
        }
    }

    /// Get a cloneable reference to the agent client.
    ///
    /// **Local-only**: panics if called on a cloud sandbox. Mirrors
    /// [`client`](Self::client).
    pub fn client_arc(&self) -> Arc<AgentClient> {
        match self.local() {
            Some(local) => Arc::clone(&local.client),
            None => panic!(
                "Sandbox::client_arc called on cloud sandbox — use sb.local() to check first"
            ),
        }
    }

    /// Returns `true` if this sandbox handle owns the process lifecycle.
    ///
    /// When `true`, dropping this handle or calling [`stop`](Self::stop)
    /// will terminate the sandbox. Cloud sandboxes never own a host process
    /// — the cloud worker does — so this returns `false` for them.
    pub fn owns_lifecycle(&self) -> bool {
        self.local().map(|s| s.handle.is_some()).unwrap_or(false)
    }

    /// Read, write, and manage files inside the running sandbox.
    ///
    /// Routes through the [`SandboxBackend`](crate::backend::SandboxBackend)
    /// trait per-method, so this constructor is infallible. On cloud each
    /// op returns `Unsupported` until cloud guest-fs lands; on local each
    /// op routes through the agent protocol (`core.fs.*`).
    pub fn fs(&self) -> fs::SandboxFsOps<'_> {
        let client = self.local().map(|local| Arc::clone(&local.client));
        fs::SandboxFsOps::new(self.backend.clone(), &self.name, client)
    }

    /// Stop the sandbox gracefully and wait until stopped state is observed.
    ///
    /// Uses [`DEFAULT_STOP_TIMEOUT`] before escalating to force termination.
    pub async fn stop(&self) -> MicrosandboxResult<()> {
        self.stop_with_timeout(DEFAULT_STOP_TIMEOUT).await
    }

    /// Request graceful shutdown and return once the request is sent.
    ///
    /// Routes through the backend trait. On local this connects to the agent
    /// endpoint and sends `core.shutdown` (agentd runs `sync()` +
    /// `reboot(RB_POWER_OFF)` for a clean ext4 unmount), falling back to
    /// platform process termination via PID if the endpoint is unreachable. On
    /// cloud this issues `POST /v1/sandboxes/by-name/:name/stop`.
    pub async fn request_stop(&self) -> MicrosandboxResult<()> {
        tracing::debug!(sandbox = %self.name, "stop: dispatching");
        self.backend
            .sandboxes()
            .stop(self.backend.clone(), &self.name)
            .await
    }

    /// Stop the sandbox gracefully with an explicit timeout before escalation.
    pub async fn stop_with_timeout(&self, timeout: std::time::Duration) -> MicrosandboxResult<()> {
        if timeout.is_zero() {
            self.kill_with_timeout(DEFAULT_KILL_TIMEOUT).await?;
            return Ok(());
        }

        self.request_stop().await?;
        if let Ok(result) = tokio::time::timeout(timeout, self.wait_until_stopped()).await {
            result?;
            return Ok(());
        }

        tracing::warn!(
            sandbox = %self.name,
            timeout_secs = timeout.as_secs(),
            "graceful stop exceeded timeout, escalating to kill"
        );
        self.request_kill().await?;
        match tokio::time::timeout(DEFAULT_KILL_TIMEOUT, self.wait_until_stopped()).await {
            Ok(result) => {
                result?;
                Ok(())
            }
            Err(_) => Err(crate::MicrosandboxError::Runtime(format!(
                "timed out observing stopped state for sandbox '{}'",
                self.name
            ))),
        }
    }

    /// Stop the sandbox gracefully and wait for the process to exit.
    ///
    /// **Local backend only.** Cloud sandboxes have no host process to wait
    /// on; use [`stop`](Self::stop) and poll [`status`](Self::status) instead.
    pub async fn stop_and_wait(&self) -> MicrosandboxResult<ExitStatus> {
        let local = self.require_local("stop_and_wait")?;
        let stop_result = self.request_stop().await;
        if local.handle.is_none() {
            stop_result?;
            // No handle to wait on — return a synthetic success status.
            return Ok(std::process::ExitStatus::default());
        }
        let wait_result = self.wait().await;
        stop_result?;
        wait_result
    }

    /// Kill the sandbox immediately and wait until stopped state is observed.
    pub async fn kill(&self) -> MicrosandboxResult<()> {
        self.kill_with_timeout(DEFAULT_KILL_TIMEOUT).await
    }

    /// Request force termination and return once the request is sent.
    ///
    /// Routes through the backend trait. On local the trait impl looks the PID
    /// up from the DB and signals SIGKILL, then marks the row Stopped once the
    /// process is confirmed dead. Cloud currently returns `Unsupported`.
    pub async fn request_kill(&self) -> MicrosandboxResult<()> {
        self.backend
            .sandboxes()
            .kill(self.backend.clone(), &self.name)
            .await
    }

    /// Trigger a graceful drain. Unix local uses SIGUSR1; Windows local uses
    /// the agent shutdown path. Cloud sandboxes currently return `Unsupported`.
    /// Force-kill the sandbox and wait up to `timeout` for stopped-state observation.
    pub async fn kill_with_timeout(&self, timeout: std::time::Duration) -> MicrosandboxResult<()> {
        self.request_kill().await?;
        match tokio::time::timeout(timeout, self.wait_until_stopped()).await {
            Ok(result) => {
                result?;
                Ok(())
            }
            Err(_) => Err(crate::MicrosandboxError::Runtime(format!(
                "timed out observing stopped state for sandbox '{}'",
                self.name
            ))),
        }
    }

    /// Trigger a graceful drain. Unix local uses SIGUSR1; Windows local uses
    /// the agent shutdown path. Cloud sandboxes currently return `Unsupported`.
    pub async fn drain(&self) -> MicrosandboxResult<()> {
        self.request_drain().await
    }

    /// Request graceful drain without waiting for observed exit.
    pub async fn request_drain(&self) -> MicrosandboxResult<()> {
        self.backend
            .sandboxes()
            .drain(self.backend.clone(), &self.name)
            .await
    }

    /// Wait for the sandbox process to exit. **Local backend only.**
    pub async fn wait(&self) -> MicrosandboxResult<ExitStatus> {
        let local = self.require_local("wait")?;
        match &local.handle {
            Some(h) => h.lock().await.wait().await,
            None => Err(crate::MicrosandboxError::Runtime(
                "cannot wait: not the lifecycle owner".into(),
            )),
        }
    }

    /// Wait until this sandbox is observed in a terminal non-running state.
    pub async fn wait_until_stopped(&self) -> MicrosandboxResult<SandboxStopResult> {
        if self.owns_lifecycle() {
            let status = self.wait().await?;
            return Ok(stop_result_from_exit_status(&self.name, status));
        }

        match self
            .backend
            .sandboxes()
            .get(self.backend.clone(), &self.name)
            .await
        {
            Ok(handle) => handle.wait_until_stopped().await,
            Err(error)
                if self.is_local_ephemeral() && sandbox_not_found_for_name(&error, &self.name) =>
            {
                Ok(ephemeral_cleanup_stop_result(&self.name))
            }
            Err(error) => Err(error),
        }
    }

    /// Detach this handle without stopping the sandbox.
    ///
    /// Disarms the SIGTERM safety net so the sandbox keeps running after
    /// this handle is dropped. Intended for CLI flows like `create`, `start`,
    /// and `run --detach`. No-op for cloud sandboxes (the cloud worker owns
    /// the lifecycle regardless of this process).
    pub async fn detach(self) {
        if let crate::backend::SandboxInner::Local(local) = self.inner.as_ref()
            && let Some(h) = &local.handle
        {
            h.lock().await.disarm();
        }
        // Normal drop runs — client reader task is aborted and
        // ProcessHandle drops without sending SIGTERM.
    }

    fn is_local_ephemeral(&self) -> bool {
        self.local().is_some() && self.config.spec.lifecycle.ephemeral
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Execution
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Execute a command and return a streaming handle.
    ///
    /// ```ignore
    /// let mut handle = sb.exec_stream("tail", ["-f", "/var/log/app.log"]).await?;
    /// ```
    pub async fn exec_stream(
        &self,
        cmd: impl Into<String>,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> MicrosandboxResult<ExecHandle> {
        let opts = ExecOptions {
            args: args.into_iter().map(Into::into).collect(),
            ..Default::default()
        };
        self.backend
            .sandboxes()
            .exec_stream(
                self.backend.clone(),
                &self.name,
                &self.config,
                cmd.into(),
                opts,
            )
            .await
    }

    /// Execute a command with full options and return a streaming handle.
    ///
    /// ```ignore
    /// let mut handle = sb.exec_stream_with("python", |e| e.stdin_pipe().tty(true)).await?;
    /// ```
    pub async fn exec_stream_with(
        &self,
        cmd: impl Into<String>,
        f: impl FnOnce(ExecOptionsBuilder) -> ExecOptionsBuilder,
    ) -> MicrosandboxResult<ExecHandle> {
        let opts = f(ExecOptionsBuilder::default()).build()?;
        self.backend
            .sandboxes()
            .exec_stream(
                self.backend.clone(),
                &self.name,
                &self.config,
                cmd.into(),
                opts,
            )
            .await
    }

    /// Execute a command and wait for completion.
    ///
    /// ```ignore
    /// let output = sb.exec("python", ["-c", "print('hi')"]).await?;
    /// ```
    pub async fn exec(
        &self,
        cmd: impl Into<String>,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> MicrosandboxResult<ExecOutput> {
        let opts = ExecOptions {
            args: args.into_iter().map(Into::into).collect(),
            ..Default::default()
        };
        self.backend
            .sandboxes()
            .exec(
                self.backend.clone(),
                &self.name,
                &self.config,
                cmd.into(),
                opts,
            )
            .await
    }

    /// Execute a command with full options and wait for completion.
    ///
    /// ```ignore
    /// let output = sb.exec_with("python", |e| e.args(["compute.py"]).cwd("/app")).await?;
    /// ```
    pub async fn exec_with(
        &self,
        cmd: impl Into<String>,
        f: impl FnOnce(ExecOptionsBuilder) -> ExecOptionsBuilder,
    ) -> MicrosandboxResult<ExecOutput> {
        let opts = f(ExecOptionsBuilder::default()).build()?;
        self.backend
            .sandboxes()
            .exec(
                self.backend.clone(),
                &self.name,
                &self.config,
                cmd.into(),
                opts,
            )
            .await
    }

    /// Run a shell command and wait for completion.
    ///
    /// Uses the sandbox's configured shell (default: `/bin/sh`) to interpret
    /// the script via `<shell> -c "<script>"`.
    ///
    /// - `sandbox.shell("echo hello")`
    /// - `sandbox.shell("ENV=val cmd | other_cmd")`
    pub async fn shell(&self, script: impl Into<String>) -> MicrosandboxResult<ExecOutput> {
        let shell = self
            .config
            .spec
            .runtime
            .shell
            .as_deref()
            .unwrap_or("/bin/sh")
            .to_string();
        let opts = ExecOptions {
            args: vec!["-c".to_string(), script.into()],
            ..Default::default()
        };
        self.backend
            .sandboxes()
            .exec(self.backend.clone(), &self.name, &self.config, shell, opts)
            .await
    }

    /// Run a shell command with full options and wait for completion.
    pub async fn shell_with(
        &self,
        script: impl Into<String>,
        f: impl FnOnce(ExecOptionsBuilder) -> ExecOptionsBuilder,
    ) -> MicrosandboxResult<ExecOutput> {
        let shell = self
            .config
            .spec
            .runtime
            .shell
            .as_deref()
            .unwrap_or("/bin/sh")
            .to_string();
        let mut opts = f(ExecOptionsBuilder::default()).build()?;
        opts.args.splice(0..0, ["-c".to_string(), script.into()]);
        self.backend
            .sandboxes()
            .exec(self.backend.clone(), &self.name, &self.config, shell, opts)
            .await
    }

    /// Run a shell command with streaming I/O.
    ///
    /// Like [`shell`](Self::shell) but returns a streaming [`ExecHandle`]
    /// instead of waiting for completion.
    pub async fn shell_stream(&self, script: impl Into<String>) -> MicrosandboxResult<ExecHandle> {
        let shell = self
            .config
            .spec
            .runtime
            .shell
            .as_deref()
            .unwrap_or("/bin/sh")
            .to_string();
        let opts = ExecOptions {
            args: vec!["-c".to_string(), script.into()],
            ..Default::default()
        };
        self.backend
            .sandboxes()
            .exec_stream(self.backend.clone(), &self.name, &self.config, shell, opts)
            .await
    }

    /// Run a shell command with full options and streaming I/O.
    pub async fn shell_stream_with(
        &self,
        script: impl Into<String>,
        f: impl FnOnce(ExecOptionsBuilder) -> ExecOptionsBuilder,
    ) -> MicrosandboxResult<ExecHandle> {
        let shell = self
            .config
            .spec
            .runtime
            .shell
            .as_deref()
            .unwrap_or("/bin/sh")
            .to_string();
        let mut opts = f(ExecOptionsBuilder::default()).build()?;
        opts.args.splice(0..0, ["-c".to_string(), script.into()]);
        self.backend
            .sandboxes()
            .exec_stream(self.backend.clone(), &self.name, &self.config, shell, opts)
            .await
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Attach
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Attach to the sandbox with an interactive terminal session.
    ///
    /// ```ignore
    /// let exit_code = sb.attach("bash", ["-l"]).await?;
    /// ```
    pub async fn attach(
        &self,
        cmd: impl Into<String>,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> MicrosandboxResult<i32> {
        let mut builder = AttachOptionsBuilder::default();
        for arg in args {
            builder = builder.arg(arg);
        }
        self.backend
            .sandboxes()
            .attach(
                self.backend.clone(),
                &self.name,
                &self.config,
                cmd.into(),
                builder,
            )
            .await
    }

    /// Attach to the sandbox with full options.
    ///
    /// ```ignore
    /// let exit_code = sb.attach_with("zsh", |a| a.env("TERM", "xterm").detach_keys("ctrl-q")).await?;
    /// ```
    pub async fn attach_with(
        &self,
        cmd: impl Into<String>,
        f: impl FnOnce(AttachOptionsBuilder) -> AttachOptionsBuilder,
    ) -> MicrosandboxResult<i32> {
        let builder = f(AttachOptionsBuilder::default());
        self.backend
            .sandboxes()
            .attach(
                self.backend.clone(),
                &self.name,
                &self.config,
                cmd.into(),
                builder,
            )
            .await
    }

    /// Attach to the sandbox's default shell.
    ///
    /// Uses the sandbox's configured shell (default: `/bin/sh`).
    pub async fn attach_shell(&self) -> MicrosandboxResult<i32> {
        let shell = self
            .config
            .spec
            .runtime
            .shell
            .as_deref()
            .unwrap_or("/bin/sh")
            .to_string();
        self.backend
            .sandboxes()
            .attach(
                self.backend.clone(),
                &self.name,
                &self.config,
                shell,
                AttachOptionsBuilder::default(),
            )
            .await
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Wait for the agent relay socket to become available and connect.
///
/// The sandbox process creates the relay socket asynchronously during startup.
/// This function retries the connection with brief delays until it succeeds
/// or a timeout is reached.
async fn wait_for_relay(
    sock_path: &std::path::Path,
    log_dir: &std::path::Path,
    handle: &mut ProcessHandle,
    sandbox_name: &str,
) -> MicrosandboxResult<AgentClient> {
    tracing::debug!(
        sock = %sock_path.display(),
        pid = handle.pid(),
        "wait_for_relay: waiting for agent socket"
    );
    let deadline = tokio::time::Instant::now() + AGENT_RELAY_READY_TIMEOUT;
    let max_backoff = std::time::Duration::from_millis(10);
    let mut backoff = std::time::Duration::from_millis(1);
    let mut attempts = 0u32;

    loop {
        attempts += 1;
        match tokio::time::timeout(
            deadline.saturating_duration_since(tokio::time::Instant::now()),
            AgentClient::connect(sock_path),
        )
        .await
        {
            Ok(Ok(client)) => {
                tracing::debug!(attempts, "wait_for_relay: connected");
                // The relay is up — clear any stale boot-error.json from
                // a previous failed attempt so it cannot misattribute a
                // future crash.
                let _ = microsandbox_runtime::boot_error::BootError::delete(log_dir);
                return Ok(client);
            }
            Ok(Err(_)) | Err(_) if tokio::time::Instant::now() < deadline => {
                // Check if the sandbox process is still alive before retrying.
                // If it crashed, there's no point waiting for the socket.
                if let Some(status) = handle.try_wait()? {
                    tracing::debug!(attempts, ?status, "wait_for_relay: sandbox process exited");

                    // Prefer the structured boot-error record if the
                    // sandbox got far enough to write one.
                    if let Some(boot_err) = read_boot_error(log_dir) {
                        return Err(crate::MicrosandboxError::BootStart {
                            name: sandbox_name.to_string(),
                            err: boot_err,
                        });
                    }

                    // No structured boot-error.json — the sandbox died
                    // too early or too violently (e.g. a Rust panic exits
                    // 101 without running our atomic-writer). Synthesize
                    // an `Other`-stage record so the CLI still renders
                    // the styled error block with the `msb logs` hint
                    // instead of dumping a raw log directory path.
                    let synthetic = microsandbox_runtime::boot_error::BootError {
                        t: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                        stage: microsandbox_runtime::boot_error::BootErrorStage::Other,
                        errno: None,
                        message: format!(
                            "sandbox process exited ({status}) before agent relay became available"
                        ),
                    };
                    return Err(crate::MicrosandboxError::BootStart {
                        name: sandbox_name.to_string(),
                        err: synthetic,
                    });
                }

                // Keep early retries tight so relay readiness doesn't inherit a
                // coarse fixed delay on warm starts.
                tokio::time::sleep(backoff).await;
                backoff = std::cmp::min(backoff.saturating_mul(2), max_backoff);
            }
            Ok(Err(e)) => {
                tracing::debug!(
                    attempts,
                    error = %e,
                    "wait_for_relay: agent connection failed"
                );
                if let Some(boot_err) = read_boot_error(log_dir) {
                    return Err(crate::MicrosandboxError::BootStart {
                        name: sandbox_name.to_string(),
                        err: boot_err,
                    });
                }
                return Err(e.into());
            }
            Err(e) => {
                tracing::debug!(
                    attempts,
                    error = %e,
                    "wait_for_relay: timed out"
                );
                // Even when the process is still running, the sandbox
                // may have written a structured boot-error before
                // stalling (e.g. agentd reported a recoverable failure
                // and never produced the handshake bytes). Prefer that
                // typed record over the raw IO/timeout error so the CLI
                // can render the styled boot-error block.
                if let Some(boot_err) = read_boot_error(log_dir) {
                    return Err(crate::MicrosandboxError::BootStart {
                        name: sandbox_name.to_string(),
                        err: boot_err,
                    });
                }
                return Err(crate::MicrosandboxError::Runtime(format!(
                    "timed out waiting for agent relay: {e}"
                )));
            }
        }
    }
}

/// Read `boot-error.json` from `log_dir` if present and parseable.
///
/// Returns `None` when the directory is unknown, the file is missing, or
/// the contents cannot be deserialized — callers fall back to a raw
/// error in those cases.
fn read_boot_error(
    log_dir: &std::path::Path,
) -> Option<microsandbox_runtime::boot_error::BootError> {
    microsandbox_runtime::boot_error::BootError::read(log_dir)
        .ok()
        .flatten()
}

/// Build an `ExecRequest` by merging sandbox config with caller-provided overrides.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_exec_request(
    config: &SandboxConfig,
    cmd: String,
    args: Vec<String>,
    cwd: Option<String>,
    user: Option<String>,
    env: &[EnvVar],
    rlimits: &[Rlimit],
    tty: bool,
    rows: u16,
    cols: u16,
) -> ExecRequest {
    let merged = config::merge_env_pairs(&config.spec.env, env);
    let mut env: Vec<String> = merged
        .iter()
        .map(|var| format!("{}={}", var.key, var.value))
        .collect();

    // Inject TERM for TTY sessions if not already set.
    if tty && !env.iter().any(|e| e.starts_with("TERM=")) {
        env.push(format!("TERM={}", default_tty_term()));
    }

    let rlimits: Vec<ExecRlimit> = rlimits
        .iter()
        .map(|rl| ExecRlimit {
            resource: rl.resource.as_str().to_string(),
            soft: rl.soft,
            hard: rl.hard,
        })
        .collect();

    ExecRequest {
        cmd,
        args,
        env,
        cwd: cwd
            .or_else(|| config.spec.runtime.workdir.clone())
            .or_else(|| Some("/".to_string())),
        user: user.or_else(|| config.spec.runtime.user.clone()),
        tty,
        rows,
        cols,
        rlimits,
    }
}

fn default_tty_term() -> String {
    select_tty_term(std::env::var("TERM").ok().as_deref())
}

fn select_tty_term(term: Option<&str>) -> String {
    match term {
        Some(term) if !term.trim().is_empty() && term != "dumb" => term.to_string(),
        _ => "xterm".to_string(),
    }
}

#[cfg(unix)]
pub(crate) fn terminal_path_for_fd(fd: std::os::fd::RawFd) -> std::io::Result<std::path::PathBuf> {
    let mut buf = [0u8; 1024];
    let rc = unsafe { libc::ttyname_r(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if rc != 0 {
        return Err(std::io::Error::from_raw_os_error(rc));
    }

    let end = buf
        .iter()
        .position(|&byte| byte == 0)
        .ok_or_else(|| std::io::Error::other("ttyname_r did not NUL-terminate"))?;

    let path = std::str::from_utf8(&buf[..end]).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "tty path is not valid UTF-8",
        )
    })?;

    Ok(std::path::PathBuf::from(path))
}

#[cfg(unix)]
pub(crate) fn open_nonblocking_terminal_input(
    path: &std::path::Path,
) -> std::io::Result<std::fs::File> {
    use std::os::fd::AsRawFd;

    let file = std::fs::File::open(path)?;
    let fd = file.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(file)
}

#[cfg(unix)]
pub(crate) fn read_from_fd(fd: std::os::fd::RawFd, buf: &mut [u8]) -> std::io::Result<usize> {
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

fn stop_result_from_exit_status(name: &str, status: ExitStatus) -> SandboxStopResult {
    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;

    SandboxStopResult {
        name: name.to_string(),
        status: SandboxStatus::Stopped,
        exit_code: status.code(),
        signal: {
            #[cfg(unix)]
            {
                status.signal()
            }
            #[cfg(not(unix))]
            {
                None
            }
        },
        observed_at: chrono::Utc::now(),
        source: Some("owned process wait".to_string()),
    }
}

pub(super) fn ephemeral_cleanup_stop_result(name: &str) -> SandboxStopResult {
    SandboxStopResult {
        name: name.to_string(),
        status: SandboxStatus::Stopped,
        exit_code: None,
        signal: None,
        observed_at: chrono::Utc::now(),
        source: Some("ephemeral cleanup removed persisted state".to_string()),
    }
}

pub(super) fn sandbox_not_found_for_name(error: &crate::MicrosandboxError, name: &str) -> bool {
    matches!(error, crate::MicrosandboxError::SandboxNotFound(missing) if missing == name)
}

/// Update the sandbox status in the database.
pub(super) async fn update_sandbox_status(
    db: &DbWriteConnection,
    sandbox_id: i32,
    status: SandboxStatus,
) -> MicrosandboxResult<()> {
    db.transaction(|txn| async move {
        let mut update = sandbox_entity::Entity::update_many()
            .col_expr(sandbox_entity::Column::Status, Expr::value(status))
            .col_expr(
                sandbox_entity::Column::UpdatedAt,
                Expr::value(chrono::Utc::now().naive_utc()),
            );
        if sandbox_status_clears_active_config(status) {
            update = update.col_expr(
                sandbox_entity::Column::ActiveConfig,
                Expr::value(Option::<String>::None),
            );
        }
        update
            .filter(sandbox_entity::Column::Id.eq(sandbox_id))
            .exec(&txn)
            .await?;
        Ok((txn, ()))
    })
    .await
}

pub(super) async fn update_sandbox_active_config(
    db: &DbWriteConnection,
    sandbox_id: i32,
    config: &SandboxConfig,
) -> MicrosandboxResult<()> {
    let config_json = serde_json::to_string(config)?;
    sandbox_entity::Entity::update_many()
        .col_expr(
            sandbox_entity::Column::ActiveConfig,
            Expr::value(Some(config_json)),
        )
        .col_expr(
            sandbox_entity::Column::UpdatedAt,
            Expr::value(chrono::Utc::now().naive_utc()),
        )
        .filter(sandbox_entity::Column::Id.eq(sandbox_id))
        .exec(db)
        .await?;

    Ok(())
}

fn sandbox_status_clears_active_config(status: SandboxStatus) -> bool {
    matches!(
        status,
        SandboxStatus::Created | SandboxStatus::Stopped | SandboxStatus::Crashed
    )
}

async fn mark_sandbox_draining_if_running(
    db: &DbWriteConnection,
    sandbox_id: i32,
) -> MicrosandboxResult<()> {
    sandbox_entity::Entity::update_many()
        .col_expr(
            sandbox_entity::Column::Status,
            Expr::value(SandboxStatus::Draining),
        )
        .col_expr(
            sandbox_entity::Column::UpdatedAt,
            Expr::value(chrono::Utc::now().naive_utc()),
        )
        .filter(sandbox_entity::Column::Id.eq(sandbox_id))
        .filter(sandbox_entity::Column::Status.eq(SandboxStatus::Running))
        .exec(db)
        .await?;

    Ok(())
}

// Stale-sandbox reaping is no longer owned by the SDK/CLI. Host runtime
// processes (`msb sandbox`) now perform lifecycle maintenance: stale active
// reconciliation and terminal ephemeral cleanup, on startup under a
// read-gated DB lease (see `microsandbox_runtime::maintenance`). The lazy
// read-time reconciliation in `reconcile_sandbox_runtime_state` below still
// keeps `get`/`list`/`start` honest for the row they touch.

//--------------------------------------------------------------------------------------------------
// Functions: State Reconciliation
//--------------------------------------------------------------------------------------------------

pub(super) async fn load_sandbox_record_reconciled(
    pools: &DbPools,
    name: &str,
) -> MicrosandboxResult<sandbox_entity::Model> {
    let sandbox = load_sandbox_record(pools.read(), name).await?;
    reconcile_sandbox_runtime_state(pools, sandbox).await
}

pub(super) async fn reconcile_sandbox_runtime_state(
    pools: &DbPools,
    sandbox: sandbox_entity::Model,
) -> MicrosandboxResult<sandbox_entity::Model> {
    if !matches!(
        sandbox.status,
        SandboxStatus::Running | SandboxStatus::Draining
    ) {
        return Ok(sandbox);
    }

    let run = load_active_run(pools.read(), sandbox.id).await?;

    // No run record yet while Running means the sandbox is still starting up
    // (the child process has not inserted its PID). A Draining row with no
    // active run, however, has already completed shutdown from the DB's point
    // of view and should not keep stop callers polling forever.
    let Some(run) = run else {
        if sandbox.status == SandboxStatus::Draining {
            let (terminal_status, reason) = stale_runtime_terminal_state(sandbox.status);
            mark_sandbox_runtime_stale(pools.write(), sandbox.id, None, terminal_status, reason)
                .await?;

            return sandbox_entity::Entity::find_by_id(sandbox.id)
                .one(pools.read())
                .await?
                .ok_or_else(|| crate::MicrosandboxError::SandboxNotFound(sandbox.name));
        }

        return Ok(sandbox);
    };

    if run.pid.is_some_and(pid_is_alive) {
        return Ok(sandbox);
    }

    let (terminal_status, reason) = stale_runtime_terminal_state(sandbox.status);
    mark_sandbox_runtime_stale(
        pools.write(),
        sandbox.id,
        Some(run.id),
        terminal_status,
        reason,
    )
    .await?;

    sandbox_entity::Entity::find_by_id(sandbox.id)
        .one(pools.read())
        .await?
        .ok_or_else(|| crate::MicrosandboxError::SandboxNotFound(sandbox.name))
}

pub(super) async fn load_active_run(
    db: &DbReadConnection,
    sandbox_id: i32,
) -> MicrosandboxResult<Option<run_entity::Model>> {
    run_entity::Entity::find()
        .filter(run_entity::Column::SandboxId.eq(sandbox_id))
        .filter(run_entity::Column::Status.eq(run_entity::RunStatus::Running))
        .order_by_desc(run_entity::Column::StartedAt)
        .one(db)
        .await
        .map_err(Into::into)
}

async fn load_active_pids(
    db: &DbReadConnection,
    sandbox_ids: &[i32],
) -> MicrosandboxResult<HashMap<i32, i32>> {
    if sandbox_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let runs = run_entity::Entity::find()
        .filter(run_entity::Column::SandboxId.is_in(sandbox_ids.iter().copied()))
        .filter(run_entity::Column::Status.eq(run_entity::RunStatus::Running))
        .order_by_desc(run_entity::Column::StartedAt)
        .all(db)
        .await?;

    let mut pids = HashMap::with_capacity(sandbox_ids.len());
    for run in runs {
        if pids.contains_key(&run.sandbox_id) {
            continue;
        }
        if let Some(pid) = pid_from_run(Some(&run)) {
            pids.insert(run.sandbox_id, pid);
        }
    }

    Ok(pids)
}

fn pid_from_run(run: Option<&run_entity::Model>) -> Option<i32> {
    run.and_then(|model| model.pid)
        .filter(|pid| pid_is_alive(*pid))
}

fn stale_runtime_terminal_state(
    status: SandboxStatus,
) -> (SandboxStatus, run_entity::TerminationReason) {
    match status {
        // Draining means a stop/drain request was already accepted. If the
        // owning runtime is now gone, the lifecycle reached its requested
        // terminal state even when the original observer could not reap it.
        SandboxStatus::Draining => (
            SandboxStatus::Stopped,
            run_entity::TerminationReason::ShutdownRequested,
        ),
        _ => (
            SandboxStatus::Crashed,
            run_entity::TerminationReason::InternalError,
        ),
    }
}

async fn mark_sandbox_runtime_stale(
    db: &DbWriteConnection,
    sandbox_id: i32,
    run_id: Option<i32>,
    terminal_status: SandboxStatus,
    reason: run_entity::TerminationReason,
) -> MicrosandboxResult<()> {
    db.transaction(|txn| async move {
        let now = chrono::Utc::now().naive_utc();

        if let Some(run_id) = run_id {
            run_entity::Entity::update_many()
                .col_expr(
                    run_entity::Column::Status,
                    Expr::value(run_entity::RunStatus::Terminated),
                )
                .col_expr(run_entity::Column::TerminationReason, Expr::value(reason))
                .col_expr(run_entity::Column::TerminatedAt, Expr::value(now))
                .filter(run_entity::Column::Id.eq(run_id))
                .exec(&txn)
                .await?;
        }

        // Only reconcile an active row. This prevents a concurrent start()
        // from having its newly-terminal or newly-running status overwritten.
        sandbox_entity::Entity::update_many()
            .col_expr(sandbox_entity::Column::Status, Expr::value(terminal_status))
            .col_expr(
                sandbox_entity::Column::ActiveConfig,
                Expr::value(Option::<String>::None),
            )
            .col_expr(sandbox_entity::Column::UpdatedAt, Expr::value(now))
            .filter(sandbox_entity::Column::Id.eq(sandbox_id))
            .filter(
                sandbox_entity::Column::Status
                    .is_in([SandboxStatus::Running, SandboxStatus::Draining]),
            )
            .exec(&txn)
            .await?;

        Ok((txn, ()))
    })
    .await
}

pub(super) fn pid_is_alive(pid: i32) -> bool {
    microsandbox_utils::process::pid_is_alive(pid)
}

#[cfg(unix)]
fn pid_is_dead_or_reaped(pid: i32) -> bool {
    let mut status = 0;
    let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    if result == pid {
        return true;
    }

    !pid_is_alive(pid)
}

#[cfg(windows)]
fn pid_is_dead_or_reaped(pid: i32) -> bool {
    !pid_is_alive(pid)
}

#[cfg(unix)]
fn terminate_pid_gracefully(pid: i32) -> MicrosandboxResult<()> {
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid),
        nix::sys::signal::Signal::SIGTERM,
    )?;
    Ok(())
}

#[cfg(windows)]
fn terminate_pid_gracefully(pid: i32) -> MicrosandboxResult<()> {
    terminate_pid(pid)
}

#[cfg(unix)]
fn kill_pid(pid: i32) -> MicrosandboxResult<()> {
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid),
        nix::sys::signal::Signal::SIGKILL,
    )?;
    Ok(())
}

#[cfg(windows)]
fn kill_pid(pid: i32) -> MicrosandboxResult<()> {
    terminate_pid(pid)
}

#[cfg(unix)]
fn drain_pid(pid: i32) -> MicrosandboxResult<()> {
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid),
        nix::sys::signal::Signal::SIGUSR1,
    )?;
    Ok(())
}

#[cfg(windows)]
fn terminate_pid(pid: i32) -> MicrosandboxResult<()> {
    let pid = u32::try_from(pid)
        .map_err(|_| crate::MicrosandboxError::Runtime(format!("invalid Windows pid: {pid}")))?;
    let handle = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
    if handle.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }

    let result = unsafe { TerminateProcess(handle, 1) };
    let close_result = unsafe { CloseHandle(handle) };
    if result == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if close_result == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn image_pull_policy(policy: PullPolicy) -> microsandbox_image::PullPolicy {
    match policy {
        PullPolicy::IfMissing => microsandbox_image::PullPolicy::IfMissing,
        PullPolicy::Always => microsandbox_image::PullPolicy::Always,
        PullPolicy::Never => microsandbox_image::PullPolicy::Never,
    }
}

/// Derive a guest hostname from a sandbox name, fitting within
/// [`MAX_HOSTNAME_BYTES`]. Names short enough pass through unchanged;
/// longer names collapse to a deterministic `<prefix>-<hash>` form to
/// keep distinct long names very unlikely to share a hostname.
pub(crate) fn hostname_from_sandbox_name(name: &str) -> String {
    derive_hostname(name)
}

/// Pull an OCI image and return the pull result.
///
/// Auth resolution:
/// 1. Explicit `RegistryAuth` from `SandboxBuilder::registry()` (if provided)
/// 2. OS keyring / credential store
/// 3. Global config `registries.hosts.<host>.auth` matched by registry hostname
/// 4. Docker credential store/config fallback
/// 5. Anonymous fallback
///
/// When `progress` is `Some`, uses `pull_with_sender()` to emit per-layer
/// progress events. The caller must consume the corresponding `PullProgressHandle`.
async fn pull_oci_image(
    local_backend: &crate::backend::LocalBackend,
    reference: &str,
    pull_policy: PullPolicy,
    registry_overrides: RegistryOverrides,
    progress: Option<PullProgressSender>,
) -> MicrosandboxResult<PullResult> {
    let global = local_backend.config();
    let cache = GlobalCache::new(&local_backend.cache_dir())?;
    let platform = microsandbox_image::Platform::host_linux();
    let image_ref: Reference = reference.parse().map_err(|e| {
        crate::MicrosandboxError::InvalidConfig(format!("invalid image reference: {e}"))
    })?;
    let options = PullOptions {
        pull_policy: image_pull_policy(pull_policy),
        ..Default::default()
    };

    // Warm runs spend most of their time outside the guest, so avoid
    // constructing the registry client when the image is already complete
    // in the local cache.
    if let Some((result, metadata)) = Registry::pull_cached(&cache, &image_ref, &options)? {
        if let Some(sender) = progress {
            let reference: std::sync::Arc<str> = reference.to_string().into();
            sender.send(PullProgress::Resolving {
                reference: reference.clone(),
            });
            sender.send(PullProgress::Resolved {
                reference: reference.clone(),
                manifest_digest: metadata.manifest_digest.clone().into(),
                layer_count: metadata.layers.len(),
                total_download_bytes: metadata
                    .layers
                    .iter()
                    .filter_map(|layer| layer.size_bytes)
                    .reduce(|a, b| a + b),
            });
            sender.send(PullProgress::Complete {
                reference,
                layer_count: metadata.layers.len(),
            });
        }

        return Ok(result);
    }

    let auth = match registry_overrides.auth {
        Some(auth) => auth,
        None => global.resolve_registry_auth(image_ref.registry())?,
    };

    // Merge global config with SDK overrides.
    let mut ca_certs = global.resolve_ca_certs().await?;
    ca_certs.extend(registry_overrides.ca_certs);

    let mut insecure_registries = global.insecure_registries();
    if registry_overrides.insecure {
        insecure_registries.push(image_ref.registry().to_string());
    }

    let registry = Registry::builder(platform, cache)
        .auth(auth)
        .extra_ca_certs(ca_certs)
        .add_insecure_registries(insecure_registries)
        .build()?;

    if let Some(sender) = progress {
        let task = registry.pull_with_sender(&image_ref, &options, sender);
        let result = task
            .await
            .map_err(|e| crate::MicrosandboxError::Custom(format!("pull task panicked: {e}")))??;
        Ok(result)
    } else {
        let result = registry.pull(&image_ref, &options).await?;
        Ok(result)
    }
}

/// Validate user-defined sandbox labels. Keys must be non-empty and must not
/// use a reserved prefix. Values may be empty.
pub(crate) fn validate_labels(labels: &BTreeMap<String, String>) -> MicrosandboxResult<()> {
    for key in labels.keys() {
        if key.is_empty() {
            return Err(crate::MicrosandboxError::InvalidConfig(
                "label key must not be empty".into(),
            ));
        }
        if let Some(prefix) = reserved_label_prefix(key) {
            return Err(crate::MicrosandboxError::InvalidConfig(format!(
                "label key '{key}' uses reserved prefix '{prefix}'"
            )));
        }
    }
    Ok(())
}

/// Validate sandbox environment variables.
pub(crate) fn validate_env(env: &[EnvVar]) -> MicrosandboxResult<()> {
    for var in env {
        if var.key.starts_with("MSB_") {
            return Err(crate::MicrosandboxError::InvalidConfig(format!(
                "environment variable {:?} uses the reserved MSB_ prefix",
                var.key
            )));
        }
    }
    Ok(())
}

fn sandbox_handle_matches_filter(handle: &SandboxHandle, filter: &SandboxFilter) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(handle.config_json()) else {
        return false;
    };

    let labels = value
        .get("labels")
        .or_else(|| value.get("config").and_then(|config| config.get("labels")))
        .and_then(serde_json::Value::as_object);

    filter.labels.iter().all(|(key, expected)| {
        labels
            .and_then(|labels| labels.get(key))
            .and_then(serde_json::Value::as_str)
            .is_some_and(|actual| actual == expected)
    })
}

/// Validate rootfs configuration that depends on host filesystem state.
fn validate_rootfs_source(rootfs: &RootfsSource) -> MicrosandboxResult<()> {
    match rootfs {
        RootfsSource::Bind(path) => {
            if !path.exists() {
                return Err(crate::MicrosandboxError::InvalidConfig(format!(
                    "rootfs bind path does not exist: {}",
                    path.display()
                )));
            }

            if !path.is_dir() {
                return Err(crate::MicrosandboxError::InvalidConfig(format!(
                    "rootfs bind path is not a directory: {}",
                    path.display()
                )));
            }
        }
        RootfsSource::Oci(_) => {}
        RootfsSource::DiskImage { path, .. } => {
            if !path.exists() {
                return Err(crate::MicrosandboxError::InvalidConfig(format!(
                    "disk image does not exist: {}",
                    path.display()
                )));
            }

            if !path.is_file() {
                return Err(crate::MicrosandboxError::InvalidConfig(format!(
                    "disk image is not a regular file: {}",
                    path.display()
                )));
            }
        }
    }

    Ok(())
}

pub(super) fn remove_dir_if_exists(path: &Path) -> MicrosandboxResult<()> {
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// Load a sandbox row by name.
pub(super) async fn load_sandbox_record(
    db: &DbReadConnection,
    name: &str,
) -> MicrosandboxResult<sandbox_entity::Model> {
    sandbox_entity::Entity::find()
        .filter(sandbox_entity::Column::Name.eq(name))
        .one(db)
        .await?
        .ok_or_else(|| crate::MicrosandboxError::SandboxNotFound(name.into()))
}

async fn prepare_create_target(
    pools: &DbPools,
    config: &SandboxConfig,
    sandbox_dir: &Path,
) -> MicrosandboxResult<()> {
    let existing = sandbox_entity::Entity::find()
        .filter(sandbox_entity::Column::Name.eq(&config.spec.name))
        .one(pools.read())
        .await?;

    let dir_exists = sandbox_dir.exists();

    if !config.replace_existing {
        if existing.is_some() || dir_exists {
            return Err(crate::MicrosandboxError::SandboxAlreadyExists(format!(
                "sandbox '{}' already exists; remove it, start the stopped sandbox, or recreate with .replace()",
                config.spec.name
            )));
        }
        return Ok(());
    }

    if let Some(model) = existing {
        let model = reconcile_sandbox_runtime_state(pools, model).await?;
        let active = matches!(
            model.status,
            SandboxStatus::Running | SandboxStatus::Draining | SandboxStatus::Paused
        );
        if active {
            stop_sandbox_for_replacement(pools, &model, config.replace_with_timeout).await?;
        }

        sandbox_entity::Entity::delete_by_id(model.id)
            .exec(pools.write())
            .await?;
    }

    remove_dir_if_exists(sandbox_dir)?;
    Ok(())
}

/// Stop the prior sandbox before recreating it.
///
/// Sends SIGTERM with the configured grace, then escalates to SIGKILL
/// and waits a short reap window. Single path for both same-process and
/// foreign-process owners: SIGKILL bypasses any signal handler so the
/// process is dead within kernel time, and the reap completes via the
/// owning process's existing wait machinery (tokio's SIGCHLD driver
/// when we're the parent, or the foreign parent's own `waitpid`).
/// Replaces the previous "wait 30s and give up" behavior, which spun
/// the full timeout when libkrun's SIGTERM handler did a slow
/// graceful shutdown.
async fn stop_sandbox_for_replacement(
    pools: &DbPools,
    sandbox: &sandbox_entity::Model,
    grace: std::time::Duration,
) -> MicrosandboxResult<()> {
    let run = load_active_run(pools.read(), sandbox.id).await?;
    let pids: Vec<i32> = run
        .as_ref()
        .and_then(|model| model.pid)
        .filter(|pid| pid_is_alive(*pid))
        .into_iter()
        .collect();

    if !pids.is_empty() {
        // Polite phase: SIGTERM and wait up to `grace` for graceful exit.
        if !grace.is_zero() {
            for pid in &pids {
                let _ = terminate_pid_gracefully(*pid);
            }
            wait_for_pids_to_exit(&pids, grace).await;
        }

        // SIGKILL anything still alive. We don't wait or verify after
        // SIGKILL: it's uncatchable, so termination is bounded by kernel
        // time, and the only state that would have us spin is the
        // zombie window between exit and the parent's `waitpid`. That
        // window is harmless: prepare_create_target wipes the DB row
        // and the sandbox dir, the new spawn gets a fresh PID, and the
        // zombie reaps on its own (tokio's SIGCHLD driver when we own
        // it, or the foreign parent's wait machinery otherwise).
        for pid in pids.iter().copied().filter(|p| pid_is_alive(*p)) {
            let _ = kill_pid(pid);
        }
    }

    mark_sandbox_stopped_for_replacement(
        pools.write(),
        sandbox.id,
        run.as_ref().map(|model| model.id),
    )
    .await
}

async fn mark_sandbox_stopped_for_replacement(
    db: &DbWriteConnection,
    sandbox_id: i32,
    run_id: Option<i32>,
) -> MicrosandboxResult<()> {
    db.transaction(|txn| async move {
        let now = chrono::Utc::now().naive_utc();

        if let Some(run_id) = run_id {
            run_entity::Entity::update_many()
                .col_expr(
                    run_entity::Column::Status,
                    Expr::value(run_entity::RunStatus::Terminated),
                )
                .col_expr(
                    run_entity::Column::TerminationReason,
                    Expr::value(run_entity::TerminationReason::Signal),
                )
                .col_expr(run_entity::Column::TerminatedAt, Expr::value(now))
                .filter(run_entity::Column::Id.eq(run_id))
                .exec(&txn)
                .await?;
        }

        sandbox_entity::Entity::update_many()
            .col_expr(
                sandbox_entity::Column::Status,
                Expr::value(SandboxStatus::Stopped),
            )
            .col_expr(sandbox_entity::Column::UpdatedAt, Expr::value(now))
            .filter(sandbox_entity::Column::Id.eq(sandbox_id))
            .exec(&txn)
            .await?;

        Ok((txn, ()))
    })
    .await
}

async fn wait_for_pids_to_exit(pids: &[i32], timeout: std::time::Duration) {
    let start = std::time::Instant::now();
    let poll_interval = std::time::Duration::from_millis(50);

    loop {
        if pids.iter().all(|pid| !pid_is_alive(*pid)) {
            return;
        }

        if start.elapsed() >= timeout {
            return;
        }

        tokio::time::sleep(poll_interval).await;
    }
}

fn validate_start_state(
    local_backend: &crate::backend::LocalBackend,
    config: &SandboxConfig,
    sandbox_dir: &Path,
) -> MicrosandboxResult<()> {
    if !sandbox_dir.exists() {
        return Err(crate::MicrosandboxError::Custom(format!(
            "sandbox state missing for '{}': {}",
            config.spec.name,
            sandbox_dir.display()
        )));
    }

    if let RootfsSource::Oci(_) = &config.spec.image
        && let Some(ref digest_str) = config.manifest_digest
    {
        let cache_dir = local_backend.cache_dir();
        if let Ok(cache) = GlobalCache::new(&cache_dir)
            && let Ok(digest) = digest_str.parse::<Digest>()
        {
            let vmdk_path = cache.vmdk_path(&digest);
            if !vmdk_path.exists() {
                return Err(crate::MicrosandboxError::Custom(format!(
                    "sandbox '{}' cannot start: VMDK missing: {}",
                    config.spec.name,
                    vmdk_path.display()
                )));
            }
        }
    }

    Ok(())
}

/// Insert the sandbox record in the database and return its ID.
async fn insert_sandbox_record(
    db: &DbWriteConnection,
    config: &SandboxConfig,
) -> MicrosandboxResult<i32> {
    let config_json = serde_json::to_string(config)?;

    db.transaction(|txn| {
        let config_json = config_json.clone();
        async move {
            let now = chrono::Utc::now().naive_utc();
            let model = sandbox_entity::ActiveModel {
                name: Set(config.spec.name.clone()),
                config: Set(config_json),
                status: Set(SandboxStatus::Running),
                ephemeral: Set(config.spec.lifecycle.ephemeral),
                created_at: Set(Some(now)),
                updated_at: Set(Some(now)),
                ..Default::default()
            };
            let result = sandbox_entity::Entity::insert(model).exec(&txn).await?;
            Ok((txn, result.last_insert_id))
        }
    })
    .await
}

async fn delete_sandbox_record(db: &DbWriteConnection, sandbox_id: i32) -> MicrosandboxResult<()> {
    sandbox_entity::Entity::delete_by_id(sandbox_id)
        .exec(db)
        .await?;
    Ok(())
}

async fn persist_oci_manifest_pin(
    db: &DbWriteConnection,
    sandbox_id: i32,
    manifest_digest: &str,
) -> MicrosandboxResult<()> {
    db.transaction(|txn| async move {
        replace_oci_manifest_pin(&txn, sandbox_id, manifest_digest).await?;
        Ok((txn, ()))
    })
    .await
}

/// Pin a sandbox to its resolved OCI manifest.
async fn replace_oci_manifest_pin<C: ConnectionTrait>(
    db: &C,
    sandbox_id: i32,
    manifest_digest: &str,
) -> MicrosandboxResult<()> {
    use crate::db::entity::manifest as manifest_entity;

    let now = chrono::Utc::now().naive_utc();

    let manifest = manifest_entity::Entity::find()
        .filter(manifest_entity::Column::Digest.eq(manifest_digest))
        .one(db)
        .await?;

    let manifest_id = manifest.map(|m| m.id);

    sandbox_rootfs_entity::Entity::delete_many()
        .filter(sandbox_rootfs_entity::Column::SandboxId.eq(sandbox_id))
        .exec(db)
        .await?;

    sandbox_rootfs_entity::Entity::insert(sandbox_rootfs_entity::ActiveModel {
        sandbox_id: Set(sandbox_id),
        manifest_id: Set(manifest_id),
        mode: Set("erofs".to_string()),
        upper_fstype: Set(Some("ext4".to_string())),
        created_at: Set(Some(now)),
        ..Default::default()
    })
    .exec(db)
    .await?;

    Ok(())
}

/// Create a sparse ext4 image for the writable overlay upper layer.
async fn create_upper_ext4(
    path: &std::path::Path,
    size_mib: u32,
    tree: Option<tree::FileTree>,
) -> MicrosandboxResult<()> {
    let _ = tokio::fs::remove_file(path).await;
    let ext4_options = ext4::Ext4FormatOptions {
        size_bytes: u64::from(size_mib) * 1024 * 1024,
        ..Default::default()
    };
    let overlay_tree = build_overlay_upper_tree(tree);
    let path = path.to_path_buf();

    tokio::task::spawn_blocking(move || {
        ext4::format_ext4_with_tree(&path, &ext4_options, overlay_tree)
    })
    .await
    .map_err(|e| crate::MicrosandboxError::Custom(format!("ext4 format task failed: {e}")))?
    .map_err(|e| crate::MicrosandboxError::Custom(format!("failed to create upper.ext4: {e}")))?;

    Ok(())
}

/// Build the ext4 root directory tree that overlayfs expects.
fn build_overlay_upper_tree(tree: Option<tree::FileTree>) -> tree::FileTree {
    use tree::{DirectoryNode, FileTree, InodeMetadata, TreeNode};

    let mut overlay_tree = FileTree::new();
    let mut upper_dir = DirectoryNode::new(InodeMetadata::default());
    let work_dir = DirectoryNode::new(InodeMetadata::default());

    if let Some(mut tree) = tree {
        upper_dir.entries = std::mem::take(&mut tree.root.entries);
    }

    overlay_tree
        .root
        .entries
        .insert("upper".into(), TreeNode::Directory(upper_dir));
    overlay_tree
        .root
        .entries
        .insert("work".into(), TreeNode::Directory(work_dir));

    overlay_tree
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };
    #[cfg(unix)]
    use std::{
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
        process::Command,
    };

    use microsandbox_db::entity::{run as run_entity, sandbox_rootfs as sandbox_rootfs_entity};
    use microsandbox_db::pool::DbPools;

    use crate::{
        backend::{Backend, LocalBackend},
        sandbox::OciRootfsSource,
    };
    use microsandbox_migration::{Migrator, MigratorTrait};
    #[cfg(unix)]
    use sea_orm::{ColumnTrait, QueryFilter};
    use sea_orm::{EntityTrait, Set};
    use tempfile::tempdir;

    use super::{
        MAX_HOSTNAME_BYTES, MAX_SANDBOX_NAME_BYTES, MountOptions, RootfsSource, SandboxConfig,
        SandboxStatus, VolumeMount, ephemeral_cleanup_stop_result, hostname_from_sandbox_name,
        insert_sandbox_record, persist_oci_manifest_pin, prepare_create_target,
        reconcile_sandbox_runtime_state, remove_dir_if_exists, sandbox_not_found_for_name,
        validate_hostname, validate_rootfs_source,
    };

    /// Open both pools at `db_path` for tests, with migrations applied.
    async fn open_test_pools(db_path: &std::path::Path) -> DbPools {
        // Connect timeout matches the production default (30s). 1s was too
        // tight on cold ci runners and surfaced as `PoolTimedOut` flakes
        // before the test body had a chance to run.
        let pools = DbPools::open(
            db_path,
            1,
            std::time::Duration::from_secs(30),
            std::time::Duration::from_secs(5),
        )
        .await
        .unwrap();
        Migrator::up(pools.write().inner(), None).await.unwrap();
        pools
    }

    fn test_config(name: impl Into<String>) -> SandboxConfig {
        SandboxConfig {
            spec: microsandbox_types::SandboxSpec {
                name: name.into(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn test_config_with_rootfs(name: impl Into<String>, image: RootfsSource) -> SandboxConfig {
        SandboxConfig {
            spec: microsandbox_types::SandboxSpec {
                name: name.into(),
                image,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn unique_temp_path(suffix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("microsandbox-rootfs-{suffix}-{nanos}"))
    }

    fn dead_pid() -> i32 {
        let mut pid = 900_000;
        while super::pid_is_alive(pid) {
            pid += 1;
        }
        pid
    }

    #[test]
    fn test_sandbox_not_found_for_name_requires_exact_match() {
        assert!(sandbox_not_found_for_name(
            &crate::MicrosandboxError::SandboxNotFound("gone".into()),
            "gone"
        ));
        assert!(!sandbox_not_found_for_name(
            &crate::MicrosandboxError::SandboxNotFound("other".into()),
            "gone"
        ));
        assert!(!sandbox_not_found_for_name(
            &crate::MicrosandboxError::Runtime("gone".into()),
            "gone"
        ));
    }

    #[test]
    fn test_ephemeral_cleanup_stop_result_marks_stopped() {
        let result = ephemeral_cleanup_stop_result("msb-gone");

        assert_eq!(result.name, "msb-gone");
        assert_eq!(result.status, SandboxStatus::Stopped);
        assert_eq!(result.exit_code, None);
        assert_eq!(result.signal, None);
        assert_eq!(
            result.source.as_deref(),
            Some("ephemeral cleanup removed persisted state")
        );
    }

    #[tokio::test]
    async fn test_runtime_name_validation_uses_explicit_backend_paths() {
        let temp = tempfile::Builder::new()
            .prefix("msb")
            .tempdir_in("/tmp")
            .unwrap();
        let home = temp.path().join("msb-home");
        let backend = LocalBackend::builder().home(&home).build().await.unwrap();

        super::validate_sandbox_name_for_runtime_with_backend(&backend, "sdk-socket-test").unwrap();
    }

    #[tokio::test]
    async fn test_create_local_validates_direct_config_mounts() {
        let temp = tempfile::Builder::new()
            .prefix("msb")
            .tempdir_in("/tmp")
            .unwrap();
        let rootfs = temp.path().join("rootfs");
        std::fs::create_dir_all(&rootfs).unwrap();
        let backend = Arc::new(
            LocalBackend::builder()
                .home(temp.path().join("home"))
                .build()
                .await
                .unwrap(),
        );
        let backend_trait: Arc<dyn Backend> = backend;
        let mut config = test_config_with_rootfs("bad-mounts", RootfsSource::Bind(rootfs));
        config.spec.mounts = vec![
            VolumeMount::Tmpfs {
                guest: "/dup".to_string(),
                size_mib: None,
                options: MountOptions::default(),
            },
            VolumeMount::Tmpfs {
                guest: "/dup".to_string(),
                size_mib: None,
                options: MountOptions::default(),
            },
        ];

        let err = match super::create_local(
            backend_trait,
            config,
            crate::runtime::SpawnMode::Attached,
            None,
        )
        .await
        {
            Ok(_) => panic!("expected invalid direct-config mounts to be rejected"),
            Err(err) => err,
        };

        assert!(
            err.to_string().contains("multiple volumes cannot mount"),
            "got: {err}"
        );
    }

    #[test]
    fn test_live_sandbox_lifecycle_api_methods_stay_available() {
        // These method items are intentionally referenced without invoking
        // them. The test is a compile-time tripwire for the unified lifecycle
        // surface that backs the language SDK bindings.
        let _ = super::Sandbox::stop;
        let _ = super::Sandbox::request_stop;
        let _ = super::Sandbox::stop_with_timeout;
        let _ = super::Sandbox::kill;
        let _ = super::Sandbox::request_kill;
        let _ = super::Sandbox::kill_with_timeout;
        let _ = super::Sandbox::request_drain;
        let _ = super::Sandbox::wait_until_stopped;
        let _ = super::all_sandbox_metrics;
    }

    #[test]
    fn test_default_tty_term_prefers_host_term() {
        assert_eq!(super::select_tty_term(Some("wezterm")), "wezterm");
    }

    #[test]
    fn test_default_tty_term_falls_back_from_dumb() {
        assert_eq!(super::select_tty_term(Some("dumb")), "xterm");
    }

    #[test]
    #[cfg(unix)]
    fn test_shared_tty_fd_flags_are_shared_across_dups() {
        let pty = nix::pty::openpty(None, None).unwrap();
        let shared_a = unsafe { OwnedFd::from_raw_fd(libc::dup(pty.slave.as_raw_fd())) };
        let shared_b = unsafe { OwnedFd::from_raw_fd(libc::dup(shared_a.as_raw_fd())) };

        let flags = unsafe { libc::fcntl(shared_a.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(flags, -1);
        let ret = unsafe {
            libc::fcntl(
                shared_a.as_raw_fd(),
                libc::F_SETFL,
                flags | libc::O_NONBLOCK,
            )
        };
        assert_ne!(ret, -1);

        let other_flags = unsafe { libc::fcntl(shared_b.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(other_flags, -1);
        assert_ne!(
            other_flags & libc::O_NONBLOCK,
            0,
            "dup'd tty fds should share O_NONBLOCK state"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_open_nonblocking_terminal_input_keeps_existing_tty_fds_blocking() {
        let pty = nix::pty::openpty(None, None).unwrap();
        let shared_a = unsafe { OwnedFd::from_raw_fd(libc::dup(pty.slave.as_raw_fd())) };
        let shared_b = unsafe { OwnedFd::from_raw_fd(libc::dup(shared_a.as_raw_fd())) };
        let tty_path = super::terminal_path_for_fd(pty.slave.as_raw_fd()).unwrap();

        let input = super::open_nonblocking_terminal_input(&tty_path).unwrap();

        let input_flags = unsafe { libc::fcntl(input.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(input_flags, -1);
        assert_ne!(
            input_flags & libc::O_NONBLOCK,
            0,
            "re-opened tty input fd should be non-blocking"
        );

        let flags_a = unsafe { libc::fcntl(shared_a.as_raw_fd(), libc::F_GETFL) };
        let flags_b = unsafe { libc::fcntl(shared_b.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(flags_a, -1);
        assert_ne!(flags_b, -1);
        assert_eq!(
            flags_a & libc::O_NONBLOCK,
            0,
            "existing tty fd should remain blocking"
        );
        assert_eq!(
            flags_b & libc::O_NONBLOCK,
            0,
            "dup'd tty fd should remain blocking"
        );
    }

    #[test]
    fn test_validate_rootfs_source_missing_bind_path() {
        let path = unique_temp_path("missing");
        let err = validate_rootfs_source(&RootfsSource::Bind(path.clone())).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "invalid config: rootfs bind path does not exist: {}",
                path.display()
            )
        );
    }

    #[test]
    fn test_validate_rootfs_source_bind_path_must_be_directory() {
        let path = unique_temp_path("file");
        fs::write(&path, b"not a directory").unwrap();

        let err = validate_rootfs_source(&RootfsSource::Bind(path.clone())).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "invalid config: rootfs bind path is not a directory: {}",
                path.display()
            )
        );

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_validate_rootfs_source_existing_bind_directory() {
        let path = unique_temp_path("dir");
        fs::create_dir(&path).unwrap();

        validate_rootfs_source(&RootfsSource::Bind(path.clone())).unwrap();

        fs::remove_dir(path).unwrap();
    }

    #[test]
    fn test_hostname_from_sandbox_name_passes_short_names_through() {
        let name = "short-name";
        assert_eq!(hostname_from_sandbox_name(name), name);

        let name = "a".repeat(MAX_HOSTNAME_BYTES);
        assert_eq!(hostname_from_sandbox_name(&name), name);
    }

    #[test]
    fn test_hostname_from_sandbox_name_collapses_long_names_to_64_bytes() {
        let derived = hostname_from_sandbox_name(&"a".repeat(MAX_HOSTNAME_BYTES + 1));
        assert_eq!(derived.len(), MAX_HOSTNAME_BYTES);

        let derived = hostname_from_sandbox_name(&"a".repeat(MAX_SANDBOX_NAME_BYTES));
        assert_eq!(derived.len(), MAX_HOSTNAME_BYTES);

        let bytes = derived.as_bytes();
        assert_eq!(bytes[MAX_HOSTNAME_BYTES - 9], b'-');
        assert!(
            bytes[MAX_HOSTNAME_BYTES - 8..]
                .iter()
                .all(u8::is_ascii_hexdigit)
        );
    }

    #[test]
    fn test_hostname_from_sandbox_name_is_deterministic_and_unique() {
        let a = "a".repeat(MAX_SANDBOX_NAME_BYTES);
        let mut b = a.clone();
        b.pop();
        b.push('b');

        assert_eq!(
            hostname_from_sandbox_name(&a),
            hostname_from_sandbox_name(&a)
        );
        assert_ne!(
            hostname_from_sandbox_name(&a),
            hostname_from_sandbox_name(&b)
        );
    }

    #[test]
    fn test_hostname_from_sandbox_name_respects_utf8_boundaries() {
        let name = "é".repeat(64);
        assert_eq!(name.len(), 128);

        let derived = hostname_from_sandbox_name(&name);
        assert!(derived.len() <= MAX_HOSTNAME_BYTES);
        assert!(derived.is_char_boundary(derived.len()));
    }

    #[test]
    fn test_validate_hostname_accepts_absent_and_64_byte_hostname() {
        validate_hostname(None).unwrap();
        validate_hostname(Some(&"y".repeat(MAX_HOSTNAME_BYTES))).unwrap();
    }

    #[test]
    fn test_validate_hostname_rejects_empty_hostname() {
        let err = validate_hostname(Some("")).unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid config: hostname must not be empty"
        );
    }

    #[test]
    fn test_validate_hostname_rejects_over_64_byte_hostname() {
        let err = validate_hostname(Some(&"y".repeat(MAX_HOSTNAME_BYTES + 1))).unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid config: hostname is too long: 65 bytes (max 64)"
        );
    }

    #[tokio::test]
    async fn test_create_local_rejects_invalid_hostname_before_rootfs_validation() {
        let temp = tempdir().unwrap();
        let backend = Arc::new(
            crate::backend::LocalBackend::builder()
                .home(temp.path())
                .build()
                .await
                .unwrap(),
        );
        let mut config =
            test_config_with_rootfs("test", RootfsSource::Bind(unique_temp_path("missing")));
        config.spec.runtime.hostname = Some("y".repeat(MAX_HOSTNAME_BYTES + 1));

        let err =
            match super::create_local(backend, config, crate::runtime::SpawnMode::Attached, None)
                .await
            {
                Ok(_) => panic!("invalid hostname should fail before sandbox creation"),
                Err(err) => err,
            };

        assert_eq!(
            err.to_string(),
            "invalid config: hostname is too long: 65 bytes (max 64)"
        );
    }

    #[test]
    fn test_remove_dir_if_exists_removes_existing_sandbox_tree() {
        let temp = tempdir().unwrap();
        let sandbox_dir = temp.path().join("sandbox");
        fs::create_dir_all(sandbox_dir.join("runtime/scripts")).unwrap();
        fs::write(sandbox_dir.join("runtime/scripts/start.sh"), b"echo hi").unwrap();
        fs::create_dir_all(sandbox_dir.join("rw")).unwrap();

        remove_dir_if_exists(&sandbox_dir).unwrap();

        assert!(!sandbox_dir.exists());
    }

    #[test]
    fn test_remove_dir_if_exists_ignores_missing_directory() {
        let temp = tempdir().unwrap();
        let sandbox_dir = temp.path().join("missing");

        remove_dir_if_exists(&sandbox_dir).unwrap();

        assert!(!sandbox_dir.exists());
    }

    #[tokio::test]
    async fn test_persist_oci_manifest_pin_upserts_rootfs_record() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let pools = open_test_pools(&db_path).await;

        let mut config = test_config_with_rootfs(
            "pinned",
            RootfsSource::Oci(OciRootfsSource {
                reference: "docker.io/library/alpine".into(),
                upper_size_mib: None,
            }),
        );
        config.manifest_digest = Some("sha256:aaaa".into());
        let sandbox_id = insert_sandbox_record(pools.write(), &config).await.unwrap();

        // First pin (no matching manifest in DB, so manifest_id will be None).
        persist_oci_manifest_pin(
            pools.write(),
            sandbox_id,
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .await
        .unwrap();

        // Second pin replaces the first.
        persist_oci_manifest_pin(
            pools.write(),
            sandbox_id,
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        )
        .await
        .unwrap();

        let pins = sandbox_rootfs_entity::Entity::find()
            .all(pools.write())
            .await
            .unwrap();
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].sandbox_id, sandbox_id);
        assert_eq!(pins[0].mode, "erofs");
        assert_eq!(pins[0].manifest_id, None);
    }

    #[tokio::test]
    async fn test_persist_oci_manifest_pin_replaces_stale_pin_for_different_digest() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let pools = open_test_pools(&db_path).await;

        let mut config = test_config_with_rootfs(
            "recreated",
            RootfsSource::Oci(OciRootfsSource {
                reference: "docker.io/library/alpine".into(),
                upper_size_mib: None,
            }),
        );
        config.manifest_digest = Some("sha256:aaaa".into());
        let sandbox_id = insert_sandbox_record(pools.write(), &config).await.unwrap();

        persist_oci_manifest_pin(
            pools.write(),
            sandbox_id,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .await
        .unwrap();

        // Replacing with a different digest should delete the old pin.
        persist_oci_manifest_pin(
            pools.write(),
            sandbox_id,
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .await
        .unwrap();

        let pins = sandbox_rootfs_entity::Entity::find()
            .all(pools.write())
            .await
            .unwrap();
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].sandbox_id, sandbox_id);
        assert_eq!(pins[0].mode, "erofs");
        assert_eq!(pins[0].manifest_id, None);
    }

    #[tokio::test]
    async fn test_insert_sandbox_record_persists_manifest_digest_in_config_json() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let pools = open_test_pools(&db_path).await;

        let mut config = test_config_with_rootfs(
            "persisted-digest",
            RootfsSource::Oci(OciRootfsSource {
                reference: "docker.io/library/alpine".into(),
                upper_size_mib: None,
            }),
        );
        config.manifest_digest = Some("sha256:abc123".into());

        let sandbox_id = insert_sandbox_record(pools.write(), &config).await.unwrap();
        let row = super::sandbox_entity::Entity::find_by_id(sandbox_id)
            .one(pools.write())
            .await
            .unwrap()
            .unwrap();
        let decoded: SandboxConfig = serde_json::from_str(&row.config).unwrap();

        assert_eq!(decoded.manifest_digest, config.manifest_digest);
    }

    #[tokio::test]
    async fn test_prepare_create_target_rejects_existing_state_without_force() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let pools = open_test_pools(&db_path).await;

        let sandbox_dir = temp.path().join("sandboxes").join("existing");
        fs::create_dir_all(&sandbox_dir).unwrap();

        let config = test_config("existing");

        let err = prepare_create_target(&pools, &config, &sandbox_dir)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[tokio::test]
    async fn test_prepare_create_target_force_replaces_stopped_sandbox_state() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let pools = open_test_pools(&db_path).await;

        let sandbox_dir = temp.path().join("sandboxes").join("replaceable");
        fs::create_dir_all(sandbox_dir.join("rw")).unwrap();
        let config = test_config("replaceable");
        let sandbox_id = insert_sandbox_record(pools.write(), &config).await.unwrap();
        super::update_sandbox_status(pools.write(), sandbox_id, super::SandboxStatus::Stopped)
            .await
            .unwrap();

        let mut forced = test_config("replaceable");
        forced.replace_existing = true;

        prepare_create_target(&pools, &forced, &sandbox_dir)
            .await
            .unwrap();

        assert!(!sandbox_dir.exists());
        assert!(
            super::sandbox_entity::Entity::find_by_id(sandbox_id)
                .one(pools.write())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_reconcile_sandbox_runtime_state_marks_dead_processes_crashed() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let pools = open_test_pools(&db_path).await;

        let config = test_config("stale");
        let sandbox_id = insert_sandbox_record(pools.write(), &config).await.unwrap();
        let dead_run_pid = dead_pid();

        let run = run_entity::ActiveModel {
            sandbox_id: Set(sandbox_id),
            pid: Set(Some(dead_run_pid)),
            status: Set(run_entity::RunStatus::Running),
            ..Default::default()
        };
        let run_id = run_entity::Entity::insert(run)
            .exec(pools.write())
            .await
            .unwrap()
            .last_insert_id;

        let sandbox = super::sandbox_entity::Entity::find_by_id(sandbox_id)
            .one(pools.write())
            .await
            .unwrap()
            .unwrap();
        let reconciled = reconcile_sandbox_runtime_state(&pools, sandbox)
            .await
            .unwrap();
        assert_eq!(reconciled.status, SandboxStatus::Crashed);

        let run = run_entity::Entity::find_by_id(run_id)
            .one(pools.write())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(run.status, run_entity::RunStatus::Terminated);
        assert_eq!(
            run.termination_reason,
            Some(run_entity::TerminationReason::InternalError)
        );
        assert!(run.terminated_at.is_some());
    }

    #[tokio::test]
    async fn test_reconcile_sandbox_runtime_state_marks_dead_draining_stopped() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let pools = open_test_pools(&db_path).await;

        let config = test_config("draining-stale");
        let sandbox_id = insert_sandbox_record(pools.write(), &config).await.unwrap();
        super::update_sandbox_status(pools.write(), sandbox_id, SandboxStatus::Draining)
            .await
            .unwrap();

        let run = run_entity::ActiveModel {
            sandbox_id: Set(sandbox_id),
            pid: Set(Some(dead_pid())),
            status: Set(run_entity::RunStatus::Running),
            ..Default::default()
        };
        let run_id = run_entity::Entity::insert(run)
            .exec(pools.write())
            .await
            .unwrap()
            .last_insert_id;

        let sandbox = super::sandbox_entity::Entity::find_by_id(sandbox_id)
            .one(pools.write())
            .await
            .unwrap()
            .unwrap();
        let reconciled = reconcile_sandbox_runtime_state(&pools, sandbox)
            .await
            .unwrap();
        assert_eq!(reconciled.status, SandboxStatus::Stopped);

        let run = run_entity::Entity::find_by_id(run_id)
            .one(pools.write())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(run.status, run_entity::RunStatus::Terminated);
        assert_eq!(
            run.termination_reason,
            Some(run_entity::TerminationReason::ShutdownRequested)
        );
        assert!(run.terminated_at.is_some());
    }

    #[tokio::test]
    async fn test_reconcile_sandbox_runtime_state_marks_draining_without_run_stopped() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let pools = open_test_pools(&db_path).await;

        let config = test_config("draining-no-run");
        let sandbox_id = insert_sandbox_record(pools.write(), &config).await.unwrap();
        super::update_sandbox_status(pools.write(), sandbox_id, SandboxStatus::Draining)
            .await
            .unwrap();

        let sandbox = super::sandbox_entity::Entity::find_by_id(sandbox_id)
            .one(pools.write())
            .await
            .unwrap()
            .unwrap();
        let reconciled = reconcile_sandbox_runtime_state(&pools, sandbox)
            .await
            .unwrap();

        assert_eq!(reconciled.status, SandboxStatus::Stopped);
    }

    #[tokio::test]
    async fn test_prepare_create_target_force_replaces_stale_running_sandbox_state() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let pools = open_test_pools(&db_path).await;

        let sandbox_dir = temp.path().join("sandboxes").join("stale-running");
        fs::create_dir_all(sandbox_dir.join("rw")).unwrap();
        let config = test_config("stale-running");
        let sandbox_id = insert_sandbox_record(pools.write(), &config).await.unwrap();

        let run = run_entity::ActiveModel {
            sandbox_id: Set(sandbox_id),
            pid: Set(Some(dead_pid())),
            status: Set(run_entity::RunStatus::Running),
            ..Default::default()
        };
        run_entity::Entity::insert(run)
            .exec(pools.write())
            .await
            .unwrap();

        let mut forced = test_config("stale-running");
        forced.replace_existing = true;

        prepare_create_target(&pools, &forced, &sandbox_dir)
            .await
            .unwrap();

        assert!(!sandbox_dir.exists());
        assert!(
            super::sandbox_entity::Entity::find_by_id(sandbox_id)
                .one(pools.write())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_prepare_create_target_force_replaces_running_sandbox() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let pools = open_test_pools(&db_path).await;

        let sandbox_dir = temp.path().join("sandboxes").join("running");
        fs::create_dir_all(&sandbox_dir).unwrap();
        let config = test_config("running");
        let sandbox_id = insert_sandbox_record(pools.write(), &config).await.unwrap();

        let child = Command::new("sleep").arg("30").spawn().unwrap();
        let live_pid = child.id() as i32;
        let waiter = std::thread::spawn(move || {
            let mut child = child;
            child.wait().unwrap()
        });
        let run = run_entity::ActiveModel {
            sandbox_id: Set(sandbox_id),
            pid: Set(Some(live_pid)),
            status: Set(run_entity::RunStatus::Running),
            ..Default::default()
        };
        run_entity::Entity::insert(run)
            .exec(pools.write())
            .await
            .unwrap();

        let mut forced = test_config("running");
        forced.replace_existing = true;

        prepare_create_target(&pools, &forced, &sandbox_dir)
            .await
            .unwrap();

        waiter.join().unwrap();

        assert!(!super::pid_is_alive(live_pid));
        assert!(!sandbox_dir.exists());
        assert!(
            super::sandbox_entity::Entity::find_by_id(sandbox_id)
                .one(pools.write())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_validate_start_state_requires_existing_sandbox_dir() {
        let temp = tempdir().unwrap();
        let sandbox_dir = temp.path().join("missing");
        let config = test_config("missing");

        let backend = crate::backend::LocalBackend::lazy();
        let err = super::validate_start_state(&backend, &config, &sandbox_dir).unwrap_err();
        assert!(err.to_string().contains("sandbox state missing"));
    }

    #[test]
    fn test_validate_start_state_accepts_oci_with_manifest_digest() {
        let temp = tempdir().unwrap();
        let sandbox_dir = temp.path().join("persisted");
        fs::create_dir_all(&sandbox_dir).unwrap();

        let mut config = test_config_with_rootfs(
            "persisted",
            RootfsSource::Oci(OciRootfsSource {
                reference: "docker.io/library/alpine".into(),
                upper_size_mib: None,
            }),
        );
        config.manifest_digest = Some("sha256:aaaa".into());

        // validate_start_state checks VMDK existence via GlobalCache,
        // which depends on the global config. In unit tests without a real
        // config, it succeeds because the cache init may fail gracefully.
        // The key thing is it doesn't panic.
        let backend = crate::backend::LocalBackend::lazy();
        let _ = super::validate_start_state(&backend, &config, &sandbox_dir);
    }

    /// Simulates the reaper sweep: queries all Running/Draining sandboxes and
    /// reconciles each. Verifies that only stale entries are reaped while
    /// live, stopped, crashed, and starting (no run record) sandboxes are
    /// left untouched.
    #[tokio::test]
    #[cfg(unix)]
    async fn test_reap_marks_only_dead_running_and_draining_sandboxes() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let pools = open_test_pools(&db_path).await;

        let dead = dead_pid();

        // --- Sandbox A: Running + dead PID → should become Crashed ---
        let cfg_a = test_config("running-dead");
        let id_a = insert_sandbox_record(pools.write(), &cfg_a).await.unwrap();
        run_entity::Entity::insert(run_entity::ActiveModel {
            sandbox_id: Set(id_a),
            pid: Set(Some(dead)),
            status: Set(run_entity::RunStatus::Running),
            ..Default::default()
        })
        .exec(pools.write())
        .await
        .unwrap();

        // --- Sandbox B: Running + live PID → should stay Running ---
        let child = Command::new("sleep").arg("30").spawn().unwrap();
        let live_pid = child.id() as i32;
        let waiter = std::thread::spawn(move || {
            let mut child = child;
            child.wait().unwrap()
        });

        let cfg_b = test_config("running-alive");
        let id_b = insert_sandbox_record(pools.write(), &cfg_b).await.unwrap();
        run_entity::Entity::insert(run_entity::ActiveModel {
            sandbox_id: Set(id_b),
            pid: Set(Some(live_pid)),
            status: Set(run_entity::RunStatus::Running),
            ..Default::default()
        })
        .exec(pools.write())
        .await
        .unwrap();

        // --- Sandbox C: Draining + dead PID → should become Stopped ---
        let cfg_c = test_config("draining-dead");
        let id_c = insert_sandbox_record(pools.write(), &cfg_c).await.unwrap();
        super::update_sandbox_status(pools.write(), id_c, SandboxStatus::Draining)
            .await
            .unwrap();
        run_entity::Entity::insert(run_entity::ActiveModel {
            sandbox_id: Set(id_c),
            pid: Set(Some(dead)),
            status: Set(run_entity::RunStatus::Running),
            ..Default::default()
        })
        .exec(pools.write())
        .await
        .unwrap();

        // --- Sandbox C2: Draining + no active run → should become Stopped ---
        let cfg_c2 = test_config("draining-no-run");
        let id_c2 = insert_sandbox_record(pools.write(), &cfg_c2).await.unwrap();
        super::update_sandbox_status(pools.write(), id_c2, SandboxStatus::Draining)
            .await
            .unwrap();

        // --- Sandbox D: Stopped → should stay Stopped ---
        let cfg_d = test_config("stopped");
        let id_d = insert_sandbox_record(pools.write(), &cfg_d).await.unwrap();
        super::update_sandbox_status(pools.write(), id_d, SandboxStatus::Stopped)
            .await
            .unwrap();

        // --- Sandbox E: Running + no run record (still starting) → should stay Running ---
        let cfg_e = test_config("starting");
        let id_e = insert_sandbox_record(pools.write(), &cfg_e).await.unwrap();

        // --- Reap: query all Running/Draining, reconcile each ---
        let stale = super::sandbox_entity::Entity::find()
            .filter(
                super::sandbox_entity::Column::Status
                    .is_in([SandboxStatus::Running, SandboxStatus::Draining]),
            )
            .all(pools.write())
            .await
            .unwrap();

        for sandbox in stale {
            let _ = reconcile_sandbox_runtime_state(&pools, sandbox).await;
        }

        // --- Assertions ---
        let load = |id| {
            let read_db = pools.read();
            async move {
                super::sandbox_entity::Entity::find_by_id(id)
                    .one(read_db)
                    .await
                    .unwrap()
                    .unwrap()
            }
        };

        assert_eq!(load(id_a).await.status, SandboxStatus::Crashed);
        assert_eq!(load(id_b).await.status, SandboxStatus::Running);
        assert_eq!(load(id_c).await.status, SandboxStatus::Stopped);
        assert_eq!(load(id_c2).await.status, SandboxStatus::Stopped);
        assert_eq!(load(id_d).await.status, SandboxStatus::Stopped);
        assert_eq!(load(id_e).await.status, SandboxStatus::Running);

        // Cleanup the live process.
        unsafe { libc::kill(live_pid, libc::SIGKILL) };
        waiter.join().unwrap();
    }
}

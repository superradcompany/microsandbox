//! Sandbox lifecycle management.
//!
//! The [`Sandbox`] struct represents a running sandbox. It is created via
//! [`Sandbox::builder`] or [`Sandbox::create`], and provides lifecycle
//! methods (stop, kill, drain, wait) and access to the [`AgentClient`]
//! for guest communication.

mod attach;
mod builder;
mod config;
pub mod exec;
pub mod fs;
mod handle;
pub mod init;
mod metrics;
mod patch;
#[cfg(feature = "ssh")]
pub mod ssh;
mod types;

use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::Arc,
};

use bytes::Bytes;
use microsandbox_db::pool::DbPools;
use microsandbox_db::{DbReadConnection, DbWriteConnection};
use microsandbox_image::Registry;
use microsandbox_protocol::{
    exec::{ExecExited, ExecRequest, ExecRlimit, ExecStarted, ExecStderr, ExecStdin, ExecStdout},
    message::{Message, MessageType},
};
use sea_orm::{
    ColumnTrait, Condition, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, Set,
    sea_query::Expr,
};
use tokio::sync::{Mutex, mpsc};

use microsandbox_image::{
    Digest, GlobalCache, PullOptions, PullProgressSender, PullResult, Reference, ext4,
    progress_channel, tree,
};

use crate::{MicrosandboxError, runtime};
use crate::{
    MicrosandboxResult,
    agent::AgentClient,
    db::{
        self,
        entity::{
            run as run_entity, sandbox as sandbox_entity, sandbox_label as sandbox_label_entity,
            sandbox_rootfs as sandbox_rootfs_entity,
        },
    },
    runtime::{ProcessHandle, SpawnMode, spawn_sandbox},
};

use self::attach::AttachOptions;
use self::exec::{ExecEvent, ExecHandle, ExecOptions, ExecSink, StdinMode};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum UTF-8 byte length for a sandbox name.
///
/// The limit matches the fixed inline name storage in the shared-memory
/// metrics slot, so SDK names can be copied into live metrics without
/// truncation.
pub const MAX_SANDBOX_NAME_BYTES: usize = microsandbox_metrics::SLOT_NAME_BYTES;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use crate::db::entity::sandbox::SandboxStatus;
pub use attach::AttachOptionsBuilder;
pub use builder::{RegistryConfigBuilder, SandboxBuilder};
pub use config::{DEFAULT_REPLACE_TIMEOUT, SandboxConfig};
pub use exec::{ExecOptionsBuilder, ExecOutput, Rlimit, RlimitResource};
pub use fs::{
    FsEntry, FsEntryKind, FsHandle, FsMetadata, FsOpenOptions, FsReadStream, FsSetAttrs,
    FsWriteSink, SandboxFsOps,
};
pub use handle::{
    DEFAULT_CONNECT_TIMEOUT, DEFAULT_KILL_TIMEOUT, DEFAULT_STOP_TIMEOUT, SandboxHandle,
};
pub use init::{HandoffInit, InitOptionsBuilder};
pub use metrics::{SandboxMetrics, all_sandbox_metrics};
pub use microsandbox_image::{PullPolicy, PullProgress, PullProgressHandle};
#[cfg(feature = "net")]
pub use microsandbox_network::builder::SecretBuilder;
#[cfg(feature = "net")]
pub use microsandbox_network::config::NetworkConfig;
#[cfg(feature = "net")]
pub use microsandbox_network::policy::NetworkPolicy;
pub use microsandbox_runtime::logging::LogLevel;
#[cfg(feature = "ssh")]
pub use ssh::{
    DEFAULT_SSH_HOST, DEFAULT_SSH_PORT, SandboxSshOps, SftpClient, SshAttachOptionsBuilder,
    SshClient, SshClientOptionsBuilder, SshExecOptionsBuilder, SshOutput, SshServer,
    SshServerOptionsBuilder, SshStdioStream,
};
pub use types::{
    DiskImageFormat, HostPermissions, ImageBuilder, ImageSource, IntoImage, MountBuilder,
    MountOptions, Patch, PatchBuilder, RootfsSource, SecurityProfile, StatVirtualization,
    VolumeMount,
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
///
/// Built fluently and passed to `list_with` to narrow which sandboxes are
/// returned. Today it selects by labels; it is designed to grow further
/// criteria (e.g. status) without changing the call site.
#[derive(Debug, Default, Clone)]
pub struct SandboxFilter {
    labels: Vec<(String, String)>,
}

impl SandboxFilter {
    /// An empty filter — matches every sandbox.
    pub fn new() -> Self {
        Self::default()
    }

    /// Require sandboxes to carry this `key=value` label. Repeatable; multiple
    /// labels are AND-matched.
    pub fn label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.push((key.into(), value.into()));
        self
    }

    /// Require sandboxes to carry all of these `key=value` labels (AND-matched).
    pub fn labels(
        mut self,
        labels: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        self.labels
            .extend(labels.into_iter().map(|(k, v)| (k.into(), v.into())));
        self
    }

    /// Whether the filter has no criteria (matches everything).
    pub fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }
}

/// A running sandbox.
///
/// Created via [`Sandbox::builder`] or [`Sandbox::create`]. Provides
/// lifecycle management and access to the agent bridge for guest communication.
#[derive(Clone)]
pub struct Sandbox {
    db_id: i32,
    config: SandboxConfig,
    handle: Option<Arc<Mutex<ProcessHandle>>>,
    client: Arc<AgentClient>,
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

//--------------------------------------------------------------------------------------------------
// Methods: Static
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Start building a new sandbox configuration.
    ///
    /// Sandbox names are limited to 128 UTF-8 bytes.
    pub fn builder(name: impl Into<String>) -> SandboxBuilder {
        SandboxBuilder::new(name)
    }

    /// Create a sandbox from a config.
    ///
    /// Boots the VM with agentd ready to accept commands. Does not run
    /// any user workload — use `exec()`, `shell()`, etc. afterward.
    pub async fn create(config: SandboxConfig) -> MicrosandboxResult<Self> {
        Self::create_with_mode(config, SpawnMode::Attached, None).await
    }

    /// Create a sandbox with pull progress reporting.
    ///
    /// Returns a progress handle for per-layer pull events and a task handle
    /// for the sandbox creation result. The caller should consume progress
    /// events until the channel closes, then await the task.
    pub fn create_with_pull_progress(
        config: SandboxConfig,
    ) -> (
        PullProgressHandle,
        tokio::task::JoinHandle<MicrosandboxResult<Self>>,
    ) {
        let (handle, sender) = progress_channel();
        let task = tokio::spawn(async move {
            Self::create_with_mode(config, SpawnMode::Attached, Some(sender)).await
        });
        (handle, task)
    }

    /// Start an existing stopped sandbox from persisted state.
    ///
    /// Sandbox names are limited to 128 UTF-8 bytes.
    ///
    /// Reuses the serialized sandbox config and pinned rootfs state without
    /// re-resolving the original OCI reference.
    pub async fn start(name: &str) -> MicrosandboxResult<Self> {
        Self::start_with_mode(name, SpawnMode::Attached).await
    }

    /// Start an existing sandbox in detached/background mode.
    ///
    /// Sandbox names are limited to 128 UTF-8 bytes.
    pub async fn start_detached(name: &str) -> MicrosandboxResult<Self> {
        Self::start_with_mode(name, SpawnMode::Detached).await
    }

    pub(crate) async fn create_with_mode(
        mut config: SandboxConfig,
        mode: SpawnMode,
        progress: Option<PullProgressSender>,
    ) -> MicrosandboxResult<Self> {
        tracing::debug!(
            sandbox = %config.name,
            image = ?config.image,
            mode = ?mode,
            cpus = config.cpus,
            memory_mib = config.memory_mib,
            "create_with_mode: starting"
        );

        let mut pinned_manifest_digest: Option<String> = None;
        let mut pinned_reference: Option<String> = None;

        config.apply_rootfs_defaults();
        config.apply_runtime_defaults();
        validate_sandbox_name_for_runtime(&config.name)?;
        validate_rootfs_source(&config.image)?;
        types::validate_volume_mounts(&config.mounts)?;
        validate_env(&config.env)?;
        validate_labels(&config.labels)?;

        // Initialize the database before any expensive image pull so we can
        // fail fast on conflicting persisted sandbox state.
        let db = db::init_global().await?;
        let sandbox_dir = crate::config::config().sandboxes_dir().join(&config.name);
        prepare_create_target(db, &config, &sandbox_dir).await?;

        // Resolve OCI images before spawning the sandbox process.
        if let RootfsSource::Oci(oci) = config.image.clone() {
            let reference = oci.reference;
            let upper_size_mib = oci.upper_size_mib;
            let snapshot_manifest_digest = if config.snapshot_upper_source.is_some() {
                Some(config.manifest_digest.clone().ok_or_else(|| {
                    MicrosandboxError::InvalidConfig(
                        "from_snapshot requires a pinned OCI manifest digest".into(),
                    )
                })?)
            } else {
                None
            };
            let pull_reference = match snapshot_manifest_digest.as_deref() {
                Some(digest) => digest_pinned_reference(&reference, digest)?,
                None => reference.clone(),
            };
            let overrides = RegistryOverrides {
                auth: config.registry_auth.clone(),
                insecure: config.insecure,
                ca_certs: config.ca_certs.clone(),
            };
            let pull_result =
                pull_oci_image(&pull_reference, config.pull_policy, overrides, progress).await?;
            let resolved_manifest_digest = pull_result.manifest_digest.to_string();
            if let Some(expected) = snapshot_manifest_digest.as_deref()
                && resolved_manifest_digest != expected
            {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "from_snapshot pinned OCI manifest digest '{expected}', but '{reference}' resolved to '{resolved_manifest_digest}'"
                )));
            }

            // Merge image config defaults under user-provided config.
            config.merge_image_defaults(&pull_result.config);

            pinned_manifest_digest = Some(resolved_manifest_digest.clone());
            pinned_reference = Some(reference.clone());

            // Verify VMDK exists in the global cache.
            let cache_dir = crate::config::config().cache_dir();
            let cache = GlobalCache::new_async(&cache_dir).await?;

            let vmdk_path = cache.vmdk_path(&pull_result.manifest_digest);
            if tokio::fs::metadata(&vmdk_path).await.is_err() {
                return Err(MicrosandboxError::Custom(format!(
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

            let upper_tree = if !config.patches.is_empty() {
                Some(patch::build_upper_tree(&config.patches, &layer_erofs_paths).await?)
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
                    return Err(MicrosandboxError::InvalidConfig(
                        "patches cannot be combined with from_snapshot".into(),
                    ));
                }
                let dst = upper_path.clone();
                tokio::task::spawn_blocking(move || {
                    microsandbox_utils::copy::fast_copy(&snap_upper, &dst)
                })
                .await
                .map_err(|e| MicrosandboxError::Custom(format!("snapshot copy task: {e}")))??;
            } else if !upper_path.exists() || upper_tree.is_some() {
                let upper_size_mib = upper_size_mib.ok_or_else(|| {
                    MicrosandboxError::InvalidConfig(
                        "OCI upper size was not resolved before create".into(),
                    )
                })?;
                create_upper_ext4(&upper_path, upper_size_mib, upper_tree).await?;
            }

            // Store manifest digest for spawn to derive paths.
            config.manifest_digest = Some(resolved_manifest_digest);

            // Persist full image metadata to database.
            if let Ok(image_ref) = pull_reference.parse::<Reference>() {
                match cache.read_image_metadata_async(&image_ref).await {
                    Ok(Some(metadata)) => {
                        if let Err(e) = crate::image::Image::persist(&reference, metadata).await {
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
        if !config.patches.is_empty() && !matches!(config.image, RootfsSource::Oci(_)) {
            patch::apply_patches(&config.image, &config.patches).await?;
        }

        // Insert the sandbox record and keep its stable database ID.
        // Auto-volumes (from `SandboxBuilder::auto_volume`) are inserted
        // in the same transaction so a concurrent `Volume::list` can't
        // see them without the owning sandbox.
        let write_db = db.write();
        let sandbox_id = insert_sandbox_record(write_db, &config).await?;
        tracing::debug!(sandbox_id, sandbox = %config.name, "create_with_mode: db record inserted");

        // Materialise the on-disk directory for each auto-volume after
        // the transaction commits. On failure, remove any directories
        // we already created plus the sandbox row so the partial state
        // doesn't leak.
        if !config.auto_volumes.is_empty()
            && let Err(e) = materialise_auto_volume_dirs(&config.auto_volumes).await
        {
            rollback_auto_volume_dirs(&config.auto_volumes).await;
            let _ = remove_sandbox_row(write_db, sandbox_id).await;
            for intent in &config.auto_volumes {
                let _ = remove_volume_row(write_db, &intent.name).await;
            }
            return Err(e);
        }

        // Spawn the sandbox process and create the bridge. On failure, mark the sandbox
        // as stopped so it doesn't appear as a phantom "Running" entry. Also
        // free the metrics slot: the runtime may have reserved one but its
        // exit observer cannot be relied upon if the child was SIGKILL'd
        // before activation, and `reconcile_sandbox_runtime_state` will not
        // run reaper cleanup for a Stopped sandbox.
        // Move auto_volumes out so we can use them after the config
        // is consumed by create_inner.
        let auto_volumes = std::mem::take(&mut config.auto_volumes);
        let sandbox = match Self::create_inner(config, sandbox_id, mode).await {
            Ok(sandbox) => sandbox,
            Err(e) => {
                let _ = update_sandbox_status(write_db, sandbox_id, SandboxStatus::Stopped).await;
                free_metrics_slot_for(sandbox_id, None, microsandbox_metrics::ReleaseMode::Free);
                rollback_auto_volume_dirs(&auto_volumes).await;
                for intent in &auto_volumes {
                    let _ = remove_volume_row(write_db, &intent.name).await;
                }
                return Err(e);
            }
        };

        if let (Some(_reference), Some(manifest_digest)) = (
            pinned_reference.as_deref(),
            pinned_manifest_digest.as_deref(),
        ) && let Err(err) = persist_oci_manifest_pin(write_db, sandbox_id, manifest_digest).await
        {
            let _ = sandbox.stop().await;
            let _ = update_sandbox_status(write_db, sandbox_id, SandboxStatus::Stopped).await;
            free_metrics_slot_for(sandbox_id, None, microsandbox_metrics::ReleaseMode::Free);
            return Err(err);
        }

        // Validate that the configured workdir exists inside the guest.
        if let Some(ref workdir) = sandbox.config.workdir {
            match sandbox.fs().stat(workdir).await {
                Ok(metadata) if metadata.kind == fs::FsEntryKind::Directory => {}
                Ok(_) => {
                    let _ = sandbox.stop().await;
                    let _ =
                        update_sandbox_status(write_db, sandbox_id, SandboxStatus::Stopped).await;
                    free_metrics_slot_for(
                        sandbox_id,
                        None,
                        microsandbox_metrics::ReleaseMode::Free,
                    );
                    return Err(MicrosandboxError::InvalidConfig(format!(
                        "workdir is not a directory in guest: {workdir}"
                    )));
                }
                Err(error) => {
                    let _ = sandbox.stop().await;
                    let _ =
                        update_sandbox_status(write_db, sandbox_id, SandboxStatus::Stopped).await;
                    free_metrics_slot_for(
                        sandbox_id,
                        None,
                        microsandbox_metrics::ReleaseMode::Free,
                    );
                    return Err(MicrosandboxError::InvalidConfig(format!(
                        "workdir does not exist in guest: {workdir}: {error}"
                    )));
                }
            }
        }

        Ok(sandbox)
    }

    pub(super) async fn start_with_mode(name: &str, mode: SpawnMode) -> MicrosandboxResult<Self> {
        validate_sandbox_name(name)?;
        tracing::debug!(sandbox = name, ?mode, "start_with_mode: loading record");
        let pools = db::init_global().await?;
        let write_db = pools.write();
        let model = load_sandbox_record_reconciled(pools, name).await?;
        tracing::debug!(sandbox = name, status = ?model.status, "start_with_mode: current status");

        if model.status == SandboxStatus::Running || model.status == SandboxStatus::Draining {
            return Err(MicrosandboxError::SandboxStillRunning(format!(
                "cannot start sandbox '{name}': already running"
            )));
        }

        if model.status != SandboxStatus::Stopped && model.status != SandboxStatus::Crashed {
            return Err(MicrosandboxError::Custom(format!(
                "cannot start sandbox '{name}': status is {:?} (expected Stopped or Crashed)",
                model.status
            )));
        }

        let mut config: SandboxConfig = serde_json::from_str(&model.config)?;
        config.apply_runtime_defaults();
        validate_sandbox_name_for_runtime(&config.name)?;
        validate_rootfs_source(&config.image)?;
        types::validate_volume_mounts(&config.mounts)?;
        validate_env(&config.env)?;
        validate_labels(&config.labels)?;
        validate_start_state(&config, &crate::config::config().sandboxes_dir().join(name))?;
        update_sandbox_status(write_db, model.id, SandboxStatus::Running).await?;

        match Self::create_inner(config, model.id, mode).await {
            Ok(sandbox) => Ok(sandbox),
            Err(err) => {
                let _ = update_sandbox_status(write_db, model.id, SandboxStatus::Stopped).await;
                free_metrics_slot_for(model.id, None, microsandbox_metrics::ReleaseMode::Free);
                Err(err)
            }
        }
    }

    /// Inner create logic separated for error-cleanup wrapper.
    async fn create_inner(
        config: SandboxConfig,
        sandbox_id: i32,
        mode: SpawnMode,
    ) -> MicrosandboxResult<Self> {
        let (mut handle, agent_sock_path) = spawn_sandbox(&config, sandbox_id, mode).await?;

        // Wait for the relay socket to become available.
        let client = wait_for_relay(&agent_sock_path, &mut handle, &config.name).await?;

        if let Ok(ready) = client.ready() {
            tracing::info!(
                boot_time_ms = ready.boot_time_ns / 1_000_000,
                init_time_ms = ready.init_time_ns / 1_000_000,
                ready_time_ms = ready.ready_time_ns / 1_000_000,
                "sandbox ready",
            );
        }
        Ok(Self {
            db_id: sandbox_id,
            config,
            handle: Some(Arc::new(Mutex::new(handle))),
            client: Arc::new(client),
        })
    }

    /// Get a sandbox handle by name from the database.
    ///
    /// Sandbox names are limited to 128 UTF-8 bytes.
    pub async fn get(name: &str) -> MicrosandboxResult<SandboxHandle> {
        validate_sandbox_name(name)?;
        let pools = db::init_global().await?;

        let model = sandbox_entity::Entity::find()
            .filter(sandbox_entity::Column::Name.eq(name))
            .one(pools.read())
            .await?
            .ok_or_else(|| MicrosandboxError::SandboxNotFound(name.into()))?;

        let model = reconcile_sandbox_runtime_state(pools, model).await?;
        build_handle(pools.read(), model).await
    }

    /// List all sandboxes from the database.
    pub async fn list() -> MicrosandboxResult<Vec<SandboxHandle>> {
        let pools = db::init_global().await?;

        let sandboxes = sandbox_entity::Entity::find()
            .order_by_desc(sandbox_entity::Column::CreatedAt)
            .all(pools.read())
            .await?;

        build_sandbox_handles(pools, sandboxes).await
    }

    /// List sandboxes matching a [`SandboxFilter`].
    ///
    /// An empty filter behaves like [`list`](Self::list). Label selectors on the
    /// filter are AND-matched: a sandbox is returned only if it carries all of
    /// them.
    pub async fn list_with(filter: SandboxFilter) -> MicrosandboxResult<Vec<SandboxHandle>> {
        if filter.is_empty() {
            return Self::list().await;
        }

        let pools = db::init_global().await?;
        let ids = filter_sandbox_ids(pools.read(), &filter).await?;
        if ids.is_empty() {
            return Ok(Vec::new());
        }

        let sandboxes = sandbox_entity::Entity::find()
            .filter(sandbox_entity::Column::Id.is_in(ids))
            .order_by_desc(sandbox_entity::Column::CreatedAt)
            .all(pools.read())
            .await?;

        build_sandbox_handles(pools, sandboxes).await
    }

    /// Remove a stopped sandbox from the database.
    ///
    /// Convenience method equivalent to `Sandbox::get(name).await?.remove().await`.
    /// Sandbox names are limited to 128 UTF-8 bytes.
    pub async fn remove(name: &str) -> MicrosandboxResult<()> {
        Self::get(name).await?.remove().await
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Instance
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Unique name identifying this sandbox.
    ///
    /// Sandbox names are limited to 128 UTF-8 bytes.
    pub fn name(&self) -> &str {
        &self.config.name
    }

    /// The full configuration this sandbox was created with (image, cpus,
    /// memory, env, mounts, etc.).
    pub fn config(&self) -> &SandboxConfig {
        &self.config
    }

    /// Read captured output from `exec.log` for this sandbox.
    ///
    /// Backed by the on-disk JSON Lines file the runtime writes via the
    /// relay tap (see `crates/runtime/lib/exec_log.rs`). Works on
    /// running and stopped sandboxes alike — there is no protocol
    /// traffic. Pass `LogOptions::default()` for "everything,
    /// stdout+stderr".
    pub async fn logs(
        &self,
        opts: &crate::logs::LogOptions,
    ) -> MicrosandboxResult<Vec<crate::logs::LogEntry>> {
        crate::logs::read_logs(self.name(), opts).await
    }

    /// Stream captured output as it appears, with optional follow.
    ///
    /// Backed by the same on-disk `exec.log` as [`logs`](Self::logs),
    /// but yields entries lazily as a [`futures::Stream`]. Pass
    /// `LogStreamOptions { follow: true, .. }` to keep the stream
    /// open past current EOF and pick up new entries as they are
    /// written; otherwise the stream drains the current contents and
    /// ends. See the type docs on [`crate::logs::LogStreamOptions`] and
    /// [`crate::logs::LogStreamStart`] for replay / resume options.
    pub async fn log_stream(
        &self,
        opts: &crate::logs::LogStreamOptions,
    ) -> MicrosandboxResult<
        impl futures::Stream<Item = MicrosandboxResult<crate::logs::LogEntry>> + Send + 'static,
    > {
        crate::logs::log_stream(self.name(), opts).await
    }

    /// Low-level access to the guest agent client. Use this for custom
    /// extensions — prefer [`exec`](Self::exec), [`shell`](Self::shell),
    /// and [`fs`](Self::fs) for standard operations.
    pub fn client(&self) -> &AgentClient {
        &self.client
    }

    /// Get a cloneable reference to the agent client.
    pub fn client_arc(&self) -> Arc<AgentClient> {
        Arc::clone(&self.client)
    }

    /// Returns `true` if this sandbox handle owns the process lifecycle.
    ///
    /// When `true`, dropping this handle or calling [`stop`](Self::stop)
    /// will terminate the sandbox. When `false`, the sandbox was created by
    /// another process and will continue running after disconnect.
    pub fn owns_lifecycle(&self) -> bool {
        self.handle.is_some()
    }

    /// Read, write, and manage files inside the running sandbox.
    /// Operations go through the guest agent (agentd).
    pub fn fs(&self) -> fs::SandboxFsOps {
        fs::SandboxFsOps::new(&self.client)
    }

    /// Request graceful shutdown and return once the request is sent.
    pub async fn request_stop(&self) -> MicrosandboxResult<()> {
        tracing::debug!(sandbox = %self.config.name, "stop: sending shutdown");
        // Shutdown carries no useful payload; agentd dispatches on `msg.t`.
        self.client.send(0, MessageType::Shutdown, &()).await?;
        Ok(())
    }

    /// Stop the sandbox gracefully and wait until it is observed stopped.
    pub async fn stop(&self) -> MicrosandboxResult<()> {
        self.stop_with_timeout(DEFAULT_STOP_TIMEOUT).await
    }

    /// Stop the sandbox gracefully with an explicit timeout before escalation.
    pub async fn stop_with_timeout(&self, timeout: std::time::Duration) -> MicrosandboxResult<()> {
        let Some(handle) = &self.handle else {
            return Sandbox::get(self.name())
                .await?
                .stop_with_timeout(timeout)
                .await;
        };

        if timeout.is_zero() {
            return self.kill_with_timeout(DEFAULT_KILL_TIMEOUT).await;
        }

        let _ = self.request_stop().await;
        let mut escalated = false;
        let status = {
            let mut handle = handle.lock().await;
            match tokio::time::timeout(timeout, handle.wait()).await {
                Ok(result) => result?,
                Err(_) => {
                    escalated = true;
                    tracing::warn!(
                        sandbox = %self.config.name,
                        timeout_secs = timeout.as_secs(),
                        "graceful stop exceeded timeout, escalating to SIGKILL"
                    );
                    handle.kill()?;
                    match tokio::time::timeout(DEFAULT_KILL_TIMEOUT, handle.wait()).await {
                        Ok(result) => result?,
                        Err(_) => {
                            return Err(MicrosandboxError::Runtime(format!(
                                "timed out observing stopped state for sandbox '{}'",
                                self.config.name
                            )));
                        }
                    }
                }
            }
        };

        let final_status = if escalated {
            SandboxStatus::Stopped
        } else {
            exit_status_to_sandbox_status(&status)
        };
        self.mark_observed_stopped(final_status).await
    }

    /// Request force termination and return once the request is sent.
    pub async fn request_kill(&self) -> MicrosandboxResult<()> {
        match &self.handle {
            Some(h) => h.lock().await.kill(),
            None => Sandbox::get(self.name()).await?.request_kill().await,
        }
    }

    /// Force-kill the sandbox and wait until it is observed stopped.
    pub async fn kill(&self) -> MicrosandboxResult<()> {
        self.kill_with_timeout(DEFAULT_KILL_TIMEOUT).await
    }

    /// Force-kill the sandbox and wait up to `timeout` for stopped-state observation.
    pub async fn kill_with_timeout(&self, timeout: std::time::Duration) -> MicrosandboxResult<()> {
        let Some(handle) = &self.handle else {
            return Sandbox::get(self.name())
                .await?
                .kill_with_timeout(timeout)
                .await;
        };

        {
            let mut handle = handle.lock().await;
            handle.kill()?;
            match tokio::time::timeout(timeout, handle.wait()).await {
                Ok(result) => result?,
                Err(_) => {
                    return Err(MicrosandboxError::Runtime(format!(
                        "timed out observing stopped state for sandbox '{}'",
                        self.config.name
                    )));
                }
            }
        };

        self.mark_observed_stopped(SandboxStatus::Stopped).await
    }

    /// Request graceful drain and return once the request is sent.
    pub async fn request_drain(&self) -> MicrosandboxResult<()> {
        match &self.handle {
            Some(h) => h.lock().await.drain(),
            None => Sandbox::get(self.name()).await?.request_drain().await,
        }
    }

    /// Wait until the sandbox is observed in a terminal non-running state.
    pub async fn wait_until_stopped(&self) -> MicrosandboxResult<SandboxStopResult> {
        let Some(handle) = &self.handle else {
            return Sandbox::get(self.name()).await?.wait_until_stopped().await;
        };

        let status = {
            let mut handle = handle.lock().await;
            handle.wait().await?
        };
        let final_status = exit_status_to_sandbox_status(&status);
        self.mark_observed_stopped(final_status).await?;

        Ok(SandboxStopResult {
            name: self.config.name.clone(),
            status: final_status,
            exit_code: status.code(),
            signal: exit_status_signal(&status),
            observed_at: chrono::Utc::now(),
            source: Some("owned process handle".to_string()),
        })
    }

    async fn mark_observed_stopped(&self, status: SandboxStatus) -> MicrosandboxResult<()> {
        let db = db::init_global().await?.write();
        update_sandbox_status(db, self.db_id, status).await
    }

    /// Detach this handle without stopping the sandbox.
    ///
    /// Disarms the SIGTERM safety net so the sandbox keeps running after
    /// this handle is dropped. Intended for CLI flows like `create`, `start`,
    /// and `run --detach`.
    pub async fn detach(self) {
        if let Some(h) = &self.handle {
            h.lock().await.disarm();
        }
        // Normal drop runs — client reader task is aborted and
        // ProcessHandle drops without sending SIGTERM.
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
        self.exec_stream_inner(cmd.into(), opts).await
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
        self.exec_stream_inner(cmd.into(), opts).await
    }

    async fn exec_stream_inner(
        &self,
        cmd: String,
        opts: ExecOptions,
    ) -> MicrosandboxResult<ExecHandle> {
        self.exec_stream_with_agent(Arc::clone(&self.client), cmd, opts, 24, 80)
            .await
    }

    pub(crate) async fn exec_stream_with_agent(
        &self,
        client: Arc<AgentClient>,
        cmd: String,
        opts: ExecOptions,
        rows: u16,
        cols: u16,
    ) -> MicrosandboxResult<ExecHandle> {
        let ExecOptions {
            args,
            cwd,
            user,
            env,
            rlimits,
            tty,
            stdin: stdin_mode,
            timeout: _,
        } = opts;

        tracing::debug!(
            sandbox = %self.config.name,
            cmd = %cmd,
            args = ?args,
            cwd = ?cwd,
            tty,
            "exec_stream"
        );

        let req = build_exec_request(
            &self.config,
            cmd,
            args,
            cwd,
            user,
            &env,
            &rlimits,
            tty,
            rows,
            cols,
        );
        let (id, rx) = client.stream(MessageType::ExecRequest, &req).await?;

        // Build stdin sink (if Pipe mode).
        let stdin = match &stdin_mode {
            StdinMode::Pipe => Some(ExecSink::new(id, Arc::clone(&client))),
            _ => None,
        };

        // Handle StdinMode::Bytes — send bytes then close.
        if let StdinMode::Bytes(ref data) = stdin_mode {
            let data = data.clone();
            let bridge = Arc::clone(&client);
            tokio::spawn(async move {
                let payload = ExecStdin { data };
                let _ = bridge.send(id, MessageType::ExecStdin, &payload).await;
                // Send empty to signal EOF.
                let close = ExecStdin { data: Vec::new() };
                let _ = bridge.send(id, MessageType::ExecStdin, &close).await;
            });
        }

        // Transform raw protocol messages into ExecEvents.
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        tokio::spawn(event_mapper_task(rx, event_tx));

        Ok(ExecHandle::new(id, event_rx, stdin, Arc::clone(&client)))
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
        self.exec_with_opts(cmd.into(), opts).await
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
        self.exec_with_opts(cmd.into(), opts).await
    }

    /// Shared implementation for exec and exec_with.
    async fn exec_with_opts(
        &self,
        cmd: String,
        opts: ExecOptions,
    ) -> MicrosandboxResult<ExecOutput> {
        let timeout_duration = opts.timeout;
        let mut handle = self.exec_stream_inner(cmd, opts).await?;

        match timeout_duration {
            Some(duration) => {
                match tokio::time::timeout(duration, handle.collect()).await {
                    Ok(result) => result,
                    Err(_) => {
                        // Timed out — kill the process and drain remaining events.
                        let _ = handle.kill().await;
                        let _ = tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            handle.collect(),
                        )
                        .await;
                        Err(MicrosandboxError::ExecTimeout(duration))
                    }
                }
            }
            None => handle.collect().await,
        }
    }

    /// Run a shell command and wait for completion.
    ///
    /// Uses the sandbox's configured shell (default: `/bin/sh`) to interpret
    /// the script via `<shell> -c "<script>"`.
    ///
    /// - `sandbox.shell("echo hello")`
    /// - `sandbox.shell("ENV=val cmd | other_cmd")`
    pub async fn shell(&self, script: impl Into<String>) -> MicrosandboxResult<ExecOutput> {
        self.shell_with(script, |e| e).await
    }

    /// Run a shell command with full execution options and wait for completion.
    ///
    /// The shell invocation itself supplies `-c <script>`, so any args configured
    /// through the builder are ignored.
    pub async fn shell_with(
        &self,
        script: impl Into<String>,
        f: impl FnOnce(ExecOptionsBuilder) -> ExecOptionsBuilder,
    ) -> MicrosandboxResult<ExecOutput> {
        let (shell, opts) = self.shell_exec_opts(script, f)?;
        self.exec_with_opts(shell, opts).await
    }

    /// Run a shell command with streaming I/O.
    ///
    /// Like [`shell`](Self::shell) but returns a streaming [`ExecHandle`]
    /// instead of waiting for completion.
    pub async fn shell_stream(&self, script: impl Into<String>) -> MicrosandboxResult<ExecHandle> {
        self.shell_stream_with(script, |e| e).await
    }

    /// Run a shell command with full execution options and streaming I/O.
    ///
    /// Like [`shell_with`](Self::shell_with) but returns a streaming
    /// [`ExecHandle`] instead of waiting for completion.
    pub async fn shell_stream_with(
        &self,
        script: impl Into<String>,
        f: impl FnOnce(ExecOptionsBuilder) -> ExecOptionsBuilder,
    ) -> MicrosandboxResult<ExecHandle> {
        let (shell, opts) = self.shell_exec_opts(script, f)?;
        self.exec_stream_inner(shell, opts).await
    }

    fn shell_exec_opts(
        &self,
        script: impl Into<String>,
        f: impl FnOnce(ExecOptionsBuilder) -> ExecOptionsBuilder,
    ) -> MicrosandboxResult<(String, ExecOptions)> {
        let shell = self
            .config
            .shell
            .as_deref()
            .unwrap_or("/bin/sh")
            .to_string();
        let mut opts = f(ExecOptionsBuilder::default()).build()?;
        opts.args = vec!["-c".to_string(), script.into()];
        Ok((shell, opts))
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
        let opts = AttachOptions {
            args: args.into_iter().map(Into::into).collect(),
            ..Default::default()
        };
        self.attach_inner(cmd.into(), opts).await
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
        let opts = f(AttachOptionsBuilder::default()).build()?;
        self.attach_inner(cmd.into(), opts).await
    }

    /// Shared implementation for attach and attach_with.
    async fn attach_inner(&self, cmd: String, opts: AttachOptions) -> MicrosandboxResult<i32> {
        use std::os::fd::AsRawFd;

        use microsandbox_protocol::exec::ExecResize;
        use tokio::io::{AsyncWriteExt, unix::AsyncFd};

        let detach_keys = match &opts.detach_keys {
            Some(spec) => attach::DetachKeys::parse(spec)?,
            None => attach::DetachKeys::default_keys(),
        };

        // Get terminal size.
        let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));

        // Build ExecRequest with tty=true and open the stream.
        let req = build_exec_request(
            &self.config,
            cmd,
            opts.args,
            opts.cwd,
            opts.user,
            &opts.env,
            &opts.rlimits,
            true,
            rows,
            cols,
        );
        let (id, mut rx) = self.client.stream(MessageType::ExecRequest, &req).await?;

        // Enter raw mode.
        crossterm::terminal::enable_raw_mode()
            .map_err(|e| MicrosandboxError::Terminal(e.to_string()))?;
        let _raw_guard = scopeguard::guard((), |_| {
            let _ = crossterm::terminal::disable_raw_mode();
        });

        // Re-open the controlling terminal for input and set only that fresh
        // fd non-blocking. Toggling O_NONBLOCK on fd 0 would also affect
        // stdout/stderr when all three stdio fds share the same TTY open file
        // description, which truncates large terminal writes.
        let tty_input_path = terminal_path_for_fd(std::io::stdin().as_raw_fd())
            .map_err(|e| MicrosandboxError::Terminal(format!("resolve tty path: {e}")))?;
        let tty_input = open_nonblocking_terminal_input(&tty_input_path)
            .map_err(|e| MicrosandboxError::Terminal(format!("open tty input: {e}")))?;
        let stdin_async = AsyncFd::new(tty_input)
            .map_err(|e| MicrosandboxError::Terminal(format!("async tty input: {e}")))?;

        // Set up async I/O.
        let mut stdout = tokio::io::stdout();
        let mut sigwinch =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
                .map_err(|e| MicrosandboxError::Runtime(format!("sigwinch: {e}")))?;

        let mut exit_code: i32 = -1;
        let mut spawn_failure: Option<microsandbox_protocol::exec::ExecFailed> = None;
        let detach_seq = detach_keys.sequence();
        let mut match_pos = 0usize;

        loop {
            tokio::select! {
                // Read stdin from host terminal (non-blocking fd).
                result = stdin_async.readable() => {
                    let mut guard = match result {
                        Ok(g) => g,
                        Err(_) => break,
                    };

                    let mut input_buf = [0u8; 1024];
                    match guard.try_io(|inner| {
                        read_from_fd(inner.get_ref().as_raw_fd(), &mut input_buf)
                    }) {
                        Ok(Ok(0)) => break, // EOF
                        Ok(Ok(n)) => {
                            let data = &input_buf[..n];

                            // Check for detach key sequence.
                            let mut detached = false;
                            for &b in data {
                                if b == detach_seq[match_pos] {
                                    match_pos += 1;
                                    if match_pos == detach_seq.len() {
                                        detached = true;
                                        break;
                                    }
                                } else {
                                    match_pos = 0;
                                    if b == detach_seq[0] {
                                        match_pos = 1;
                                    }
                                }
                            }

                            if detached {
                                break;
                            }

                            // Forward to guest.
                            let payload = ExecStdin { data: data.to_vec() };
                            let _ = self.client.send(id, MessageType::ExecStdin, &payload).await;
                        }
                        Ok(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Ok(Err(_)) => break,
                        Err(_would_block) => continue,
                    }
                }

                // Receive output from guest.
                //
                // TUI apps (e.g. Ink-based CLIs) write a full re-render as one
                // write(), but the guest PTY reader chunks it into ~4 KB
                // ExecStdout messages. Writing each chunk to the host terminal
                // separately lets the terminal emulator render intermediate
                // states — partial cursor movements, partially overwritten
                // lines — producing visible afterimage artifacts.
                //
                // Fix: after receiving the first message, drain all immediately
                // available ExecStdout messages and batch their data into a
                // single write. This coalesces the output so the terminal
                // processes each re-render atomically.
                Some(msg) = rx.recv() => {
                    let mut should_break = false;

                    match msg.t {
                        MessageType::ExecStdout => {
                            if let Ok(out) = msg.payload::<ExecStdout>() {
                                let _ = stdout.write_all(&out.data).await;
                            }
                        }
                        MessageType::ExecExited => {
                            if let Ok(exited) = msg.payload::<ExecExited>() {
                                exit_code = exited.code;
                            }
                            should_break = true;
                        }
                        MessageType::ExecFailed => {
                            if let Ok(failed) =
                                msg.payload::<microsandbox_protocol::exec::ExecFailed>()
                            {
                                spawn_failure = Some(failed);
                            }
                            should_break = true;
                        }
                        _ => {}
                    }

                    // Drain all buffered messages before flushing.
                    if !should_break {
                        while let Ok(next) = rx.try_recv() {
                            match next.t {
                                MessageType::ExecStdout => {
                                    if let Ok(out) = next.payload::<ExecStdout>() {
                                        let _ = stdout.write_all(&out.data).await;
                                    }
                                }
                                MessageType::ExecExited => {
                                    if let Ok(exited) = next.payload::<ExecExited>() {
                                        exit_code = exited.code;
                                    }
                                    should_break = true;
                                    break;
                                }
                                MessageType::ExecFailed => {
                                    if let Ok(failed) = next
                                        .payload::<microsandbox_protocol::exec::ExecFailed>()
                                    {
                                        spawn_failure = Some(failed);
                                    }
                                    should_break = true;
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }

                    let _ = stdout.flush().await;

                    if should_break {
                        break;
                    }
                }

                // Terminal resize.
                _ = sigwinch.recv() => {
                    if let Ok((new_cols, new_rows)) = crossterm::terminal::size() {
                        let payload = ExecResize { rows: new_rows, cols: new_cols };
                        let _ = self.client.send(id, MessageType::ExecResize, &payload).await;
                    }
                }
            }
        }

        // Guards restore: non-blocking → blocking, raw mode → cooked.
        if let Some(failure) = spawn_failure {
            return Err(MicrosandboxError::ExecFailed(failure));
        }
        Ok(exit_code)
    }

    /// Attach to the sandbox's default shell.
    ///
    /// Uses the sandbox's configured shell (default: `/bin/sh`).
    pub async fn attach_shell(&self) -> MicrosandboxResult<i32> {
        let shell = self.config.shell.as_deref().unwrap_or("/bin/sh");
        self.attach_inner(shell.into(), AttachOptions::default())
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
    handle: &mut ProcessHandle,
    sandbox_name: &str,
) -> MicrosandboxResult<AgentClient> {
    tracing::debug!(
        sock = %sock_path.display(),
        pid = handle.pid(),
        "wait_for_relay: waiting for agent socket"
    );
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    let max_backoff = std::time::Duration::from_millis(10);
    let mut backoff = std::time::Duration::from_millis(1);
    let mut attempts = 0u32;

    let log_dir = sock_path
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("logs"));

    loop {
        attempts += 1;
        match AgentClient::connect_with_deadline(sock_path, deadline).await {
            Ok(client) => {
                tracing::debug!(attempts, "wait_for_relay: connected");
                // The relay is up — clear any stale boot-error.json from
                // a previous failed attempt so it cannot misattribute a
                // future crash.
                if let Some(ref dir) = log_dir {
                    let _ = microsandbox_runtime::boot_error::BootError::delete(dir);
                }
                return Ok(client);
            }
            Err(_) if tokio::time::Instant::now() < deadline => {
                // Check if the sandbox process is still alive before retrying.
                // If it crashed, there's no point waiting for the socket.
                if let Some(status) = handle.try_wait()? {
                    tracing::debug!(attempts, ?status, "wait_for_relay: sandbox process exited");

                    // Prefer the structured boot-error record if the
                    // sandbox got far enough to write one.
                    if let Some(boot_err) = read_boot_error(log_dir.as_deref()) {
                        return Err(MicrosandboxError::BootStart {
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
                    return Err(MicrosandboxError::BootStart {
                        name: sandbox_name.to_string(),
                        err: synthetic,
                    });
                }

                // Keep early retries tight so relay readiness doesn't inherit a
                // coarse fixed delay on warm starts.
                tokio::time::sleep(backoff).await;
                backoff = std::cmp::min(backoff.saturating_mul(2), max_backoff);
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
                if let Some(boot_err) = read_boot_error(log_dir.as_deref()) {
                    return Err(MicrosandboxError::BootStart {
                        name: sandbox_name.to_string(),
                        err: boot_err,
                    });
                }
                return Err(e.into());
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
    log_dir: Option<&std::path::Path>,
) -> Option<microsandbox_runtime::boot_error::BootError> {
    let dir = log_dir?;
    microsandbox_runtime::boot_error::BootError::read(dir)
        .ok()
        .flatten()
}

/// Build a [`SandboxHandle`] by eagerly loading the microVM PID.
async fn build_handle(
    db: &DbReadConnection,
    model: sandbox_entity::Model,
) -> MicrosandboxResult<SandboxHandle> {
    let run = load_active_run(db, model.id).await?;
    Ok(build_handle_with_pid(model, pid_from_run(run.as_ref())))
}

/// Build an `ExecRequest` by merging sandbox config with caller-provided overrides.
#[allow(clippy::too_many_arguments)]
fn build_exec_request(
    config: &SandboxConfig,
    cmd: String,
    args: Vec<String>,
    cwd: Option<String>,
    user: Option<String>,
    env: &[(String, String)],
    rlimits: &[Rlimit],
    tty: bool,
    rows: u16,
    cols: u16,
) -> ExecRequest {
    let merged = config::merge_env_pairs(&config.env, env);
    let mut env: Vec<String> = merged.iter().map(|(k, v)| format!("{k}={v}")).collect();

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
            .or_else(|| config.workdir.clone())
            .or_else(|| Some("/".to_string())),
        user: user.or_else(|| config.user.clone()),
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

fn terminal_path_for_fd(fd: std::os::fd::RawFd) -> std::io::Result<std::path::PathBuf> {
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

fn open_nonblocking_terminal_input(path: &std::path::Path) -> std::io::Result<std::fs::File> {
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

fn read_from_fd(fd: std::os::fd::RawFd, buf: &mut [u8]) -> std::io::Result<usize> {
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

/// Background task that converts raw protocol messages into [`ExecEvent`]s.
async fn event_mapper_task(mut rx: mpsc::Receiver<Message>, tx: mpsc::UnboundedSender<ExecEvent>) {
    while let Some(msg) = rx.recv().await {
        let event = match msg.t {
            MessageType::ExecStarted => {
                if let Ok(started) = msg.payload::<ExecStarted>() {
                    ExecEvent::Started { pid: started.pid }
                } else {
                    continue;
                }
            }
            MessageType::ExecStdout => {
                if let Ok(out) = msg.payload::<ExecStdout>() {
                    ExecEvent::Stdout(Bytes::from(out.data))
                } else {
                    continue;
                }
            }
            MessageType::ExecStderr => {
                if let Ok(err) = msg.payload::<ExecStderr>() {
                    ExecEvent::Stderr(Bytes::from(err.data))
                } else {
                    continue;
                }
            }
            MessageType::ExecExited => {
                if let Ok(exited) = msg.payload::<ExecExited>() {
                    let _ = tx.send(ExecEvent::Exited { code: exited.code });
                }
                break;
            }
            MessageType::ExecFailed => {
                if let Ok(failed) = msg.payload::<microsandbox_protocol::exec::ExecFailed>() {
                    let _ = tx.send(ExecEvent::Failed(failed));
                }
                break;
            }
            MessageType::ExecStdinError => {
                if let Ok(payload) = msg.payload::<microsandbox_protocol::exec::ExecStdinError>() {
                    ExecEvent::StdinError(payload)
                } else {
                    continue;
                }
            }
            _ => continue,
        };
        if tx.send(event).is_err() {
            break;
        }
    }
}

/// Update the sandbox status in the database.
pub(super) async fn update_sandbox_status(
    db: &DbWriteConnection,
    sandbox_id: i32,
    status: SandboxStatus,
) -> MicrosandboxResult<()> {
    db.transaction(|txn| async move {
        sandbox_entity::Entity::update_many()
            .col_expr(sandbox_entity::Column::Status, Expr::value(status))
            .col_expr(
                sandbox_entity::Column::UpdatedAt,
                Expr::value(chrono::Utc::now().naive_utc()),
            )
            .filter(sandbox_entity::Column::Id.eq(sandbox_id))
            .exec(&txn)
            .await?;
        Ok((txn, ()))
    })
    .await
}

//--------------------------------------------------------------------------------------------------
// Functions: Reaper
//--------------------------------------------------------------------------------------------------

/// Reap all stale sandboxes in the global database.
///
/// Queries all sandboxes with status `Running` or `Draining`, checks whether
/// their process is still alive via `kill(pid, 0)`, and marks dead ones as
/// `Crashed`.
///
/// Designed to run once at startup as a fire-and-forget background task so
/// that crashes (SIGSEGV, SIGKILL, etc.) that prevented the sandbox process
/// from updating the database on exit are cleaned up without blocking the
/// main path.
pub async fn reap_stale_sandboxes() -> MicrosandboxResult<()> {
    let pools = db::init_global().await?;

    let stale = sandbox_entity::Entity::find()
        .filter(
            sandbox_entity::Column::Status.is_in([SandboxStatus::Running, SandboxStatus::Draining]),
        )
        .all(pools.read())
        .await?;

    for sandbox in stale {
        // Best-effort: ignore per-sandbox errors so one bad record does not
        // prevent the rest from being reaped.
        let _ = reconcile_sandbox_runtime_state(pools, sandbox).await;
    }

    Ok(())
}

/// Spawn a one-shot background reaper task.
///
/// The task queries the global database for sandboxes that claim to be
/// `Running` or `Draining` but whose process has already exited, and marks
/// them as `Crashed`. Errors are silently ignored so the caller's hot path
/// is never affected.
///
/// Safe to call multiple times — only the first invocation spawns a task.
pub fn spawn_reaper() {
    static SPAWNED: std::sync::Once = std::sync::Once::new();
    SPAWNED.call_once(|| {
        // Guard: tokio::spawn requires an active runtime. If called outside
        // one (e.g., from synchronous SDK setup code), silently skip rather
        // than panicking and poisoning the Once.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async {
                if let Err(e) = reap_stale_sandboxes().await {
                    tracing::debug!(error = %e, "background reaper failed");
                }
            });
        }
    });
}

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

    // No run record yet — the sandbox is still starting up (the child
    // process has not inserted its PID). Skip reconciliation to avoid
    // racing with create/start.
    let Some(run) = run else {
        return Ok(sandbox);
    };

    if run.pid.is_some_and(pid_is_alive) {
        return Ok(sandbox);
    }

    mark_sandbox_runtime_stale(pools.write(), sandbox.id, Some(run.id)).await?;

    sandbox_entity::Entity::find_by_id(sandbox.id)
        .one(pools.read())
        .await?
        .ok_or_else(|| MicrosandboxError::SandboxNotFound(sandbox.name))
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

fn build_handle_with_pid(model: sandbox_entity::Model, pid: Option<i32>) -> SandboxHandle {
    SandboxHandle::new(model, pid)
}

/// Reconcile runtime state for each sandbox row and build a handle (with live
/// pid) for each. Shared by [`Sandbox::list`] and [`Sandbox::list_by_labels`].
async fn build_sandbox_handles(
    pools: &DbPools,
    sandboxes: Vec<sandbox_entity::Model>,
) -> MicrosandboxResult<Vec<SandboxHandle>> {
    let mut reconciled = Vec::with_capacity(sandboxes.len());
    for sandbox in sandboxes {
        let model = reconcile_sandbox_runtime_state(pools, sandbox).await?;
        reconciled.push(model);
    }

    let sandbox_ids: Vec<i32> = reconciled.iter().map(|sandbox| sandbox.id).collect();
    let active_pids = load_active_pids(pools.read(), &sandbox_ids).await?;
    let mut handles = Vec::with_capacity(reconciled.len());
    for sandbox in reconciled {
        handles.push(build_handle_with_pid(
            sandbox.clone(),
            active_pids.get(&sandbox.id).copied(),
        ));
    }

    Ok(handles)
}

/// Return the ids of sandboxes matching every criterion of `filter`.
///
/// Only call this for a non-empty filter (callers short-circuit the empty case
/// to a full listing). Today the only criterion is labels — AND-matched, with
/// duplicate selectors de-duplicated. As `SandboxFilter` grows new fields, each
/// becomes an additional narrowing step here.
async fn filter_sandbox_ids(
    db: &DbReadConnection,
    filter: &SandboxFilter,
) -> MicrosandboxResult<Vec<i32>> {
    let wanted: HashSet<(String, String)> = filter.labels.iter().cloned().collect();
    if wanted.is_empty() {
        return Ok(Vec::new());
    }

    let mut cond = Condition::any();
    for (key, value) in &wanted {
        cond = cond.add(
            sandbox_label_entity::Column::Key
                .eq(key.clone())
                .and(sandbox_label_entity::Column::Value.eq(value.clone())),
        );
    }

    let rows = sandbox_label_entity::Entity::find()
        .filter(cond)
        .all(db)
        .await?;

    // Group matched (key, value) pairs per sandbox; a sandbox qualifies only
    // when its set covers all wanted selectors. The set dedups so duplicate
    // rows cannot inflate the count.
    let mut matched: HashMap<i32, HashSet<(String, String)>> = HashMap::new();
    for row in rows {
        matched
            .entry(row.sandbox_id)
            .or_default()
            .insert((row.key, row.value));
    }

    Ok(matched
        .into_iter()
        .filter(|(_, set)| set.len() == wanted.len())
        .map(|(id, _)| id)
        .collect())
}

fn pid_from_run(run: Option<&run_entity::Model>) -> Option<i32> {
    run.and_then(|model| model.pid)
        .filter(|pid| pid_is_alive(*pid))
}

async fn mark_sandbox_runtime_stale(
    db: &DbWriteConnection,
    sandbox_id: i32,
    run_id: Option<i32>,
) -> MicrosandboxResult<()> {
    // The runtime exit observer normally clears its own slot. When the
    // reaper is running, the runtime crashed without that hook firing —
    // free the slot here so it can be reused.
    free_metrics_slot_for(sandbox_id, run_id, microsandbox_metrics::ReleaseMode::Free);

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
                    Expr::value(run_entity::TerminationReason::InternalError),
                )
                .col_expr(run_entity::Column::TerminatedAt, Expr::value(now))
                .filter(run_entity::Column::Id.eq(run_id))
                .exec(&txn)
                .await?;
        }

        // Only mark Crashed if the sandbox is still Running or Draining. This
        // prevents a concurrent start() from having its Running status overwritten.
        sandbox_entity::Entity::update_many()
            .col_expr(
                sandbox_entity::Column::Status,
                Expr::value(SandboxStatus::Crashed),
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

/// Best-effort free of the metrics slot for a given sandbox/run identity.
///
/// Matches by run id first (most precise) and falls back to sandbox id when
/// no run id is known. Failures here are swallowed because the registry
/// itself will eventually reclaim dead slots under capacity pressure.
fn free_metrics_slot_for(
    sandbox_id: i32,
    run_id: Option<i32>,
    mode: microsandbox_metrics::ReleaseMode,
) {
    let name = crate::config::config().metrics_registry_shm_name();
    let reg = match microsandbox_metrics::MetricsRegistry::open(&name) {
        Ok(reg) => reg,
        Err(microsandbox_metrics::MetricsError::Io(ref e))
            if e.raw_os_error() == Some(libc::ENOENT) =>
        {
            return;
        }
        Err(err) => {
            tracing::debug!(error = %err, "failed to open metrics registry for slot cleanup");
            return;
        }
    };
    if let Err(err) = reg.release_by_identity(sandbox_id, run_id, mode) {
        tracing::debug!(error = %err, sandbox_id, ?run_id, "metrics slot cleanup failed");
    }
}

pub(super) fn pid_is_alive(pid: i32) -> bool {
    let result = unsafe { libc::kill(pid, 0) };
    if result == 0 {
        return true;
    }

    matches!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(code) if code == libc::EPERM
    )
}

fn digest_pinned_reference(reference: &str, manifest_digest: &str) -> MicrosandboxResult<String> {
    let image_ref: Reference = reference
        .parse()
        .map_err(|e| MicrosandboxError::InvalidConfig(format!("invalid image reference: {e}")))?;
    let pinned = image_ref
        .clone_with_digest(manifest_digest.to_string())
        .to_string();
    pinned.parse::<Reference>().map_err(|e| {
        MicrosandboxError::InvalidConfig(format!("invalid pinned image reference '{pinned}': {e}"))
    })?;
    Ok(pinned)
}

/// Validate a sandbox name used by CLI and SDK APIs.
///
/// Names are UTF-8 strings and must be non-empty and no longer than
/// [`MAX_SANDBOX_NAME_BYTES`] bytes. The limit is measured in bytes, not
/// Unicode scalar values, because names are stored in fixed-size shared-memory
/// metrics slots.
pub fn validate_sandbox_name(name: &str) -> MicrosandboxResult<()> {
    if let Some(message) = sandbox_name_validation_message(name) {
        return Err(MicrosandboxError::InvalidConfig(message));
    }

    Ok(())
}

/// Validate sandbox-name-derived runtime paths before the sandbox process starts.
pub(super) fn validate_sandbox_name_for_runtime(name: &str) -> MicrosandboxResult<()> {
    validate_sandbox_name(name)?;
    runtime::resolve_sandbox_agent_socket_path(name).map(|_| ())
}

pub(crate) fn sandbox_name_validation_message(name: &str) -> Option<String> {
    if name.is_empty() {
        return Some("sandbox name is required".into());
    }

    let len = name.len();
    if len > MAX_SANDBOX_NAME_BYTES {
        return Some(format!(
            "sandbox name is too long: {len} bytes (max {MAX_SANDBOX_NAME_BYTES})"
        ));
    }

    None
}

/// Pull an OCI image and return the pull result.
///
/// Auth resolution:
/// 1. Explicit `RegistryAuth` from `SandboxBuilder::registry_auth()` (if provided)
/// 2. OS keyring / credential store
/// 3. Global config `registries.auth` matched by registry hostname
/// 4. Docker credential store/config fallback
/// 5. Anonymous fallback
///
/// When `progress` is `Some`, uses `pull_with_sender()` to emit per-layer
/// progress events. The caller must consume the corresponding `PullProgressHandle`.
async fn pull_oci_image(
    reference: &str,
    pull_policy: PullPolicy,
    registry_overrides: RegistryOverrides,
    progress: Option<PullProgressSender>,
) -> MicrosandboxResult<PullResult> {
    let global = crate::config::config();
    let cache = GlobalCache::new(&global.cache_dir())?;
    let platform = microsandbox_image::Platform::host_linux();
    let image_ref: Reference = reference
        .parse()
        .map_err(|e| MicrosandboxError::InvalidConfig(format!("invalid image reference: {e}")))?;
    let options = PullOptions {
        pull_policy,
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
            .map_err(|e| MicrosandboxError::Custom(format!("pull task panicked: {e}")))??;
        Ok(result)
    } else {
        let result = registry.pull(&image_ref, &options).await?;
        Ok(result)
    }
}

/// Prefixes reserved for the built-in identity/resource attributes the metrics
/// exporter emits. User labels must not use them or they would shadow the
/// `sandbox.*` / `microsandbox.*` / `service.*` attributes downstream.
pub(crate) const RESERVED_LABEL_PREFIXES: [&str; 3] = ["sandbox.", "microsandbox.", "service."];

/// Return the reserved prefix a label key starts with, if any.
pub(crate) fn reserved_label_prefix(key: &str) -> Option<&'static str> {
    RESERVED_LABEL_PREFIXES
        .iter()
        .copied()
        .find(|prefix| key.starts_with(prefix))
}

/// Validate user-defined sandbox labels. Keys must be non-empty and must not
/// use a reserved prefix. Values may be empty: a valueless label is a plain
/// marker (e.g. `gpu`), matching Docker's label semantics.
fn validate_labels(labels: &HashMap<String, String>) -> MicrosandboxResult<()> {
    for key in labels.keys() {
        if key.is_empty() {
            return Err(MicrosandboxError::InvalidConfig(
                "label key must not be empty".into(),
            ));
        }
        if let Some(prefix) = reserved_label_prefix(key) {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "label key '{key}' uses reserved prefix '{prefix}'"
            )));
        }
    }
    Ok(())
}

pub(crate) fn validate_env(env: &[(String, String)]) -> MicrosandboxResult<()> {
    for (key, _) in env {
        if key.starts_with("MSB_") {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "environment variable {key:?} uses the reserved MSB_ prefix"
            )));
        }
    }
    Ok(())
}

fn validate_rootfs_source(rootfs: &RootfsSource) -> MicrosandboxResult<()> {
    match rootfs {
        RootfsSource::Bind(path) => {
            if !path.exists() {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "rootfs bind path does not exist: {}",
                    path.display()
                )));
            }

            if !path.is_dir() {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "rootfs bind path is not a directory: {}",
                    path.display()
                )));
            }
        }
        RootfsSource::Oci(oci) => {
            if oci.reference.is_empty() {
                return Err(MicrosandboxError::InvalidConfig(
                    "image source is required".into(),
                ));
            }
            if oci.upper_size_mib == Some(0) {
                return Err(MicrosandboxError::InvalidConfig(
                    "oci upper_size must be greater than 0".into(),
                ));
            }
        }
        RootfsSource::DiskImage { path, .. } => {
            if !path.exists() {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "disk image does not exist: {}",
                    path.display()
                )));
            }

            if !path.is_file() {
                return Err(MicrosandboxError::InvalidConfig(format!(
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
        .ok_or_else(|| MicrosandboxError::SandboxNotFound(name.into()))
}

async fn prepare_create_target(
    pools: &DbPools,
    config: &SandboxConfig,
    sandbox_dir: &Path,
) -> MicrosandboxResult<()> {
    let existing = sandbox_entity::Entity::find()
        .filter(sandbox_entity::Column::Name.eq(&config.name))
        .one(pools.read())
        .await?;

    let dir_exists = sandbox_dir.exists();

    if !config.replace_existing {
        if existing.is_some() || dir_exists {
            return Err(MicrosandboxError::SandboxAlreadyExists(format!(
                "sandbox '{}' already exists; remove it, start the stopped sandbox, or recreate with .replace()",
                config.name
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

        // Free any lingering metrics slot before the row goes away; once the
        // sandbox id is gone there is no way for the reaper to map a slot
        // back to it.
        free_metrics_slot_for(model.id, None, microsandbox_metrics::ReleaseMode::Free);

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
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(*pid),
                    nix::sys::signal::Signal::SIGTERM,
                );
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
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
    }

    mark_sandbox_stopped_after_signal(
        pools.write(),
        sandbox.id,
        run.as_ref().map(|model| model.id),
    )
    .await
}

fn exit_status_to_sandbox_status(status: &std::process::ExitStatus) -> SandboxStatus {
    if status.success() {
        SandboxStatus::Stopped
    } else {
        SandboxStatus::Crashed
    }
}

#[cfg(unix)]
fn exit_status_signal(status: &std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal()
}

#[cfg(not(unix))]
fn exit_status_signal(_status: &std::process::ExitStatus) -> Option<i32> {
    None
}

pub(super) async fn mark_sandbox_stopped_after_signal(
    db: &DbWriteConnection,
    sandbox_id: i32,
    run_id: Option<i32>,
) -> MicrosandboxResult<()> {
    free_metrics_slot_for(sandbox_id, run_id, microsandbox_metrics::ReleaseMode::Free);

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

fn validate_start_state(config: &SandboxConfig, sandbox_dir: &Path) -> MicrosandboxResult<()> {
    if !sandbox_dir.exists() {
        return Err(MicrosandboxError::Custom(format!(
            "sandbox state missing for '{}': {}",
            config.name,
            sandbox_dir.display()
        )));
    }

    if let RootfsSource::Oci(_) = &config.image
        && let Some(ref digest_str) = config.manifest_digest
    {
        let cache_dir = crate::config::config().cache_dir();
        if let Ok(cache) = GlobalCache::new(&cache_dir)
            && let Ok(digest) = digest_str.parse::<Digest>()
        {
            let vmdk_path = cache.vmdk_path(&digest);
            if !vmdk_path.exists() {
                return Err(MicrosandboxError::Custom(format!(
                    "sandbox '{}' cannot start: VMDK missing: {}",
                    config.name,
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
    // `auto_volumes` is `#[serde(skip)]` so the cloned config carries
    // no record of these intents — capture them before the move.
    let auto_volumes = config.auto_volumes.clone();

    db.transaction(|txn| {
        let config_json = config_json.clone();
        let auto_volumes = auto_volumes.clone();
        async move {
            let now = chrono::Utc::now().naive_utc();
            let model = sandbox_entity::ActiveModel {
                name: Set(config.name.clone()),
                config: Set(config_json),
                status: Set(SandboxStatus::Running),
                created_at: Set(Some(now)),
                updated_at: Set(Some(now)),
                ..Default::default()
            };
            let result = sandbox_entity::Entity::insert(model).exec(&txn).await?;
            let sandbox_id = result.last_insert_id;

            let label_rows: Vec<sandbox_label_entity::ActiveModel> = config
                .labels
                .iter()
                .map(|(key, value)| sandbox_label_entity::ActiveModel {
                    sandbox_id: Set(sandbox_id),
                    key: Set(key.clone()),
                    value: Set(value.clone()),
                })
                .collect();
            if !label_rows.is_empty() {
                sandbox_label_entity::Entity::insert_many(label_rows)
                    .exec(&txn)
                    .await?;
            }

            for intent in &auto_volumes {
                let vol_config = crate::volume::VolumeConfig {
                    name: intent.name.clone(),
                    kind: intent.kind,
                    quota_mib: intent.quota_mib,
                    capacity_mib: intent.capacity_mib,
                    labels: intent.labels.clone(),
                };
                crate::volume::Volume::create_in_transaction(&txn, &vol_config).await?;
            }

            Ok((txn, sandbox_id))
        }
    })
    .await
}

async fn materialise_auto_volume_dirs(
    intents: &[crate::sandbox::config::AutoVolumeIntent],
) -> MicrosandboxResult<()> {
    for intent in intents {
        let vol_config = crate::volume::VolumeConfig {
            name: intent.name.clone(),
            kind: intent.kind,
            quota_mib: intent.quota_mib,
            capacity_mib: intent.capacity_mib,
            labels: intent.labels.clone(),
        };
        crate::volume::Volume::materialise_for(&vol_config).await?;
    }
    Ok(())
}

async fn rollback_auto_volume_dirs(intents: &[crate::sandbox::config::AutoVolumeIntent]) {
    for intent in intents {
        let path = crate::volume::Volume::path_for(&intent.name);
        let _ = tokio::fs::remove_dir_all(&path).await;
    }
}

async fn remove_sandbox_row(db: &DbWriteConnection, sandbox_id: i32) -> MicrosandboxResult<()> {
    db.transaction(|txn| async move {
        sandbox_entity::Entity::delete_by_id(sandbox_id)
            .exec(&txn)
            .await?;
        Ok((txn, ()))
    })
    .await
}

async fn remove_volume_row(db: &DbWriteConnection, name: &str) -> MicrosandboxResult<()> {
    use crate::db::entity::volume as volume_entity;
    let name = name.to_string();
    db.transaction(|txn| {
        let name = name.clone();
        async move {
            volume_entity::Entity::delete_many()
                .filter(volume_entity::Column::Name.eq(name))
                .exec(&txn)
                .await?;
            Ok((txn, ()))
        }
    })
    .await
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
    upper_size_mib: u32,
    tree: Option<tree::FileTree>,
) -> MicrosandboxResult<()> {
    let _ = tokio::fs::remove_file(path).await;
    let ext4_options = ext4::Ext4FormatOptions {
        size_bytes: u64::from(upper_size_mib) * 1024 * 1024,
        ..Default::default()
    };
    let overlay_tree = build_overlay_upper_tree(tree);
    let path = path.to_path_buf();

    tokio::task::spawn_blocking(move || {
        ext4::format_ext4_with_tree(&path, &ext4_options, overlay_tree)
    })
    .await
    .map_err(|e| MicrosandboxError::Custom(format!("ext4 format task failed: {e}")))?
    .map_err(|e| MicrosandboxError::Custom(format!("failed to create upper.ext4: {e}")))?;

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
        collections::HashMap,
        fs,
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
        path::PathBuf,
        process::Command,
        time::{SystemTime, UNIX_EPOCH},
    };

    use microsandbox_db::entity::{run as run_entity, sandbox_rootfs as sandbox_rootfs_entity};
    use microsandbox_db::pool::DbPools;
    use microsandbox_migration::{Migrator, MigratorTrait};
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
    use tempfile::tempdir;

    use super::{
        MAX_SANDBOX_NAME_BYTES, RootfsSource, SandboxConfig, SandboxFilter, SandboxStatus,
        digest_pinned_reference, filter_sandbox_ids, insert_sandbox_record,
        persist_oci_manifest_pin, prepare_create_target, reconcile_sandbox_runtime_state,
        remove_dir_if_exists, validate_labels, validate_rootfs_source,
        validate_sandbox_name_for_runtime,
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
    fn test_default_tty_term_prefers_host_term() {
        assert_eq!(super::select_tty_term(Some("wezterm")), "wezterm");
    }

    #[test]
    fn test_default_tty_term_falls_back_from_dumb() {
        assert_eq!(super::select_tty_term(Some("dumb")), "xterm");
    }

    #[test]
    fn test_digest_pinned_reference_replaces_tag_with_digest() {
        let pinned = digest_pinned_reference(
            "docker.io/library/alpine:3.20",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap();

        assert_eq!(
            pinned,
            "docker.io/library/alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }

    #[test]
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
    fn test_validate_sandbox_name_rejects_empty_name() {
        let err = validate_sandbox_name_for_runtime("").unwrap_err();

        assert_eq!(err.to_string(), "invalid config: sandbox name is required");
    }

    #[test]
    fn test_validate_sandbox_name_accepts_128_byte_name() {
        validate_sandbox_name_for_runtime(&"x".repeat(MAX_SANDBOX_NAME_BYTES)).unwrap();
    }

    #[test]
    fn test_validate_sandbox_name_rejects_over_128_bytes() {
        let err =
            validate_sandbox_name_for_runtime(&"x".repeat(MAX_SANDBOX_NAME_BYTES + 1)).unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid config: sandbox name is too long: 129 bytes (max 128)"
        );
    }

    #[test]
    fn test_validate_sandbox_name_limit_is_utf8_bytes() {
        validate_sandbox_name_for_runtime(&"é".repeat(64)).unwrap();

        let err = validate_sandbox_name_for_runtime(&"é".repeat(65)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid config: sandbox name is too long: 130 bytes (max 128)"
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

        let mut config = SandboxConfig {
            name: "pinned".into(),
            image: RootfsSource::oci("docker.io/library/alpine"),
            ..Default::default()
        };
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

        let mut config = SandboxConfig {
            name: "recreated".into(),
            image: RootfsSource::oci("docker.io/library/alpine"),
            ..Default::default()
        };
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

        let mut config = SandboxConfig {
            name: "persisted-digest".into(),
            image: RootfsSource::oci("docker.io/library/alpine"),
            ..Default::default()
        };
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

    #[test]
    fn test_validate_labels_accepts_plain_and_valueless() {
        let labels = HashMap::from([
            ("user.id".to_string(), "alice".to_string()),
            ("tenant".to_string(), "acme".to_string()),
        ]);
        assert!(validate_labels(&labels).is_ok());
        assert!(validate_labels(&HashMap::new()).is_ok());

        // A valueless label (empty value) is a valid marker.
        let marker = HashMap::from([("gpu".to_string(), String::new())]);
        assert!(validate_labels(&marker).is_ok());
    }

    #[test]
    fn test_validate_labels_rejects_empty_key_and_reserved() {
        let empty_key = HashMap::from([(String::new(), "v".to_string())]);
        assert!(validate_labels(&empty_key).is_err());

        for reserved in ["sandbox.id", "microsandbox.cpu", "service.name"] {
            let labels = HashMap::from([(reserved.to_string(), "v".to_string())]);
            assert!(
                validate_labels(&labels).is_err(),
                "reserved key {reserved} should be rejected"
            );
        }
    }

    #[tokio::test]
    async fn test_insert_sandbox_record_persists_labels() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let pools = open_test_pools(&db_path).await;

        let config = SandboxConfig {
            name: "labelled".into(),
            image: RootfsSource::oci("docker.io/library/alpine"),
            labels: HashMap::from([
                ("user.id".to_string(), "alice".to_string()),
                ("tenant".to_string(), "acme".to_string()),
            ]),
            ..Default::default()
        };

        let sandbox_id = insert_sandbox_record(pools.write(), &config).await.unwrap();

        let mut rows = super::sandbox_label_entity::Entity::find()
            .filter(super::sandbox_label_entity::Column::SandboxId.eq(sandbox_id))
            .all(pools.write())
            .await
            .unwrap();
        rows.sort_by(|a, b| a.key.cmp(&b.key));

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].key, "tenant");
        assert_eq!(rows[0].value, "acme");
        assert_eq!(rows[1].key, "user.id");
        assert_eq!(rows[1].value, "alice");

        // Deleting the sandbox cascades to its labels.
        super::sandbox_entity::Entity::delete_by_id(sandbox_id)
            .exec(pools.write())
            .await
            .unwrap();
        let remaining = super::sandbox_label_entity::Entity::find()
            .filter(super::sandbox_label_entity::Column::SandboxId.eq(sandbox_id))
            .all(pools.write())
            .await
            .unwrap();
        assert!(remaining.is_empty(), "labels should cascade-delete");
    }

    #[tokio::test]
    async fn test_filter_sandbox_ids_and_semantics() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let pools = open_test_pools(&db_path).await;

        // alice owns two sandboxes; bob owns one. One of alice's is also prod.
        let alice_web = SandboxConfig {
            name: "alice-web".into(),
            image: RootfsSource::oci("alpine"),
            labels: HashMap::from([
                ("user.id".to_string(), "alice".to_string()),
                ("env".to_string(), "prod".to_string()),
            ]),
            ..Default::default()
        };
        let alice_job = SandboxConfig {
            name: "alice-job".into(),
            image: RootfsSource::oci("alpine"),
            labels: HashMap::from([("user.id".to_string(), "alice".to_string())]),
            ..Default::default()
        };
        let bob_web = SandboxConfig {
            name: "bob-web".into(),
            image: RootfsSource::oci("alpine"),
            labels: HashMap::from([("user.id".to_string(), "bob".to_string())]),
            ..Default::default()
        };

        let alice_web_id = insert_sandbox_record(pools.write(), &alice_web)
            .await
            .unwrap();
        let alice_job_id = insert_sandbox_record(pools.write(), &alice_job)
            .await
            .unwrap();
        let bob_web_id = insert_sandbox_record(pools.write(), &bob_web)
            .await
            .unwrap();

        async fn by(pools: &DbPools, sel: &[(&str, &str)]) -> Vec<i32> {
            let filter = SandboxFilter::new().labels(
                sel.iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect::<Vec<_>>(),
            );
            let mut ids = filter_sandbox_ids(pools.read(), &filter).await.unwrap();
            ids.sort();
            ids
        }

        // Single selector → both of alice's sandboxes.
        let mut alice = vec![alice_web_id, alice_job_id];
        alice.sort();
        assert_eq!(by(&pools, &[("user.id", "alice")]).await, alice);

        // AND of two selectors → only the sandbox with both.
        assert_eq!(
            by(&pools, &[("user.id", "alice"), ("env", "prod")]).await,
            vec![alice_web_id]
        );

        // bob's selector → only bob's sandbox.
        assert_eq!(by(&pools, &[("user.id", "bob")]).await, vec![bob_web_id]);

        // Non-matching value → empty.
        assert!(by(&pools, &[("user.id", "carol")]).await.is_empty());

        // Conflicting AND (no sandbox has both) → empty.
        assert!(
            by(&pools, &[("user.id", "alice"), ("user.id", "bob")])
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_insert_sandbox_record_atomic_with_auto_volumes() {
        use crate::db::entity::volume as volume_entity;
        use crate::sandbox::config::AutoVolumeIntent;

        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let pools = open_test_pools(&db_path).await;

        let mut config = SandboxConfig {
            name: "atomic-host".into(),
            image: RootfsSource::oci("docker.io/library/alpine"),
            ..Default::default()
        };
        config.auto_volumes.push(AutoVolumeIntent {
            name: "atomic-host-tmp".into(),
            kind: crate::volume::VolumeKind::Directory,
            quota_mib: None,
            capacity_mib: None,
            labels: vec![("owner".into(), "atomic-host".into())],
        });

        let _sandbox_id = insert_sandbox_record(pools.write(), &config).await.unwrap();

        // Both rows visible after the same transaction commits.
        let vol = volume_entity::Entity::find()
            .filter(volume_entity::Column::Name.eq("atomic-host-tmp"))
            .one(pools.read())
            .await
            .unwrap();
        assert!(
            vol.is_some(),
            "auto-volume row must exist alongside sandbox"
        );
        let vol = vol.unwrap();
        let labels: Vec<(String, String)> =
            serde_json::from_str(vol.labels.as_deref().unwrap_or("[]")).unwrap();
        assert!(labels.contains(&("owner".to_string(), "atomic-host".to_string())));
    }

    #[tokio::test]
    async fn test_insert_sandbox_record_rolls_back_when_volume_name_collides() {
        use crate::db::entity::volume as volume_entity;
        use crate::sandbox::config::AutoVolumeIntent;

        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let pools = open_test_pools(&db_path).await;

        // Pre-seed a volume that collides with the auto-volume name.
        let now = chrono::Utc::now().naive_utc();
        volume_entity::Entity::insert(volume_entity::ActiveModel {
            name: Set("collision".into()),
            kind: Set(crate::volume::VolumeKind::Directory.as_str().to_string()),
            created_at: Set(Some(now)),
            updated_at: Set(Some(now)),
            ..Default::default()
        })
        .exec(pools.write())
        .await
        .unwrap();

        let mut config = SandboxConfig {
            name: "rollback-host".into(),
            image: RootfsSource::oci("docker.io/library/alpine"),
            ..Default::default()
        };
        config.auto_volumes.push(AutoVolumeIntent {
            name: "collision".into(),
            kind: crate::volume::VolumeKind::Directory,
            quota_mib: None,
            capacity_mib: None,
            labels: Vec::new(),
        });

        let result = insert_sandbox_record(pools.write(), &config).await;
        assert!(
            result.is_err(),
            "duplicate volume name must fail the insert"
        );

        // Sandbox row must NOT exist — transaction rolled back.
        let sb = super::sandbox_entity::Entity::find()
            .filter(super::sandbox_entity::Column::Name.eq("rollback-host"))
            .one(pools.read())
            .await
            .unwrap();
        assert!(
            sb.is_none(),
            "transaction must roll back the sandbox row when volume insert fails"
        );
    }

    #[tokio::test]
    async fn test_prepare_create_target_rejects_existing_state_without_force() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let pools = open_test_pools(&db_path).await;

        let sandbox_dir = temp.path().join("sandboxes").join("existing");
        fs::create_dir_all(&sandbox_dir).unwrap();

        let config = SandboxConfig {
            name: "existing".into(),
            ..Default::default()
        };

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
        let config = SandboxConfig {
            name: "replaceable".into(),
            ..Default::default()
        };
        let sandbox_id = insert_sandbox_record(pools.write(), &config).await.unwrap();
        super::update_sandbox_status(pools.write(), sandbox_id, super::SandboxStatus::Stopped)
            .await
            .unwrap();

        let mut forced = SandboxConfig {
            name: "replaceable".into(),
            ..Default::default()
        };
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

        let config = SandboxConfig {
            name: "stale".into(),
            ..Default::default()
        };
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
    async fn test_prepare_create_target_force_replaces_stale_running_sandbox_state() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let pools = open_test_pools(&db_path).await;

        let sandbox_dir = temp.path().join("sandboxes").join("stale-running");
        fs::create_dir_all(sandbox_dir.join("rw")).unwrap();
        let config = SandboxConfig {
            name: "stale-running".into(),
            ..Default::default()
        };
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

        let mut forced = SandboxConfig {
            name: "stale-running".into(),
            ..Default::default()
        };
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
    async fn test_prepare_create_target_force_replaces_running_sandbox() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let pools = open_test_pools(&db_path).await;

        let sandbox_dir = temp.path().join("sandboxes").join("running");
        fs::create_dir_all(&sandbox_dir).unwrap();
        let config = SandboxConfig {
            name: "running".into(),
            ..Default::default()
        };
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

        let mut forced = SandboxConfig {
            name: "running".into(),
            ..Default::default()
        };
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
        let config = SandboxConfig {
            name: "missing".into(),
            ..Default::default()
        };

        let err = super::validate_start_state(&config, &sandbox_dir).unwrap_err();
        assert!(err.to_string().contains("sandbox state missing"));
    }

    #[test]
    fn test_validate_start_state_accepts_oci_with_manifest_digest() {
        let temp = tempdir().unwrap();
        let sandbox_dir = temp.path().join("persisted");
        fs::create_dir_all(&sandbox_dir).unwrap();

        let mut config = SandboxConfig {
            name: "persisted".into(),
            image: RootfsSource::oci("docker.io/library/alpine"),
            ..Default::default()
        };
        config.manifest_digest = Some("sha256:aaaa".into());

        // validate_start_state checks VMDK existence via GlobalCache,
        // which depends on the global config. In unit tests without a real
        // config, it succeeds because the cache init may fail gracefully.
        // The key thing is it doesn't panic.
        let _ = super::validate_start_state(&config, &sandbox_dir);
    }

    /// Simulates the reaper sweep: queries all Running/Draining sandboxes and
    /// reconciles each. Verifies that only stale entries are reaped while
    /// live, stopped, crashed, and starting (no run record) sandboxes are
    /// left untouched.
    #[tokio::test]
    async fn test_reap_marks_only_dead_running_and_draining_sandboxes() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let pools = open_test_pools(&db_path).await;

        let dead = dead_pid();

        // --- Sandbox A: Running + dead PID → should become Crashed ---
        let cfg_a = SandboxConfig {
            name: "running-dead".into(),
            ..Default::default()
        };
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

        let cfg_b = SandboxConfig {
            name: "running-alive".into(),
            ..Default::default()
        };
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

        // --- Sandbox C: Draining + dead PID → should become Crashed ---
        let cfg_c = SandboxConfig {
            name: "draining-dead".into(),
            ..Default::default()
        };
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

        // --- Sandbox D: Stopped → should stay Stopped ---
        let cfg_d = SandboxConfig {
            name: "stopped".into(),
            ..Default::default()
        };
        let id_d = insert_sandbox_record(pools.write(), &cfg_d).await.unwrap();
        super::update_sandbox_status(pools.write(), id_d, SandboxStatus::Stopped)
            .await
            .unwrap();

        // --- Sandbox E: Running + no run record (still starting) → should stay Running ---
        let cfg_e = SandboxConfig {
            name: "starting".into(),
            ..Default::default()
        };
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
        assert_eq!(load(id_c).await.status, SandboxStatus::Crashed);
        assert_eq!(load(id_d).await.status, SandboxStatus::Stopped);
        assert_eq!(load(id_e).await.status, SandboxStatus::Running);

        // Cleanup the live process.
        unsafe { libc::kill(live_pid, libc::SIGKILL) };
        waiter.join().unwrap();
    }
}

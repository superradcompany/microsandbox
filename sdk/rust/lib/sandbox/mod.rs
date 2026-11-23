//! Sandbox lifecycle management.
//!
//! The [`Sandbox`] struct represents a running sandbox. It is created via
//! [`Sandbox::builder`] or [`Sandbox::create`], and provides lifecycle
//! methods (stop, kill, drain, wait) and access to the [`AgentClient`]
//! for guest communication.

pub(crate) mod attach;
pub(crate) mod branch;
mod branch_batch;
mod builder;
mod config_inspection;
mod context;
mod execution;
mod inspection;
mod lifetime;
mod readiness;
mod state;
#[cfg(feature = "local")]
pub(crate) use builder::{apply_portable_snapshot_defaults, prepare_local_snapshot_restore};
mod caller_config_overrides;
#[cfg(feature = "cloud")]
mod cloud;
pub(crate) mod command_provenance;
mod compact;
pub(crate) mod config;
#[cfg(test)]
mod control_pipe;
#[cfg(feature = "local")]
mod creation_cleanup;
mod environment_provenance;
pub mod exec;
#[cfg(feature = "local")]
mod exit;
mod field_presence;
#[cfg(feature = "local")]
pub(crate) mod flat_rootfs;
pub mod fs;
mod fs_handle;
mod handle;
pub(crate) mod identity;
pub mod init;
pub(crate) mod init_provenance;
pub mod jobs;
#[cfg(all(feature = "local", target_os = "linux"))]
mod lease_recovery;
pub(crate) mod metrics;
#[cfg(any(feature = "local", feature = "cloud"))]
mod modify;
mod mount_presence;
#[cfg(all(test, feature = "local"))]
mod mount_presence_tests;
mod network_policy_presence;
pub(crate) mod network_presence;
#[cfg(all(test, feature = "local"))]
mod network_presence_tests;
#[cfg(feature = "local")]
mod patch;
#[cfg(feature = "local")]
pub(crate) mod patch_sources;
#[cfg(feature = "local")]
pub(crate) mod storage_preview;
mod storage_recovery;
#[cfg(all(feature = "local", windows))]
pub(crate) use patch::{
    windows_mark_delete, windows_open_relative_for_removal, windows_remove_open_entry,
};
#[cfg(feature = "local")]
pub(crate) mod pause;
#[cfg(all(feature = "local", windows))]
mod reap;
#[cfg(not(feature = "local"))]
mod remote_only;
#[cfg(feature = "local")]
mod resize;
mod restore_builder;
pub(crate) mod restore_resources;
mod snapshot;
#[cfg(feature = "ssh")]
pub mod ssh;
// Windows-only in shipping builds, but kept compiled under `test` so the
// platform-independent encoding logic is covered on every host.
mod status;
#[cfg(any(windows, test))]
pub(crate) mod terminal;
mod types;
#[cfg(feature = "local")]
pub(crate) mod upper;

use std::{collections::BTreeMap, process::ExitStatus, sync::Arc};

#[cfg(feature = "local")]
use std::path::Path;

#[cfg(feature = "local")]
use microsandbox_db::DbReadConnection;
use microsandbox_protocol::{
    core::{CoreError, Ping, Pong, Touch, Touched},
    exec::{ExecRequest, ExecRlimit},
    message::MessageType,
};
use microsandbox_types::hostname_from_sandbox_name as derive_hostname;
#[cfg(feature = "local")]
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

#[cfg(feature = "local")]
use microsandbox_image::progress_channel;

#[cfg(feature = "local")]
use crate::context::local::creation::{CreationStorage, RemovalMode};
use crate::{MicrosandboxResult, agent::AgentClient, context::sandbox::SandboxIdentity};
#[cfg(feature = "local")]
use crate::{
    context::LocalContext,
    db::entity::sandbox as sandbox_entity,
    error::{Operation, UnsupportedReason},
    runtime::SpawnMode,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Prefixes reserved for built-in identity/resource attributes.
pub(crate) const RESERVED_LABEL_PREFIXES: [&str; 3] = ["sandbox.", "microsandbox.", "service."];

//--------------------------------------------------------------------------------------------------
// Functions: Validation
//--------------------------------------------------------------------------------------------------

/// Validate a sandbox name used by CLI and SDK APIs.
pub fn validate_sandbox_name(name: &str) -> MicrosandboxResult<()> {
    microsandbox_types::validate_sandbox_name(name).map_err(Into::into)
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

// `mod patch` and `mod types` are private; re-export the entry points the
// local backend's lifecycle and create methods under `backend/local/` call.
#[cfg(feature = "local")]
pub(crate) use builder::{
    apply_checkpoint_restore_constraints, apply_snapshot_guest_clock, apply_snapshot_root_layout,
};
#[cfg(feature = "local")]
pub(crate) use patch::{apply_patches, build_flat_tree, build_upper_tree};
#[cfg(all(feature = "local", windows))]
pub(crate) use reap::reap_leaked_runtime_process;
#[cfg(feature = "local")]
pub(crate) use types::validate_named_disk_mount_options;
#[cfg(any(feature = "local", feature = "cloud"))]
pub(crate) use types::validate_volume_mounts;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use crate::logs::{LogEntry, LogOptions, LogSource, LogStreamOptions};
pub use attach::AttachOptionsBuilder;
#[allow(deprecated)]
pub use branch::{BranchBuilder, BranchManyBuilder, BranchOutcome};
pub use branch::{ForkBuilder, ForkManyBuilder, ForkOutcome};
pub use builder::{RegistryConfigBuilder, SandboxBuilder};
pub use compact::{DiskCompactionBuilder, DiskCompactionDiskResult, DiskCompactionResult};
pub use config::{SandboxConfig, SandboxConfigPatch};
pub use config_inspection::{
    RemoteMountInspection, RemoteNetworkInspection, RemoteResourceInspection,
    RemoteSandboxInspection, RemoteSecretInjection, RemoteSecretInspection, RemoteSecretViolation,
    SandboxConfigInspection, SandboxInspectedSettings,
};
pub use exec::{ExecOptionsBuilder, ExecOutput, Rlimit, RlimitResource};
#[cfg(feature = "local")]
pub use exit::{SandboxRunExit, SandboxTerminationReason};
pub use fs::{
    FsEntry, FsEntryKind, FsHandle, FsMetadata, FsOpenOptions, FsReadStream, FsSetAttrs,
    FsWriteSink, SandboxFsOps,
};
#[cfg(feature = "cloud")]
pub(crate) use handle::get_identified_handle;
pub(crate) use handle::restart_by_stop_and_start;
pub use handle::{
    DEFAULT_KILL_TIMEOUT, DEFAULT_STOP_TIMEOUT, DestroyOptions, RestartOptions, SandboxRecord,
};
pub use identity::SandboxId;
pub use init::{HandoffInit, InitOptionsBuilder};
pub use inspection::{SandboxInfo, SandboxLaunchInfo};
pub use metrics::SandboxMetrics;
#[cfg(feature = "local")]
pub use metrics::{
    SandboxMetricsReport, SandboxMetricsState, all_sandbox_metrics, all_sandbox_metrics_local,
    all_sandbox_metrics_reports_local, sandbox_metrics_report_local,
};
#[cfg(feature = "net")]
pub use microsandbox_network::builder::SecretBuilder;
#[cfg(feature = "net")]
pub use microsandbox_network::config::{NetworkConfig, PublishedPort};
#[cfg(feature = "net")]
pub use microsandbox_network::dns::Nameserver;
#[cfg(feature = "net")]
pub use microsandbox_network::policy::{
    Action as NetworkAction, NetworkPolicy, NetworkProfile, Rule as NetworkRule,
};
#[cfg(feature = "net")]
pub use microsandbox_network::{HttpConnectCredentials, OutboundProxy, Socks5Credentials};
#[cfg(feature = "local")]
pub use microsandbox_runtime::control::PauseControlState as SandboxPauseState;
pub use microsandbox_types::SandboxLogLevel as LogLevel;
pub use microsandbox_types::pull_progress::{PullProgress, PullProgressHandle};
pub use microsandbox_types::{CpuPlacement, PullPolicy};
#[cfg(feature = "net")]
pub use microsandbox_types::{
    DnsConfigPatch, HostPattern, HttpConfig, HttpConfigPatch, HttpDenyResponseFormat,
    InterfaceOverridesPatch, NetworkRateLimiterConfigPatch, SecretSubstitution,
    SecretViolationAction, SecretsConfigPatch, TlsConfigPatch,
};
pub use microsandbox_types::{
    EnvVar, GuestClockPolicy, MAX_HOSTNAME_BYTES, MAX_SANDBOX_NAME_BYTES, NetworkSpec,
    NetworkSpecPatch, PortProtocol, PublishedPortSpec, SandboxLogLevel, SandboxPolicyPatch,
    SandboxResources, SandboxResourcesPatch, SandboxRuntimeOptions, SandboxRuntimeOptionsPatch,
    SandboxSpec, SandboxSpecPatch, TransparentHugePagePolicy, VsockRouteSpec, VsockSocketType,
    VsockSpec, VsockSpecPatch,
};
pub use microsandbox_types::{ExternalMountRestorePolicy, ExternalMountWarning};
pub use restore_builder::RestoreBuilder;
#[cfg(feature = "local")]
#[doc(hidden)]
pub use storage_preview::{StoragePreview, StoragePreviewEntry};
pub use storage_recovery::{StorageRecovery, StorageRecoveryOptions, StorageRecoverySelection};

#[cfg(feature = "local")]
mod external_mounts;
mod restore_warnings;
mod stop;
#[cfg(feature = "local")]
pub(crate) use external_mounts::{
    external_bind_guest_paths, require_guest_mounts, require_recorded_mounts,
    resolve_external_mounts,
};
pub use microsandbox_protocol::resize::{
    ResizeObservation, ResizeOperation, ResizeOutcome, ResizeTarget, ResizeTracking,
};
#[cfg(any(feature = "local", feature = "cloud"))]
pub use modify::SandboxModificationResult;
#[cfg(any(feature = "local", feature = "cloud"))]
pub use modify::{
    ChangeKind, ConfigPlannedChange, ModificationConflict, ModificationDisposition,
    ModificationPolicy, ModificationWarning, PlannedChange, PublishedPortKey,
    ResourceConvergenceState, ResourceKind, ResourceResizeStatus, SandboxModificationBuilder,
    SandboxModificationPatch, SandboxModificationPlan, SecretChangeKind, SecretModificationPatch,
    SecretPatchBuilder, SecretPlannedChange, SecretSource,
};
#[cfg(not(feature = "local"))]
pub use remote_only::DEFAULT_RESIZE_READ_TIMEOUT;
#[cfg(feature = "local")]
pub use resize::DEFAULT_RESIZE_READ_TIMEOUT;
#[cfg(feature = "ssh")]
pub use ssh::{
    DEFAULT_SSH_HOST, DEFAULT_SSH_PORT, SandboxSshOps, SftpClient, SshAttachOptionsBuilder,
    SshClient, SshClientOptionsBuilder, SshExecOptionsBuilder, SshOutput, SshServer,
    SshServerOptionsBuilder, SshStdioStream,
};
pub use status::SandboxStatus;
pub use types::{
    DeploymentProfile, DiskImageFormat, FlatClone, HostPermissions, ImageBuilder, ImageSource,
    IntoImage, MountBuilder, MountOptions, NamedVolumeMode, OciRootfsSource, OwnedVolumeBuilder,
    OwnedVolumeStorage, Patch, PatchBuilder, RootDisk, RootDiskBuilder, RootfsSource,
    SecurityProfile, StatVirtualization, VolumeMount,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Default number of sandboxes returned by one list request.
pub const DEFAULT_SANDBOX_LIST_LIMIT: u32 = 20;

/// Maximum number of sandboxes returned by one list request.
pub const MAX_SANDBOX_LIST_LIMIT: u32 = 100;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Configures one paginated [`Sandbox::list_with`] request.
#[derive(Debug, Clone)]
pub struct SandboxListBuilder {
    pub(crate) cursor: Option<String>,
    pub(crate) limit: u32,
    pub(crate) labels: BTreeMap<String, String>,
}

/// One page of unprepared sandbox resources.
pub struct SandboxPage {
    /// Sandboxes in this page.
    pub sandboxes: Vec<Sandbox>,
    /// Opaque cursor for the next page, or `None` when this is the final page.
    pub next_cursor: Option<String>,
}

/// A sandbox resource with stable identity and lazily prepared guest access.
///
/// Created via [`Sandbox::builder`] or [`Sandbox::create`], or fetched without
/// starting it via [`Sandbox::get`]. Guest execution prepares the resource;
/// mutable inspection remains live and non-starting.
///
/// Per the SDK local-cloud parity plan (D6.4) `Sandbox` is a single type
/// regardless of backend. It holds an [`Arc<dyn Context>`](crate::context::Context)
/// to route lifecycle ops through, and a backend-private
/// [`SandboxInner`](crate::context::SandboxInner) enum carrying variant-specific
/// state. Users reach variant data via [`Sandbox::local_state`] / [`Sandbox::remote_state`].
#[derive(Clone)]
#[must_use = "Retain the Sandbox; discarding an owning result may trigger shutdown"]
pub struct Sandbox {
    backend: Arc<dyn crate::context::Context>,
    binding: Arc<state::SandboxBinding>,
    identity: SandboxIdentity,
    name: String,
    ephemeral: bool,
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

/// Result returned by [`Sandbox::ping`] and [`SandboxRecord::ping`].
#[derive(Debug, Clone)]
pub struct SandboxPingResult {
    /// Sandbox name that was pinged.
    pub name: String,

    /// Round-trip latency measured by the SDK.
    pub latency: std::time::Duration,
}

/// Result returned by [`Sandbox::touch`] and [`SandboxRecord::touch`].
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
    /// Uses the configured context. To override the destination, use
    /// `Sandbox::remote()?.builder(name)` or `Sandbox::ctx(&context).builder(name)`.
    pub async fn create(config: SandboxConfig) -> MicrosandboxResult<Self> {
        #[cfg(feature = "local")]
        if create_spawn_mode(&config, SpawnMode::Attached) == SpawnMode::Detached {
            // A full restore already owns its captured workload and has no new foreground exec
            // session for this caller to own. Start it as a service-owned runtime from the outset
            // so an exiting CLI/SDK process cannot reap the successfully restored VM.
            return Self::create_detached(config).await;
        }
        let backend = crate::context::configured_context();
        backend
            .sandbox_ops()
            .create(backend.clone(), config, true)
            .await
    }

    /// Create a sandbox that must survive after the creating process exits.
    ///
    /// This is intended for detached CLI workflows such as `msb create` and
    /// `msb run --detach`, where the sandbox should keep running in the
    /// background after the command returns. Uses the configured context.
    pub async fn create_detached(config: SandboxConfig) -> MicrosandboxResult<Self> {
        let backend = crate::context::configured_context();
        backend
            .sandbox_ops()
            .create_detached(backend.clone(), config)
            .await
    }

    /// Create a sandbox with pull progress reporting.
    ///
    /// Returns a progress handle for per-layer pull events and a task handle
    /// for the sandbox creation result. The caller should consume progress
    /// events until the channel closes, then await the task. This entry point uses
    /// the configured context.
    #[cfg(feature = "local")]
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
    #[cfg(feature = "local")]
    pub fn create_detached_with_pull_progress(
        config: SandboxConfig,
    ) -> (
        PullProgressHandle,
        tokio::task::JoinHandle<MicrosandboxResult<Self>>,
    ) {
        Self::create_with_pull_progress_and_mode(config, SpawnMode::Detached)
    }

    #[cfg(feature = "local")]
    fn create_with_pull_progress_and_mode(
        mut config: SandboxConfig,
        requested_mode: SpawnMode,
    ) -> (
        PullProgressHandle,
        tokio::task::JoinHandle<MicrosandboxResult<Self>>,
    ) {
        let backend = crate::context::configured_context();
        // Resolve before spawning: the task may first run after the caller changes cwd.
        let paths = if backend.as_local().is_some() {
            crate::context::local::host_paths::resolve_host_paths(&mut config)
        } else {
            Ok(())
        };
        let (handle, sender) = progress_channel();
        let task = tokio::spawn(async move {
            paths?;
            let mode = create_spawn_mode(&config, requested_mode);
            // Pull progress is local-only; ignore the channel on non-local
            // backends and dispatch through the trait without progress events.
            match backend.kind() {
                crate::context::ContextKind::Local => {
                    let local = backend.as_local().ok_or_else(|| {
                        crate::MicrosandboxError::local_only(Operation::SandboxCreate)
                    })?;
                    local
                        .create_sandbox(backend.clone(), config, mode, Some(sender))
                        .await
                }
                crate::context::ContextKind::Remote => {
                    drop(sender); // close the channel — no per-layer events for cloud.
                    backend
                        .sandbox_ops()
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
    /// re-resolving the original OCI reference. Uses the configured context.
    ///
    /// For an explicitly remote start via `Sandbox::remote()?.start(name)`, the provider returns
    /// [`MicrosandboxError::CloudHttp`](crate::MicrosandboxError::CloudHttp) (409) while a
    /// secret change to it is being saved, or while its result is not yet known after
    /// [`MicrosandboxError::ModificationNotConfirmed`](crate::MicrosandboxError::ModificationNotConfirmed);
    /// this usually clears within seconds. Start again after a short wait.
    pub async fn start(name: &str) -> MicrosandboxResult<Self> {
        let backend = crate::context::configured_context();
        backend.sandbox_ops().start(backend.clone(), name).await
    }

    /// Start an existing sandbox in detached/background mode in the configured context.
    ///
    /// For an explicitly remote start via `Sandbox::remote()?.start_detached(name)`, the provider returns
    /// [`MicrosandboxError::CloudHttp`](crate::MicrosandboxError::CloudHttp) (409) while a
    /// secret change to it is being saved, or while its result is not yet known after
    /// [`MicrosandboxError::ModificationNotConfirmed`](crate::MicrosandboxError::ModificationNotConfirmed);
    /// this usually clears within seconds. Start again after a short wait.
    pub async fn start_detached(name: &str) -> MicrosandboxResult<Self> {
        let backend = crate::context::configured_context();
        backend
            .sandbox_ops()
            .start_detached(backend.clone(), name)
            .await
    }

    /// Look up an existing resource without starting or connecting to its VM.
    /// Guest execution prepares it lazily; inspection remains non-starting.
    pub async fn get(name: &str) -> MicrosandboxResult<Self> {
        Self::get_record(name).await.map(Self::from_record)
    }

    pub(crate) async fn get_record(name: &str) -> MicrosandboxResult<SandboxRecord> {
        let backend = crate::context::configured_context();
        backend.sandbox_ops().get(backend.clone(), name).await
    }

    /// List the first page of sandboxes using the default page size.
    pub async fn list() -> MicrosandboxResult<SandboxPage> {
        Self::list_with(|list| list).await
    }

    /// List a configured page of sandboxes.
    ///
    /// Labels are AND-matched by the selected backend before pagination.
    pub async fn list_with(
        configure: impl FnOnce(SandboxListBuilder) -> SandboxListBuilder,
    ) -> MicrosandboxResult<SandboxPage> {
        let query = configure(SandboxListBuilder::default());
        if !(1..=MAX_SANDBOX_LIST_LIMIT).contains(&query.limit) {
            return Err(crate::MicrosandboxError::InvalidConfig(format!(
                "sandbox list limit must be between 1 and {MAX_SANDBOX_LIST_LIMIT}"
            )));
        }

        let backend = crate::context::configured_context();
        backend
            .sandbox_ops()
            .list(backend.clone(), query)
            .await
            .map(SandboxPage::from_records)
    }

    /// Remove a stopped sandbox by name in the configured context.
    pub async fn remove(name: &str) -> MicrosandboxResult<()> {
        let backend = crate::context::configured_context();
        backend.sandbox_ops().remove(backend.clone(), name).await
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: SandboxListBuilder
//--------------------------------------------------------------------------------------------------

impl SandboxListBuilder {
    /// Set the maximum number of sandboxes returned in this page.
    pub fn limit(mut self, limit: u32) -> Self {
        self.limit = limit;
        self
    }

    /// Continue listing after an opaque cursor returned by a previous page.
    pub fn cursor(mut self, cursor: impl Into<String>) -> Self {
        self.cursor = Some(cursor.into());
        self
    }

    /// Require sandboxes to carry this `key=value` label.
    pub fn label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
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
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for SandboxListBuilder {
    fn default() -> Self {
        Self {
            cursor: None,
            limit: DEFAULT_SANDBOX_LIST_LIMIT,
            labels: BTreeMap::new(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Construction helpers
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Build an outer `Sandbox` from local-variant inner state.
    #[cfg(feature = "local")]
    pub(crate) fn from_local(
        backend: Arc<dyn crate::context::Context>,
        local: crate::context::SandboxLocalState,
        config: SandboxConfig,
    ) -> Self {
        let identity = SandboxIdentity::Local(local.db_id);
        let session = state::RuntimeSession {
            inner: crate::context::SandboxInner::Local(Arc::new(local)),
            config: config.clone(),
        };
        Self {
            backend,
            identity,
            binding: Arc::new(state::SandboxBinding::new(Some(Arc::new(session)))),
            name: config.spec.name.clone(),
            ephemeral: config.spec.lifecycle.ephemeral,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Agent Requests
//--------------------------------------------------------------------------------------------------

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
    #[cfg(feature = "local")]
    pub async fn remove_persisted(&self) -> MicrosandboxResult<()> {
        let local = self.require_local(Operation::SandboxRemovePersisted)?;
        let local_backend = self.backend.as_local().ok_or_else(|| {
            crate::MicrosandboxError::unsupported(
                Operation::SandboxRemovePersisted,
                UnsupportedReason::UseInstead(Operation::SandboxRemove),
            )
        })?;
        remove_local_persisted_sandbox(local_backend, &self.name, local.db_id).await
    }

    /// Name captured when this resource was created or fetched.
    /// Use `info().await` for the provider's current observation.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Stable identity of this persisted sandbox.
    pub fn id(&self) -> SandboxId {
        match &self.identity {
            SandboxIdentity::Local(id) => SandboxId::local(*id),
            SandboxIdentity::Cloud(id) => SandboxId::cloud(id),
        }
    }

    fn identity(&self) -> SandboxIdentity {
        self.identity.clone()
    }

    async fn refresh_handle(&self) -> MicrosandboxResult<SandboxRecord> {
        let handle = self
            .backend
            .sandbox_ops()
            .get(self.backend.clone(), &self.name)
            .await?;
        if handle.identity() != self.identity() {
            return Err(crate::MicrosandboxError::SandboxReplaced {
                name: self.name.clone(),
                expected: self.id().to_string(),
                actual: handle.id().to_string(),
            });
        }
        Ok(handle)
    }

    /// Start a sandbox modification.
    ///
    /// Returns a builder; `dry_run` plans the patch, `apply` applies it.
    #[cfg(any(feature = "local", feature = "cloud"))]
    pub fn modify(&self) -> SandboxModificationBuilder {
        SandboxModificationBuilder::new(self.backend.clone(), self.name.clone())
            .bound_to(self.identity())
    }

    /// Explicitly compact sealed backing layers of the root and sandbox-owned data disks.
    pub fn compact(&self) -> DiskCompactionBuilder {
        DiskCompactionBuilder::new(self.backend.clone(), self.name.clone()).bound_to(self.id())
    }

    /// Which context this sandbox retains: `Local` or `Remote`.
    pub fn context_kind(&self) -> crate::context::ContextKind {
        self.backend.kind()
    }

    /// The `Arc<dyn Context>` this sandbox routes through. Useful when
    /// invoking other backend resources (e.g. volumes) from a sandbox
    /// reference.
    pub fn backend(&self) -> &Arc<dyn crate::context::Context> {
        &self.backend
    }

    /// Local-only state accessor. Returns `Some` when this `Sandbox` was
    /// created by the local libkrun backend.
    #[cfg(feature = "local")]
    pub fn local_state(&self) -> Option<Arc<crate::context::SandboxLocalState>> {
        match &self.binding.current()?.inner {
            crate::context::SandboxInner::Local(local) => Some(local.clone()),
            _ => None,
        }
    }

    /// Current remote runtime metadata, if preparation has established it.
    pub fn remote_state(&self) -> Option<Arc<crate::context::SandboxRemoteState>> {
        match &self.binding.current()?.inner {
            crate::context::SandboxInner::Cloud(remote) => Some(remote.clone()),
            _ => None,
        }
    }

    /// Same as [`Sandbox::local_state`] but returns a typed `Unsupported` error
    /// for cloud sandboxes. Used by methods that have no cloud equivalent yet.
    #[cfg(feature = "local")]
    fn require_local(
        &self,
        op: Operation,
    ) -> MicrosandboxResult<Arc<crate::context::SandboxLocalState>> {
        self.local_state().ok_or_else(|| {
            if self.backend.as_local().is_some() {
                crate::MicrosandboxError::SandboxNotRunning(self.name.clone())
            } else {
                crate::MicrosandboxError::local_only(op)
            }
        })
    }

    /// Live status from the backend. Always hits `backend.sandbox_ops().get(name)`
    /// — there is no cached status on the outer struct, per the D6.4
    /// "fetch-live" policy.
    ///
    /// Each call is a separate round-trip (DB read for local, HTTP GET for
    /// cloud). Use [`Self::info`] to observe several fields in one lookup.
    pub async fn status(&self) -> MicrosandboxResult<SandboxStatus> {
        let handle = self.refresh_handle().await?;
        Ok(handle.status_snapshot())
    }

    /// Live failure message from the backend, when any. Always hits the
    /// backend, never reads a cached field.
    ///
    /// Each call is a separate round-trip. If you need this alongside
    /// `status()`, fetch [`info()`](Self::info) once and read both fields
    /// from that observation.
    pub async fn last_failure_message(&self) -> MicrosandboxResult<Option<String>> {
        let handle = self.refresh_handle().await?;
        Ok(handle.last_failure_message_snapshot())
    }

    /// Read captured output from `exec.log` for this sandbox.
    ///
    /// Routes through the [`SandboxOps`](crate::context::SandboxOps)
    /// trait. Local reads the on-disk JSON Lines file the runtime writes via
    /// the relay tap (`crates/runtime/lib/exec_log.rs`); cloud returns
    /// `Unsupported` until bounded cloud log snapshots land.
    pub async fn logs(&self, opts: &LogOptions) -> MicrosandboxResult<Vec<LogEntry>> {
        self.backend
            .sandbox_ops()
            .logs(self.backend.clone(), &self.name, opts)
            .await
    }

    /// Stream log entries for this sandbox.
    ///
    /// Local streams the on-disk JSON Lines files produced by the relay tap;
    /// cloud streams the API SSE logs endpoint and maps each event into
    /// a typed [`LogEntry`].
    pub async fn log_stream(
        &self,
        opts: &LogStreamOptions,
    ) -> MicrosandboxResult<crate::context::sandbox::LogStream> {
        self.backend
            .sandbox_ops()
            .log_stream(self.backend.clone(), &self.name, opts)
            .await
    }

    /// Replay a filtered log snapshot, then follow new entries.
    ///
    /// The backend performs the snapshot-to-stream handoff. Local backends
    /// preserve the exact snapshot cursor; cloud backends use their live SSE
    /// transport and return a typed unsupported error for bounded-history
    /// filters.
    pub async fn follow_logs(
        &self,
        opts: &LogOptions,
    ) -> MicrosandboxResult<crate::context::sandbox::LogStream> {
        self.backend
            .sandbox_ops()
            .follow_logs(self.backend.clone(), &self.name, opts)
            .await
    }

    /// A local logger handle over this sandbox's on-disk logs.
    ///
    /// Used directly, followed streams each own a private filesystem watcher.
    /// Register it with a [`LogRegistry`](crate::logs::LogRegistry) to share a
    /// single watcher across many sandboxes. Cloud logs have no host directory
    /// and continue to use [`log_stream`](Self::log_stream) over SSE.
    #[cfg(feature = "local")]
    pub fn logger(&self) -> MicrosandboxResult<crate::logs::SandboxLogger> {
        self.require_local(Operation::SandboxLogger)?;
        let local = self
            .backend
            .as_local()
            .ok_or_else(|| crate::MicrosandboxError::local_only(Operation::SandboxLogger))?;
        Ok(crate::logs::SandboxLogger::for_local(local, &self.name))
    }

    /// Check whether agentd is reachable without refreshing the sandbox idle timer.
    ///
    /// Local backend only. The request uses `core.ping` and returns the SDK-measured
    /// round-trip latency. If the sandbox runtime predates protocol generation 6,
    /// this fails before any bytes are sent with an unsupported-operation error.
    #[cfg(feature = "local")]
    pub async fn ping(&self) -> MicrosandboxResult<SandboxPingResult> {
        if self.backend.as_local().is_none() {
            return Err(crate::MicrosandboxError::local_only(Operation::SandboxPing));
        }
        let session = self.connect_running().await?;
        let crate::context::SandboxInner::Local(local) = &session.inner else {
            return Err(crate::MicrosandboxError::local_only(Operation::SandboxPing));
        };
        ping_agent(&self.name, &local.client).await
    }

    /// Explicitly refresh the sandbox idle timer.
    ///
    /// Local backend only. The request uses `core.touch`, so callers can keep a
    /// sandbox alive intentionally without relying on unrelated agent traffic.
    #[cfg(feature = "local")]
    pub async fn touch(&self) -> MicrosandboxResult<SandboxTouchResult> {
        if self.backend.as_local().is_none() {
            return Err(crate::MicrosandboxError::local_only(
                Operation::SandboxTouch,
            ));
        }
        let session = self.connect_running().await?;
        let crate::context::SandboxInner::Local(local) = &session.inner else {
            return Err(crate::MicrosandboxError::local_only(
                Operation::SandboxTouch,
            ));
        };
        touch_agent(&self.name, &local.client).await
    }

    /// Return an idle filesystem facade. Operations prepare this receiver on demand.
    pub fn fs(&self) -> fs::SandboxFsOps {
        fs::SandboxFsOps::new(self)
    }

    /// Request graceful shutdown and wait without a built-in deadline for completion.
    ///
    /// Local completion includes release of runtime ownership for the targeted run.
    /// Cancelling this wait never requests force termination; use [`Self::kill`] explicitly.
    pub async fn stop(&self) -> MicrosandboxResult<()> {
        stop::stop(
            self.backend.clone(),
            &self.name,
            self.identity(),
            self.is_local_ephemeral(),
            None,
        )
        .await
    }

    /// Request graceful shutdown and return once the request is sent.
    ///
    /// Routes through the backend trait. On local this connects to the agent
    /// endpoint and sends `core.shutdown` (agentd runs `sync()` +
    /// `reboot(RB_POWER_OFF)` for a clean ext4 unmount). If delivery fails, the
    /// error is returned without substituting process termination. On cloud
    /// this issues `POST /v1/sandboxes/by-name/:name/stop`.
    pub async fn request_stop(&self) -> MicrosandboxResult<()> {
        tracing::debug!(sandbox = %self.name, "stop: dispatching");
        self.backend
            .sandbox_ops()
            .stop_identified(self.backend.clone(), &self.name, self.identity())
            .await
    }

    /// Wait for graceful completion under one budget, including dispatch and runtime release.
    ///
    /// Expiry returns [`crate::MicrosandboxError::StopTimeout`] without killing. Zero has no
    /// dispatch budget. A delivered shutdown request may still complete after timeout.
    pub async fn stop_with_timeout(&self, timeout: std::time::Duration) -> MicrosandboxResult<()> {
        stop::stop(
            self.backend.clone(),
            &self.name,
            self.identity(),
            self.is_local_ephemeral(),
            Some(timeout),
        )
        .await
    }

    /// Stop the sandbox gracefully and wait for the process to exit.
    ///
    /// **Local backend only.** Cloud sandboxes have no host process to wait
    /// on; use [`stop`](Self::stop) and poll [`status`](Self::status) instead.
    ///
    /// With no owned child-process handle, preserves the existing synthetic success status
    /// after runtime completion; this is not the guest's actual exit code.
    #[cfg(feature = "local")]
    pub async fn stop_and_wait(&self) -> MicrosandboxResult<ExitStatus> {
        let local = self.require_local(Operation::SandboxStopAndWait)?;
        self.stop().await?;
        if local.handle.is_none() {
            Ok(std::process::ExitStatus::default())
        } else {
            self.wait().await
        }
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
            .sandbox_ops()
            .kill_identified(self.backend.clone(), &self.name, self.identity())
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
                #[cfg(feature = "local")]
                self.reap_exited_child()?;
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
            .sandbox_ops()
            .drain_identified(self.backend.clone(), &self.name, self.identity())
            .await
    }

    /// Wait for the sandbox process to exit. **Local backend only.**
    #[cfg(feature = "local")]
    pub async fn wait(&self) -> MicrosandboxResult<ExitStatus> {
        let local = self.require_local(Operation::SandboxWait)?;
        match &local.handle {
            Some(h) => h.lock().await.wait().await,
            None => Err(crate::MicrosandboxError::Runtime(
                "cannot wait: not the lifecycle owner".into(),
            )),
        }
    }

    /// Stop and start this exact sandbox using default graceful options.
    pub async fn restart(&self) -> MicrosandboxResult<Sandbox> {
        self.restart_with(RestartOptions::default()).await
    }

    /// Stop and start this exact sandbox with explicit lifecycle options.
    pub async fn restart_with(&self, options: RestartOptions) -> MicrosandboxResult<Sandbox> {
        self.refresh_handle().await?.restart_with(options).await
    }

    /// Stop and remove this exact sandbox using default graceful options.
    pub async fn destroy(&self) -> MicrosandboxResult<()> {
        self.destroy_with(DestroyOptions::default()).await
    }

    /// Stop and remove this exact sandbox with explicit lifecycle options.
    pub async fn destroy_with(&self, options: DestroyOptions) -> MicrosandboxResult<()> {
        self.refresh_handle().await?.destroy_with(options).await
    }

    /// Wait until this sandbox is observed in a terminal non-running state.
    pub async fn wait_until_stopped(&self) -> MicrosandboxResult<SandboxStopResult> {
        #[cfg(feature = "local")]
        if self.owns_lifecycle() {
            let status = self.wait().await?;
            return Ok(stop_result_from_exit_status(&self.name, status));
        }

        match self.refresh_handle().await {
            Ok(handle) => handle.wait_until_stopped().await,
            Err(error)
                if self.is_local_ephemeral() && sandbox_not_found_for_name(&error, &self.name) =>
            {
                Ok(ephemeral_cleanup_stop_result(&self.name))
            }
            Err(error) => Err(error),
        }
    }

    /// Keep the creator's process safety net armed until every creation check has succeeded.
    #[cfg(feature = "local")]
    pub(crate) async fn finish_detached_creation(&mut self) -> MicrosandboxResult<()> {
        if let Some(local) = self.local_state()
            && let Some(cleanup) = &local.cleanup
        {
            cleanup.disarm_retained(local.handle.as_ref())?;
        }
        Ok(())
    }

    fn is_local_ephemeral(&self) -> bool {
        #[cfg(feature = "local")]
        {
            matches!(self.identity, SandboxIdentity::Local(_)) && self.ephemeral
        }
        #[cfg(not(feature = "local"))]
        {
            false
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Select lifecycle ownership after deferred snapshot resolution.
///
/// A full restore has no newly-created foreground command for the caller to own. It must enter the
/// detached runtime path before process creation so Unix never installs a parent watchdog and
/// Windows never assigns the runtime to a kill-on-close job.
#[cfg(feature = "local")]
pub(crate) fn create_spawn_mode(config: &SandboxConfig, requested: SpawnMode) -> SpawnMode {
    if config.resumed_from_full_snapshot() {
        SpawnMode::Detached
    } else {
        requested
    }
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
        // With no workdir known here, the sandbox's own default applies.
        cwd: cwd.or_else(|| config.spec.runtime.workdir.clone()),
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

/// Derive a guest hostname from a sandbox name, fitting within
/// [`MAX_HOSTNAME_BYTES`]. Names short enough pass through unchanged;
/// longer names collapse to a deterministic `<prefix>-<hash>` form to
/// keep distinct long names very unlikely to share a hostname.
pub(crate) fn hostname_from_sandbox_name(name: &str) -> String {
    derive_hostname(name)
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
        init::validate_env_pair("environment variable", &var.key, &var.value)?;
    }
    Ok(())
}

#[cfg(feature = "local")]
pub(super) fn remove_dir_if_exists(path: &Path) -> MicrosandboxResult<()> {
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// Remove one exact local sandbox identity after proving no runtime owns it.
#[cfg(feature = "local")]
pub(super) async fn remove_local_persisted_sandbox(
    local_backend: &LocalContext,
    name: &str,
    expected_id: i32,
) -> MicrosandboxResult<()> {
    // An internal recovery alias may be visible to a mixed-version catalog reader.
    // It cannot own a user operation, including deletion of TLS keys by numeric ID.
    validate_sandbox_name(name)?;
    let _transition_guard =
        LocalContext::acquire_sandbox_transition_guard(&local_backend.config().run_dir(), name)
            .await?;
    let _lineage_guard =
        crate::snapshot::lineage::lock_source(&local_backend.config().run_dir(), name).await?;

    // Re-read after acquiring transition ownership. A stale `Sandbox` object must never delete a
    // newer sandbox that reused the same deterministic name, and an active identity must not be
    // reaped merely because a caller held an older terminal snapshot.
    let pools = local_backend.db().await?;
    let mut current = microsandbox_db::catalog::sandbox_query(pools.read())
        .await?
        .filter(sandbox_entity::Column::Name.eq(name))
        .one(pools.read())
        .await?
        .ok_or_else(|| crate::MicrosandboxError::SandboxNotFound(name.to_string()))?;
    if current.id != expected_id {
        return Err(crate::MicrosandboxError::SandboxReplaced {
            name: name.to_string(),
            expected: format!("local:{expected_id}"),
            actual: format!("local:{}", current.id),
        });
    }
    if !matches!(
        current.status,
        SandboxStatus::Created | SandboxStatus::Stopped | SandboxStatus::Crashed
    ) {
        return Err(crate::MicrosandboxError::SandboxStillRunning(format!(
            "cannot remove sandbox {name:?}: status is {:?}",
            current.status
        )));
    }

    // Older Windows runtimes did not own a lifecycle lock and can outlive their terminal DB row.
    // Transition ownership prevents a new start while this identity-checked compatibility cleanup
    // terminates that recorded generation.
    #[cfg(windows)]
    if reap_leaked_runtime_process(local_backend, expected_id, name).await?
        == reap::LeakedReapVerdict::Unverifiable
    {
        return Err(crate::MicrosandboxError::Runtime(format!(
            "cannot remove sandbox {name:?}: its recorded runtime process could not be verified"
        )));
    }

    let _runtime_guard = crate::runtime::acquire_sandbox_lifecycle_guard(
        &local_backend.config().run_dir(),
        name,
        std::time::Duration::from_secs(5),
    )
    .await?;

    // Runtime ownership may have taken time to become available. Recheck the exact identity and
    // terminal state before deleting any deterministic storage.
    current = microsandbox_db::catalog::sandbox_query(pools.read())
        .await?
        .filter(sandbox_entity::Column::Name.eq(name))
        .one(pools.read())
        .await?
        .ok_or_else(|| crate::MicrosandboxError::SandboxNotFound(name.to_string()))?;
    if current.id != expected_id {
        return Err(crate::MicrosandboxError::SandboxReplaced {
            name: name.to_string(),
            expected: format!("local:{expected_id}"),
            actual: format!("local:{}", current.id),
        });
    }
    if !matches!(
        current.status,
        SandboxStatus::Created | SandboxStatus::Stopped | SandboxStatus::Crashed
    ) {
        return Err(crate::MicrosandboxError::SandboxStillRunning(format!(
            "cannot remove sandbox {name:?}: status changed to {:?}",
            current.status
        )));
    }

    // The runtime lock is the authoritative ownership proof. A numeric PID can remain visible
    // while an exited Unix child is waiting to be reaped, or can already identify an unrelated
    // process after PID reuse, so it must not override successful lock acquisition.
    if crate::context::local::creation::pending(pools.write(), expected_id).await? {
        return local_backend
            .remove_incomplete_sandbox(expected_id, name, RemovalMode::Recovery)
            .await;
    }

    let _storage = CreationStorage::acquire(local_backend, name)?;
    local_backend.remove_socket_artifacts(name)?;
    #[cfg(target_os = "linux")]
    if local_backend.config().runtime.private_writeback_leases
        || local_backend.private_writeback_lease_dir(name).exists()
    {
        lease_recovery::recover(
            local_backend,
            pools.read(),
            pools.write(),
            name,
            expected_id,
        )
        .await?;
    }
    #[cfg(target_os = "linux")]
    crate::runtime::private_metrics::remove(&local_backend.config().run_dir(), name)?;
    microsandbox_runtime::checkpoint::remove_sandbox_identity(
        &local_backend.config().home(),
        expected_id,
    )
    .map_err(crate::MicrosandboxError::Runtime)?;
    remove_dir_if_exists(&local_backend.sandboxes_dir().join(name))?;
    sandbox_entity::Entity::delete_by_id(expected_id)
        .exec(pools.write())
        .await?;

    Ok(())
}

/// Load a sandbox row by name.
#[cfg(feature = "local")]
pub(super) async fn load_sandbox_record(
    db: &DbReadConnection,
    name: &str,
) -> MicrosandboxResult<sandbox_entity::Model> {
    microsandbox_db::catalog::sandbox_query(db)
        .await?
        .filter(sandbox_entity::Column::Name.eq(name))
        .one(db)
        .await?
        .ok_or_else(|| crate::MicrosandboxError::SandboxNotFound(name.into()))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, feature = "local"))]
mod tests {
    use std::fs;
    #[cfg(unix)]
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    #[cfg(unix)]
    use sea_orm::EntityTrait;
    use sea_orm::{ActiveModelTrait, Set};
    use tempfile::tempdir;

    use super::{
        MAX_HOSTNAME_BYTES, MAX_SANDBOX_NAME_BYTES, SandboxStatus, create_spawn_mode,
        ephemeral_cleanup_stop_result, hostname_from_sandbox_name, remove_dir_if_exists,
        remove_local_persisted_sandbox, sandbox_not_found_for_name, validate_hostname,
    };
    use crate::context::LocalContext;
    use crate::runtime::SpawnMode;

    #[test]
    fn full_restore_forces_detached_creation_before_spawn() {
        let mut config = super::SandboxConfig::default();
        assert_eq!(
            create_spawn_mode(&config, SpawnMode::Attached),
            SpawnMode::Attached
        );
        assert_eq!(
            create_spawn_mode(&config, SpawnMode::Detached),
            SpawnMode::Detached
        );

        config.suppress_launch_for_full_restore();
        assert_eq!(
            create_spawn_mode(&config, SpawnMode::Attached),
            SpawnMode::Detached
        );
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
    async fn persisted_removal_rejects_a_stale_sandbox_identity() {
        let temp = tempdir().unwrap();
        let backend = LocalContext::builder()
            .config_path(temp.path().join("home").join("config.json"))
            .managed_config_path(temp.path().join("home").join("managed.json"))
            .home(temp.path().join("home"))
            .build()
            .unwrap();
        let pools = backend.db().await.unwrap();
        let current = super::sandbox_entity::ActiveModel {
            name: Set("recreated".to_string()),
            config: Set("{}".to_string()),
            status: Set(SandboxStatus::Stopped),
            ephemeral: Set(false),
            ..Default::default()
        }
        .insert(pools.write())
        .await
        .unwrap();
        let sandbox_dir = backend.sandboxes_dir().join("recreated");
        std::fs::create_dir_all(&sandbox_dir).unwrap();
        std::fs::write(sandbox_dir.join("marker"), b"successor").unwrap();

        let error = remove_local_persisted_sandbox(&backend, "recreated", current.id + 1)
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            crate::MicrosandboxError::SandboxReplaced { .. }
        ));
        assert!(sandbox_dir.join("marker").exists());
    }

    #[tokio::test]
    async fn persisted_removal_removes_a_sandbox_that_never_started() {
        let temp = tempdir().unwrap();
        let backend = LocalContext::builder()
            .config_path(temp.path().join("home").join("config.json"))
            .managed_config_path(temp.path().join("home").join("managed.json"))
            .home(temp.path().join("home"))
            .build()
            .unwrap();
        let pools = backend.db().await.unwrap();
        let created = super::sandbox_entity::ActiveModel {
            name: Set("never-started".to_string()),
            config: Set("{}".to_string()),
            status: Set(SandboxStatus::Created),
            ephemeral: Set(false),
            ..Default::default()
        }
        .insert(pools.write())
        .await
        .unwrap();
        let sandbox_dir = backend.sandboxes_dir().join("never-started");
        std::fs::create_dir_all(&sandbox_dir).unwrap();

        remove_local_persisted_sandbox(&backend, "never-started", created.id)
            .await
            .unwrap();

        assert!(!sandbox_dir.exists());
        assert!(matches!(
            remove_local_persisted_sandbox(&backend, "never-started", created.id).await,
            Err(crate::MicrosandboxError::SandboxNotFound(_))
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn persisted_removal_trusts_runtime_ownership_over_a_recycled_pid() {
        use crate::db::entity::run as run_entity;

        let temp = tempdir().unwrap();
        let backend = LocalContext::builder()
            .config_path(temp.path().join("home").join("config.json"))
            .managed_config_path(temp.path().join("home").join("managed.json"))
            .home(temp.path().join("home"))
            .build()
            .unwrap();
        let pools = backend.db().await.unwrap();
        let current = super::sandbox_entity::ActiveModel {
            name: Set("recycled-pid".to_string()),
            config: Set("{}".to_string()),
            status: Set(SandboxStatus::Stopped),
            ephemeral: Set(false),
            ..Default::default()
        }
        .insert(pools.write())
        .await
        .unwrap();
        run_entity::ActiveModel {
            sandbox_id: Set(current.id),
            // This PID is alive but cannot own the free lifecycle lock. It models both PID reuse
            // and an exited Unix child that remains visible until its parent reaps the zombie.
            pid: Set(Some(std::process::id() as i32)),
            status: Set(run_entity::RunStatus::Running),
            ..Default::default()
        }
        .insert(pools.write())
        .await
        .unwrap();
        let sandbox_dir = backend.sandboxes_dir().join("recycled-pid");
        std::fs::create_dir_all(&sandbox_dir).unwrap();

        remove_local_persisted_sandbox(&backend, "recycled-pid", current.id)
            .await
            .unwrap();

        assert!(!sandbox_dir.exists());
        assert!(
            super::sandbox_entity::Entity::find_by_id(current.id)
                .one(pools.read())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn persisted_removal_waits_for_snapshot_lineage_owner() {
        let temp = tempdir().unwrap();
        let backend = std::sync::Arc::new(
            crate::test_support::local_backend_builder(temp.path().join("home"))
                .build()
                .unwrap(),
        );
        let pools = backend.db().await.unwrap();
        let current = super::sandbox_entity::ActiveModel {
            name: Set("snapshot-source".to_string()),
            config: Set("{}".to_string()),
            status: Set(SandboxStatus::Stopped),
            ephemeral: Set(false),
            ..Default::default()
        }
        .insert(pools.write())
        .await
        .unwrap();
        let sandbox_dir = backend.sandboxes_dir().join("snapshot-source");
        std::fs::create_dir_all(&sandbox_dir).unwrap();
        let lineage =
            crate::snapshot::lineage::lock_source(&backend.config().run_dir(), "snapshot-source")
                .await
                .unwrap();
        let other = backend.clone();
        let mut removal = tokio::spawn(async move {
            remove_local_persisted_sandbox(&other, "snapshot-source", current.id).await
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut removal)
                .await
                .is_err()
        );
        // The source must remain present while capture can still publish its cursor.
        assert!(sandbox_dir.exists());
        drop(lineage);
        tokio::time::timeout(std::time::Duration::from_secs(5), removal)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(!sandbox_dir.exists());
    }

    #[test]
    fn exec_request_leaves_cwd_to_the_sandbox_when_no_workdir_is_known() {
        let request = |config: &super::SandboxConfig, cwd: Option<&str>| {
            super::build_exec_request(
                config,
                "pwd".into(),
                Vec::new(),
                cwd.map(str::to_string),
                None,
                &[],
                &[],
                false,
                24,
                80,
            )
            .cwd
        };
        let mut config = super::SandboxConfig::default();
        assert_eq!(request(&config, None), None);
        assert_eq!(request(&config, Some("/tmp")).as_deref(), Some("/tmp"));

        config.spec.runtime.workdir = Some("/app".into());
        assert_eq!(request(&config, None).as_deref(), Some("/app"));
        assert_eq!(request(&config, Some("/tmp")).as_deref(), Some("/tmp"));
    }
}

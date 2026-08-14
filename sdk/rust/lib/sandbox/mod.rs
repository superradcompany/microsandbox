//! Sandbox lifecycle management.
//!
//! The [`Sandbox`] struct represents a running sandbox. It is created via
//! [`Sandbox::builder`] or [`Sandbox::create`], and provides lifecycle
//! methods (stop, kill, drain, wait) and access to the [`AgentClient`]
//! for guest communication.

pub(crate) mod attach;
mod builder;
pub(crate) mod config;
mod config_patch;
pub mod exec;
pub(crate) mod flat_rootfs;
pub mod fs;
mod handle;
pub mod init;
pub(crate) mod metrics;
mod modify;
mod patch;
#[cfg(windows)]
mod reap;
#[cfg(feature = "ssh")]
pub mod ssh;
// Windows-only in shipping builds, but kept compiled under `test` so the
// platform-independent encoding logic is covered on every host.
#[cfg(any(windows, test))]
pub(crate) mod terminal;
mod types;
pub(crate) mod upper;

use std::{collections::BTreeMap, path::Path, process::ExitStatus, sync::Arc};

use microsandbox_db::DbReadConnection;
use microsandbox_protocol::{
    core::{CoreError, Ping, Pong, Touch, Touched},
    exec::{ExecRequest, ExecRlimit},
    message::MessageType,
};
use microsandbox_types::hostname_from_sandbox_name as derive_hostname;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};

use microsandbox_image::progress_channel;

use crate::{
    MicrosandboxResult,
    agent::AgentClient,
    backend::LocalBackend,
    db::entity::{run as run_entity, sandbox as sandbox_entity},
    error::{Operation, UnsupportedReason},
    runtime::SpawnMode,
};

use self::exec::{ExecHandle, ExecOptions};

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
pub(crate) use patch::{apply_patches, build_upper_tree};
#[cfg(windows)]
pub(crate) use reap::reap_leaked_runtime_process;
pub(crate) use types::validate_named_disk_mount_options;
pub(crate) use types::validate_volume_mounts;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use crate::db::entity::sandbox::SandboxStatus;
pub use crate::logs::{LogEntry, LogOptions, LogSource, LogStreamOptions};
pub use attach::AttachOptionsBuilder;
pub use builder::{RegistryConfigBuilder, SandboxBuilder};
pub use config::SandboxConfig;
#[cfg(feature = "net")]
pub use config_patch::{
    DnsConfigPatch, NetworkConfigPatch, NetworkPolicyConfigPatch, SecretConfigPatch,
    SecretEntryConfigPatch, TlsConfigPatch,
};
pub use config_patch::{
    FilesystemConfigPatch, InitConfigPatch, ResourceConfigPatch, RuntimeConfigPatch,
    SandboxConfigPatch, SandboxImagePatch, ScriptConfigPatch,
};
pub use exec::{ExecOptionsBuilder, ExecOutput, Rlimit, RlimitResource};
pub use fs::{
    FsEntry, FsEntryKind, FsHandle, FsMetadata, FsOpenOptions, FsReadStream, FsSetAttrs,
    FsWriteSink, SandboxFsOps,
};
pub use handle::{DEFAULT_KILL_TIMEOUT, DEFAULT_STOP_TIMEOUT, SandboxHandle};
pub use init::{HandoffInit, InitOptionsBuilder};
pub use metrics::{
    SandboxMetrics, SandboxMetricsReport, SandboxMetricsState, all_sandbox_metrics,
    all_sandbox_metrics_local, all_sandbox_metrics_reports_local, sandbox_metrics_report_local,
};
pub use microsandbox_image::{PullProgress, PullProgressHandle};
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
pub use microsandbox_runtime::logging::LogLevel;
pub use microsandbox_types::{CpuPlacement, PullPolicy};
pub use microsandbox_types::{
    EnvVar, MAX_HOSTNAME_BYTES, MAX_SANDBOX_NAME_BYTES, NetworkSpec, PortProtocol,
    PublishedPortSpec, SandboxLogLevel, SandboxResources, SandboxRuntimeOptions, SandboxSpec,
    TransparentHugePagePolicy, VsockRouteSpec, VsockSocketType, VsockSpec,
};
#[cfg(feature = "net")]
pub use microsandbox_types::{HostPattern, SecretInjection};
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
    DeploymentProfile, DiskImageFormat, FlatClone, HostPermissions, ImageBuilder, ImageSource,
    IntoImage, MountBuilder, MountOptions, NamedVolumeMode, OciRootfsSource, Patch, PatchBuilder,
    RootDisk, RootDiskBuilder, RootfsSource, SecurityProfile, StatVirtualization, VolumeMount,
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

/// One page of sandbox handles.
pub struct SandboxPage {
    /// Sandboxes in this page.
    pub sandboxes: Vec<SandboxHandle>,
    /// Opaque cursor for the next page, or `None` when this is the final page.
    pub next_cursor: Option<String>,
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
        let builder = SandboxBuilder::new(name);
        let backend = crate::backend::default_backend();
        match backend.as_local() {
            Some(local) => builder.with_local_defaults(local.config()),
            None => builder,
        }
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
                    let local = backend.as_local().ok_or_else(|| {
                        crate::MicrosandboxError::local_only(Operation::SandboxCreate)
                    })?;
                    local
                        .create_sandbox(backend.clone(), config, mode, Some(sender))
                        .await
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

        let backend = crate::backend::default_backend();
        backend.sandboxes().list(backend.clone(), query).await
    }

    /// Remove a stopped sandbox by name via the ambient
    /// [`default_backend`](crate::backend::default_backend).
    pub async fn remove(name: &str) -> MicrosandboxResult<()> {
        let backend = crate::backend::default_backend();
        backend.sandboxes().remove(backend.clone(), name).await
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

    /// Build an outer `Sandbox` from a [`CloudCreateSandboxResponse`](crate::backend::CloudCreateSandboxResponse)
    /// HTTP response plus the originating [`SandboxConfig`].
    pub(crate) fn from_cloud(
        backend: Arc<dyn crate::backend::Backend>,
        cloud: crate::backend::CloudCreateSandboxResponse,
        config: SandboxConfig,
    ) -> Self {
        let state = crate::backend::SandboxCloudState {
            id: cloud.id,
            org_id: cloud.org_id,
            created_at: cloud.created_at,
        };
        Self::from_cloud_state(backend, state, cloud.name, config)
    }

    /// Build an outer `Sandbox` from cloud state already captured by a
    /// [`SandboxHandle`]. Cloud agent operations establish their own
    /// authenticated WebSocket lazily, so reconnecting does not need to hold
    /// an eager agent client.
    pub(crate) fn from_cloud_state(
        backend: Arc<dyn crate::backend::Backend>,
        state: crate::backend::SandboxCloudState,
        name: String,
        config: SandboxConfig,
    ) -> Self {
        Self {
            backend,
            inner: Arc::new(crate::backend::SandboxInner::Cloud(state)),
            name,
            config,
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
        op: Operation,
    ) -> MicrosandboxResult<&crate::backend::SandboxLocalState> {
        self.local()
            .ok_or_else(|| crate::MicrosandboxError::local_only(op))
    }

    /// Live status from the backend. Always hits `backend.sandboxes().get(name)`
    /// — there is no cached status on the outer struct, per the D6.4
    /// "fetch-live" policy.
    ///
    /// Each call is a separate round-trip (DB read for local, HTTP GET for
    /// cloud). If you need to read multiple fields together (e.g. status +
    /// last failure message), call [`Sandbox::get`](Self::get) once and read off the
    /// returned [`SandboxHandle`]'s `*_snapshot` accessors instead.
    pub async fn status(&self) -> MicrosandboxResult<SandboxStatus> {
        let handle = self
            .backend
            .sandboxes()
            .get(self.backend.clone(), &self.name)
            .await?;
        Ok(handle.status_snapshot())
    }

    /// Live failure message from the backend, when any. Always hits the
    /// backend, never reads a cached field.
    ///
    /// Each call is a separate round-trip. If you need this alongside
    /// `status()`, fetch a fresh [`SandboxHandle`] via
    /// [`Sandbox::get`](Self::get) once and read both off the snapshot.
    pub async fn last_failure_message(&self) -> MicrosandboxResult<Option<String>> {
        let handle = self
            .backend
            .sandboxes()
            .get(self.backend.clone(), &self.name)
            .await?;
        Ok(handle.last_failure_message_snapshot())
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

    /// A local logger handle over this sandbox's on-disk logs.
    ///
    /// Used directly, followed streams each own a private filesystem watcher.
    /// Register it with a [`LogRegistry`](crate::logs::LogRegistry) to share a
    /// single watcher across many sandboxes. Cloud logs have no host directory
    /// and continue to use [`log_stream`](Self::log_stream) over SSE.
    pub fn logger(&self) -> MicrosandboxResult<crate::logs::SandboxLogger> {
        self.require_local(Operation::SandboxLogger)?;
        let local = self
            .backend
            .as_local()
            .ok_or_else(|| crate::MicrosandboxError::local_only(Operation::SandboxLogger))?;
        let log_dir = crate::logs::log_dir_for_local(local, &self.name);
        Ok(crate::logs::SandboxLogger::new(self.name.clone(), log_dir))
    }

    /// Check whether agentd is reachable without refreshing the sandbox idle timer.
    ///
    /// Local backend only. The request uses `core.ping` and returns the SDK-measured
    /// round-trip latency. If the sandbox runtime predates protocol generation 6,
    /// this fails before any bytes are sent with an unsupported-operation error.
    pub async fn ping(&self) -> MicrosandboxResult<SandboxPingResult> {
        self.require_local(Operation::SandboxPing)?;
        ping_agent(&self.name, self.client()).await
    }

    /// Explicitly refresh the sandbox idle timer.
    ///
    /// Local backend only. The request uses `core.touch`, so callers can keep a
    /// sandbox alive intentionally without relying on unrelated agent traffic.
    pub async fn touch(&self) -> MicrosandboxResult<SandboxTouchResult> {
        self.require_local(Operation::SandboxTouch)?;
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
        let local = self.require_local(Operation::SandboxStopAndWait)?;
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
        let local = self.require_local(Operation::SandboxWait)?;
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

    fn resolve_default_command(&self) -> MicrosandboxResult<microsandbox_types::ResolvedCommand> {
        microsandbox_types::resolve_default_command(
            self.config.spec.runtime.entrypoint.as_deref(),
            self.config.spec.runtime.cmd.as_deref(),
            None,
        )
        .map_err(Into::into)
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Execution
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Execute the sandbox's effective OCI entrypoint and CMD and return a streaming handle.
    pub async fn exec_default_stream(&self) -> MicrosandboxResult<ExecHandle> {
        self.exec_default_stream_with(|options| options).await
    }

    /// Execute the sandbox's effective OCI entrypoint and CMD with full streaming options.
    ///
    /// Arguments configured through the options builder are appended after the resolved default
    /// argv. They are execution arguments, not an OCI CMD override.
    pub async fn exec_default_stream_with(
        &self,
        f: impl FnOnce(ExecOptionsBuilder) -> ExecOptionsBuilder,
    ) -> MicrosandboxResult<ExecHandle> {
        let command = self.resolve_default_command()?;
        let opts = f(ExecOptionsBuilder::default())
            .prepend_args(command.args)
            .build()?;
        self.backend
            .sandboxes()
            .exec_stream(
                self.backend.clone(),
                &self.name,
                &self.config,
                command.program,
                opts,
            )
            .await
    }

    /// Execute the sandbox's effective OCI entrypoint and CMD and wait for completion.
    pub async fn exec_default(&self) -> MicrosandboxResult<ExecOutput> {
        self.exec_default_with(|options| options).await
    }

    /// Execute the sandbox's effective OCI entrypoint and CMD with full options.
    ///
    /// Arguments configured through the options builder are appended after the resolved default
    /// argv. They are execution arguments, not an OCI CMD override.
    pub async fn exec_default_with(
        &self,
        f: impl FnOnce(ExecOptionsBuilder) -> ExecOptionsBuilder,
    ) -> MicrosandboxResult<ExecOutput> {
        let command = self.resolve_default_command()?;
        let opts = f(ExecOptionsBuilder::default())
            .prepend_args(command.args)
            .build()?;
        self.backend
            .sandboxes()
            .exec(
                self.backend.clone(),
                &self.name,
                &self.config,
                command.program,
                opts,
            )
            .await
    }

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
    /// Attach to the sandbox's effective OCI entrypoint and CMD.
    pub async fn attach_default(&self) -> MicrosandboxResult<i32> {
        self.attach_default_with(|options| options).await
    }

    /// Attach to the sandbox's effective OCI entrypoint and CMD with full options.
    ///
    /// Arguments configured through the options builder are appended after the resolved default
    /// argv. They are execution arguments, not an OCI CMD override.
    pub async fn attach_default_with(
        &self,
        f: impl FnOnce(AttachOptionsBuilder) -> AttachOptionsBuilder,
    ) -> MicrosandboxResult<i32> {
        let command = self.resolve_default_command()?;
        let builder = f(AttachOptionsBuilder::default()).prepend_args(command.args);
        self.backend
            .sandboxes()
            .attach(
                self.backend.clone(),
                &self.name,
                &self.config,
                command.program,
                builder,
            )
            .await
    }

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

/// Remove one exact local sandbox identity after proving no runtime owns it.
pub(super) async fn remove_local_persisted_sandbox(
    local_backend: &LocalBackend,
    name: &str,
    expected_id: i32,
) -> MicrosandboxResult<()> {
    let _guard = crate::runtime::acquire_sandbox_lifecycle_guard(
        &local_backend.config().run_dir(),
        name,
        std::time::Duration::from_secs(5),
    )
    .await?;

    // Re-read only after acquiring ownership. A stale `Sandbox` object must
    // never delete a newer sandbox that reused the same deterministic name.
    let pools = local_backend.db().await?;
    let current = sandbox_entity::Entity::find()
        .filter(sandbox_entity::Column::Name.eq(name))
        .one(pools.read())
        .await?
        .ok_or_else(|| crate::MicrosandboxError::SandboxNotFound(name.to_string()))?;
    if current.id != expected_id {
        return Err(crate::MicrosandboxError::Runtime(format!(
            "sandbox {name:?} identity changed from database id {expected_id} to {}; refusing stale removal",
            current.id
        )));
    }
    if !matches!(
        current.status,
        SandboxStatus::Stopped | SandboxStatus::Crashed
    ) {
        return Err(crate::MicrosandboxError::SandboxStillRunning(format!(
            "cannot remove sandbox {name:?}: status is {:?}",
            current.status
        )));
    }

    let latest_run = run_entity::Entity::find()
        .filter(run_entity::Column::SandboxId.eq(expected_id))
        .order_by_desc(run_entity::Column::Id)
        .one(pools.read())
        .await?;
    if latest_run
        .and_then(|run| run.pid)
        .is_some_and(microsandbox_utils::process::pid_is_alive)
    {
        return Err(crate::MicrosandboxError::SandboxStillRunning(format!(
            "cannot remove sandbox {name:?}: its recorded runtime process is still alive"
        )));
    }

    crate::runtime::remove_sandbox_socket_artifacts_for(local_backend, name)?;
    remove_dir_if_exists(&local_backend.sandboxes_dir().join(name))?;
    sandbox_entity::Entity::delete_by_id(expected_id)
        .exec(pools.write())
        .await?;

    Ok(())
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

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(unix)]
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use sea_orm::{ActiveModelTrait, Set};
    use tempfile::tempdir;

    use super::{
        MAX_HOSTNAME_BYTES, MAX_SANDBOX_NAME_BYTES, SandboxStatus, ephemeral_cleanup_stop_result,
        hostname_from_sandbox_name, remove_dir_if_exists, remove_local_persisted_sandbox,
        sandbox_not_found_for_name, validate_hostname,
    };
    use crate::backend::LocalBackend;

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
        let backend = LocalBackend::builder()
            .home(temp.path().join("home"))
            .build()
            .await
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

        assert!(error.to_string().contains("identity changed"));
        assert!(sandbox_dir.join("marker").exists());
    }
}

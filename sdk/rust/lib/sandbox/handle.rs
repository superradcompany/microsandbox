//! Provider observations used internally to construct and inspect unified resources.
//! Application code uses `Sandbox`; records do not represent independent resource ownership.

use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "cloud")]
use crate::context::{CloudCreateSandboxResponse, SandboxRemoteState};
#[cfg(feature = "local")]
use crate::db::entity::sandbox as sandbox_entity;
use crate::{
    MicrosandboxError, MicrosandboxResult,
    context::{
        Context, SandboxRecordCloudState, SandboxRecordInner, SandboxRecordLocalState,
        sandbox::SandboxIdentity,
    },
    error::Operation,
};

#[cfg(feature = "local")]
use super::ResourceResizeStatus;
#[cfg(any(feature = "local", feature = "cloud"))]
use super::SandboxModificationBuilder;
use super::{Sandbox, SandboxConfig, SandboxId, SandboxStatus, SandboxStopResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Default timeout for the eager local agent connection made by
/// [`SandboxRecord::connect`].
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default graceful budget for explicit restart/destroy convergence options.
/// [`SandboxRecord::stop`] itself has no built-in deadline.
pub const DEFAULT_STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// Default timeout for observing stopped state after force termination.
pub const DEFAULT_KILL_TIMEOUT: Duration = Duration::from_secs(5);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Options controlling a sandbox restart.
#[derive(Clone, Copy, Debug)]
pub struct RestartOptions {
    /// Force termination instead of requesting graceful shutdown.
    pub force: bool,
    /// Graceful-shutdown completion budget; expiry does not force termination.
    /// Running Cloud restarts round positive budgets up to whole seconds and
    /// reject budgets above 60 seconds before dispatching the restart request.
    pub timeout: Duration,
    /// Start the replacement runtime in detached mode.
    pub detached: bool,
}

/// Options controlling stop-and-remove lifecycle convergence.
#[derive(Clone, Copy, Debug)]
pub struct DestroyOptions {
    /// Force termination instead of requesting graceful shutdown.
    pub force: bool,
    /// Graceful-shutdown completion budget; expiry does not force termination.
    pub timeout: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnectOrStartAction {
    Connect,
    Start,
    Wait,
    RejectDraining,
    RejectPaused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RestartAction {
    Start,
    Wait,
    StopThenStart,
    RejectPaused,
}

/// Provider observation used to construct a unified `Sandbox`.
/// This implementation type is exposed only for provider and native ABI integration.
#[doc(hidden)]
pub struct SandboxRecord {
    pub(super) backend: Arc<dyn Context>,
    inner: SandboxRecordInner,
    name: String,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SandboxRecord {
    /// Build a handle from a local sandbox DB row + active PID.
    #[cfg(feature = "local")]
    pub(crate) fn from_local_model(
        backend: Arc<dyn Context>,
        model: sandbox_entity::Model,
        pid: Option<i32>,
    ) -> Self {
        let name = model.name.clone();
        Self {
            backend,
            inner: SandboxRecordInner::Local(SandboxRecordLocalState {
                db_id: model.id,
                status: model.status,
                config_json: model.config,
                caller_config_overrides_json: model.caller_config_overrides,
                active_config_json: model.active_config,
                created_at: model.created_at.map(|dt| dt.and_utc()),
                updated_at: model.updated_at.map(|dt| dt.and_utc()),
                pid,
            }),
            name,
        }
    }

    /// Build a handle from a [`CloudCreateSandboxResponse`] HTTP response.
    ///
    /// Preserves the cloud's optional curated spec as JSON for the
    /// `config_json()` inspection view. An absent spec is represented as JSON
    /// `null`; it is not replaced with a fabricated SDK configuration.
    #[cfg(feature = "cloud")]
    pub(crate) fn from_cloud(
        backend: Arc<dyn Context>,
        cloud: CloudCreateSandboxResponse,
    ) -> MicrosandboxResult<Self> {
        let status = crate::context::sandbox::cloud_status_to_sandbox_status(cloud.status);
        let config_json = serde_json::to_string(&cloud.spec)?;
        let name = cloud.name.clone();
        Ok(Self {
            backend,
            inner: SandboxRecordInner::Cloud(SandboxRecordCloudState {
                id: cloud.id,
                org_id: cloud.org_id,
                status,
                config_json,
                created_at: Some(cloud.created_at),
                started_at: cloud.started_at,
                stopped_at: cloud.stopped_at,
                last_failure_message: cloud.last_failure_message,
            }),
            name,
        })
    }

    /// Unique name identifying this sandbox.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Observe files in this sandbox's managed directory using its captured backend.
    ///
    /// Host bind mounts and shared runtime-memory caches are excluded. Ownership and physical
    /// reclamation cannot be inferred from these file lengths.
    pub async fn storage_usage(&self) -> MicrosandboxResult<crate::StorageItemUsage> {
        #[cfg(feature = "local")]
        {
            let local = self
                .backend
                .as_local()
                .ok_or_else(|| MicrosandboxError::local_only(Operation::StorageUsage))?;
            super::validate_sandbox_name(&self.name)?;
            // Fence cooperative removal/recreation while checking this handle's identity and
            // scanning its path. A pre-scan refresh alone can measure a replacement sandbox.
            let _transition = crate::LocalContext::acquire_sandbox_transition_guard(
                &local.config().run_dir(),
                &self.name,
            )
            .await?;
            self.refresh().await?;
            crate::Storage::directory_usage(
                self.name.clone(),
                local.sandboxes_dir().join(&self.name),
                local.sandboxes_dir(),
                "Persisted sandbox data is retained, including stopped and crashed sandboxes. Host bind mounts and shared runtime-memory caches are excluded.",
            ).await
        }
        #[cfg(not(feature = "local"))]
        Err(MicrosandboxError::local_only(Operation::StorageUsage))
    }

    /// Stable identity of this persisted sandbox.
    ///
    /// Unlike [`name`](Self::name), this value changes when a sandbox is
    /// removed and recreated under the same name.
    pub fn id(&self) -> SandboxId {
        match &self.inner {
            SandboxRecordInner::Local(state) => SandboxId::local(state.db_id),
            SandboxRecordInner::Cloud(state) => SandboxId::cloud(&state.id),
        }
    }

    /// Context-private identity selector used by receiver lifecycle methods.
    pub(crate) fn identity(&self) -> SandboxIdentity {
        match &self.inner {
            SandboxRecordInner::Local(state) => SandboxIdentity::Local(state.db_id),
            SandboxRecordInner::Cloud(state) => SandboxIdentity::Cloud(state.id.clone()),
        }
    }

    /// Which backend variant this handle is bound to.
    pub fn context_kind(&self) -> crate::context::ContextKind {
        self.backend.kind()
    }

    /// Local-only handle state. Returns `Some` for local-backed handles.
    pub fn local_state(&self) -> Option<&SandboxRecordLocalState> {
        match &self.inner {
            SandboxRecordInner::Local(s) => Some(s),
            SandboxRecordInner::Cloud(_) => None,
        }
    }

    /// Cloud-only handle state. Returns `Some` for cloud-backed handles.
    pub fn remote_state(&self) -> Option<&SandboxRecordCloudState> {
        match &self.inner {
            SandboxRecordInner::Cloud(s) => Some(s),
            SandboxRecordInner::Local(_) => None,
        }
    }

    /// Snapshot of sandbox status captured when this handle was created.
    ///
    /// **Not live** — call [`Sandbox::status`](super::Sandbox::status) on the
    /// live `Sandbox` (or re-fetch via [`Sandbox::get`](super::Sandbox::get))
    /// for a fresh reading. The `_snapshot` suffix is deliberate to avoid
    /// confusion with `Sandbox::status()` which is async + fetch-live.
    ///
    /// Resource callers should use `Sandbox::info` for an explicit observation
    /// or `Sandbox::status` for a fresh status without starting the sandbox.
    pub fn status_snapshot(&self) -> SandboxStatus {
        match &self.inner {
            SandboxRecordInner::Local(s) => s.status,
            SandboxRecordInner::Cloud(s) => s.status,
        }
    }

    /// Snapshot of the cloud `last_failure_message`, if any. Returns `None`
    /// for local handles (local errors flow through the typed error stack).
    pub fn last_failure_message_snapshot(&self) -> Option<String> {
        match &self.inner {
            SandboxRecordInner::Cloud(s) => s.last_failure_message.clone(),
            SandboxRecordInner::Local(_) => None,
        }
    }

    /// The serialized sandbox configuration as stored in the database (local)
    /// or returned by the cloud API (cloud). Use [`config()`](Self::config) for a
    /// deserialized [`SandboxConfig`].
    pub fn config_json(&self) -> &str {
        match &self.inner {
            SandboxRecordInner::Local(s) => &s.config_json,
            SandboxRecordInner::Cloud(s) => &s.config_json,
        }
    }

    /// The serialized configuration used by the active VM, when known.
    ///
    /// Local handles return `Some` only while a sandbox has started under a
    /// runtime that records active config snapshots. Stopped sandboxes and
    /// older running sandboxes may return `None`.
    pub fn active_config_json(&self) -> Option<&str> {
        match &self.inner {
            SandboxRecordInner::Local(s) => s.active_config_json.as_deref(),
            SandboxRecordInner::Cloud(_) => None,
        }
    }

    /// Parse the stored configuration. Returns an error if the JSON
    /// is malformed (e.g., schema changed since the sandbox was created).
    ///
    /// For local handles this deserializes the persisted [`SandboxConfig`].
    /// For cloud handles this returns an `Unsupported` error: the cloud wire
    /// shape is [`CloudCreateSandboxRequest`](crate::context::CloudCreateSandboxRequest),
    /// not `SandboxConfig`. Use [`config_json`](Self::config_json) to read the
    /// raw JSON, or [`cloud`](Self::cloud) to access the typed cloud state.
    pub fn config(&self) -> MicrosandboxResult<SandboxConfig> {
        match &self.inner {
            SandboxRecordInner::Local(s) => SandboxConfig::from_stored(
                &s.config_json,
                s.caller_config_overrides_json.as_deref(),
            ),
            SandboxRecordInner::Cloud(_) => {
                Err(MicrosandboxError::local_only(Operation::SandboxConfig))
            }
        }
    }

    /// Parse the active configuration snapshot, when one is available.
    pub fn active_config(&self) -> MicrosandboxResult<Option<SandboxConfig>> {
        Ok(self
            .active_config_json()
            .map(serde_json::from_str::<SandboxConfig>)
            .transpose()?)
    }

    /// Start planning a sandbox modification from this handle.
    ///
    /// The builder fetches a fresh handle during [`dry_run`](SandboxModificationBuilder::dry_run)
    /// so planning uses current status and persisted config rather than this
    /// handle's possibly stale snapshot.
    #[cfg(any(feature = "local", feature = "cloud"))]
    pub fn modify(&self) -> SandboxModificationBuilder {
        SandboxModificationBuilder::new(self.backend.clone(), self.name.clone())
            .bound_to(self.identity())
    }

    /// Read the current live CPU and memory resize status.
    ///
    /// Returns an error when the sandbox is not running, and
    /// `Unsupported` when its runtime cannot report resize status.
    #[cfg(feature = "local")]
    pub async fn resize_status(&self) -> MicrosandboxResult<Vec<ResourceResizeStatus>> {
        super::resize::resize_status(&self.backend, &self.name, &self.identity()).await
    }

    /// Read latest per-resource operation identities and evidence without applying a target.
    #[cfg(feature = "local")]
    pub async fn resize_operations(&self) -> MicrosandboxResult<Vec<super::ResizeOperation>> {
        super::resize::resize_operations(&self.backend, &self.name, &self.identity()).await
    }

    /// Wait for exact operations returned by `apply_with_resize_tracking`.
    ///
    /// A replaced runtime, expired operation or supersession is an error. `None`
    /// waits without a deadline; timing out does not undo the resize.
    #[cfg(feature = "local")]
    pub async fn wait_for_resize_operations(
        &self,
        operations: &[super::ResizeOperation],
        timeout: Option<std::time::Duration>,
    ) -> MicrosandboxResult<Vec<ResourceResizeStatus>> {
        super::resize::wait_for_operations(
            &self.backend,
            &self.name,
            &self.identity(),
            Some(operations),
            timeout,
        )
        .await
    }

    /// Binding hook for one check after identity lookup has consumed part of its budget.
    ///
    /// The remaining setup/read budget never enables polling. Timeout errors retain each
    /// completed resource reply and report the original zero-timeout single-check request.
    #[doc(hidden)]
    #[cfg(feature = "local")]
    pub async fn check_resize_operations_with_budget(
        &self,
        operations: Option<&[super::ResizeOperation]>,
        budget: std::time::Duration,
    ) -> MicrosandboxResult<Vec<ResourceResizeStatus>> {
        super::resize::wait_for_operations_with_budget(
            &self.backend,
            &self.name,
            &self.identity(),
            operations,
            Some(std::time::Duration::ZERO),
            Some(budget),
        )
        .await
    }

    /// Wait for the initially selected operations to be guest-confirmed.
    ///
    /// Returns an error when the sandbox is not running, and
    /// `Unsupported` when its runtime cannot report resize status. Keeps polling
    /// while a guest never converges; use `wait_until_resized_with_timeout` to
    /// bound the wait.
    #[cfg(feature = "local")]
    pub async fn wait_until_resized(&self) -> MicrosandboxResult<Vec<ResourceResizeStatus>> {
        super::resize::wait_until_resized(&self.backend, &self.name, &self.identity(), None).await
    }

    /// Wait for the initially selected operations to be guest-confirmed within `timeout`.
    ///
    /// Returns an error when the sandbox is not running, and
    /// `Unsupported` when its runtime cannot report resize status. Expiry returns
    /// [`MicrosandboxError::ResizeTimeout`] with the last observed status, which is empty when no read
    /// completed before the deadline.
    #[cfg(feature = "local")]
    pub async fn wait_until_resized_with_timeout(
        &self,
        timeout: std::time::Duration,
    ) -> MicrosandboxResult<Vec<ResourceResizeStatus>> {
        super::resize::wait_until_resized(
            &self.backend,
            &self.name,
            &self.identity(),
            Some(timeout),
        )
        .await
    }

    /// Compact sealed backing layers of the root and sandbox-owned data disks, running or stopped.
    pub fn compact(&self) -> super::DiskCompactionBuilder {
        super::DiskCompactionBuilder::new(self.backend.clone(), self.name.clone())
    }

    /// Fail with a typed error when the sandbox is not running.
    fn require_running(&self, operation: &str) -> MicrosandboxResult<()> {
        let status = self.status_snapshot();
        if matches!(
            status,
            super::SandboxStatus::Running | super::SandboxStatus::Draining
        ) {
            return Ok(());
        }
        Err(MicrosandboxError::SandboxNotRunning(format!(
            "'{}' is not running (status: {status:?}); cannot {operation}",
            self.name
        )))
    }

    /// Return a fresh handle for the same persisted sandbox.
    ///
    /// If the name now points at a replacement, this returns
    /// [`MicrosandboxError::SandboxReplaced`] instead of silently rebinding the
    /// receiver.
    pub async fn refresh(&self) -> MicrosandboxResult<SandboxRecord> {
        let current = self
            .backend
            .sandbox_ops()
            .get(self.backend.clone(), &self.name)
            .await?;
        self.ensure_same_identity(&current)?;
        Ok(current)
    }

    fn ensure_same_identity(&self, current: &SandboxRecord) -> MicrosandboxResult<()> {
        ensure_identity(&self.name, &self.identity(), current)
    }

    /// When this sandbox was first created, if recorded.
    pub fn created_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        match &self.inner {
            SandboxRecordInner::Local(s) => s.created_at,
            SandboxRecordInner::Cloud(s) => s.created_at,
        }
    }

    /// Best-effort "last activity" timestamp.
    ///
    /// - Local: the database row's `updated_at` (modification time of the
    ///   persisted record).
    /// - Cloud: the most recent of `stopped_at` / `started_at` / `created_at`
    ///   from the API response. This timestamp is computed on the client.
    pub fn updated_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        match &self.inner {
            SandboxRecordInner::Local(s) => s.updated_at,
            SandboxRecordInner::Cloud(s) => s.stopped_at.or(s.started_at).or(s.created_at),
        }
    }

    /// Read captured output from `exec.log` for this sandbox.
    ///
    /// Same backing data as [`Sandbox::logs`](super::Sandbox::logs).
    /// Works without starting the sandbox. **Local handles only**.
    pub async fn logs(
        &self,
        opts: &crate::logs::LogOptions,
    ) -> MicrosandboxResult<Vec<crate::logs::LogEntry>> {
        self.backend
            .sandbox_ops()
            .logs(self.backend.clone(), &self.name, opts)
            .await
    }

    /// Stream captured output for this sandbox.
    ///
    /// Same backing data as [`Sandbox::log_stream`](super::Sandbox::log_stream).
    /// Works without starting the sandbox.
    pub async fn log_stream(
        &self,
        opts: &crate::logs::LogStreamOptions,
    ) -> MicrosandboxResult<crate::context::sandbox::LogStream> {
        self.backend
            .sandbox_ops()
            .log_stream(self.backend.clone(), &self.name, opts)
            .await
    }

    /// Replay a filtered log snapshot, then follow new entries.
    ///
    /// The backend owns the cursor handoff and transport selection.
    pub async fn follow_logs(
        &self,
        opts: &crate::logs::LogOptions,
    ) -> MicrosandboxResult<crate::context::sandbox::LogStream> {
        self.backend
            .sandbox_ops()
            .follow_logs(self.backend.clone(), &self.name, opts)
            .await
    }

    /// Get the latest metrics snapshot for this sandbox. **Local handles only**.
    #[cfg(feature = "local")]
    pub async fn metrics(&self) -> MicrosandboxResult<super::SandboxMetrics> {
        let local = self
            .local_state()
            .ok_or_else(|| MicrosandboxError::local_only(Operation::SandboxMetrics))?;

        if !matches!(
            local.status,
            SandboxStatus::Running | SandboxStatus::Draining | SandboxStatus::Paused
        ) {
            return Err(MicrosandboxError::SandboxNotRunning(format!(
                "'{}' is not running (status: {:?})",
                self.name, local.status
            )));
        }

        let config = self.config()?;
        if config.effective_metrics_interval().is_none() {
            return Err(MicrosandboxError::MetricsDisabled(self.name.clone()));
        }

        let local_backend = self
            .backend
            .as_local()
            .ok_or_else(|| MicrosandboxError::local_only(Operation::SandboxMetrics))?;
        let db = local_backend.db().await?.read();
        super::metrics::metrics_for_sandbox(db, local_backend, local.db_id, &config).await
    }

    /// Start this sandbox and return a live handle.
    ///
    /// Boots the VM using the persisted configuration and pinned rootfs state
    /// for local; routes through `POST /v1/sandboxes/by-name/:name/start` for
    /// cloud. The handle remains usable if start fails.
    ///
    /// On a Cloud sandbox, a start is refused with
    /// [`MicrosandboxError::CloudHttp`](crate::MicrosandboxError::CloudHttp) (409) while a
    /// secret change to it is being saved, or while its result is not yet known after
    /// [`MicrosandboxError::ModificationNotConfirmed`](crate::MicrosandboxError::ModificationNotConfirmed);
    /// this usually clears within seconds. Start again after a short wait.
    pub async fn start(&self) -> MicrosandboxResult<Sandbox> {
        self.backend
            .sandbox_ops()
            .start_identified(self.backend.clone(), &self.name, self.identity())
            .await
    }

    /// Start this sandbox in detached/background mode.
    ///
    /// The handle remains usable if start fails.
    ///
    /// On a Cloud sandbox, a start is refused with
    /// [`MicrosandboxError::CloudHttp`](crate::MicrosandboxError::CloudHttp) (409) while a
    /// secret change to it is being saved, or while its result is not yet known after
    /// [`MicrosandboxError::ModificationNotConfirmed`](crate::MicrosandboxError::ModificationNotConfirmed);
    /// this usually clears within seconds. Start again after a short wait.
    pub async fn start_detached(&self) -> MicrosandboxResult<Sandbox> {
        self.backend
            .sandbox_ops()
            .start_detached_identified(self.backend.clone(), &self.name, self.identity())
            .await
    }

    /// Connect when running, or start the same persisted sandbox when stopped.
    ///
    /// A `Starting` sandbox is observed until it becomes `Running`. Draining
    /// and paused sandboxes are rejected because neither state is safe to
    /// reinterpret as a start request.
    pub async fn connect_or_start(&self) -> MicrosandboxResult<Sandbox> {
        self.connect_or_start_with_mode(false).await
    }

    /// Connect when running, or start in detached mode when stopped.
    pub async fn connect_or_start_detached(&self) -> MicrosandboxResult<Sandbox> {
        self.connect_or_start_with_mode(true).await
    }

    pub(crate) async fn connect_or_start_with_mode(
        &self,
        detached: bool,
    ) -> MicrosandboxResult<Sandbox> {
        loop {
            let current = self.refresh().await?;
            match connect_or_start_action(current.status_snapshot()) {
                ConnectOrStartAction::Connect => {
                    return current.connect_with_timeout(DEFAULT_CONNECT_TIMEOUT).await;
                }
                ConnectOrStartAction::Start => {
                    let start = if detached {
                        current.start_detached().await
                    } else {
                        current.start().await
                    };
                    match start {
                        Ok(sandbox) => return Ok(sandbox),
                        // Another caller may have started the same persisted
                        // sandbox after our refresh. Observe that transition
                        // and converge instead of exposing the race.
                        Err(MicrosandboxError::SandboxStillRunning(_)) => {}
                        Err(error) => return Err(error),
                    }
                }
                ConnectOrStartAction::Wait => {}
                ConnectOrStartAction::RejectDraining => {
                    return Err(MicrosandboxError::SandboxStillRunning(format!(
                        "cannot connect or start sandbox '{}': shutdown is already in progress",
                        current.name
                    )));
                }
                ConnectOrStartAction::RejectPaused => {
                    return Err(MicrosandboxError::SandboxNotRunning(format!(
                        "'{}' is paused; resume support is required before it can be connected",
                        current.name
                    )));
                }
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Connect to a running sandbox and return a live handle.
    ///
    /// Local sandboxes establish the agent relay connection eagerly. Cloud
    /// sandboxes return a backend-bound handle whose exec, SSH, and filesystem
    /// operations open authenticated agent WebSockets on demand.
    pub async fn connect(&self) -> MicrosandboxResult<Sandbox> {
        self.connect_with_timeout(DEFAULT_CONNECT_TIMEOUT).await
    }

    /// Connect to a running sandbox with an explicit local agent handshake
    /// timeout.
    ///
    /// Cloud reconnect is lazy and does not open an agent WebSocket here, so
    /// this timeout applies only to local handles.
    pub async fn connect_with_timeout(&self, timeout: Duration) -> MicrosandboxResult<Sandbox> {
        match &self.inner {
            // Cloud agent routes are already keyed by the captured UUID, so
            // reconnecting cannot follow a reused name and needs no lookup.
            SandboxRecordInner::Cloud(_) => self.connect_current_with_timeout(timeout).await,
            SandboxRecordInner::Local(_) => {
                let current = self.refresh().await?;
                current.connect_current_with_timeout(timeout).await
            }
        }
    }

    pub(super) async fn connect_current_with_timeout(
        &self,
        timeout: Duration,
    ) -> MicrosandboxResult<Sandbox> {
        #[cfg(not(feature = "local"))]
        let _ = timeout;

        if !matches!(
            self.status_snapshot(),
            SandboxStatus::Running | SandboxStatus::Draining
        ) {
            return Err(MicrosandboxError::SandboxNotRunning(format!(
                "'{}' is not running (status: {:?})",
                self.name,
                self.status_snapshot()
            )));
        }

        match &self.inner {
            #[cfg(feature = "local")]
            SandboxRecordInner::Local(local) => {
                let local_backend = self.backend.as_local().ok_or_else(|| {
                    MicrosandboxError::local_only(Operation::SandboxEnsureRunning)
                })?;
                let run_id = crate::LocalContext::load_latest_run(
                    local_backend.db().await?.read(),
                    local.db_id,
                )
                .await?
                .map(|run| run.id);
                let client = crate::sandbox::fs::agent::connect_agent_with_timeout(
                    local_backend,
                    &self.name,
                    timeout,
                )
                .await?;
                // The local transport is name-addressed. Recheck after the
                // handshake so concurrent name reuse cannot silently rebind
                // this receiver to the replacement.
                self.refresh().await?;
                let after = crate::LocalContext::load_latest_run(
                    local_backend.db().await?.read(),
                    local.db_id,
                )
                .await?
                .map(|run| run.id);
                if run_id.is_none() || run_id != after {
                    return Err(MicrosandboxError::SandboxNotRunning(format!(
                        "runtime generation changed while connecting to '{}'",
                        self.name,
                    )));
                }
                let config = SandboxConfig::from_stored(
                    &local.config_json,
                    local.caller_config_overrides_json.as_deref(),
                )?;

                Ok(Sandbox::from_local(
                    self.backend.clone(),
                    crate::context::SandboxLocalState {
                        db_id: local.db_id,
                        run_id,
                        handle: None,
                        cleanup: None,
                        owned_run_id: None,
                        client: Arc::new(client),
                    },
                    config,
                ))
            }
            #[cfg(not(feature = "local"))]
            SandboxRecordInner::Local(_) => Err(MicrosandboxError::local_only(
                Operation::SandboxEnsureRunning,
            )),
            SandboxRecordInner::Cloud(cloud) => {
                #[cfg(not(feature = "cloud"))]
                {
                    let _ = cloud;
                    Err(MicrosandboxError::cloud_only(
                        Operation::SandboxEnsureRunning,
                    ))
                }
                #[cfg(feature = "cloud")]
                {
                    // Decode execution settings from the inspection projection,
                    // independently of redacted creation-only fields. Invalid
                    // runtime settings must fail preparation rather than vanish.
                    let spec = serde_json::from_str(&cloud.config_json)?;
                    let config =
                        crate::context::sandbox::sandbox_config_from_cloud_spec(&self.name, spec)?;
                    let created_at = cloud.created_at.ok_or_else(|| {
                        MicrosandboxError::Runtime(format!(
                            "cloud sandbox {:?} is missing its creation timestamp",
                            self.name
                        ))
                    })?;

                    Ok(Sandbox::from_cloud_state(
                        self.backend.clone(),
                        SandboxRemoteState {
                            id: cloud.id.clone(),
                            org_id: cloud.org_id.clone(),
                            created_at,
                        },
                        self.name.clone(),
                        config,
                    ))
                }
            }
        }
    }

    /// Check whether agentd is reachable without refreshing the sandbox idle timer.
    ///
    /// Connects to the running sandbox and sends `core.ping`. Stopped sandboxes
    /// are not started implicitly; call [`start`](Self::start) first when that
    /// is the desired behavior.
    #[cfg(feature = "local")]
    pub async fn ping(&self) -> MicrosandboxResult<super::SandboxPingResult> {
        self.require_running("ping")?;
        self.connect().await?.ping().await
    }

    /// Explicitly refresh the sandbox idle timer.
    ///
    /// Connects to the running sandbox and sends `core.touch`. Stopped sandboxes
    /// are not started implicitly; call [`start`](Self::start) first when that
    /// is the desired behavior.
    #[cfg(feature = "local")]
    pub async fn touch(&self) -> MicrosandboxResult<super::SandboxTouchResult> {
        self.require_running("touch")?;
        self.connect().await?.touch().await
    }

    /// Create a new source-bound history and its initial disk checkpoint.
    pub async fn snapshot(&self, group: &str) -> MicrosandboxResult<crate::SnapshotCreateResult> {
        self.snapshot_with(group, |capture| capture).await
    }

    /// Configure initial capture. An existing group cannot turn this call into append.
    pub async fn snapshot_with(
        &self,
        group: &str,
        configure: impl FnOnce(crate::SnapshotCaptureOptions) -> crate::SnapshotCaptureOptions,
    ) -> MicrosandboxResult<crate::SnapshotCreateResult> {
        crate::Snapshot::create_for(
            self.backend.clone(),
            &self.name,
            self.id(),
            group,
            configure(crate::SnapshotCaptureOptions::default()),
        )
        .await
    }

    /// Request graceful shutdown and wait indefinitely for this run's runtime ownership release.
    /// Cancelling the wait does not kill the sandbox or undo a delivered request.
    pub async fn stop(&self) -> MicrosandboxResult<()> {
        super::stop::stop(
            self.backend.clone(),
            &self.name,
            self.identity(),
            self.is_local_ephemeral(),
            None,
        )
        .await
    }

    /// Graceful completion under one budget, without implicit force termination.
    /// Zero returns a timeout before dispatch; a delivered request may finish later.
    pub async fn stop_with_timeout(&self, timeout: Duration) -> MicrosandboxResult<()> {
        super::stop::stop(
            self.backend.clone(),
            &self.name,
            self.identity(),
            self.is_local_ephemeral(),
            Some(timeout),
        )
        .await
    }

    /// Request graceful shutdown without waiting for observed stopped state.
    pub async fn request_stop(&self) -> MicrosandboxResult<()> {
        let current = self.refresh().await?;
        if sandbox_status_is_terminal(current.status_snapshot()) {
            return Ok(());
        }

        current
            .backend
            .sandbox_ops()
            .stop_identified(current.backend.clone(), &current.name, current.identity())
            .await
    }

    /// Kill the sandbox immediately and wait until it is observed stopped.
    pub async fn kill(&self) -> MicrosandboxResult<()> {
        self.kill_with_timeout(DEFAULT_KILL_TIMEOUT).await
    }

    /// Request force termination without waiting for observed stopped state.
    pub async fn request_kill(&self) -> MicrosandboxResult<()> {
        let current = self.refresh().await?;
        if sandbox_status_is_terminal(current.status_snapshot()) {
            return Ok(());
        }

        current
            .backend
            .sandbox_ops()
            .kill_identified(current.backend.clone(), &current.name, current.identity())
            .await
    }

    /// Force-kill the sandbox and wait up to `timeout` for stopped-state observation.
    pub async fn kill_with_timeout(&self, timeout: Duration) -> MicrosandboxResult<()> {
        let current = self.refresh().await?;
        if sandbox_status_is_terminal(current.status_snapshot()) {
            return Ok(());
        }

        current.request_kill().await?;
        match tokio::time::timeout(timeout, current.wait_until_stopped()).await {
            Ok(result) => {
                result?;
                Ok(())
            }
            Err(_) => Err(MicrosandboxError::Runtime(format!(
                "timed out observing stopped state for sandbox '{}'",
                current.name
            ))),
        }
    }

    /// Request drain without waiting for observed stopped state.
    pub async fn request_drain(&self) -> MicrosandboxResult<()> {
        let current = self.refresh().await?;
        if sandbox_status_is_terminal(current.status_snapshot()) {
            return Ok(());
        }

        current
            .backend
            .sandbox_ops()
            .drain_identified(current.backend.clone(), &current.name, current.identity())
            .await
    }

    /// Wait until this exact sandbox reaches `status`.
    ///
    /// This method intentionally has no timeout parameter. Callers compose
    /// their own deadline or cancellation primitive around the future.
    pub async fn wait_for_status(
        &self,
        status: SandboxStatus,
    ) -> MicrosandboxResult<SandboxRecord> {
        loop {
            let current = self.refresh().await?;
            if current.status_snapshot() == status {
                return Ok(current);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Restart this exact sandbox using default graceful options.
    pub async fn restart(&self) -> MicrosandboxResult<Sandbox> {
        self.restart_with(RestartOptions::default()).await
    }

    /// Restart this exact sandbox with explicit lifecycle options.
    pub async fn restart_with(&self, options: RestartOptions) -> MicrosandboxResult<Sandbox> {
        self.backend
            .sandbox_ops()
            .restart_identified(self.backend.clone(), &self.name, self.identity(), options)
            .await
    }

    /// Stop and remove this exact sandbox using default graceful options.
    pub async fn destroy(&self) -> MicrosandboxResult<()> {
        self.destroy_with(DestroyOptions::default()).await
    }

    /// Stop and remove this exact sandbox with explicit lifecycle options.
    pub async fn destroy_with(&self, options: DestroyOptions) -> MicrosandboxResult<()> {
        let current = self.refresh().await?;
        if destroy_requires_stop(current.status_snapshot()) {
            stop_for_convergence(&current, options.force, options.timeout).await?;
        }
        match current.remove().await {
            Ok(()) => Ok(()),
            Err(error)
                if current.is_local_ephemeral()
                    && super::sandbox_not_found_for_name(&error, &current.name) =>
            {
                // Local ephemeral cleanup removes persisted state as part of
                // shutdown, so there is nothing left for destroy to delete.
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    /// Wait until this sandbox is observed in a terminal non-running state.
    pub async fn wait_until_stopped(&self) -> MicrosandboxResult<SandboxStopResult> {
        loop {
            let current = match self.refresh().await {
                Ok(current) => current,
                Err(error)
                    if self.is_local_ephemeral()
                        && super::sandbox_not_found_for_name(&error, &self.name) =>
                {
                    return Ok(super::ephemeral_cleanup_stop_result(&self.name));
                }
                Err(error) => return Err(error),
            };
            let status = current.status_snapshot();
            if sandbox_status_is_terminal(status) {
                return Ok(SandboxStopResult {
                    name: current.name,
                    status,
                    exit_code: None,
                    signal: None,
                    observed_at: chrono::Utc::now(),
                    source: Some("refreshed backend state".to_string()),
                });
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Remove this sandbox.
    ///
    /// The sandbox must be stopped first. Use [`stop`](Self::stop) or
    /// [`kill`](Self::kill) to stop it before removing. Routes through the
    /// backend trait so cloud handles hit `DELETE /v1/sandboxes/by-name/:name`.
    pub async fn remove(&self) -> MicrosandboxResult<()> {
        match &self.inner {
            #[cfg(feature = "local")]
            SandboxRecordInner::Local(_) => {
                let refreshed = self.refresh().await?;
                let local = refreshed
                    .local_state()
                    .ok_or_else(|| MicrosandboxError::local_only(Operation::SandboxDestroy))?;
                if matches!(
                    local.status,
                    SandboxStatus::Starting
                        | SandboxStatus::Running
                        | SandboxStatus::Draining
                        | SandboxStatus::Paused
                ) {
                    return Err(MicrosandboxError::SandboxStillRunning(format!(
                        "cannot remove sandbox '{}': still running",
                        self.name
                    )));
                }

                let local_backend = self
                    .backend
                    .as_local()
                    .ok_or_else(|| MicrosandboxError::local_only(Operation::SandboxDestroy))?;

                super::remove_local_persisted_sandbox(local_backend, &self.name, local.db_id).await
            }
            #[cfg(not(feature = "local"))]
            SandboxRecordInner::Local(_) => {
                Err(MicrosandboxError::local_only(Operation::SandboxDestroy))
            }
            SandboxRecordInner::Cloud(_) => {
                self.backend
                    .sandbox_ops()
                    .remove_identified(self.backend.clone(), &self.name, self.identity())
                    .await
            }
        }
    }

    pub(crate) fn is_local_ephemeral(&self) -> bool {
        is_local_ephemeral_handle(&self.inner)
    }
}

impl Default for RestartOptions {
    fn default() -> Self {
        Self {
            force: false,
            timeout: DEFAULT_STOP_TIMEOUT,
            detached: false,
        }
    }
}

impl Default for DestroyOptions {
    fn default() -> Self {
        Self {
            force: false,
            timeout: DEFAULT_STOP_TIMEOUT,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) async fn get_identified_handle(
    backend: &Arc<dyn Context>,
    name: &str,
    identity: &SandboxIdentity,
) -> MicrosandboxResult<SandboxRecord> {
    let current = backend.sandbox_ops().get(backend.clone(), name).await?;
    ensure_identity(name, identity, &current)?;
    Ok(current)
}

pub(crate) async fn restart_by_stop_and_start(
    backend: Arc<dyn Context>,
    name: &str,
    identity: SandboxIdentity,
    options: RestartOptions,
) -> MicrosandboxResult<Sandbox> {
    let current = loop {
        let current = get_identified_handle(&backend, name, &identity).await?;
        match restart_action(current.status_snapshot()) {
            RestartAction::Start => break current,
            RestartAction::Wait => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            RestartAction::StopThenStart => {
                stop_for_convergence(&current, options.force, options.timeout).await?;
                break current;
            }
            RestartAction::RejectPaused => {
                return Err(MicrosandboxError::SandboxNotRunning(format!(
                    "cannot restart paused sandbox '{}': resume support is not available",
                    current.name
                )));
            }
        }
    };

    if options.detached {
        current.start_detached().await
    } else {
        current.start().await
    }
}

fn ensure_identity(
    name: &str,
    identity: &SandboxIdentity,
    current: &SandboxRecord,
) -> MicrosandboxResult<()> {
    if *identity == current.identity() {
        return Ok(());
    }

    let expected = match identity {
        SandboxIdentity::Local(id) => SandboxId::local(*id),
        SandboxIdentity::Cloud(id) => SandboxId::cloud(id),
    };
    Err(MicrosandboxError::SandboxReplaced {
        name: name.to_string(),
        expected: expected.to_string(),
        actual: current.id().to_string(),
    })
}

fn is_local_ephemeral_handle(inner: &SandboxRecordInner) -> bool {
    let SandboxRecordInner::Local(state) = inner else {
        return false;
    };

    serde_json::from_str::<SandboxConfig>(&state.config_json)
        .map(|config| config.spec.lifecycle.ephemeral)
        .unwrap_or(false)
}

fn sandbox_status_is_terminal(status: SandboxStatus) -> bool {
    matches!(status, SandboxStatus::Stopped | SandboxStatus::Crashed)
}

fn connect_or_start_action(status: SandboxStatus) -> ConnectOrStartAction {
    match status {
        SandboxStatus::Running => ConnectOrStartAction::Connect,
        SandboxStatus::Created | SandboxStatus::Stopped | SandboxStatus::Crashed => {
            ConnectOrStartAction::Start
        }
        SandboxStatus::Starting => ConnectOrStartAction::Wait,
        SandboxStatus::Draining => ConnectOrStartAction::RejectDraining,
        SandboxStatus::Paused => ConnectOrStartAction::RejectPaused,
    }
}

fn restart_action(status: SandboxStatus) -> RestartAction {
    match status {
        SandboxStatus::Created | SandboxStatus::Stopped | SandboxStatus::Crashed => {
            RestartAction::Start
        }
        SandboxStatus::Starting => RestartAction::Wait,
        SandboxStatus::Running | SandboxStatus::Draining => RestartAction::StopThenStart,
        SandboxStatus::Paused => RestartAction::RejectPaused,
    }
}

fn destroy_requires_stop(status: SandboxStatus) -> bool {
    !matches!(
        status,
        SandboxStatus::Created | SandboxStatus::Stopped | SandboxStatus::Crashed
    )
}

async fn stop_for_convergence(
    handle: &SandboxRecord,
    force: bool,
    timeout: Duration,
) -> MicrosandboxResult<()> {
    if force {
        handle.kill_with_timeout(timeout).await
    } else {
        handle.stop_with_timeout(timeout).await
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl std::fmt::Debug for SandboxRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxRecord")
            .field("name", &self.name)
            .field("backend_kind", &self.backend.kind())
            .field("status", &self.status_snapshot())
            .finish()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, feature = "local"))]
mod storage_tests {
    use std::time::Duration;

    use sea_orm::{EntityTrait, Set};

    use super::*;

    #[tokio::test]
    async fn storage_observation_waits_for_transition_and_rejects_a_replaced_name() {
        let home = tempfile::tempdir().unwrap();
        let local = Arc::new(
            crate::test_support::local_backend_builder(home.path())
                .build()
                .unwrap(),
        );
        let backend: Arc<dyn Context> = local.clone();
        let db = local.db().await.unwrap();
        let original = sandbox_entity::Entity::insert(sandbox_entity::ActiveModel {
            name: Set("storage-owner".into()),
            config: Set("{}".into()),
            status: Set(SandboxStatus::Stopped),
            ephemeral: Set(false),
            ..Default::default()
        })
        .exec(db.write())
        .await
        .unwrap()
        .last_insert_id;
        let model = sandbox_entity::Entity::find_by_id(original)
            .one(db.read())
            .await
            .unwrap()
            .unwrap();
        let stale = SandboxRecord::from_local_model(backend.clone(), model, None);
        let directory = local.sandboxes_dir().join("storage-owner");
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("disk"), [7; 11]).unwrap();

        // Simulate a cooperative replacement that already owns the name transition.
        let transition = crate::LocalContext::acquire_sandbox_transition_guard(
            &local.config().run_dir(),
            "storage-owner",
        )
        .await
        .unwrap();
        let mut observation = Box::pin(stale.storage_usage());
        assert!(
            tokio::time::timeout(Duration::from_millis(50), observation.as_mut())
                .await
                .is_err(),
            "storage inspection crossed an active namespace transition"
        );
        sandbox_entity::Entity::delete_by_id(original)
            .exec(db.write())
            .await
            .unwrap();
        sandbox_entity::Entity::insert(sandbox_entity::ActiveModel {
            id: Set(original + 1),
            name: Set("storage-owner".into()),
            config: Set("{}".into()),
            status: Set(SandboxStatus::Stopped),
            ephemeral: Set(false),
            ..Default::default()
        })
        .exec(db.write())
        .await
        .unwrap();
        std::fs::write(directory.join("disk"), [9; 23]).unwrap();
        drop(transition);

        let result = tokio::time::timeout(Duration::from_secs(2), observation)
            .await
            .unwrap();
        assert!(matches!(
            result,
            Err(MicrosandboxError::SandboxReplaced { .. })
        ));
        let current = backend
            .sandbox_ops()
            .get(backend.clone(), "storage-owner")
            .await
            .unwrap();
        let usage = tokio::time::timeout(Duration::from_secs(2), current.storage_usage())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(usage.logical_bytes, Some(23));
    }
}

#[cfg(all(test, feature = "cloud"))]
mod tests {
    use super::*;
    use crate::context::{CloudSandboxStatus, ContextKind};

    #[tokio::test]
    async fn cloud_connect_rebuilds_live_sandbox_without_http_request() {
        let handle = cloud_handle(CloudSandboxStatus::Running);

        let sandbox = handle.connect().await.unwrap();

        assert_eq!(sandbox.name(), "cloud-connect-test");
        assert_eq!(sandbox.context_kind(), ContextKind::Remote);
        assert_eq!(sandbox.remote_state().unwrap().id, "sandbox-id");
        assert_eq!(
            sandbox.prepared_runtime().unwrap().config.spec.name,
            "cloud-connect-test"
        );
    }

    #[tokio::test]
    async fn cloud_connect_rejects_stopped_sandbox() {
        let handle = cloud_handle(CloudSandboxStatus::Stopped);

        let result = handle.connect().await;

        assert!(matches!(
            result,
            Err(MicrosandboxError::SandboxNotRunning(_))
        ));
    }

    #[test]
    #[allow(deprecated)]
    fn fork_builders_keep_legacy_branch_aliases() {
        let source = cloud_handle(CloudSandboxStatus::Running);
        let canonical: crate::sandbox::ForkBuilder = source.fork("child");
        let legacy: crate::sandbox::BranchBuilder = source.branch("child");
        assert_eq!(
            serde_json::to_value(canonical.config.inner.config.into_config()).unwrap(),
            serde_json::to_value(legacy.config.inner.config.into_config()).unwrap(),
        );
        let _: crate::sandbox::ForkManyBuilder = source.branch_many(["a", "b"]);
        let _: crate::sandbox::BranchManyBuilder = source.fork_many(["a", "b"]);
    }

    #[test]
    fn sandbox_id_is_stable_and_backend_qualified() {
        let handle = cloud_handle(CloudSandboxStatus::Running);

        assert_eq!(handle.id().as_str(), "cloud:sandbox-id");
        assert_eq!(handle.id().to_string(), "cloud:sandbox-id");
    }

    #[test]
    fn identity_check_rejects_a_reused_name() {
        let stale = cloud_handle_with_id(CloudSandboxStatus::Stopped, "old-id");
        let replacement = cloud_handle_with_id(CloudSandboxStatus::Running, "new-id");

        let error = stale.ensure_same_identity(&replacement).unwrap_err();

        assert!(matches!(
            error,
            MicrosandboxError::SandboxReplaced {
                name,
                expected,
                actual,
            } if name == "cloud-connect-test"
                && expected == "cloud:old-id"
                && actual == "cloud:new-id"
        ));
    }

    #[test]
    fn lifecycle_action_tables_cover_every_status() {
        assert_eq!(
            connect_or_start_action(SandboxStatus::Running),
            ConnectOrStartAction::Connect
        );
        for status in [
            SandboxStatus::Created,
            SandboxStatus::Stopped,
            SandboxStatus::Crashed,
        ] {
            assert_eq!(connect_or_start_action(status), ConnectOrStartAction::Start);
            assert_eq!(restart_action(status), RestartAction::Start);
            assert!(!destroy_requires_stop(status));
        }
        assert_eq!(
            connect_or_start_action(SandboxStatus::Starting),
            ConnectOrStartAction::Wait
        );
        assert_eq!(restart_action(SandboxStatus::Starting), RestartAction::Wait);
        assert!(destroy_requires_stop(SandboxStatus::Starting));
        assert_eq!(
            connect_or_start_action(SandboxStatus::Draining),
            ConnectOrStartAction::RejectDraining
        );
        assert_eq!(
            restart_action(SandboxStatus::Draining),
            RestartAction::StopThenStart
        );
        assert!(destroy_requires_stop(SandboxStatus::Draining));
        assert_eq!(
            connect_or_start_action(SandboxStatus::Paused),
            ConnectOrStartAction::RejectPaused
        );
        assert_eq!(
            restart_action(SandboxStatus::Paused),
            RestartAction::RejectPaused
        );
        assert!(destroy_requires_stop(SandboxStatus::Paused));
        assert_eq!(
            restart_action(SandboxStatus::Running),
            RestartAction::StopThenStart
        );
        assert!(destroy_requires_stop(SandboxStatus::Running));
    }

    fn cloud_handle(status: CloudSandboxStatus) -> SandboxRecord {
        cloud_handle_with_id(status, "sandbox-id")
    }

    fn cloud_handle_with_id(status: CloudSandboxStatus, id: &str) -> SandboxRecord {
        let backend: Arc<dyn Context> = Arc::new(
            crate::test_support::cloud_backend("https://unused.invalid", "msb_test_connect")
                .unwrap(),
        );
        SandboxRecord::from_cloud(
            backend,
            CloudCreateSandboxResponse {
                id: id.into(),
                org_id: "org-id".into(),
                name: "cloud-connect-test".into(),
                slug: "cloud-connect-test".into(),
                status,
                status_reason: None,
                spec: None,
                ephemeral: false,
                created_at: chrono::Utc::now(),
                started_at: None,
                stopped_at: None,
                last_failure_message: None,
            },
        )
        .unwrap()
    }
}

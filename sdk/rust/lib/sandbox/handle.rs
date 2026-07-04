//! Lightweight sandbox handle for metadata and signal-based lifecycle management.
//!
//! Per the SDK local-cloud parity plan (D6.4) `SandboxHandle` stays a single
//! type regardless of backend. It carries an `Arc<dyn Backend>` plus a
//! backend-private [`SandboxHandleInner`](crate::backend::SandboxHandleInner)
//! enum. Users reach variant-specific data via [`SandboxHandle::local`] /
//! [`SandboxHandle::cloud`].

use std::sync::Arc;

use sea_orm::EntityTrait;

use crate::{
    MicrosandboxResult,
    backend::{
        Backend, CloudSandbox, SandboxHandleCloudState, SandboxHandleInner, SandboxHandleLocalState,
    },
    db::entity::sandbox as sandbox_entity,
};

use super::{Sandbox, SandboxConfig, SandboxModificationBuilder, SandboxStatus, SandboxStopResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Default timeout for [`SandboxHandle::connect`].
pub const DEFAULT_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Default timeout for [`SandboxHandle::stop`] before escalation.
pub const DEFAULT_STOP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Default timeout for observing stopped state after force termination.
pub const DEFAULT_KILL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A lightweight handle to a sandbox.
///
/// Provides metadata access and signal-based lifecycle management (stop, kill,
/// remove) without requiring a live agent bridge. Obtained via
/// [`Sandbox::get`] or [`Sandbox::list`].
///
/// For full runtime capabilities (exec, shell, fs), call [`start`](SandboxHandle::start)
/// to boot the sandbox and obtain a live [`Sandbox`] handle.
pub struct SandboxHandle {
    backend: Arc<dyn Backend>,
    inner: SandboxHandleInner,
    name: String,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SandboxHandle {
    /// Build a handle from a local sandbox DB row + active PID.
    pub(crate) fn from_local_model(
        backend: Arc<dyn Backend>,
        model: sandbox_entity::Model,
        pid: Option<i32>,
    ) -> Self {
        let name = model.name.clone();
        Self {
            backend,
            inner: SandboxHandleInner::Local(SandboxHandleLocalState {
                db_id: model.id,
                status: model.status,
                config_json: model.config,
                active_config_json: model.active_config,
                created_at: model.created_at.map(|dt| dt.and_utc()),
                updated_at: model.updated_at.map(|dt| dt.and_utc()),
                pid,
            }),
            name,
        }
    }

    /// Build a handle from a [`CloudSandbox`] HTTP response.
    ///
    /// Returns an error if `cloud.config` cannot be re-serialised to JSON for
    /// the `config_json()` view. Silent fallback to an empty string here would
    /// surface later as a confusing `serde_json::Error` ("EOF while parsing")
    /// out of [`config()`](Self::config) / [`config_json()`](Self::config_json).
    pub(crate) fn from_cloud(
        backend: Arc<dyn Backend>,
        cloud: CloudSandbox,
    ) -> MicrosandboxResult<Self> {
        let status = crate::backend::sandbox::cloud_status_to_sandbox_status(cloud.status);
        let config_json = serde_json::to_string(&cloud.config)?;
        let name = cloud.name.clone();
        Ok(Self {
            backend,
            inner: SandboxHandleInner::Cloud(SandboxHandleCloudState {
                id: cloud.id,
                org_id: cloud.org_id,
                status,
                config_json,
                created_at: Some(cloud.created_at),
                started_at: cloud.started_at,
                stopped_at: cloud.stopped_at,
                last_error: cloud.last_error,
            }),
            name,
        })
    }

    /// Unique name identifying this sandbox.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Which backend variant this handle is bound to.
    pub fn backend_kind(&self) -> crate::backend::BackendKind {
        self.backend.kind()
    }

    /// Local-only handle state. Returns `Some` for local-backed handles.
    pub fn local(&self) -> Option<&SandboxHandleLocalState> {
        match &self.inner {
            SandboxHandleInner::Local(s) => Some(s),
            SandboxHandleInner::Cloud(_) => None,
        }
    }

    /// Cloud-only handle state. Returns `Some` for cloud-backed handles.
    pub fn cloud(&self) -> Option<&SandboxHandleCloudState> {
        match &self.inner {
            SandboxHandleInner::Cloud(s) => Some(s),
            SandboxHandleInner::Local(_) => None,
        }
    }

    /// Snapshot of sandbox status captured when this handle was created.
    ///
    /// **Not live** — call [`Sandbox::status`](super::Sandbox::status) on the
    /// live `Sandbox` (or re-fetch via [`Sandbox::get`](super::Sandbox::get))
    /// for a fresh reading. The `_snapshot` suffix is deliberate to avoid
    /// confusion with `Sandbox::status()` which is async + fetch-live.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let handle = Sandbox::get("agent-1").await?;
    /// // Cheap, in-memory; reflects state at handle-creation time.
    /// let snap = handle.status_snapshot();
    ///
    /// // For a fresh reading, drive through the live Sandbox:
    /// let sb = handle.start().await?;
    /// let live = sb.status().await?;
    /// ```
    pub fn status_snapshot(&self) -> SandboxStatus {
        match &self.inner {
            SandboxHandleInner::Local(s) => s.status,
            SandboxHandleInner::Cloud(s) => s.status,
        }
    }

    /// Snapshot of the cloud `last_error`, if any. Returns `None` for local
    /// handles (local error reporting flows through the typed error stack).
    pub fn last_error_snapshot(&self) -> Option<String> {
        match &self.inner {
            SandboxHandleInner::Cloud(s) => s.last_error.clone(),
            SandboxHandleInner::Local(_) => None,
        }
    }

    /// The serialized sandbox configuration as stored in the database (local)
    /// or returned by msb-cloud (cloud). Use [`config()`](Self::config) for a
    /// deserialized [`SandboxConfig`].
    pub fn config_json(&self) -> &str {
        match &self.inner {
            SandboxHandleInner::Local(s) => &s.config_json,
            SandboxHandleInner::Cloud(s) => &s.config_json,
        }
    }

    /// The serialized configuration used by the active VM, when known.
    ///
    /// Local handles return `Some` only while a sandbox has started under a
    /// runtime that records active config snapshots. Stopped sandboxes and
    /// older running sandboxes may return `None`.
    pub fn active_config_json(&self) -> Option<&str> {
        match &self.inner {
            SandboxHandleInner::Local(s) => s.active_config_json.as_deref(),
            SandboxHandleInner::Cloud(_) => None,
        }
    }

    /// Parse the stored configuration. Returns an error if the JSON
    /// is malformed (e.g., schema changed since the sandbox was created).
    ///
    /// For local handles this deserializes the persisted [`SandboxConfig`].
    /// For cloud handles this returns an `Unsupported` error: the cloud wire
    /// shape is [`CloudCreateSandboxRequest`](crate::backend::CloudCreateSandboxRequest),
    /// not `SandboxConfig`. Use [`config_json`](Self::config_json) to read the
    /// raw JSON, or [`cloud`](Self::cloud) to access the typed cloud state.
    pub fn config(&self) -> MicrosandboxResult<SandboxConfig> {
        match &self.inner {
            SandboxHandleInner::Local(s) => Ok(serde_json::from_str(&s.config_json)?),
            SandboxHandleInner::Cloud(_) => Err(crate::MicrosandboxError::Unsupported {
                feature: "SandboxHandle::config on cloud".into(),
                available_when: "when SandboxConfig is the cloud wire shape".into(),
            }),
        }
    }

    /// Parse the active configuration snapshot, when one is available.
    pub fn active_config(&self) -> MicrosandboxResult<Option<SandboxConfig>> {
        self.active_config_json()
            .map(serde_json::from_str)
            .transpose()
            .map_err(Into::into)
    }

    /// Start planning a sandbox modification from this handle.
    ///
    /// The builder fetches a fresh handle during [`dry_run`](SandboxModificationBuilder::dry_run)
    /// so planning uses current status and persisted config rather than this
    /// handle's possibly stale snapshot.
    pub fn modify(&self) -> SandboxModificationBuilder {
        SandboxModificationBuilder::new(self.backend.clone(), self.name.clone())
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
        Err(crate::MicrosandboxError::SandboxNotRunning(format!(
            "'{}' is not running (status: {status:?}); cannot {operation}",
            self.name
        )))
    }

    /// Return a fresh handle for the same sandbox name.
    pub async fn refresh(&self) -> MicrosandboxResult<SandboxHandle> {
        self.backend
            .sandboxes()
            .get(self.backend.clone(), &self.name)
            .await
    }

    /// When this sandbox was first created, if recorded.
    pub fn created_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        match &self.inner {
            SandboxHandleInner::Local(s) => s.created_at,
            SandboxHandleInner::Cloud(s) => s.created_at,
        }
    }

    /// Best-effort "last activity" timestamp.
    ///
    /// - Local: the database row's `updated_at` (modification time of the
    ///   persisted record).
    /// - Cloud: the most recent of `stopped_at` / `started_at` / `created_at`
    ///   from the msb-cloud response. msb-cloud has no dedicated
    ///   `updated_at` column, so this is synthesised on the client.
    pub fn updated_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        match &self.inner {
            SandboxHandleInner::Local(s) => s.updated_at,
            SandboxHandleInner::Cloud(s) => s.stopped_at.or(s.started_at).or(s.created_at),
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
            .sandboxes()
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
    ) -> MicrosandboxResult<crate::backend::sandbox::LogStream> {
        self.backend
            .sandboxes()
            .log_stream(self.backend.clone(), &self.name, opts)
            .await
    }

    /// Get the latest metrics snapshot for this sandbox. **Local handles only**.
    pub async fn metrics(&self) -> MicrosandboxResult<super::SandboxMetrics> {
        let local = self
            .local()
            .ok_or_else(|| crate::MicrosandboxError::Unsupported {
                feature: "SandboxHandle::metrics on cloud".into(),
                available_when: "when cloud metrics land".into(),
            })?;

        if local.status != SandboxStatus::Running && local.status != SandboxStatus::Draining {
            return Err(crate::MicrosandboxError::SandboxNotRunning(format!(
                "'{}' is not running (status: {:?})",
                self.name, local.status
            )));
        }

        let config = self.config()?;
        if config.effective_metrics_interval().is_none() {
            return Err(crate::MicrosandboxError::MetricsDisabled(self.name.clone()));
        }

        let local_backend =
            self.backend
                .as_local()
                .ok_or_else(|| crate::MicrosandboxError::Unsupported {
                    feature: "SandboxHandle::metrics on cloud".into(),
                    available_when: "when cloud metrics land".into(),
                })?;
        let db = local_backend.db().await?.read();
        super::metrics::metrics_for_sandbox(db, local_backend, local.db_id, &config).await
    }

    /// Start this sandbox and return a live handle.
    ///
    /// Boots the VM using the persisted configuration and pinned rootfs state
    /// for local; routes through `POST /v1/sandboxes/by-name/:name/start` for
    /// cloud. The handle remains usable if start fails.
    pub async fn start(&self) -> MicrosandboxResult<Sandbox> {
        self.backend
            .sandboxes()
            .start(self.backend.clone(), &self.name)
            .await
    }

    /// Start this sandbox in detached/background mode.
    ///
    /// The handle remains usable if start fails.
    pub async fn start_detached(&self) -> MicrosandboxResult<Sandbox> {
        self.backend
            .sandboxes()
            .start_detached(self.backend.clone(), &self.name)
            .await
    }

    /// Connect to a running sandbox via the agent relay socket. **Local
    /// handles only** — cloud sandbox attach is HTTP/WS and not wired up in
    /// this delegation.
    pub async fn connect(&self) -> MicrosandboxResult<Sandbox> {
        self.connect_with_timeout(DEFAULT_CONNECT_TIMEOUT).await
    }

    /// Connect to a running sandbox with an explicit agent handshake timeout.
    pub async fn connect_with_timeout(
        &self,
        timeout: std::time::Duration,
    ) -> MicrosandboxResult<Sandbox> {
        let local = self
            .local()
            .ok_or_else(|| crate::MicrosandboxError::Unsupported {
                feature: "SandboxHandle::connect on cloud".into(),
                available_when: "when cloud attach lands".into(),
            })?;
        if local.status != SandboxStatus::Running && local.status != SandboxStatus::Draining {
            return Err(crate::MicrosandboxError::SandboxNotRunning(format!(
                "'{}' is not running (status: {:?})",
                self.name, local.status
            )));
        }

        let local_backend =
            self.backend
                .as_local()
                .ok_or_else(|| crate::MicrosandboxError::Unsupported {
                    feature: "SandboxHandle::connect on cloud".into(),
                    available_when: "when cloud attach lands".into(),
                })?;
        let client = crate::sandbox::fs::local::connect_agent_with_timeout(
            local_backend,
            &self.name,
            timeout,
        )
        .await?;
        let config: SandboxConfig = serde_json::from_str(&local.config_json)?;

        Ok(Sandbox::from_local(
            self.backend.clone(),
            crate::backend::SandboxLocalState {
                db_id: local.db_id,
                handle: None,
                client: Arc::new(client),
            },
            config,
        ))
    }

    /// Check whether agentd is reachable without refreshing the sandbox idle timer.
    ///
    /// Connects to the running sandbox and sends `core.ping`. Stopped sandboxes
    /// are not started implicitly; call [`start`](Self::start) first when that
    /// is the desired behavior.
    pub async fn ping(&self) -> MicrosandboxResult<super::SandboxPingResult> {
        self.require_running("ping")?;
        self.connect().await?.ping().await
    }

    /// Explicitly refresh the sandbox idle timer.
    ///
    /// Connects to the running sandbox and sends `core.touch`. Stopped sandboxes
    /// are not started implicitly; call [`start`](Self::start) first when that
    /// is the desired behavior.
    pub async fn touch(&self) -> MicrosandboxResult<super::SandboxTouchResult> {
        self.require_running("touch")?;
        self.connect().await?.touch().await
    }

    /// Snapshot this sandbox to a bare name under the default snapshots
    /// directory (`~/.microsandbox/snapshots/<name>/`).
    ///
    /// The sandbox must be stopped (or crashed); running sandboxes are
    /// rejected with `MicrosandboxError::SnapshotSandboxRunning`. **Local
    /// handles only** — cloud snapshot semantics are deferred.
    pub async fn snapshot(
        &self,
        name: &str,
    ) -> MicrosandboxResult<super::super::snapshot::Snapshot> {
        if self.local().is_none() {
            return Err(crate::MicrosandboxError::Unsupported {
                feature: "SandboxHandle::snapshot on cloud".into(),
                available_when: "when cloud snapshots land".into(),
            });
        }
        use super::super::snapshot::{Snapshot, SnapshotDestination};
        Snapshot::builder(&self.name)
            .destination(SnapshotDestination::Name(name.to_string()))
            .create()
            .await
    }

    /// Snapshot this sandbox to an explicit filesystem path. **Local handles only.**
    pub async fn snapshot_to(
        &self,
        path: impl AsRef<std::path::Path>,
    ) -> MicrosandboxResult<super::super::snapshot::Snapshot> {
        if self.local().is_none() {
            return Err(crate::MicrosandboxError::Unsupported {
                feature: "SandboxHandle::snapshot_to on cloud".into(),
                available_when: "when cloud snapshots land".into(),
            });
        }
        use super::super::snapshot::{Snapshot, SnapshotDestination};
        Snapshot::builder(&self.name)
            .destination(SnapshotDestination::Path(path.as_ref().to_path_buf()))
            .create()
            .await
    }

    /// Stop the sandbox gracefully using the default stop timeout.
    pub async fn stop(&self) -> MicrosandboxResult<()> {
        self.stop_with_timeout(DEFAULT_STOP_TIMEOUT).await
    }

    /// Stop the sandbox gracefully with an explicit timeout before escalation.
    pub async fn stop_with_timeout(&self, timeout: std::time::Duration) -> MicrosandboxResult<()> {
        let current = self.refresh().await?;
        if sandbox_status_is_terminal(current.status_snapshot()) {
            return Ok(());
        }

        if timeout.is_zero() {
            current.kill_with_timeout(DEFAULT_KILL_TIMEOUT).await?;
            return Ok(());
        }

        current.request_stop().await?;
        match tokio::time::timeout(timeout, current.wait_until_stopped()).await {
            Ok(Ok(_)) => return Ok(()),
            Ok(Err(error)) => return Err(error),
            Err(_) => {}
        }

        tracing::warn!(
            sandbox = %current.name,
            timeout_secs = timeout.as_secs(),
            "graceful stop exceeded timeout, escalating to kill"
        );
        current.request_kill().await?;
        match tokio::time::timeout(DEFAULT_KILL_TIMEOUT, current.wait_until_stopped()).await {
            Ok(result) => {
                result?;
                Ok(())
            }
            Err(_) => Err(crate::MicrosandboxError::Runtime(format!(
                "timed out observing stopped state for sandbox '{}'",
                current.name
            ))),
        }
    }

    /// Request graceful shutdown without waiting for observed stopped state.
    pub async fn request_stop(&self) -> MicrosandboxResult<()> {
        let current = self.refresh().await?;
        if sandbox_status_is_terminal(current.status_snapshot()) {
            return Ok(());
        }

        current
            .backend
            .sandboxes()
            .stop(current.backend.clone(), &current.name)
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
            .sandboxes()
            .kill(current.backend.clone(), &current.name)
            .await
    }

    /// Force-kill the sandbox and wait up to `timeout` for stopped-state observation.
    pub async fn kill_with_timeout(&self, timeout: std::time::Duration) -> MicrosandboxResult<()> {
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
            Err(_) => Err(crate::MicrosandboxError::Runtime(format!(
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
            .sandboxes()
            .drain(current.backend.clone(), &current.name)
            .await
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

            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    /// Remove this sandbox.
    ///
    /// The sandbox must be stopped first. Use [`stop`](Self::stop) or
    /// [`kill`](Self::kill) to stop it before removing. Routes through the
    /// backend trait so cloud handles hit `DELETE /v1/sandboxes/by-name/:name`.
    pub async fn remove(&self) -> MicrosandboxResult<()> {
        match &self.inner {
            SandboxHandleInner::Local(_) => {
                let refreshed = self.refresh().await?;
                let local =
                    refreshed
                        .local()
                        .ok_or_else(|| crate::MicrosandboxError::Unsupported {
                            feature: "SandboxHandle::remove on cloud".into(),
                            available_when: "wired via Cloud variant".into(),
                        })?;
                if matches!(
                    local.status,
                    SandboxStatus::Running | SandboxStatus::Draining | SandboxStatus::Paused
                ) {
                    return Err(crate::MicrosandboxError::SandboxStillRunning(format!(
                        "cannot remove sandbox '{}': still running",
                        self.name
                    )));
                }

                let local_backend = self.backend.as_local().ok_or_else(|| {
                    crate::MicrosandboxError::Unsupported {
                        feature: "SandboxHandle::remove on cloud".into(),
                        available_when: "wired via Cloud variant".into(),
                    }
                })?;
                let pools = local_backend.db().await?;

                super::remove_dir_if_exists(&local_backend.sandboxes_dir().join(&self.name))?;
                sandbox_entity::Entity::delete_by_id(local.db_id)
                    .exec(pools.write())
                    .await?;

                Ok(())
            }
            SandboxHandleInner::Cloud(_) => {
                self.backend
                    .sandboxes()
                    .remove(self.backend.clone(), &self.name)
                    .await
            }
        }
    }

    fn is_local_ephemeral(&self) -> bool {
        is_local_ephemeral_handle(&self.inner)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn is_local_ephemeral_handle(inner: &SandboxHandleInner) -> bool {
    let SandboxHandleInner::Local(state) = inner else {
        return false;
    };

    serde_json::from_str::<SandboxConfig>(&state.config_json)
        .map(|config| config.spec.lifecycle.ephemeral)
        .unwrap_or(false)
}

fn sandbox_status_is_terminal(status: SandboxStatus) -> bool {
    matches!(status, SandboxStatus::Stopped | SandboxStatus::Crashed)
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl std::fmt::Debug for SandboxHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxHandle")
            .field("name", &self.name)
            .field("backend_kind", &self.backend.kind())
            .field("status", &self.status_snapshot())
            .finish()
    }
}

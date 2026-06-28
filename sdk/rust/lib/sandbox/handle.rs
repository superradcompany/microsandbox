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

use super::{Sandbox, SandboxConfig, SandboxStatus, SandboxStopResult};

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
    /// Provider bundle captured when this handle was created. Stop/kill/remove
    /// tear down only this generation so a stale handle cannot disturb a later
    /// same-name replace.
    pub(crate) virtual_mount_teardown_bundle:
        Option<Arc<super::virtual_mount::VirtualMountServers>>,
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
                created_at: model.created_at.map(|dt| dt.and_utc()),
                updated_at: model.updated_at.map(|dt| dt.and_utc()),
                pid,
            }),
            name: name.clone(),
            virtual_mount_teardown_bundle: super::virtual_mount::snapshot_servers(&name),
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
            virtual_mount_teardown_bundle: None,
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
    /// After a same-name [`.replace()`](super::SandboxBuilder::replace), call
    /// [`refresh`](Self::refresh) before using lifecycle methods; stale handles
    /// return an error from those methods rather than from this snapshot.
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
    ///
    /// Like [`status_snapshot`](Self::status_snapshot), this reflects handle
    /// creation time — call [`refresh`](Self::refresh) after same-name replace.
    pub fn config_json(&self) -> &str {
        match &self.inner {
            SandboxHandleInner::Local(s) => &s.config_json,
            SandboxHandleInner::Cloud(s) => &s.config_json,
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
        if self.backend.as_local().is_none() {
            return Err(crate::MicrosandboxError::Unsupported {
                feature: "SandboxHandle::logs on cloud".into(),
                available_when: "when cloud logs land".into(),
            });
        }
        let current = self.refresh().await?;
        ensure_local_handle_current(self, &current)?;
        ensure_local_handle_still_current(self).await?;
        crate::logs::read_logs(&self.name, opts).await
    }

    /// Stream log entries for this sandbox.
    ///
    /// Same backing data as [`Sandbox::log_stream`](super::Sandbox::log_stream).
    /// Works without starting the sandbox. **Local handles only**.
    pub async fn log_stream(
        &self,
        opts: &crate::logs::LogStreamOptions,
    ) -> MicrosandboxResult<crate::backend::sandbox::LogStream> {
        if self.backend.as_local().is_none() {
            return Err(crate::MicrosandboxError::Unsupported {
                feature: "SandboxHandle::log_stream on cloud".into(),
                available_when: "when cloud logs land".into(),
            });
        }
        let current = self.refresh().await?;
        ensure_local_handle_current(self, &current)?;
        ensure_local_handle_still_current(self).await?;
        self.backend
            .sandboxes()
            .log_stream(self.backend.clone(), &self.name, opts)
            .await
    }

    /// Get the latest metrics snapshot for this sandbox. **Local handles only**.
    pub async fn metrics(&self) -> MicrosandboxResult<super::SandboxMetrics> {
        let current = self.refresh().await?;
        ensure_local_handle_current(self, &current)?;
        let local = current
            .local()
            .ok_or_else(|| crate::MicrosandboxError::Unsupported {
                feature: "SandboxHandle::metrics on cloud".into(),
                available_when: "when cloud metrics land".into(),
            })?;

        if local.status != SandboxStatus::Running && local.status != SandboxStatus::Draining {
            return Err(crate::MicrosandboxError::Custom(format!(
                "sandbox '{}' is not running (status: {:?})",
                self.name, local.status
            )));
        }

        let config = current.config()?;
        if config.effective_metrics_interval().is_none() {
            return Err(crate::MicrosandboxError::MetricsDisabled(self.name.clone()));
        }

        let local_backend =
            current
                .backend
                .as_local()
                .ok_or_else(|| crate::MicrosandboxError::Unsupported {
                    feature: "SandboxHandle::metrics on cloud".into(),
                    available_when: "when cloud metrics land".into(),
                })?;
        ensure_local_handle_still_current(self).await?;
        let db = local_backend.db().await?.read();
        super::metrics::metrics_for_sandbox(db, local_backend, local.db_id, &config).await
    }

    /// Start this sandbox and return a live handle.
    ///
    /// Boots the VM using the persisted configuration and pinned rootfs state
    /// for local; routes through `POST /v1/sandboxes/by-name/:name/start` for
    /// cloud. The handle remains usable if start fails.
    pub async fn start(&self) -> MicrosandboxResult<Sandbox> {
        let current = self.refresh().await?;
        ensure_local_handle_current(self, &current)?;
        ensure_local_handle_still_current(self).await?;
        self.backend
            .sandboxes()
            .start(self.backend.clone(), &self.name)
            .await
    }

    /// Start this sandbox in detached/background mode.
    ///
    /// The handle remains usable if start fails.
    pub async fn start_detached(&self) -> MicrosandboxResult<Sandbox> {
        let current = self.refresh().await?;
        ensure_local_handle_current(self, &current)?;
        ensure_local_handle_still_current(self).await?;
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
        let current = self.refresh().await?;
        ensure_local_handle_current(self, &current)?;
        let local = current
            .local()
            .ok_or_else(|| crate::MicrosandboxError::Unsupported {
                feature: "SandboxHandle::connect on cloud".into(),
                available_when: "when cloud attach lands".into(),
            })?;
        if local.status != SandboxStatus::Running && local.status != SandboxStatus::Draining {
            return Err(crate::MicrosandboxError::Custom(format!(
                "sandbox '{}' is not running (status: {:?})",
                self.name, local.status
            )));
        }

        let local_backend =
            current
                .backend
                .as_local()
                .ok_or_else(|| crate::MicrosandboxError::Unsupported {
                    feature: "SandboxHandle::connect on cloud".into(),
                    available_when: "when cloud attach lands".into(),
                })?;
        ensure_local_handle_still_current(self).await?;
        let config: SandboxConfig = serde_json::from_str(&local.config_json)?;
        super::check_virtual_mount_connect(&self.name, &config)?;
        let virtual_mount_session = if config.had_virtual_mounts {
            Some(super::virtual_mount::acquire_session(&self.name)?)
        } else {
            None
        };
        ensure_local_handle_still_current(self).await?;
        let client = crate::sandbox::fs::local::connect_agent_with_timeout(
            local_backend,
            &self.name,
            timeout,
        )
        .await?;
        if let Some(session) = virtual_mount_session.as_ref()
            && (!super::virtual_mount::has_live_servers(&self.name)
                || !super::virtual_mount::is_live_session(&self.name, session))
        {
            return Err(crate::MicrosandboxError::InvalidConfig(
                super::virtual_mount::connect_error(&self.name).to_string(),
            ));
        }

        Ok(Sandbox::from_local(
            current.backend.clone(),
            crate::backend::SandboxLocalState {
                db_id: local.db_id,
                handle: None,
                client: Arc::new(client),
            },
            config,
            virtual_mount_session,
            None,
        ))
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
        let current = self.refresh().await?;
        ensure_local_handle_current(self, &current)?;
        use super::super::snapshot::{Snapshot, SnapshotDestination};
        ensure_local_handle_still_current(self).await?;
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
        let current = self.refresh().await?;
        ensure_local_handle_current(self, &current)?;
        use super::super::snapshot::{Snapshot, SnapshotDestination};
        ensure_local_handle_still_current(self).await?;
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
        let virtual_mount_bundle = self.virtual_mount_teardown_bundle.clone();
        let current = self.refresh().await?;
        ensure_local_handle_current(self, &current)?;
        if sandbox_status_is_terminal(current.status_snapshot()) {
            if let Some(bundle) = virtual_mount_bundle {
                super::virtual_mount::teardown_bundle(&self.name, &bundle);
            }
            return Ok(());
        }

        if timeout.is_zero() {
            current.kill_with_timeout(DEFAULT_KILL_TIMEOUT).await?;
            if let Some(bundle) = virtual_mount_bundle {
                super::virtual_mount::teardown_bundle(&self.name, &bundle);
            }
            return Ok(());
        }

        current.request_stop().await?;
        match tokio::time::timeout(timeout, current.wait_until_stopped()).await {
            Ok(Ok(_)) => {
                if let Some(bundle) = virtual_mount_bundle {
                    super::virtual_mount::teardown_bundle(&self.name, &bundle);
                }
                return Ok(());
            }
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
                if let Some(bundle) = virtual_mount_bundle {
                    super::virtual_mount::teardown_bundle(&self.name, &bundle);
                }
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
        let virtual_mount_bundle = self.virtual_mount_teardown_bundle.clone();
        let current = self.refresh().await?;
        ensure_local_handle_current(self, &current)?;
        if sandbox_status_is_terminal(current.status_snapshot()) {
            if let Some(bundle) = virtual_mount_bundle {
                super::virtual_mount::teardown_bundle(&self.name, &bundle);
            }
            return Ok(());
        }

        ensure_local_handle_still_current(self).await?;
        current
            .backend
            .sandboxes()
            .stop(current.backend.clone(), &current.name)
            .await?;
        if let Some(bundle) = virtual_mount_bundle {
            bundle.schedule_teardown_when_stopped(self.name.clone(), Arc::clone(&current.backend));
        }
        Ok(())
    }

    /// Kill the sandbox immediately and wait until it is observed stopped.
    pub async fn kill(&self) -> MicrosandboxResult<()> {
        self.kill_with_timeout(DEFAULT_KILL_TIMEOUT).await
    }

    /// Request force termination without waiting for observed stopped state.
    pub async fn request_kill(&self) -> MicrosandboxResult<()> {
        let virtual_mount_bundle = self.virtual_mount_teardown_bundle.clone();
        let current = self.refresh().await?;
        ensure_local_handle_current(self, &current)?;
        if sandbox_status_is_terminal(current.status_snapshot()) {
            if let Some(bundle) = virtual_mount_bundle {
                super::virtual_mount::teardown_bundle(&self.name, &bundle);
            }
            return Ok(());
        }

        ensure_local_handle_still_current(self).await?;
        current
            .backend
            .sandboxes()
            .kill(current.backend.clone(), &current.name)
            .await?;
        if let Some(bundle) = virtual_mount_bundle {
            bundle.schedule_teardown_when_stopped(self.name.clone(), Arc::clone(&current.backend));
        }
        Ok(())
    }

    /// Force-kill the sandbox and wait up to `timeout` for stopped-state observation.
    pub async fn kill_with_timeout(&self, timeout: std::time::Duration) -> MicrosandboxResult<()> {
        let virtual_mount_bundle = self.virtual_mount_teardown_bundle.clone();
        let current = self.refresh().await?;
        ensure_local_handle_current(self, &current)?;
        if sandbox_status_is_terminal(current.status_snapshot()) {
            if let Some(bundle) = virtual_mount_bundle {
                super::virtual_mount::teardown_bundle(&self.name, &bundle);
            }
            return Ok(());
        }

        current.request_kill().await?;
        match tokio::time::timeout(timeout, current.wait_until_stopped()).await {
            Ok(result) => {
                result?;
                if let Some(bundle) = virtual_mount_bundle {
                    super::virtual_mount::teardown_bundle(&self.name, &bundle);
                }
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
        let virtual_mount_bundle = self.virtual_mount_teardown_bundle.clone();
        let current = self.refresh().await?;
        ensure_local_handle_current(self, &current)?;
        if sandbox_status_is_terminal(current.status_snapshot()) {
            if let Some(bundle) = virtual_mount_bundle {
                super::virtual_mount::teardown_bundle(&self.name, &bundle);
            }
            return Ok(());
        }

        ensure_local_handle_still_current(self).await?;
        current
            .backend
            .sandboxes()
            .drain(current.backend.clone(), &current.name)
            .await?;
        if let Some(bundle) = virtual_mount_bundle {
            bundle.schedule_teardown_when_stopped(self.name.clone(), Arc::clone(&current.backend));
        }
        Ok(())
    }

    /// Wait until this sandbox is observed in a terminal non-running state.
    pub async fn wait_until_stopped(&self) -> MicrosandboxResult<SandboxStopResult> {
        let mut current = self.refresh().await?;
        ensure_local_handle_current(self, &current)?;
        loop {
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
            current = current.refresh().await?;
            ensure_local_handle_current(self, &current)?;
        }
    }

    /// Remove this sandbox.
    ///
    /// The sandbox must be stopped first. Use [`stop`](Self::stop) or
    /// [`kill`](Self::kill) to stop it before removing. Routes through the
    /// backend trait so cloud handles hit `DELETE /v1/sandboxes/by-name/:name`.
    pub async fn remove(&self) -> MicrosandboxResult<()> {
        let virtual_mount_bundle = self.virtual_mount_teardown_bundle.clone();
        let current = self.refresh().await?;
        ensure_local_handle_current(self, &current)?;
        match &current.inner {
            SandboxHandleInner::Local(local) => {
                if local.status == SandboxStatus::Running || local.status == SandboxStatus::Draining
                {
                    return Err(crate::MicrosandboxError::SandboxStillRunning(format!(
                        "cannot remove sandbox '{}': still running",
                        self.name
                    )));
                }

                let local_backend = current.backend.as_local().ok_or_else(|| {
                    crate::MicrosandboxError::Unsupported {
                        feature: "SandboxHandle::remove on cloud".into(),
                        available_when: "wired via Cloud variant".into(),
                    }
                })?;
                let pools = local_backend.db().await?;

                ensure_local_handle_still_current(self).await?;
                super::remove_dir_if_exists(&local_backend.sandboxes_dir().join(&self.name))?;
                sandbox_entity::Entity::delete_by_id(local.db_id)
                    .exec(pools.write())
                    .await?;
                let teardown_bundle = virtual_mount_bundle
                    .or_else(|| super::virtual_mount::snapshot_servers(&self.name));
                if let Some(bundle) = teardown_bundle {
                    super::virtual_mount::teardown_bundle(&self.name, &bundle);
                }
                super::virtual_mount::clear_live_slot(&self.name);

                Ok(())
            }
            SandboxHandleInner::Cloud(_) => {
                ensure_local_handle_still_current(self).await?;
                current
                    .backend
                    .sandboxes()
                    .remove(current.backend.clone(), &self.name)
                    .await
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn sandbox_status_is_terminal(status: SandboxStatus) -> bool {
    matches!(status, SandboxStatus::Stopped | SandboxStatus::Crashed)
}

pub(crate) fn stale_sandbox_handle_error(name: &str) -> crate::MicrosandboxError {
    crate::MicrosandboxError::SandboxHandleStale(format!(
        "sandbox '{name}' was replaced or removed since this handle was created; \
         refresh the handle with Sandbox::get or SandboxHandle::refresh before \
         connect, start, stop, or remove"
    ))
}

pub(crate) async fn ensure_local_handle_still_current(
    handle: &SandboxHandle,
) -> MicrosandboxResult<()> {
    let current = handle.refresh().await?;
    ensure_local_handle_current(handle, &current)
}

pub(crate) fn ensure_local_handle_current(
    handle: &SandboxHandle,
    current: &SandboxHandle,
) -> MicrosandboxResult<()> {
    let Some(handle_local) = handle.local() else {
        return Ok(());
    };
    let Some(current_local) = current.local() else {
        return Ok(());
    };
    if handle_local.db_id != current_local.db_id {
        return Err(stale_sandbox_handle_error(&handle.name));
    }
    // When db_id is unavailable (0), fall back to updated_at so a same-name
    // replace is still detected. Also compare captured virtual mount bundle pointers
    // when this handle registered virtual-mount providers.
    if handle_local.db_id == 0
        && let (Some(handle_updated), Some(current_updated)) =
            (handle.updated_at(), current.updated_at())
        && handle_updated != current_updated
    {
        return Err(stale_sandbox_handle_error(&handle.name));
    }
    if let Some(handle_bundle) = handle.virtual_mount_teardown_bundle.as_ref()
        && !current
            .virtual_mount_teardown_bundle
            .as_ref()
            .is_some_and(|current_bundle| Arc::ptr_eq(handle_bundle, current_bundle))
    {
        return Err(stale_sandbox_handle_error(&handle.name));
    }
    Ok(())
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

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MicrosandboxError;
    use crate::db::entity::sandbox as sandbox_entity;

    fn model(id: i32) -> sandbox_entity::Model {
        sandbox_entity::Model {
            id,
            name: "demo".into(),
            config: "{}".into(),
            status: sandbox_entity::SandboxStatus::Stopped,
            ephemeral: false,
            created_at: None,
            updated_at: None,
        }
    }

    #[tokio::test]
    async fn ensure_local_handle_current_rejects_replaced_sandbox() {
        let temp = tempfile::tempdir().unwrap();
        let backend: Arc<dyn crate::backend::Backend> = Arc::new(
            crate::backend::LocalBackend::builder()
                .home(temp.path())
                .build()
                .await
                .unwrap(),
        );
        let first = SandboxHandle::from_local_model(Arc::clone(&backend), model(1), None);
        let second = SandboxHandle::from_local_model(backend, model(2), None);
        let err = ensure_local_handle_current(&first, &second).unwrap_err();
        assert!(matches!(err, MicrosandboxError::SandboxHandleStale(_)));
        ensure_local_handle_current(&first, &first).unwrap();
    }

    #[tokio::test]
    async fn ensure_local_handle_current_rejects_stale_updated_at_when_db_id_zero() {
        let temp = tempfile::tempdir().unwrap();
        let backend: Arc<dyn crate::backend::Backend> = Arc::new(
            crate::backend::LocalBackend::builder()
                .home(temp.path())
                .build()
                .await
                .unwrap(),
        );
        let mut first_model = model(0);
        first_model.updated_at = Some(chrono::Utc::now().naive_utc());
        let mut second_model = model(0);
        second_model.updated_at =
            Some((chrono::Utc::now() + chrono::Duration::seconds(5)).naive_utc());
        let first = SandboxHandle::from_local_model(Arc::clone(&backend), first_model, None);
        let second = SandboxHandle::from_local_model(backend, second_model, None);
        let err = ensure_local_handle_current(&first, &second).unwrap_err();
        assert!(matches!(err, MicrosandboxError::SandboxHandleStale(_)));
    }

    #[tokio::test]
    async fn ensure_local_handle_current_rejects_stale_virtual_mount_bundle() {
        use super::super::virtual_mount::VirtualMountServers;

        let temp = tempfile::tempdir().unwrap();
        let backend: Arc<dyn crate::backend::Backend> = Arc::new(
            crate::backend::LocalBackend::builder()
                .home(temp.path())
                .build()
                .await
                .unwrap(),
        );
        let mut first = SandboxHandle::from_local_model(Arc::clone(&backend), model(1), None);
        let mut second = SandboxHandle::from_local_model(Arc::clone(&backend), model(1), None);
        first.virtual_mount_teardown_bundle = Some(Arc::new(VirtualMountServers::new()));
        second.virtual_mount_teardown_bundle = Some(Arc::new(VirtualMountServers::new()));
        let err = ensure_local_handle_current(&first, &second).unwrap_err();
        assert!(matches!(err, MicrosandboxError::SandboxHandleStale(_)));
    }
}

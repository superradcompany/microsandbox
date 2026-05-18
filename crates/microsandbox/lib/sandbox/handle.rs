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
    agent::AgentClient,
    backend::{
        Backend, CloudSandbox, SandboxHandleCloudState, SandboxHandleInner, SandboxHandleLocalState,
    },
    db::entity::sandbox as sandbox_entity,
};

use super::{Sandbox, SandboxConfig, SandboxStatus};

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
                created_at: model.created_at.map(|dt| dt.and_utc()),
                updated_at: model.updated_at.map(|dt| dt.and_utc()),
                pid,
            }),
            name,
        }
    }

    /// Build a handle from a [`CloudSandbox`] HTTP response.
    pub(crate) fn from_cloud(backend: Arc<dyn Backend>, cloud: CloudSandbox) -> Self {
        let status = crate::backend::sandbox::cloud_status_to_sandbox_status(cloud.status);
        let config_json = serde_json::to_string(&cloud.config).unwrap_or_default();
        let name = cloud.name.clone();
        Self {
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
        }
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
    /// for a fresh reading.
    pub fn status_snapshot(&self) -> SandboxStatus {
        match &self.inner {
            SandboxHandleInner::Local(s) => s.status,
            SandboxHandleInner::Cloud(s) => s.status,
        }
    }

    /// Snapshot of the sandbox status (alias for [`status_snapshot`](Self::status_snapshot)).
    pub fn status(&self) -> SandboxStatus {
        self.status_snapshot()
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

    /// When this sandbox was first created, if recorded.
    pub fn created_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        match &self.inner {
            SandboxHandleInner::Local(s) => s.created_at,
            SandboxHandleInner::Cloud(s) => s.created_at,
        }
    }

    /// When this sandbox's database record was last modified. Local handles
    /// only — cloud handles surface `started_at` / `stopped_at` instead via
    /// [`cloud`](Self::cloud).
    pub fn updated_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        match &self.inner {
            SandboxHandleInner::Local(s) => s.updated_at,
            SandboxHandleInner::Cloud(_) => None,
        }
    }

    /// Read captured output from `exec.log` for this sandbox.
    ///
    /// Same backing data as [`Sandbox::logs`](super::Sandbox::logs).
    /// Works without starting the sandbox. **Local handles only**.
    pub fn logs(&self, opts: &super::LogOptions) -> MicrosandboxResult<Vec<super::LogEntry>> {
        if self.local().is_none() {
            return Err(crate::MicrosandboxError::Unsupported {
                feature: "SandboxHandle::logs on cloud".into(),
                available_when: "when cloud logs land".into(),
            });
        }
        super::logs::read_logs(&self.name, opts)
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
            return Err(crate::MicrosandboxError::Custom(format!(
                "sandbox '{}' is not running (status: {:?})",
                self.name, local.status
            )));
        }

        let config = self.config()?;
        if config.effective_metrics_interval().is_none() {
            return Err(crate::MicrosandboxError::MetricsDisabled(self.name.clone()));
        }

        let db = crate::db::init_global().await?.read();
        super::metrics::metrics_for_sandbox(
            db,
            local.db_id,
            u64::from(config.memory_mib) * 1024 * 1024,
        )
        .await
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
        let local = self
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

        let global = crate::config::config();
        let sock_path = global
            .sandboxes_dir()
            .join(&self.name)
            .join("runtime")
            .join("agent.sock");

        // Bound the handshake reads. The relay is supposed to be running
        // already for a sandbox in Running/Draining state; if it doesn't
        // respond within 10s, something is wedged and the caller should
        // see a timeout instead of hanging forever.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        let client = AgentClient::connect(&sock_path, deadline).await?;
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

    /// Stop the sandbox gracefully.
    ///
    /// For local handles this sends SIGTERM to the libkrun process (no-op
    /// when the sandbox isn't running). For cloud handles this issues
    /// `POST /v1/sandboxes/by-name/:name/stop`.
    pub async fn stop(&self) -> MicrosandboxResult<()> {
        match &self.inner {
            SandboxHandleInner::Local(local) => {
                if local.status != SandboxStatus::Running && local.status != SandboxStatus::Draining
                {
                    return Ok(());
                }
                signal_pid(local.pid, nix::sys::signal::Signal::SIGTERM)?;
                Ok(())
            }
            SandboxHandleInner::Cloud(_) => self.backend.sandboxes().stop(&self.name).await,
        }
    }

    /// Kill the sandbox immediately.
    ///
    /// Local handles signal SIGKILL to the libkrun PID and wait briefly,
    /// then mark the sandbox stopped. Cloud handles currently return
    /// `Unsupported`.
    pub async fn kill(&mut self) -> MicrosandboxResult<()> {
        match &mut self.inner {
            SandboxHandleInner::Local(local) => {
                if local.status != SandboxStatus::Running && local.status != SandboxStatus::Draining
                {
                    return Ok(());
                }

                let pids = signal_pid(local.pid, nix::sys::signal::Signal::SIGKILL)?;

                if !pids.is_empty() {
                    wait_for_exit(&pids, std::time::Duration::from_secs(5)).await;
                }

                // Mark stopped if all processes are confirmed dead (or were already gone).
                let all_dead = pids.is_empty() || pids.iter().all(|pid| !super::pid_is_alive(*pid));

                if all_dead {
                    let db = crate::db::init_global().await?.write();
                    if let Err(e) =
                        super::update_sandbox_status(db, local.db_id, SandboxStatus::Stopped).await
                    {
                        tracing::warn!(sandbox = %self.name, error = %e, "failed to update sandbox status after kill");
                    }
                    local.status = SandboxStatus::Stopped;
                }

                Ok(())
            }
            SandboxHandleInner::Cloud(_) => self.backend.sandboxes().kill(&self.name).await,
        }
    }

    /// Remove this sandbox.
    ///
    /// The sandbox must be stopped first. Use [`stop`](Self::stop) or
    /// [`kill`](Self::kill) to stop it before removing. Routes through the
    /// backend trait so cloud handles hit `DELETE /v1/sandboxes/by-name/:name`.
    pub async fn remove(&self) -> MicrosandboxResult<()> {
        match &self.inner {
            SandboxHandleInner::Local(local) => {
                if local.status == SandboxStatus::Running || local.status == SandboxStatus::Draining
                {
                    return Err(crate::MicrosandboxError::SandboxStillRunning(format!(
                        "cannot remove sandbox '{}': still running",
                        self.name
                    )));
                }

                let pools = crate::db::init_global().await?;

                super::remove_dir_if_exists(
                    &crate::config::config().sandboxes_dir().join(&self.name),
                )?;
                sandbox_entity::Entity::delete_by_id(local.db_id)
                    .exec(pools.write())
                    .await?;

                Ok(())
            }
            SandboxHandleInner::Cloud(_) => self.backend.sandboxes().remove(&self.name).await,
        }
    }
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
// Functions
//--------------------------------------------------------------------------------------------------

/// Send a signal to the sandbox process.
///
/// Returns the PIDs that were signalled.
fn signal_pid(pid: Option<i32>, signal: nix::sys::signal::Signal) -> MicrosandboxResult<Vec<i32>> {
    if let Some(pid) = pid.filter(|pid| super::pid_is_alive(*pid)) {
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), signal)?;
        return Ok(vec![pid]);
    }

    Ok(vec![])
}

/// Poll until all PIDs have exited or the timeout is reached.
async fn wait_for_exit(pids: &[i32], timeout: std::time::Duration) {
    let start = std::time::Instant::now();
    let poll_interval = std::time::Duration::from_millis(50);

    while start.elapsed() < timeout {
        if pids.iter().all(|pid| !super::pid_is_alive(*pid)) {
            return;
        }
        tokio::time::sleep(poll_interval).await;
    }
}

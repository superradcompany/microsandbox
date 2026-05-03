//! Lightweight sandbox handle for metadata and signal-based lifecycle management.

use sea_orm::EntityTrait;

use std::sync::Arc;

use crate::{
    MicrosandboxResult, agent::AgentClient, db::entity::sandbox as sandbox_entity,
    runtime::SpawnMode,
};

use super::{Sandbox, SandboxConfig, SandboxStatus};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A lightweight handle to a sandbox from the database.
///
/// Provides metadata access and signal-based lifecycle management (stop, kill)
/// without requiring a live agent bridge. Obtained via [`Sandbox::get`] or
/// [`Sandbox::list`].
///
/// For full runtime capabilities (exec, shell, fs), call [`start`](SandboxHandle::start)
/// to boot the sandbox and obtain a live [`Sandbox`] handle.
#[derive(Debug)]
pub struct SandboxHandle {
    db_id: i32,
    name: String,
    status: SandboxStatus,
    config_json: String,
    created_at: Option<chrono::DateTime<chrono::Utc>>,
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
    pid: Option<i32>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SandboxHandle {
    /// Create a handle from a database entity model and its resolved process PID.
    pub(super) fn new(model: sandbox_entity::Model, pid: Option<i32>) -> Self {
        Self {
            db_id: model.id,
            name: model.name,
            status: model.status,
            config_json: model.config,
            created_at: model.created_at.map(|dt| dt.and_utc()),
            updated_at: model.updated_at.map(|dt| dt.and_utc()),
            pid,
        }
    }

    /// Unique name identifying this sandbox.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Snapshot of sandbox status from when this handle was created.
    /// Not live — call [`Sandbox::get`] again for a fresh reading.
    pub fn status(&self) -> SandboxStatus {
        self.status
    }

    /// The serialized sandbox configuration as stored in the database.
    /// Use [`config()`](Self::config) for a deserialized version.
    pub fn config_json(&self) -> &str {
        &self.config_json
    }

    /// Parse the stored configuration. Returns an error if the JSON
    /// is malformed (e.g., schema changed since the sandbox was created).
    pub fn config(&self) -> MicrosandboxResult<SandboxConfig> {
        Ok(serde_json::from_str(&self.config_json)?)
    }

    /// When this sandbox was first created, if recorded.
    pub fn created_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.created_at
    }

    /// When this sandbox's database record was last modified.
    pub fn updated_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.updated_at
    }

    /// Read captured output from `exec.log` for this sandbox.
    ///
    /// Same backing data as [`Sandbox::logs`](super::Sandbox::logs).
    /// Works without starting the sandbox.
    pub fn logs(&self, opts: &super::LogOptions) -> MicrosandboxResult<Vec<super::LogEntry>> {
        super::logs::read_logs(&self.name, opts)
    }

    /// Get the latest metrics snapshot for this sandbox.
    pub async fn metrics(&self) -> MicrosandboxResult<super::SandboxMetrics> {
        if self.status != SandboxStatus::Running && self.status != SandboxStatus::Draining {
            return Err(crate::MicrosandboxError::Custom(format!(
                "sandbox '{}' is not running (status: {:?})",
                self.name, self.status
            )));
        }

        let config = self.config()?;
        if config.metrics_sample_interval_ms == 0 {
            return Err(crate::MicrosandboxError::MetricsDisabled(self.name.clone()));
        }

        let db =
            crate::db::init_global(Some(crate::config::config().database.max_connections)).await?;
        super::metrics::metrics_for_sandbox(
            db,
            self.db_id,
            u64::from(config.memory_mib) * 1024 * 1024,
        )
        .await
    }

    /// Start this sandbox and return a live handle.
    ///
    /// Boots the VM using the persisted configuration and pinned rootfs state.
    /// The handle remains usable if start fails.
    pub async fn start(&self) -> MicrosandboxResult<Sandbox> {
        Sandbox::start_with_mode(&self.name, SpawnMode::Attached).await
    }

    /// Start this sandbox in detached/background mode.
    ///
    /// The handle remains usable if start fails.
    pub async fn start_detached(&self) -> MicrosandboxResult<Sandbox> {
        Sandbox::start_with_mode(&self.name, SpawnMode::Detached).await
    }

    /// Connect to a running sandbox via the agent relay socket.
    ///
    /// Returns a [`Sandbox`] handle that communicates through the relay
    /// without owning the process lifecycle. The sandbox will continue
    /// running after this handle is dropped.
    pub async fn connect(&self) -> MicrosandboxResult<Sandbox> {
        if self.status != SandboxStatus::Running && self.status != SandboxStatus::Draining {
            return Err(crate::MicrosandboxError::Custom(format!(
                "sandbox '{}' is not running (status: {:?})",
                self.name, self.status
            )));
        }

        let global = crate::config::config();
        let sock_path = global
            .sandboxes_dir()
            .join(&self.name)
            .join("runtime")
            .join("agent.sock");

        let client = AgentClient::connect(&sock_path).await?;
        let config: SandboxConfig = serde_json::from_str(&self.config_json)?;

        Ok(Sandbox {
            db_id: self.db_id,
            config,
            handle: None,
            client: Arc::new(client),
        })
    }

    /// Snapshot this sandbox to a bare name under the default snapshots
    /// directory (`~/.microsandbox/snapshots/<name>/`).
    ///
    /// The sandbox must be stopped (or crashed); running sandboxes are
    /// rejected with `MicrosandboxError::SnapshotSandboxRunning`. For
    /// an explicit filesystem destination, see
    /// [`snapshot_to`](Self::snapshot_to).
    pub async fn snapshot(
        &self,
        name: &str,
    ) -> MicrosandboxResult<super::super::snapshot::Snapshot> {
        use super::super::snapshot::{Snapshot, SnapshotDestination};
        Snapshot::builder(&self.name)
            .destination(SnapshotDestination::Name(name.to_string()))
            .create()
            .await
    }

    /// Snapshot this sandbox to an explicit filesystem path.
    ///
    /// The sandbox must be stopped (or crashed); running sandboxes are
    /// rejected with `MicrosandboxError::SnapshotSandboxRunning`. For
    /// the common case of writing under the default snapshots
    /// directory, see [`snapshot`](Self::snapshot).
    pub async fn snapshot_to(
        &self,
        path: impl AsRef<std::path::Path>,
    ) -> MicrosandboxResult<super::super::snapshot::Snapshot> {
        use super::super::snapshot::{Snapshot, SnapshotDestination};
        Snapshot::builder(&self.name)
            .destination(SnapshotDestination::Path(path.as_ref().to_path_buf()))
            .create()
            .await
    }

    /// Stop the sandbox gracefully (SIGTERM).
    pub async fn stop(&self) -> MicrosandboxResult<()> {
        if self.status != SandboxStatus::Running && self.status != SandboxStatus::Draining {
            return Ok(());
        }

        signal_pid(self.pid, nix::sys::signal::Signal::SIGTERM)?;
        Ok(())
    }

    /// Kill the sandbox immediately (SIGKILL).
    ///
    /// Waits for the process to exit (up to 5 seconds) and marks the
    /// sandbox as `Stopped`.
    pub async fn kill(&mut self) -> MicrosandboxResult<()> {
        if self.status != SandboxStatus::Running && self.status != SandboxStatus::Draining {
            return Ok(());
        }

        let pids = signal_pid(self.pid, nix::sys::signal::Signal::SIGKILL)?;

        if !pids.is_empty() {
            wait_for_exit(&pids, std::time::Duration::from_secs(5)).await;
        }

        // Mark stopped if all processes are confirmed dead (or were already gone).
        let all_dead = pids.is_empty() || pids.iter().all(|pid| !super::pid_is_alive(*pid));

        if all_dead {
            let db = crate::db::init_global(Some(crate::config::config().database.max_connections))
                .await?;
            if let Err(e) =
                super::update_sandbox_status(db, self.db_id, SandboxStatus::Stopped).await
            {
                tracing::warn!(sandbox = %self.name, error = %e, "failed to update sandbox status after kill");
            }
            self.status = SandboxStatus::Stopped;
        }

        Ok(())
    }

    /// Remove this sandbox from the database and filesystem.
    ///
    /// The sandbox must be stopped first. Use [`stop`](SandboxHandle::stop) or
    /// [`kill`](SandboxHandle::kill) to stop it before removing.
    pub async fn remove(&self) -> MicrosandboxResult<()> {
        if self.status == SandboxStatus::Running || self.status == SandboxStatus::Draining {
            return Err(crate::MicrosandboxError::SandboxStillRunning(format!(
                "cannot remove sandbox '{}': still running",
                self.name
            )));
        }

        let db =
            crate::db::init_global(Some(crate::config::config().database.max_connections)).await?;

        super::remove_dir_if_exists(&crate::config::config().sandboxes_dir().join(&self.name))?;
        sandbox_entity::Entity::delete_by_id(self.db_id)
            .exec(db)
            .await?;

        Ok(())
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

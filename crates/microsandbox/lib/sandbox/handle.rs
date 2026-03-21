//! Lightweight sandbox handle for metadata and signal-based lifecycle management.

use sea_orm::EntityTrait;

use crate::{
    MicrosandboxResult, db::entity::sandbox as sandbox_entity, runtime::SupervisorSpawnMode,
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
    created_at: Option<chrono::NaiveDateTime>,
    updated_at: Option<chrono::NaiveDateTime>,
    supervisor_pid: Option<i32>,
    vm_pid: Option<i32>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SandboxHandle {
    /// Create a handle from a database entity model and its resolved process PIDs.
    pub(super) fn new(
        model: sandbox_entity::Model,
        supervisor_pid: Option<i32>,
        vm_pid: Option<i32>,
    ) -> Self {
        Self {
            db_id: model.id,
            name: model.name,
            status: model.status,
            config_json: model.config,
            created_at: model.created_at,
            updated_at: model.updated_at,
            supervisor_pid,
            vm_pid,
        }
    }

    /// Get the sandbox name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the sandbox status at the time this handle was created.
    pub fn status(&self) -> SandboxStatus {
        self.status
    }

    /// Get the raw JSON sandbox configuration.
    pub fn config_json(&self) -> &str {
        &self.config_json
    }

    /// Deserialize the sandbox configuration.
    pub fn config(&self) -> MicrosandboxResult<SandboxConfig> {
        Ok(serde_json::from_str(&self.config_json)?)
    }

    /// Get the creation timestamp.
    pub fn created_at(&self) -> Option<chrono::NaiveDateTime> {
        self.created_at
    }

    /// Get the last update timestamp.
    pub fn updated_at(&self) -> Option<chrono::NaiveDateTime> {
        self.updated_at
    }

    /// Start this sandbox and return a live handle.
    ///
    /// Boots the VM using the persisted configuration and pinned rootfs state.
    /// The handle remains usable if start fails.
    pub async fn start(&self) -> MicrosandboxResult<Sandbox> {
        Sandbox::start_with_mode(&self.name, SupervisorSpawnMode::Attached).await
    }

    /// Start this sandbox in detached/background mode.
    ///
    /// The handle remains usable if start fails.
    pub async fn start_detached(&self) -> MicrosandboxResult<Sandbox> {
        Sandbox::start_with_mode(&self.name, SupervisorSpawnMode::Detached).await
    }

    /// Stop the sandbox gracefully (SIGTERM).
    ///
    /// Signals the running supervisor with SIGTERM, or falls back to the
    /// microVM process group if the supervisor is already gone.
    pub async fn stop(&self) -> MicrosandboxResult<()> {
        if self.status != SandboxStatus::Running && self.status != SandboxStatus::Draining {
            return Err(crate::MicrosandboxError::Custom(format!(
                "sandbox '{}' is not running",
                self.name
            )));
        }

        signal_pids(
            self.supervisor_pid,
            self.vm_pid,
            nix::sys::signal::Signal::SIGTERM,
        )?;
        Ok(())
    }

    /// Kill the sandbox immediately (SIGKILL).
    ///
    /// Signals the running supervisor with SIGKILL, or falls back to the
    /// microVM process group if the supervisor is already gone. Waits for the
    /// process to exit (up to 5 seconds) and marks the sandbox as `Stopped`.
    pub async fn kill(&mut self) -> MicrosandboxResult<()> {
        if self.status != SandboxStatus::Running && self.status != SandboxStatus::Draining {
            return Ok(());
        }

        let pids = signal_pids(
            self.supervisor_pid,
            self.vm_pid,
            nix::sys::signal::Signal::SIGKILL,
        )?;

        if !pids.is_empty() {
            wait_for_exit(&pids, std::time::Duration::from_secs(5)).await;
        }

        // Mark stopped if all processes are confirmed dead (or were already gone).
        let all_dead = pids.is_empty() || pids.iter().all(|pid| !super::pid_is_alive(*pid));

        if all_dead {
            let db = crate::db::init_global(Some(crate::config::config().database.max_connections))
                .await?;
            let _ = super::update_sandbox_status(db, self.db_id, SandboxStatus::Stopped).await;
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

/// Send a signal to the supervisor or microVM process from cached PIDs.
///
/// Returns the PIDs that were signalled.
fn signal_pids(
    supervisor_pid: Option<i32>,
    vm_pid: Option<i32>,
    signal: nix::sys::signal::Signal,
) -> MicrosandboxResult<Vec<i32>> {
    if let Some(pid) = supervisor_pid.filter(|pid| super::pid_is_alive(*pid)) {
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), signal)?;
        return Ok(vec![pid]);
    }

    if let Some(pid) = vm_pid.filter(|pid| super::pid_is_alive(*pid)) {
        nix::sys::signal::killpg(nix::unistd::Pid::from_raw(pid), signal)?;
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

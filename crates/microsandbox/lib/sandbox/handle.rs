//! Lightweight sandbox handle for metadata and signal-based lifecycle management.

use sea_orm::EntityTrait;

use std::sync::Arc;

use crate::{
    MicrosandboxResult, agent::AgentClient, db::entity::sandbox as sandbox_entity,
    runtime::SpawnMode,
};

use super::{Sandbox, SandboxConfig, SandboxStatus};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Default timeout for [`SandboxHandle::connect`].
///
/// If the sandbox doesn't respond in this window, `connect()` returns
/// a typed error instead of blocking.
pub const DEFAULT_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Default timeout for [`SandboxHandle::stop`] before it force-kills.
///
/// Long enough to let the sandbox finish writing pending data on a
/// healthy host, short enough that an unresponsive sandbox doesn't
/// stall an interactive `msb stop`. Override per call with
/// [`SandboxHandle::stop_with_timeout`].
///
/// Unlike [`DEFAULT_CONNECT_TIMEOUT`], expiry here does not produce
/// an error — the sandbox is force-killed and the call returns
/// successfully.
pub const DEFAULT_STOP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

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
    pub async fn logs(
        &self,
        opts: &crate::logs::LogOptions,
    ) -> MicrosandboxResult<Vec<crate::logs::LogEntry>> {
        crate::logs::read_logs(&self.name, opts).await
    }

    /// Stream captured output as it appears, with optional follow.
    ///
    /// Same backing data as [`Sandbox::log_stream`](super::Sandbox::log_stream).
    /// Works without starting the sandbox; with `follow: true`, the
    /// stream picks up new entries the moment they land in `exec.log`.
    pub async fn log_stream(
        &self,
        opts: &crate::logs::LogStreamOptions,
    ) -> MicrosandboxResult<
        impl futures::Stream<Item = MicrosandboxResult<crate::logs::LogEntry>> + Send + 'static,
    > {
        crate::logs::log_stream(&self.name, opts).await
    }

    /// Get the latest metrics snapshot for this sandbox.
    pub async fn metrics(&self) -> MicrosandboxResult<super::SandboxMetrics> {
        // Skip the stale-status snapshot check on purpose: it can lag behind
        // a sandbox that just crashed, and `metrics_for_sandbox` already
        // returns a clear "no active run" error via `load_active_run`.
        let config = self.config()?;
        if config.effective_metrics_interval().is_none() {
            return Err(crate::MicrosandboxError::MetricsDisabled(self.name.clone()));
        }

        let db = crate::db::init_global().await?.read();
        super::metrics::metrics_for_sandbox(db, self.db_id, &config).await
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

    /// Connect to a running sandbox.
    ///
    /// Returns a [`Sandbox`] handle that does not own the process
    /// lifecycle — the sandbox keeps running after this handle is
    /// dropped. Returns a typed error if the sandbox doesn't respond
    /// within [`DEFAULT_CONNECT_TIMEOUT`]; use
    /// [`connect_with_timeout`](Self::connect_with_timeout) to override.
    pub async fn connect(&self) -> MicrosandboxResult<Sandbox> {
        self.connect_with_timeout(DEFAULT_CONNECT_TIMEOUT).await
    }

    /// Connect with an explicit timeout.
    ///
    /// If the sandbox doesn't respond within `timeout`, the call
    /// returns a typed error instead of blocking.
    pub async fn connect_with_timeout(
        &self,
        timeout: std::time::Duration,
    ) -> MicrosandboxResult<Sandbox> {
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

        let client = AgentClient::connect_with_timeout(&sock_path, timeout).await?;
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

    /// Stop the sandbox gracefully, using [`DEFAULT_STOP_TIMEOUT`].
    ///
    /// Lets the sandbox finish writing any pending data to disk before
    /// it exits, so files written inside the sandbox aren't lost
    /// across a later restart. Waits up to the default timeout for a
    /// clean exit; if the sandbox is still running after that, it is
    /// force-killed.
    ///
    /// Unlike [`connect_with_timeout`](Self::connect_with_timeout), an
    /// expired timeout here does **not** return an error — it
    /// transitions to a force-kill and the call still returns `Ok`.
    /// Use [`stop_with_timeout`](Self::stop_with_timeout) to override
    /// the budget for a single call.
    pub async fn stop(&self) -> MicrosandboxResult<()> {
        self.stop_with_timeout(DEFAULT_STOP_TIMEOUT).await
    }

    /// Stop the sandbox gracefully with an explicit timeout.
    ///
    /// `timeout` is the end-to-end deadline for a clean exit. If the
    /// sandbox is still running when the deadline expires, it is
    /// force-killed; the call returns `Ok` either way — it does not
    /// surface a timeout error.
    ///
    /// - `timeout > 0`: ask the sandbox to shut down cleanly and wait
    ///   up to `timeout`; force-kill anything still running afterward.
    ///   Pending writes that exceed the budget may be lost.
    /// - `timeout == Duration::ZERO`: force-kill immediately
    ///   (equivalent to [`kill`](Self::kill)). Pending writes that the
    ///   workload hasn't `fsync`'d may be lost — same durability as a
    ///   sudden power loss on a physical machine.
    pub async fn stop_with_timeout(&self, timeout: std::time::Duration) -> MicrosandboxResult<()> {
        if self.status != SandboxStatus::Running && self.status != SandboxStatus::Draining {
            return Ok(());
        }

        let pid = self.pid.filter(|pid| super::pid_is_alive(*pid));
        // Tracks whether we issued a SIGKILL. After SIGKILL the process is
        // guaranteed dead by kernel time; `pid_is_alive` still returns true
        // during the zombie window before the parent's `waitpid`, so we
        // can't rely on it to gate the DB update.
        let mut sigkilled = false;

        if timeout.is_zero() {
            // Skip graceful path — caller asked for immediate kill.
            let pids = signal_pid(self.pid, nix::sys::signal::Signal::SIGKILL)?;
            if !pids.is_empty() {
                sigkilled = true;
                wait_for_exit(&pids, std::time::Duration::from_secs(5)).await;
            }
        } else {
            let deadline = tokio::time::Instant::now() + timeout;
            self.shutdown_via_agent_or_sigterm(deadline).await;

            if let Some(pid) = pid {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                wait_for_exit(&[pid], remaining).await;
                if super::pid_is_alive(pid) {
                    tracing::warn!(
                        sandbox = %self.name,
                        timeout_secs = timeout.as_secs(),
                        "graceful stop exceeded timeout, escalating to SIGKILL"
                    );
                    let _ = signal_pid(self.pid, nix::sys::signal::Signal::SIGKILL)?;
                    sigkilled = true;
                    wait_for_exit(&[pid], std::time::Duration::from_secs(5)).await;
                }
            }
        }

        // Idempotent with the VMM exit observer (vm.rs build_vm): on a clean
        // poweroff the observer already wrote Stopped; this just covers paths
        // where the observer didn't get to run (e.g., SIGKILL escalation, or
        // a sandbox owned by a foreign process). After SIGKILL we trust the
        // kernel and don't poll the zombie window.
        let all_dead = sigkilled || pid.map(|p| !super::pid_is_alive(p)).unwrap_or(true);
        if all_dead {
            let db = crate::db::init_global().await?.write();
            if let Err(e) =
                super::update_sandbox_status(db, self.db_id, SandboxStatus::Stopped).await
            {
                tracing::warn!(sandbox = %self.name, error = %e, "failed to update sandbox status after stop");
            }
        }

        Ok(())
    }

    /// Send `core.shutdown` via the agent relay, with the handshake
    /// bounded by the remaining time until `deadline` so a wedged relay
    /// can't blow the stop budget. Falls back to SIGTERM on any
    /// agent-side failure.
    async fn shutdown_via_agent_or_sigterm(&self, deadline: tokio::time::Instant) {
        let budget = deadline.saturating_duration_since(tokio::time::Instant::now());
        match self.connect_with_timeout(budget).await {
            Ok(sandbox) => {
                if let Err(e) = sandbox.stop().await {
                    tracing::warn!(
                        sandbox = %self.name,
                        error = %e,
                        "agent shutdown send failed; falling back to SIGTERM"
                    );
                    let _ = signal_pid(self.pid, nix::sys::signal::Signal::SIGTERM);
                }
            }
            Err(e) => {
                tracing::warn!(
                    sandbox = %self.name,
                    error = %e,
                    "agent shutdown unavailable; falling back to SIGTERM"
                );
                let _ = signal_pid(self.pid, nix::sys::signal::Signal::SIGTERM);
            }
        }
    }

    /// Kill the sandbox immediately (SIGKILL).
    ///
    /// Waits for the process to exit (up to 5 seconds) and marks the
    /// sandbox as `Stopped`.
    ///
    /// Pending writes that the workload hasn't `fsync`'d may be lost —
    /// same durability semantics as a sudden power loss on a physical
    /// machine. Use [`stop`](Self::stop) for graceful shutdown that
    /// gives the workload a chance to flush.
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
            let db = crate::db::init_global().await?.write();
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

        let pools = crate::db::init_global().await?;

        super::remove_dir_if_exists(&crate::config::config().sandboxes_dir().join(&self.name))?;
        super::free_metrics_slot_for(self.db_id, None, microsandbox_metrics::ReleaseMode::Free);
        sandbox_entity::Entity::delete_by_id(self.db_id)
            .exec(pools.write())
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

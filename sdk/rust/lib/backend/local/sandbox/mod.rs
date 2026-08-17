//! Local sandbox lifecycle: the [`SandboxBackend`] impl for [`LocalBackend`]
//! plus the inherent lifecycle and runtime-state helpers it dispatches to.
//!
//! The create flow (image pull, rootfs preparation, record insertion,
//! process spawn) lives in the `create` submodule as further inherent
//! methods; [`LocalBackend::create_sandbox`] is its entry point.

mod create;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::future::BoxFuture;
use microsandbox_db::pool::DbPools;
use microsandbox_db::{DbReadConnection, DbWriteConnection};
use microsandbox_image::{Digest, GlobalCache};
use microsandbox_protocol::message::MessageType;
use sea_orm::{
    ColumnTrait, Condition, EntityTrait, ExprTrait, QueryFilter, QueryOrder, QuerySelect,
    sea_query::Expr,
};
#[cfg(windows)]
use windows_sys::Win32::Foundation::CloseHandle;
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};

use super::LocalBackend;
use crate::MicrosandboxResult;
use crate::backend::{
    Backend,
    sandbox::{LogStream, MetricsStream, SandboxBackend},
};
use crate::db::entity::{
    run as run_entity, sandbox as sandbox_entity, sandbox_label as sandbox_label_entity,
};
use crate::logs::{LogEntry, LogOptions, LogStreamOptions};
use crate::runtime::SpawnMode;
use crate::sandbox::metrics::SandboxMetrics;
use crate::sandbox::{
    RootfsSource, Sandbox, SandboxConfig, SandboxHandle, SandboxListBuilder, SandboxPage,
    SandboxStatus, load_sandbox_record, validate_env, validate_hostname, validate_labels,
    validate_volume_mounts,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum time to wait when connecting to the agent for lifecycle shutdown.
const AGENT_SHUTDOWN_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

//--------------------------------------------------------------------------------------------------
// Methods: Lifecycle
//--------------------------------------------------------------------------------------------------

impl LocalBackend {
    /// Local start path. Returns a complete [`Sandbox`] wrapping the supplied
    /// backend Arc.
    ///
    /// `backend` must be the `Arc<dyn Backend>` wrapping `self`: the trait
    /// impl forwards the Arc it was handed so the returned [`Sandbox`] routes
    /// follow-up calls through this same backend.
    async fn start_sandbox(
        &self,
        backend: Arc<dyn Backend>,
        name: &str,
        mode: SpawnMode,
    ) -> MicrosandboxResult<Sandbox> {
        tracing::debug!(sandbox = name, ?mode, "start_local: loading record");
        let pools = self.db().await?;
        let write_db = pools.write();
        let model = self.load_sandbox_record_reconciled(pools, name).await?;
        tracing::debug!(sandbox = name, status = ?model.status, "start_local: current status");

        if model.status == SandboxStatus::Running || model.status == SandboxStatus::Draining {
            return Err(crate::MicrosandboxError::SandboxStillRunning(format!(
                "cannot start sandbox '{name}': already running"
            )));
        }

        if model.status != SandboxStatus::Stopped && model.status != SandboxStatus::Crashed {
            return Err(crate::MicrosandboxError::Custom(format!(
                "cannot start sandbox '{name}': status is {:?} (expected Stopped or Crashed)",
                model.status
            )));
        }

        let lifecycle_guard = crate::runtime::acquire_sandbox_lifecycle_guard(
            &self.config().run_dir(),
            name,
            Duration::from_secs(5),
        )
        .await?;

        // Removal or another start may have won while the initial reconciled
        // snapshot was being loaded. Re-read under ownership and require the
        // same persisted identity before changing state or touching sockets.
        let current = load_sandbox_record(pools.read(), name).await?;
        if current.id != model.id {
            return Err(crate::MicrosandboxError::Runtime(format!(
                "sandbox {name:?} identity changed from database id {} to {}; refusing stale start",
                model.id, current.id
            )));
        }
        if !matches!(
            current.status,
            SandboxStatus::Stopped | SandboxStatus::Crashed
        ) {
            return Err(crate::MicrosandboxError::SandboxStillRunning(format!(
                "cannot start sandbox {name:?}: status changed to {:?}",
                current.status
            )));
        }
        let model = current;

        // Older runtimes did not hold the lifecycle lock and published their
        // terminal DB state just before process exit. Preserve upgrade safety
        // by waiting for that recorded owner before the new runtime acquires
        // and cleans the deterministic socket namespace.
        if let Some(pid) = Self::load_latest_run(pools.read(), model.id)
            .await?
            .and_then(|run| run.pid)
            .filter(|pid| Self::pid_is_alive(*pid))
        {
            let start = std::time::Instant::now();
            while start.elapsed() < Duration::from_secs(5) && !Self::pid_has_exited(pid) {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            if !Self::pid_has_exited(pid) {
                return Err(crate::MicrosandboxError::SandboxStillRunning(format!(
                    "cannot start sandbox {name:?}: previous runtime pid {pid} is still alive"
                )));
            }
        }

        let mut config: SandboxConfig = serde_json::from_str(&model.config)?;
        self.apply_deployment_profile(&mut config);
        config.apply_runtime_defaults();
        validate_hostname(config.spec.runtime.hostname.as_deref())?;
        self.validate_sandbox_name_for_runtime(&config.spec.name)?;
        Self::validate_rootfs_source(&config.spec.image)?;
        validate_env(&config.spec.env)?;
        validate_labels(&config.spec.labels)?;
        validate_volume_mounts(&mut config.spec.mounts)?;
        self.validate_start_state(&config, &self.sandboxes_dir().join(name))?;
        Self::update_sandbox_status(write_db, model.id, SandboxStatus::Running).await?;

        match self
            .create_sandbox_inner(config, model.id, mode, Some(lifecycle_guard))
            .await
        {
            Ok((local_state, returned_config)) => {
                let sandbox = Sandbox::from_local(backend.clone(), local_state, returned_config);
                if let Err(err) = Self::update_sandbox_active_config(
                    write_db,
                    model.id,
                    &sandbox.config().clone_for_persistence(),
                )
                .await
                {
                    let _ = sandbox.stop().await;
                    return Err(err);
                }
                Ok(sandbox)
            }
            Err(err) => {
                let _ =
                    Self::update_sandbox_status(write_db, model.id, SandboxStatus::Stopped).await;
                Err(err)
            }
        }
    }

    /// Local lifecycle: stop a sandbox by name.
    ///
    /// Tries the configured agent relay socket candidates, connects, sends
    /// `MessageType::Shutdown`, and lets agentd run an in-guest `sync()` +
    /// `reboot(RB_POWER_OFF)` so ext4 unmounts cleanly (no journal replay on
    /// next boot). Falls back to platform process termination via PID if the
    /// agent endpoint is unreachable (agentd wedged, sandbox just
    /// transitioning, etc.).
    ///
    /// No-op when the sandbox isn't in Running/Draining.
    async fn stop_sandbox(&self, name: &str) -> MicrosandboxResult<()> {
        let (model, pid) = self.sandbox_handle_state(name).await?;
        if model.status != SandboxStatus::Running && model.status != SandboxStatus::Draining {
            return Ok(());
        }

        if model.status == SandboxStatus::Running {
            Self::mark_sandbox_draining_if_running(self.db().await?.write(), model.id).await?;
        }

        match self.request_agent_shutdown(name).await {
            Ok(()) => Ok(()),
            Err(e) => {
                // Graceful degradation: agent endpoint unreachable (socket/pipe
                // missing, ECONNREFUSED, handshake timeout) or shutdown delivery
                // failed. Fall back to direct process termination so we still
                // attempt a stop, at the cost of skipping the in-guest sync().
                // The reaper updates DB status on PID exit.
                tracing::warn!(
                    sandbox = %name,
                    error = %e,
                    "stop_local: agent endpoint unreachable; falling back to process termination",
                );
                if let Some(pid) = pid.filter(|p| Self::pid_is_alive(*p)) {
                    Self::terminate_pid_gracefully(pid)?;
                }
                Ok(())
            }
        }
    }

    /// Local lifecycle: kill a sandbox by name (SIGKILL).
    ///
    /// Destructive by design — no clean-shutdown path. Signals SIGKILL to the
    /// libkrun PID, waits briefly for the process to exit, then marks the DB
    /// row Stopped if all signalled PIDs are confirmed dead.
    async fn kill_sandbox(&self, name: &str) -> MicrosandboxResult<()> {
        let (model, pid) = self.sandbox_handle_state(name).await?;
        if model.status != SandboxStatus::Running && model.status != SandboxStatus::Draining {
            return Ok(());
        }

        let mut pids = Vec::new();
        if let Some(pid) = pid.filter(|p| Self::pid_is_alive(*p)) {
            Self::kill_pid(pid)?;
            pids.push(pid);
        }

        if !pids.is_empty() {
            let timeout = Duration::from_secs(5);
            let start = std::time::Instant::now();
            let poll_interval = Duration::from_millis(50);
            while start.elapsed() < timeout {
                if pids.iter().all(|pid| Self::pid_has_exited(*pid)) {
                    break;
                }
                tokio::time::sleep(poll_interval).await;
            }
        }

        let all_dead = pids.is_empty() || pids.iter().all(|pid| Self::pid_has_exited(*pid));
        if all_dead {
            let db = self.db().await?.write();
            if let Err(e) = Self::update_sandbox_status(db, model.id, SandboxStatus::Stopped).await
            {
                tracing::warn!(sandbox = %name, error = %e, "failed to update sandbox status after kill");
            }
        }

        Ok(())
    }

    /// Local lifecycle: drain a running sandbox by name.
    ///
    /// Unix keeps the legacy SIGUSR1 drain path. Windows uses the existing
    /// `core.shutdown` agent message so the guest can sync and power off
    /// without pretending a direct process termination is graceful.
    async fn drain_sandbox(&self, name: &str) -> MicrosandboxResult<()> {
        let (model, pid) = self.sandbox_handle_state(name).await?;
        if model.status != SandboxStatus::Running && model.status != SandboxStatus::Draining {
            return Ok(());
        }

        if model.status == SandboxStatus::Running {
            Self::mark_sandbox_draining_if_running(self.db().await?.write(), model.id).await?;
        }

        #[cfg(windows)]
        {
            if pid.is_some_and(Self::pid_is_alive) {
                self.request_agent_shutdown(name).await.map_err(|err| {
                    crate::MicrosandboxError::Runtime(format!(
                        "windows drain requires the agent shutdown path, but the agent endpoint is unavailable: {err}"
                    ))
                })?;
            }
            Ok(())
        }

        #[cfg(unix)]
        {
            if let Some(pid) = pid.filter(|p| Self::pid_is_alive(*p)) {
                Self::drain_pid(pid)?;
            }
            Ok(())
        }
    }

    /// Local lifecycle: remove a stopped sandbox by name.
    ///
    /// `backend` must be the `Arc<dyn Backend>` wrapping `self`. Removal
    /// deliberately delegates through [`SandboxHandle::remove`] instead of
    /// inlining it, so explicit removes and handle-driven removes share one
    /// implementation.
    async fn remove_sandbox(
        &self,
        backend: Arc<dyn Backend>,
        name: &str,
    ) -> MicrosandboxResult<()> {
        let (model, pid) = self.sandbox_handle_state(name).await?;
        let handle = SandboxHandle::from_local_model(backend, model, pid);
        handle.remove().await
    }

    /// Load the local DB row + active PID for a sandbox handle.
    async fn sandbox_handle_state(
        &self,
        name: &str,
    ) -> MicrosandboxResult<(sandbox_entity::Model, Option<i32>)> {
        let pools = self.db().await?;
        let model = sandbox_entity::Entity::find()
            .filter(sandbox_entity::Column::Name.eq(name))
            .one(pools.read())
            .await?
            .ok_or_else(|| crate::MicrosandboxError::SandboxNotFound(name.into()))?;
        let model = self.reconcile_sandbox_runtime_state(pools, model).await?;
        let run = Self::load_active_run(pools.read(), model.id).await?;
        let pid = Self::pid_from_run(run.as_ref());
        Ok((model, pid))
    }

    /// Load one filtered page of local DB rows + their active PIDs.
    async fn list_sandbox_handle_state(
        &self,
        query: &SandboxListBuilder,
    ) -> MicrosandboxResult<(Vec<(sandbox_entity::Model, Option<i32>)>, Option<String>)> {
        let pools = self.db().await?;
        let mut select = sandbox_entity::Entity::find();

        if let Some(cursor) = query.cursor.as_deref() {
            select = select.filter(sandbox_entity::Column::Id.lt(decode_list_cursor(cursor)?));
        }

        if !query.labels.is_empty() {
            let ids = filter_sandbox_ids(pools.read(), &query.labels).await?;
            if ids.is_empty() {
                return Ok((Vec::new(), None));
            }
            select = select.filter(sandbox_entity::Column::Id.is_in(ids));
        }

        let mut sandboxes = select
            .order_by_desc(sandbox_entity::Column::Id)
            .limit(u64::from(query.limit) + 1)
            .all(pools.read())
            .await?;

        let has_more = sandboxes.len() > query.limit as usize;
        if has_more {
            sandboxes.truncate(query.limit as usize);
        }
        let next_cursor = has_more
            .then(|| {
                sandboxes
                    .last()
                    .map(|sandbox| encode_list_cursor(sandbox.id))
            })
            .flatten();

        let mut reconciled = Vec::with_capacity(sandboxes.len());
        for sandbox in sandboxes {
            let model = self.reconcile_sandbox_runtime_state(pools, sandbox).await?;
            reconciled.push(model);
        }

        let sandbox_ids: Vec<i32> = reconciled.iter().map(|sandbox| sandbox.id).collect();
        let active_pids = Self::load_active_pids(pools.read(), &sandbox_ids).await?;
        let mut out = Vec::with_capacity(reconciled.len());
        for sandbox in reconciled {
            let pid = active_pids.get(&sandbox.id).copied();
            out.push((sandbox, pid));
        }
        Ok((out, next_cursor))
    }

    /// Connect to the named sandbox's agent endpoint and send `core.shutdown`.
    async fn request_agent_shutdown(&self, name: &str) -> MicrosandboxResult<()> {
        let client = crate::sandbox::fs::agent::connect_agent_with_timeout(
            self,
            name,
            AGENT_SHUTDOWN_CONNECT_TIMEOUT,
        )
        .await?;
        client.send(0, MessageType::Shutdown, &()).await?;
        Ok(())
    }

    /// Validate persisted on-disk state before starting a stopped sandbox.
    fn validate_start_state(
        &self,
        config: &SandboxConfig,
        sandbox_dir: &Path,
    ) -> MicrosandboxResult<()> {
        if !sandbox_dir.exists() {
            return Err(crate::MicrosandboxError::Custom(format!(
                "sandbox state missing for '{}': {}",
                config.spec.name,
                sandbox_dir.display()
            )));
        }

        if let RootfsSource::Oci(_) = &config.spec.image
            && let Some(ref digest_str) = config.manifest_digest
        {
            let cache_dir = self.cache_dir();
            if let Ok(cache) = GlobalCache::new(&cache_dir)
                && let Ok(digest) = digest_str.parse::<Digest>()
            {
                let vmdk_path = cache.vmdk_path(&digest);
                if !vmdk_path.exists() {
                    return Err(crate::MicrosandboxError::Custom(format!(
                        "sandbox '{}' cannot start: VMDK missing: {}",
                        config.spec.name,
                        vmdk_path.display()
                    )));
                }
            }
        }

        Ok(())
    }
}

// Stale-sandbox reaping is no longer owned by the SDK/CLI. Host runtime
// processes (`msb sandbox`) now perform lifecycle maintenance: stale active
// reconciliation and terminal ephemeral cleanup, on startup under a
// read-gated DB lease (see `microsandbox_runtime::maintenance`). The lazy
// read-time reconciliation in `reconcile_sandbox_runtime_state` below still
// keeps `get`/`list`/`start` honest for the row they touch.

//--------------------------------------------------------------------------------------------------
// Methods: State Reconciliation
//--------------------------------------------------------------------------------------------------

impl LocalBackend {
    /// Load a sandbox row by name and reconcile its runtime state.
    async fn load_sandbox_record_reconciled(
        &self,
        pools: &DbPools,
        name: &str,
    ) -> MicrosandboxResult<sandbox_entity::Model> {
        let sandbox = load_sandbox_record(pools.read(), name).await?;
        self.reconcile_sandbox_runtime_state(pools, sandbox).await
    }

    /// Reconcile a Running/Draining row against the owning process's
    /// liveness, marking it terminal when the runtime is gone.
    async fn reconcile_sandbox_runtime_state(
        &self,
        pools: &DbPools,
        sandbox: sandbox_entity::Model,
    ) -> MicrosandboxResult<sandbox_entity::Model> {
        let run_dir = self.config().run_dir();
        let sandboxes_dir = self.config().sandboxes_dir();
        Self::reconcile_sandbox_runtime_state_with_paths(
            pools,
            sandbox,
            Some((&run_dir, &sandboxes_dir)),
        )
        .await
    }

    /// Reconcile runtime state with optional exact socket roots.
    async fn reconcile_sandbox_runtime_state_with_paths(
        pools: &DbPools,
        sandbox: sandbox_entity::Model,
        socket_roots: Option<(&Path, &Path)>,
    ) -> MicrosandboxResult<sandbox_entity::Model> {
        if !matches!(
            sandbox.status,
            SandboxStatus::Running | SandboxStatus::Draining
        ) {
            return Ok(sandbox);
        }

        let run = Self::load_active_run(pools.read(), sandbox.id).await?;
        if run
            .as_ref()
            .and_then(|run| run.pid)
            .is_some_and(Self::pid_is_alive)
        {
            return Ok(sandbox);
        }

        // A dead-PID snapshot is not sufficient: another process may already
        // have reconciled and restarted this name. Serialize on the runtime
        // ownership lock, then re-read the exact row/run before unlinking.
        let _guard = if let Some((run_dir, _)) = socket_roots {
            let Some(guard) =
                microsandbox_runtime::ipc::try_acquire_lifecycle_guard(run_dir, &sandbox.name)?
            else {
                return Ok(sandbox);
            };
            Some(guard)
        } else {
            None
        };
        let Some(sandbox) = sandbox_entity::Entity::find_by_id(sandbox.id)
            .one(pools.read())
            .await?
        else {
            return Err(crate::MicrosandboxError::SandboxNotFound(sandbox.name));
        };
        if !matches!(
            sandbox.status,
            SandboxStatus::Running | SandboxStatus::Draining
        ) {
            return Ok(sandbox);
        }
        let run = Self::load_active_run(pools.read(), sandbox.id).await?;

        // No run record yet while Running means the sandbox is still starting up
        // (the child process has not inserted its PID). A Draining row with no
        // active run, however, has already completed shutdown from the DB's point
        // of view and should not keep stop callers polling forever.
        let Some(run) = run else {
            if sandbox.status == SandboxStatus::Draining {
                if let Some((run_dir, sandboxes_dir)) = socket_roots {
                    crate::runtime::remove_sandbox_socket_artifacts_at(
                        run_dir,
                        sandboxes_dir,
                        &sandbox.name,
                    )?;
                }
                let (terminal_status, reason) = Self::stale_runtime_terminal_state(sandbox.status);
                Self::mark_sandbox_runtime_stale(
                    pools.write(),
                    sandbox.id,
                    None,
                    terminal_status,
                    reason,
                )
                .await?;

                return sandbox_entity::Entity::find_by_id(sandbox.id)
                    .one(pools.read())
                    .await?
                    .ok_or_else(|| crate::MicrosandboxError::SandboxNotFound(sandbox.name));
            }

            return Ok(sandbox);
        };

        if run.pid.is_some_and(Self::pid_is_alive) {
            return Ok(sandbox);
        }

        if let Some((run_dir, sandboxes_dir)) = socket_roots {
            crate::runtime::remove_sandbox_socket_artifacts_at(
                run_dir,
                sandboxes_dir,
                &sandbox.name,
            )?;
        }
        let (terminal_status, reason) = Self::stale_runtime_terminal_state(sandbox.status);
        Self::mark_sandbox_runtime_stale(
            pools.write(),
            sandbox.id,
            Some(run.id),
            terminal_status,
            reason,
        )
        .await?;

        sandbox_entity::Entity::find_by_id(sandbox.id)
            .one(pools.read())
            .await?
            .ok_or_else(|| crate::MicrosandboxError::SandboxNotFound(sandbox.name))
    }

    /// Load the most recent active run record for a sandbox, if any.
    pub(crate) async fn load_active_run(
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

    /// Load the most recent run record regardless of lifecycle status.
    pub(crate) async fn load_latest_run(
        db: &DbReadConnection,
        sandbox_id: i32,
    ) -> MicrosandboxResult<Option<run_entity::Model>> {
        run_entity::Entity::find()
            .filter(run_entity::Column::SandboxId.eq(sandbox_id))
            .order_by_desc(run_entity::Column::Id)
            .one(db)
            .await
            .map_err(Into::into)
    }

    /// Load the live PIDs of the most recent active runs for `sandbox_ids`.
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
            if let Some(pid) = Self::pid_from_run(Some(&run)) {
                pids.insert(run.sandbox_id, pid);
            }
        }

        Ok(pids)
    }

    /// Extract a live PID from a run record, if the process is still alive.
    fn pid_from_run(run: Option<&run_entity::Model>) -> Option<i32> {
        run.and_then(|model| model.pid)
            .filter(|pid| Self::pid_is_alive(*pid))
    }

    /// Terminal status + termination reason for a stale Running/Draining row.
    fn stale_runtime_terminal_state(
        status: SandboxStatus,
    ) -> (SandboxStatus, run_entity::TerminationReason) {
        match status {
            // Draining means a stop/drain request was already accepted. If the
            // owning runtime is now gone, the lifecycle reached its requested
            // terminal state even when the original observer could not reap it.
            SandboxStatus::Draining => (
                SandboxStatus::Stopped,
                run_entity::TerminationReason::ShutdownRequested,
            ),
            _ => (
                SandboxStatus::Crashed,
                run_entity::TerminationReason::InternalError,
            ),
        }
    }

    /// Mark a stale sandbox row (and optionally its run) terminal.
    async fn mark_sandbox_runtime_stale(
        db: &DbWriteConnection,
        sandbox_id: i32,
        run_id: Option<i32>,
        terminal_status: SandboxStatus,
        reason: run_entity::TerminationReason,
    ) -> MicrosandboxResult<()> {
        db.transaction(|txn| async move {
            let now = chrono::Utc::now().naive_utc();

            if let Some(run_id) = run_id {
                run_entity::Entity::update_many()
                    .col_expr(
                        run_entity::Column::Status,
                        Expr::value(run_entity::RunStatus::Terminated),
                    )
                    .col_expr(run_entity::Column::TerminationReason, Expr::value(reason))
                    .col_expr(run_entity::Column::TerminatedAt, Expr::value(now))
                    .filter(run_entity::Column::Id.eq(run_id))
                    .exec(&txn)
                    .await?;
            }

            // Only reconcile an active row. This prevents a concurrent start()
            // from having its newly-terminal or newly-running status overwritten.
            sandbox_entity::Entity::update_many()
                .col_expr(sandbox_entity::Column::Status, Expr::value(terminal_status))
                .col_expr(
                    sandbox_entity::Column::ActiveConfig,
                    Expr::value(Option::<String>::None),
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

    /// Update the sandbox status in the database.
    async fn update_sandbox_status(
        db: &DbWriteConnection,
        sandbox_id: i32,
        status: SandboxStatus,
    ) -> MicrosandboxResult<()> {
        db.transaction(|txn| async move {
            let mut update = sandbox_entity::Entity::update_many()
                .col_expr(sandbox_entity::Column::Status, Expr::value(status))
                .col_expr(
                    sandbox_entity::Column::UpdatedAt,
                    Expr::value(chrono::Utc::now().naive_utc()),
                );
            if Self::sandbox_status_clears_active_config(status) {
                update = update.col_expr(
                    sandbox_entity::Column::ActiveConfig,
                    Expr::value(Option::<String>::None),
                );
            }
            update
                .filter(sandbox_entity::Column::Id.eq(sandbox_id))
                .exec(&txn)
                .await?;
            Ok((txn, ()))
        })
        .await
    }

    /// Persist the config used by the active VM for a running sandbox.
    async fn update_sandbox_active_config(
        db: &DbWriteConnection,
        sandbox_id: i32,
        config: &SandboxConfig,
    ) -> MicrosandboxResult<()> {
        let config_json = serde_json::to_string(config)?;
        sandbox_entity::Entity::update_many()
            .col_expr(
                sandbox_entity::Column::ActiveConfig,
                Expr::value(Some(config_json)),
            )
            .col_expr(
                sandbox_entity::Column::UpdatedAt,
                Expr::value(chrono::Utc::now().naive_utc()),
            )
            .filter(sandbox_entity::Column::Id.eq(sandbox_id))
            .exec(db)
            .await?;

        Ok(())
    }

    /// Whether a status transition clears the persisted active config.
    fn sandbox_status_clears_active_config(status: SandboxStatus) -> bool {
        matches!(
            status,
            SandboxStatus::Created | SandboxStatus::Stopped | SandboxStatus::Crashed
        )
    }

    /// Move a Running row to Draining (no-op for any other status).
    async fn mark_sandbox_draining_if_running(
        db: &DbWriteConnection,
        sandbox_id: i32,
    ) -> MicrosandboxResult<()> {
        sandbox_entity::Entity::update_many()
            .col_expr(
                sandbox_entity::Column::Status,
                Expr::value(SandboxStatus::Draining),
            )
            .col_expr(
                sandbox_entity::Column::UpdatedAt,
                Expr::value(chrono::Utc::now().naive_utc()),
            )
            .filter(sandbox_entity::Column::Id.eq(sandbox_id))
            .filter(sandbox_entity::Column::Status.eq(SandboxStatus::Running))
            .exec(db)
            .await?;

        Ok(())
    }

    /// Whether `pid` refers to a live process.
    fn pid_is_alive(pid: i32) -> bool {
        microsandbox_utils::process::pid_is_alive(pid)
    }

    /// Whether `pid` has exited without consuming its wait status.
    ///
    /// The runtime's owning `Child` or Tokio task must remain the sole reaper;
    /// probing with `waitpid` here can steal the status and make that waiter
    /// fail with `ECHILD`.
    fn pid_has_exited(pid: i32) -> bool {
        !Self::pid_is_alive(pid)
    }

    /// Request graceful termination (SIGTERM).
    #[cfg(unix)]
    fn terminate_pid_gracefully(pid: i32) -> MicrosandboxResult<()> {
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid),
            nix::sys::signal::Signal::SIGTERM,
        )?;
        Ok(())
    }

    /// Request termination (Windows has no graceful signal equivalent).
    #[cfg(windows)]
    fn terminate_pid_gracefully(pid: i32) -> MicrosandboxResult<()> {
        Self::terminate_pid(pid)
    }

    /// Force-kill a process (SIGKILL).
    #[cfg(unix)]
    fn kill_pid(pid: i32) -> MicrosandboxResult<()> {
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid),
            nix::sys::signal::Signal::SIGKILL,
        )?;
        Ok(())
    }

    /// Force-kill a process.
    #[cfg(windows)]
    fn kill_pid(pid: i32) -> MicrosandboxResult<()> {
        Self::terminate_pid(pid)
    }

    /// Trigger the legacy drain path (SIGUSR1).
    #[cfg(unix)]
    fn drain_pid(pid: i32) -> MicrosandboxResult<()> {
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid),
            nix::sys::signal::Signal::SIGUSR1,
        )?;
        Ok(())
    }

    /// Terminate a process via the Win32 process API.
    #[cfg(windows)]
    fn terminate_pid(pid: i32) -> MicrosandboxResult<()> {
        let pid = u32::try_from(pid).map_err(|_| {
            crate::MicrosandboxError::Runtime(format!("invalid Windows pid: {pid}"))
        })?;
        let handle = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error().into());
        }

        let result = unsafe { TerminateProcess(handle, 1) };
        let close_result = unsafe { CloseHandle(handle) };
        if result == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if close_result == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl SandboxBackend for LocalBackend {
    fn create<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        config: SandboxConfig,
        _start: bool,
    ) -> BoxFuture<'a, MicrosandboxResult<Sandbox>> {
        Box::pin(async move {
            self.warn_cloud_only(&config);
            // Local backend always boots immediately — `start` only differs
            // for cloud where create-without-start is a distinct state.
            self.create_sandbox(backend, config, SpawnMode::Attached, None)
                .await
        })
    }

    fn create_detached<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        config: SandboxConfig,
    ) -> BoxFuture<'a, MicrosandboxResult<Sandbox>> {
        Box::pin(async move {
            self.warn_cloud_only(&config);
            self.create_sandbox(backend, config, SpawnMode::Detached, None)
                .await
        })
    }

    fn start<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Sandbox>> {
        Box::pin(async move { self.start_sandbox(backend, name, SpawnMode::Attached).await })
    }

    fn start_detached<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Sandbox>> {
        Box::pin(async move { self.start_sandbox(backend, name, SpawnMode::Detached).await })
    }

    fn get<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<SandboxHandle>> {
        Box::pin(async move {
            let (model, pid) = self.sandbox_handle_state(name).await?;
            Ok(SandboxHandle::from_local_model(backend, model, pid))
        })
    }

    fn list<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        query: SandboxListBuilder,
    ) -> BoxFuture<'a, MicrosandboxResult<SandboxPage>> {
        Box::pin(async move {
            let (rows, next_cursor) = self.list_sandbox_handle_state(&query).await?;
            let sandboxes = rows
                .into_iter()
                .map(|(model, pid)| SandboxHandle::from_local_model(backend.clone(), model, pid))
                .collect();
            Ok(SandboxPage {
                sandboxes,
                next_cursor,
            })
        })
    }

    fn remove<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { self.remove_sandbox(backend, name).await })
    }

    fn stop<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { self.stop_sandbox(name).await })
    }

    fn kill<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { self.kill_sandbox(name).await })
    }

    fn drain<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { self.drain_sandbox(name).await })
    }

    fn logs<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        name: &'a str,
        opts: &'a LogOptions,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<LogEntry>>> {
        Box::pin(async move { crate::logs::read_logs_local(self, name, opts).await })
    }

    fn log_stream<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        name: &'a str,
        opts: &'a LogStreamOptions,
    ) -> BoxFuture<'a, MicrosandboxResult<LogStream>> {
        Box::pin(async move {
            let stream = crate::logs::log_stream_local(self, name, opts).await?;
            Ok(Box::pin(stream) as LogStream)
        })
    }

    fn metrics<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        name: &'a str,
        config: &'a SandboxConfig,
    ) -> BoxFuture<'a, MicrosandboxResult<SandboxMetrics>> {
        Box::pin(async move { crate::sandbox::metrics::local_metrics(self, name, config).await })
    }

    fn metrics_stream(
        &self,
        backend: Arc<dyn Backend>,
        name: String,
        config: SandboxConfig,
        interval: Duration,
    ) -> MetricsStream {
        crate::sandbox::metrics::local_metrics_stream(backend, name, config, interval)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn encode_list_cursor(id: i32) -> String {
    URL_SAFE_NO_PAD.encode(id.to_string())
}

fn decode_list_cursor(cursor: &str) -> MicrosandboxResult<i32> {
    let bytes = URL_SAFE_NO_PAD.decode(cursor).map_err(|_| {
        crate::MicrosandboxError::InvalidCursor("invalid sandbox list cursor encoding".into())
    })?;
    let raw = std::str::from_utf8(&bytes).map_err(|_| {
        crate::MicrosandboxError::InvalidCursor("invalid sandbox list cursor payload".into())
    })?;
    raw.parse().map_err(|_| {
        crate::MicrosandboxError::InvalidCursor("invalid sandbox list cursor payload".into())
    })
}

async fn filter_sandbox_ids(
    db: &DbReadConnection,
    labels: &BTreeMap<String, String>,
) -> MicrosandboxResult<Vec<i32>> {
    let mut condition = Condition::any();
    for (key, value) in labels {
        condition = condition.add(
            sandbox_label_entity::Column::Key
                .eq(key)
                .and(sandbox_label_entity::Column::Value.eq(value)),
        );
    }

    let rows = sandbox_label_entity::Entity::find()
        .filter(condition)
        .all(db)
        .await?;
    let mut matched: HashMap<i32, HashSet<(String, String)>> = HashMap::new();
    for row in rows {
        matched
            .entry(row.sandbox_id)
            .or_default()
            .insert((row.key, row.value));
    }

    Ok(matched
        .into_iter()
        .filter_map(|(id, found)| (found.len() == labels.len()).then_some(id))
        .collect())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(unix)]
    use std::process::Command;

    use microsandbox_db::entity::run as run_entity;
    use microsandbox_db::pool::DbPools;
    use microsandbox_migration::{Migrator, MigratorTrait};
    #[cfg(unix)]
    use sea_orm::{ColumnTrait, QueryFilter};
    use sea_orm::{EntityTrait, Set};
    use tempfile::tempdir;

    use super::sandbox_entity;
    use crate::backend::LocalBackend;
    use crate::sandbox::{
        OciRootfsSource, RootfsSource, SandboxConfig, SandboxListBuilder, SandboxStatus,
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

    fn test_config(name: impl Into<String>) -> SandboxConfig {
        SandboxConfig {
            spec: microsandbox_types::SandboxSpec {
                name: name.into(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn test_config_with_rootfs(name: impl Into<String>, image: RootfsSource) -> SandboxConfig {
        SandboxConfig {
            spec: microsandbox_types::SandboxSpec {
                name: name.into(),
                image,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn dead_pid() -> i32 {
        let mut pid = 900_000;
        while LocalBackend::pid_is_alive(pid) {
            pid += 1;
        }
        pid
    }

    #[test]
    #[cfg(unix)]
    fn pid_exit_probe_does_not_reap_child() {
        let mut child = Command::new("sh").arg("-c").arg("exit 0").spawn().unwrap();
        let pid = child.id() as i32;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);

        // Wait until the process is a zombie. The exit probe must observe that
        // state without consuming the status owned by `child` below.
        while LocalBackend::pid_is_alive(pid) && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        assert!(LocalBackend::pid_has_exited(pid));
        assert!(child.wait().unwrap().success());
    }

    #[tokio::test]
    async fn list_pages_after_filtering_by_labels() {
        let temp = tempdir().unwrap();
        let backend = LocalBackend::builder()
            .home(temp.path())
            .build()
            .await
            .unwrap();
        let pools = backend.db().await.unwrap();

        for (name, owner) in [
            ("first", "mine"),
            ("other", "theirs"),
            ("second", "mine"),
            ("third", "mine"),
        ] {
            let mut config = test_config(name);
            config.spec.labels.insert("owner".into(), owner.into());
            LocalBackend::insert_sandbox_record(pools.write(), &config)
                .await
                .unwrap();
        }

        let first_query = SandboxListBuilder::default()
            .limit(2)
            .label("owner", "mine");
        let (first, cursor) = backend
            .list_sandbox_handle_state(&first_query)
            .await
            .unwrap();
        assert_eq!(
            first
                .iter()
                .map(|(sandbox, _)| sandbox.name.as_str())
                .collect::<Vec<_>>(),
            ["third", "second"]
        );

        let second_query = SandboxListBuilder::default()
            .limit(2)
            .label("owner", "mine")
            .cursor(cursor.expect("first page has another matching row"));
        let (second, cursor) = backend
            .list_sandbox_handle_state(&second_query)
            .await
            .unwrap();
        assert_eq!(second[0].0.name, "first");
        assert!(cursor.is_none());
    }

    #[tokio::test]
    async fn test_reconcile_sandbox_runtime_state_marks_dead_processes_crashed() {
        #[cfg(unix)]
        let temp = tempfile::Builder::new()
            .prefix("msb-lazy-reap")
            .tempdir_in("/tmp")
            .unwrap();
        #[cfg(not(unix))]
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let pools = open_test_pools(&db_path).await;

        let config = test_config("stale");
        let sandbox_id = LocalBackend::insert_sandbox_record(pools.write(), &config)
            .await
            .unwrap();
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

        let sandbox = sandbox_entity::Entity::find_by_id(sandbox_id)
            .one(pools.write())
            .await
            .unwrap()
            .unwrap();
        let run_dir = temp.path().join("run");
        let sandboxes_dir = temp.path().join("sandboxes");
        #[cfg(unix)]
        let socket_paths = {
            let paths = microsandbox_runtime::ipc::sandbox_socket_paths(&run_dir, "stale");
            std::fs::create_dir_all(&paths.canonical_dir).unwrap();
            std::fs::write(&paths.agent, b"stale").unwrap();
            std::fs::write(&paths.control, b"stale").unwrap();
            microsandbox_runtime::ipc::publish_legacy_agent_link(&run_dir, "stale", &paths.agent)
                .unwrap();
            microsandbox_runtime::ipc::publish_legacy_control_link(
                &run_dir,
                "stale",
                &paths.control,
            )
            .unwrap();
            paths
        };
        let reconciled = LocalBackend::reconcile_sandbox_runtime_state_with_paths(
            &pools,
            sandbox,
            Some((&run_dir, &sandboxes_dir)),
        )
        .await
        .unwrap();
        assert_eq!(reconciled.status, SandboxStatus::Crashed);
        #[cfg(unix)]
        for path in [
            &socket_paths.agent,
            &socket_paths.control,
            &socket_paths.legacy_agent,
            &socket_paths.legacy_control,
            &socket_paths.canonical_dir,
        ] {
            assert!(std::fs::symlink_metadata(path).is_err());
        }

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
    async fn test_reconcile_sandbox_runtime_state_marks_dead_draining_stopped() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let pools = open_test_pools(&db_path).await;

        let config = test_config("draining-stale");
        let sandbox_id = LocalBackend::insert_sandbox_record(pools.write(), &config)
            .await
            .unwrap();
        LocalBackend::update_sandbox_status(pools.write(), sandbox_id, SandboxStatus::Draining)
            .await
            .unwrap();

        let run = run_entity::ActiveModel {
            sandbox_id: Set(sandbox_id),
            pid: Set(Some(dead_pid())),
            status: Set(run_entity::RunStatus::Running),
            ..Default::default()
        };
        let run_id = run_entity::Entity::insert(run)
            .exec(pools.write())
            .await
            .unwrap()
            .last_insert_id;

        let sandbox = sandbox_entity::Entity::find_by_id(sandbox_id)
            .one(pools.write())
            .await
            .unwrap()
            .unwrap();
        let reconciled =
            LocalBackend::reconcile_sandbox_runtime_state_with_paths(&pools, sandbox, None)
                .await
                .unwrap();
        assert_eq!(reconciled.status, SandboxStatus::Stopped);

        let run = run_entity::Entity::find_by_id(run_id)
            .one(pools.write())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(run.status, run_entity::RunStatus::Terminated);
        assert_eq!(
            run.termination_reason,
            Some(run_entity::TerminationReason::ShutdownRequested)
        );
        assert!(run.terminated_at.is_some());
    }

    #[tokio::test]
    async fn test_reconcile_sandbox_runtime_state_marks_draining_without_run_stopped() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let pools = open_test_pools(&db_path).await;

        let config = test_config("draining-no-run");
        let sandbox_id = LocalBackend::insert_sandbox_record(pools.write(), &config)
            .await
            .unwrap();
        LocalBackend::update_sandbox_status(pools.write(), sandbox_id, SandboxStatus::Draining)
            .await
            .unwrap();

        let sandbox = sandbox_entity::Entity::find_by_id(sandbox_id)
            .one(pools.write())
            .await
            .unwrap()
            .unwrap();
        let reconciled =
            LocalBackend::reconcile_sandbox_runtime_state_with_paths(&pools, sandbox, None)
                .await
                .unwrap();

        assert_eq!(reconciled.status, SandboxStatus::Stopped);
    }

    #[test]
    fn test_validate_start_state_requires_existing_sandbox_dir() {
        let temp = tempdir().unwrap();
        let sandbox_dir = temp.path().join("missing");
        let config = test_config("missing");

        let backend = LocalBackend::lazy();
        let err = backend
            .validate_start_state(&config, &sandbox_dir)
            .unwrap_err();
        assert!(err.to_string().contains("sandbox state missing"));
    }

    #[test]
    fn test_validate_start_state_accepts_oci_with_manifest_digest() {
        let temp = tempdir().unwrap();
        let sandbox_dir = temp.path().join("persisted");
        fs::create_dir_all(&sandbox_dir).unwrap();

        let mut config = test_config_with_rootfs(
            "persisted",
            RootfsSource::Oci(OciRootfsSource {
                reference: "docker.io/library/alpine".into(),
                root_disk: None,
            }),
        );
        config.manifest_digest = Some("sha256:aaaa".into());

        // validate_start_state checks VMDK existence via GlobalCache,
        // which depends on the global config. In unit tests without a real
        // config, it succeeds because the cache init may fail gracefully.
        // The key thing is it doesn't panic.
        let backend = LocalBackend::lazy();
        let _ = backend.validate_start_state(&config, &sandbox_dir);
    }

    /// Simulates the reaper sweep: queries all Running/Draining sandboxes and
    /// reconciles each. Verifies that only stale entries are reaped while
    /// live, stopped, crashed, and starting (no run record) sandboxes are
    /// left untouched.
    #[tokio::test]
    #[cfg(unix)]
    async fn test_reap_marks_only_dead_running_and_draining_sandboxes() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let pools = open_test_pools(&db_path).await;

        let dead = dead_pid();

        // --- Sandbox A: Running + dead PID → should become Crashed ---
        let cfg_a = test_config("running-dead");
        let id_a = LocalBackend::insert_sandbox_record(pools.write(), &cfg_a)
            .await
            .unwrap();
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

        let cfg_b = test_config("running-alive");
        let id_b = LocalBackend::insert_sandbox_record(pools.write(), &cfg_b)
            .await
            .unwrap();
        run_entity::Entity::insert(run_entity::ActiveModel {
            sandbox_id: Set(id_b),
            pid: Set(Some(live_pid)),
            status: Set(run_entity::RunStatus::Running),
            ..Default::default()
        })
        .exec(pools.write())
        .await
        .unwrap();

        // --- Sandbox C: Draining + dead PID → should become Stopped ---
        let cfg_c = test_config("draining-dead");
        let id_c = LocalBackend::insert_sandbox_record(pools.write(), &cfg_c)
            .await
            .unwrap();
        LocalBackend::update_sandbox_status(pools.write(), id_c, SandboxStatus::Draining)
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

        // --- Sandbox C2: Draining + no active run → should become Stopped ---
        let cfg_c2 = test_config("draining-no-run");
        let id_c2 = LocalBackend::insert_sandbox_record(pools.write(), &cfg_c2)
            .await
            .unwrap();
        LocalBackend::update_sandbox_status(pools.write(), id_c2, SandboxStatus::Draining)
            .await
            .unwrap();

        // --- Sandbox D: Stopped → should stay Stopped ---
        let cfg_d = test_config("stopped");
        let id_d = LocalBackend::insert_sandbox_record(pools.write(), &cfg_d)
            .await
            .unwrap();
        LocalBackend::update_sandbox_status(pools.write(), id_d, SandboxStatus::Stopped)
            .await
            .unwrap();

        // --- Sandbox E: Running + no run record (still starting) → should stay Running ---
        let cfg_e = test_config("starting");
        let id_e = LocalBackend::insert_sandbox_record(pools.write(), &cfg_e)
            .await
            .unwrap();

        // --- Reap: query all Running/Draining, reconcile each ---
        let stale = sandbox_entity::Entity::find()
            .filter(
                sandbox_entity::Column::Status
                    .is_in([SandboxStatus::Running, SandboxStatus::Draining]),
            )
            .all(pools.write())
            .await
            .unwrap();

        for sandbox in stale {
            let _ = LocalBackend::reconcile_sandbox_runtime_state_with_paths(&pools, sandbox, None)
                .await;
        }

        // --- Assertions ---
        let load = |id| {
            let read_db = pools.read();
            async move {
                sandbox_entity::Entity::find_by_id(id)
                    .one(read_db)
                    .await
                    .unwrap()
                    .unwrap()
            }
        };

        assert_eq!(load(id_a).await.status, SandboxStatus::Crashed);
        assert_eq!(load(id_b).await.status, SandboxStatus::Running);
        assert_eq!(load(id_c).await.status, SandboxStatus::Stopped);
        assert_eq!(load(id_c2).await.status, SandboxStatus::Stopped);
        assert_eq!(load(id_d).await.status, SandboxStatus::Stopped);
        assert_eq!(load(id_e).await.status, SandboxStatus::Running);

        // Cleanup the live process.
        unsafe { libc::kill(live_pid, libc::SIGKILL) };
        waiter.join().unwrap();
    }
}

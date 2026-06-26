//! Host-runtime-owned sandbox lifecycle maintenance.
//!
//! Each `msb sandbox` process self-cleans its own ephemeral sandbox when the
//! VM reaches a terminal status (see [`cleanup_terminal_ephemeral_sandbox`]),
//! and on startup performs a cheap, bounded, opportunistic sweep of leftovers
//! from runtimes that died before they could self-clean
//! ([`run_startup_maintenance`]).
//!
//! Coordination uses a single-row `maintenance_lease` table as a read-gated,
//! non-blocking lease: a runtime first reads the lease row and skips entirely
//! when another runtime holds it or completed a sweep recently, only issuing a
//! write when the lease is genuinely stale. A burst of sandbox starts
//! therefore costs one indexed read each, and at most one runtime per window
//! runs the actual scan, never a blocking lock or one contended write per
//! start.
//!
//! Cleanup removes the sandbox directory before conditionally deleting the DB
//! row. That keeps filesystem failures retryable: if directory removal fails,
//! the row remains for a later self-clean or maintenance sweep.

use std::path::Path;
use std::time::Instant;

use microsandbox_db::DbWriteConnection;
use microsandbox_db::entity::{
    maintenance_lease as lease_entity, run as run_entity, sandbox as sandbox_entity,
};
use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{
    ColumnTrait, Condition, DbErr, EntityTrait, QueryFilter, QueryOrder, QuerySelect, Set,
};

use crate::RuntimeResult;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// How long an acquired lifecycle-maintenance lease is held before another
/// runtime may reclaim it, even if the holder died mid-sweep.
const LEASE_DURATION_SECS: i64 = 10;

/// Minimum interval between successful sweeps. Read-gates the lease so most
/// startups skip the maintenance write entirely.
const MIN_SWEEP_INTERVAL_SECS: i64 = 30;

/// Wall-clock budget for a single maintenance sweep. The sweep stops early
/// (leaving the rest for the next window) once this elapses.
const MAX_SWEEP_DURATION_MS: u64 = 250;

/// Maximum stale active sandbox rows reconciled in one sweep.
const MAX_STALE_ACTIVE_ROWS: u64 = 250;

/// Maximum terminal ephemeral sandbox rows cleaned in one sweep.
const MAX_TERMINAL_EPHEMERAL_ROWS: u64 = 250;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Outcome of attempting to clean a single terminal ephemeral sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupOutcome {
    /// The directory and row were removed.
    Removed,

    /// Directory removal failed; the row remains so cleanup can retry later.
    DirRemoveFailed,

    /// The sandbox row was already gone (cleaned by another runtime).
    AlreadyGone,

    /// Another runtime won the conditional delete first.
    AlreadyClaimed,

    /// The sandbox is persistent, so it is intentionally left in place.
    SkippedPersistent,

    /// The sandbox is not in a terminal status yet.
    SkippedActive,

    /// The sandbox still has a run with a live PID.
    SkippedLivePid,
}

/// Bounds applied to a single maintenance sweep.
#[derive(Debug, Clone, Copy)]
pub struct MaintenanceLimits {
    /// Maximum stale active rows to reconcile.
    pub max_stale_active: u64,
    /// Maximum terminal ephemeral rows to clean.
    pub max_terminal_ephemeral: u64,
    /// Wall-clock budget for the whole sweep.
    pub max_duration: std::time::Duration,
}

/// Summary of what one maintenance sweep did. Best-effort counters only.
#[derive(Debug, Default, Clone, Copy)]
pub struct MaintenanceReport {
    /// Stale active sandboxes reconciled to a terminal status.
    pub reconciled: u64,
    /// Terminal ephemeral sandboxes removed.
    pub removed: u64,
    /// Per-row errors that were logged and skipped.
    pub errors: u64,
    /// Whether the sweep stopped early due to the time budget.
    pub timed_out: bool,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for MaintenanceLimits {
    fn default() -> Self {
        Self {
            max_stale_active: MAX_STALE_ACTIVE_ROWS,
            max_terminal_ephemeral: MAX_TERMINAL_EPHEMERAL_ROWS,
            max_duration: std::time::Duration::from_millis(MAX_SWEEP_DURATION_MS),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Run startup lifecycle maintenance under a read-gated lease.
///
/// Best-effort: this must never abort the sandbox boot path, so all errors are
/// logged and swallowed. When the lease is not won, returns immediately after a
/// single indexed read.
pub async fn run_startup_maintenance(db: &DbWriteConnection, sandboxes_dir: &Path) {
    match try_acquire_lease(db).await {
        Ok(true) => {}
        Ok(false) => {
            tracing::debug!("lifecycle maintenance lease not acquired; skipping sweep");
            return;
        }
        Err(err) => {
            tracing::debug!(error = %err, "lifecycle maintenance lease attempt failed");
            return;
        }
    }

    match run_sandbox_lifecycle_maintenance(db, sandboxes_dir, MaintenanceLimits::default()).await {
        Ok(report) => {
            tracing::debug!(
                reconciled = report.reconciled,
                removed = report.removed,
                errors = report.errors,
                timed_out = report.timed_out,
                "sandbox lifecycle maintenance complete"
            );
            // Record completion so the read-gate suppresses redundant sweeps
            // for the next window. On error we deliberately skip this so the
            // lease simply expires and another runtime retries sooner.
            if let Err(err) = record_completion(db).await {
                tracing::debug!(error = %err, "failed to record maintenance completion");
            }
        }
        Err(err) => {
            tracing::warn!(error = %err, "sandbox lifecycle maintenance sweep failed");
        }
    }
}

/// Run one bounded maintenance sweep: reconcile stale active sandboxes, then
/// clean terminal ephemeral sandboxes. Per-row errors are counted, not
/// propagated, so one bad row cannot abort the rest.
pub async fn run_sandbox_lifecycle_maintenance(
    db: &DbWriteConnection,
    sandboxes_dir: &Path,
    limits: MaintenanceLimits,
) -> RuntimeResult<MaintenanceReport> {
    let mut report = MaintenanceReport::default();
    let start = Instant::now();

    // Phase 1: stale active reconciliation. Mark sandboxes whose owning
    // runtime died (dead PID) as terminal.
    let active = sandbox_entity::Entity::find()
        .filter(sandbox_entity::Column::Status.is_in([
            sandbox_entity::SandboxStatus::Running,
            sandbox_entity::SandboxStatus::Draining,
        ]))
        .order_by_asc(sandbox_entity::Column::Id)
        .limit(limits.max_stale_active)
        .all(db)
        .await?;

    for sandbox in active {
        if start.elapsed() >= limits.max_duration {
            report.timed_out = true;
            break;
        }
        match reconcile_stale_active(db, &sandbox).await {
            Ok(true) => report.reconciled += 1,
            Ok(false) => {}
            Err(err) => {
                report.errors += 1;
                tracing::debug!(sandbox = %sandbox.name, error = %err, "stale reconciliation failed");
            }
        }
    }

    // Phase 2: terminal ephemeral cleanup driven by the (ephemeral, status)
    // index, never a config scan.
    if !report.timed_out {
        let candidates = sandbox_entity::Entity::find()
            .filter(sandbox_entity::Column::Ephemeral.eq(true))
            .filter(sandbox_entity::Column::Status.is_in([
                sandbox_entity::SandboxStatus::Stopped,
                sandbox_entity::SandboxStatus::Crashed,
            ]))
            .order_by_asc(sandbox_entity::Column::Id)
            .limit(limits.max_terminal_ephemeral)
            .all(db)
            .await?;

        for sandbox in candidates {
            if start.elapsed() >= limits.max_duration {
                report.timed_out = true;
                break;
            }
            match cleanup_terminal_ephemeral_sandbox(db, sandboxes_dir, sandbox.id).await {
                Ok(CleanupOutcome::Removed) => report.removed += 1,
                Ok(_) => {}
                Err(err) => {
                    report.errors += 1;
                    tracing::debug!(sandbox = %sandbox.name, error = %err, "ephemeral cleanup failed");
                }
            }
        }
    }

    Ok(report)
}

/// Remove a single terminal ephemeral sandbox's persisted state.
///
/// Idempotent and race-safe: the row is claimed with a conditional delete, so
/// concurrent callers produce exactly one [`CleanupOutcome::Removed`] and the
/// rest see [`CleanupOutcome::AlreadyClaimed`] / [`CleanupOutcome::AlreadyGone`].
/// Usable both from the runtime exit observer (self-clean) and the startup
/// sweep.
pub async fn cleanup_terminal_ephemeral_sandbox(
    db: &DbWriteConnection,
    sandboxes_dir: &Path,
    sandbox_id: i32,
) -> RuntimeResult<CleanupOutcome> {
    let Some(sandbox) = sandbox_entity::Entity::find_by_id(sandbox_id)
        .one(db)
        .await?
    else {
        return Ok(CleanupOutcome::AlreadyGone);
    };

    if !sandbox.ephemeral {
        return Ok(CleanupOutcome::SkippedPersistent);
    }

    if !is_terminal(sandbox.status) {
        return Ok(CleanupOutcome::SkippedActive);
    }

    if has_live_active_run(db, sandbox.id).await? {
        return Ok(CleanupOutcome::SkippedLivePid);
    }

    // Remove the on-disk state before deleting the DB row. If this fails, the
    // DB row remains and the cleanup remains visible/retryable. Missing
    // directories count as success so a crash between directory removal and
    // row deletion is repaired by the next pass.
    let dir = sandboxes_dir.join(&sandbox.name);
    if let Err(err) = remove_dir_if_exists(&dir) {
        tracing::warn!(
            sandbox = %sandbox.name,
            dir = %dir.display(),
            error = %err,
            "ephemeral cleanup failed to remove sandbox directory; keeping row for retry"
        );
        return Ok(CleanupOutcome::DirRemoveFailed);
    }

    // Delete only while still ephemeral + terminal. Deleting the sandbox row
    // cascades to its run rows (FK ON DELETE CASCADE).
    let rows = sandbox_entity::Entity::delete_many()
        .filter(sandbox_entity::Column::Id.eq(sandbox.id))
        .filter(sandbox_entity::Column::Ephemeral.eq(true))
        .filter(sandbox_entity::Column::Status.is_in([
            sandbox_entity::SandboxStatus::Stopped,
            sandbox_entity::SandboxStatus::Crashed,
        ]))
        .exec(db)
        .await?
        .rows_affected;

    if rows == 0 {
        return Ok(CleanupOutcome::AlreadyClaimed);
    }

    Ok(CleanupOutcome::Removed)
}

//--------------------------------------------------------------------------------------------------
// Functions: Lease
//--------------------------------------------------------------------------------------------------

/// Attempt to acquire the lifecycle-maintenance lease without blocking.
///
/// Read-gates first: a cheap SELECT skips the write entirely when the lease is
/// currently held or a sweep completed within the last interval. Only a
/// genuinely stale lease triggers the conditional acquire write.
async fn try_acquire_lease(db: &DbWriteConnection) -> RuntimeResult<bool> {
    let now = chrono::Utc::now().naive_utc();
    let recent_cutoff = now - chrono::Duration::seconds(MIN_SWEEP_INTERVAL_SECS);

    let existing = lease_entity::Entity::find_by_id(lease_entity::SANDBOX_LIFECYCLE_MAINTENANCE)
        .one(db)
        .await?;

    if let Some(lease) = &existing {
        let held = lease.lease_expires_at > now;
        let recently_done = lease
            .last_completed_at
            .is_some_and(|completed| completed > recent_cutoff);
        if held || recently_done {
            return Ok(false);
        }
    } else {
        // Seed a claimable row. INSERT OR IGNORE: if another runtime seeded it
        // first, fall through to the conditional acquire below.
        let seed = lease_entity::ActiveModel {
            name: Set(lease_entity::SANDBOX_LIFECYCLE_MAINTENANCE.to_string()),
            holder_pid: Set(None),
            lease_expires_at: Set(now),
            last_completed_at: Set(None),
        };
        let insert = lease_entity::Entity::insert(seed)
            .on_conflict(
                OnConflict::column(lease_entity::Column::Name)
                    .do_nothing()
                    .to_owned(),
            )
            .exec(db)
            .await;
        match insert {
            Ok(_) => {}
            // No row inserted because of the conflict; expected under a race.
            Err(DbErr::RecordNotInserted) => {}
            Err(err) => return Err(err.into()),
        }
    }

    // Conditional acquire: claim only while expired AND not recently completed.
    let lease_deadline = now + chrono::Duration::seconds(LEASE_DURATION_SECS);
    let result = lease_entity::Entity::update_many()
        .col_expr(
            lease_entity::Column::HolderPid,
            Expr::value(std::process::id() as i32),
        )
        .col_expr(
            lease_entity::Column::LeaseExpiresAt,
            Expr::value(lease_deadline),
        )
        .filter(lease_entity::Column::Name.eq(lease_entity::SANDBOX_LIFECYCLE_MAINTENANCE))
        .filter(lease_entity::Column::LeaseExpiresAt.lte(now))
        .filter(
            Condition::any()
                .add(lease_entity::Column::LastCompletedAt.is_null())
                .add(lease_entity::Column::LastCompletedAt.lte(recent_cutoff)),
        )
        .exec(db)
        .await?;

    Ok(result.rows_affected == 1)
}

/// Record successful sweep completion so the read-gate suppresses redundant
/// sweeps for the next interval.
async fn record_completion(db: &DbWriteConnection) -> RuntimeResult<()> {
    let now = chrono::Utc::now().naive_utc();
    lease_entity::Entity::update_many()
        .col_expr(lease_entity::Column::LastCompletedAt, Expr::value(now))
        .col_expr(lease_entity::Column::HolderPid, Expr::value(None::<i32>))
        .filter(lease_entity::Column::Name.eq(lease_entity::SANDBOX_LIFECYCLE_MAINTENANCE))
        .exec(db)
        .await?;
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Reconcile one active sandbox whose owning runtime may have died. Returns
/// `true` when the sandbox was marked terminal.
async fn reconcile_stale_active(
    db: &DbWriteConnection,
    sandbox: &sandbox_entity::Model,
) -> RuntimeResult<bool> {
    let run = run_entity::Entity::find()
        .filter(run_entity::Column::SandboxId.eq(sandbox.id))
        .filter(run_entity::Column::Status.eq(run_entity::RunStatus::Running))
        .order_by_desc(run_entity::Column::StartedAt)
        .one(db)
        .await?;

    // No active run yet: the sandbox is still starting (its runtime has not
    // inserted a run row). Skip to avoid racing create/start.
    let Some(run) = run else {
        return Ok(false);
    };

    // NOTE: `pid_is_alive` treats zombies as dead, but still cannot
    // distinguish a genuinely live runtime from an unrelated process that
    // reused the PID after a reboot. A post-reboot stale row whose PID was
    // reused therefore stays Running until that PID exits. Addressing this
    // needs a boot-id or process-start-time check stored alongside the PID;
    // left as a known, pre-existing limitation.
    if run.pid.is_some_and(pid_is_alive) {
        return Ok(false);
    }

    let now = chrono::Utc::now().naive_utc();
    let (terminal_status, reason) = stale_runtime_terminal_state(sandbox.status);

    // Mark the dead run Terminated only while still Running.
    run_entity::Entity::update_many()
        .col_expr(
            run_entity::Column::Status,
            Expr::value(run_entity::RunStatus::Terminated),
        )
        .col_expr(run_entity::Column::TerminationReason, Expr::value(reason))
        .col_expr(run_entity::Column::TerminatedAt, Expr::value(now))
        .filter(run_entity::Column::Id.eq(run.id))
        .filter(run_entity::Column::Status.eq(run_entity::RunStatus::Running))
        .exec(db)
        .await?;

    // Reconcile only while still active so a concurrent lifecycle transition
    // is not clobbered.
    let result = sandbox_entity::Entity::update_many()
        .col_expr(sandbox_entity::Column::Status, Expr::value(terminal_status))
        .col_expr(sandbox_entity::Column::UpdatedAt, Expr::value(now))
        .filter(sandbox_entity::Column::Id.eq(sandbox.id))
        .filter(sandbox_entity::Column::Status.is_in([
            sandbox_entity::SandboxStatus::Running,
            sandbox_entity::SandboxStatus::Draining,
        ]))
        .exec(db)
        .await?;

    Ok(result.rows_affected > 0)
}

fn stale_runtime_terminal_state(
    status: sandbox_entity::SandboxStatus,
) -> (sandbox_entity::SandboxStatus, run_entity::TerminationReason) {
    match status {
        // Draining means a stop/drain request was already accepted. If the
        // owning runtime is now gone, the lifecycle reached its requested
        // terminal state even when the original observer could not reap it.
        sandbox_entity::SandboxStatus::Draining => (
            sandbox_entity::SandboxStatus::Stopped,
            run_entity::TerminationReason::ShutdownRequested,
        ),
        _ => (
            sandbox_entity::SandboxStatus::Crashed,
            run_entity::TerminationReason::InternalError,
        ),
    }
}

/// Whether the sandbox has any run that is still Running with a live PID.
async fn has_live_active_run(db: &DbWriteConnection, sandbox_id: i32) -> RuntimeResult<bool> {
    let runs = run_entity::Entity::find()
        .filter(run_entity::Column::SandboxId.eq(sandbox_id))
        .filter(run_entity::Column::Status.eq(run_entity::RunStatus::Running))
        .all(db)
        .await?;
    Ok(runs.iter().any(|run| run.pid.is_some_and(pid_is_alive)))
}

/// Whether a sandbox status is terminal (eligible for ephemeral cleanup).
fn is_terminal(status: sandbox_entity::SandboxStatus) -> bool {
    matches!(
        status,
        sandbox_entity::SandboxStatus::Stopped | sandbox_entity::SandboxStatus::Crashed
    )
}

/// Best-effort liveness probe for a PID. Zombies are treated as dead because
/// the runtime has exited even if its parent has not reaped the process yet.
fn pid_is_alive(pid: i32) -> bool {
    microsandbox_utils::process::pid_is_alive(pid)
}

/// Remove a directory tree, treating a missing directory as success.
fn remove_dir_if_exists(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use microsandbox_migration::{Migrator, MigratorTrait};
    use sea_orm::ActiveModelTrait;
    use tempfile::TempDir;

    use super::*;

    /// A PID that is essentially certain not to map to a live process.
    const DEAD_PID: i32 = 2_000_000_000;

    async fn test_db() -> (TempDir, DbWriteConnection) {
        let dir = tempfile::tempdir().unwrap();
        let db = DbWriteConnection::open(
            &dir.path().join("test.db"),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        Migrator::up(db.inner(), None).await.unwrap();
        (dir, db)
    }

    async fn insert_sandbox(
        db: &DbWriteConnection,
        name: &str,
        status: sandbox_entity::SandboxStatus,
        ephemeral: bool,
    ) -> i32 {
        let now = chrono::Utc::now().naive_utc();
        sandbox_entity::ActiveModel {
            name: Set(name.to_string()),
            config: Set("{}".to_string()),
            status: Set(status),
            ephemeral: Set(ephemeral),
            created_at: Set(Some(now)),
            updated_at: Set(Some(now)),
            ..Default::default()
        }
        .insert(db)
        .await
        .unwrap()
        .id
    }

    async fn insert_run(
        db: &DbWriteConnection,
        sandbox_id: i32,
        pid: Option<i32>,
        status: run_entity::RunStatus,
    ) {
        run_entity::ActiveModel {
            sandbox_id: Set(sandbox_id),
            pid: Set(pid),
            status: Set(status),
            started_at: Set(Some(chrono::Utc::now().naive_utc())),
            ..Default::default()
        }
        .insert(db)
        .await
        .unwrap();
    }

    async fn status_of(db: &DbWriteConnection, id: i32) -> Option<sandbox_entity::SandboxStatus> {
        sandbox_entity::Entity::find_by_id(id)
            .one(db)
            .await
            .unwrap()
            .map(|model| model.status)
    }

    #[tokio::test]
    async fn cleanup_removes_terminal_ephemeral_row_and_dir() {
        let (dir, db) = test_db().await;
        let id = insert_sandbox(&db, "eph", sandbox_entity::SandboxStatus::Stopped, true).await;
        let sandbox_dir = dir.path().join("eph");
        std::fs::create_dir_all(&sandbox_dir).unwrap();

        let outcome = cleanup_terminal_ephemeral_sandbox(&db, dir.path(), id)
            .await
            .unwrap();

        assert_eq!(outcome, CleanupOutcome::Removed);
        assert!(status_of(&db, id).await.is_none(), "row should be deleted");
        assert!(!sandbox_dir.exists(), "directory should be removed");
    }

    #[tokio::test]
    async fn cleanup_skips_persistent() {
        let (dir, db) = test_db().await;
        let id = insert_sandbox(&db, "keep", sandbox_entity::SandboxStatus::Stopped, false).await;

        let outcome = cleanup_terminal_ephemeral_sandbox(&db, dir.path(), id)
            .await
            .unwrap();

        assert_eq!(outcome, CleanupOutcome::SkippedPersistent);
        assert!(status_of(&db, id).await.is_some(), "row should remain");
    }

    #[tokio::test]
    async fn cleanup_skips_non_terminal() {
        let (dir, db) = test_db().await;
        let id = insert_sandbox(&db, "run", sandbox_entity::SandboxStatus::Running, true).await;

        let outcome = cleanup_terminal_ephemeral_sandbox(&db, dir.path(), id)
            .await
            .unwrap();

        assert_eq!(outcome, CleanupOutcome::SkippedActive);
        assert!(status_of(&db, id).await.is_some());
    }

    #[tokio::test]
    async fn cleanup_skips_when_run_pid_is_live() {
        let (dir, db) = test_db().await;
        let id = insert_sandbox(&db, "live", sandbox_entity::SandboxStatus::Stopped, true).await;
        // The current process is unquestionably alive.
        insert_run(
            &db,
            id,
            Some(std::process::id() as i32),
            run_entity::RunStatus::Running,
        )
        .await;

        let outcome = cleanup_terminal_ephemeral_sandbox(&db, dir.path(), id)
            .await
            .unwrap();

        assert_eq!(outcome, CleanupOutcome::SkippedLivePid);
        assert!(status_of(&db, id).await.is_some());
    }

    #[tokio::test]
    async fn cleanup_second_call_is_no_op() {
        let (dir, db) = test_db().await;
        let id = insert_sandbox(&db, "eph", sandbox_entity::SandboxStatus::Stopped, true).await;

        assert_eq!(
            cleanup_terminal_ephemeral_sandbox(&db, dir.path(), id)
                .await
                .unwrap(),
            CleanupOutcome::Removed
        );
        assert_eq!(
            cleanup_terminal_ephemeral_sandbox(&db, dir.path(), id)
                .await
                .unwrap(),
            CleanupOutcome::AlreadyGone
        );
    }

    #[tokio::test]
    async fn lease_is_read_gated_while_held() {
        let (_dir, db) = test_db().await;
        // First attempt seeds + acquires.
        assert!(try_acquire_lease(&db).await.unwrap());
        // Second attempt is skipped by the read-gate: the lease is still held.
        assert!(!try_acquire_lease(&db).await.unwrap());
    }

    #[tokio::test]
    async fn lease_is_read_gated_after_recent_completion() {
        let (_dir, db) = test_db().await;
        assert!(try_acquire_lease(&db).await.unwrap());
        record_completion(&db).await.unwrap();
        // Even though the holder released, a completion within the interval
        // suppresses the next sweep.
        assert!(!try_acquire_lease(&db).await.unwrap());
    }

    #[tokio::test]
    async fn lease_is_reacquirable_once_stale() {
        let (_dir, db) = test_db().await;
        assert!(try_acquire_lease(&db).await.unwrap());

        // Force the lease stale: expired and with no recent completion.
        let past = chrono::Utc::now().naive_utc() - chrono::Duration::seconds(120);
        lease_entity::Entity::update_many()
            .col_expr(lease_entity::Column::LeaseExpiresAt, Expr::value(past))
            .col_expr(
                lease_entity::Column::LastCompletedAt,
                Expr::value(None::<chrono::NaiveDateTime>),
            )
            .filter(lease_entity::Column::Name.eq(lease_entity::SANDBOX_LIFECYCLE_MAINTENANCE))
            .exec(&db)
            .await
            .unwrap();

        assert!(try_acquire_lease(&db).await.unwrap());
    }

    #[tokio::test]
    async fn sweep_reconciles_dead_active_and_cleans_terminal_ephemeral() {
        let (dir, db) = test_db().await;

        // Persistent Running sandbox with a dead PID should become Crashed.
        let dead = insert_sandbox(&db, "dead", sandbox_entity::SandboxStatus::Running, false).await;
        insert_run(&db, dead, Some(DEAD_PID), run_entity::RunStatus::Running).await;

        // Persistent Draining sandbox with a dead PID completed a requested stop.
        let draining = insert_sandbox(
            &db,
            "draining",
            sandbox_entity::SandboxStatus::Draining,
            false,
        )
        .await;
        insert_run(
            &db,
            draining,
            Some(DEAD_PID),
            run_entity::RunStatus::Running,
        )
        .await;

        // Ephemeral Stopped sandbox should be removed in phase 2.
        let eph = insert_sandbox(&db, "eph", sandbox_entity::SandboxStatus::Stopped, true).await;
        std::fs::create_dir_all(dir.path().join("eph")).unwrap();

        let report =
            run_sandbox_lifecycle_maintenance(&db, dir.path(), MaintenanceLimits::default())
                .await
                .unwrap();

        assert_eq!(report.reconciled, 2);
        assert_eq!(report.removed, 1);
        assert_eq!(report.errors, 0);
        assert_eq!(
            status_of(&db, dead).await,
            Some(sandbox_entity::SandboxStatus::Crashed)
        );
        assert_eq!(
            status_of(&db, draining).await,
            Some(sandbox_entity::SandboxStatus::Stopped)
        );
        assert!(status_of(&db, eph).await.is_none());
        assert!(!dir.path().join("eph").exists());
    }
}

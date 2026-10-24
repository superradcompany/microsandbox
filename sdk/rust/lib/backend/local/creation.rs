//! Durable ownership for incomplete local creates. Callers retain namespace and runtime locks.

use std::fs::File;
use std::future::Future;
use std::sync::Arc;

use microsandbox_db::DbWriteConnection;
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};

use super::LocalBackend;
use crate::sandbox::{SandboxStatus, remove_dir_if_exists};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Evidence held by the caller before removing incomplete storage.
pub(crate) enum RemovalMode {
    /// Preparation returned an error; all awaited formatters have finished.
    PreparationFailed,
    /// The creator reached its cleanup guard and still owns the volume locks.
    Creator,
    /// A later explicit removal also acquires the provisional volume locks.
    Recovery,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Exclude removal while preparation or any of its filesystem workers still owns the name.
/// Never unlink this lock file: another process may already have the same inode open.
pub(crate) fn lock_preparation(local: &LocalBackend, name: &str) -> MicrosandboxResult<Arc<File>> {
    let path =
        microsandbox_runtime::ipc::sandbox_transition_lock_path(&local.config().run_dir(), name)
            .with_extension("creation.lock");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = microsandbox_utils::process_lock::open_lock_file(&path)?;
    if !microsandbox_utils::process_lock::try_lock_exclusive(&file)? {
        return Err(MicrosandboxError::Runtime(format!(
            "sandbox {name:?} preparation is still finishing; retry removal after its filesystem work completes"
        )));
    }
    Ok(Arc::new(file))
}

/// Scope preparation ownership so every dispatched filesystem worker can retain it on cancellation.
pub(crate) fn preparing<F: Future>(guard: Arc<File>, future: F) -> impl Future<Output = F::Output> {
    PREPARATION.scope(guard, Box::pin(future))
}

/// Dispatch preparation filesystem work without releasing its removal fence on future cancellation.
/// Outside preparation this has the same behavior as Tokio's blocking dispatcher.
pub(crate) fn spawn_blocking<F, R>(work: F) -> tokio::task::JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let guard = PREPARATION.try_with(Arc::clone).ok();
    tokio::task::spawn_blocking(move || {
        let _guard = guard;
        work()
    })
}

/// Whether an unfinished create still owns this sandbox.
pub(crate) async fn pending<C: ConnectionTrait>(db: &C, id: i32) -> MicrosandboxResult<bool> {
    // Runtime processes may operate an older catalog without applying SDK migrations.
    if !microsandbox_db::catalog::has_column(db, "sandbox", "creation_state").await? {
        return Ok(false);
    }
    Ok(db
        .query_one_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "SELECT id FROM sandbox WHERE id = ? AND creation_state IS NOT NULL",
            [id.into()],
        ))
        .await?
        .is_some())
}

/// Reject starting an incomplete sandbox, including after a process crash.
pub(crate) async fn require_complete<C: ConnectionTrait>(
    db: &C,
    id: i32,
    name: &str,
) -> MicrosandboxResult<()> {
    if pending(db, id).await? {
        return Err(MicrosandboxError::InvalidConfig(format!(
            "sandbox {name:?} has an incomplete creation or cleanup; remove or replace it before starting"
        )));
    }
    Ok(())
}

/// Prevent another sandbox or a direct volume handle from adopting provisional storage.
pub(crate) async fn require_volume_available<C: ConnectionTrait>(
    db: &C,
    volume_id: i32,
    creator: Option<&str>,
) -> MicrosandboxResult<()> {
    if !microsandbox_db::catalog::has_column(db, "volume", "pending_creation_sandbox_id").await? {
        return Ok(());
    }
    let row = db.query_one_raw(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "SELECT sandbox.name FROM volume JOIN sandbox ON sandbox.id = volume.pending_creation_sandbox_id WHERE volume.id = ?",
        [volume_id.into()],
    )).await?;
    if let Some(row) = row {
        let name: String = row.try_get("", "name")?;
        if creator != Some(name.as_str()) {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "volume belongs to incomplete sandbox {name:?}; remove or complete that sandbox before using the volume"
            )));
        }
    }
    Ok(())
}

/// Retire recovery ownership only after successful publication or a recoverable stopped boot.
pub(crate) async fn complete(
    db: &DbWriteConnection,
    id: i32,
    status: SandboxStatus,
) -> MicrosandboxResult<()> {
    db.transaction(|txn| async move {
        // Read the current desired configuration in the same transaction as publication.
        let row = txn.query_one_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "SELECT config FROM sandbox WHERE id = ?",
            [id.into()],
        )).await?.ok_or_else(|| MicrosandboxError::Runtime("creation owner disappeared".into()))?;
        let config: crate::sandbox::SandboxConfig =
            serde_json::from_str(&row.try_get::<String>("", "config")?)?;
        let expected = if status == SandboxStatus::Running {
            "status = 'Starting'"
        } else {
            "status IN ('Starting', 'Running', 'Stopped', 'Crashed')"
        };
        let updated = txn.execute_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            format!("UPDATE sandbox SET status = ?, ephemeral = ?, creation_state = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND creation_state IS NOT NULL AND {expected}"),
            [status.into(), config.spec.lifecycle.ephemeral.into(), id.into()],
        )).await?;
        if updated.rows_affected() != 1 {
            return Err(MicrosandboxError::Runtime(
                "sandbox lost its creation state before publication".into(),
            ));
        }
        txn.execute_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "UPDATE volume SET pending_creation_sandbox_id = NULL WHERE pending_creation_sandbox_id = ?",
            [id.into()],
        )).await?;
        Ok::<_, MicrosandboxError>((txn, ()))
    }).await?;
    Ok(())
}

/// Preserve the previous stopped-sandbox behavior only after preparation completed and no new
/// named volumes require rollback. A crash never calls this; its recovery record remains armed.
pub(crate) async fn can_retain(db: &DbWriteConnection, id: i32) -> MicrosandboxResult<bool> {
    Ok(db.query_one_raw(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "SELECT id FROM sandbox WHERE id = ? AND creation_state = 'prepared' AND NOT EXISTS (SELECT 1 FROM volume WHERE pending_creation_sandbox_id = ?)",
        [id.into(), id.into()],
    )).await?.is_some())
}

/// Remove files first, then atomically release all catalog ownership. On any failure the records
/// remain so explicit removal can retry, including when some files are already absent.
/// The caller owns the sandbox transition and lifecycle guards. Recovery also excludes a live
/// preparation worker: a cancelled async task may leave a blocking formatter running.
pub(crate) async fn remove(
    local: &LocalBackend,
    id: i32,
    name: &str,
    mode: RemovalMode,
) -> MicrosandboxResult<()> {
    let pools = local.db().await?;
    let _preparation = lock_preparation(local, name)?;

    let rows = pools
        .write()
        .query_all_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "SELECT id, name FROM volume WHERE pending_creation_sandbox_id = ? ORDER BY name",
            [id.into()],
        ))
        .await?;
    let mut locks = Vec::new();
    let mut volumes = Vec::new();
    for row in rows {
        let volume_id: i32 = row.try_get("", "id")?;
        let volume_name: String = row.try_get("", "name")?;
        crate::volume::validate_volume_name(&volume_name)?;
        if !matches!(mode, RemovalMode::Creator) {
            locks.push(crate::volume::lock_volume_name(local, &volume_name).await?);
        }
        volumes.push((volume_id, volume_name));
    }

    // Keep volume rows until every deletion succeeds. They prevent name reuse during recovery.
    for (_, volume_name) in &volumes {
        remove_dir_if_exists(&local.volume_path(volume_name))?;
    }
    crate::runtime::remove_sandbox_socket_artifacts_for(local, name)?;
    remove_dir_if_exists(&local.sandboxes_dir().join(name))?;

    pools
        .write()
        .transaction(|txn| {
            let volumes = volumes.clone();
            async move {
                txn.execute_raw(Statement::from_sql_and_values(
                    DatabaseBackend::Sqlite,
                    "UPDATE volume SET pending_creation_sandbox_id = NULL WHERE pending_creation_sandbox_id = ?",
                    [id.into()],
                ))
                .await?;
                for (volume_id, _) in volumes {
                    txn.execute_raw(Statement::from_sql_and_values(
                        DatabaseBackend::Sqlite,
                        "DELETE FROM volume WHERE id = ?",
                        [volume_id.into()],
                    ))
                    .await?;
                }
                txn.execute_raw(Statement::from_sql_and_values(
                    DatabaseBackend::Sqlite,
                    "UPDATE sandbox SET creation_state = NULL WHERE id = ? AND name = ?",
                    [id.into(), name.into()],
                ))
                .await?;
                txn.execute_raw(Statement::from_sql_and_values(
                    DatabaseBackend::Sqlite,
                    "DELETE FROM sandbox WHERE id = ? AND name = ?",
                    [id.into(), name.into()],
                ))
                .await?;
                Ok::<_, MicrosandboxError>((txn, ()))
            }
        })
        .await?;
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Macros
//--------------------------------------------------------------------------------------------------

tokio::task_local! {
    static PREPARATION: Arc<File>;
}

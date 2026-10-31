//! Durable ownership for incomplete local creates. Callers retain namespace and runtime locks.

use std::fs::File;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use microsandbox_db::DbWriteConnection;
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};

use super::LocalBackend;
use crate::sandbox::{SandboxStatus, remove_dir_if_exists};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A creation-owned path. Cloning it retains storage ownership for background I/O.
/// The catalog owns the directory after a process crash; the live lease prevents
/// recovery from deleting it while a cancelled caller still has active workers.
#[derive(Clone)]
pub(crate) struct CreationStorage {
    path: PathBuf,
    owner: StorageOwner,
}

#[derive(Clone)]
enum StorageOwner {
    Reserved {
        _lock: Arc<File>,
    },
    #[cfg(test)]
    Temporary {
        _directory: Arc<tempfile::TempDir>,
    },
    #[cfg(test)]
    Fixture,
}

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
// Methods
//--------------------------------------------------------------------------------------------------

impl CreationStorage {
    /// Exclude removal while preparation or any of its filesystem workers still owns the name.
    /// Never unlink this lock file: another process may already have the same inode open.
    pub(crate) fn acquire(local: &LocalBackend, name: &str) -> MicrosandboxResult<Self> {
        let path = microsandbox_runtime::ipc::sandbox_transition_lock_path(
            &local.config().run_dir(),
            name,
        )
        .with_extension("creation.lock");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = microsandbox_utils::process_lock::open_lock_file(&path)?;
        if !microsandbox_utils::process_lock::try_lock_exclusive(&file)? {
            return Err(MicrosandboxError::Runtime(format!(
                "sandbox {name:?} preparation is still finishing; retry after its filesystem work completes"
            )));
        }
        Ok(Self {
            path: local.sandboxes_dir().join(name),
            owner: StorageOwner::Reserved {
                _lock: Arc::new(file),
            },
        })
    }

    /// Bind another resource already reserved by this operation to the same owner.
    pub(crate) fn at(&self, path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            owner: self.owner.clone(),
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(test)]
    pub(crate) fn temporary(directory: Arc<tempfile::TempDir>) -> Self {
        Self {
            path: directory.path().to_path_buf(),
            owner: StorageOwner::Temporary {
                _directory: directory,
            },
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            owner: StorageOwner::Fixture,
        }
    }
}

impl LocalBackend {
    /// Remove files first, then atomically release all catalog ownership. On any failure the records
    /// remain so explicit removal can retry, including when some files are already absent.
    /// The caller owns the sandbox transition and lifecycle guards. Recovery also excludes a live
    /// preparation worker: a cancelled async task may leave a blocking formatter running.
    pub(crate) async fn remove_incomplete_sandbox(
        &self,
        id: i32,
        name: &str,
        mode: RemovalMode,
    ) -> MicrosandboxResult<()> {
        let pools = self.db().await?;
        let preparation = CreationStorage::acquire(self, name)?;

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
                locks.push(crate::volume::lock_volume_name(self, &volume_name).await?);
            }
            volumes.push((volume_id, volume_name));
        }

        // Keep volume rows until every deletion succeeds. They prevent name reuse during recovery.
        let paths = volumes
            .iter()
            .map(|(_, name)| self.volume_path(name))
            .collect::<Vec<_>>();
        let run_dir = self.config().run_dir();
        let sandboxes_dir = self.sandboxes_dir();
        let sandbox_name = name.to_owned();
        let worker_storage = preparation.clone();

        tokio::task::spawn_blocking(move || -> MicrosandboxResult<()> {
            let _storage = worker_storage;
            let _volume_locks = locks;
            for path in paths {
                remove_dir_if_exists(&path)?;
            }

            crate::runtime::remove_socket_artifacts_at(&run_dir, &sandboxes_dir, &sandbox_name)?;

            remove_dir_if_exists(&sandboxes_dir.join(sandbox_name))?;
            Ok(())
        })
        .await
        .map_err(|error| {
            MicrosandboxError::Runtime(format!("creation cleanup worker: {error}"))
        })??;

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
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Deref for CreationStorage {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.path
    }
}

impl AsRef<Path> for CreationStorage {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

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

/// Reject using an incomplete sandbox, including after a process crash.
pub(crate) async fn require_complete<C: ConnectionTrait>(
    db: &C,
    id: i32,
    name: &str,
) -> MicrosandboxResult<()> {
    if pending(db, id).await? {
        return Err(MicrosandboxError::InvalidConfig(format!(
            "sandbox {name:?} has an incomplete creation or cleanup; remove or replace it before using it"
        )));
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

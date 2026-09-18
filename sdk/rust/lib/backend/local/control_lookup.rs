//! Read-only lookup for a live control target, without unrelated snapshot reconciliation.

use std::time::Duration;

use microsandbox_db::DbReadConnection;
use microsandbox_migration::schema_metadata;
use sea_orm::{ColumnTrait, ConnectionTrait, DatabaseBackend, EntityTrait, QueryFilter, Statement};

use super::{
    LocalBackend, acquire_migration_lock, refuse_incomplete_self_downgrade, refuse_schema_ahead,
};
use crate::db::entity::sandbox as sandbox_entity;
use crate::sandbox::SandboxStatus;
use crate::sandbox::identity::SandboxRunIdentity;
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LocalBackend {
    /// Select the exact live run while the caller owns the name's transition guard.
    pub(crate) async fn control_run_identity(
        &self,
        name: &str,
        expected_id: i32,
    ) -> MicrosandboxResult<SandboxRunIdentity> {
        if let Some((model, run)) = self.try_control_target(name).await? {
            if model.id != expected_id {
                return Err(MicrosandboxError::SandboxReplaced {
                    name: name.into(),
                    expected: format!("local:{expected_id}"),
                    actual: format!("local:{}", model.id),
                });
            }
            return Ok(run);
        }
        let (model, _) = self.sandbox_handle_state(name, Some(expected_id)).await?;
        let run = Self::load_active_run(self.db().await?.read(), model.id).await?;
        let run = run
            .filter(|run| run.pid.is_some_and(Self::pid_is_alive))
            .ok_or_else(|| {
                MicrosandboxError::SandboxNotRunning(format!(
                    "sandbox {name:?} has no live runtime"
                ))
            })?;
        Ok(SandboxRunIdentity {
            sandbox_id: model.id,
            run_id: run.id,
            pid: run.pid.expect("live run has a PID"),
        })
    }

    /// A runtime restart must not redirect a control request selected for its predecessor.
    pub(crate) async fn validate_control_run(
        &self,
        name: &str,
        expected: SandboxRunIdentity,
    ) -> MicrosandboxResult<()> {
        let current = self.control_run_identity(name, expected.sandbox_id).await?;
        if current != expected {
            return Err(MicrosandboxError::Runtime(format!(
                "sandbox {name:?} changed runtime during control operation"
            )));
        }
        Ok(())
    }

    /// Return a healthy live target from a current catalog. `None` requests the existing
    /// migration/stale-runtime path; errors must never become an unvalidated fast path.
    pub(crate) async fn try_control_handle_state(
        &self,
        name: &str,
    ) -> MicrosandboxResult<Option<(sandbox_entity::Model, Option<i32>)>> {
        Ok(self
            .try_control_target(name)
            .await?
            .map(|(model, run)| (model, Some(run.pid))))
    }

    /// Keep authoritative control selection on the same read-only path as CLI lookup.
    async fn try_control_target(
        &self,
        name: &str,
    ) -> MicrosandboxResult<Option<(sandbox_entity::Model, SandboxRunIdentity)>> {
        let db_dir = self.config().home().join(microsandbox_utils::DB_SUBDIR);
        let db_path = db_dir.join(microsandbox_utils::DB_FILENAME);
        match std::fs::metadata(&db_path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        // Use the same installation coordination as the slow path. In particular, a rolled
        // back database can look current while an incomplete downgrade still owns its files.
        let _migration_lock = acquire_migration_lock(&db_dir).await?;
        refuse_incomplete_self_downgrade(&db_dir)?;
        let database = &self.config().database;
        let read = if let Some(pools) = self.db.get() {
            pools.read().clone()
        } else {
            DbReadConnection::open_read_only(
                &db_path,
                Duration::from_secs(database.connect_timeout_secs),
                Duration::from_secs(database.busy_timeout_secs),
            )
            .await
            .map_err(|error| {
                MicrosandboxError::Custom(format!(
                    "read control catalog {}: {error}",
                    db_path.display()
                ))
            })?
        };
        microsandbox_runtime::maintenance::refuse_if_install_exclusive_held(&read)
            .await
            .map_err(|error| MicrosandboxError::Runtime(error.to_string()))?;
        refuse_schema_ahead(read.inner()).await?;
        let row = match read
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(*) FROM seaql_migrations",
            ))
            .await
        {
            Ok(Some(row)) => row,
            Ok(None) => return Ok(None),
            Err(error) if super::is_missing_migrations_table(&error) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if row.try_get_by_index::<i64>(0)? != schema_metadata::migration_ids().count() as i64 {
            return Ok(None);
        }
        let model = sandbox_entity::Entity::find()
            .filter(sandbox_entity::Column::Name.eq(name))
            .one(&read)
            .await?
            .ok_or_else(|| MicrosandboxError::SandboxNotFound(name.into()))?;
        if !matches!(
            model.status,
            SandboxStatus::Running | SandboxStatus::Draining
        ) {
            return Ok(None);
        }
        let run = Self::load_active_run(&read, model.id).await?;
        let pid = Self::pid_from_run(run.as_ref());
        // Do not clean up sockets from this read-only observation. The slow path rechecks
        // the exact row/run under lifecycle ownership before touching stale artifacts.
        if let (Some(run), Some(pid)) = (run, pid) {
            let identity = SandboxRunIdentity {
                sandbox_id: model.id,
                run_id: run.id,
                pid,
            };
            Ok(Some((model, identity)))
        } else {
            Ok(None)
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    async fn fixture() -> (tempfile::TempDir, LocalBackend) {
        let home = tempfile::tempdir().unwrap();
        let backend = crate::test_support::local_backend(crate::config::GlobalConfig {
            home: Some(home.path().to_path_buf()),
            ..Default::default()
        });
        let pools = backend.db().await.unwrap();
        pools.write().execute_unprepared(
            "INSERT INTO sandbox (id, name, config, status, ephemeral) VALUES (1, 'source', '{}', 'Running', 0)",
        ).await.unwrap();
        pools
            .write()
            .execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "INSERT INTO run (sandbox_id, pid, status) VALUES (1, ?, 'Running')",
                [i64::from(std::process::id()).into()],
            ))
            .await
            .unwrap();
        (home, backend)
    }

    #[tokio::test]
    async fn healthy_lookup_does_not_initialize_writer_or_reconcile_snapshots() {
        let (home, _) = fixture().await;
        // A non-directory snapshot path would fail normal reconciliation. The live
        // control path has no reason to inspect it or mutate the target's catalog.
        let snapshots = home.path().join("snapshots");
        if snapshots.exists() {
            std::fs::remove_dir(&snapshots).unwrap();
        }
        std::fs::write(&snapshots, b"unrelated snapshot inventory").unwrap();
        let backend = crate::test_support::local_backend(crate::config::GlobalConfig {
            home: Some(home.path().to_path_buf()),
            ..Default::default()
        });
        let (model, pid) = backend
            .try_control_handle_state("source")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(model.id, 1);
        assert_eq!(pid, Some(std::process::id() as i32));
        assert!(backend.db.get().is_none());
        let run = backend
            .control_run_identity("source", model.id)
            .await
            .unwrap();
        backend.validate_control_run("source", run).await.unwrap();
        assert!(
            backend.db.get().is_none(),
            "control run validation must stay read-only"
        );
        assert_eq!(
            std::fs::read(snapshots).unwrap(),
            b"unrelated snapshot inventory"
        );
    }

    #[tokio::test]
    async fn branch_refuses_a_restarted_source_before_writing_handoff_state() {
        let (home, backend) = fixture().await;
        let selected = backend.control_run_identity("source", 1).await.unwrap();
        let writer = backend.db().await.unwrap().write();
        writer
            .execute_unprepared("UPDATE run SET status = 'Terminated' WHERE sandbox_id = 1")
            .await
            .unwrap();
        writer
            .execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "INSERT INTO run (sandbox_id, pid, status) VALUES (1, ?, 'Running')",
                [i64::from(std::process::id()).into()],
            ))
            .await
            .unwrap();
        assert_ne!(
            selected.run_id,
            backend
                .control_run_identity("source", 1)
                .await
                .unwrap()
                .run_id
        );
        let mut child = crate::sandbox::SandboxConfig::default();
        child.spec.name = "child".into();
        let child_dir = home.path().join("child");
        std::fs::create_dir(&child_dir).unwrap();
        let result = crate::sandbox::branch::capture_child(
            &backend,
            &mut child,
            &crate::sandbox::identity::BranchSource {
                guest_flush: None,
                batch: None,
                record_integrity: false,
                name: "source".into(),
                run: selected,
            },
            &child_dir,
        )
        .await;
        assert!(result.unwrap_err().to_string().contains("changed runtime"));
        assert_eq!(std::fs::read_dir(child_dir).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn absent_catalog_and_terminal_target_request_slow_path() {
        let home = tempfile::tempdir().unwrap();
        let empty = crate::test_support::local_backend(crate::config::GlobalConfig {
            home: Some(home.path().to_path_buf()),
            ..Default::default()
        });
        assert!(
            empty
                .try_control_handle_state("source")
                .await
                .unwrap()
                .is_none()
        );
        assert!(!home.path().join("db").exists());
        let (_home, backend) = fixture().await;
        backend
            .db()
            .await
            .unwrap()
            .write()
            .execute_unprepared("UPDATE sandbox SET status = 'Stopped' WHERE id = 1")
            .await
            .unwrap();
        assert!(
            backend
                .try_control_handle_state("source")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn schema_and_install_gates_are_not_bypassed() {
        let (home, backend) = fixture().await;
        let writer = backend.db().await.unwrap().write();
        writer.execute_unprepared(
            "INSERT INTO seaql_migrations (version, applied_at) VALUES ('future_unknown_migration', 0)",
        ).await.unwrap();
        assert!(
            backend
                .try_control_handle_state("source")
                .await
                .unwrap_err()
                .to_string()
                .contains("schema is newer")
        );
        writer
            .execute_unprepared(
                "DELETE FROM seaql_migrations WHERE version = 'future_unknown_migration'",
            )
            .await
            .unwrap();
        writer.execute_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
                "INSERT OR REPLACE INTO maintenance_lease (name, holder_pid, lease_expires_at) VALUES ('install_exclusive', ?, ?)",
            [(std::process::id() as i32).into(), (chrono::Utc::now().naive_utc() + chrono::Duration::minutes(10)).into()],
        )).await.unwrap();
        assert!(
            backend
                .try_control_handle_state("source")
                .await
                .unwrap_err()
                .to_string()
                .contains("install operation in progress")
        );
        writer
            .execute_unprepared("DELETE FROM maintenance_lease WHERE name = 'install_exclusive'")
            .await
            .unwrap();
        let journal_dir = home.path().join("db/self-downgrade/test-operation");
        std::fs::create_dir_all(&journal_dir).unwrap();
        std::fs::write(
            journal_dir.join("journal.json"),
            br#"{"phase":"preparing"}"#,
        )
        .unwrap();
        assert!(
            backend
                .try_control_handle_state("source")
                .await
                .unwrap_err()
                .to_string()
                .contains("self_downgrade_recovery_required")
        );
    }

    #[tokio::test]
    async fn older_schema_and_missing_active_run_fall_back_without_cleanup() {
        let (home, backend) = fixture().await;
        let writer = backend.db().await.unwrap().write();
        writer
            .execute_unprepared("DELETE FROM run WHERE sandbox_id = 1")
            .await
            .unwrap();
        let runtime = home.path().join("sandboxes/source/runtime");
        std::fs::create_dir_all(&runtime).unwrap();
        let hint = runtime.join("runtime-boot-id");
        std::fs::write(&hint, b"do-not-clean-during-observation").unwrap();
        assert!(
            backend
                .try_control_handle_state("source")
                .await
                .unwrap()
                .is_none()
        );
        assert!(hint.exists());
        let last = schema_metadata::migration_ids().last().unwrap();
        writer
            .execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "DELETE FROM seaql_migrations WHERE version = ?",
                [last.into()],
            ))
            .await
            .unwrap();
        assert!(
            backend
                .try_control_handle_state("source")
                .await
                .unwrap()
                .is_none()
        );
        assert!(hint.exists());
    }
}

//! Retain standalone volume ownership until preparation or cleanup completes.

use sea_orm_migration::{
    prelude::*,
    sea_orm::{DatabaseBackend, Statement},
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Track unfinished standalone volumes without changing existing volume rows.
#[derive(DeriveMigrationName)]
pub struct Migration;

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Downgrade must drop this CHECK before the sandbox-creation migration drops its referenced column.
        manager.get_connection().execute_unprepared(
            "ALTER TABLE volume ADD COLUMN creation_state TEXT DEFAULT NULL
                CHECK (creation_state IS NULL OR (creation_state = 'creating' AND pending_creation_sandbox_id IS NULL));
             CREATE TRIGGER standalone_volume_no_delete BEFORE DELETE ON volume
             WHEN OLD.creation_state IS NOT NULL
             BEGIN SELECT RAISE(ABORT, 'incomplete volume creation; finish cleanup before deleting'); END;"
        ).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let pending = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT id FROM volume WHERE creation_state IS NOT NULL LIMIT 1",
            ))
            .await?;
        if pending.is_some() {
            return Err(DbErr::Migration(
                "unfinished volume creation remains; remove the incomplete volumes before downgrading".into(),
            ));
        }

        db.execute_unprepared("DROP TRIGGER standalone_volume_no_delete; ALTER TABLE volume DROP COLUMN creation_state;").await?;
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use sea_orm_migration::sea_orm::Database;

    use super::*;
    use crate::{Migrator, MigratorTrait};

    #[tokio::test]
    async fn interrupted_volume_blocks_deletion_and_downgrade_until_cleanup() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        let position = Migrator::migrations()
            .iter()
            .position(|m| m.name() == Migration.name())
            .unwrap();
        Migrator::up(&db, Some(position as u32)).await.unwrap();
        db.execute_unprepared("INSERT INTO volume (name, kind) VALUES ('existing', 'directory')")
            .await
            .unwrap();
        Migrator::up(&db, Some(1)).await.unwrap();

        db.execute_unprepared(
            "INSERT INTO sandbox (id, name, config, status, ephemeral, creation_state)
            VALUES (1, 'owner', '{}', 'Starting', 0, 'preparing');",
        )
        .await
        .unwrap();
        assert!(
            db.execute_unprepared(
                "INSERT INTO volume (name, kind, creation_state, pending_creation_sandbox_id)
            VALUES ('conflicting', 'directory', 'creating', 1)"
            )
            .await
            .is_err()
        );
        db.execute_unprepared("INSERT INTO volume (name, kind, pending_creation_sandbox_id) VALUES ('owned', 'directory', 1)").await.unwrap();
        assert!(
            db.execute_unprepared("UPDATE volume SET creation_state='creating' WHERE name='owned'")
                .await
                .is_err()
        );
        db.execute_unprepared("UPDATE volume SET pending_creation_sandbox_id=NULL WHERE name='owned'; DELETE FROM volume WHERE name='owned';
            UPDATE sandbox SET creation_state=NULL WHERE id=1; DELETE FROM sandbox WHERE id=1;").await.unwrap();

        // Existing writers can still update completed volumes after the upgrade.
        db.execute_unprepared("UPDATE volume SET quota_mib = 128 WHERE name = 'existing';
            INSERT INTO volume (name, kind, creation_state) VALUES ('interrupted', 'disk', 'creating');").await.unwrap();
        assert!(
            db.execute_unprepared("DELETE FROM volume WHERE name = 'interrupted'")
                .await
                .is_err()
        );
        assert!(
            Migrator::down(&db, Some(1))
                .await
                .unwrap_err()
                .to_string()
                .contains("unfinished volume creation")
        );

        db.execute_unprepared(
            "BEGIN; UPDATE volume SET creation_state = NULL WHERE name = 'interrupted';
            DELETE FROM volume WHERE name = 'interrupted'; ROLLBACK;",
        )
        .await
        .unwrap();
        assert!(
            Migrator::down(&db, Some(1)).await.is_err(),
            "rolled-back cleanup must retain recovery state"
        );

        db.execute_unprepared(
            "BEGIN; UPDATE volume SET creation_state = NULL WHERE name = 'interrupted';
            DELETE FROM volume WHERE name = 'interrupted'; COMMIT;",
        )
        .await
        .unwrap();
        Migrator::down(&db, Some(2)).await.unwrap();
        let row = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT quota_mib FROM volume WHERE name = 'existing'",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.try_get::<i32>("", "quota_mib").unwrap(), 128);
    }
}

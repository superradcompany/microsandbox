//! Track unfinished sandbox creation without releasing ownership before file cleanup.

use sea_orm_migration::{
    prelude::*,
    sea_orm::{DatabaseBackend, Statement},
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Persist create intent and the exact named volumes created by it.
pub struct Migration;

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261024_000001_sandbox_creation"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        db.execute_unprepared(
            "ALTER TABLE sandbox ADD COLUMN creation_state TEXT DEFAULT NULL
                CHECK (creation_state IS NULL OR creation_state IN ('preparing', 'prepared'));
            ALTER TABLE volume ADD COLUMN pending_creation_sandbox_id INTEGER DEFAULT NULL
                REFERENCES sandbox(id) ON DELETE RESTRICT;
            CREATE INDEX volume_pending_creation ON volume(pending_creation_sandbox_id);
            CREATE TRIGGER sandbox_creation_no_restart BEFORE UPDATE OF status ON sandbox
            WHEN NEW.status IN ('Starting', 'Running') AND OLD.status IN ('Created', 'Stopped', 'Crashed')
                 AND OLD.creation_state IS NOT NULL
            BEGIN SELECT RAISE(ABORT, 'incomplete sandbox creation; remove or replace it before starting'); END;
            CREATE TRIGGER sandbox_creation_no_delete BEFORE DELETE ON sandbox
            WHEN OLD.creation_state IS NOT NULL
            BEGIN SELECT RAISE(ABORT, 'incomplete sandbox creation; finish cleanup before deleting'); END;
            CREATE TRIGGER volume_creation_no_delete BEFORE DELETE ON volume
            WHEN OLD.pending_creation_sandbox_id IS NOT NULL
            BEGIN SELECT RAISE(ABORT, 'incomplete volume creation; finish cleanup before deleting'); END;",
        ).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let pending = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT id FROM sandbox WHERE creation_state IS NOT NULL UNION ALL SELECT pending_creation_sandbox_id FROM volume WHERE pending_creation_sandbox_id IS NOT NULL LIMIT 1",
            ))
            .await?;
        if pending.is_some() {
            return Err(DbErr::Migration(
                "unfinished sandbox creation remains; remove the incomplete sandboxes before downgrading".into(),
            ));
        }
        db.execute_unprepared("DROP TRIGGER sandbox_creation_no_restart; DROP TRIGGER sandbox_creation_no_delete; DROP TRIGGER volume_creation_no_delete; DROP INDEX volume_pending_creation; ALTER TABLE volume DROP COLUMN pending_creation_sandbox_id; ALTER TABLE sandbox DROP COLUMN creation_state;").await?;
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Migrator, MigratorTrait};
    use sea_orm_migration::sea_orm::Database;

    #[tokio::test]
    async fn pending_creation_blocks_restart_deletion_and_downgrade() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        db.execute_unprepared("PRAGMA foreign_keys=ON")
            .await
            .unwrap();
        Migrator::up(
            &db,
            Some(
                (Migrator::migrations()
                    .iter()
                    .position(|m| m.name() == Migration.name())
                    .unwrap()
                    + 1) as u32,
            ),
        )
        .await
        .unwrap();
        db.execute_unprepared(
            "INSERT INTO sandbox (id, name, config, status, ephemeral) VALUES (1, 'incomplete', '{}', 'Crashed', 0);
             UPDATE sandbox SET creation_state='preparing' WHERE id=1;
             INSERT INTO volume (id, name, kind) VALUES (1, 'new', 'directory');
             UPDATE volume SET pending_creation_sandbox_id=1 WHERE id=1;",
        ).await.unwrap();

        assert!(
            db.execute_unprepared("UPDATE sandbox SET status='Running' WHERE id=1")
                .await
                .unwrap_err()
                .to_string()
                .contains("incomplete sandbox creation")
        );
        assert!(
            db.execute_unprepared("DELETE FROM sandbox WHERE id=1")
                .await
                .is_err()
        );
        assert!(
            db.execute_unprepared("DELETE FROM volume WHERE id=1")
                .await
                .is_err()
        );
        assert!(
            Migrator::down(&db, Some(1))
                .await
                .unwrap_err()
                .to_string()
                .contains("unfinished sandbox creation")
        );
        assert!(
            db.query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT * FROM volume WHERE pending_creation_sandbox_id=1"
            ))
            .await
            .unwrap()
            .is_some()
        );

        // The foreign key independently protects the root even after its marker is cleared.
        db.execute_unprepared("UPDATE sandbox SET creation_state=NULL WHERE id=1")
            .await
            .unwrap();
        assert!(
            db.execute_unprepared("DELETE FROM sandbox WHERE id=1")
                .await
                .is_err()
        );
        assert!(Migrator::down(&db, Some(1)).await.is_err());

        db.execute_unprepared("UPDATE volume SET pending_creation_sandbox_id=NULL WHERE pending_creation_sandbox_id=1; UPDATE sandbox SET creation_state=NULL WHERE id=1")
            .await
            .unwrap();
        db.execute_unprepared("UPDATE sandbox SET status='Running' WHERE id=1")
            .await
            .unwrap();
        Migrator::down(&db, Some(1)).await.unwrap();
    }

    #[tokio::test]
    async fn upgrade_and_downgrade_preserve_existing_resources() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        db.execute_unprepared("PRAGMA foreign_keys=ON")
            .await
            .unwrap();
        Migrator::up(
            &db,
            Some(
                Migrator::migrations()
                    .iter()
                    .position(|m| m.name() == Migration.name())
                    .unwrap() as u32,
            ),
        )
        .await
        .unwrap();
        db.execute_unprepared(
            "INSERT INTO sandbox (id, name, config, status, ephemeral) VALUES (1, 'existing', '{}', 'Running', 0);
             INSERT INTO volume (id, name, kind) VALUES (1, 'shared', 'directory');"
        ).await.unwrap();

        Migrator::up(&db, Some(1)).await.unwrap();
        db.execute_unprepared("UPDATE sandbox SET status='Stopped' WHERE id=1")
            .await
            .unwrap();
        let row = db.query_one_raw(Statement::from_string(DatabaseBackend::Sqlite,
            "SELECT sandbox.creation_state, volume.pending_creation_sandbox_id FROM sandbox JOIN volume ON volume.id=sandbox.id WHERE sandbox.id=1"
        )).await.unwrap().unwrap();
        assert_eq!(
            row.try_get::<Option<String>>("", "creation_state").unwrap(),
            None
        );
        assert_eq!(
            row.try_get::<Option<i32>>("", "pending_creation_sandbox_id")
                .unwrap(),
            None
        );

        Migrator::down(&db, Some(1)).await.unwrap();
        let row = db.query_one_raw(Statement::from_string(DatabaseBackend::Sqlite,
            "SELECT sandbox.name, sandbox.status, volume.name AS volume_name FROM sandbox JOIN volume ON volume.id=sandbox.id WHERE sandbox.id=1"
        )).await.unwrap().unwrap();
        assert_eq!(row.try_get::<String>("", "name").unwrap(), "existing");
        assert_eq!(row.try_get::<String>("", "status").unwrap(), "Stopped");
        assert_eq!(row.try_get::<String>("", "volume_name").unwrap(), "shared");
        Migrator::up(&db, Some(1)).await.unwrap();
    }
}

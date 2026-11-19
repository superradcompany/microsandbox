//! Persist SDK-observed process identity without changing the runtime's run model.

use sea_orm_migration::{
    prelude::*,
    sea_orm::{DatabaseBackend, Statement},
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(DeriveMigrationName)]
pub struct Migration;

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // NULL means unknown. Older runtimes can continue their named-column writes.
        manager
            .get_connection()
            .execute_unprepared("ALTER TABLE run ADD COLUMN process_identity TEXT DEFAULT NULL;")
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        // A terminal row does not prove process teardown. Do not discard identity
        // evidence here. The SDK retires finished identities under runtime-resource
        // guards; safe sandbox removal also cascades its runs.
        if db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT id FROM run WHERE process_identity IS NOT NULL LIMIT 1",
            ))
            .await?
            .is_some()
        {
            return Err(DbErr::Migration("recorded process identities remain; use the newer SDK to stop and inspect their sandboxes, or remove them safely, before downgrading".into()));
        }
        db.execute_unprepared("ALTER TABLE run DROP COLUMN process_identity;")
            .await?;
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
    async fn old_named_column_writes_survive_upgrade_and_downgrade_preserves_evidence() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        let count = Migrator::migrations().len();
        Migrator::up(&db, Some((count - 1) as u32)).await.unwrap();
        db.execute_unprepared("INSERT INTO sandbox (id, name, config, status, ephemeral) VALUES (1, 'compat', '{}', 'Running', 0);
            INSERT INTO run (id, sandbox_id, pid, status) VALUES (1, 1, 1234, 'Running');").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        let row = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT process_identity FROM run WHERE id = 1",
            ))
            .await
            .unwrap()
            .unwrap();
        assert!(row.try_get_by_index::<Option<String>>(0).unwrap().is_none());
        db.execute_unprepared(
            "UPDATE run SET process_identity = '{\"version\":1}' WHERE id = 1;
            UPDATE run SET status = 'Terminated', exit_code = 0 WHERE id = 1;
            INSERT INTO run (id, sandbox_id, pid, status) VALUES (2, 1, 5678, 'Running');",
        )
        .await
        .unwrap();
        assert!(
            Migrator::down(&db, Some(1))
                .await
                .unwrap_err()
                .to_string()
                .contains("identities remain")
        );
        let row = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT process_identity FROM run WHERE id = 1",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            row.try_get_by_index::<String>(0).unwrap(),
            "{\"version\":1}"
        );
        db.execute_unprepared("DELETE FROM run;").await.unwrap();
        Migrator::down(&db, Some(1)).await.unwrap();
        db.execute_unprepared(
            "INSERT INTO run (sandbox_id, pid, status) VALUES (1, 9012, 'Running');",
        )
        .await
        .unwrap();
    }
}

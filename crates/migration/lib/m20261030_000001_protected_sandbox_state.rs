//! Keep protected and migrating sandbox storage out of old catalog readers' reach.

use sea_orm_migration::{
    prelude::*,
    sea_orm::{DatabaseBackend, Statement},
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Record protection independently of mutable saved/active configuration payloads.
#[derive(DeriveMigrationName)]
pub struct Migration;

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "CREATE TABLE protected_sandbox_state (
                sandbox_id INTEGER PRIMARY KEY REFERENCES sandbox(id) ON DELETE CASCADE,
                layout_version INTEGER NOT NULL CHECK (layout_version = 1)
            );",
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        // This query also runs against downgrade's isolated database copy, before replacing
        // binaries. Keep unfinished migrations registered even when filesystem admission fails.
        if db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT sandbox_id FROM protected_sandbox_state LIMIT 1",
            ))
            .await?
            .is_some()
        {
            return Err(DbErr::Migration("protected sandbox state requires a patched SDK and runtime; remove protected or migrating sandboxes before downgrading".into()));
        }
        db.execute_unprepared("DROP TABLE protected_sandbox_state")
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
    async fn protection_blocks_downgrade_until_owned_storage_is_removed() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        db.execute_unprepared("INSERT INTO sandbox (id, name, config, status, ephemeral) VALUES (1, 'protected', '{}', 'Stopped', 0);
            INSERT INTO protected_sandbox_state VALUES (1, 1);").await.unwrap();
        assert!(
            Migrator::down(&db, Some(1))
                .await
                .unwrap_err()
                .to_string()
                .contains("protected sandbox state")
        );
        // Ordinary running-runtime writes remain representable after the catalog upgrade.
        db.execute_unprepared("UPDATE sandbox SET status='Stopped' WHERE id=1")
            .await
            .unwrap();
        db.execute_unprepared("DELETE FROM sandbox WHERE id=1")
            .await
            .unwrap();
        Migrator::down(&db, Some(1)).await.unwrap();
    }
}

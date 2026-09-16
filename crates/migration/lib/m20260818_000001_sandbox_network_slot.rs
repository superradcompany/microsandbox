//! Migration: persist each sandbox's assigned network address-pool slot.
//!
//! The slot used to be derived live from the sandbox's AUTOINCREMENT id,
//! which only ever grows and permanently exhausted the u16 slot space on
//! long-lived hosts (#1390). Slots are now recycled, and the assigned slot is
//! persisted on the row for the lifetime of the active run, so occupancy
//! reflects what is actually held rather than what the id counter implies.
//! Existing active rows backfill from their id where it fits the pool,
//! preserving their current addressing through the upgrade. Terminal rows do
//! not reserve slots.

use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::{DatabaseBackend, Statement};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const ADD_COLUMN: &str = "
    ALTER TABLE sandbox
    ADD COLUMN network_slot INTEGER
    CHECK (
        network_slot IS NULL OR (
            typeof(network_slot) = 'integer'
            AND network_slot BETWEEN 1 AND 65535
        )
    );
";

const BACKFILL_FROM_ID: &str = "
    UPDATE sandbox
    SET network_slot = id
    WHERE id BETWEEN 1 AND 65535
      AND status IN ('Starting', 'Running', 'Draining', 'Paused');
";

const CLEAR_INACTIVE_LEASES: &str = "
    UPDATE sandbox
    SET network_slot = NULL
    WHERE network_slot IS NOT NULL
      AND status IN ('Created', 'Stopped', 'Crashed');
";

const CREATE_UNIQUE_INDEX: &str = "
    CREATE UNIQUE INDEX IF NOT EXISTS idx_sandbox_network_slot_unique
    ON sandbox (network_slot)
    WHERE network_slot IS NOT NULL;
";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub struct Migration;

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260818_000001_sandbox_network_slot"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let connection = manager.get_connection();

        // Idempotent: `down` deliberately leaves the column in place (SQLite
        // DROP COLUMN is not available on every supported version), so a
        // rollback that removes the migration record followed by a re-upgrade
        // must not fail on the duplicate column. Probe PRAGMA first.
        let has_column = !connection
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT 1 FROM pragma_table_info('sandbox') WHERE name = 'network_slot'".to_owned(),
            ))
            .await?
            .is_empty();
        if !has_column {
            connection.execute_unprepared(ADD_COLUMN).await?;
            // Active rows whose id already fits the u16 pool keep the
            // addressing of their current run. Terminal rows and active rows
            // past the cap stay NULL and receive a recycled slot when started.
            connection.execute_unprepared(BACKFILL_FROM_ID).await?;
        }

        // Clearing inactive rows here repairs leases left by an older runtime
        // that stopped after a rollback preserved the column.
        connection.execute_unprepared(CLEAR_INACTIVE_LEASES).await?;

        // Keep the index creation outside the column guard so a rollback and
        // re-upgrade repairs an interrupted migration without overwriting any
        // assignments made after the first upgrade.
        connection.execute_unprepared(CREATE_UNIQUE_INDEX).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // SQLite has no DROP COLUMN on every supported version; recreating
        // the table to shed one column is out of proportion for a host-local
        // schema. The column is harmless when unused; `up` probes for it so
        // a re-upgrade after this rollback succeeds.
        let _ = manager;
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use sea_orm_migration::sea_orm::{Database, DatabaseConnection};

    use super::*;

    async fn open_catalog() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        db.execute_unprepared(
            "CREATE TABLE sandbox (id INTEGER PRIMARY KEY, status TEXT NOT NULL);",
        )
        .await
        .unwrap();
        db
    }

    #[tokio::test]
    async fn migration_backfills_valid_ids_and_enforces_slot_invariants() {
        let db = open_catalog().await;
        db.execute_unprepared(
            "INSERT INTO sandbox (id, status) VALUES
             (1, 'Running'), (65535, 'Stopped'), (70000, 'Running');",
        )
        .await
        .unwrap();

        Migration.up(&SchemaManager::new(&db)).await.unwrap();
        // A rollback leaves the column in place, so reapplying must still
        // ensure the unique index exists without overwriting assignments.
        Migration.up(&SchemaManager::new(&db)).await.unwrap();

        let rows = db
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT id, network_slot FROM sandbox ORDER BY id".to_owned(),
            ))
            .await
            .unwrap();
        let slots: Vec<(i32, Option<u16>)> = rows
            .into_iter()
            .map(|row| {
                (
                    row.try_get_by_index(0).unwrap(),
                    row.try_get_by_index(1).unwrap(),
                )
            })
            .collect();
        assert_eq!(slots, vec![(1, Some(1)), (65_535, None), (70_000, None)]);

        db.execute_unprepared("UPDATE sandbox SET network_slot = 2 WHERE id = 70000;")
            .await
            .unwrap();
        assert!(
            db.execute_unprepared("UPDATE sandbox SET network_slot = 0 WHERE id = 70000;")
                .await
                .is_err()
        );
        assert!(
            db.execute_unprepared("UPDATE sandbox SET network_slot = 65536 WHERE id = 70000;",)
                .await
                .is_err()
        );
        assert!(
            db.execute_unprepared("UPDATE sandbox SET network_slot = 1.5 WHERE id = 70000;")
                .await
                .is_err()
        );
        assert!(
            db.execute_unprepared("UPDATE sandbox SET network_slot = 1 WHERE id = 70000;")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn migration_repairs_leases_left_on_inactive_rows() {
        let db = open_catalog().await;
        db.execute_unprepared("INSERT INTO sandbox (id, status) VALUES (1, 'Running');")
            .await
            .unwrap();
        Migration.up(&SchemaManager::new(&db)).await.unwrap();

        // Simulate an older runtime stopping after the migration backfill but
        // before that runtime knew to clear network_slot itself.
        db.execute_unprepared("UPDATE sandbox SET status = 'Stopped' WHERE id = 1;")
            .await
            .unwrap();
        Migration.up(&SchemaManager::new(&db)).await.unwrap();

        let slot = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT network_slot FROM sandbox WHERE id = 1".to_owned(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index::<Option<u16>>(0)
            .unwrap();
        assert_eq!(slot, None);
    }
}

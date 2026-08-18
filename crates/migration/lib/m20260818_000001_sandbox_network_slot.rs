//! Migration: persist each sandbox's assigned network address-pool slot.
//!
//! The slot used to be derived live from the sandbox's AUTOINCREMENT id,
//! which only ever grows and permanently exhausted the u16 slot space on
//! long-lived hosts (#1390). Slots are now recycled, and the assigned slot is
//! persisted on the row so occupancy reflects what is actually held rather
//! than what the id counter implies. Existing rows backfill from their id
//! where it fits the pool, preserving every host's current addressing.

use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::{DatabaseBackend, Statement};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const ADD_COLUMN: &str = "ALTER TABLE sandbox ADD COLUMN network_slot INTEGER;";

const BACKFILL_FROM_ID: &str = "
    UPDATE sandbox
    SET network_slot = id
    WHERE id BETWEEN 1 AND 65535;
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
            // Rows whose id already fits the u16 pool keep exactly the
            // addressing they had; rows past the cap (hosts that hit #1390)
            // stay NULL and receive a recycled slot on their next spawn.
            connection.execute_unprepared(BACKFILL_FROM_ID).await?;
        }

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

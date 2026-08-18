//! Migration: persist each sandbox's assigned network address-pool slot.
//!
//! The slot used to be derived live from the sandbox's AUTOINCREMENT id,
//! which only ever grows and permanently exhausted the u16 slot space on
//! long-lived hosts (#1390). Slots are now recycled, and the assigned slot is
//! persisted on the row so occupancy reflects what is actually held rather
//! than what the id counter implies. Existing rows backfill from their id
//! where it fits the pool, preserving every host's current addressing.

use sea_orm_migration::prelude::*;

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

        connection.execute_unprepared(ADD_COLUMN).await?;
        // Rows whose id already fits the u16 pool keep exactly the addressing
        // they had; rows past the cap (hosts that hit #1390) stay NULL and
        // receive a recycled slot on their next spawn.
        connection.execute_unprepared(BACKFILL_FROM_ID).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // SQLite has no DROP COLUMN on every supported version; recreating
        // the table to shed one column is out of proportion for a host-local
        // schema. The column is harmless when unused.
        let _ = manager;
        Ok(())
    }
}

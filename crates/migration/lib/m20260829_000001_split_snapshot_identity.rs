//! Split stable snapshot identity from descriptor integrity in the rebuildable index.

use sea_orm_migration::prelude::*;

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
        let connection = manager.get_connection();
        connection
            .execute_unprepared("ALTER TABLE snapshot_index ADD COLUMN snapshot_id TEXT")
            .await?;
        connection
            .execute_unprepared("ALTER TABLE snapshot_index ADD COLUMN descriptor_digest TEXT")
            .await?;
        // Existing rows use the released descriptor digest as their provisional ID until their
        // artifact is opened and translated by the exact compatibility reader.
        connection
            .execute_unprepared(
                "UPDATE snapshot_index SET snapshot_id = digest, descriptor_digest = digest",
            )
            .await?;
        connection
            .execute_unprepared(
                "CREATE UNIQUE INDEX idx_snapshot_index_snapshot_id ON snapshot_index (snapshot_id)",
            )
            .await?;
        connection
            .execute_unprepared(
                "CREATE INDEX idx_snapshot_index_descriptor_digest ON snapshot_index (descriptor_digest)",
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let connection = manager.get_connection();
        connection
            .execute_unprepared("DROP INDEX IF EXISTS idx_snapshot_index_snapshot_id")
            .await?;
        connection
            .execute_unprepared("DROP INDEX IF EXISTS idx_snapshot_index_descriptor_digest")
            .await?;
        connection
            .execute_unprepared("ALTER TABLE snapshot_index DROP COLUMN snapshot_id")
            .await?;
        connection
            .execute_unprepared("ALTER TABLE snapshot_index DROP COLUMN descriptor_digest")
            .await?;
        Ok(())
    }
}

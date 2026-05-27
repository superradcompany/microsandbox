//! Migration: Drop the legacy `sandbox_metric` table.
//!
//! Live metrics moved to a shared-memory registry; the catalog no longer
//! stores per-sample rows. Existing data is discarded — there is no public
//! historical metrics API today.

use sea_orm_migration::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub struct Migration;

//--------------------------------------------------------------------------------------------------
// Types: Identifiers
//--------------------------------------------------------------------------------------------------

#[derive(Iden)]
enum SandboxMetric {
    Table,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260517_000001_drop_sandbox_metric"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(SandboxMetric::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // Live metrics no longer live in the catalog; reverting this
        // migration intentionally does nothing.
        Ok(())
    }
}

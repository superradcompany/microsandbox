//! Migration: Add `sandbox.active_config` for desired-vs-active config tracking.

use sea_orm_migration::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub struct Migration;

//--------------------------------------------------------------------------------------------------
// Types: Identifiers
//--------------------------------------------------------------------------------------------------

#[derive(Iden)]
enum Sandbox {
    Table,
    ActiveConfig,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260703_000001_add_sandbox_active_config"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Sandbox::Table)
                    .add_column(ColumnDef::new(Sandbox::ActiveConfig).text())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Sandbox::Table)
                    .drop_column(Sandbox::ActiveConfig)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

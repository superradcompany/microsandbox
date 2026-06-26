//! Migration: Add `sandbox.ephemeral` and index it with `status`.

use sea_orm_migration::prelude::*;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const IDX_SANDBOX_EPHEMERAL_STATUS: &str = "idx_sandbox_ephemeral_status";

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
    Status,
    Ephemeral,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260621_000001_add_sandbox_ephemeral"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Sandbox::Table)
                    .add_column(
                        ColumnDef::new(Sandbox::Ephemeral)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await?;

        // Index ephemeral lifecycle-maintenance lookups: terminal ephemeral
        // cleanup queries `ephemeral = true AND status IN (...)`.
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name(IDX_SANDBOX_EPHEMERAL_STATUS)
                    .table(Sandbox::Table)
                    .col(Sandbox::Ephemeral)
                    .col(Sandbox::Status)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .name(IDX_SANDBOX_EPHEMERAL_STATUS)
                    .table(Sandbox::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Sandbox::Table)
                    .drop_column(Sandbox::Ephemeral)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

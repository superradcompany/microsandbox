//! Migration: Index sandbox_labels on (key, value) for selector queries.

use sea_orm_migration::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub struct Migration;

//--------------------------------------------------------------------------------------------------
// Types: Identifiers
//--------------------------------------------------------------------------------------------------

#[derive(Iden)]
enum SandboxLabels {
    Table,
    Key,
    Value,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260531_000002_index_sandbox_labels_key_value"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_sandbox_labels_key_value")
                    .table(SandboxLabels::Table)
                    .col(SandboxLabels::Key)
                    .col(SandboxLabels::Value)
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
                    .name("idx_sandbox_labels_key_value")
                    .table(SandboxLabels::Table)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

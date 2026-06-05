//! Migration: Create the sandbox_labels table.

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
    Id,
}

#[derive(Iden)]
enum SandboxLabels {
    Table,
    SandboxId,
    Key,
    Value,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260531_000001_create_sandbox_labels"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(SandboxLabels::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(SandboxLabels::SandboxId)
                            .integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(SandboxLabels::Key).text().not_null())
                    .col(ColumnDef::new(SandboxLabels::Value).text().not_null())
                    .primary_key(
                        Index::create()
                            .col(SandboxLabels::SandboxId)
                            .col(SandboxLabels::Key),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(SandboxLabels::Table, SandboxLabels::SandboxId)
                            .to(Sandbox::Table, Sandbox::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_sandbox_labels_sandbox_id")
                    .table(SandboxLabels::Table)
                    .col(SandboxLabels::SandboxId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(SandboxLabels::Table).to_owned())
            .await?;
        Ok(())
    }
}

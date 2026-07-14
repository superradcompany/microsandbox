//! Migration: Add snapshot payload scope to the local snapshot index.

use sea_orm_migration::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub struct Migration;

//--------------------------------------------------------------------------------------------------
// Types: Identifiers
//--------------------------------------------------------------------------------------------------

#[derive(Iden)]
enum SnapshotIndex {
    Table,
    Scope,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260714_000001_add_snapshot_scope"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(SnapshotIndex::Table)
                    .add_column(
                        ColumnDef::new(SnapshotIndex::Scope)
                            .text()
                            .not_null()
                            .default("disk"),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(SnapshotIndex::Table)
                    .drop_column(SnapshotIndex::Scope)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

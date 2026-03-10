//! Migration: Create storage tables (volumes, snapshots).

use sea_orm_migration::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub struct Migration;

//--------------------------------------------------------------------------------------------------
// Types: Identifiers
//--------------------------------------------------------------------------------------------------

#[derive(Iden)]
enum Volume {
    Table,
    Id,
    Name,
    QuotaMib,
    SizeBytes,
    Labels,
    CreatedAt,
    UpdatedAt,
}

#[derive(Iden)]
enum Snapshot {
    Table,
    Id,
    Name,
    SandboxId,
    SizeBytes,
    Description,
    CreatedAt,
}

/// Reference to the sandbox table (defined in migration 2).
#[derive(Iden)]
enum Sandbox {
    Table,
    Id,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260305_000003_create_storage_tables"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // volumes
        manager
            .create_table(
                Table::create()
                    .table(Volume::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Volume::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Volume::Name).text().not_null().unique_key())
                    .col(ColumnDef::new(Volume::QuotaMib).integer())
                    .col(ColumnDef::new(Volume::SizeBytes).big_integer())
                    .col(ColumnDef::new(Volume::Labels).text())
                    .col(ColumnDef::new(Volume::CreatedAt).date_time())
                    .col(ColumnDef::new(Volume::UpdatedAt).date_time())
                    .to_owned(),
            )
            .await?;

        // snapshots
        manager
            .create_table(
                Table::create()
                    .table(Snapshot::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Snapshot::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Snapshot::Name).text().not_null())
                    .col(ColumnDef::new(Snapshot::SandboxId).integer())
                    .col(ColumnDef::new(Snapshot::SizeBytes).big_integer())
                    .col(ColumnDef::new(Snapshot::Description).text())
                    .col(ColumnDef::new(Snapshot::CreatedAt).date_time())
                    .foreign_key(
                        ForeignKey::create()
                            .from(Snapshot::Table, Snapshot::SandboxId)
                            .to(Sandbox::Table, Sandbox::Id)
                            .on_delete(ForeignKeyAction::SetNull),
                    )
                    .to_owned(),
            )
            .await?;

        // Unique index on snapshots(name, sandbox_id) for sandbox-bound snapshots
        manager
            .create_index(
                Index::create()
                    .name("idx_snapshots_name_sandbox_unique")
                    .table(Snapshot::Table)
                    .col(Snapshot::Name)
                    .col(Snapshot::SandboxId)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // Partial unique index for sandbox-independent snapshots.
        // SQLite treats NULLs as distinct in unique indexes, so the composite
        // index above won't prevent duplicate names when sandbox_id IS NULL.
        manager
            .get_connection()
            .execute_unprepared(
                "CREATE UNIQUE INDEX idx_snapshots_name_unique_no_sandbox ON snapshot (name) WHERE sandbox_id IS NULL",
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Snapshot::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Volume::Table).to_owned())
            .await?;
        Ok(())
    }
}

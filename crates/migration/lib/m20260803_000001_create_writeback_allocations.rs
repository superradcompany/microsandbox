//! Migration: Create host-global writeback allocation state.

use sea_orm_migration::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub struct Migration;

#[derive(Iden)]
enum WritebackAllocation {
    Table,
    Id,
    RunId,
    LeaseName,
    PerDiskLimitBytes,
    DiskCount,
    ReservedBytes,
    PoolBytes,
    BootId,
    BackingDevices,
    CreatedAt,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260803_000001_create_writeback_allocations"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(WritebackAllocation::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(WritebackAllocation::Id)
                            .text()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(WritebackAllocation::RunId)
                            .integer()
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(WritebackAllocation::LeaseName)
                            .text()
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(WritebackAllocation::PerDiskLimitBytes)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(WritebackAllocation::DiskCount)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(WritebackAllocation::ReservedBytes)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(WritebackAllocation::PoolBytes)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(WritebackAllocation::BootId)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(WritebackAllocation::BackingDevices)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(WritebackAllocation::CreatedAt)
                            .date_time()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(WritebackAllocation::Table).to_owned())
            .await?;
        Ok(())
    }
}

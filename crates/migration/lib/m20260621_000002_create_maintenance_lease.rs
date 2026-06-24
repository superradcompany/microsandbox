//! Migration: Create the `maintenance_lease` coordination table.

use sea_orm_migration::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub struct Migration;

//--------------------------------------------------------------------------------------------------
// Types: Identifiers
//--------------------------------------------------------------------------------------------------

#[derive(Iden)]
enum MaintenanceLease {
    Table,
    Name,
    HolderPid,
    LeaseExpiresAt,
    LastCompletedAt,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260621_000002_create_maintenance_lease"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(MaintenanceLease::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(MaintenanceLease::Name)
                            .text()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(MaintenanceLease::HolderPid).integer())
                    .col(
                        ColumnDef::new(MaintenanceLease::LeaseExpiresAt)
                            .date_time()
                            .not_null(),
                    )
                    .col(ColumnDef::new(MaintenanceLease::LastCompletedAt).date_time())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(MaintenanceLease::Table).to_owned())
            .await?;
        Ok(())
    }
}

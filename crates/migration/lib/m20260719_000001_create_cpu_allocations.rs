//! Migration: Create cooperative host CPU allocation tables.

use sea_orm_migration::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub struct Migration;

#[derive(Iden)]
enum CpuAllocation {
    Table,
    Id,
    RunId,
    RequestedPolicy,
    ResolvedPolicy,
    Enforcement,
    TopologyFingerprint,
    LeaseName,
    State,
    CreatedAt,
}

#[derive(Iden)]
enum CpuAllocationCpu {
    Table,
    LogicalCpu,
    AllocationId,
    VcpuIndex,
    Role,
}

#[derive(Iden)]
enum Run {
    Table,
    Id,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260719_000001_create_cpu_allocations"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(CpuAllocation::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(CpuAllocation::Id)
                            .text()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(CpuAllocation::RunId)
                            .integer()
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(CpuAllocation::RequestedPolicy)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CpuAllocation::ResolvedPolicy)
                            .text()
                            .not_null(),
                    )
                    .col(ColumnDef::new(CpuAllocation::Enforcement).text().not_null())
                    .col(
                        ColumnDef::new(CpuAllocation::TopologyFingerprint)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CpuAllocation::LeaseName)
                            .text()
                            .not_null()
                            .unique_key(),
                    )
                    .col(ColumnDef::new(CpuAllocation::State).text().not_null())
                    .col(
                        ColumnDef::new(CpuAllocation::CreatedAt)
                            .date_time()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(CpuAllocation::Table, CpuAllocation::RunId)
                            .to(Run::Table, Run::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(CpuAllocationCpu::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(CpuAllocationCpu::LogicalCpu)
                            .integer()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(CpuAllocationCpu::AllocationId)
                            .text()
                            .not_null(),
                    )
                    .col(ColumnDef::new(CpuAllocationCpu::VcpuIndex).integer())
                    .col(ColumnDef::new(CpuAllocationCpu::Role).text().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .from(CpuAllocationCpu::Table, CpuAllocationCpu::AllocationId)
                            .to(CpuAllocation::Table, CpuAllocation::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_cpu_allocation_cpu_vcpu")
                    .table(CpuAllocationCpu::Table)
                    .col(CpuAllocationCpu::AllocationId)
                    .col(CpuAllocationCpu::VcpuIndex)
                    .unique()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(CpuAllocationCpu::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(CpuAllocation::Table).to_owned())
            .await?;
        Ok(())
    }
}

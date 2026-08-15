//! Migration: Add cooperative per-NUMA-node memory promises.

use sea_orm_migration::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub struct Migration;

#[derive(Iden)]
enum MemoryAllocationNode {
    Table,
    AllocationId,
    GuestNumaNode,
    HostNumaNode,
    BootMib,
    MaxMib,
}

#[derive(Iden)]
enum CpuAllocation {
    Table,
    Id,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260808_000001_create_memory_allocation_nodes"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(MemoryAllocationNode::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(MemoryAllocationNode::AllocationId)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(MemoryAllocationNode::GuestNumaNode)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(MemoryAllocationNode::HostNumaNode)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(MemoryAllocationNode::BootMib)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(MemoryAllocationNode::MaxMib)
                            .big_integer()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(MemoryAllocationNode::AllocationId)
                            .col(MemoryAllocationNode::GuestNumaNode),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(
                                MemoryAllocationNode::Table,
                                MemoryAllocationNode::AllocationId,
                            )
                            .to(CpuAllocation::Table, CpuAllocation::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_memory_allocation_node_host")
                    .table(MemoryAllocationNode::Table)
                    .col(MemoryAllocationNode::HostNumaNode)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(MemoryAllocationNode::Table).to_owned())
            .await
    }
}

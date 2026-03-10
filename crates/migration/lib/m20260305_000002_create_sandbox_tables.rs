//! Migration: Create sandbox tables (sandboxes, supervisors, microvms, msbnets, sandbox_metrics).

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
    Name,
    Config,
    Status,
    CreatedAt,
    UpdatedAt,
}

#[derive(Iden)]
enum Supervisor {
    Table,
    Id,
    SandboxId,
    Pid,
    Status,
    StartedAt,
    StoppedAt,
}

#[derive(Iden)]
enum Microvm {
    Table,
    Id,
    SandboxId,
    SupervisorId,
    Pid,
    Status,
    ExitCode,
    ExitSignal,
    TerminationReason,
    TerminationDetail,
    SignalsSent,
    StartedAt,
    TerminatedAt,
}

#[derive(Iden)]
enum Msbnet {
    Table,
    Id,
    SandboxId,
    SupervisorId,
    Pid,
    Status,
    StartedAt,
    StoppedAt,
}

#[derive(Iden)]
enum SandboxMetric {
    Table,
    Id,
    SandboxId,
    CpuPercent,
    MemoryBytes,
    DiskReadBytes,
    DiskWriteBytes,
    NetRxBytes,
    NetTxBytes,
    SampledAt,
    CreatedAt,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260305_000002_create_sandbox_tables"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // sandboxes
        manager
            .create_table(
                Table::create()
                    .table(Sandbox::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Sandbox::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Sandbox::Name).text().not_null().unique_key())
                    .col(ColumnDef::new(Sandbox::Config).text().not_null())
                    .col(ColumnDef::new(Sandbox::Status).text().not_null())
                    .col(ColumnDef::new(Sandbox::CreatedAt).date_time())
                    .col(ColumnDef::new(Sandbox::UpdatedAt).date_time())
                    .to_owned(),
            )
            .await?;

        // supervisors
        manager
            .create_table(
                Table::create()
                    .table(Supervisor::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Supervisor::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Supervisor::SandboxId).integer().not_null())
                    .col(ColumnDef::new(Supervisor::Pid).integer())
                    .col(ColumnDef::new(Supervisor::Status).text().not_null())
                    .col(ColumnDef::new(Supervisor::StartedAt).date_time())
                    .col(ColumnDef::new(Supervisor::StoppedAt).date_time())
                    .foreign_key(
                        ForeignKey::create()
                            .from(Supervisor::Table, Supervisor::SandboxId)
                            .to(Sandbox::Table, Sandbox::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // microvms
        manager
            .create_table(
                Table::create()
                    .table(Microvm::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Microvm::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Microvm::SandboxId).integer().not_null())
                    .col(ColumnDef::new(Microvm::SupervisorId).integer().not_null())
                    .col(ColumnDef::new(Microvm::Pid).integer())
                    .col(ColumnDef::new(Microvm::Status).text().not_null())
                    .col(ColumnDef::new(Microvm::ExitCode).integer())
                    .col(ColumnDef::new(Microvm::ExitSignal).integer())
                    .col(ColumnDef::new(Microvm::TerminationReason).text())
                    .col(ColumnDef::new(Microvm::TerminationDetail).text())
                    .col(ColumnDef::new(Microvm::SignalsSent).text())
                    .col(ColumnDef::new(Microvm::StartedAt).date_time())
                    .col(ColumnDef::new(Microvm::TerminatedAt).date_time())
                    .foreign_key(
                        ForeignKey::create()
                            .from(Microvm::Table, Microvm::SandboxId)
                            .to(Sandbox::Table, Sandbox::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(Microvm::Table, Microvm::SupervisorId)
                            .to(Supervisor::Table, Supervisor::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // msbnets
        manager
            .create_table(
                Table::create()
                    .table(Msbnet::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Msbnet::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Msbnet::SandboxId).integer().not_null())
                    .col(ColumnDef::new(Msbnet::SupervisorId).integer().not_null())
                    .col(ColumnDef::new(Msbnet::Pid).integer())
                    .col(ColumnDef::new(Msbnet::Status).text().not_null())
                    .col(ColumnDef::new(Msbnet::StartedAt).date_time())
                    .col(ColumnDef::new(Msbnet::StoppedAt).date_time())
                    .foreign_key(
                        ForeignKey::create()
                            .from(Msbnet::Table, Msbnet::SandboxId)
                            .to(Sandbox::Table, Sandbox::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(Msbnet::Table, Msbnet::SupervisorId)
                            .to(Supervisor::Table, Supervisor::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // sandbox_metrics
        manager
            .create_table(
                Table::create()
                    .table(SandboxMetric::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(SandboxMetric::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(SandboxMetric::SandboxId)
                            .integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(SandboxMetric::CpuPercent).float())
                    .col(ColumnDef::new(SandboxMetric::MemoryBytes).big_integer())
                    .col(ColumnDef::new(SandboxMetric::DiskReadBytes).big_integer())
                    .col(ColumnDef::new(SandboxMetric::DiskWriteBytes).big_integer())
                    .col(ColumnDef::new(SandboxMetric::NetRxBytes).big_integer())
                    .col(ColumnDef::new(SandboxMetric::NetTxBytes).big_integer())
                    .col(ColumnDef::new(SandboxMetric::SampledAt).date_time())
                    .col(ColumnDef::new(SandboxMetric::CreatedAt).date_time())
                    .foreign_key(
                        ForeignKey::create()
                            .from(SandboxMetric::Table, SandboxMetric::SandboxId)
                            .to(Sandbox::Table, Sandbox::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Composite index for time-range queries on sandbox metrics
        manager
            .create_index(
                Index::create()
                    .name("idx_sandbox_metrics_sandbox_sampled")
                    .table(SandboxMetric::Table)
                    .col(SandboxMetric::SandboxId)
                    .col(SandboxMetric::SampledAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(SandboxMetric::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Msbnet::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Microvm::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Supervisor::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Sandbox::Table).to_owned())
            .await?;
        Ok(())
    }
}

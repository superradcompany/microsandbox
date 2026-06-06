//! Migration: Add named volume kinds.

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
    Kind,
    CapacityBytes,
    DiskFormat,
    DiskFstype,
}

#[derive(Iden)]
enum VolumeAttach {
    Table,
    Id,
    VolumeId,
    SandboxId,
    Pid,
    Mode,
    CreatedAt,
}

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
        "m20260606_000001_named_volume_kinds"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Volume::Table)
                    .add_column(
                        ColumnDef::new(Volume::Kind)
                            .text()
                            .not_null()
                            .default("dir"),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Volume::Table)
                    .add_column(ColumnDef::new(Volume::CapacityBytes).big_integer())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Volume::Table)
                    .add_column(ColumnDef::new(Volume::DiskFormat).text())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Volume::Table)
                    .add_column(ColumnDef::new(Volume::DiskFstype).text())
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(VolumeAttach::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(VolumeAttach::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(VolumeAttach::VolumeId).integer().not_null())
                    .col(ColumnDef::new(VolumeAttach::SandboxId).integer())
                    .col(ColumnDef::new(VolumeAttach::Pid).integer().not_null())
                    .col(ColumnDef::new(VolumeAttach::Mode).text().not_null())
                    .col(
                        ColumnDef::new(VolumeAttach::CreatedAt)
                            .date_time()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(VolumeAttach::Table, VolumeAttach::VolumeId)
                            .to(Volume::Table, Volume::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(VolumeAttach::Table, VolumeAttach::SandboxId)
                            .to(Sandbox::Table, Sandbox::Id)
                            .on_delete(ForeignKeyAction::SetNull),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_volume_attach_volume_id")
                    .table(VolumeAttach::Table)
                    .col(VolumeAttach::VolumeId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(VolumeAttach::Table).to_owned())
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Volume::Table)
                    .drop_column(Volume::DiskFstype)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Volume::Table)
                    .drop_column(Volume::DiskFormat)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Volume::Table)
                    .drop_column(Volume::CapacityBytes)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Volume::Table)
                    .drop_column(Volume::Kind)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

//! Migration: Create sandbox_images join table for manifest pinning and safe image GC.

use sea_orm_migration::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub struct Migration;

//--------------------------------------------------------------------------------------------------
// Types: Identifiers
//--------------------------------------------------------------------------------------------------

#[derive(Iden)]
enum SandboxImage {
    Table,
    Id,
    SandboxId,
    ImageId,
    ManifestDigest,
    CreatedAt,
}

/// Reference to existing tables for foreign keys.
#[derive(Iden)]
enum Sandbox {
    Table,
    Id,
}

#[derive(Iden)]
enum Image {
    Table,
    Id,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260305_000004_create_sandbox_images_table"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(SandboxImage::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(SandboxImage::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(SandboxImage::SandboxId).integer().not_null())
                    .col(ColumnDef::new(SandboxImage::ImageId).integer().not_null())
                    .col(
                        ColumnDef::new(SandboxImage::ManifestDigest)
                            .text()
                            .not_null(),
                    )
                    .col(ColumnDef::new(SandboxImage::CreatedAt).date_time())
                    .foreign_key(
                        ForeignKey::create()
                            .from(SandboxImage::Table, SandboxImage::SandboxId)
                            .to(Sandbox::Table, Sandbox::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(SandboxImage::Table, SandboxImage::ImageId)
                            .to(Image::Table, Image::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Unique index: a sandbox can only reference each image once.
        manager
            .create_index(
                sea_orm_migration::prelude::Index::create()
                    .name("idx_sandbox_images_unique")
                    .table(SandboxImage::Table)
                    .col(SandboxImage::SandboxId)
                    .col(SandboxImage::ImageId)
                    .unique()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(SandboxImage::Table).to_owned())
            .await?;
        Ok(())
    }
}

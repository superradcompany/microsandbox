//! Migration: Replace image tables with EROFS-backed OCI rootfs schema.
//!
//! Drops old `image`, `index`, `sandbox_image` tables and recreates the image
//! pipeline schema for block-device-backed EROFS + guest overlayfs.

use sea_orm_migration::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types: Identifiers
//--------------------------------------------------------------------------------------------------

pub struct Migration;

// Old tables to drop.

#[derive(Iden)]
enum OldSandboxImage {
    #[iden = "sandbox_image"]
    Table,
}

#[derive(Iden)]
enum OldManifestLayer {
    #[iden = "manifest_layer"]
    Table,
}

#[derive(Iden)]
enum OldLayer {
    #[iden = "layer"]
    Table,
}

#[derive(Iden)]
enum OldConfig {
    #[iden = "config"]
    Table,
}

#[derive(Iden)]
enum OldManifest {
    #[iden = "manifest"]
    Table,
}

#[derive(Iden)]
enum OldIndex {
    #[iden = "index"]
    Table,
}

#[derive(Iden)]
enum OldImage {
    #[iden = "image"]
    Table,
}

// New tables.

#[derive(Iden)]
enum ImageRef {
    Table,
    Id,
    Reference,
    ManifestId,
    CreatedAt,
    UpdatedAt,
}

#[derive(Iden)]
enum Manifest {
    Table,
    Id,
    Digest,
    MediaType,
    ConfigDigest,
    Architecture,
    Os,
    Variant,
    LayerCount,
    TotalSizeBytes,
    CreatedAt,
}

#[derive(Iden)]
enum Config {
    Table,
    Id,
    ManifestId,
    Digest,
    Env,
    Cmd,
    Entrypoint,
    WorkingDir,
    User,
    Labels,
    StopSignal,
    CreatedAt,
}

#[derive(Iden)]
enum Layer {
    Table,
    Id,
    DiffId,
    BlobDigest,
    MediaType,
    CompressedSizeBytes,
    ErofsSizeBytes,
    CreatedAt,
    LastUsedAt,
}

#[derive(Iden)]
enum ManifestLayer {
    Table,
    Id,
    ManifestId,
    LayerId,
    Position,
}

#[derive(Iden)]
enum SandboxRootfs {
    Table,
    Id,
    SandboxId,
    ManifestId,
    Mode,
    UpperFstype,
    CreatedAt,
}

/// Reference to existing `sandbox` table for foreign keys.
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
        "m20260410_000001_erofs_image_schema"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // ── Drop old tables (FK-safe order) ──────────────────────────────

        manager
            .drop_table(
                Table::drop()
                    .table(OldSandboxImage::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(OldManifestLayer::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(OldLayer::Table).if_exists().to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(OldConfig::Table).if_exists().to_owned())
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(OldManifest::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(OldIndex::Table).if_exists().to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(OldImage::Table).if_exists().to_owned())
            .await?;

        // ── Create new tables ────────────────────────────────────────────

        // manifests (must exist before image_refs FK)
        manager
            .create_table(
                Table::create()
                    .table(Manifest::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Manifest::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Manifest::Digest)
                            .text()
                            .not_null()
                            .unique_key(),
                    )
                    .col(ColumnDef::new(Manifest::MediaType).text())
                    .col(ColumnDef::new(Manifest::ConfigDigest).text())
                    .col(ColumnDef::new(Manifest::Architecture).text())
                    .col(ColumnDef::new(Manifest::Os).text())
                    .col(ColumnDef::new(Manifest::Variant).text())
                    .col(ColumnDef::new(Manifest::LayerCount).integer())
                    .col(ColumnDef::new(Manifest::TotalSizeBytes).big_integer())
                    .col(ColumnDef::new(Manifest::CreatedAt).date_time())
                    .to_owned(),
            )
            .await?;

        // image_refs
        manager
            .create_table(
                Table::create()
                    .table(ImageRef::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ImageRef::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(ImageRef::Reference)
                            .text()
                            .not_null()
                            .unique_key(),
                    )
                    .col(ColumnDef::new(ImageRef::ManifestId).integer().not_null())
                    .col(ColumnDef::new(ImageRef::CreatedAt).date_time())
                    .col(ColumnDef::new(ImageRef::UpdatedAt).date_time())
                    .foreign_key(
                        ForeignKey::create()
                            .from(ImageRef::Table, ImageRef::ManifestId)
                            .to(Manifest::Table, Manifest::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // configs
        manager
            .create_table(
                Table::create()
                    .table(Config::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Config::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Config::ManifestId)
                            .integer()
                            .not_null()
                            .unique_key(),
                    )
                    .col(ColumnDef::new(Config::Digest).text().not_null())
                    .col(ColumnDef::new(Config::Env).text())
                    .col(ColumnDef::new(Config::Cmd).text())
                    .col(ColumnDef::new(Config::Entrypoint).text())
                    .col(ColumnDef::new(Config::WorkingDir).text())
                    .col(ColumnDef::new(Config::User).text())
                    .col(ColumnDef::new(Config::Labels).text())
                    .col(ColumnDef::new(Config::StopSignal).text())
                    .col(ColumnDef::new(Config::CreatedAt).date_time())
                    .foreign_key(
                        ForeignKey::create()
                            .from(Config::Table, Config::ManifestId)
                            .to(Manifest::Table, Manifest::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // layers
        manager
            .create_table(
                Table::create()
                    .table(Layer::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Layer::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Layer::DiffId).text().not_null().unique_key())
                    .col(ColumnDef::new(Layer::BlobDigest).text().not_null())
                    .col(ColumnDef::new(Layer::MediaType).text())
                    .col(ColumnDef::new(Layer::CompressedSizeBytes).big_integer())
                    .col(ColumnDef::new(Layer::ErofsSizeBytes).big_integer())
                    .col(ColumnDef::new(Layer::CreatedAt).date_time())
                    .col(ColumnDef::new(Layer::LastUsedAt).date_time())
                    .to_owned(),
            )
            .await?;

        // manifest_layers
        manager
            .create_table(
                Table::create()
                    .table(ManifestLayer::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ManifestLayer::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(ManifestLayer::ManifestId)
                            .integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(ManifestLayer::LayerId).integer().not_null())
                    .col(ColumnDef::new(ManifestLayer::Position).integer().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .from(ManifestLayer::Table, ManifestLayer::ManifestId)
                            .to(Manifest::Table, Manifest::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(ManifestLayer::Table, ManifestLayer::LayerId)
                            .to(Layer::Table, Layer::Id)
                            .on_delete(ForeignKeyAction::Restrict),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                sea_orm_migration::prelude::Index::create()
                    .name("idx_manifest_layers_manifest_position")
                    .table(ManifestLayer::Table)
                    .col(ManifestLayer::ManifestId)
                    .col(ManifestLayer::Position)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // sandbox_rootfs
        manager
            .create_table(
                Table::create()
                    .table(SandboxRootfs::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(SandboxRootfs::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(SandboxRootfs::SandboxId)
                            .integer()
                            .not_null()
                            .unique_key(),
                    )
                    .col(ColumnDef::new(SandboxRootfs::ManifestId).integer())
                    .col(ColumnDef::new(SandboxRootfs::Mode).text().not_null())
                    .col(ColumnDef::new(SandboxRootfs::UpperFstype).text())
                    .col(ColumnDef::new(SandboxRootfs::CreatedAt).date_time())
                    .foreign_key(
                        ForeignKey::create()
                            .from(SandboxRootfs::Table, SandboxRootfs::SandboxId)
                            .to(Sandbox::Table, Sandbox::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(SandboxRootfs::Table, SandboxRootfs::ManifestId)
                            .to(Manifest::Table, Manifest::Id)
                            .on_delete(ForeignKeyAction::Restrict),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(SandboxRootfs::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(ManifestLayer::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Layer::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Config::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(ImageRef::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Manifest::Table).to_owned())
            .await?;
        Ok(())
    }
}

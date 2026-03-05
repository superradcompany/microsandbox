//! Migration: Create image tables (images, indexes, manifests, configs, layers, manifest_layers).

use sea_orm_migration::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub struct Migration;

//--------------------------------------------------------------------------------------------------
// Types: Identifiers
//--------------------------------------------------------------------------------------------------

#[derive(Iden)]
enum Image {
    Table,
    Id,
    Reference,
    SizeBytes,
    LastUsedAt,
    CreatedAt,
}

#[derive(Iden)]
enum Index {
    Table,
    Id,
    ImageId,
    SchemaVersion,
    MediaType,
    PlatformOs,
    PlatformArch,
    PlatformVariant,
    Annotations,
    CreatedAt,
}

#[derive(Iden)]
enum Manifest {
    Table,
    Id,
    ImageId,
    IndexId,
    Digest,
    SchemaVersion,
    MediaType,
    Annotations,
    CreatedAt,
}

#[derive(Iden)]
enum Config {
    Table,
    Id,
    ManifestId,
    Digest,
    Architecture,
    Os,
    OsVariant,
    Env,
    Cmd,
    Entrypoint,
    WorkingDir,
    Volumes,
    ExposedPorts,
    User,
    RootfsType,
    RootfsDiffIds,
    History,
    CreatedAt,
}

#[derive(Iden)]
enum Layer {
    Table,
    Id,
    Digest,
    DiffId,
    MediaType,
    SizeBytes,
    CreatedAt,
}

#[derive(Iden)]
enum ManifestLayer {
    Table,
    Id,
    ManifestId,
    LayerId,
    Position,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260305_000001_create_image_tables"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // images
        manager
            .create_table(
                Table::create()
                    .table(Image::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Image::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Image::Reference)
                            .text()
                            .not_null()
                            .unique_key(),
                    )
                    .col(ColumnDef::new(Image::SizeBytes).big_integer())
                    .col(ColumnDef::new(Image::LastUsedAt).date_time())
                    .col(ColumnDef::new(Image::CreatedAt).date_time())
                    .to_owned(),
            )
            .await?;

        // indexes
        manager
            .create_table(
                Table::create()
                    .table(Index::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Index::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Index::ImageId).integer().not_null())
                    .col(ColumnDef::new(Index::SchemaVersion).integer())
                    .col(ColumnDef::new(Index::MediaType).text())
                    .col(ColumnDef::new(Index::PlatformOs).text())
                    .col(ColumnDef::new(Index::PlatformArch).text())
                    .col(ColumnDef::new(Index::PlatformVariant).text())
                    .col(ColumnDef::new(Index::Annotations).text())
                    .col(ColumnDef::new(Index::CreatedAt).date_time())
                    .foreign_key(
                        ForeignKey::create()
                            .from(Index::Table, Index::ImageId)
                            .to(Image::Table, Image::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // manifests
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
                    .col(ColumnDef::new(Manifest::ImageId).integer().not_null())
                    .col(ColumnDef::new(Manifest::IndexId).integer())
                    .col(
                        ColumnDef::new(Manifest::Digest)
                            .text()
                            .not_null()
                            .unique_key(),
                    )
                    .col(ColumnDef::new(Manifest::SchemaVersion).integer())
                    .col(ColumnDef::new(Manifest::MediaType).text())
                    .col(ColumnDef::new(Manifest::Annotations).text())
                    .col(ColumnDef::new(Manifest::CreatedAt).date_time())
                    .foreign_key(
                        ForeignKey::create()
                            .from(Manifest::Table, Manifest::ImageId)
                            .to(Image::Table, Image::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(Manifest::Table, Manifest::IndexId)
                            .to(Index::Table, Index::Id)
                            .on_delete(ForeignKeyAction::SetNull),
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
                    .col(ColumnDef::new(Config::Architecture).text())
                    .col(ColumnDef::new(Config::Os).text())
                    .col(ColumnDef::new(Config::OsVariant).text())
                    .col(ColumnDef::new(Config::Env).text())
                    .col(ColumnDef::new(Config::Cmd).text())
                    .col(ColumnDef::new(Config::Entrypoint).text())
                    .col(ColumnDef::new(Config::WorkingDir).text())
                    .col(ColumnDef::new(Config::Volumes).text())
                    .col(ColumnDef::new(Config::ExposedPorts).text())
                    .col(ColumnDef::new(Config::User).text())
                    .col(ColumnDef::new(Config::RootfsType).text())
                    .col(ColumnDef::new(Config::RootfsDiffIds).text())
                    .col(ColumnDef::new(Config::History).text())
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
                    .col(
                        ColumnDef::new(Layer::Digest)
                            .text()
                            .not_null()
                            .unique_key(),
                    )
                    .col(ColumnDef::new(Layer::DiffId).text().not_null())
                    .col(ColumnDef::new(Layer::MediaType).text())
                    .col(ColumnDef::new(Layer::SizeBytes).big_integer())
                    .col(ColumnDef::new(Layer::CreatedAt).date_time())
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
                    .col(
                        ColumnDef::new(ManifestLayer::LayerId)
                            .integer()
                            .not_null(),
                    )
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
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Unique index on manifest_layers(manifest_id, layer_id)
        manager
            .create_index(
                sea_orm_migration::prelude::Index::create()
                    .name("idx_manifest_layers_unique")
                    .table(ManifestLayer::Table)
                    .col(ManifestLayer::ManifestId)
                    .col(ManifestLayer::LayerId)
                    .unique()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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
            .drop_table(Table::drop().table(Manifest::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Index::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Image::Table).to_owned())
            .await?;
        Ok(())
    }
}

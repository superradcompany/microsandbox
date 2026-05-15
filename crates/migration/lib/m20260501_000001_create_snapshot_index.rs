//! Migration: Replace the legacy `snapshot` stub table with a digest-keyed
//! `snapshot_index` table that mirrors the file-first artifact format.
//!
//! The artifact on disk is the source of truth; this table is a local
//! cache for fast queries and parent-edge bookkeeping.

use sea_orm_migration::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub struct Migration;

#[derive(Iden)]
enum LegacySnapshot {
    #[iden = "snapshot"]
    Table,
}

#[derive(Iden)]
enum SnapshotIndex {
    Table,
    Digest,
    Name,
    ParentDigest,
    ImageRef,
    ImageManifestDigest,
    Format,
    Fstype,
    ArtifactPath,
    SizeBytes,
    CreatedAt,
    IndexedAt,
    ChildCount,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260501_000001_create_snapshot_index"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Drop the legacy stub table along with any indexes we created on
        // it in migration 0003. It was never user-facing, so no data is
        // at risk.
        manager
            .get_connection()
            .execute_unprepared("DROP INDEX IF EXISTS idx_snapshots_name_unique_no_sandbox")
            .await?;
        manager
            .get_connection()
            .execute_unprepared("DROP INDEX IF EXISTS idx_snapshots_name_sandbox_unique")
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(LegacySnapshot::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(SnapshotIndex::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(SnapshotIndex::Digest)
                            .text()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(SnapshotIndex::Name).text())
                    .col(ColumnDef::new(SnapshotIndex::ParentDigest).text())
                    .col(ColumnDef::new(SnapshotIndex::ImageRef).text().not_null())
                    .col(
                        ColumnDef::new(SnapshotIndex::ImageManifestDigest)
                            .text()
                            .not_null(),
                    )
                    .col(ColumnDef::new(SnapshotIndex::Format).text().not_null())
                    .col(ColumnDef::new(SnapshotIndex::Fstype).text().not_null())
                    .col(
                        ColumnDef::new(SnapshotIndex::ArtifactPath)
                            .text()
                            .not_null(),
                    )
                    .col(ColumnDef::new(SnapshotIndex::SizeBytes).big_integer())
                    .col(
                        ColumnDef::new(SnapshotIndex::CreatedAt)
                            .date_time()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SnapshotIndex::IndexedAt)
                            .date_time()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SnapshotIndex::ChildCount)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .to_owned(),
            )
            .await?;

        // SQLite-specific partial unique index: enforce name uniqueness
        // only when name is not NULL. Mirrors the pattern in migration
        // 0003 for sandbox-independent snapshots.
        manager
            .get_connection()
            .execute_unprepared(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_snapshot_index_name \
                 ON snapshot_index (name) WHERE name IS NOT NULL",
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_snapshot_index_parent")
                    .table(SnapshotIndex::Table)
                    .col(SnapshotIndex::ParentDigest)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_snapshot_index_image")
                    .table(SnapshotIndex::Table)
                    .col(SnapshotIndex::ImageManifestDigest)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(SnapshotIndex::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

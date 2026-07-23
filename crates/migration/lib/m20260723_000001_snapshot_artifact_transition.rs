//! Migration: project final schema-1 snapshot state and journal adjacent
//! v0.6.6 artifact conversion.

use sea_orm::{ConnectionTrait, Statement};
use sea_orm_migration::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub struct Migration;

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260723_000001_snapshot_artifact_transition"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let connection = manager.get_connection();

        // SQLite cannot make the legacy format/fstype columns nullable in
        // place, so rebuild the projection before checkpoint rows can exist.
        connection
            .execute_unprepared("DROP INDEX IF EXISTS idx_snapshot_index_name")
            .await?;
        connection
            .execute_unprepared("DROP INDEX IF EXISTS idx_snapshot_index_parent")
            .await?;
        connection
            .execute_unprepared("DROP INDEX IF EXISTS idx_snapshot_index_image")
            .await?;
        connection
            .execute_unprepared("ALTER TABLE snapshot_index RENAME TO snapshot_index_pre_v067")
            .await?;
        connection
            .execute_unprepared(
                "CREATE TABLE snapshot_index (\
                    digest TEXT NOT NULL PRIMARY KEY,\
                    name TEXT,\
                    parent_digest TEXT,\
                    scope TEXT NOT NULL,\
                    state_kind TEXT NOT NULL,\
                    image_ref TEXT NOT NULL,\
                    image_manifest_digest TEXT NOT NULL,\
                    format TEXT,\
                    fstype TEXT,\
                    checkpoint_manifest_digest TEXT,\
                    artifact_path TEXT NOT NULL,\
                    size_bytes BIGINT,\
                    locality TEXT NOT NULL DEFAULT 'embedded',\
                    storage_binding_id TEXT,\
                    availability TEXT NOT NULL DEFAULT 'ready',\
                    migration_state TEXT NOT NULL DEFAULT 'canonical',\
                    migration_error_code TEXT,\
                    created_at DATETIME NOT NULL,\
                    indexed_at DATETIME NOT NULL,\
                    child_count INTEGER NOT NULL DEFAULT 0\
                )",
            )
            .await?;
        connection
            .execute_unprepared(
                r#"INSERT INTO snapshot_index (
                    digest, name, parent_digest, scope, state_kind, image_ref,
                    image_manifest_digest, format, fstype, artifact_path,
                    size_bytes, created_at, indexed_at, child_count
                ) SELECT
                    digest, name, parent_digest, scope, 'file', image_ref,
                    image_manifest_digest, format, fstype, artifact_path,
                    size_bytes, created_at, indexed_at, child_count
                FROM snapshot_index_pre_v067"#,
            )
            .await?;
        connection
            .execute_unprepared("DROP TABLE snapshot_index_pre_v067")
            .await?;
        create_snapshot_indexes(connection).await?;

        connection
            .execute_unprepared(
                "CREATE TABLE snapshot_artifact_migration (\
                    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,\
                    kind TEXT NOT NULL,\
                    artifact_path TEXT NOT NULL,\
                    indexed_digest TEXT,\
                    source_digest TEXT,\
                    target_digest TEXT,\
                    source_parent_digest TEXT,\
                    target_parent_digest TEXT,\
                    payload_integrity TEXT,\
                    payload_size BIGINT,\
                    payload_file_identity TEXT,\
                    phase TEXT NOT NULL,\
                    attempts INTEGER NOT NULL DEFAULT 0,\
                    error_code TEXT,\
                    error_detail TEXT,\
                    discovered_at DATETIME NOT NULL,\
                    updated_at DATETIME NOT NULL,\
                    completed_at DATETIME,\
                    recovery_member TEXT,\
                    translation_source TEXT,\
                    UNIQUE(kind, artifact_path)\
                )",
            )
            .await?;
        connection
            .execute_unprepared(
                "CREATE INDEX idx_snapshot_artifact_migration_source ON snapshot_artifact_migration (kind, source_digest)",
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let connection = manager.get_connection();
        let unreversed = connection
            .query_one(Statement::from_string(
                manager.get_database_backend(),
                "SELECT COUNT(*) FROM snapshot_index WHERE migration_state != 'reverse_complete'",
            ))
            .await?
            .ok_or_else(|| DbErr::Migration("snapshot downgrade preflight returned no row".into()))?
            .try_get_by_index::<i64>(0)?;
        if unreversed != 0 {
            return Err(DbErr::Migration(
                "snapshot_downgrade_recovery_required: reverse managed snapshot artifacts before rolling back the snapshot schema"
                    .into(),
            ));
        }
        connection
            .execute_unprepared("DROP TABLE IF EXISTS snapshot_artifact_migration")
            .await?;
        connection
            .execute_unprepared("DROP INDEX IF EXISTS idx_snapshot_index_name")
            .await?;
        connection
            .execute_unprepared("DROP INDEX IF EXISTS idx_snapshot_index_parent")
            .await?;
        connection
            .execute_unprepared("DROP INDEX IF EXISTS idx_snapshot_index_image")
            .await?;
        connection
            .execute_unprepared("ALTER TABLE snapshot_index RENAME TO snapshot_index_v067")
            .await?;
        connection
            .execute_unprepared(
                "CREATE TABLE snapshot_index (\
                    digest TEXT NOT NULL PRIMARY KEY,\
                    name TEXT,\
                    parent_digest TEXT,\
                    image_ref TEXT NOT NULL,\
                    image_manifest_digest TEXT NOT NULL,\
                    format TEXT NOT NULL,\
                    fstype TEXT NOT NULL,\
                    artifact_path TEXT NOT NULL,\
                    size_bytes BIGINT,\
                    created_at DATETIME NOT NULL,\
                    indexed_at DATETIME NOT NULL,\
                    child_count INTEGER NOT NULL DEFAULT 0,\
                    scope TEXT NOT NULL DEFAULT 'disk'\
                )",
            )
            .await?;
        connection
            .execute_unprepared(
                r#"INSERT INTO snapshot_index (
                    digest, name, parent_digest, image_ref, image_manifest_digest,
                    format, fstype, artifact_path, size_bytes, created_at,
                    indexed_at, child_count, scope
                ) SELECT
                    digest, name, parent_digest, image_ref, image_manifest_digest,
                    COALESCE(format, ''), COALESCE(fstype, ''), artifact_path,
                    size_bytes, created_at, indexed_at, child_count, scope
                FROM snapshot_index_v067"#,
            )
            .await?;
        connection
            .execute_unprepared("DROP TABLE snapshot_index_v067")
            .await?;
        create_snapshot_indexes(connection).await?;

        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

async fn create_snapshot_indexes<C>(connection: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    connection
        .execute_unprepared(
            "CREATE UNIQUE INDEX idx_snapshot_index_name ON snapshot_index (name) WHERE name IS NOT NULL",
        )
        .await?;
    connection
        .execute_unprepared(
            "CREATE INDEX idx_snapshot_index_parent ON snapshot_index (parent_digest)",
        )
        .await?;
    connection
        .execute_unprepared(
            "CREATE INDEX idx_snapshot_index_image ON snapshot_index (image_manifest_digest)",
        )
        .await?;
    Ok(())
}

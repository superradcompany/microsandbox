//! Index local snapshot instances separately from portable identities.

use sea_orm_migration::{
    prelude::*,
    sea_orm::{DatabaseBackend, Statement},
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const SHARED_COLUMNS: &str = "digest, snapshot_id, descriptor_digest, name, parent_digest, scope, state_kind, image_ref, image_manifest_digest, format, fstype, checkpoint_manifest_digest, artifact_path, size_bytes, locality, storage_binding_id, availability, migration_state, migration_error_code, created_at, indexed_at, child_count";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(DeriveMigrationName)]
pub struct Migration;

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        rebuild_index(manager, true).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let connection = manager.get_connection();
        // Check before rebuilding: older binaries cannot address groups or retain several
        // copies of one portable identity. Never silently discard rows to satisfy old keys.
        let incompatible = connection
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT EXISTS(SELECT 1 FROM snapshot_index WHERE group_path IS NOT NULL OR group_name IS NOT NULL) OR EXISTS(SELECT 1 FROM snapshot_index GROUP BY digest HAVING COUNT(*) > 1) OR EXISTS(SELECT 1 FROM snapshot_index WHERE snapshot_id IS NOT NULL GROUP BY snapshot_id HAVING COUNT(*) > 1) OR EXISTS(SELECT 1 FROM snapshot_index WHERE name IS NOT NULL GROUP BY name HAVING COUNT(*) > 1) AS incompatible",
            ))
            .await?
            .ok_or_else(|| DbErr::Custom("snapshot group downgrade preflight returned no row".into()))?
            .try_get::<i64>("", "incompatible")?;
        if incompatible != 0 {
            return Err(DbErr::Custom(
                "snapshot groups prevent downgrade: retain this version or export and remove grouped/duplicate snapshot instances before retrying".into(),
            ));
        }
        rebuild_index(manager, false).await
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn rebuild_index(manager: &SchemaManager<'_>, grouped: bool) -> Result<(), DbErr> {
    let connection = manager.get_connection();
    connection
        .execute_unprepared("ALTER TABLE snapshot_index RENAME TO snapshot_index_group_transition")
        .await?;
    let digest_key = if grouped { "" } else { " PRIMARY KEY" };
    let path_key = if grouped { " PRIMARY KEY" } else { "" };
    let group_columns = if grouped {
        "group_name TEXT, group_path TEXT,"
    } else {
        ""
    };
    connection
        .execute_unprepared(&format!(
            "CREATE TABLE snapshot_index (digest TEXT NOT NULL{digest_key}, snapshot_id TEXT, descriptor_digest TEXT, name TEXT, {group_columns} parent_digest TEXT, scope TEXT NOT NULL, state_kind TEXT NOT NULL, image_ref TEXT NOT NULL, image_manifest_digest TEXT NOT NULL, format TEXT, fstype TEXT, checkpoint_manifest_digest TEXT, artifact_path TEXT NOT NULL{path_key}, size_bytes BIGINT, locality TEXT NOT NULL DEFAULT 'embedded', storage_binding_id TEXT, availability TEXT NOT NULL DEFAULT 'ready', migration_state TEXT NOT NULL DEFAULT 'canonical', migration_error_code TEXT, created_at DATETIME NOT NULL, indexed_at DATETIME NOT NULL, child_count INTEGER NOT NULL DEFAULT 0)"
        ))
        .await?;
    connection
        .execute_unprepared(&format!(
            "INSERT INTO snapshot_index ({SHARED_COLUMNS}) SELECT {SHARED_COLUMNS} FROM snapshot_index_group_transition"
        ))
        .await?;
    // Dropping the old table also releases its index names before creating replacements.
    connection
        .execute_unprepared("DROP TABLE snapshot_index_group_transition")
        .await?;
    let name_index = if grouped {
        "CREATE UNIQUE INDEX idx_snapshot_index_name ON snapshot_index (group_path, name) WHERE group_path IS NOT NULL AND name IS NOT NULL"
    } else {
        "CREATE UNIQUE INDEX idx_snapshot_index_name ON snapshot_index (name) WHERE name IS NOT NULL"
    };
    connection.execute_unprepared(name_index).await?;
    let identity_unique = if grouped { "" } else { "UNIQUE " };
    connection.execute_unprepared(&format!("CREATE {identity_unique}INDEX idx_snapshot_index_snapshot_id ON snapshot_index (snapshot_id)")).await?;
    for (name, column) in [
        ("idx_snapshot_index_digest", "digest"),
        ("idx_snapshot_index_descriptor_digest", "descriptor_digest"),
        ("idx_snapshot_index_parent", "parent_digest"),
        ("idx_snapshot_index_image", "image_manifest_digest"),
    ] {
        connection
            .execute_unprepared(&format!("CREATE INDEX {name} ON snapshot_index ({column})"))
            .await?;
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use sea_orm_migration::sea_orm::{Database, DatabaseConnection};

    use super::*;
    use crate::{Migrator, MigratorTrait};

    async fn prior_database() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, Some((Migrator::migrations().len() - 1) as u32))
            .await
            .unwrap();
        db.execute_unprepared("INSERT INTO snapshot_index (digest, snapshot_id, descriptor_digest, name, scope, state_kind, image_ref, image_manifest_digest, artifact_path, created_at, indexed_at) VALUES ('sha256:original', 'snap_original', 'sha256:original', 'baseline', 'disk', 'file', 'example', 'sha256:image', '/old/baseline', '2026-09-10 00:00:00', '2026-09-10 00:00:00')").await.unwrap();
        db
    }

    #[tokio::test]
    async fn preserves_old_rows_and_round_trips_ungrouped_database() {
        let db = prior_database().await;
        Migrator::up(&db, None).await.unwrap();
        let row = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT digest, artifact_path, group_name FROM snapshot_index",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            row.try_get::<String>("", "digest").unwrap(),
            "sha256:original"
        );
        assert_eq!(
            row.try_get::<String>("", "artifact_path").unwrap(),
            "/old/baseline"
        );
        assert_eq!(
            row.try_get::<Option<String>>("", "group_name").unwrap(),
            None
        );
        Migrator::down(&db, Some(1)).await.unwrap();
        let row = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT digest FROM snapshot_index",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            row.try_get::<String>("", "digest").unwrap(),
            "sha256:original"
        );
    }

    #[tokio::test]
    async fn permits_duplicate_imports_and_refuses_lossy_downgrade() {
        let db = prior_database().await;
        Migrator::up(&db, None).await.unwrap();
        for group in ["first", "second"] {
            db.execute_unprepared(&format!("INSERT INTO snapshot_index ({SHARED_COLUMNS}, group_name, group_path) SELECT digest, snapshot_id, descriptor_digest, name, parent_digest, scope, state_kind, image_ref, image_manifest_digest, format, fstype, checkpoint_manifest_digest, '/snapshots/{group}/baseline', size_bytes, locality, storage_binding_id, availability, migration_state, migration_error_code, created_at, indexed_at, child_count, '{group}', '/snapshots/{group}' FROM snapshot_index WHERE artifact_path = '/old/baseline'")).await.unwrap();
        }
        let error = Migrator::down(&db, Some(1)).await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("snapshot groups prevent downgrade")
        );
        let row = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(*) AS n FROM snapshot_index",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.try_get::<i64>("", "n").unwrap(), 3);
    }
}

//! Queries for catalog columns that vary across supported SDK releases.
//!
//! These helpers inspect the schema without migrating it. They deliberately
//! select only known entity fields so additional historical columns remain
//! owned by the release that created them.

use sea_orm::sea_query::Expr;
use sea_orm::{
    ConnectionTrait, DbBackend, DbErr, EntityTrait, Iterable, QuerySelect, Select, Statement,
};

use crate::entity::{sandbox, sandbox_rootfs};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Whether a table exists in the current connection's catalog.
pub async fn has_table<C: ConnectionTrait>(db: &C, table: &str) -> Result<bool, DbErr> {
    Ok(db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?",
            [table.into()],
        ))
        .await?
        .is_some())
}

/// Whether a catalog table currently contains a column.
///
/// Do not cache an absence permanently: an older CLI may legitimately upgrade
/// its own catalog while another SDK process is still running.
pub async fn has_column<C: ConnectionTrait>(
    db: &C,
    table: &str,
    column: &str,
) -> Result<bool, DbErr> {
    Ok(db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT 1 FROM pragma_table_info(?) WHERE name = ?",
            [table.into(), column.into()],
        ))
        .await?
        .is_some())
}

/// Select a sandbox using the historical absence of active-config tracking.
pub async fn sandbox_query<C: ConnectionTrait>(db: &C) -> Result<Select<sandbox::Entity>, DbErr> {
    let active = has_column(db, "sandbox", "active_config").await?;
    let network = has_column(db, "sandbox", "network_slot").await?;
    let mut query = sandbox::Entity::find()
        .select_only()
        .columns(sandbox::Column::iter().filter(|column| match column {
            sandbox::Column::ActiveConfig => active,
            sandbox::Column::NetworkSlot => network,
            _ => true,
        }));
    if !active {
        query = query.column_as(
            Expr::val(Option::<String>::None),
            sandbox::Column::ActiveConfig,
        );
    }
    if !network {
        query = query.column_as(Expr::val(Option::<u16>::None), sandbox::Column::NetworkSlot);
    }
    Ok(query)
}

/// Clear runtime-only columns that exist in the owning catalog's schema.
pub async fn clear_runtime_fields<C: ConnectionTrait>(
    db: &C,
    mut update: sea_orm::UpdateMany<sandbox::Entity>,
) -> Result<sea_orm::UpdateMany<sandbox::Entity>, DbErr> {
    if has_column(db, "sandbox", "active_config").await? {
        update = update.col_expr(
            sandbox::Column::ActiveConfig,
            Expr::val(Option::<String>::None),
        );
    }
    if has_column(db, "sandbox", "network_slot").await? {
        update = update.col_expr(sandbox::Column::NetworkSlot, Expr::val(Option::<u16>::None));
    }
    Ok(update)
}

/// Select rootfs pins written before explicit root-disk kinds were introduced.
/// Old OCI pins always described the managed writable root disk.
pub async fn rootfs_query<C: ConnectionTrait>(
    db: &C,
) -> Result<Select<sandbox_rootfs::Entity>, DbErr> {
    let kind = has_column(db, "sandbox_rootfs", "root_disk_kind").await?;
    let path = has_column(db, "sandbox_rootfs", "root_disk_path").await?;
    let mut query = sandbox_rootfs::Entity::find().select_only().columns(
        sandbox_rootfs::Column::iter().filter(|column| match column {
            sandbox_rootfs::Column::RootDiskKind => kind,
            sandbox_rootfs::Column::RootDiskPath => path,
            _ => true,
        }),
    );
    if !kind {
        query = query.column_as(Expr::val("managed"), sandbox_rootfs::Column::RootDiskKind);
    }
    if !path {
        query = query.column_as(
            Expr::val(Option::<String>::None),
            sandbox_rootfs::Column::RootDiskPath,
        );
    }
    Ok(query)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{ColumnTrait, Database, QueryFilter};

    #[tokio::test]
    async fn sandbox_queries_follow_existing_columns_without_changing_them() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        db.execute_unprepared("CREATE TABLE sandbox (id INTEGER PRIMARY KEY, name TEXT NOT NULL, config TEXT NOT NULL, status TEXT NOT NULL, ephemeral INTEGER NOT NULL, created_at TEXT, updated_at TEXT); INSERT INTO sandbox VALUES (1, 'old', '{}', 'Stopped', 0, NULL, NULL)").await.unwrap();
        let row = sandbox_query(&db)
            .await
            .unwrap()
            .filter(sandbox::Column::Id.eq(1))
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert!(row.active_config.is_none());
        assert_eq!(row.name, "old");
        assert!(!has_column(&db, "sandbox", "active_config").await.unwrap());
        // Simulate the owning CLI adding its own column after this SDK opened.
        db.execute_unprepared("ALTER TABLE sandbox ADD COLUMN active_config TEXT; UPDATE sandbox SET active_config = 'active'").await.unwrap();
        let row = sandbox_query(&db)
            .await
            .unwrap()
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.active_config.as_deref(), Some("active"));
    }

    #[tokio::test]
    async fn old_rootfs_pins_remain_managed_without_schema_changes() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        db.execute_unprepared("CREATE TABLE sandbox_rootfs (id INTEGER PRIMARY KEY, sandbox_id INTEGER NOT NULL, manifest_id INTEGER, mode TEXT NOT NULL, upper_fstype TEXT, created_at TEXT); INSERT INTO sandbox_rootfs VALUES (1, 2, 3, 'erofs', 'ext4', NULL)").await.unwrap();
        let row = rootfs_query(&db)
            .await
            .unwrap()
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.root_disk_kind, "managed");
        assert!(row.root_disk_path.is_none());
        assert!(
            !has_column(&db, "sandbox_rootfs", "root_disk_kind")
                .await
                .unwrap()
        );
        assert!(has_table(&db, "sandbox_rootfs").await.unwrap());
        assert!(!has_table(&db, "seaql_migrations").await.unwrap());
    }
}

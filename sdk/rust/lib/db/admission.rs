//! Admission for an existing catalog without changing its owning CLI's schema.

use std::{collections::BTreeSet, sync::LazyLock};

use microsandbox_db::catalog::has_table;
use microsandbox_migration::schema_metadata;
use sea_orm::{ConnectionTrait, DbBackend, Statement};
use serde::Deserialize;

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

static RELEASED: LazyLock<Vec<ReleasedCatalog>> = LazyLock::new(|| {
    serde_json::from_str(include_str!("fixtures/catalog-profiles.json"))
        .expect("checked-in released catalog profiles must parse")
});

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Deserialize)]
struct ReleasedCatalog {
    migrations: BTreeSet<String>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Returns true only for a new catalog or interrupted pre-floor initialization.
/// Complete supported catalogs remain in their existing schema and retain their
/// migration history, including known released schemas ahead of this checkout.
pub(crate) async fn requires_initialization<C: ConnectionTrait>(
    db: &C,
) -> MicrosandboxResult<bool> {
    if !has_table(db, "seaql_migrations").await? {
        let tables = db.query_one_raw(Statement::from_string(DbBackend::Sqlite,
            "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"))
            .await?.expect("COUNT returns one row").try_get_by_index::<i64>(0)?;
        if tables == 0 {
            return Ok(true);
        }
        return Err(MicrosandboxError::Runtime("database has tables but no migration history; refusing to initialize an unrecognized catalog".into()));
    }
    let rows = db
        .query_all_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT version FROM seaql_migrations",
        ))
        .await?;
    let applied = rows
        .into_iter()
        .map(|row| row.try_get_by_index::<String>(0))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if RELEASED.iter().any(|profile| profile.migrations == applied) {
        return Ok(false);
    }
    if let Some(prefix) =
        schema_metadata::canonical_applied_prefix(applied.iter().map(String::as_str))
    {
        if prefix.len() < schema_metadata::BASELINE_0_6_0_MIGRATIONS.len() {
            return Ok(true);
        }
        if prefix.len() == schema_metadata::migration_ids().count() {
            return Ok(false);
        }
    }
    Err(MicrosandboxError::Runtime(
        "database schema is newer than this msb binary or has an unknown migration prefix; refusing to change an unrecognized catalog".into(),
    ))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::Database;

    #[tokio::test]
    async fn every_released_profile_is_preserved_and_unknown_history_is_refused() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        assert!(requires_initialization(&db).await.unwrap());
        db.execute_unprepared(
            "CREATE TABLE seaql_migrations (version TEXT PRIMARY KEY, applied_at BIGINT NOT NULL)",
        )
        .await
        .unwrap();
        for profile in RELEASED.iter() {
            db.execute_unprepared("DELETE FROM seaql_migrations")
                .await
                .unwrap();
            for version in &profile.migrations {
                db.execute_raw(Statement::from_sql_and_values(
                    DbBackend::Sqlite,
                    "INSERT INTO seaql_migrations VALUES (?, 1)",
                    [version.clone().into()],
                ))
                .await
                .unwrap();
            }
            assert!(!requires_initialization(&db).await.unwrap());
            let count = db
                .query_one_raw(Statement::from_string(
                    DbBackend::Sqlite,
                    "SELECT COUNT(*) FROM seaql_migrations",
                ))
                .await
                .unwrap()
                .unwrap()
                .try_get_by_index::<i64>(0)
                .unwrap();
            assert_eq!(count as usize, profile.migrations.len());
        }
        db.execute_unprepared(
            "INSERT INTO seaql_migrations VALUES ('unknown_future_migration', 1)",
        )
        .await
        .unwrap();
        assert!(requires_initialization(&db).await.is_err());
    }
}

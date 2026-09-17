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
    versions: Vec<String>,
    migrations: BTreeSet<String>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Compare identities, not counts: an unknown migration must never admit a current writer.
pub(crate) async fn is_current<C: ConnectionTrait>(db: &C) -> MicrosandboxResult<bool> {
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
    Ok(applied
        == schema_metadata::migration_ids()
            .map(str::to_owned)
            .collect())
}

/// Earliest released writer for an exact historical migration set.
pub(super) async fn historical_patch<C: ConnectionTrait>(db: &C) -> MicrosandboxResult<u64> {
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
    RELEASED
        .iter()
        .find(|profile| profile.migrations == applied)
        .and_then(|profile| {
            profile
                .versions
                .iter()
                .filter_map(|version| version.rsplit('.').next()?.parse().ok())
                .min()
        })
        .ok_or_else(|| {
            MicrosandboxError::InvalidConfig(
                "unrecognized catalog migration history; refusing configuration write".into(),
            )
        })
}

pub(crate) fn historical_migration_count(patch: u64) -> MicrosandboxResult<u32> {
    let version = format!("v0.6.{patch}");
    RELEASED
        .iter()
        .find(|profile| profile.versions.contains(&version))
        .map(|profile| profile.migrations.len() as u32)
        .ok_or_else(|| {
            MicrosandboxError::Runtime(format!("unrecognized catalog release {version}"))
        })
}

pub(super) fn same_historical_schema(left: u64, right: u64) -> bool {
    let left = format!("v0.6.{left}");
    let right = format!("v0.6.{right}");
    RELEASED
        .iter()
        .any(|profile| profile.versions.contains(&left) && profile.versions.contains(&right))
}

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

    #[tokio::test]
    async fn equal_migration_counts_do_not_admit_an_unknown_writer() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        db.execute_unprepared(
            "CREATE TABLE seaql_migrations (version TEXT PRIMARY KEY, applied_at BIGINT NOT NULL)",
        )
        .await
        .unwrap();
        for version in schema_metadata::migration_ids() {
            db.execute_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "INSERT INTO seaql_migrations VALUES (?, 1)",
                [version.into()],
            ))
            .await
            .unwrap();
        }
        assert!(is_current(&db).await.unwrap());
        db.execute_unprepared("UPDATE seaql_migrations SET version = 'unknown_replacement' WHERE version = (SELECT version FROM seaql_migrations ORDER BY version LIMIT 1)").await.unwrap();
        assert!(!is_current(&db).await.unwrap());
        assert!(requires_initialization(&db).await.is_err());
        assert!(historical_patch(&db).await.is_err());
    }
}

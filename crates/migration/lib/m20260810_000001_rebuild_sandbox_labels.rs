//! Migration: Rebuild the sandbox label index from persisted configs.
//!
//! Sandbox config JSON is the canonical label source. Releases affected by a
//! backend-routing regression persisted labels there without updating the
//! `sandbox_labels` projection consumed by label selection. Rebuild the complete
//! projection so both missing and stale rows are repaired.

use std::collections::BTreeMap;

use sea_orm_migration::{
    prelude::*,
    sea_orm::{ConnectionTrait, DatabaseBackend, Statement, TransactionError, TransactionTrait},
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub struct Migration;

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260810_000001_rebuild_sandbox_labels"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        conn.transaction::<_, (), DbErr>(|txn| {
            Box::pin(async move {
                let rows = txn
                    .query_all_raw(Statement::from_string(
                        DatabaseBackend::Sqlite,
                        "SELECT id, config FROM sandbox".to_owned(),
                    ))
                    .await?;
                let mut labels_by_sandbox = Vec::with_capacity(rows.len());

                // Parse every config before changing the projection. A
                // malformed row rolls the transaction back without deleting
                // labels from otherwise valid rows.
                for row in rows {
                    let sandbox_id = row.try_get_by_index::<i32>(0)?;
                    let config = row.try_get_by_index::<String>(1)?;
                    let labels = extract_labels(&config).map_err(|error| {
                        DbErr::Custom(format!(
                            "rebuild labels for sandbox id {sandbox_id}: {error}"
                        ))
                    })?;
                    labels_by_sandbox.push((sandbox_id, labels));
                }

                txn.execute_raw(Statement::from_string(
                    DatabaseBackend::Sqlite,
                    "DELETE FROM sandbox_labels".to_owned(),
                ))
                .await?;

                for (sandbox_id, labels) in labels_by_sandbox {
                    for (key, value) in labels {
                        txn.execute_raw(Statement::from_sql_and_values(
                            DatabaseBackend::Sqlite,
                            "INSERT INTO sandbox_labels (sandbox_id, key, value) VALUES (?, ?, ?)",
                            [sandbox_id.into(), key.into(), value.into()],
                        ))
                        .await?;
                    }
                }

                Ok(())
            })
        })
        .await
        .map_err(|error| match error {
            TransactionError::Connection(error) | TransactionError::Transaction(error) => error,
        })?;

        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // Repaired projection rows are compatible with older releases and
        // should not be reverted to the inconsistent pre-migration state.
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn extract_labels(config: &str) -> Result<BTreeMap<String, String>, DbErr> {
    let value = serde_json::from_str::<serde_json::Value>(config)
        .map_err(|error| DbErr::Custom(format!("parse sandbox config JSON: {error}")))?;
    let Some(labels) = value.get("labels") else {
        return Ok(BTreeMap::new());
    };
    let labels = labels.as_object().ok_or_else(|| {
        DbErr::Custom("parse sandbox config JSON: labels must be an object".into())
    })?;

    labels
        .iter()
        .map(|(key, value)| {
            let value = value.as_str().ok_or_else(|| {
                DbErr::Custom(format!(
                    "parse sandbox config JSON: label {key:?} must have a string value"
                ))
            })?;
            Ok((key.clone(), value.to_owned()))
        })
        .collect()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use sea_orm_migration::sea_orm::{Database, DatabaseConnection};

    use super::*;

    async fn open_catalog() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        db.execute_unprepared(
            "CREATE TABLE sandbox (id INTEGER PRIMARY KEY, config TEXT NOT NULL);\
             CREATE TABLE sandbox_labels (\
                 sandbox_id INTEGER NOT NULL,\
                 key TEXT NOT NULL,\
                 value TEXT NOT NULL,\
                 PRIMARY KEY (sandbox_id, key)\
             );",
        )
        .await
        .unwrap();
        db
    }

    #[test]
    fn extract_labels_reads_canonical_config_shape() {
        let labels =
            extract_labels(r#"{"name":"api","labels":{"team":"metrics","tier":"gold"}}"#).unwrap();

        assert_eq!(labels.get("team").map(String::as_str), Some("metrics"));
        assert_eq!(labels.get("tier").map(String::as_str), Some("gold"));
    }

    #[test]
    fn extract_labels_accepts_configs_without_labels() {
        let labels = extract_labels(r#"{"name":"api","resources":{"cpus":2}}"#).unwrap();

        assert!(labels.is_empty());
    }

    #[test]
    fn extract_labels_rejects_non_string_values() {
        let error = extract_labels(r#"{"labels":{"attempt":3}}"#).unwrap_err();

        assert!(error.to_string().contains("must have a string value"));
    }

    #[tokio::test]
    async fn migration_replaces_missing_and_stale_projection_rows() {
        let db = open_catalog().await;
        for (id, config) in [
            (
                1,
                r#"{"name":"first","labels":{"team":"metrics","tier":"gold"}}"#,
            ),
            (2, r#"{"name":"second","labels":{}}"#),
        ] {
            db.execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "INSERT INTO sandbox (id, config) VALUES (?, ?)",
                [id.into(), config.into()],
            ))
            .await
            .unwrap();
        }
        for (sandbox_id, key, value) in [
            (1, "team", "stale"),
            (1, "removed", "ghost"),
            (2, "removed", "ghost"),
        ] {
            db.execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "INSERT INTO sandbox_labels (sandbox_id, key, value) VALUES (?, ?, ?)",
                [sandbox_id.into(), key.into(), value.into()],
            ))
            .await
            .unwrap();
        }

        Migration.up(&SchemaManager::new(&db)).await.unwrap();
        // Running the operation again rebuilds the same projection without
        // duplicate or stale rows.
        Migration.up(&SchemaManager::new(&db)).await.unwrap();

        let rows = db
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT sandbox_id, key, value FROM sandbox_labels ORDER BY sandbox_id, key"
                    .to_owned(),
            ))
            .await
            .unwrap();
        let rows: Vec<(i32, String, String)> = rows
            .into_iter()
            .map(|row| {
                (
                    row.try_get_by_index(0).unwrap(),
                    row.try_get_by_index(1).unwrap(),
                    row.try_get_by_index(2).unwrap(),
                )
            })
            .collect();

        assert_eq!(
            rows,
            vec![
                (1, "team".into(), "metrics".into()),
                (1, "tier".into(), "gold".into()),
            ]
        );
    }

    #[tokio::test]
    async fn migration_preserves_projection_when_a_config_is_invalid() {
        let db = open_catalog().await;
        db.execute_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "INSERT INTO sandbox (id, config) VALUES (?, ?)",
            [1.into(), r#"{"labels":{"attempt":3}}"#.into()],
        ))
        .await
        .unwrap();
        db.execute_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "INSERT INTO sandbox_labels (sandbox_id, key, value) VALUES (?, ?, ?)",
            [1.into(), "team".into(), "existing".into()],
        ))
        .await
        .unwrap();

        let error = Migration.up(&SchemaManager::new(&db)).await.unwrap_err();

        assert!(error.to_string().contains("sandbox id 1"));
        let rows = db
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT key, value FROM sandbox_labels".to_owned(),
            ))
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].try_get_by_index::<String>(0).unwrap(), "team");
        assert_eq!(rows[0].try_get_by_index::<String>(1).unwrap(), "existing");
    }
}

//! Migration: establish the durable-config floor for mount ownership.
//!
//! The schema itself does not change. Recording this migration makes older
//! binaries refuse an ahead database instead of deserializing sandbox configs
//! while silently discarding mount ownership policy.

use sea_orm_migration::{
    prelude::*,
    sea_orm::{ConnectionTrait, DatabaseBackend, Statement},
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
        "m20260824_000001_mount_owner_config"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // The migration row itself is the compatibility marker.
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // The migration is only a compatibility marker, so an owner-free
        // database can remove it exactly. Preflight both desired and active
        // configs before the migration row is removed; an old binary would
        // otherwise deserialize either snapshot while silently dropping the
        // ownership policy.
        let rows = manager
            .get_connection()
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT id, config, active_config FROM sandbox".to_owned(),
            ))
            .await?;

        for row in rows {
            let id = row.try_get_by_index::<i32>(0)?;
            let config = row.try_get_by_index::<String>(1)?;
            reject_persisted_owner(id, "config", &config)?;

            if let Some(active_config) = row.try_get_by_index::<Option<String>>(2)? {
                reject_persisted_owner(id, "active_config", &active_config)?;
            }
        }

        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn reject_persisted_owner(sandbox_id: i32, column: &str, config: &str) -> Result<(), DbErr> {
    let value: serde_json::Value = serde_json::from_str(config).map_err(|error| {
        DbErr::Migration(format!(
            "mount_owner_downgrade_unrepresentable: sandbox {sandbox_id} {column} is invalid JSON: {error}"
        ))
    })?;
    let has_owner = value
        .pointer("/spec/mounts")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|mounts| {
            mounts.iter().any(|mount| {
                ["override_uid", "override_gid"].into_iter().any(|field| {
                    mount
                        .get("options")
                        .and_then(|options| options.get(field))
                        .is_some_and(|owner| !owner.is_null())
                })
            })
        });

    if has_owner {
        return Err(DbErr::Migration(format!(
            "mount_owner_downgrade_unrepresentable: sandbox {sandbox_id} {column} contains mount ownership that an older binary would discard"
        )));
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use sea_orm_migration::sea_orm::{ConnectionTrait, Database, Statement};

    use super::*;

    #[tokio::test]
    async fn downgrade_allows_owner_free_configs() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        db.execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "CREATE TABLE sandbox (id INTEGER PRIMARY KEY, config TEXT NOT NULL, active_config TEXT)"
                .to_owned(),
        ))
        .await
        .unwrap();
        db.execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            r#"INSERT INTO sandbox (id, config, active_config) VALUES (1, '{"spec":{"mounts":[{"options":{}}]}}', NULL)"#.to_owned(),
        ))
        .await
        .unwrap();

        Migration.down(&SchemaManager::new(&db)).await.unwrap();
    }

    #[tokio::test]
    async fn downgrade_refuses_owner_in_desired_or_active_config() {
        for column in ["config", "active_config"] {
            let db = Database::connect("sqlite::memory:").await.unwrap();
            db.execute_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "CREATE TABLE sandbox (id INTEGER PRIMARY KEY, config TEXT NOT NULL, active_config TEXT)"
                    .to_owned(),
            ))
            .await
            .unwrap();
            let owner =
                r#"{"spec":{"mounts":[{"options":{"override_uid":1000,"override_gid":1001}}]}}"#;
            let empty = r#"{"spec":{"mounts":[]}}"#;
            let (config, active_config) = if column == "config" {
                (owner, empty)
            } else {
                (empty, owner)
            };
            db.execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "INSERT INTO sandbox (id, config, active_config) VALUES (1, ?, ?)",
                [config.into(), active_config.into()],
            ))
            .await
            .unwrap();

            let error = Migration.down(&SchemaManager::new(&db)).await.unwrap_err();
            assert!(error.to_string().contains(column), "{error}");
            assert!(
                error
                    .to_string()
                    .contains("mount_owner_downgrade_unrepresentable")
            );
        }
    }
}

//! Prevent older SDKs from silently enabling guest wall-clock synchronization.
//!
//! The migration record protects the catalog without changing its tables or sandbox data.

use sea_orm_migration::{
    prelude::*,
    sea_orm::{ConnectionTrait, DatabaseBackend, Statement},
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Guard persisted guest clock policies against older catalog readers.
pub struct Migration;

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261001_000001_guest_clock_config"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // Older catalog readers reject this unknown migration before decoding saved settings.
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let rows = manager
            .get_connection()
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT name, config, active_config FROM sandbox",
            ))
            .await?;

        for row in rows {
            let name: String = row.try_get("", "name")?;
            let config: String = row.try_get("", "config")?;
            require_sync_policy(&name, "config", &config)?;

            if let Some(active) = row.try_get::<Option<String>>("", "active_config")? {
                require_sync_policy(&name, "active_config", &active)?;
            }
        }

        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn require_sync_policy(name: &str, column: &str, raw: &str) -> Result<(), DbErr> {
    let value: serde_json::Value = serde_json::from_str(raw).map_err(|error| {
        DbErr::Migration(format!(
            "guest_clock_downgrade_unrepresentable: sandbox '{name}' {column} is invalid JSON: {error}"
        ))
    })?;

    // SandboxConfig flattens SandboxSpec. Read raw JSON so future policies cannot be dropped
    // by deserialization; only an absent, null, or explicit sync policy is safe to discard.
    match value.pointer("/runtime/guest_clock") {
        None | Some(serde_json::Value::Null) => Ok(()),
        Some(serde_json::Value::String(policy)) if policy == "sync" => Ok(()),
        Some(_) => Err(DbErr::Migration(format!(
            "guest_clock_downgrade_unrepresentable: sandbox '{name}' {column} has a guest clock policy that an older SDK would discard; keep a compatible SDK or remove this sandbox before downgrading"
        ))),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use microsandbox_types::{GuestClockPolicy, SandboxSpec};
    use sea_orm_migration::sea_orm::{
        ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, Statement,
    };

    use super::*;
    use crate::{Migrator, MigratorTrait};

    fn config(policy: Option<GuestClockPolicy>) -> String {
        // SandboxConfig flattens this shared spec into its durable JSON.
        let mut spec = SandboxSpec::default();
        spec.runtime.guest_clock = policy;
        serde_json::to_string(&spec).unwrap()
    }

    async fn database(config: &str, active: Option<&str>) -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        db.execute_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "INSERT INTO sandbox (name, config, active_config, status, ephemeral) VALUES ('clock-fixture', ?, ?, 'Stopped', 0)",
            [config.into(), active.into()],
        ))
        .await
        .unwrap();
        db
    }

    async fn saved_state(db: &DatabaseConnection) -> (String, Option<String>, Vec<String>) {
        let row = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT config, active_config FROM sandbox WHERE name = 'clock-fixture'",
            ))
            .await
            .unwrap()
            .unwrap();
        let migrations = Migrator::get_applied_migrations(db)
            .await
            .unwrap()
            .into_iter()
            .map(|migration| migration.name().to_owned())
            .collect();
        (
            row.try_get("", "config").unwrap(),
            row.try_get("", "active_config").unwrap(),
            migrations,
        )
    }

    #[tokio::test]
    async fn guest_clock_downgrade_refuses_lossy_or_invalid_configs_without_mutation() {
        let sync = config(Some(GuestClockPolicy::Sync));
        let invalid = [
            config(Some(GuestClockPolicy::Off)),
            r#"{"runtime":{"guest_clock":"future-policy"}}"#.into(),
            "invalid JSON".into(),
        ];
        for raw in invalid {
            for column in ["config", "active_config"] {
                let (desired, active) = if column == "config" {
                    (raw.as_str(), sync.as_str())
                } else {
                    (sync.as_str(), raw.as_str())
                };
                let db = database(desired, Some(active)).await;
                let before = saved_state(&db).await;

                let error = Migrator::down(&db, Some(1)).await.unwrap_err();

                let message = error.to_string();
                assert!(
                    message.contains("guest_clock_downgrade_unrepresentable"),
                    "{message}"
                );
                assert!(message.contains("clock-fixture"), "{message}");
                assert!(message.contains(column), "{message}");
                assert_eq!(saved_state(&db).await, before);
            }
        }
    }

    #[tokio::test]
    async fn guest_clock_downgrade_and_reupgrade_preserve_sync_configs() {
        for raw in [
            config(None),
            config(Some(GuestClockPolicy::Sync)),
            r#"{"runtime":{"guest_clock":null}}"#.into(),
        ] {
            for active in [None, Some(raw.as_str())] {
                let db = database(&raw, active).await;
                let before = saved_state(&db).await;

                Migrator::down(&db, Some(1)).await.unwrap();

                let after = saved_state(&db).await;
                assert_eq!(after.0, before.0);
                assert_eq!(after.1, before.1);
                assert_eq!(after.2.len() + 1, before.2.len());
                assert!(!after.2.iter().any(|id| id == Migration.name()));

                Migrator::up(&db, None).await.unwrap();
                assert_eq!(saved_state(&db).await, before);
            }
        }
    }
}

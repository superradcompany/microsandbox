//! Normalize persisted secret policies and previous catalog field spellings.
//!
//! Current readers deserialize directly after upgrade. Reuse the previous
//! normalizer so older image, mount, CPU and pull-policy spellings are migrated
//! too; do not leave their conversion to application reads.

use microsandbox_db::compat;
use sea_orm_migration::{
    prelude::*,
    sea_orm::{ConnectionTrait, DatabaseBackend, Statement},
};
use serde_json::Value;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub struct Migration;

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260922_000001_migrate_secret_config"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        rewrite(manager, true).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // The preceding v0.7 format already uses substitution. Do not restore
        // v0.6 spellings here: the CLI selects those for v0.6 targets before
        // schema rollback. Refuse modern global defaults that older v0.7
        // readers cannot preserve; previous defaults already projected for
        // a v0.6 target are left intact.
        rewrite(manager, false).await
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn rewrite(manager: &SchemaManager<'_>, upgrade: bool) -> Result<(), DbErr> {
    let db = manager.get_connection();
    // Validate both columns and every row before writing any converted data.
    let mut updates = Vec::new();
    for column in ["config", "active_config"] {
        let rows = db
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                format!("SELECT id, {column}, name FROM sandbox WHERE {column} IS NOT NULL"),
            ))
            .await?;
        for row in rows {
            let id = row.try_get_by_index::<i32>(0)?;
            let raw = row.try_get_by_index::<String>(1)?;
            let name = row.try_get_by_index::<String>(2)?;
            let converted = convert(&raw, upgrade).map_err(|reason| {
                DbErr::Migration(format!(
                    "secret_config_migration: sandbox {id} ({name:?}) {column}: {reason}. \
                     Database upgrade was not applied. Use the previous SDK/CLI to repair or \
                     remove this sandbox, then retry the upgrade."
                ))
            })?;
            if let Some(converted) = converted {
                updates.push((column, id, converted));
            }
        }
    }
    for (column, id, converted) in updates {
        db.execute_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            format!("UPDATE sandbox SET {column} = ? WHERE id = ?"),
            [converted.into(), id.into()],
        ))
        .await?;
    }
    Ok(())
}

fn convert(raw: &str, upgrade: bool) -> Result<Option<String>, &'static str> {
    let mut value: Value = serde_json::from_str(raw).map_err(|_| "invalid configuration JSON")?;
    if !upgrade {
        if value
            .pointer("/network/secrets/passthrough_hosts")
            .is_some_and(|hosts| !Value::is_null(hosts))
        {
            return Err(
                "secret_config_downgrade_unrepresentable: global passthrough defaults require a supporting runtime",
            );
        }
        return Ok(None);
    }
    let original = value.clone();
    compat::config::to_current(&mut value)?;
    if value == original {
        return Ok(None);
    }

    serde_json::to_string(&value)
        .map(Some)
        .map_err(|_| "cannot encode configuration JSON")
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use sea_orm_migration::sea_orm::Database;

    use super::*;
    use microsandbox_types::compat::v0_5_0::local::secrets;

    const PREVIOUS_CONFIG: &str = include_str!(
        "../../../sdk/rust/lib/db/fixtures/config-0.6.18-global-passthrough-with-entries.json"
    );

    #[test]
    fn conversion_preserves_global_defaults_and_unrelated_fields() {
        let raw: Value = serde_json::from_str(PREVIOUS_CONFIG).unwrap();
        let encoded = convert(PREVIOUS_CONFIG, true).unwrap().unwrap();
        let mut current: Value = serde_json::from_str(&encoded).unwrap();
        let policy = current["network"]
            .as_object_mut()
            .unwrap()
            .remove("secrets")
            .unwrap();
        assert!(policy.get("passthrough_hosts").is_some());
        assert!(policy["secrets"][0].get("substitution").is_some());
        let mut original = raw;
        original["network"]
            .as_object_mut()
            .unwrap()
            .remove("secrets");
        assert_eq!(current, original);
        assert!(convert(&encoded, true).unwrap().is_none());
        assert!(convert(&encoded, false).is_err());
        assert!(convert(PREVIOUS_CONFIG, false).unwrap().is_none());
    }

    #[tokio::test]
    async fn migrates_both_columns_and_validates_before_writing() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        db.execute_unprepared(
            "CREATE TABLE sandbox(id INTEGER PRIMARY KEY, config TEXT, active_config TEXT, name TEXT)",
        )
        .await
        .unwrap();
        db.execute_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "INSERT INTO sandbox VALUES (1, ?, ?, 'repair-me')",
            [PREVIOUS_CONFIG.into(), "{invalid".into()],
        ))
        .await
        .unwrap();
        let manager = SchemaManager::new(&db);
        let error = Migration.up(&manager).await.unwrap_err().to_string();
        assert!(error.contains("sandbox 1 (\"repair-me\") active_config"));
        assert!(error.contains("Database upgrade was not applied"));
        assert!(error.contains("previous SDK/CLI"));
        assert!(!error.contains("{invalid"));
        let row = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT config FROM sandbox",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.try_get_by_index::<String>(0).unwrap(), PREVIOUS_CONFIG);
        db.execute_unprepared("UPDATE sandbox SET active_config = config")
            .await
            .unwrap();
        Migration.up(&manager).await.unwrap();
        let row = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT config, active_config FROM sandbox",
            ))
            .await
            .unwrap()
            .unwrap();
        let desired: String = row.try_get_by_index(0).unwrap();
        assert_eq!(desired, row.try_get_by_index::<String>(1).unwrap());
        assert_eq!(desired, convert(PREVIOUS_CONFIG, true).unwrap().unwrap());
        assert!(Migration.down(&manager).await.is_err());
        // The CLI's v0.6 projection runs before migration rollback.
        let mut value: Value = serde_json::from_str(&desired).unwrap();
        secrets::to_previous_version(value["network"]["secrets"].as_object_mut().unwrap()).unwrap();
        db.execute_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "UPDATE sandbox SET config = ?, active_config = ?",
            [value.to_string().into(), value.to_string().into()],
        ))
        .await
        .unwrap();
        Migration.down(&manager).await.unwrap();
    }
}

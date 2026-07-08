//! Migration: Rewrite legacy bind rootfs config records.
//!
//! The `RootfsSource::Bind` variant gained a `follow_root_symlinks` field, so it
//! is now serialized as an object (`{path, follow_root_symlinks}`) instead of a
//! bare path string. Rewrite persisted configs that still store the string form
//! under `image.bind` (or the legacy `image.Bind`) to the object shape, mirroring
//! the earlier OCI rootfs migration. Applies to both the `config` and
//! `active_config` columns.
//!
//! TODO(upgrade): Remove once migration history is squashed and databases
//! predating the bind-rootfs object shape no longer need direct migration.

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
        "m20260708_000001_migrate_bind_rootfs_source"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        let rows = conn
            .query_all(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT id, config, active_config FROM sandbox".to_owned(),
            ))
            .await?;

        for row in rows {
            let id = row.try_get_by_index::<i32>(0)?;
            let config = row.try_get_by_index::<String>(1)?;
            let active_config = row.try_get_by_index::<Option<String>>(2)?;

            if let Some(updated) = migrate_config(&config)? {
                conn.execute(Statement::from_sql_and_values(
                    DatabaseBackend::Sqlite,
                    "UPDATE sandbox SET config = ? WHERE id = ?",
                    [updated.into(), id.into()],
                ))
                .await?;
            }

            if let Some(active) = active_config
                && let Some(updated) = migrate_config(&active)?
            {
                conn.execute(Statement::from_sql_and_values(
                    DatabaseBackend::Sqlite,
                    "UPDATE sandbox SET active_config = ? WHERE id = ?",
                    [updated.into(), id.into()],
                ))
                .await?;
            }
        }

        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // The object shape is the canonical persisted representation. Reverting
        // would reintroduce config JSON that current code cannot read.
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Rewrite a `image.bind` (or legacy `image.Bind`) string payload into the
/// `{path, follow_root_symlinks}` object shape. Returns `None` when the config
/// carries no legacy bind string (already migrated or a different rootfs kind).
fn migrate_config(config: &str) -> Result<Option<String>, DbErr> {
    let mut value = serde_json::from_str::<serde_json::Value>(config)
        .map_err(|err| DbErr::Custom(format!("parse sandbox config JSON: {err}")))?;

    let Some(image) = value.get_mut("image") else {
        return Ok(None);
    };

    // Support both the snake_case key and the legacy capitalized alias.
    let key = if image.get("bind").is_some() {
        "bind"
    } else if image.get("Bind").is_some() {
        "Bind"
    } else {
        return Ok(None);
    };

    let Some(bind) = image.get_mut(key) else {
        return Ok(None);
    };

    // Only a bare string payload is legacy; an object is already migrated.
    let Some(path) = bind.as_str().map(str::to_owned) else {
        return Ok(None);
    };

    *bind = serde_json::json!({
        "path": path,
        "follow_root_symlinks": false,
    });

    serde_json::to_string(&value)
        .map(Some)
        .map_err(|err| DbErr::Custom(format!("serialize sandbox config JSON: {err}")))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrate_config_rewrites_legacy_bind_string() {
        let config = r#"{"name":"legacy","image":{"bind":"/srv/rootfs"}}"#;
        let updated = migrate_config(config).unwrap().unwrap();
        let value: serde_json::Value = serde_json::from_str(&updated).unwrap();

        assert_eq!(value["image"]["bind"]["path"], "/srv/rootfs");
        assert_eq!(value["image"]["bind"]["follow_root_symlinks"], false);
    }

    #[test]
    fn migrate_config_rewrites_legacy_capitalized_bind_string() {
        let config = r#"{"name":"legacy","image":{"Bind":"/srv/rootfs"}}"#;
        let updated = migrate_config(config).unwrap().unwrap();
        let value: serde_json::Value = serde_json::from_str(&updated).unwrap();

        assert_eq!(value["image"]["Bind"]["path"], "/srv/rootfs");
        assert_eq!(value["image"]["Bind"]["follow_root_symlinks"], false);
    }

    #[test]
    fn migrate_config_ignores_new_bind_object() {
        let config =
            r#"{"name":"new","image":{"bind":{"path":"/srv/rootfs","follow_root_symlinks":true}}}"#;
        assert!(migrate_config(config).unwrap().is_none());
    }

    #[test]
    fn migrate_config_ignores_non_bind_rootfs() {
        let config = r#"{"name":"oci","image":{"oci":{"reference":"ubuntu"}}}"#;
        assert!(migrate_config(config).unwrap().is_none());
    }
}

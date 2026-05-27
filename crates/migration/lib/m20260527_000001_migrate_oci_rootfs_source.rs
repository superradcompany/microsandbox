//! Migration: Rewrite legacy OCI rootfs config records.
//!
//! microsandbox 0.5 stores OCI rootfs configuration as an object so the
//! persisted config can carry the writable upper size. Earlier versions stored
//! only the image reference string under `image.Oci`.
//!
//! TODO(upgrade-0.6): Remove in 0.6.x or later if migration history is
//! squashed and pre-0.5 databases no longer need direct migration.

use sea_orm_migration::{
    prelude::*,
    sea_orm::{ConnectionTrait, DatabaseBackend, Statement},
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const DEFAULT_OCI_UPPER_SIZE_MIB: u32 = 4 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub struct Migration;

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260527_000001_migrate_oci_rootfs_source"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        let rows = conn
            .query_all(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT id, config FROM sandbox".to_owned(),
            ))
            .await?;

        for row in rows {
            let id = row.try_get_by_index::<i32>(0)?;
            let config = row.try_get_by_index::<String>(1)?;
            let Some(updated) = migrate_config(&config)? else {
                continue;
            };

            conn.execute(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "UPDATE sandbox SET config = ? WHERE id = ?",
                [updated.into(), id.into()],
            ))
            .await?;
        }

        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // The new shape is the canonical persisted representation. Reverting
        // would reintroduce config JSON that current code cannot read.
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn migrate_config(config: &str) -> Result<Option<String>, DbErr> {
    let mut value = serde_json::from_str::<serde_json::Value>(config)
        .map_err(|err| DbErr::Custom(format!("parse sandbox config JSON: {err}")))?;

    let Some(oci) = value
        .get_mut("image")
        .and_then(|image| image.get_mut("Oci"))
    else {
        return Ok(None);
    };

    let Some(reference) = oci.as_str().map(str::to_owned) else {
        return Ok(None);
    };

    *oci = serde_json::json!({
        "reference": reference,
        "upper_size_mib": DEFAULT_OCI_UPPER_SIZE_MIB,
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
    fn migrate_config_rewrites_legacy_oci_source() {
        let config = r#"{"name":"legacy","image":{"Oci":"ubuntu"}}"#;
        let updated = migrate_config(config).unwrap().unwrap();
        let value: serde_json::Value = serde_json::from_str(&updated).unwrap();

        assert_eq!(value["image"]["Oci"]["reference"], "ubuntu");
        assert_eq!(value["image"]["Oci"]["upper_size_mib"], 4096);
    }

    #[test]
    fn migrate_config_ignores_new_oci_source() {
        let config =
            r#"{"name":"new","image":{"Oci":{"reference":"ubuntu","upper_size_mib":8192}}}"#;

        assert!(migrate_config(config).unwrap().is_none());
    }
}

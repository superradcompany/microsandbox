//! Migration: Root disk kinds for the OCI writable layer.
//!
//! microsandbox 0.6 replaces `image.Oci.upper_size_mib` in persisted sandbox
//! config JSON with the structured `root_disk` spec (`{kind, ...}`), and adds
//! `sandbox_rootfs.root_disk_kind` / `root_disk_path` so spawn can dispatch on
//! the kind without parsing config.

use sea_orm_migration::{
    prelude::*,
    sea_orm::{ConnectionTrait, DatabaseBackend, Statement},
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub struct Migration;

//--------------------------------------------------------------------------------------------------
// Types: Identifiers
//--------------------------------------------------------------------------------------------------

#[derive(Iden)]
enum SandboxRootfs {
    Table,
    RootDiskKind,
    RootDiskPath,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260710_000001_migrate_root_disk"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(SandboxRootfs::Table)
                    .add_column(
                        ColumnDef::new(SandboxRootfs::RootDiskKind)
                            .text()
                            .not_null()
                            .default("managed"),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(SandboxRootfs::Table)
                    .add_column(ColumnDef::new(SandboxRootfs::RootDiskPath).text())
                    .to_owned(),
            )
            .await?;

        let conn = manager.get_connection();
        for column in ["config", "active_config"] {
            let rows = conn
                .query_all(Statement::from_string(
                    DatabaseBackend::Sqlite,
                    format!("SELECT id, {column} FROM sandbox WHERE {column} IS NOT NULL"),
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
                    format!("UPDATE sandbox SET {column} = ? WHERE id = ?"),
                    [updated.into(), id.into()],
                ))
                .await?;
            }
        }

        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // The structured root_disk shape is the canonical persisted
        // representation. Reverting would reintroduce config JSON that current
        // code cannot read.
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
        .and_then(|oci| oci.as_object_mut())
    else {
        return Ok(None);
    };

    if oci.contains_key("root_disk") {
        return Ok(None);
    }

    let Some(size) = oci.remove("upper_size_mib") else {
        return Ok(None);
    };

    if !size.is_null() {
        oci.insert(
            "root_disk".to_owned(),
            serde_json::json!({ "kind": "managed", "size_mib": size }),
        );
    }

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
    fn migrate_config_rewrites_upper_size_to_root_disk() {
        let config =
            r#"{"name":"old","image":{"Oci":{"reference":"ubuntu","upper_size_mib":8192}}}"#;
        let updated = migrate_config(config).unwrap().unwrap();
        let value: serde_json::Value = serde_json::from_str(&updated).unwrap();

        assert_eq!(value["image"]["Oci"]["reference"], "ubuntu");
        assert_eq!(value["image"]["Oci"]["root_disk"]["kind"], "managed");
        assert_eq!(value["image"]["Oci"]["root_disk"]["size_mib"], 8192);
        assert!(value["image"]["Oci"].get("upper_size_mib").is_none());
    }

    #[test]
    fn migrate_config_drops_null_upper_size_without_root_disk() {
        let config =
            r#"{"name":"old","image":{"Oci":{"reference":"ubuntu","upper_size_mib":null}}}"#;
        let updated = migrate_config(config).unwrap().unwrap();
        let value: serde_json::Value = serde_json::from_str(&updated).unwrap();

        assert!(value["image"]["Oci"].get("upper_size_mib").is_none());
        assert!(value["image"]["Oci"].get("root_disk").is_none());
    }

    #[test]
    fn migrate_config_ignores_migrated_and_non_oci_sources() {
        let migrated = r#"{"name":"new","image":{"Oci":{"reference":"ubuntu","root_disk":{"kind":"managed","size_mib":8192}}}}"#;
        assert!(migrate_config(migrated).unwrap().is_none());

        let bind = r#"{"name":"bind","image":{"Bind":"/tmp/rootfs"}}"#;
        assert!(migrate_config(bind).unwrap().is_none());
    }
}

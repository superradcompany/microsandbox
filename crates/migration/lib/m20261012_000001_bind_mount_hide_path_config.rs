//! Prevent older binaries from silently discarding persisted bind-mount hide-path lists.
//!
//! The schema itself does not change; the migration record is the compatibility
//! marker. `VolumeMount`'s deserializer tolerates unknown fields, so an older
//! binary would read a config whose bind mount carries a `hide_path` list, ignore the
//! field, and restart the sandbox with the hidden host paths exposed. Recording
//! this migration makes older binaries refuse an ahead database, and `down()`
//! refuses a downgrade while any sandbox still carries a hide-path list.

use sea_orm_migration::{
    prelude::*,
    sea_orm::{ConnectionTrait, DatabaseBackend, Statement},
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Guard persisted bind-mount hide-path lists against older catalog readers.
pub struct Migration;

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261012_000001_bind_mount_hide_path_config"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // The migration row itself is the compatibility marker.
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // An older binary would deserialize either saved config while silently
        // dropping the hide-path list, so preflight both before the marker row is
        // removed and the database becomes downgradeable again.
        let rows = manager
            .get_connection()
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT name, config, active_config FROM sandbox".to_owned(),
            ))
            .await?;

        for row in rows {
            let name: String = row.try_get("", "name")?;
            let config: String = row.try_get("", "config")?;
            reject_persisted_hide_path(&name, "config", &config)?;

            if let Some(active_config) = row.try_get::<Option<String>>("", "active_config")? {
                reject_persisted_hide_path(&name, "active_config", &active_config)?;
            }
        }

        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn reject_persisted_hide_path(name: &str, column: &str, raw: &str) -> Result<(), DbErr> {
    let value: serde_json::Value = serde_json::from_str(raw).map_err(|error| {
        DbErr::Migration(format!(
            "bind_mount_hide_path_downgrade_unrepresentable: sandbox '{name}' {column} is invalid JSON: {error}"
        ))
    })?;

    // Read raw JSON so a later policy cannot be dropped by deserialization. Only
    // an absent, null, or empty hide-path list is safe to discard. `SandboxConfig`
    // flattens `SandboxSpec`, so mounts live at the top level (`/mounts`), not
    // under `/spec`; see the guest-clock migration for the same shape. The scan
    // is shape-tolerant because `msb self downgrade` runs the v0.6.5 mount rewrap
    // (`config::prepare`) before the schema rollback reaches this guard, moving
    // the hide-path list from the mount object into its nested `bind` object.
    let has_hide_path = value
        .pointer("/mounts")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|mounts| mounts.iter().any(mount_carries_hide_path));

    if has_hide_path {
        return Err(DbErr::Migration(format!(
            "bind_mount_hide_path_downgrade_unrepresentable: sandbox '{name}' {column} contains a bind-mount hide-path list that an older binary would discard; keep a compatible binary or remove this sandbox before downgrading"
        )));
    }
    Ok(())
}

/// Whether a serialized mount object carries a non-empty `hide_path` list.
///
/// The current shape stores the list directly on the mount
/// (`{"type":"Bind","hide_path":[...]}`). A previous-version rewrap stores the same
/// fields one level down (`{"bind":{"hide_path":[...]}}`). Recursing through nested
/// objects finds the list at either nesting, so a future mount rewrite cannot
/// hide the policy from the guard. Only an absent, null, or empty list is safe.
fn mount_carries_hide_path(mount: &serde_json::Value) -> bool {
    match mount {
        serde_json::Value::Object(fields) => fields.iter().any(|(key, value)| {
            (key == "hide_path"
                && value
                    .as_array()
                    .is_some_and(|hide_path| !hide_path.is_empty()))
                || mount_carries_hide_path(value)
        }),
        serde_json::Value::Array(items) => items.iter().any(mount_carries_hide_path),
        _ => false,
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use microsandbox_types::{SandboxSpec, VolumeMount};
    use sea_orm_migration::sea_orm::{
        ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, Statement,
    };

    use super::*;
    use crate::{Migrator, MigratorTrait};

    async fn database(config: &str, active: Option<&str>) -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        db.execute_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "INSERT INTO sandbox (name, config, active_config, status, ephemeral) VALUES ('hide_path-fixture', ?, ?, 'Stopped', 0)",
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
                "SELECT config, active_config FROM sandbox WHERE name = 'hide_path-fixture'",
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

    /// A durable sandbox config carrying one bind mount with the given hide-path list.
    ///
    /// Built from the shared `SandboxSpec`, whose fields `SandboxConfig` flattens
    /// into the persisted JSON — so this is the exact production shape, with
    /// `mounts` at the top level.
    fn config(hide_path: Vec<String>) -> String {
        let mut spec = SandboxSpec::default();
        let mut mount = VolumeMount::bind("/host/data", "/data");
        if let VolumeMount::Bind {
            hide_path: mount_hide_path,
            ..
        } = &mut mount
        {
            *mount_hide_path = hide_path;
        }
        spec.mounts.push(mount);
        serde_json::to_string(&spec).unwrap()
    }

    /// A durable sandbox config with no mounts at all.
    fn config_without_mounts() -> String {
        serde_json::to_string(&SandboxSpec::default()).unwrap()
    }

    /// Pin the assumption the guard depends on: persisted configs flatten the
    /// spec, so `mounts` (and `hide_path` within them) live at the top level, not
    /// under `spec`. A regression here would make the downgrade guard dead code.
    #[test]
    fn persisted_config_places_mounts_at_top_level() {
        let value: serde_json::Value = serde_json::from_str(&config(vec![".env".into()])).unwrap();
        assert!(
            value.get("spec").is_none(),
            "SandboxConfig flattens SandboxSpec"
        );
        assert_eq!(value["mounts"][0]["hide_path"][0], ".env");
    }

    /// Proof that the pre-fix pointer `/spec/mounts` never detected a real hide_path
    /// list, while `/mounts` does. Runs the exact predicate from
    /// [`reject_persisted_hide_path`] against the production-shaped JSON.
    #[test]
    fn old_spec_pointer_was_dead_for_production_shape() {
        let raw = config(vec!["sub/.env".into()]);
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();

        let hide_path_under = |pointer: &str| {
            value
                .pointer(pointer)
                .and_then(serde_json::Value::as_array)
                .is_some_and(|mounts| {
                    mounts.iter().any(|mount| {
                        mount
                            .get("hide_path")
                            .and_then(serde_json::Value::as_array)
                            .is_some_and(|hide_path| !hide_path.is_empty())
                    })
                })
        };

        eprintln!(
            "production config shape:\n{}",
            serde_json::to_string_pretty(&value).unwrap()
        );
        eprintln!(
            "/spec/mounts detects hide_path = {}",
            hide_path_under("/spec/mounts")
        );
        eprintln!(
            "/mounts detects hide_path      = {}",
            hide_path_under("/mounts")
        );

        assert!(
            !hide_path_under("/spec/mounts"),
            "the old pointer must be proven dead on real data"
        );
        assert!(
            hide_path_under("/mounts"),
            "the new pointer must detect the hide-path list"
        );
    }

    /// Number of applied migrations from the newest down to (and including) this
    /// marker. Keeps the downgrade test independent of markers added after it.
    fn steps_to_hide_path_marker() -> u32 {
        let all = Migrator::migrations();
        let index = all
            .iter()
            .position(|migration| migration.name() == Migration.name())
            .expect("hide_path marker migration is listed");
        (all.len() - index) as u32
    }

    #[tokio::test]
    async fn downgrade_refuses_hide_path_in_desired_or_active_config() {
        let hide_path = config(vec!["sub/.env".to_string()]);
        let empty = config(Vec::new());
        for column in ["config", "active_config"] {
            let (desired, active) = if column == "config" {
                (hide_path.as_str(), empty.as_str())
            } else {
                (empty.as_str(), hide_path.as_str())
            };
            let db = database(desired, Some(active)).await;
            let before = saved_state(&db).await;

            let error = Migration.down(&SchemaManager::new(&db)).await.unwrap_err();

            let message = error.to_string();
            assert!(
                message.contains("bind_mount_hide_path_downgrade_unrepresentable"),
                "{message}"
            );
            assert!(message.contains("hide_path-fixture"), "{message}");
            assert!(message.contains(column), "{message}");
            assert_eq!(saved_state(&db).await, before);
        }
    }

    /// The v0.6.5 saved-config rewrap nests a bind mount's fields under a `bind`
    /// object (`{"bind":{"hide_path":[...]}}`). The downgrade path runs `config::prepare`
    /// before `Migrator::down`, so the guard must still find the hide-path list at the
    /// rewritten nesting instead of dropping the policy.
    #[tokio::test]
    async fn v0_6_5_downgrade_refuses_when_hide_path_wrapped_in_bind() {
        let raw =
            r#"{"mounts":[{"bind":{"host":"/host/data","guest":"/data","hide_path":[".env"]}}]}"#;
        for column in ["config", "active_config"] {
            let (desired, active) = if column == "config" {
                (raw, "{}")
            } else {
                ("{}", raw)
            };
            let db = database(desired, Some(active)).await;
            let before = saved_state(&db).await;

            let error = Migration.down(&SchemaManager::new(&db)).await.unwrap_err();

            let message = error.to_string();
            assert!(
                message.contains("bind_mount_hide_path_downgrade_unrepresentable"),
                "{message}"
            );
            assert!(message.contains("hide_path-fixture"), "{message}");
            assert!(message.contains(column), "{message}");
            assert_eq!(saved_state(&db).await, before);
        }
    }

    #[tokio::test]
    async fn downgrade_and_reupgrade_preserve_hide_path_free_configs() {
        for raw in [
            config_without_mounts(),
            config(Vec::new()),
            // A config whose serialized form predates `mounts` entirely.
            r#"{"name":"legacy"}"#.to_string(),
        ] {
            for active in [None, Some(raw.as_str())] {
                let db = database(&raw, active).await;
                let before = saved_state(&db).await;

                let steps = steps_to_hide_path_marker();
                Migrator::down(&db, Some(steps)).await.unwrap();

                let after = saved_state(&db).await;
                assert_eq!(after.0, before.0);
                assert_eq!(after.1, before.1);
                assert_eq!(before.2.len() - after.2.len(), steps as usize);
                assert!(!after.2.iter().any(|id| id == Migration.name()));

                Migrator::up(&db, None).await.unwrap();
                assert_eq!(saved_state(&db).await, before);
            }
        }
    }

    /// Released v0.6.0 `SandboxSpec` serialization. See `fixtures/README.md` for
    /// provenance: byte-for-byte copy of
    /// `git show v0.7.0:sdk/rust/lib/db/fixtures/config-0.6.0.json`, shape-verified
    /// against tag `v0.6.0`.
    const RELEASED_V0_6_0: &str = include_str!("fixtures/config-0.6.0.json");

    /// The released configuration extended with the new bind `hide_path` field, as a
    /// later release would persist it.
    fn released_config_with_bind_hide_path() -> String {
        let mut value: serde_json::Value = serde_json::from_str(RELEASED_V0_6_0).unwrap();
        value["mounts"]
            .as_array_mut()
            .expect("released fixture has mounts")
            .push(serde_json::json!({
                "type": "Bind",
                "host": "/host/data",
                "guest": "/data",
                "hide_path": [".env"]
            }));
        value.to_string()
    }

    /// Pin the released fixture's provenance assumptions: it is the v0.6.0 shape
    /// (no `hide_path`, no boot-capacity fields, released image tag) and predates the
    /// policy this guard protects.
    #[test]
    fn released_fixture_is_v0_6_0_shape_without_hide_path() {
        let value: serde_json::Value = serde_json::from_str(RELEASED_V0_6_0).unwrap();
        assert_eq!(value["name"], "catalog-fixture");
        assert!(value.pointer("/resources/cpus").is_some());
        assert!(value.pointer("/resources/max_cpus").is_none());
        assert!(value.pointer("/deployment_profile").is_none());
        assert!(value.pointer("/image/Oci").is_some());
        assert!(
            value["mounts"]
                .as_array()
                .expect("released fixture has mounts")
                .iter()
                .all(|mount| mount.get("hide_path").is_none())
        );
    }

    /// A real released v0.6.x configuration that predates hide_path downgrades cleanly
    /// across the marker; the marker is the only thing removed.
    #[tokio::test]
    async fn released_v0_6_0_fixture_without_hide_path_downgrades_cleanly() {
        let db = database(RELEASED_V0_6_0, Some(RELEASED_V0_6_0)).await;
        let before = saved_state(&db).await;

        Migrator::down(&db, Some(steps_to_hide_path_marker()))
            .await
            .unwrap();

        let after = saved_state(&db).await;
        assert_eq!(after.0, before.0);
        assert_eq!(after.1, before.1);
        assert!(!after.2.iter().any(|id| id == Migration.name()));
    }

    /// The same released fixture extended with a bind hide-path list must refuse the
    /// downgrade through `Migrator::down`, never silently drop the policy.
    #[tokio::test]
    async fn released_v0_6_0_fixture_with_added_hide_path_refuses_downgrade() {
        let hide_path = released_config_with_bind_hide_path();
        for column in ["config", "active_config"] {
            let (desired, active) = if column == "config" {
                (hide_path.as_str(), RELEASED_V0_6_0)
            } else {
                (RELEASED_V0_6_0, hide_path.as_str())
            };
            let db = database(desired, Some(active)).await;
            let before = saved_state(&db).await;

            let error = Migrator::down(&db, Some(steps_to_hide_path_marker()))
                .await
                .unwrap_err();

            let message = error.to_string();
            assert!(
                message.contains("bind_mount_hide_path_downgrade_unrepresentable"),
                "{message}"
            );
            assert!(message.contains(column), "{message}");
            assert_eq!(saved_state(&db).await, before);
        }
    }
}

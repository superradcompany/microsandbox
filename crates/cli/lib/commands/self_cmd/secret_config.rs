//! Check or rewrite secret policies before installing a historical executable.

use microsandbox_types::SecretsConfig;
use microsandbox_types::compatibility::v0_6::local::secrets;
use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseConnection, Statement};
use serde_json::Value;

use super::Version;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Target {
    V0_6 { patch: u64 },
    ReleasedV0_7,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Target {
    fn for_version(version: Version) -> Option<Self> {
        match (version.major, version.minor, version.patch) {
            (0, 6, patch) => Some(Self::V0_6 { patch }),
            (0, 7, 0..=2) => Some(Self::ReleasedV0_7),
            _ => None,
        }
    }

    fn prepare(self, raw: &str) -> Result<Option<String>, &'static str> {
        match self {
            Self::V0_6 { patch } => encode(raw, patch),
            Self::ReleasedV0_7 => {
                check_released_v0_7(raw)?;
                Ok(None)
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Targets requiring secret-policy conversion or representability checks.
pub(super) fn requires_secret_config_downgrade(version: Version) -> bool {
    Target::for_version(version).is_some()
}

/// Targets whose secret compatibility preparation can change stored records.
pub(super) fn requires_secret_config_rewrite(version: Version) -> bool {
    matches!(Target::for_version(version), Some(Target::V0_6 { .. }))
}

/// Called inside schema rollback transactions, or directly for read-only checks.
pub(super) async fn prepare(db: &DatabaseConnection, version: Version) -> anyhow::Result<()> {
    let Some(target) = Target::for_version(version) else {
        return Ok(());
    };
    let columns = db
        .query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "PRAGMA table_info(sandbox)",
        ))
        .await?;
    for column in ["config", "active_config"] {
        if !columns.iter().any(|row| {
            row.try_get::<String>("", "name")
                .is_ok_and(|name| name == column)
        }) {
            continue;
        }
        let rows = db
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                format!("SELECT id, {column} AS payload FROM sandbox WHERE {column} IS NOT NULL"),
            ))
            .await?;
        for row in rows {
            let id: i64 = row.try_get("", "id")?;
            let raw: String = row.try_get("", "payload")?;
            let encoded = target.prepare(&raw).map_err(|reason| {
                anyhow::anyhow!(
                    "secret_config_downgrade_unrepresentable: sandbox {id} {column}: {reason}"
                )
            })?;
            if let Some(encoded) = encoded {
                db.execute_raw(Statement::from_sql_and_values(
                    DatabaseBackend::Sqlite,
                    format!("UPDATE sandbox SET {column} = ? WHERE id = ?"),
                    [encoded.into(), id.into()],
                ))
                .await?;
            }
        }
    }
    Ok(())
}

fn check_released_v0_7(raw: &str) -> Result<(), &'static str> {
    let value: Value = serde_json::from_str(raw).map_err(|_| "invalid configuration JSON")?;
    let Some(policy) = value
        .pointer("/network/secrets")
        .filter(|value| !value.is_null())
    else {
        return Ok(());
    };
    let mut fields = policy.as_object().ok_or("invalid secrets object")?.clone();
    // Recognize both persisted spellings without changing the source record.
    secrets::normalize(&mut fields)?;
    if fields
        .get("passthrough_hosts")
        .is_some_and(|hosts| !hosts.is_null())
    {
        return Err(
            "v0.7.0-v0.7.2 cannot preserve global secret passthrough defaults; choose a runtime version that supports them",
        );
    }
    Ok(())
}

fn encode(raw: &str, target_patch: u64) -> Result<Option<String>, &'static str> {
    let mut value: Value = serde_json::from_str(raw).map_err(|_| "invalid configuration JSON")?;
    let Some(secrets) = value
        .pointer_mut("/network/secrets")
        .filter(|v| !v.is_null())
    else {
        return Ok(None);
    };
    if target_patch < 4
        && secrets
            .get("secrets")
            .or_else(|| secrets.get("entries"))
            .and_then(Value::as_array)
            .is_some_and(|entries| {
                entries
                    .iter()
                    .any(|entry| entry.get("source").is_some_and(|source| !source.is_null()))
            })
    {
        return Err("secret source references require v0.6.4 or later");
    }
    let current = secrets.get("violation_action").is_some()
        || secrets.get("passthrough_hosts").is_some()
        || secrets
            .get("secrets")
            .or_else(|| secrets.get("entries"))
            .and_then(Value::as_array)
            .is_some_and(|entries| {
                entries.iter().any(|entry| {
                    entry.get("substitution").is_some()
                        || entry.get("violation_action").is_some()
                        || entry.get("passthrough_hosts").is_some()
                })
            });
    // Already-historical records retain their exact bytes and independent
    // header/Basic Auth switches; downgrade must not reconvert them.
    if !current {
        return Ok(None);
    }
    let original = secrets.clone();
    let fields = secrets.as_object_mut().ok_or("invalid secrets object")?;
    secrets::normalize(fields)?;
    let expected: SecretsConfig =
        serde_json::from_value(secrets.clone()).map_err(|_| "invalid secret policy")?;
    let canonical = serde_json::to_value(expected).map_err(|_| "invalid secret policy")?;
    if !preserves(secrets, &canonical) {
        return Err("secret policy contains fields unsupported by the downgrade codec");
    }
    // Serialize defaults explicitly so historical defaults cannot enable scopes.
    *secrets = canonical.clone();
    secrets::encode(secrets.as_object_mut().ok_or("invalid secrets object")?)?;
    let mut roundtrip = secrets.clone();
    secrets::normalize(roundtrip.as_object_mut().ok_or("invalid secrets object")?)?;
    let restored: SecretsConfig =
        serde_json::from_value(roundtrip).map_err(|_| "invalid converted policy")?;
    if serde_json::to_value(restored).map_err(|_| "invalid converted policy")? != canonical {
        return Err("secret policy cannot be preserved in v0.6");
    }
    if *secrets == original {
        return Ok(None);
    }
    serde_json::to_string(&value)
        .map(Some)
        .map_err(|_| "invalid configuration JSON")
}

fn preserves(input: &Value, output: &Value) -> bool {
    match (input, output) {
        (Value::Object(input), Value::Object(output)) => input
            .iter()
            .all(|(key, value)| preserves(value, output.get(key).unwrap_or(&Value::Null))),
        (Value::Array(input), Value::Array(output)) => {
            input.len() == output.len() && input.iter().zip(output).all(|(a, b)| preserves(a, b))
        }
        _ => input == output,
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::{
        Version, open_downgrade_db, preflight_schema_rollback, rollback_schema_for_target,
    };
    use super::*;

    fn current() -> String {
        serde_json::json!({"name":"keep-name", "labels":{"keep":"value"}, "network":{"secrets":{
            "violation_action":"block-and-log", "secrets":[{
                "env_var":"TOKEN", "value":"synthetic", "placeholder":"$TOKEN",
                "allowed_hosts":[{"exact":"allowed.example"}],
                "substitution":{"headers":false,"query":true,"body":false},
                "passthrough_hosts":[{"exact":"pass.example"}]
            }]
        }}})
        .to_string()
    }

    #[test]
    fn downgrade_target_gates_include_released_v0_7_only() {
        for version in ["0.6.0", "0.6.18", "0.7.0", "0.7.1", "0.7.2"] {
            assert!(requires_secret_config_downgrade(
                Version::parse(version).unwrap()
            ));
        }
        for version in ["0.7.0", "0.7.1", "0.7.2"] {
            assert!(!requires_secret_config_rewrite(
                Version::parse(version).unwrap()
            ));
        }
        assert!(requires_secret_config_rewrite(
            Version::parse("0.6.18").unwrap()
        ));
        for version in ["0.5.0", "0.7.3", "0.8.0", "1.6.0"] {
            assert!(!requires_secret_config_downgrade(
                Version::parse(version).unwrap()
            ));
        }
    }

    #[test]
    fn populated_global_fixture_keeps_inheritance_and_overrides_through_downgrade() {
        // Hand-extended released fixture, not a new captured runtime result.
        let raw = include_str!(
            "../../../../../sdk/rust/lib/db/fixtures/config-0.6.18-global-passthrough-with-entries.json"
        );
        assert!(encode(raw, 18).unwrap().is_none());
        let mut current: Value = serde_json::from_str(raw).unwrap();
        let policy = &mut current["network"]["secrets"];
        secrets::normalize(policy.as_object_mut().unwrap()).unwrap();
        let expected: SecretsConfig = serde_json::from_value(policy.clone()).unwrap();
        let launch = secrets::for_current_runtime(&expected);
        let global = microsandbox_types::HostPattern::Exact("example.com".into());
        assert_eq!(launch.secrets[0].passthrough_hosts, vec![global.clone()]);
        assert!(launch.secrets[1].passthrough_hosts.is_empty());
        assert!(launch.secrets[2].passthrough_hosts.contains(&global));
        assert!(launch.secrets[2].passthrough_hosts.contains(
            &microsandbox_types::HostPattern::Exact("entry.example".into())
        ));
        assert!(expected.secrets[0].passthrough_hosts.is_empty());
        let downgraded = encode(&current.to_string(), 18).unwrap().unwrap();
        let mut restored: Value = serde_json::from_str(&downgraded).unwrap();
        secrets::normalize(restored["network"]["secrets"].as_object_mut().unwrap()).unwrap();
        assert_eq!(
            restored["network"]["secrets"],
            serde_json::to_value(expected).unwrap()
        );
    }

    #[test]
    fn released_v0_7_checks_global_defaults_without_mutating_supported_configs() {
        for patch in 0..=2 {
            let target =
                Target::for_version(Version::parse(&format!("0.7.{patch}")).unwrap()).unwrap();
            let raw = current();
            assert!(target.prepare(&raw).unwrap().is_none());
            for hosts in [serde_json::json!([]), serde_json::json!(["any"])] {
                let mut value: Value = serde_json::from_str(&raw).unwrap();
                value["network"]["secrets"]["passthrough_hosts"] = hosts;
                let error = target.prepare(&value.to_string()).unwrap_err();
                assert!(error.contains("cannot preserve global secret passthrough defaults"));
                assert!(!error.contains("synthetic"));
            }
            let historical = include_str!(
                "../../../../../sdk/rust/lib/db/fixtures/config-0.6.18-global-passthrough-with-entries.json"
            );
            assert!(target.prepare(historical).is_err());
        }
    }

    #[tokio::test]
    async fn released_v0_7_check_works_on_read_only_connection() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_downgrade_db(&dir.path().join("source.db"))
            .await
            .unwrap();
        db.inner()
            .execute_unprepared(
                "CREATE TABLE sandbox(id INTEGER PRIMARY KEY, config TEXT, active_config TEXT)",
            )
            .await
            .unwrap();
        let raw = current();
        db.inner()
            .execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "INSERT INTO sandbox VALUES (1, ?, ?)",
                [raw.clone().into(), raw.clone().into()],
            ))
            .await
            .unwrap();
        db.inner()
            .execute_unprepared("PRAGMA query_only = ON")
            .await
            .unwrap();
        for patch in 0..=2 {
            prepare(db.inner(), Version::parse(&format!("0.7.{patch}")).unwrap())
                .await
                .unwrap();
        }
        let row = db
            .inner()
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT config, active_config FROM sandbox",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.try_get::<String>("", "config").unwrap(), raw);
        assert_eq!(row.try_get::<String>("", "active_config").unwrap(), raw);
    }

    #[tokio::test]
    async fn released_v0_7_preflight_rejects_global_defaults_in_either_column() {
        for column in ["config", "active_config"] {
            let dir = tempfile::tempdir().unwrap();
            let db = open_downgrade_db(&dir.path().join("source.db"))
                .await
                .unwrap();
            db.inner()
                .execute_unprepared(
                    "CREATE TABLE sandbox(id INTEGER PRIMARY KEY, config TEXT, active_config TEXT)",
                )
                .await
                .unwrap();
            let raw = current();
            let mut unsupported: Value = serde_json::from_str(&raw).unwrap();
            unsupported["network"]["secrets"]["passthrough_hosts"] = serde_json::json!(["any"]);
            let unsupported = unsupported.to_string();
            let (config, active) = if column == "config" {
                (&unsupported, &raw)
            } else {
                (&raw, &unsupported)
            };
            db.inner()
                .execute_raw(Statement::from_sql_and_values(
                    DatabaseBackend::Sqlite,
                    "INSERT INTO sandbox VALUES (1, ?, ?)",
                    [config.clone().into(), active.clone().into()],
                ))
                .await
                .unwrap();
            for patch in 0..=2 {
                let target = Version::parse(&format!("0.7.{patch}")).unwrap();
                assert!(
                    prepare(db.inner(), target)
                        .await
                        .unwrap_err()
                        .to_string()
                        .contains(column)
                );
                let error = preflight_schema_rollback(
                    db.inner(),
                    &dir.path().join("preflight.db"),
                    0,
                    target,
                )
                .await
                .unwrap_err();
                assert!(error.to_string().contains(column));
                assert!(!error.to_string().contains("synthetic"));
                assert!(
                    rollback_schema_for_target(db.inner(), 0, Some(target))
                        .await
                        .is_err()
                );
                let row = db
                    .inner()
                    .query_one_raw(Statement::from_string(
                        DatabaseBackend::Sqlite,
                        "SELECT config, active_config FROM sandbox",
                    ))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(&row.try_get::<String>("", "config").unwrap(), config);
                assert_eq!(&row.try_get::<String>("", "active_config").unwrap(), active);
            }
        }
    }

    #[tokio::test]
    async fn migrated_global_policies_survive_cli_downgrade_and_reupgrade() {
        use microsandbox_migration::{Migrator, MigratorTrait};

        let dir = tempfile::tempdir().unwrap();
        let db = open_downgrade_db(&dir.path().join("source.db"))
            .await
            .unwrap();
        let before = Migrator::migrations()
            .iter()
            .position(|migration| {
                migration.name()
                    == microsandbox_migration::schema_metadata::SECRET_CONFIG_MIGRATION_ID
            })
            .unwrap();
        Migrator::up(db.inner(), Some(before as u32)).await.unwrap();
        let raw = include_str!(
            "../../../../../sdk/rust/lib/db/fixtures/config-0.6.18-global-passthrough-with-entries.json"
        );
        db.inner().execute_raw(Statement::from_sql_and_values(DatabaseBackend::Sqlite,
            "INSERT INTO sandbox (name, config, active_config, status, ephemeral) VALUES ('migration-test', ?, ?, 'Stopped', 0)",
            [raw.into(), raw.into()],
        )).await.unwrap();
        Migrator::up(db.inner(), None).await.unwrap();
        let read = || async {
            let row = db
                .inner()
                .query_one_raw(Statement::from_string(
                    DatabaseBackend::Sqlite,
                    "SELECT config, active_config FROM sandbox WHERE name = 'migration-test'",
                ))
                .await
                .unwrap()
                .unwrap();
            let config: String = row.try_get("", "config").unwrap();
            assert_eq!(config, row.try_get::<String>("", "active_config").unwrap());
            config
        };
        let migrated = read().await;
        assert!(!migrated.contains("\"injection\""));
        assert!(migrated.contains("\"substitution\""));
        let target = Version::parse("0.6.18").unwrap();
        let released_prefix = Migrator::migrations()
            .iter()
            .position(|migration| {
                migration.name()
                    == microsandbox_migration::schema_metadata::SNAPSHOT_IDENTITY_MIGRATION_ID
            })
            .unwrap();
        let steps = Migrator::migrations().len() - released_prefix;
        preflight_schema_rollback(db.inner(), &dir.path().join("preflight.db"), steps, target)
            .await
            .unwrap();
        assert_eq!(read().await, migrated);
        rollback_schema_for_target(db.inner(), steps, Some(target))
            .await
            .unwrap();
        let historical = read().await;
        assert!(historical.contains("\"injection\""));
        assert!(!historical.contains("\"substitution\""));
        Migrator::up(db.inner(), None).await.unwrap();
        assert_eq!(read().await, migrated);
    }

    #[test]
    fn conversion_preserves_unrelated_fields_and_explicit_scopes() {
        let raw = current();
        let encoded = encode(&raw, 18).unwrap().unwrap();
        let value: Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(value["labels"]["keep"], "value");
        let secret = &value["network"]["secrets"]["secrets"][0];
        assert_eq!(secret["injection"]["headers"], false);
        assert_eq!(secret["injection"]["basic_auth"], false);
        assert_eq!(secret["injection"]["query_params"], true);
        assert!(secret["on_violation"].get("passthrough").is_some());
        assert!(encode(&encoded, 18).unwrap().is_none());
    }

    #[test]
    fn historical_config_keeps_independent_header_switches() {
        let raw = r#"{"network":{"secrets":{"on_violation":"block-and-log","secrets":[{"injection":{"headers":false,"basic_auth":true}}]}}}"#;
        assert!(encode(raw, 18).unwrap().is_none());
    }

    #[test]
    fn source_references_require_a_target_that_can_resolve_them() {
        let mut value: Value = serde_json::from_str(&current()).unwrap();
        value["network"]["secrets"]["secrets"][0]["source"] =
            serde_json::json!({"kind":"env","var":"TOKEN"});
        assert!(encode(&value.to_string(), 3).is_err());
        assert!(encode(&value.to_string(), 4).is_ok());
    }

    #[tokio::test]
    async fn preflight_is_read_only_and_zero_step_rollback_rewrites_both_columns() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_downgrade_db(&dir.path().join("source.db"))
            .await
            .unwrap();
        db.inner()
            .execute_unprepared(
                "CREATE TABLE sandbox(id INTEGER PRIMARY KEY, config TEXT, active_config TEXT)",
            )
            .await
            .unwrap();
        let raw = current();
        db.inner()
            .execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "INSERT INTO sandbox VALUES (1, ?, ?)",
                [raw.clone().into(), raw.clone().into()],
            ))
            .await
            .unwrap();
        let target = Version::parse("0.6.18").unwrap();
        preflight_schema_rollback(db.inner(), &dir.path().join("preflight.db"), 0, target)
            .await
            .unwrap();
        let row = db
            .inner()
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT config FROM sandbox",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.try_get::<String>("", "config").unwrap(), raw);
        rollback_schema_for_target(db.inner(), 0, Some(target))
            .await
            .unwrap();
        let row = db
            .inner()
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT config, active_config FROM sandbox",
            ))
            .await
            .unwrap()
            .unwrap();
        for column in ["config", "active_config"] {
            assert_eq!(
                row.try_get::<String>("", column).unwrap(),
                encode(&raw, 18).unwrap().unwrap()
            );
        }
    }

    #[tokio::test]
    async fn invalid_active_policy_rolls_back_all_config_writes() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_downgrade_db(&dir.path().join("source.db"))
            .await
            .unwrap();
        db.inner()
            .execute_unprepared(
                "CREATE TABLE sandbox(id INTEGER PRIMARY KEY, config TEXT, active_config TEXT)",
            )
            .await
            .unwrap();
        let raw = current();
        let mut invalid: Value = serde_json::from_str(&raw).unwrap();
        invalid["network"]["secrets"]["secrets"][0]["violation_action"] =
            serde_json::json!("block");
        db.inner()
            .execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "INSERT INTO sandbox VALUES (1, ?, ?)",
                [raw.clone().into(), invalid.to_string().into()],
            ))
            .await
            .unwrap();
        assert!(
            preflight_schema_rollback(
                db.inner(),
                &dir.path().join("preflight.db"),
                0,
                Version::parse("0.6.18").unwrap()
            )
            .await
            .is_err()
        );
        let error =
            rollback_schema_for_target(db.inner(), 0, Some(Version::parse("0.6.18").unwrap()))
                .await
                .unwrap_err();
        assert!(error.to_string().contains("active_config"));
        assert!(!error.to_string().contains("synthetic"));
        let row = db
            .inner()
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT config FROM sandbox",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.try_get::<String>("", "config").unwrap(), raw);
    }

    /// Uses catalogs created and upgraded by real release/candidate binaries.
    #[tokio::test]
    #[ignore = "requires MSB_TEST_CATALOG_MATRIX containing isolated release fixture homes"]
    async fn released_catalog_downgrade_matrix() {
        use super::super::{SchemaBaseline, applied_migrations, build_rollback_plan};

        let manifest = std::env::var("MSB_TEST_CATALOG_MATRIX").unwrap();
        let rows: Vec<Value> = serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
        let mut results = Vec::new();
        for row in rows {
            let version = row["version"].as_str().unwrap();
            if version.starts_with("0.5.") {
                continue;
            }
            let home = std::path::Path::new(row["home"].as_str().unwrap());
            let result: anyhow::Result<()> = async {
                let db = open_downgrade_db(&home.join("db/msb.db")).await?;
                let baseline = SchemaBaseline {
                    schema_baseline_version: 1,
                    downgrade_floor: "0.6.0".into(),
                    migrations: serde_json::from_value(row["baseline"].clone())?,
                };
                let applied = applied_migrations(db.inner()).await?;
                let plan = build_rollback_plan(&baseline, &applied)?;
                let target = Version::parse(version)?;
                preflight_schema_rollback(
                    db.inner(),
                    &home.join("matrix-preflight.db"),
                    plan.steps(),
                    target,
                )
                .await?;
                rollback_schema_for_target(db.inner(), plan.steps(), Some(target)).await?;
                let restored = applied_migrations(db.inner()).await?;
                let expected: std::collections::BTreeSet<_> = baseline.migrations.iter().collect();
                anyhow::ensure!(
                    restored.iter().collect::<std::collections::BTreeSet<_>>() == expected,
                    "migration history mismatch"
                );
                drop(db);
                let binary = row["binary"].as_str().unwrap();
                let firmware = std::path::Path::new(binary)
                    .parent()
                    .unwrap()
                    .join("libkrunfw.5.dylib");
                let mut args = vec!["list"];
                if row["kind"] == "populated" {
                    args = vec!["inspect", "catalog-fixture", "--format", "json"];
                }
                let output = tokio::time::timeout(
                    std::time::Duration::from_secs(60),
                    tokio::process::Command::new(binary)
                        .args(args)
                        .env("MSB_HOME", home)
                        .env("MSB_BACKEND", "local")
                        .env("MSB_PATH", binary)
                        .env("MSB_LIBKRUNFW_PATH", firmware)
                        .env("MSB_CONFIG_PATH", home.join("config.json"))
                        .kill_on_drop(true)
                        .output(),
                )
                .await??;
                anyhow::ensure!(
                    output.status.success(),
                    "released reopen: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                Ok(())
            }
            .await;
            let error = result.err().map(|error| error.to_string());
            eprintln!(
                "{} {}: {}",
                version,
                row["kind"],
                error.as_deref().unwrap_or("PASS")
            );
            results.push(serde_json::json!({"version":version,"kind":row["kind"],"error":error}));
        }
        std::fs::write(
            std::path::Path::new(&manifest).with_file_name("downgrade-results.json"),
            serde_json::to_vec_pretty(&results).unwrap(),
        )
        .unwrap();
        assert!(
            results.iter().all(|row| row["error"].is_null()),
            "see downgrade-results.json"
        );
    }

    /// Requires explicit released/candidate binaries; never runs on the user's catalog.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    #[ignore = "requires released v0.6.18 SDK/runtime and codesigned candidate runtime"]
    async fn released_sdk_secret_downgrade() {
        use super::super::{SchemaBaseline, applied_migrations, build_rollback_plan};
        let dir = tempfile::Builder::new()
            .prefix("msb-secret-down-")
            .tempdir_in("/tmp")
            .unwrap();
        let old_python = std::env::var("MSB_TEST_OLD_PYTHON").unwrap();
        let old_runtime = std::env::var("MSB_TEST_OLD_RUNTIME").unwrap();
        let new_python = std::env::var("MSB_TEST_NEW_PYTHON").unwrap();
        let new_runtime = std::env::var("MSB_TEST_NEW_RUNTIME").unwrap();
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/smoke/sdk/secret-downgrade.py");
        let phase = |name: &'static str, python: String, runtime: String| {
            let script = script.clone();
            let home = dir.path().to_path_buf();
            async move {
                let firmware = std::path::Path::new(&runtime)
                    .parent()
                    .unwrap()
                    .join("libkrunfw.5.dylib");
                let output = tokio::time::timeout(
                    std::time::Duration::from_secs(180),
                    tokio::process::Command::new(python)
                        .arg(script)
                        .arg(name)
                        .env("MSB_HOME", home)
                        .env("MSB_PATH", runtime)
                        .env("MSB_LIBKRUNFW_PATH", firmware)
                        .kill_on_drop(true)
                        .output(),
                )
                .await
                .unwrap()
                .unwrap();
                assert!(
                    output.status.success(),
                    "phase {name}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                eprintln!("{}", String::from_utf8_lossy(&output.stdout));
            }
        };
        phase("create", old_python.clone(), old_runtime.clone()).await;
        let db_path = dir
            .path()
            .join(microsandbox_utils::DB_SUBDIR)
            .join(microsandbox_utils::DB_FILENAME);
        let db = open_downgrade_db(&db_path).await.unwrap();
        let original_migrations = applied_migrations(db.inner()).await.unwrap();
        drop(db);
        phase("edit", new_python, new_runtime).await;
        let db = open_downgrade_db(&db_path).await.unwrap();
        let row = db
            .inner()
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT config FROM sandbox",
            ))
            .await
            .unwrap()
            .unwrap();
        let before: Value =
            serde_json::from_str(&row.try_get::<String>("", "config").unwrap()).unwrap();
        assert!(
            before
                .pointer("/network/secrets/secrets/0/substitution")
                .is_some()
        );
        assert_eq!(before["labels"]["downgrade-test"], "edited-by-v07");
        let baseline = SchemaBaseline {
            schema_baseline_version: 1,
            downgrade_floor: "0.6.0".into(),
            migrations: original_migrations,
        };
        let applied = applied_migrations(db.inner()).await.unwrap();
        let plan = build_rollback_plan(&baseline, &applied).unwrap();
        let target = Version::parse("0.6.18").unwrap();
        preflight_schema_rollback(
            db.inner(),
            &dir.path().join("preflight.db"),
            plan.steps(),
            target,
        )
        .await
        .unwrap();
        rollback_schema_for_target(db.inner(), plan.steps(), Some(target))
            .await
            .unwrap();
        drop(db);
        phase("restart", old_python, old_runtime).await;
    }
}

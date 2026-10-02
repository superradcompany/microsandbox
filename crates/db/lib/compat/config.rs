//! Dispatch for configurations from previous versions stored in the local SQLite database.

use sea_orm::{ConnectionTrait, DatabaseBackend, DbErr, Statement};
use semver::Version;
use serde_json::Value;

use crate::compat;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Check or rewrite sandbox `config` and `active_config` for a target release.
/// Call inside the caller's rollback transaction when rewriting records; this
/// function does not start or commit a transaction. Targets requiring only
/// representability checks can use a read-only connection.
pub async fn prepare<C: ConnectionTrait>(db: &C, version: &Version) -> Result<(), DbErr> {
    if !requires_downgrade(version) {
        return Ok(());
    }
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
            let encoded = to_previous_version(&raw, version).map_err(|reason| {
                DbErr::Custom(format!(
                    "secret_config_downgrade_unrepresentable: sandbox {id} {column}: {reason}"
                ))
            })?;
            if let Some(encoded) = encoded {
                if !requires_rewrite(version) {
                    return Err(DbErr::Custom(
                        "read-only compatibility check requested a configuration rewrite".into(),
                    ));
                }
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

/// Convert supported saved formats from previous versions without dropping unknown fields.
pub fn to_current(value: &mut Value) -> Result<(), &'static str> {
    compat::v0_6_5::config::to_current(value)?;
    compat::v0_5_0::secrets::to_current(value)
}

/// Prepare a saved configuration for a previous contract.
/// Returns `None` when the original bytes already work; rejects lossy conversions.
pub fn to_previous_version(raw: &str, version: &Version) -> Result<Option<String>, &'static str> {
    if !version.pre.is_empty() {
        return Err("saved-config compatibility requires a stable release version");
    }
    match (version.major, version.minor, version.patch) {
        (0, 6, patch) => to_v0_6(raw, patch),
        (0, 7, 0..=2) => compat::v0_7_0::secrets::to_previous_version(raw),
        _ => Ok(None),
    }
}

/// Whether this destination requires saved-config conversion or representability checks.
/// Installation support and downgrade floors are checked by the caller.
pub fn requires_downgrade(version: &Version) -> bool {
    matches!(
        (version.major, version.minor, version.patch),
        (0, 6, _) | (0, 7, 0..=2)
    )
}

/// Whether compatibility preparation for this destination can rewrite saved records.
pub fn requires_rewrite(version: &Version) -> bool {
    matches!((version.major, version.minor), (0, 6))
}

// Secret source references arrived in v0.6.4; the policy shape predates v0.6.
fn to_v0_6(raw: &str, target_patch: u64) -> Result<Option<String>, &'static str> {
    let value: Value = serde_json::from_str(raw).map_err(|_| "invalid configuration JSON")?;
    if target_patch < 4
        && let Some(secrets) = value.pointer("/network/secrets")
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
    let encoded = compat::v0_5_0::secrets::to_previous_version(raw)?;
    if target_patch != 5 {
        return Ok(encoded);
    }
    let input = encoded.as_deref().unwrap_or(raw);
    let mut value: Value = serde_json::from_str(input).map_err(|_| "invalid configuration JSON")?;
    let original = value.clone();
    compat::v0_6_5::config::to_previous_version(&mut value)?;
    if value == original {
        return Ok(encoded);
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
    use super::*;
    use microsandbox_types::compat::v0_5_0::local::secrets;
    use microsandbox_types::{SecretsConfig, compat};

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
    fn v0_6_5_downgrade_restores_cpu_and_mount_fields_without_losing_settings() {
        let raw = include_str!("../../../../sdk/rust/lib/db/fixtures/config-0.6.5.json");
        let mut value: Value = serde_json::from_str(raw).unwrap();
        value["resources"]["vcpus"] = serde_json::json!(4);
        value["resources"]["max_vcpus"] = serde_json::json!(8);
        value["unrecognized_saved_field"] = serde_json::json!({"keep": true});
        to_current(&mut value).unwrap();
        let encoded = to_previous_version(&value.to_string(), &Version::new(0, 6, 5))
            .unwrap()
            .unwrap();
        let mut previous: Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(previous["resources"]["vcpus"], 4);
        assert_eq!(previous["resources"]["max_vcpus"], 8);
        assert!(previous["resources"].get("cpus").is_none());
        assert_eq!(previous["mounts"][0]["tmpfs"]["size_mib"], 64);
        // Root-disk rollback still needs this spelling before schema rollback.
        assert!(previous["image"].get("Oci").is_some());
        to_current(&mut previous).unwrap();
        assert_eq!(previous, value);
        assert!(
            to_previous_version(&encoded, &Version::new(0, 6, 5))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn v0_6_5_downgrade_rejects_unrepresentable_mounts() {
        let raw = serde_json::json!({"mounts":[{"type":"Owned","guest":"/data"}]}).to_string();
        assert!(
            to_previous_version(&raw, &Version::new(0, 6, 5))
                .unwrap_err()
                .contains("mount type")
        );
    }

    #[test]
    fn downgrade_target_gates_include_released_v0_7_only() {
        for version in ["0.6.0", "0.6.18", "0.7.0", "0.7.1", "0.7.2"] {
            assert!(requires_downgrade(&Version::parse(version).unwrap()));
        }
        for version in ["0.7.0", "0.7.1", "0.7.2"] {
            assert!(!requires_rewrite(&Version::parse(version).unwrap()));
        }
        assert!(requires_rewrite(&Version::parse("0.6.18").unwrap()));
        for version in ["0.5.0", "0.7.3", "0.8.0", "1.6.0"] {
            assert!(!requires_downgrade(&Version::parse(version).unwrap()));
        }
    }

    #[test]
    fn populated_global_fixture_keeps_inheritance_and_overrides_through_downgrade() {
        // Hand-extended released fixture, not a new captured runtime result.
        let raw = include_str!(
            "../../../../sdk/rust/lib/db/fixtures/config-0.6.18-global-passthrough-with-entries.json"
        );
        assert!(
            to_previous_version(raw, &Version::new(0, 6, 18))
                .unwrap()
                .is_none()
        );
        let mut current: Value = serde_json::from_str(raw).unwrap();
        let policy = &mut current["network"]["secrets"];
        secrets::to_current(policy.as_object_mut().unwrap()).unwrap();
        let expected: SecretsConfig = serde_json::from_value(policy.clone()).unwrap();
        let launch = compat::v0_7_0::local::secrets::to_previous_version(&expected);
        let global = microsandbox_types::HostPattern::Exact("example.com".into());
        assert_eq!(launch.secrets[0].passthrough_hosts, vec![global.clone()]);
        assert!(launch.secrets[1].passthrough_hosts.is_empty());
        assert!(launch.secrets[2].passthrough_hosts.contains(&global));
        assert!(launch.secrets[2].passthrough_hosts.contains(
            &microsandbox_types::HostPattern::Exact("entry.example".into())
        ));
        assert!(expected.secrets[0].passthrough_hosts.is_empty());
        let downgraded = to_previous_version(&current.to_string(), &Version::new(0, 6, 18))
            .unwrap()
            .unwrap();
        let mut restored: Value = serde_json::from_str(&downgraded).unwrap();
        secrets::to_current(restored["network"]["secrets"].as_object_mut().unwrap()).unwrap();
        assert_eq!(
            restored["network"]["secrets"],
            serde_json::to_value(expected).unwrap()
        );
    }

    #[test]
    fn released_v0_7_checks_global_defaults_without_mutating_supported_configs() {
        for patch in 0..=2 {
            let target = Version::new(0, 7, patch);
            let raw = current();
            assert!(to_previous_version(&raw, &target).unwrap().is_none());
            for hosts in [serde_json::json!([]), serde_json::json!(["any"])] {
                let mut value: Value = serde_json::from_str(&raw).unwrap();
                value["network"]["secrets"]["passthrough_hosts"] = hosts;
                let error = to_previous_version(&value.to_string(), &target).unwrap_err();
                assert!(error.contains("cannot preserve global secret passthrough defaults"));
                assert!(!error.contains("synthetic"));
            }
            let previous = include_str!(
                "../../../../sdk/rust/lib/db/fixtures/config-0.6.18-global-passthrough-with-entries.json"
            );
            assert!(to_previous_version(previous, &target).is_err());
        }
    }

    #[test]
    fn conversion_preserves_unrelated_fields_and_explicit_scopes() {
        let raw = current();
        let encoded = to_previous_version(&raw, &Version::new(0, 6, 18))
            .unwrap()
            .unwrap();
        let value: Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(value["labels"]["keep"], "value");
        let secret = &value["network"]["secrets"]["secrets"][0];
        assert_eq!(secret["injection"]["headers"], false);
        assert_eq!(secret["injection"]["basic_auth"], false);
        assert_eq!(secret["injection"]["query_params"], true);
        assert!(secret["on_violation"].get("passthrough").is_some());
        assert!(
            to_previous_version(&encoded, &Version::new(0, 6, 18))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn previous_version_config_keeps_independent_header_switches() {
        let raw = r#"{"network":{"secrets":{"on_violation":"block-and-log","secrets":[{"injection":{"headers":false,"basic_auth":true}}]}}}"#;
        assert!(
            to_previous_version(raw, &Version::new(0, 6, 18))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn source_references_require_a_target_that_can_resolve_them() {
        let mut value: Value = serde_json::from_str(&current()).unwrap();
        value["network"]["secrets"]["secrets"][0]["source"] =
            serde_json::json!({"kind":"env","var":"TOKEN"});
        assert!(to_previous_version(&value.to_string(), &Version::new(0, 6, 3)).is_err());
        assert!(to_previous_version(&value.to_string(), &Version::new(0, 6, 4)).is_ok());
    }

    #[test]
    fn release_boundaries_select_the_saved_config_contract() {
        let raw = r#"{"network":{"secrets":{"passthrough_hosts":[],"secrets":[]}}}"#;
        assert!(
            to_previous_version(raw, &Version::new(0, 6, 18))
                .unwrap()
                .is_some()
        );
        for patch in 0..=2 {
            let version = Version::new(0, 7, patch);
            assert!(requires_downgrade(&version));
            assert!(!requires_rewrite(&version));
            assert!(
                to_previous_version(raw, &version)
                    .unwrap_err()
                    .contains("cannot preserve")
            );
        }
        let version = Version::new(0, 7, 3);
        assert!(!requires_downgrade(&version));
        assert!(to_previous_version(raw, &version).unwrap().is_none());
        assert!(to_previous_version(raw, &Version::parse("0.6.18-preview").unwrap()).is_err());
    }
}

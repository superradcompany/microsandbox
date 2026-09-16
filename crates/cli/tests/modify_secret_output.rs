//! Secret-output regression coverage through the real CLI, without starting a VM.

#![cfg(feature = "net")]

use std::{path::Path, process::Output, time::Duration};

use microsandbox::SandboxConfig;
use microsandbox_db::{DbWriteConnection, entity::sandbox};
use microsandbox_migration::{Migrator, MigratorTrait};
use microsandbox_types::{
    HostPattern, SecretEntry, SecretSource, SecretSubstitution, SecretsConfig,
};
use sea_orm::{ActiveModelTrait, EntityTrait, Set};
use tokio::{process::Command, time::timeout};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const SANDBOX: &str = "modify-secret-output";
const SECRET_ENV: &str = "MSB_MODIFY_OUTPUT_TOKEN";
const STORED_SENTINEL: &str = "cli-stored-secret-sentinel-7f2b9c";
const HOST_SENTINEL: &str = "cli-host-secret-sentinel-4a8d1e";
const HOST: &str = "api.example.test";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn modify(home: &Path, json: bool, dry_run: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_msb"));
    // Isolate selection and runtime configuration without mutating the test
    // process's environment, so the two output formats can run in parallel.
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("MSB_") {
            command.env_remove(key);
        }
    }
    command
        .env("MSB_HOME", home)
        .env("MSB_BACKEND", "local")
        .env(SECRET_ENV, HOST_SENTINEL)
        .env("NO_COLOR", "1")
        .args(["modify", SANDBOX, "--secret"])
        .arg(format!("{SECRET_ENV}@{HOST}"))
        .kill_on_drop(true);
    if json {
        command.args(["--format", "json"]);
    }
    if dry_run {
        command.arg("--dry-run");
    }
    timeout(COMMAND_TIMEOUT, command.output())
        .await
        .expect("modify must finish without a running VM")
        .expect("spawn freshly built msb")
}

fn assert_safe_output(output: &Output, json: bool, applied: bool) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Check both streams before including diagnostics in subsequent failures.
    // The stored value is genuinely loaded by planning; the host value is
    // present in the child's environment, not merely an absent search string.
    for sentinel in [STORED_SENTINEL, HOST_SENTINEL] {
        assert!(!stdout.contains(sentinel), "stdout exposed secret material");
        assert!(!stderr.contains(sentinel), "stderr exposed secret material");
    }
    assert!(
        output.status.success(),
        "modify failed: stdout={stdout}; stderr={stderr}"
    );
    if json {
        let plan: serde_json::Value = serde_json::from_str(&stdout).expect("valid plan JSON");
        assert_eq!(plan["sandbox"], SANDBOX);
        assert_eq!(plan["status"], "stopped");
        assert_eq!(plan["applied"], applied);
        assert_eq!(plan["conflicts"], serde_json::json!([]));
        let changes = plan["changes"].as_array().expect("plan changes");
        assert!(changes.iter().any(|change| {
            change["kind"] == "secret"
                && change["name"] == SECRET_ENV
                && change["change"] == "rotated"
                && change["disposition"] == "next start"
        }));
    } else if applied {
        let combined = format!("{stdout}\n{stderr}");
        assert!(combined.contains("Modified"));
        assert!(combined.contains(SANDBOX));
    } else {
        assert!(stdout.contains(&format!("$MSB_{SECRET_ENV}")));
        assert!(stdout.contains("rotated"));
        assert!(stderr.contains("dry run"));
        assert!(stderr.contains("nothing applied"));
    }
}

async fn check_secret_output(json: bool) {
    let home = tempfile::tempdir().expect("isolated home");
    let db_dir = home.path().join(microsandbox_utils::DB_SUBDIR);
    std::fs::create_dir_all(&db_dir).expect("create isolated database directory");
    let database = DbWriteConnection::open(
        &db_dir.join(microsandbox_utils::DB_FILENAME),
        Duration::from_secs(5),
        Duration::from_secs(5),
    )
    .await
    .expect("open fixture database");
    Migrator::up(database.inner(), None)
        .await
        .expect("apply real database migrations");

    // A stopped, non-ephemeral row needs no image, runtime, or agent. Seed
    // actual inline material so dumping the loaded config would fail the test.
    let mut config = SandboxConfig::default();
    config.spec.name = SANDBOX.to_string();
    config.spec.network.secrets = Some(SecretsConfig {
        secrets: vec![SecretEntry {
            env_var: SECRET_ENV.to_string(),
            value: zeroize::Zeroizing::new(STORED_SENTINEL.to_string()),
            source: None,
            placeholder: format!("$MSB_{SECRET_ENV}"),
            allowed_hosts: vec![HostPattern::Exact(HOST.to_string())],
            substitution: SecretSubstitution::default(),
            passthrough_hosts: Vec::new(),
            violation_action: None,
            require_tls_identity: true,
        }],
        ..SecretsConfig::default()
    });
    let original_config = serde_json::to_string(&config).expect("serialize fixture config");
    assert!(original_config.contains(STORED_SENTINEL));
    let model = sandbox::ActiveModel {
        name: Set(SANDBOX.to_string()),
        config: Set(original_config.clone()),
        active_config: Set(None),
        status: Set(sandbox::SandboxStatus::Stopped),
        ephemeral: Set(false),
        created_at: Set(None),
        updated_at: Set(None),
        ..Default::default()
    }
    .insert(&database)
    .await
    .expect("insert stopped sandbox");

    assert_safe_output(&modify(home.path(), json, true).await, json, false);
    let planned = sandbox::Entity::find_by_id(model.id)
        .one(&database)
        .await
        .unwrap()
        .expect("sandbox remains after dry run");
    assert_eq!(planned.config, original_config, "dry run must not persist");

    assert_safe_output(&modify(home.path(), json, false).await, json, true);
    let applied = sandbox::Entity::find_by_id(model.id)
        .one(&database)
        .await
        .unwrap()
        .expect("sandbox remains after apply");
    assert_eq!(applied.status, sandbox::SandboxStatus::Stopped);
    assert!(applied.active_config.is_none());
    assert!(!applied.config.contains(STORED_SENTINEL));
    assert!(!applied.config.contains(HOST_SENTINEL));
    let config: SandboxConfig = serde_json::from_str(&applied.config).unwrap();
    let secrets = config
        .spec
        .network
        .secrets
        .expect("persisted secret policy");
    assert_eq!(secrets.secrets.len(), 1);
    assert!(secrets.secrets[0].value.is_empty());
    assert_eq!(
        secrets.secrets[0].source,
        Some(SecretSource::Env {
            var: SECRET_ENV.to_string(),
        })
    );
    // Close SQLite explicitly before the temporary directory is removed,
    // including on Windows where open handles prevent file deletion.
    database.inner().clone().close().await.unwrap();
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn human_plan_and_apply_do_not_expose_secret_values() {
    check_secret_output(false).await;
}

#[tokio::test]
async fn json_plan_and_apply_do_not_expose_secret_values() {
    check_secret_output(true).await;
}

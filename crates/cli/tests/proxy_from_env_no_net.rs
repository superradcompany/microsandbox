//! Ambient proxy admission in a CLI built without networking.
#![cfg(not(feature = "net"))]

use std::{
    path::Path,
    process::{Command, Output},
    time::Duration,
};

use microsandbox::SandboxConfig;
use microsandbox_db::{DbWriteConnection, entity::sandbox};
use microsandbox_migration::{Migrator, MigratorTrait};
use sea_orm::{ActiveModelTrait, EntityTrait, Set};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// The build-feature refusal, which must precede any runtime or lifecycle work.
const REFUSAL: &str = "requires a microsandbox SDK build with networking enabled";

const SANDBOX: &str = "ambient-row";

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

fn msb() -> Command {
    Command::new(env!("CARGO_BIN_EXE_msb"))
}

/// Short home inside `/tmp`: the runtime derives Unix socket paths from it.
fn home() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("msb-pfe-")
        .tempdir_in("/tmp")
        .expect("isolated home")
}

/// Run `msb` against an isolated home with the caller's environment kept out.
fn run(home: &Path, arguments: &[&str], environment: &[(&str, &str)]) -> Output {
    let mut command = msb();
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("MSB_") {
            command.env_remove(key);
        }
    }
    command
        .env("MSB_HOME", home)
        .env("MSB_BACKEND", "local")
        .env("NO_COLOR", "1")
        .args(arguments);
    for (key, value) in environment {
        command.env(key, value);
    }
    command.output().expect("spawn the freshly built msb")
}

fn assert_refused(output: &Output, context: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "{context}: unexpectedly succeeded"
    );
    assert!(
        stderr.contains(REFUSAL),
        "{context}: expected the build-feature refusal, got {stderr}"
    );
}

fn assert_not_refused(output: &Output, context: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains(REFUSAL),
        "{context}: ambient intent must not be refused here, got {stderr}"
    );
}

/// Seed one saved shared-spec row, exactly as an SDK launch would leave it.
async fn seed(
    home: &Path,
    status: sandbox::SandboxStatus,
    proxy_from_env: bool,
) -> DbWriteConnection {
    let db_dir = home.join(microsandbox_utils::DB_SUBDIR);
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

    let mut config = SandboxConfig::default();
    config.spec.name = SANDBOX.to_string();
    config.spec.network.proxy_from_env = proxy_from_env;
    let raw = serde_json::to_string(&config).expect("serialize fixture config");
    let active = raw.clone();
    sandbox::ActiveModel {
        name: Set(SANDBOX.to_string()),
        config: Set(raw),
        active_config: Set(Some(active)),
        status: Set(status),
        ephemeral: Set(false),
        ..Default::default()
    }
    .insert(&database)
    .await
    .expect("insert fixture sandbox");

    database
}

/// Read back the saved row so a refusal can be shown to have changed nothing.
async fn saved(database: &DbWriteConnection) -> (sandbox::SandboxStatus, String, Option<String>) {
    let row = sandbox::Entity::find()
        .one(database)
        .await
        .expect("read fixture sandbox")
        .expect("fixture sandbox remains");
    (row.status, row.config, row.active_config)
}

#[test]
fn proxy_from_env_no_net_launch_protocol_advertises_false() {
    let output = msb().arg("__launch-protocol").output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let capabilities: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(capabilities["protocols"], serde_json::json!([2, 1]));
    assert_eq!(
        capabilities["proxy_from_env"],
        serde_json::json!(false),
        "a build without networking must not advertise ambient discovery"
    );
}

#[test]
fn proxy_from_env_no_net_flag_is_unavailable() {
    let output = msb()
        .args(["run", "--proxy-from-env", "alpine"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--proxy-from-env"), "{stderr}");
    assert!(
        stderr.contains("unexpected argument") || stderr.contains("unrecognized"),
        "{stderr}"
    );

    // Explicit `=false` is just as unavailable: the flag does not exist at all.
    let output = msb()
        .args(["run", "--proxy-from-env=false", "alpine"])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

/// The toggle and saved defaults must reach the core refusal through the real
/// binary, not only through the flag parser.
#[test]
fn proxy_from_env_no_net_defaults_reach_the_build_refusal() {
    let home = home();

    // Host toggle as the only source of intent.
    let output = run(
        home.path(),
        &["create", "alpine"],
        &[("MSB_PROXY_FROM_ENV", "1")],
    );
    assert_refused(&output, "toggle default");

    // An accepted spelling is enough; the value is not echoed back.
    for value in ["true", "YES", "On"] {
        let output = run(
            home.path(),
            &["create", "alpine"],
            &[("MSB_PROXY_FROM_ENV", value)],
        );
        assert_refused(&output, &format!("toggle {value}"));
    }

    // Ordinary user defaults from the saved configuration file.
    std::fs::write(
        home.path().join(microsandbox_utils::CONFIG_FILENAME),
        "{\"version\":1,\"sandbox_defaults\":{\"proxy_from_env\":true}}\n",
    )
    .expect("write user defaults");
    let output = run(home.path(), &["create", "alpine"], &[]);
    assert_refused(&output, "user default");

    // The toggle sits above ordinary defaults: an explicit `0` disables the saved
    // `true`, so the request proceeds past the build refusal.
    let output = run(
        home.path(),
        &["create", "alpine"],
        &[("MSB_PROXY_FROM_ENV", "0")],
    );
    assert_not_refused(&output, "toggle below explicit disable");
}

/// Saved shared-spec rows are admitted through start, ordinary restart, and
/// restart-backed modification before any lifecycle mutation.
#[tokio::test]
async fn proxy_from_env_no_net_saved_rows_refuse_every_lifecycle_path() {
    let commands: &[(&str, sandbox::SandboxStatus, &[&str])] = &[
        (
            "start",
            sandbox::SandboxStatus::Stopped,
            &["start", SANDBOX],
        ),
        (
            "restart",
            sandbox::SandboxStatus::Running,
            &["restart", SANDBOX],
        ),
        (
            "restart-backed modify",
            sandbox::SandboxStatus::Running,
            &["modify", SANDBOX, "--workdir", "/srv", "--restart"],
        ),
    ];

    for (context, status, arguments) in commands {
        let home = home();
        let database = seed(home.path(), *status, true).await;
        let before = saved(&database).await;

        let output = run(home.path(), arguments, &[]);
        assert_refused(&output, context);
        assert_eq!(
            saved(&database).await,
            before,
            "{context}: a refused row must keep its status, desired and active state"
        );
        database.inner().clone().close().await.unwrap();
    }
}

/// The same lifecycle paths, with ambient intent saved as `false`, must reach the
/// ordinary runtime work instead of the build refusal.
#[tokio::test]
async fn proxy_from_env_no_net_saved_false_rows_are_admitted() {
    let commands: &[(&str, sandbox::SandboxStatus, &[&str])] = &[
        (
            "start",
            sandbox::SandboxStatus::Stopped,
            &["start", SANDBOX],
        ),
        (
            "restart",
            sandbox::SandboxStatus::Running,
            &["restart", SANDBOX],
        ),
        (
            "restart-backed modify",
            sandbox::SandboxStatus::Running,
            &["modify", SANDBOX, "--workdir", "/srv", "--restart"],
        ),
    ];

    for (context, status, arguments) in commands {
        let home = home();
        let database = seed(home.path(), *status, false).await;

        let output = run(home.path(), arguments, &[]);
        assert_not_refused(&output, context);
        // The refusal happens before the stop; without it, the missing runtime stops
        // the command later. Either way the saved intent is what admission read.
        let (_, config, _) = saved(&database).await;
        let config: SandboxConfig = serde_json::from_str(&config).expect("saved config");
        assert!(
            !config.spec.network.proxy_from_env,
            "{context}: saved intent must survive the command"
        );
        database.inner().clone().close().await.unwrap();
    }
}

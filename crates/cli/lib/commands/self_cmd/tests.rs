//! Tests for CLI self-update and downgrade operations.

use microsandbox_db::compat as db_compat;
use microsandbox_db::compat::config::prepare;
use serde_json::Value;

use super::*;

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn downgrade_operation_lock_child() {
    let Some(home) = std::env::var_os("MSB_TEST_DOWNGRADE_LOCK_HOME") else {
        return;
    };
    let db_dir = PathBuf::from(home);
    match std::env::var("MSB_TEST_DOWNGRADE_LOCK_MODE")
        .unwrap()
        .as_str()
    {
        "owner" => {
            // Model an already-running command using the previous lock
            // acquisition path, not just two copies of the new helper.
            let _guard = acquire_migration_lock(&db_dir.join("self-downgrade")).unwrap();
            println!("DOWNGRADE_LOCK_READY");
            std::io::stdout().flush().unwrap();
            std::io::stdin().read_line(&mut String::new()).unwrap();
        }
        "contender" => {
            let error = acquire_downgrade_operation_lock(&db_dir)
                .err()
                .expect("a live owner must exclude a competing downgrade");
            assert!(
                error
                    .to_string()
                    .contains("another downgrade is in progress"),
                "{error}"
            );
        }
        "catalog" => {
            // Ordinary catalog admission uses a different lock namespace.
            drop(acquire_migration_lock(&db_dir).unwrap());
        }
        mode => panic!("unknown lock test mode: {mode}"),
    }
}

#[tokio::test]
async fn downgrade_operation_lock_fails_promptly_and_recovers_after_owner_exit() {
    use std::process::Stdio;

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    for kill_owner in [false, true] {
        let home = tempfile::tempdir().unwrap();
        let child_command = |mode| {
            let mut command = TokioCommand::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "commands::self_cmd::tests::downgrade_operation_lock_child",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("MSB_TEST_DOWNGRADE_LOCK_HOME", home.path())
                .env("MSB_TEST_DOWNGRADE_LOCK_MODE", mode)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .kill_on_drop(true);
            command
        };
        let mut owner = child_command("owner").spawn().unwrap();
        let mut output = BufReader::new(owner.stdout.take().unwrap()).lines();
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let line = output
                    .next_line()
                    .await
                    .unwrap()
                    .expect("owner exited before locking");
                if line.ends_with("DOWNGRADE_LOCK_READY") {
                    break;
                }
            }
        })
        .await
        .expect("owner must acquire the operation lock");

        // Rejection must neither wait for nor unlock the first command.
        // Repeating also catches an erroneous unlock by a failed contender.
        // Bound the separate catalog-lock probe too: a future path mix-up
        // must fail the test rather than hang its async runtime.
        for mode in ["contender", "contender", "catalog"] {
            let mut contender = child_command(mode).spawn().unwrap();
            let status = tokio::time::timeout(Duration::from_secs(5), contender.wait())
                .await
                .expect("competing downgrade must not wait for the owner")
                .unwrap();
            assert!(status.success());
        }
        if kill_owner {
            owner.start_kill().unwrap();
        } else {
            owner.stdin.take().unwrap().write_all(b"\n").await.unwrap();
        }
        let status = tokio::time::timeout(Duration::from_secs(5), owner.wait())
            .await
            .expect("owner must exit")
            .unwrap();
        if !kill_owner {
            assert!(status.success());
        }
        drop(acquire_downgrade_operation_lock(home.path()).unwrap());
        // Leaving the lock file behind must not turn it into a stale lease.
        assert!(
            home.path()
                .join("self-downgrade/msb.db.migration.lock")
                .exists()
        );
        drop(acquire_downgrade_operation_lock(home.path()).unwrap());
    }
}

#[test]
fn downgrade_operation_lock_preserves_filesystem_errors() {
    let home = tempfile::tempdir().unwrap();
    fs::write(home.path().join("self-downgrade"), "not a directory").unwrap();
    let error = acquire_downgrade_operation_lock(home.path()).err().unwrap();
    assert!(
        !error
            .to_string()
            .contains("another downgrade is in progress")
    );
    assert!(error.downcast_ref::<std::io::Error>().is_some());
}

#[test]
fn cancellation_retires_only_unstarted_downgrade_journals() {
    for phase in [
        DowngradePhase::TargetStaged,
        DowngradePhase::PreflightComplete,
        DowngradePhase::BackupComplete,
        DowngradePhase::ArtifactsReverting,
        DowngradePhase::ArtifactsReverted,
        DowngradePhase::DatabaseReverted,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let directory = dir.path().join("operation");
        fs::create_dir(&directory).unwrap();
        let journal = DowngradeOperationJournal {
            format_version: 1,
            operation_id: "operation".into(),
            source_version: "0.7.0".into(),
            target_version: "0.6.18".into(),
            phase,
            target_dir: directory.join("target"),
            recovery_dir: directory.join("recovery"),
            backup_path: None,
            updated_at: chrono::Utc::now().to_rfc3339(),
        };
        let bytes = serde_json::to_vec(&journal).unwrap();
        let journal_path = directory.join("journal.json");
        fs::write(&journal_path, &bytes).unwrap();
        let operation = DowngradeOperation {
            directory: directory.clone(),
            journal_path,
            journal,
        };
        let result = retire_unstarted_downgrade(&operation);
        if phase < DowngradePhase::ArtifactsReverting {
            result.unwrap();
            assert!(!directory.exists());
            assert_eq!(
                fs::read(dir.path().join(".cancelled-operation/journal.json")).unwrap(),
                bytes
            );
            assert!(
                find_active_downgrade_operation(dir.path())
                    .unwrap()
                    .is_none()
            );
        } else {
            assert!(result.is_err());
            assert_eq!(fs::read(directory.join("journal.json")).unwrap(), bytes);
            assert!(
                find_active_downgrade_operation(dir.path())
                    .unwrap()
                    .is_some()
            );
        }
    }
}

#[test]
fn info_fact_rank_keeps_support_header_first() {
    assert_eq!(info_fact_rank("Platform"), 0);
    assert_eq!(info_fact_rank("Version"), 1);
    assert_eq!(info_fact_rank("MSB_HOME"), 2);
}

#[tokio::test]
async fn vacuum_into_writes_backup_file() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("msb.db");
    let db = microsandbox_db::connection::DbWriteConnection::open(
        &db_path,
        std::time::Duration::from_secs(5),
        std::time::Duration::from_secs(5),
    )
    .await
    .unwrap();
    db.execute_unprepared("CREATE TABLE sample (id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
        .await
        .unwrap();
    db.execute_unprepared("INSERT INTO sample (id, value) VALUES (1, 'wal-value')")
        .await
        .unwrap();

    let backup_path = dir.path().join("backup").join("msb.db.bak");
    vacuum_into(db.inner(), &backup_path).await.unwrap();

    assert!(backup_path.exists());

    let backup_db = microsandbox_db::connection::DbWriteConnection::open(
        &backup_path,
        std::time::Duration::from_secs(5),
        std::time::Duration::from_secs(5),
    )
    .await
    .unwrap();
    let row = backup_db
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT value FROM sample WHERE id = 1",
        ))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(row.try_get_by_index::<String>(0).unwrap(), "wal-value");
}

#[tokio::test]
async fn downgrade_refuses_unindexed_group_before_artifact_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    let snapshots = dir.path().join("snapshots");
    let group = snapshots.join("unindexed");
    fs::create_dir_all(&group).unwrap();
    let state = br#"{"schema":"microsandbox.snapshot-group/1","head":null}"#;
    fs::write(group.join("group.json"), state).unwrap();
    let error = refuse_snapshot_group_downgrade(&db, &snapshots)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("snapshot groups prevent downgrade")
    );
    assert_eq!(fs::read(group.join("group.json")).unwrap(), state);
}

#[tokio::test]
async fn rollback_schema_steps_through_latest_migrations() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("msb.db");
    let db = microsandbox_db::connection::DbWriteConnection::open(
        &db_path,
        std::time::Duration::from_secs(5),
        std::time::Duration::from_secs(5),
    )
    .await
    .unwrap();
    Migrator::up(db.inner(), None).await.unwrap();

    // Empty catalogs have no secret policies requiring downgrade conversion.
    rollback_schema(db.inner(), 1).await.unwrap();

    // Empty databases can drop grouped addressing without discarding any instances.
    rollback_schema(db.inner(), 1).await.unwrap();

    // With no snapshot
    // artifacts to translate, rollback removes its two rebuildable index
    // projections before touching any migration from the released prefix.
    rollback_schema(db.inner(), 1).await.unwrap();

    let rows = db
        .query_all_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "SELECT version FROM seaql_migrations WHERE version = ?",
            [schema_metadata::SNAPSHOT_IDENTITY_MIGRATION_ID.into()],
        ))
        .await
        .unwrap();
    assert!(rows.is_empty(), "snapshot identity should be rolled back");

    let columns = db
        .query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "PRAGMA table_info(snapshot_index)",
        ))
        .await
        .unwrap();
    assert!(!columns.iter().any(|row| {
        matches!(
            row.try_get_by_index::<String>(1).unwrap().as_str(),
            "snapshot_id" | "descriptor_digest"
        )
    }));

    // The backdated network-slot migration shipped after the owner marker.
    // Its rollback retains the compatible column but removes its record.
    rollback_schema(db.inner(), 1).await.unwrap();

    let rows = db
        .query_all_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "SELECT version FROM seaql_migrations WHERE version = ?",
            [schema_metadata::SANDBOX_NETWORK_SLOT_MIGRATION_ID.into()],
        ))
        .await
        .unwrap();
    assert!(
        rows.is_empty(),
        "network slot migration should be rolled back"
    );

    let columns = db
        .query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "PRAGMA table_info(sandbox)",
        ))
        .await
        .unwrap();
    assert!(
        columns
            .iter()
            .any(|row| row.try_get_by_index::<String>(1).unwrap() == "network_slot"),
        "network slot column should remain compatible after rollback"
    );

    // The owner-compatibility marker has no schema objects of its own. With
    // no persisted sandboxes, its preflight permits rollback and removes
    // only the migration record.
    rollback_schema(db.inner(), 1).await.unwrap();

    let rows = db
        .query_all_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "SELECT version FROM seaql_migrations WHERE version = ?",
            [schema_metadata::MOUNT_OWNER_CONFIG_MIGRATION_ID.into()],
        ))
        .await
        .unwrap();
    assert!(rows.is_empty(), "mount owner marker should be rolled back");

    // Shared CPU assignment rows downgrade first. Active sandboxes are
    // prohibited during schema rollback, so the allocation table is empty
    // and can safely return to its exclusive logical-CPU key.
    rollback_schema(db.inner(), 1).await.unwrap();

    let rows = db
        .query_all_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "SELECT version FROM seaql_migrations WHERE version = ?",
            [schema_metadata::SHARED_CPU_ALLOCATION_MIGRATION_ID.into()],
        ))
        .await
        .unwrap();
    assert!(
        rows.is_empty(),
        "shared CPU allocation should be rolled back"
    );

    // The label rebuild is compatible with older releases, so its down
    // migration only removes the migration record. NUMA memory and
    // writeback state must remain until their own rollback steps.
    rollback_schema(db.inner(), 1).await.unwrap();

    let rows = db
        .query_all_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "SELECT version FROM seaql_migrations WHERE version = ?",
            [schema_metadata::SANDBOX_LABEL_REBUILD_MIGRATION_ID.into()],
        ))
        .await
        .unwrap();
    assert!(rows.is_empty(), "label rebuild should be rolled back");

    let rows = db
        .query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'writeback_allocation'",
        ))
        .await
        .unwrap();
    assert_eq!(
        rows.len(),
        1,
        "writeback allocation should remain after one rollback"
    );

    rollback_schema(db.inner(), 1).await.unwrap();

    let rows = db
        .query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'memory_allocation_node'",
        ))
        .await
        .unwrap();
    assert!(
        rows.is_empty(),
        "NUMA memory allocation should be rolled back"
    );

    let rows = db
        .query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'writeback_allocation'",
        ))
        .await
        .unwrap();
    assert_eq!(
        rows.len(),
        1,
        "writeback allocation should remain after NUMA rollback"
    );

    rollback_schema(db.inner(), 1).await.unwrap();

    let rows = db
        .query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'writeback_allocation'",
        ))
        .await
        .unwrap();
    assert!(
        rows.is_empty(),
        "writeback allocation should be rolled back"
    );

    for table in ["cpu_allocation", "cpu_allocation_cpu"] {
        let rows = db
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                format!("SELECT name FROM sqlite_master WHERE type = 'table' AND name = '{table}'"),
            ))
            .await
            .unwrap();
        assert!(!rows.is_empty(), "{table} should remain after one rollback");
    }

    let columns = db
        .query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "PRAGMA table_info(snapshot_index)",
        ))
        .await
        .unwrap();
    let has_scope = columns
        .iter()
        .any(|row| row.try_get_by_index::<String>(1).unwrap() == "scope");
    let has_state_kind = columns
        .iter()
        .any(|row| row.try_get_by_index::<String>(1).unwrap() == "state_kind");
    assert!(has_scope);
    assert!(has_state_kind);

    let rows = db
        .query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT name FROM pragma_table_info('sandbox') WHERE name = 'active_config'",
        ))
        .await
        .unwrap();
    assert!(!rows.is_empty());

    let rows = db
        .query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'maintenance_lease'",
        ))
        .await
        .unwrap();
    assert!(!rows.is_empty());
}

#[tokio::test]
async fn user_data_warnings_list_snapshots_and_disk_volumes() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("msb.db");
    let db = microsandbox_db::connection::DbWriteConnection::open(
        &db_path,
        std::time::Duration::from_secs(5),
        std::time::Duration::from_secs(5),
    )
    .await
    .unwrap();
    db.execute_unprepared("CREATE TABLE snapshot_index (digest TEXT PRIMARY KEY)")
        .await
        .unwrap();
    db.execute_unprepared("CREATE TABLE volume (kind TEXT, disk_format TEXT, disk_fstype TEXT)")
        .await
        .unwrap();
    db.execute_unprepared("INSERT INTO snapshot_index (digest) VALUES ('sha256:test')")
        .await
        .unwrap();
    db.execute_unprepared(
        "INSERT INTO volume (kind, disk_format, disk_fstype) VALUES ('disk', 'raw', 'ext4')",
    )
    .await
    .unwrap();

    let warnings = user_data_warnings(db.inner()).await.unwrap();

    assert_eq!(warnings.len(), 2);
    assert!(warnings[0].contains("snapshots to project"));
    assert!(warnings[1].contains("disk volumes left untouched"));
}

#[test]
fn version_parse_orders_release_versions() {
    assert!(parse_version("0.6.1").unwrap() > parse_version("v0.6.0").unwrap());
    assert!(parse_version("0.5.10").unwrap() < MIN_DOWNGRADE_VERSION);
    assert_eq!(parse_version(" v0.6.18 ").unwrap(), Version::new(0, 6, 18));
    for input in [
        "0.6",
        "0.6.18.1",
        "0.6.18-preview",
        "0.6.18+build",
        "invalid",
    ] {
        assert!(parse_version(input).is_err());
    }
}

#[test]
fn rollback_plan_uses_target_prefix() {
    let baseline = SchemaBaseline {
        schema_baseline_version: schema_metadata::SCHEMA_BASELINE_FORMAT_VERSION,
        downgrade_floor: schema_metadata::DOWNGRADE_FLOOR.to_string(),
        migrations: schema_metadata::BASELINE_0_6_0_MIGRATIONS
            .iter()
            .map(|id| (*id).to_string())
            .collect(),
    };
    let applied: Vec<String> = schema_metadata::migration_ids()
        .map(str::to_string)
        .collect();

    let plan = build_rollback_plan(&baseline, &applied).unwrap();

    assert_eq!(
        plan.steps(),
        schema_metadata::MIGRATION_METADATA.len()
            - schema_metadata::BASELINE_0_6_0_MIGRATIONS.len()
    );
}

#[test]
fn rollback_plan_uses_applied_migrations_not_current_binary_length() {
    let baseline = SchemaBaseline {
        schema_baseline_version: schema_metadata::SCHEMA_BASELINE_FORMAT_VERSION,
        downgrade_floor: schema_metadata::DOWNGRADE_FLOOR.to_string(),
        migrations: schema_metadata::BASELINE_0_6_0_MIGRATIONS
            .iter()
            .map(|id| (*id).to_string())
            .collect(),
    };
    let applied: Vec<String> = schema_metadata::BASELINE_0_6_0_MIGRATIONS
        .iter()
        .map(|id| (*id).to_string())
        .collect();

    let plan = build_rollback_plan(&baseline, &applied).unwrap();

    assert_eq!(plan.steps(), 0);
    assert!(!plan.affects_cache);
    assert!(!plan.affects_user_data);
}

#[test]
fn rollback_plan_rejects_non_prefix_baseline() {
    let baseline = SchemaBaseline {
        schema_baseline_version: schema_metadata::SCHEMA_BASELINE_FORMAT_VERSION,
        downgrade_floor: schema_metadata::DOWNGRADE_FLOOR.to_string(),
        migrations: vec!["not_a_real_migration".to_string()],
    };
    let applied = Vec::new();

    let err = build_rollback_plan(&baseline, &applied).unwrap_err();
    assert!(err.to_string().contains("not compatible"));
}

#[test]
fn rollback_plan_accepts_released_probe_order_but_not_gaps_or_duplicates() {
    let applied: Vec<String> = schema_metadata::migration_ids()
        .map(str::to_string)
        .collect();
    let end = applied
        .iter()
        .position(|id| id == schema_metadata::SANDBOX_NETWORK_SLOT_MIGRATION_ID)
        .unwrap()
        + 1;
    let mut baseline = SchemaBaseline {
        schema_baseline_version: schema_metadata::SCHEMA_BASELINE_FORMAT_VERSION,
        downgrade_floor: schema_metadata::DOWNGRADE_FLOOR.to_string(),
        migrations: applied[..end].to_vec(),
    };
    baseline.migrations.sort(); // v0.6.16 probe order
    assert_eq!(
        build_rollback_plan(&baseline, &applied).unwrap().steps(),
        applied.len() - end
    );
    let mut missing = baseline.clone();
    missing.migrations.remove(0);
    assert!(build_rollback_plan(&missing, &applied).is_err());
    baseline.migrations.push(baseline.migrations[0].clone());
    assert!(build_rollback_plan(&baseline, &applied).is_err());
}

#[cfg(windows)]
#[test]
fn windows_self_swap_resume_preserves_update_completion() {
    let resume = WindowsSelfSwapResume {
        format_version: 1,
        task_name: "Microsandbox-Self-Update-test".to_string(),
        parent_pid: 42,
        base_dir: PathBuf::from(r"C:\Users\Test\.microsandbox"),
        staged_dir: PathBuf::from(r"C:\Users\Test\.microsandbox\db\stage"),
        target_version: "0.6.9".to_string(),
        log_path: PathBuf::from(r"C:\Users\Test\.microsandbox\logs\update.log"),
        completion: WindowsSelfSwapCompletion::Update,
    };

    let encoded = serde_json::to_vec(&resume).unwrap();
    let decoded: WindowsSelfSwapResume = serde_json::from_slice(&encoded).unwrap();

    assert_eq!(decoded.task_name, resume.task_name);
    assert_eq!(decoded.target_version, "0.6.9");
    assert!(matches!(
        decoded.completion,
        WindowsSelfSwapCompletion::Update
    ));
}

#[cfg(windows)]
#[test]
fn windows_release_swap_refreshes_both_cli_names() {
    let dir = tempfile::tempdir().unwrap();
    let staged_dir = dir.path().join("staged");
    let base_dir = dir.path().join("installed");
    let staged_bin = staged_dir.join(microsandbox_utils::BIN_SUBDIR);
    let staged_lib = staged_dir.join(microsandbox_utils::LIB_SUBDIR);
    fs::create_dir_all(&staged_bin).unwrap();
    fs::create_dir_all(&staged_lib).unwrap();
    fs::write(staged_bin.join("msb.exe"), b"new-cli").unwrap();
    fs::write(staged_lib.join("libkrunfw.dll"), b"new-firmware").unwrap();

    let log_path = dir.path().join("swap.log");
    let mut log = File::create(&log_path).unwrap();
    copy_windows_release_artifacts(&staged_dir, &base_dir, &mut log).unwrap();

    let installed_bin = base_dir.join(microsandbox_utils::BIN_SUBDIR);
    assert_eq!(fs::read(installed_bin.join("msb.exe")).unwrap(), b"new-cli");
    assert_eq!(
        fs::read(installed_bin.join("microsandbox.exe")).unwrap(),
        b"new-cli"
    );
    assert_eq!(
        fs::read(
            base_dir
                .join(microsandbox_utils::LIB_SUBDIR)
                .join("libkrunfw.dll")
        )
        .unwrap(),
        b"new-firmware"
    );
}

fn current_saved_config() -> String {
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
    let raw = current_saved_config();
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
        prepare(
            db.inner(),
            &Version::parse(&format!("0.7.{patch}")).unwrap(),
        )
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
        let raw = current_saved_config();
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
                prepare(db.inner(), &target)
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains(column)
            );
            let error =
                preflight_schema_rollback(db.inner(), &dir.path().join("preflight.db"), 0, &target)
                    .await
                    .unwrap_err();
            assert!(error.to_string().contains(column));
            assert!(!error.to_string().contains("synthetic"));
            assert!(
                rollback_schema_for_target(db.inner(), 0, Some(&target))
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
            migration.name() == microsandbox_migration::schema_metadata::SECRET_CONFIG_MIGRATION_ID
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
    preflight_schema_rollback(db.inner(), &dir.path().join("preflight.db"), steps, &target)
        .await
        .unwrap();
    assert_eq!(read().await, migrated);
    rollback_schema_for_target(db.inner(), steps, Some(&target))
        .await
        .unwrap();
    let previous = read().await;
    assert!(previous.contains("\"injection\""));
    assert!(!previous.contains("\"substitution\""));
    Migrator::up(db.inner(), None).await.unwrap();
    assert_eq!(read().await, migrated);
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
    let raw = current_saved_config();
    db.inner()
        .execute_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "INSERT INTO sandbox VALUES (1, ?, ?)",
            [raw.clone().into(), raw.clone().into()],
        ))
        .await
        .unwrap();
    let target = Version::parse("0.6.18").unwrap();
    preflight_schema_rollback(db.inner(), &dir.path().join("preflight.db"), 0, &target)
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
    rollback_schema_for_target(db.inner(), 0, Some(&target))
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
            db_compat::config::to_previous_version(&raw, &Version::new(0, 6, 18))
                .unwrap()
                .unwrap()
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
    let raw = current_saved_config();
    let mut invalid: Value = serde_json::from_str(&raw).unwrap();
    invalid["network"]["secrets"]["secrets"][0]["violation_action"] = serde_json::json!("block");
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
            &Version::parse("0.6.18").unwrap()
        )
        .await
        .is_err()
    );
    let error = rollback_schema_for_target(db.inner(), 0, Some(&Version::parse("0.6.18").unwrap()))
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
    use super::{SchemaBaseline, applied_migrations, build_rollback_plan};

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
                &target,
            )
            .await?;
            rollback_schema_for_target(db.inner(), plan.steps(), Some(&target)).await?;
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
                .join(microsandbox_utils::libkrunfw_filename(std::env::consts::OS));
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
#[tokio::test]
#[ignore = "requires released SDK/runtime, candidate SDK/runtime, and host virtualization"]
async fn released_sdk_secret_downgrade() {
    use super::{SchemaBaseline, applied_migrations, build_rollback_plan};
    let dir = tempfile::Builder::new()
        .prefix("msb-secret-down-")
        .tempdir_in("/tmp")
        .unwrap();
    let old_python = std::env::var("MSB_TEST_OLD_PYTHON").unwrap();
    let old_runtime = std::env::var("MSB_TEST_OLD_RUNTIME").unwrap();
    let new_python = std::env::var("MSB_TEST_NEW_PYTHON").unwrap();
    let new_runtime = std::env::var("MSB_TEST_NEW_RUNTIME").unwrap();
    let target =
        Version::parse(&std::env::var("MSB_TEST_OLD_VERSION").unwrap_or_else(|_| "0.6.18".into()))
            .unwrap();
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/smoke/sdk/secret-downgrade.py");
    let phase = |name: &'static str, python: String, runtime: String| {
        let script = script.clone();
        let home = dir.path().to_path_buf();
        async move {
            let firmware = std::path::Path::new(&runtime)
                .parent()
                .unwrap()
                .join(microsandbox_utils::libkrunfw_filename(std::env::consts::OS));
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
    preflight_schema_rollback(
        db.inner(),
        &dir.path().join("preflight.db"),
        plan.steps(),
        &target,
    )
    .await
    .unwrap();
    rollback_schema_for_target(db.inner(), plan.steps(), Some(&target))
        .await
        .unwrap();
    drop(db);
    phase("restart", old_python, old_runtime).await;
}

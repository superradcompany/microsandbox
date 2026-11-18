use std::fs;
use std::path::Path;

use super::*;

async fn catalog(home: &Path) -> (GlobalConfig, SqliteConnection) {
    let config = GlobalConfig {
        home: Some(home.to_path_buf()),
        ..Default::default()
    };
    let directory = home.join(microsandbox_utils::DB_SUBDIR);
    fs::create_dir_all(&directory).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // A host's permissive umask must not make the fixture home itself an unsafe ancestor.
        fs::set_permissions(home, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let options = SqliteConnectOptions::new()
        .filename(directory.join(microsandbox_utils::DB_FILENAME))
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
    let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
    sqlx::query("CREATE TABLE sandbox(id INTEGER PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL, config TEXT NOT NULL, caller_config_overrides TEXT, creation_state TEXT, active_config TEXT)")
        .execute(&mut connection).await.unwrap();
    sqlx::query("CREATE TABLE protected_sandbox_state(sandbox_id INTEGER PRIMARY KEY, layout_version INTEGER NOT NULL)").execute(&mut connection).await.unwrap();
    (config, connection)
}

async fn insert(connection: &mut SqliteConnection, name: &str, payload: &str) {
    sqlx::query("INSERT INTO sandbox(name,status,config) VALUES(?,'Stopped',?)")
        .bind(name)
        .bind(payload)
        .execute(connection)
        .await
        .unwrap();
}

#[tokio::test]
async fn native_diagnosis_serializes_guest_mounts_from_the_selected_catalog() {
    use std::sync::Arc;

    use microsandbox_types::{
        HostPermissions, OwnedVolumeStorage, StatVirtualization, VolumeMount, owned_volume_mount_id,
    };

    use crate::backend::{Backend, BackendSelectionSource, LocalBackend, with_backend};
    use crate::config::layers::BackendConfig;

    let home = microsandbox_runtime::checkpoint::migration::private_preview_parent().unwrap();
    let (config, mut writer) = catalog(home.path()).await;
    let mut saved = SandboxConfig::default();
    saved.spec.name = "mounted".into();
    for guest in ["/data", "/logs"] {
        saved.spec.mounts.push(VolumeMount::Owned {
            guest: guest.into(),
            storage: OwnedVolumeStorage::Disk { capacity_mib: 64 },
            options: Default::default(),
            stat_virtualization: StatVirtualization::Strict,
            host_permissions: HostPermissions::Private,
        });
    }
    insert(
        &mut writer,
        "mounted",
        &serde_json::to_string(&saved).unwrap(),
    )
    .await;
    insert(&mut writer, "invalid", "invalid saved configuration").await;
    let local = LocalBackend::from_backend_config(
        BackendConfig::new(
            GlobalConfigPatch::from_present_fields(config),
            Default::default(),
        ),
        BackendSelectionSource::Programmatic,
        None,
    );
    let backend: Arc<dyn Backend> = Arc::new(local);
    // All four native SDKs return this exact JSON to their language decoder. Exercise the
    // actual catalog read and wire serialization instead of constructing a report by hand.
    let wire = with_backend(
        backend,
        crate::setup::binding_diagnose_storage(
            "{}",
            r#"{"named":["mounted","invalid","missing"]}"#,
        ),
    )
    .await
    .unwrap();
    let report: serde_json::Value = serde_json::from_str(&wire).unwrap();
    let items = report["sandboxes"].as_array().unwrap();
    let mounted = items.iter().find(|item| item["name"] == "mounted").unwrap();
    let expected = std::collections::BTreeMap::from([
        ("root".to_owned(), "/".to_owned()),
        (owned_volume_mount_id("/data"), "/data".to_owned()),
        (owned_volume_mount_id("/logs"), "/logs".to_owned()),
    ]);
    assert_eq!(
        mounted["guest_mounts"],
        serde_json::to_value(expected).unwrap()
    );
    for name in ["invalid", "missing"] {
        let item = items.iter().find(|item| item["name"] == name).unwrap();
        assert_eq!(item["guest_mounts"], serde_json::json!({}));
    }
}

#[tokio::test]
async fn storage_preview_blockers_never_authorize_an_incomplete_or_terminal_target() {
    let temp = tempfile::tempdir().unwrap();
    let (config, mut writer) = catalog(temp.path()).await;
    let mut saved = SandboxConfig::default();
    saved.spec.name = "target".into();
    insert(
        &mut writer,
        "target",
        &serde_json::to_string(&saved).unwrap(),
    )
    .await;
    sqlx::query(
        "CREATE TABLE run(id INTEGER PRIMARY KEY, sandbox_id INTEGER, status TEXT, pid INTEGER)",
    )
    .execute(&mut writer)
    .await
    .unwrap();
    sqlx::query("INSERT INTO run VALUES(12,1,'Running',?)")
        .bind(std::process::id() as i64)
        .execute(&mut writer)
        .await
        .unwrap();
    sqlx::query("UPDATE sandbox SET status='Running',creation_state='creating'")
        .execute(&mut writer)
        .await
        .unwrap();
    let error = repair::blockers_resolved(&config, "target")
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("incomplete or inconsistent"),
        "{error}"
    );
    sqlx::query("UPDATE sandbox SET status='Stopped',creation_state=NULL")
        .execute(&mut writer)
        .await
        .unwrap();
    let error = repair::blockers_resolved(&config, "target")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("wait for teardown"), "{error}");
    sqlx::query("UPDATE sandbox SET status='Running'")
        .execute(&mut writer)
        .await
        .unwrap();
    let blockers = repair::blockers_resolved(&config, "target").await.unwrap();
    assert_eq!(blockers.len(), 1);
    assert_eq!(blockers[0].name, "target");
}

#[tokio::test]
async fn storage_preview_cancel_preserves_released_schema_version_and_rows() {
    use crate::backend::{BackendSelectionSource, LocalBackend};
    use crate::config::layers::BackendConfig;
    let temp = microsandbox_runtime::checkpoint::migration::private_preview_parent().unwrap();
    let scratch = microsandbox_runtime::checkpoint::migration::private_preview_parent().unwrap();
    let (config, mut legacy) = catalog(temp.path()).await;
    sqlx::query("DROP TABLE protected_sandbox_state")
        .execute(&mut legacy)
        .await
        .unwrap();
    sqlx::query("CREATE TABLE seaql_migrations(version TEXT PRIMARY KEY, applied_at INTEGER)")
        .execute(&mut legacy)
        .await
        .unwrap();
    sqlx::query("INSERT INTO seaql_migrations VALUES('released_before_protection',1)")
        .execute(&mut legacy)
        .await
        .unwrap();
    sqlx::query(
        "CREATE TABLE run(id INTEGER PRIMARY KEY, sandbox_id INTEGER, status TEXT, pid INTEGER)",
    )
    .execute(&mut legacy)
    .await
    .unwrap();
    let mut saved = SandboxConfig::default();
    saved.spec.name = "legacy-view".into();
    saved.spec.image = crate::sandbox::RootfsSource::Oci(microsandbox_types::OciRootfsSource {
        reference: "example/test".into(),
        root_disk: None,
    });
    let payload = serde_json::to_string(&saved).unwrap();
    insert(&mut legacy, "legacy-view", &payload).await;
    let sandbox = config.sandboxes_dir().join("legacy-view");
    fs::create_dir_all(sandbox.join("runtime")).unwrap();
    fs::write(sandbox.join("upper.ext4"), vec![23; 131_072]).unwrap();
    let local = LocalBackend::from_backend_config(
        BackendConfig::new(
            GlobalConfigPatch::from_present_fields(config),
            Default::default(),
        ),
        BackendSelectionSource::Programmatic,
        None,
    );
    let options = crate::sandbox::StorageRecoveryOptions {
        legacy_writers_stopped: true,
        ..Default::default()
    };
    let (_, mut views) = crate::sandbox::storage_preview::capture_readonly(
        &local,
        "legacy-view",
        &options,
        scratch.path(),
    )
    .await
    .unwrap();
    let id = views.candidates()[0].id.clone();
    let detached = views.materialize("root", &id).unwrap();
    drop(views);
    assert!(!detached.exists() && !sandbox.join(".storage-migration").exists());
    let versions: Vec<String> = sqlx::query_scalar("SELECT version FROM seaql_migrations")
        .fetch_all(&mut legacy)
        .await
        .unwrap();
    assert_eq!(versions, ["released_before_protection"]);
    let rows: Vec<(String, String)> = sqlx::query_as("SELECT name,config FROM sandbox")
        .fetch_all(&mut legacy)
        .await
        .unwrap();
    assert_eq!(rows, [("legacy-view".into(), payload)]);
    let protected: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sqlite_schema WHERE name='protected_sandbox_state'",
    )
    .fetch_one(&mut legacy)
    .await
    .unwrap();
    assert_eq!(protected, 0);
}

#[tokio::test]
async fn inspection_reads_live_wal_without_catalog_migration_or_permission_repairs() {
    let temp = tempfile::tempdir().unwrap();
    let (config, mut writer) = catalog(temp.path()).await;
    insert(&mut writer, "broken", "{secret-that-must-not-appear").await;
    sqlx::query("INSERT INTO protected_sandbox_state VALUES(1,1)")
        .execute(&mut writer)
        .await
        .unwrap();
    let db = temp
        .path()
        .join(microsandbox_utils::DB_SUBDIR)
        .join(microsandbox_utils::DB_FILENAME);
    let before = fs::read(&db).unwrap();
    let wal = db.with_file_name(format!("{}-wal", microsandbox_utils::DB_FILENAME));
    let before_wal = fs::read(&wal).unwrap();
    #[cfg(unix)]
    let modes = {
        use std::os::unix::fs::PermissionsExt;
        (
            fs::metadata(&db).unwrap().permissions().mode(),
            fs::metadata(db.parent().unwrap())
                .unwrap()
                .permissions()
                .mode(),
        )
    };
    let report = diagnose_resolved(
        &config,
        StorageSelection::Named(vec!["missing".into(), "broken".into(), "broken".into()]),
    )
    .await
    .unwrap();
    assert_eq!(report.sandboxes.len(), 2);
    assert!(report.sandboxes[0].protection_registered);
    assert_eq!(
        report.sandboxes[0].reason,
        Some(StorageDiagnosticReason::InvalidConfiguration)
    );
    assert_eq!(
        report.sandboxes[1].reason,
        Some(StorageDiagnosticReason::NotFound)
    );
    assert_eq!(report.exit_code(), 3);
    assert!(
        !serde_json::to_string(&report)
            .unwrap()
            .contains("secret-that-must-not-appear")
    );
    assert_eq!(fs::read(&db).unwrap(), before);
    assert_eq!(fs::read(&wal).unwrap(), before_wal);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            (
                fs::metadata(&db).unwrap().permissions().mode(),
                fs::metadata(db.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
            ),
            modes
        );
    }
    let tables: i64 =
        sqlx::query_scalar("SELECT count(*) FROM sqlite_schema WHERE name='seaql_migrations'")
            .fetch_one(&mut writer)
            .await
            .unwrap();
    assert_eq!(tables, 0);
    assert!(!config.sandboxes_dir().exists());
    writer.close().await.unwrap();
}

#[tokio::test]
async fn closed_wal_catalog_and_named_scope_do_not_require_existing_sidecars() {
    let temp = tempfile::tempdir().unwrap();
    let (config, mut writer) = catalog(temp.path()).await;
    insert(&mut writer, "selected", "invalid").await;
    insert(&mut writer, "unrelated", "invalid").await;
    writer.close().await.unwrap();
    let db = temp
        .path()
        .join(microsandbox_utils::DB_SUBDIR)
        .join(microsandbox_utils::DB_FILENAME);
    let before = fs::read(&db).unwrap();
    let report = diagnose_resolved(&config, StorageSelection::Named(vec!["selected".into()]))
        .await
        .unwrap();
    assert_eq!(report.sandboxes.len(), 1);
    assert_eq!(report.sandboxes[0].name, "selected");
    assert_eq!(fs::read(&db).unwrap(), before);
    assert_eq!(
        diagnose_resolved(&config, StorageSelection::All)
            .await
            .unwrap()
            .sandboxes
            .len(),
        2
    );
}

#[tokio::test]
async fn inspection_reports_ready_storage_and_partial_errors_independently() {
    let temp = tempfile::tempdir().unwrap();
    let (config, mut writer) = catalog(temp.path()).await;
    let mut sandbox = SandboxConfig::default();
    sandbox.spec.name = "ready".into();
    insert(
        &mut writer,
        "ready",
        &serde_json::to_string(&sandbox).unwrap(),
    )
    .await;
    insert(&mut writer, "broken", "{}").await;
    let runtime = config.sandboxes_dir().join("ready/runtime");
    fs::create_dir_all(&runtime).unwrap();
    microsandbox_runtime::checkpoint::layout::initialize_new(&runtime).unwrap();
    let marker = fs::read(runtime.parent().unwrap().join("state-layout.json")).unwrap();
    sqlx::query("UPDATE sandbox SET status='Running' WHERE name='ready'")
        .execute(&mut writer)
        .await
        .unwrap();
    // A protected VM needs no migration or stop, so its running state is not a blocker.
    let ready = diagnose_resolved(&config, StorageSelection::Named(vec!["ready".into()]))
        .await
        .unwrap();
    assert!(ready.sandboxes[0].running);
    assert_eq!(ready.exit_code(), 0);
    let report = diagnose_resolved(&config, StorageSelection::All)
        .await
        .unwrap();
    assert_eq!(report.sandboxes.len(), 2);
    assert_eq!(report.sandboxes[1].status, StorageDiagnosticStatus::Ready);
    assert_eq!(
        report.sandboxes[0].status,
        StorageDiagnosticStatus::Unavailable
    );
    assert_eq!(
        fs::read(runtime.parent().unwrap().join("state-layout.json")).unwrap(),
        marker
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM protected_sandbox_state")
        .fetch_one(&mut writer)
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn oversized_overrides_do_not_silently_drop_configuration_authority() {
    let temp = tempfile::tempdir().unwrap();
    let (config, mut writer) = catalog(temp.path()).await;
    let mut sandbox = SandboxConfig::default();
    sandbox.spec.name = "oversized".into();
    insert(
        &mut writer,
        "oversized",
        &serde_json::to_string(&sandbox).unwrap(),
    )
    .await;
    sqlx::query("UPDATE sandbox SET caller_config_overrides = ?")
        .bind("x".repeat(MAX_CONFIG_BYTES + 1))
        .execute(&mut writer)
        .await
        .unwrap();
    let report = diagnose_resolved(&config, StorageSelection::All)
        .await
        .unwrap();
    assert_eq!(
        report.sandboxes[0].reason,
        Some(StorageDiagnosticReason::InvalidConfiguration)
    );
}

#[cfg(unix)]
#[tokio::test]
async fn inspection_refuses_sidecar_symlinks_fifos_and_writable_catalog_without_repair() {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{PermissionsExt, symlink};
    let temp = tempfile::tempdir().unwrap();
    let (config, writer) = catalog(temp.path()).await;
    writer.close().await.unwrap();
    let directory = temp.path().join(microsandbox_utils::DB_SUBDIR);
    let db = directory.join(microsandbox_utils::DB_FILENAME);
    let canary = temp.path().join("canary");
    fs::write(&canary, b"unchanged").unwrap();
    for suffix in ["-wal", "-shm", "-journal"] {
        let path = directory.join(format!("{}{suffix}", microsandbox_utils::DB_FILENAME));
        symlink(&canary, &path).unwrap();
        assert!(
            diagnose_resolved(&config, StorageSelection::All)
                .await
                .is_err()
        );
        fs::remove_file(&path).unwrap();
        let bytes = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(bytes.as_ptr(), 0o600) }, 0);
        assert!(
            diagnose_resolved(&config, StorageSelection::All)
                .await
                .is_err()
        );
        fs::remove_file(path).unwrap();
    }
    fs::set_permissions(&db, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(
        diagnose_resolved(&config, StorageSelection::All)
            .await
            .is_err()
    );
    assert_eq!(
        fs::metadata(&db).unwrap().permissions().mode() & 0o777,
        0o666
    );
    assert_eq!(fs::read(canary).unwrap(), b"unchanged");
}

#[test]
fn named_selection_is_explicit_bounded_and_validated() {
    assert!(selected_names(StorageSelection::Named(Vec::new())).is_err());
    assert!(selected_names(StorageSelection::Named(vec!["../escape".into()])).is_err());
    assert_eq!(
        selected_names(StorageSelection::Named(vec!["app".into(), "app".into()]))
            .unwrap()
            .unwrap()
            .len(),
        1
    );
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn inspection_rejects_mutating_macos_acl_without_removing_it() {
    use std::process::Command;
    let temp = tempfile::tempdir().unwrap();
    let (config, writer) = catalog(temp.path()).await;
    writer.close().await.unwrap();
    let db = temp
        .path()
        .join(microsandbox_utils::DB_SUBDIR)
        .join(microsandbox_utils::DB_FILENAME);
    assert!(
        Command::new("chmod")
            .args(["+a", "everyone allow write,append"])
            .arg(&db)
            .status()
            .unwrap()
            .success()
    );
    let before = Command::new("ls")
        .arg("-le")
        .arg(&db)
        .output()
        .unwrap()
        .stdout;
    assert!(
        diagnose_resolved(&config, StorageSelection::All)
            .await
            .is_err()
    );
    assert_eq!(
        before,
        Command::new("ls")
            .arg("-le")
            .arg(&db)
            .output()
            .unwrap()
            .stdout
    );
}

#[tokio::test]
async fn unfinished_peer_does_not_hide_independent_legacy_diagnosis() {
    let temp = tempfile::tempdir().unwrap();
    let (global, mut writer) = catalog(temp.path()).await;
    for name in ["legacy", "peer"] {
        let mut config = SandboxConfig::default();
        config.spec.name = name.into();
        insert(&mut writer, name, &serde_json::to_string(&config).unwrap()).await;
    }
    sqlx::query("UPDATE sandbox SET creation_state='preparing' WHERE name='peer'")
        .execute(&mut writer)
        .await
        .unwrap();
    let sandbox = global.sandboxes_dir().join("legacy");
    fs::create_dir_all(sandbox.join("runtime")).unwrap();
    let contents = vec![23u8; 131072];
    fs::write(sandbox.join("upper.ext4"), &contents).unwrap();
    let selected = StorageSelection::Named(vec!["legacy".into(), "peer".into()]);
    let report = diagnose_resolved(&global, selected).await.unwrap();
    assert_eq!(report.sandboxes.len(), 2);
    assert_eq!(report.sandboxes[0].name, "legacy");
    assert_eq!(
        report.sandboxes[0].status,
        if cfg!(target_os = "macos") {
            StorageDiagnosticStatus::MaintenanceRequired
        } else {
            StorageDiagnosticStatus::Eligible
        }
    );
    assert_eq!(report.sandboxes[1].name, "peer");
    assert_eq!(
        report.sandboxes[1].status,
        StorageDiagnosticStatus::RecoveryRequired
    );
    assert_eq!(
        report.sandboxes[1].reason,
        Some(StorageDiagnosticReason::IncompleteCreation)
    );

    // Do not skip incomplete peers: a malformed saved configuration could hide a writer.
    sqlx::query("UPDATE sandbox SET config='invalid-saved-config' WHERE name='peer'")
        .execute(&mut writer)
        .await
        .unwrap();
    let report = diagnose_resolved(&global, StorageSelection::Named(vec!["legacy".into()]))
        .await
        .unwrap();
    assert_eq!(
        report.sandboxes[0].status,
        StorageDiagnosticStatus::Unavailable
    );
    assert_eq!(
        report.sandboxes[0].reason,
        Some(StorageDiagnosticReason::StorageUnavailable)
    );
    assert_eq!(fs::read(sandbox.join("upper.ext4")).unwrap(), contents);
    assert!(!sandbox.join("state-layout.json").exists());
    assert!(!global.sandboxes_dir().join("peer").exists());
    let registered: i64 = sqlx::query_scalar("SELECT count(*) FROM protected_sandbox_state")
        .fetch_one(&mut writer)
        .await
        .unwrap();
    assert_eq!(registered, 0, "inspection must not admit either sandbox");
}

#[tokio::test]
async fn legacy_preview_accounts_for_active_configuration_writers_without_admission() {
    let temp = tempfile::tempdir().unwrap();
    let (global, mut writer) = catalog(temp.path()).await;
    let mut selected = SandboxConfig::default();
    selected.spec.name = "legacy".into();
    insert(
        &mut writer,
        "legacy",
        &serde_json::to_string(&selected).unwrap(),
    )
    .await;
    sqlx::query("INSERT INTO protected_sandbox_state VALUES(1,1)")
        .execute(&mut writer)
        .await
        .unwrap();
    let sandbox = global.sandboxes_dir().join("legacy");
    fs::create_dir_all(sandbox.join("runtime")).unwrap();
    fs::write(sandbox.join("upper.ext4"), vec![23u8; 131072]).unwrap();
    let report = diagnose_resolved(&global, StorageSelection::Named(vec!["legacy".into()]))
        .await
        .unwrap();
    assert_eq!(
        report.sandboxes[0].status,
        if cfg!(target_os = "macos") {
            StorageDiagnosticStatus::MaintenanceRequired
        } else {
            StorageDiagnosticStatus::Eligible
        }
    );
    assert_eq!(
        report.exit_code(),
        if cfg!(target_os = "macos") { 2 } else { 0 }
    );
    assert!(report.sandboxes[0].protection_registered);
    assert!(!sandbox.join("state-layout.json").exists());
    assert!(!sandbox.join("runtime/root-disk.json").exists());

    let mut peer = SandboxConfig::default();
    peer.spec.name = "peer".into();
    insert(&mut writer, "peer", &serde_json::to_string(&peer).unwrap()).await;
    let mut active = peer.clone();
    active.spec.image = crate::sandbox::RootfsSource::Bind {
        path: sandbox.clone(),
        follow_root_symlinks: false,
    };
    // Incomplete rows remain in writer discovery: creation state never makes an active
    // desired/active configuration safe to ignore, including before a start finishes.
    for (status, creation) in [
        ("Running", None),
        ("Starting", Some("preparing")),
        ("Running", Some("prepared")),
    ] {
        sqlx::query(
            "UPDATE sandbox SET status=?, creation_state=?, active_config=? WHERE name='peer'",
        )
        .bind(status)
        .bind(creation)
        .bind(serde_json::to_string(&active).unwrap())
        .execute(&mut writer)
        .await
        .unwrap();
        let report = diagnose_resolved(&global, StorageSelection::Named(vec!["legacy".into()]))
            .await
            .unwrap();
        assert_eq!(report.sandboxes.len(), 1);
        assert_eq!(
            report.sandboxes[0].status,
            StorageDiagnosticStatus::RecoveryRequired
        );
        assert!(
            report.sandboxes[0]
                .inspection
                .as_ref()
                .unwrap()
                .reasons
                .iter()
                .any(|reason| reason.contains("active")),
            "{status}/{creation:?}: overlapping incomplete writers must remain blocked"
        );
    }
    assert_eq!(
        fs::read(sandbox.join("upper.ext4")).unwrap(),
        vec![23u8; 131072]
    );
    assert!(!sandbox.join("state-layout.json").exists());
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn inspection_refuses_inheritable_read_acl_before_sqlite_sidecar_creation() {
    use std::process::Command;
    let temp = tempfile::tempdir().unwrap();
    let (config, writer) = catalog(temp.path()).await;
    writer.close().await.unwrap();
    let directory = temp.path().join(microsandbox_utils::DB_SUBDIR);
    let db = directory.join(microsandbox_utils::DB_FILENAME);
    let wal = directory.join(format!("{}-wal", microsandbox_utils::DB_FILENAME));
    let shm = directory.join(format!("{}-shm", microsandbox_utils::DB_FILENAME));
    assert!(!wal.exists() && !shm.exists());
    assert!(
        Command::new("chmod")
            .args([
                "+a",
                "everyone allow read,readattr,readextattr,readsecurity,file_inherit,only_inherit"
            ])
            .arg(&directory)
            .status()
            .unwrap()
            .success()
    );
    let before = Command::new("ls")
        .arg("-lde")
        .arg(&directory)
        .output()
        .unwrap()
        .stdout;
    let contents = fs::read(&db).unwrap();
    assert!(
        diagnose_resolved(&config, StorageSelection::All)
            .await
            .is_err()
    );
    assert_eq!(
        before,
        Command::new("ls")
            .arg("-lde")
            .arg(&directory)
            .output()
            .unwrap()
            .stdout
    );
    assert_eq!(contents, fs::read(&db).unwrap());
    assert!(!wal.exists() && !shm.exists());
}

/// A selected backend is an immutable configuration scope, including settings captured
/// from the environment at construction. Diagnosis must use the same catalog as recovery.
#[test]
fn scoped_diagnosis_preserves_captured_home_and_config_without_backend_initialization() {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;

    use crate::backend::{Backend, LocalBackend, with_backend};

    let _guard = crate::test_support::lock_env();
    let names = [
        "MSB_HOME",
        "MSB_CONFIG_PATH",
        "MSB_PATH",
        "MSB_LIBKRUNFW_PATH",
        "MSB_AGENTD_PATH",
    ];
    let previous = names.map(|name| (name, std::env::var_os(name)));
    let _restore = scopeguard::guard(previous, |previous| {
        for (name, value) in previous {
            // SAFETY: the shared environment lock remains held through restoration.
            unsafe {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    });
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let root = tempfile::tempdir().unwrap();
    // Every fixture ancestor participates in the catalog's path-substitution checks.
    #[cfg(unix)]
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let ambient_home = root.path().join("ambient-home");
    let invalid_ambient = root.path().join("invalid-ambient.json");
    fs::write(&invalid_ambient, "invalid ambient config").unwrap();
    // Exercise both a programmatic home and a home originally captured from MSB_HOME.
    for explicit_home in [false, true] {
        let base = root.path().join(if explicit_home {
            "explicit"
        } else {
            "captured"
        });
        fs::create_dir(&base).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        let home = base.join("home");
        let config_file = base.join("custom-config.json");
        let managed_file = base.join("managed.json");
        fs::write(
            &config_file,
            r#"{"paths":{"snapshots":"./saved-snapshots"}}"#,
        )
        .unwrap();
        // SAFETY: environment-mutating tests hold the shared lock.
        unsafe {
            std::env::set_var("MSB_HOME", &home);
            std::env::set_var("MSB_CONFIG_PATH", &invalid_ambient);
            std::env::set_var("MSB_AGENTD_PATH", base.join("captured-agentd"));
            std::env::remove_var("MSB_PATH");
            std::env::remove_var("MSB_LIBKRUNFW_PATH");
        }
        let mut builder = LocalBackend::builder()
            .config_path(&config_file)
            .managed_config_path(&managed_file);
        if explicit_home {
            builder = builder.home(&home);
        }
        let local = Arc::new(builder.build_lazy().unwrap());
        assert!(!home.exists());
        // A later environment change and even an invalid original config file cannot
        // change a backend already selected by the caller.
        fs::write(&config_file, "invalid after capture").unwrap();
        unsafe {
            std::env::set_var("MSB_HOME", &ambient_home);
            std::env::set_var("MSB_AGENTD_PATH", base.join("changed-agentd"));
        }
        runtime.block_on(async {
            let (_, mut writer) = catalog(&home).await;
            insert(&mut writer, "captured-only", "invalid stored sandbox").await;
            let db = home
                .join(microsandbox_utils::DB_SUBDIR)
                .join(microsandbox_utils::DB_FILENAME);
            let before = fs::read(&db).unwrap();
            let backend: Arc<dyn Backend> = local.clone();
            with_backend(backend, async {
                let sources = inspection_config(GlobalConfigPatch::new()).unwrap();
                assert_eq!(sources.resolved_config().home(), home);
                assert_eq!(
                    sources.resolved_config().snapshots_dir(),
                    base.join("saved-snapshots")
                );
                assert_eq!(
                    sources.resolved_config().paths.agentd,
                    Some(base.join("captured-agentd"))
                );
                let report = diagnose_storage(GlobalConfigPatch::new(), StorageSelection::All)
                    .await
                    .unwrap();
                assert_eq!(report.home, home);
                assert_eq!(report.sandboxes.len(), 1);
                assert_eq!(report.sandboxes[0].name, "captured-only");
            })
            .await;
            assert_eq!(fs::read(&db).unwrap(), before);
            let migrations: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM sqlite_schema WHERE name='seaql_migrations'",
            )
            .fetch_one(&mut writer)
            .await
            .unwrap();
            assert_eq!(migrations, 0);
            assert!(!home.join(microsandbox_utils::SANDBOXES_SUBDIR).exists());
            writer.close().await.unwrap();
        });
        assert_eq!(local.config().home(), home);
        assert!(!ambient_home.exists());
    }
}

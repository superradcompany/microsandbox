#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use sea_orm::{ConnectionTrait, DbBackend, Statement};

use super::*;
use crate::{DbReadConnection, DbWriteConnection};

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().mode() & 0o777
}
fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn legacy_repair_is_bounded_and_preserves_parent_permissions() {
    let root = tempfile::tempdir().unwrap();
    chmod(root.path(), 0o755);
    let dir = root.path().join("db");
    fs::create_dir(&dir).unwrap();
    chmod(&dir, 0o755);
    for name in [
        "msb.db",
        "msb.db-wal",
        "msb.db-shm",
        "msb.db-journal",
        "msb.db.bak-123",
    ] {
        fs::write(dir.join(name), "synthetic secret").unwrap();
        chmod(&dir.join(name), 0o644);
    }
    fs::write(dir.join("unrelated"), "untouched").unwrap();
    chmod(&dir.join("unrelated"), 0o644);
    ensure_private_database_directory(&dir).unwrap();
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(root.path()), 0o755);
    for name in [
        "msb.db",
        "msb.db-wal",
        "msb.db-shm",
        "msb.db-journal",
        "msb.db.bak-123",
    ] {
        assert_eq!(mode(&dir.join(name)), 0o600);
        assert_eq!(
            fs::read_to_string(dir.join(name)).unwrap(),
            "synthetic secret"
        );
    }
    assert_eq!(mode(&dir.join("unrelated")), 0o644);
}

#[test]
fn links_and_untrusted_parents_never_chmod_unrelated_targets() {
    // Use the shared /tmp tree: macOS's per-user temp root is already private.
    let root = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
    chmod(root.path(), 0o755);
    let external = root.path().join("external");
    fs::write(&external, "untouched").unwrap();
    chmod(&external, 0o644);
    for name in ["msb.db", "msb.db-wal", "msb.db-shm", "msb.db.bak-legacy"] {
        let dir = root.path().join(name.replace('.', "_"));
        fs::create_dir(&dir).unwrap();
        symlink(&external, dir.join(name)).unwrap();
        assert!(ensure_private_database_directory(&dir).is_err());
        assert_eq!(mode(&external), 0o644);
        assert_eq!(fs::read_to_string(&external).unwrap(), "untouched");
    }
    let dir = root.path().join("hardlink");
    fs::create_dir(&dir).unwrap();
    fs::hard_link(&external, dir.join("msb.db")).unwrap();
    assert!(prepare_database_file(&dir.join("msb.db"), true).is_err());
    assert_eq!(mode(&external), 0o644);
    let alias = root.path().join("db-link");
    symlink(&dir, &alias).unwrap();
    assert!(ensure_private_database_directory(&alias).is_err());
    let shared = root.path().join("shared");
    fs::create_dir(&shared).unwrap();
    chmod(&shared, 0o777);
    assert!(ensure_private_database_directory(&shared.join("db")).is_err());
    assert_eq!(mode(&shared), 0o777);
}

#[test]
fn configured_parent_aliases_and_relative_paths_still_work() {
    let root = tempfile::tempdir().unwrap();
    chmod(root.path(), 0o700);
    let home = root.path().join("home");
    fs::create_dir(&home).unwrap();
    let alias = root.path().join("home-alias");
    symlink(&home, &alias).unwrap();
    let path = alias.join("db/msb.db");
    let resolved = prepare_database_file(&path, true).unwrap();
    assert_eq!(resolved, fs::canonicalize(home.join("db/msb.db")).unwrap());
    assert_eq!(mode(&resolved), 0o600);
}

#[test]
fn permissive_umask_is_isolated_in_a_subprocess() {
    let root = tempfile::tempdir().unwrap();
    chmod(root.path(), 0o700);
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "private_storage::tests::fresh_storage_child",
            "--nocapture",
        ])
        .current_dir(root.path())
        .env("MSB_PRIVATE_STORAGE_CHILD", root.path())
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(mode(&root.path().join("db")), 0o700);
    assert_eq!(mode(&root.path().join("db/msb.db")), 0o600);
}

#[tokio::test]
async fn fresh_storage_child() {
    let Some(root) = std::env::var_os("MSB_PRIVATE_STORAGE_CHILD") else {
        return;
    };
    unsafe {
        libc::umask(0);
    }
    let dir = Path::new(&root).join("db");
    let path = prepare_database_file(Path::new("db/msb.db"), true).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().len(), 0);
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(&dir), 0o700);
    let db = DbWriteConnection::open(&path, Duration::from_secs(5), Duration::from_secs(5))
        .await
        .unwrap();
    db.execute_unprepared("CREATE TABLE sample(value); INSERT INTO sample VALUES ('secret')")
        .await
        .unwrap();
    for name in ["msb.db", "msb.db-wal", "msb.db-shm"] {
        assert_eq!(mode(&dir.join(name)), 0o600);
    }
}

#[tokio::test]
async fn secure_read_only_inspection_does_not_change_permissions() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("msb.db");
    let db = DbWriteConnection::open(&path, Duration::from_secs(5), Duration::from_secs(5))
        .await
        .unwrap();
    db.execute_unprepared(
        "CREATE TABLE sample(value TEXT); INSERT INTO sample VALUES ('preserved')",
    )
    .await
    .unwrap();
    // A fully read-only directory cannot create WAL sidecars; use a checkpointed
    // rollback-journal fixture here. Live WAL readers are covered separately.
    db.execute_unprepared("PRAGMA journal_mode=DELETE")
        .await
        .unwrap();
    db.inner().clone().close().await.unwrap();
    chmod(&path, 0o400);
    chmod(root.path(), 0o500);
    let before = fs::metadata(&path).unwrap();
    let reader =
        DbReadConnection::open_read_only(&path, Duration::from_secs(5), Duration::from_secs(5))
            .await
            .unwrap();
    let row = reader
        .query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT value FROM sample",
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.try_get_by_index::<String>(0).unwrap(), "preserved");
    reader.inner().clone().close().await.unwrap();
    let after = fs::metadata(&path).unwrap();
    assert_eq!(
        (before.ctime(), before.ctime_nsec()),
        (after.ctime(), after.ctime_nsec())
    );
    assert_eq!(mode(&path), 0o400);
    assert_eq!(mode(root.path()), 0o500);
    chmod(root.path(), 0o700);
}

#[tokio::test]
async fn inspection_does_not_release_live_sqlite_locks() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("msb.db");
    let db = DbWriteConnection::open(&path, Duration::from_secs(5), Duration::from_secs(5))
        .await
        .unwrap();
    db.execute_unprepared("CREATE TABLE sample(value); BEGIN IMMEDIATE")
        .await
        .unwrap();
    prepare_database_file(&path, true).unwrap();
    let output = Command::new("python3").arg("-c").arg("import sqlite3,sys\nc=sqlite3.connect(sys.argv[1],timeout=0)\ntry: c.execute('begin immediate')\nexcept sqlite3.OperationalError as e:\n assert 'locked' in str(e); sys.exit(0)\nsys.exit(1)").arg(&path).output().unwrap();
    assert!(output.status.success(), "{:?}", output);
    db.execute_unprepared("ROLLBACK").await.unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn darwin_acl_grants_are_removed_before_creation() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("db");
    fs::create_dir(&dir).unwrap();
    let path = dir.join("msb.db");
    fs::write(&path, "secret").unwrap();
    for candidate in [&dir, &path] {
        assert!(
            Command::new("chmod")
                .args([
                    "+a",
                    "everyone allow read,readattr,readextattr,readsecurity"
                ])
                .arg(candidate)
                .status()
                .unwrap()
                .success()
        );
    }
    assert!(
        Command::new("chmod")
            .args(["+a", "everyone allow read,file_inherit,directory_inherit"])
            .arg(&dir)
            .status()
            .unwrap()
            .success()
    );
    let before = Command::new("ls").arg("-lde").arg(&path).output().unwrap();
    assert!(
        before.status.success() && String::from_utf8_lossy(&before.stdout).contains(" allow "),
        "{before:?}"
    );
    prepare_database_file(&path, false).unwrap();
    for candidate in [&dir, &path] {
        let output = Command::new("ls")
            .arg("-lde")
            .arg(candidate)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains(" allow "),
            "{output:?}"
        );
    }
    prepare_database_file(&dir.join("new.db"), true).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires setfacl and passwordless sudo to the unprivileged nobody test identity"]
fn second_account_cannot_read_legacy_fresh_or_acl_inherited_storage() {
    let root = tempfile::Builder::new()
        .prefix("msb-cvr8-access-")
        .tempdir_in("/tmp")
        .unwrap();
    chmod(root.path(), 0o755);
    let dir = root.path().join("db");
    fs::create_dir(&dir).unwrap();
    chmod(&dir, 0o755);
    let files: Vec<_> = ["msb.db", "msb.db-wal", "msb.db-shm", "msb.db.bak-123"]
        .into_iter()
        .map(|n| dir.join(n))
        .collect();
    for path in &files {
        fs::write(path, "synthetic secret").unwrap();
        chmod(path, 0o644);
    }
    let read_as_other = |paths: &[std::path::PathBuf], denied: bool| {
        let script = "import os,sys,errno\nassert os.geteuid() == 65534\nfor p in sys.argv[2:]:\n try:\n  with open(p,'rb') as f: f.read()\n except PermissionError as e:\n  assert sys.argv[1]=='denied' and e.errno==errno.EACCES\n else: assert sys.argv[1]=='allowed'\n";
        let output = Command::new("sudo")
            .args([
                "-n",
                "-u",
                "nobody",
                "python3",
                "-c",
                script,
                if denied { "denied" } else { "allowed" },
            ])
            .args(paths)
            .output()
            .unwrap();
        assert!(output.status.success(), "{:?}", output);
    };
    read_as_other(&files, false); // Reproduce the original unauthorized read under another UID.
    assert!(
        Command::new("setfacl")
            .args(["-m", "u:nobody:rwx,d:u:nobody:rwx"])
            .arg(&dir)
            .status()
            .unwrap()
            .success()
    );
    ensure_private_database_directory(&dir).unwrap();
    read_as_other(&files, true);
    let fresh = prepare_database_file(&dir.join("fresh.db"), true).unwrap();
    fs::write(&fresh, "fresh secret").unwrap();
    read_as_other(&[fresh.clone()], true);
    // Isolate the inherited file ACL from the directory barrier: search-only access
    // must still leave the fresh file unreadable. Restore the boundary immediately.
    chmod(&dir, 0o711);
    read_as_other(&[fresh.clone()], true);
    chmod(&dir, 0o700);
    let output = Command::new("sudo").args(["-n", "-u", "nobody", "python3", "-c",
        "import os,sys,errno\ntry: os.symlink(sys.argv[1],sys.argv[2])\nexcept PermissionError as e: assert e.errno==errno.EACCES\nelse: raise AssertionError('other account could substitute catalog path')"])
        .arg(&fresh).arg(dir.join("msb.db.bak-substitute")).output().unwrap();
    assert!(output.status.success(), "{:?}", output);

    let foreign = root.path().join("foreign.db");
    fs::write(&foreign, "unchanged").unwrap();
    chmod(&foreign, 0o644);
    assert!(
        Command::new("sudo")
            .args(["-n", "chown", "nobody"])
            .arg(&foreign)
            .status()
            .unwrap()
            .success()
    );
    let error = prepare_database_file(&foreign, false).unwrap_err();
    assert!(error.to_string().contains("not owned by this account"));
    assert_eq!(mode(&foreign), 0o644);
    assert_eq!(fs::read_to_string(&foreign).unwrap(), "unchanged");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_catalog_opens_preserve_wal_writes_and_reads() {
    let root = tempfile::tempdir().unwrap();
    chmod(root.path(), 0o700);
    let path = root.path().join("db/msb.db");
    let open =
        || crate::pool::DbPools::open(&path, 2, Duration::from_secs(5), Duration::from_secs(5));
    let (first, second) = tokio::join!(open(), open());
    let first = first.unwrap();
    let second = second.unwrap();
    first
        .write()
        .execute_unprepared("CREATE TABLE sample(value); INSERT INTO sample VALUES ('first')")
        .await
        .unwrap();
    second
        .write()
        .execute_unprepared("INSERT INTO sample VALUES ('second')")
        .await
        .unwrap();
    for pools in [&first, &second] {
        let row = pools
            .read()
            .query_one_raw(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT COUNT(*) FROM sample",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.try_get_by_index::<i64>(0).unwrap(), 2);
    }
}

#[cfg(target_os = "macos")]
#[test]
fn mutating_ancestor_acl_is_rejected_without_rewriting_it() {
    let root = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
    chmod(root.path(), 0o755);
    assert!(
        Command::new("chmod")
            .args([
                "+a",
                "everyone allow add_file,add_subdirectory,delete_child"
            ])
            .arg(root.path())
            .status()
            .unwrap()
            .success()
    );
    assert!(ensure_private_database_directory(&root.path().join("db")).is_err());
    let output = Command::new("ls")
        .arg("-lde")
        .arg(root.path())
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&output.stdout).contains(" allow "),
        "{output:?}"
    );
    assert_eq!(mode(root.path()), 0o755);
}

#[cfg(target_os = "macos")]
#[test]
fn explicit_owner_acl_on_configured_parent_is_preserved() {
    let root = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
    chmod(root.path(), 0o755);
    let identity = Command::new("id").arg("-un").output().unwrap();
    assert!(identity.status.success());
    let grant = format!(
        "user:{} allow add_file,add_subdirectory,delete_child",
        String::from_utf8(identity.stdout).unwrap().trim()
    );
    assert!(
        Command::new("chmod")
            .args(["+a", &grant])
            .arg(root.path())
            .status()
            .unwrap()
            .success()
    );
    ensure_private_database_directory(&root.path().join("db")).unwrap();
    let output = Command::new("ls")
        .arg("-lde")
        .arg(root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success() && String::from_utf8_lossy(&output.stdout).contains(" allow "),
        "{output:?}"
    );
    assert_eq!(mode(root.path()), 0o755);
}

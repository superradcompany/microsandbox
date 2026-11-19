use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::process::Command;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use sea_orm::{ConnectionTrait, DbBackend, DbErr, Statement};

use super::*;
use crate::DbWriteConnection;

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

async fn source(path: &Path) -> DbWriteConnection {
    let db = DbWriteConnection::open(path, Duration::from_secs(5), Duration::from_secs(5))
        .await
        .unwrap();
    db.execute_unprepared(
        "CREATE TABLE sample(value TEXT); INSERT INTO sample VALUES ('synthetic backup canary')",
    )
    .await
    .unwrap();
    db
}

#[tokio::test]
async fn backup_is_private_before_writing_and_before_publication() {
    let root = tempfile::tempdir().unwrap();
    let db = source(&root.path().join("msb.db")).await;
    let backup = root.path().join("backup/msb.db.bak-test");
    let mut observations = 0;
    create_with_observer(db.inner(), &backup, |stage| {
        assert!(!backup.exists());
        #[cfg(unix)]
        {
            assert_eq!(
                fs::metadata(stage).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(stage.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        if observations == 0 {
            assert_eq!(fs::metadata(stage).unwrap().len(), 0);
        } else {
            assert!(
                fs::read(stage)
                    .unwrap()
                    .windows(b"synthetic backup canary".len())
                    .any(|w| w == b"synthetic backup canary")
            );
        }
        observations += 1;
        Ok(())
    })
    .await
    .unwrap();
    assert_eq!(observations, 2);
    validate_backup(&backup).await.unwrap();
    let reader = crate::DbReadConnection::open_read_only(
        &backup,
        Duration::from_secs(5),
        Duration::from_secs(5),
    )
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
    assert_eq!(
        row.try_get_by_index::<String>(0).unwrap(),
        "synthetic backup canary"
    );
}

#[tokio::test]
async fn failed_copy_is_not_published_and_retry_preserves_existing_backup() {
    let root = tempfile::tempdir().unwrap();
    let db = source(&root.path().join("msb.db")).await;
    let backup = root.path().join("msb.db.bak-test");
    for fail_after_write in [false, true] {
        let mut calls = 0;
        let error = create_with_observer(db.inner(), &backup, |_| {
            calls += 1;
            if calls == if fail_after_write { 2 } else { 1 } {
                return Err(DbErr::Custom("injected failure".into()));
            }
            Ok(())
        })
        .await
        .unwrap_err();
        assert!(error.to_string().contains("injected failure"));
        assert!(!backup.exists());
    }
    create_private_backup(db.inner(), &backup).await.unwrap();
    let before = fs::read(&backup).unwrap();
    assert!(create_private_backup(db.inner(), &backup).await.is_err());
    assert_eq!(fs::read(&backup).unwrap(), before);
    let empty = root.path().join("empty.db");
    fs::write(&empty, b"").unwrap();
    assert!(validate_backup(&empty).await.is_err());
    fs::write(&empty, b"not a database").unwrap();
    assert!(validate_backup(&empty).await.is_err());
}

#[tokio::test]
async fn sqlite_failure_does_not_publish_a_backup() {
    let root = tempfile::tempdir().unwrap();
    let db = source(&root.path().join("msb.db")).await;
    let backup = root.path().join("msb.db.bak-test");
    db.execute_unprepared("BEGIN IMMEDIATE").await.unwrap();
    assert!(create_private_backup(db.inner(), &backup).await.is_err());
    assert!(!backup.exists());
    db.execute_unprepared("ROLLBACK").await.unwrap();
    create_private_backup(db.inner(), &backup).await.unwrap();
}

#[tokio::test]
async fn interruption_child() {
    let Some(root) = std::env::var_os("MSB_BACKUP_INTERRUPTION_CHILD") else {
        return;
    };
    let root = Path::new(&root);
    let db = source(&root.join("msb.db")).await;
    create_with_observer(db.inner(), &root.join("msb.db.bak-test"), |stage| {
        if fs::metadata(stage).unwrap().len() > 0 {
            std::process::exit(73);
        }
        Ok(())
    })
    .await
    .unwrap();
    panic!("interruption hook did not run");
}

#[tokio::test]
async fn interruption_leaves_only_private_staging_and_can_retry() {
    let root = tempfile::tempdir().unwrap();
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "backup::tests::interruption_child",
            "--nocapture",
        ])
        .env("MSB_BACKUP_INTERRUPTION_CHILD", root.path())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(73));
    let backup = root.path().join("msb.db.bak-test");
    assert!(!backup.exists());
    let stages: Vec<_> = fs::read_dir(root.path())
        .unwrap()
        .map(Result::unwrap)
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(".msb-db-incomplete-")
        })
        .collect();
    assert_eq!(stages.len(), 1);
    #[cfg(unix)]
    {
        assert_eq!(
            fs::metadata(stages[0].path()).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let db = DbWriteConnection::open(
        &root.path().join("msb.db"),
        Duration::from_secs(5),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    create_private_backup(db.inner(), &backup).await.unwrap();
    validate_backup(&backup).await.unwrap();
}

/// Interrupt SQLite itself only after the staging file contains a synthetic secret.
/// This observes the write window deterministically, without timing sleeps.
async fn interrupt_during_write(check_other_account: bool) {
    let root = if check_other_account {
        tempfile::Builder::new()
            .prefix("msb-backup-window-")
            .tempdir_in("/tmp")
            .unwrap()
    } else {
        tempfile::tempdir().unwrap()
    };
    let db = source(&root.path().join("msb.db")).await;
    db.execute_unprepared("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<2000) INSERT INTO sample SELECT 'synthetic backup canary' || zeroblob(4096) FROM n").await.unwrap();
    let backup = root.path().join("msb.db.bak-test");
    let stage_name = Arc::new(Mutex::new(None::<std::path::PathBuf>));
    let observed = Arc::new(AtomicBool::new(false));
    let callback_name = stage_name.clone();
    let callback_observed = observed.clone();
    let pool = db.inner().get_sqlite_connection_pool();
    let mut connection = pool.acquire().await.unwrap();
    connection
        .lock_handle()
        .await
        .unwrap()
        .set_progress_handler(100, move || {
            let guard = callback_name.lock().unwrap();
            let Some(stage) = guard.as_ref() else {
                return true;
            };
            let bytes = fs::read(stage).unwrap();
            if bytes
                .windows(b"synthetic backup canary".len())
                .any(|w| w == b"synthetic backup canary")
            {
                #[cfg(unix)]
                {
                    assert_eq!(
                        fs::metadata(stage).unwrap().permissions().mode() & 0o777,
                        0o600
                    );
                }
                if check_other_account {
                    denied_as_other_account(stage);
                }
                callback_observed.store(true, Ordering::SeqCst);
                return false;
            }
            true
        });
    drop(connection);
    let result = create_with_observer(db.inner(), &backup, |stage| {
        if check_other_account {
            denied_as_other_account(stage);
        }
        *stage_name.lock().unwrap() = Some(stage.to_owned());
        Ok(())
    })
    .await;
    assert!(result.is_err());
    assert!(
        observed.load(Ordering::SeqCst),
        "SQLite must be interrupted after writing the canary"
    );
    assert!(!backup.exists());
    assert!(!stage_name.lock().unwrap().as_ref().unwrap().exists());
    let mut connection = pool.acquire().await.unwrap();
    connection
        .lock_handle()
        .await
        .unwrap()
        .remove_progress_handler();
    drop(connection);
    create_private_backup(db.inner(), &backup).await.unwrap();
    validate_backup(&backup).await.unwrap();
    if check_other_account {
        denied_as_other_account(&backup);
    }
}

fn denied_as_other_account(path: &Path) {
    let output = Command::new("sudo").args(["-n", "-u", "nobody", "python3", "-c",
        "import os,sys,errno\nassert os.geteuid()==65534\ntry: open(sys.argv[1],'rb').read()\nexcept PermissionError as e: assert e.errno==errno.EACCES\nelse: raise AssertionError('other account read private data')"])
        .arg(path).output().unwrap();
    assert!(output.status.success(), "{:?}", output);
}

#[tokio::test]
async fn sqlite_interruption_during_sensitive_write_is_private_and_retryable() {
    interrupt_during_write(false).await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires passwordless sudo to the unprivileged nobody test identity"]
async fn second_account_cannot_read_during_backup_or_after_interruption() {
    interrupt_during_write(true).await;
    let root = tempfile::Builder::new()
        .prefix("msb-backup-crash-")
        .tempdir_in("/tmp")
        .unwrap();
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "backup::tests::interruption_child"])
        .env("MSB_BACKUP_INTERRUPTION_CHILD", root.path())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(73));
    assert!(!root.path().join("msb.db.bak-test").exists());
    for entry in fs::read_dir(root.path()).unwrap() {
        denied_as_other_account(&entry.unwrap().path());
    }
}

#[cfg(unix)]
#[tokio::test]
async fn backup_destination_symlink_never_changes_external_target() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let db = source(&root.path().join("db/msb.db")).await;
    let external = root.path().join("external");
    fs::write(&external, "untouched").unwrap();
    fs::set_permissions(&external, fs::Permissions::from_mode(0o644)).unwrap();
    let destination = root.path().join("backup.db");
    symlink(&external, &destination).unwrap();
    assert!(
        create_private_backup(db.inner(), &destination)
            .await
            .is_err()
    );
    assert_eq!(fs::read_to_string(&external).unwrap(), "untouched");
    assert_eq!(
        fs::metadata(&external).unwrap().permissions().mode() & 0o777,
        0o644
    );
}

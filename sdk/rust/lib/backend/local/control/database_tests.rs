//! Cross-process catalog durability and kernel-lock ownership regressions.

use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use microsandbox_db::{DbReadConnection, entity::volume};
use sea_orm::{ConnectionTrait, DbBackend, EntityTrait, Statement};
use tokio::process::Command;

use super::identity::DatabaseIdentity;
use crate::Sandbox;
use crate::backend::{Backend, LocalBackend, with_backend};
use crate::volume::Volume;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const CHILD: &str = "backend::local::control::database_tests::database_child";
const CHILD_COMPLETED: &str = "database child completed";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn child(path: &Path, action: &str) {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", CHILD, "--ignored", "--nocapture"])
        .env("MSB_IDENTITY_TEST_PATH", path)
        .env("MSB_IDENTITY_TEST_ACTION", action)
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(30), command.output())
        .await
        .expect("database child timed out")
        .unwrap();
    assert!(
        output.status.success(),
        "child {action} failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains(&format!("{CHILD_COMPLETED} {action}")),
        "child {action} did not execute its checks"
    );
}

async fn backend(home: &Path) -> Arc<LocalBackend> {
    Arc::new(
        LocalBackend::builder()
            .home(home)
            .config_path(home.join("config.json"))
            .managed_config_path(home.join("managed.json"))
            .build()
            .await
            .unwrap(),
    )
}

async fn close(backend: &LocalBackend) {
    let pools = backend.db().await.unwrap();
    // Await actual SQLite close/checkpoint completion while the child is still
    // alive. Exiting immediately after dropping a pool can skip WAL cleanup.
    pools.read().inner().close_by_ref().await.unwrap();
    pools.write().inner().close_by_ref().await.unwrap();
}

fn lock(file: &File) -> std::io::Result<()> {
    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    lock.l_type = libc::F_WRLCK as _;
    lock.l_whence = libc::SEEK_SET as _;
    let result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLK, &lock) };
    if result == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn database_identity_preserves_process_locks() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("database");
    let file = File::create(&path).unwrap();
    lock(&file).unwrap();
    let identity = DatabaseIdentity::capture(&path).unwrap();
    child(&path, "locked").await;
    identity.verify().unwrap();
    child(&path, "locked").await;
    // A second backend/metrics reader can release its identity while another
    // SQLite connection in this process still owns locks on the same inode.
    drop(DatabaseIdentity::capture(&path).unwrap());
    child(&path, "locked").await;
    drop(identity);
    child(&path, "locked").await;
}

#[tokio::test]
async fn acknowledged_volumes_survive_other_processes_closing_catalog() {
    let home = tempfile::tempdir().unwrap();
    let parent = backend(home.path()).await;
    with_backend(parent.clone() as Arc<dyn Backend>, async {
        Sandbox::list().await.unwrap();
        child(home.path(), "child-one").await;
        drop(Volume::builder("parent").create().await.unwrap());
        child(home.path(), "child-two").await;

        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        let shm = home.path().canonicalize().unwrap().join("db/msb.db-shm");
        let mappings: Vec<_> = maps
            .lines()
            .filter(|line| line.contains(shm.to_str().unwrap()))
            .collect();
        assert!(
            !mappings.is_empty(),
            "parent has no SHM mapping for {}: {maps}",
            shm.display()
        );
        assert!(
            !mappings.iter().any(|line| line.contains("(deleted)")),
            "parent SHM mapping was deleted: {mappings:?}"
        );

        child(home.path(), "read").await;
    })
    .await;
    close(&parent).await;
    drop(parent);
    child(home.path(), "read").await;
}

#[tokio::test]
#[ignore = "subprocess helper"]
async fn database_child() {
    let Some(path) = std::env::var_os("MSB_IDENTITY_TEST_PATH") else {
        return;
    };
    let path = Path::new(&path);
    let action = std::env::var("MSB_IDENTITY_TEST_ACTION").unwrap();
    if action == "locked" {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        let error = lock(&file).expect_err("identity checks released the parent's POSIX lock");
        assert!(matches!(
            error.raw_os_error(),
            Some(libc::EAGAIN | libc::EACCES)
        ));
        println!("{CHILD_COMPLETED} {action}");
        return;
    }

    if action == "read" {
        let db = DbReadConnection::open_read_only(
            &path.join("db/msb.db"),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        let mut names: Vec<_> = volume::Entity::find()
            .all(db.inner())
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.name)
            .collect();
        names.sort();
        assert_eq!(names, ["child-one", "child-two", "parent"]);
        let integrity = db
            .inner()
            .query_one_raw(Statement::from_string(
                DbBackend::Sqlite,
                "PRAGMA integrity_check",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(integrity.try_get_by_index::<String>(0).unwrap(), "ok");
        println!("{CHILD_COMPLETED} {action}");
        return;
    }

    assert!(
        matches!(action.as_str(), "child-one" | "child-two"),
        "unknown database child action: {action}"
    );

    let backend = backend(path).await;
    with_backend(backend.clone() as Arc<dyn Backend>, async {
        drop(Volume::builder(&action).create().await.unwrap());
    })
    .await;
    close(&backend).await;
    println!("{CHILD_COMPLETED} {action}");
}

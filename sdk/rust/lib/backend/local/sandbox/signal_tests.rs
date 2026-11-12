//! Lifecycle signal dispatch: only a PID proven to still be the registered
//! runtime receives kill or drain signals.

use std::process::Command;
use std::sync::Arc;

use sea_orm::{EntityTrait, Set};

use super::LocalBackend;
use crate::db::entity::{run as run_entity, sandbox as sandbox_entity};
use crate::sandbox::{SandboxConfig, SandboxStatus};

//--------------------------------------------------------------------------------------------------
// Helpers
//--------------------------------------------------------------------------------------------------

fn test_config(name: impl Into<String>) -> SandboxConfig {
    SandboxConfig {
        spec: microsandbox_types::SandboxSpec {
            name: name.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn lifecycle_signal_child() {
    use std::io::Read;
    if std::env::var_os("MSB_LIFECYCLE_SIGNAL_CHILD").is_none() {
        return;
    }
    // A stray SIGUSR1 must terminate this child.
    unsafe {
        libc::signal(libc::SIGUSR1, libc::SIG_DFL);
        let empty: libc::sigset_t = std::mem::zeroed();
        libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut());
    }
    println!("ready");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let mut byte = [0];
    let _ = std::io::stdin().read_exact(&mut byte);
    std::process::exit(0);
}

async fn backend_with_stale_running_pid(
    home: &std::path::Path,
    name: &str,
    pid: i32,
) -> (Arc<LocalBackend>, i32) {
    let backend = Arc::new(
        crate::test_support::local_backend_builder(home)
            .build()
            .await
            .unwrap(),
    );
    let run_dir = backend.config().run_dir();
    std::fs::create_dir_all(&run_dir).unwrap();
    drop(microsandbox_runtime::ipc::acquire_lifecycle_guard(&run_dir, name).unwrap());
    let pools = backend.db().await.unwrap();
    let id = LocalBackend::insert_sandbox_record(pools.write(), &test_config(name))
        .await
        .unwrap();
    run_entity::Entity::insert(run_entity::ActiveModel {
        sandbox_id: Set(id),
        pid: Set(Some(pid)),
        status: Set(run_entity::RunStatus::Running),
        ..Default::default()
    })
    .exec(pools.write())
    .await
    .unwrap();
    (backend, id)
}

async fn recorded_sandbox_status(backend: &LocalBackend, id: i32) -> SandboxStatus {
    let pools = backend.db().await.unwrap();
    sandbox_entity::Entity::find_by_id(id)
        .one(pools.read())
        .await
        .unwrap()
        .unwrap()
        .status
}

#[tokio::test]
async fn kill_sandbox_spares_unrelated_recycled_pid() {
    let home = tempfile::tempdir_in("/tmp").unwrap();
    let mut innocent_command = Command::new(std::env::current_exe().unwrap());
    innocent_command
        .args([
            "--exact",
            "backend::local::sandbox::signal_tests::lifecycle_signal_child",
            "--nocapture",
        ])
        .env("MSB_LIFECYCLE_SIGNAL_CHILD", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    let mut innocent = scopeguard::guard(innocent_command.spawn().unwrap(), |mut child| {
        let _ = child.kill();
        let _ = child.wait();
    });
    {
        use std::io::BufRead;
        let mut output = std::io::BufReader::new(innocent.stdout.take().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            assert_ne!(output.read_line(&mut line).unwrap(), 0);
            if line.trim() == "ready" {
                break;
            }
        }
    }
    let (backend, id) =
        backend_with_stale_running_pid(home.path(), "stale", innocent.id() as i32).await;
    backend.kill_sandbox("stale", None).await.unwrap();
    assert!(
        LocalBackend::pid_is_alive(innocent.id() as i32),
        "a PID the backend cannot prove is the runtime must not receive SIGKILL"
    );
    assert_eq!(
        recorded_sandbox_status(&backend, id).await,
        SandboxStatus::Stopped
    );
}

#[tokio::test]
async fn drain_sandbox_spares_unrelated_recycled_pid() {
    let home = tempfile::tempdir_in("/tmp").unwrap();
    let mut innocent_command = Command::new(std::env::current_exe().unwrap());
    innocent_command
        .args([
            "--exact",
            "backend::local::sandbox::signal_tests::lifecycle_signal_child",
            "--nocapture",
        ])
        .env("MSB_LIFECYCLE_SIGNAL_CHILD", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    let mut innocent = scopeguard::guard(innocent_command.spawn().unwrap(), |mut child| {
        let _ = child.kill();
        let _ = child.wait();
    });
    {
        use std::io::BufRead;
        let mut output = std::io::BufReader::new(innocent.stdout.take().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            assert_ne!(output.read_line(&mut line).unwrap(), 0);
            if line.trim() == "ready" {
                break;
            }
        }
    }
    let (backend, id) =
        backend_with_stale_running_pid(home.path(), "stale", innocent.id() as i32).await;
    backend.drain_sandbox("stale", None).await.unwrap();
    assert!(
        LocalBackend::pid_is_alive(innocent.id() as i32),
        "a PID the backend cannot prove is the runtime must not receive SIGUSR1"
    );
    assert_eq!(
        recorded_sandbox_status(&backend, id).await,
        SandboxStatus::Draining
    );
}

#[tokio::test]
async fn kill_sandbox_still_kills_a_proven_runtime() {
    use std::io::BufRead;
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::process::Stdio;

    let home = tempfile::tempdir_in("/tmp").unwrap();
    let backend = Arc::new(
        crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap(),
    );
    let name = "live";
    let run_dir = backend.config().run_dir();
    std::fs::create_dir_all(&run_dir).unwrap();
    let guard = microsandbox_runtime::ipc::acquire_lifecycle_guard(&run_dir, name).unwrap();
    let guard_fd = guard.as_raw_fd();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "backend::local::sandbox::signal_tests::lifecycle_signal_child",
            "--nocapture",
        ])
        .env("MSB_LIFECYCLE_SIGNAL_CHILD", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    unsafe {
        command.pre_exec(move || {
            let copy = libc::fcntl(guard_fd, libc::F_DUPFD_CLOEXEC, 200);
            if copy < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::dup2(copy, microsandbox_runtime::vm::LIFECYCLE_LOCK_FD) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = scopeguard::guard(command.spawn().unwrap(), |mut child| {
        let _ = child.kill();
        let _ = child.wait();
    });
    {
        let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            assert_ne!(output.read_line(&mut line).unwrap(), 0);
            if line.trim() == "ready" {
                break;
            }
        }
    }
    let pools = backend.db().await.unwrap();
    let id = LocalBackend::insert_sandbox_record(pools.write(), &test_config(name))
        .await
        .unwrap();
    run_entity::Entity::insert(run_entity::ActiveModel {
        sandbox_id: Set(id),
        pid: Set(Some(child.id() as i32)),
        status: Set(run_entity::RunStatus::Running),
        ..Default::default()
    })
    .exec(pools.write())
    .await
    .unwrap();
    backend.kill_sandbox(name, None).await.unwrap();
    let status = child.wait().unwrap();
    assert_eq!(
        status.signal(),
        Some(libc::SIGKILL),
        "the proven runtime must still receive the kill signal"
    );
    assert_eq!(
        recorded_sandbox_status(&backend, id).await,
        SandboxStatus::Stopped
    );
}

#[tokio::test]
async fn drain_sandbox_still_drains_a_proven_runtime() {
    use std::io::BufRead;
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::process::Stdio;

    let home = tempfile::tempdir_in("/tmp").unwrap();
    let backend = Arc::new(
        crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap(),
    );
    let name = "live";
    let run_dir = backend.config().run_dir();
    std::fs::create_dir_all(&run_dir).unwrap();
    let guard = microsandbox_runtime::ipc::acquire_lifecycle_guard(&run_dir, name).unwrap();
    let guard_fd = guard.as_raw_fd();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "backend::local::sandbox::signal_tests::lifecycle_signal_child",
            "--nocapture",
        ])
        .env("MSB_LIFECYCLE_SIGNAL_CHILD", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    unsafe {
        command.pre_exec(move || {
            let copy = libc::fcntl(guard_fd, libc::F_DUPFD_CLOEXEC, 200);
            if copy < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::dup2(copy, microsandbox_runtime::vm::LIFECYCLE_LOCK_FD) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = scopeguard::guard(command.spawn().unwrap(), |mut child| {
        let _ = child.kill();
        let _ = child.wait();
    });
    {
        let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            assert_ne!(output.read_line(&mut line).unwrap(), 0);
            if line.trim() == "ready" {
                break;
            }
        }
    }
    let pools = backend.db().await.unwrap();
    let id = LocalBackend::insert_sandbox_record(pools.write(), &test_config(name))
        .await
        .unwrap();
    run_entity::Entity::insert(run_entity::ActiveModel {
        sandbox_id: Set(id),
        pid: Set(Some(child.id() as i32)),
        status: Set(run_entity::RunStatus::Running),
        ..Default::default()
    })
    .exec(pools.write())
    .await
    .unwrap();
    backend.drain_sandbox(name, None).await.unwrap();
    let status = child.wait().unwrap();
    assert_eq!(
        status.signal(),
        Some(libc::SIGUSR1),
        "the proven runtime must still receive the drain signal"
    );
    assert_eq!(
        recorded_sandbox_status(&backend, id).await,
        SandboxStatus::Draining
    );
}

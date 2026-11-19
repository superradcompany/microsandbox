//! Lifecycle signal dispatch: only a PID proven to still be the registered
//! runtime receives kill or drain signals.

use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, ChildStdout, Command, ExitStatus};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use sea_orm::{EntityTrait, Set};

use super::LocalContext;
use crate::db::entity::{run as run_entity, sandbox as sandbox_entity};
use crate::sandbox::{SandboxConfig, SandboxStatus};

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

fn test_home() -> tempfile::TempDir {
    let mut builder = tempfile::Builder::new();
    builder.permissions(std::fs::Permissions::from_mode(0o700));
    // Keep Darwin socket paths short; honor TMPDIR on the Linux test hosts.
    #[cfg(target_os = "macos")]
    let directory = builder.tempdir_in("/tmp");
    #[cfg(target_os = "linux")]
    let directory = builder.tempdir();
    directory.unwrap()
}

pub(super) fn child_lines(stdout: ChildStdout) -> Receiver<String> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    receiver
}

pub(super) fn expect_line(lines: &Receiver<String>, expected: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let line = lines
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .unwrap_or_else(|error| panic!("child did not report {expected:?}: {error}"));
        if line.trim() == expected {
            return;
        }
    }
}

pub(super) fn wait_child(child: &mut Child) -> ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "child {} failed to exit",
            child.id()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

pub(super) fn cleanup_child(child: &mut Child) {
    let _ = child.kill();
    // Cleanup must remain bounded even when an assertion is already unwinding.
    let deadline = Instant::now() + Duration::from_secs(5);
    while matches!(child.try_wait(), Ok(None)) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
}

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
    #[cfg(target_os = "linux")]
    if std::env::var_os("MSB_TEST_PRIVATE_CHILD").is_some() {
        // Model a process whose descriptors an unprivileged SDK cannot inspect.
        assert_eq!(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) }, 0);
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
) -> (Arc<LocalContext>, i32) {
    let backend = Arc::new(
        crate::test_support::local_backend_builder(home)
            .build()
            .unwrap(),
    );
    let run_dir = backend.config().run_dir();
    std::fs::create_dir_all(&run_dir).unwrap();
    drop(microsandbox_runtime::ipc::acquire_lifecycle_guard(&run_dir, name).unwrap());
    let pools = backend.db().await.unwrap();
    let id = LocalContext::insert_sandbox_record(pools.write(), &test_config(name))
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

async fn recorded_sandbox_status(backend: &LocalContext, id: i32) -> SandboxStatus {
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
    let home = test_home();
    let mut innocent_command = Command::new(std::env::current_exe().unwrap());
    innocent_command
        .args([
            "--exact",
            "context::local::sandbox::signal_tests::lifecycle_signal_child",
            "--nocapture",
        ])
        .env("MSB_LIFECYCLE_SIGNAL_CHILD", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    let mut innocent = scopeguard::guard(innocent_command.spawn().unwrap(), |mut child| {
        cleanup_child(&mut child);
    });
    expect_line(&child_lines(innocent.stdout.take().unwrap()), "ready");
    let (backend, id) =
        backend_with_stale_running_pid(home.path(), "stale", innocent.id() as i32).await;
    backend.kill_sandbox("stale", None).await.unwrap();
    assert!(
        LocalContext::pid_is_alive(innocent.id() as i32),
        "a PID the backend cannot prove is the runtime must not receive SIGKILL"
    );
    assert_eq!(
        recorded_sandbox_status(&backend, id).await,
        SandboxStatus::Stopped
    );
}

#[tokio::test]
async fn drain_sandbox_spares_unrelated_recycled_pid() {
    let home = test_home();
    let mut innocent_command = Command::new(std::env::current_exe().unwrap());
    innocent_command
        .args([
            "--exact",
            "context::local::sandbox::signal_tests::lifecycle_signal_child",
            "--nocapture",
        ])
        .env("MSB_LIFECYCLE_SIGNAL_CHILD", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    let mut innocent = scopeguard::guard(innocent_command.spawn().unwrap(), |mut child| {
        cleanup_child(&mut child);
    });
    expect_line(&child_lines(innocent.stdout.take().unwrap()), "ready");
    let (backend, id) =
        backend_with_stale_running_pid(home.path(), "stale", innocent.id() as i32).await;
    backend.drain_sandbox("stale", None).await.unwrap();
    assert!(
        LocalContext::pid_is_alive(innocent.id() as i32),
        "a PID the backend cannot prove is the runtime must not receive SIGUSR1"
    );
    assert_eq!(
        recorded_sandbox_status(&backend, id).await,
        SandboxStatus::Crashed
    );
}

#[tokio::test]
async fn kill_sandbox_still_kills_a_proven_runtime() {
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::process::Stdio;

    let home = test_home();
    let backend = Arc::new(
        crate::test_support::local_backend_builder(home.path())
            .build()
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
            "context::local::sandbox::signal_tests::lifecycle_signal_child",
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
        cleanup_child(&mut child);
    });
    expect_line(&child_lines(child.stdout.take().unwrap()), "ready");
    let pools = backend.db().await.unwrap();
    let id = LocalContext::insert_sandbox_record(pools.write(), &test_config(name))
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
    drop(guard); // Only the runtime retains the lifecycle lock after startup.
    backend.kill_sandbox(name, None).await.unwrap();
    let status = wait_child(&mut child);
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
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::process::Stdio;

    let home = test_home();
    let backend = Arc::new(
        crate::test_support::local_backend_builder(home.path())
            .build()
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
            "context::local::sandbox::signal_tests::lifecycle_signal_child",
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
        cleanup_child(&mut child);
    });
    expect_line(&child_lines(child.stdout.take().unwrap()), "ready");
    let pools = backend.db().await.unwrap();
    let id = LocalContext::insert_sandbox_record(pools.write(), &test_config(name))
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
    drop(guard);
    backend.drain_sandbox(name, None).await.unwrap();
    let status = wait_child(&mut child);
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

#[tokio::test]
async fn ambiguous_runtime_ownership_preserves_active_state() {
    let home = test_home();
    let (backend, id) =
        backend_with_stale_running_pid(home.path(), "busy", std::process::id() as i32).await;
    let _guard =
        microsandbox_runtime::ipc::acquire_lifecycle_guard(&backend.config().run_dir(), "busy")
            .unwrap();
    assert!(backend.drain_sandbox("busy", Some(id)).await.is_err());
    assert!(backend.kill_sandbox("busy", Some(id)).await.is_err());
    assert_eq!(
        recorded_sandbox_status(&backend, id).await,
        SandboxStatus::Running
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn stop_reconciles_a_released_generation_with_a_private_pid() {
    use std::process::Stdio;

    let home = test_home();
    let mut child = scopeguard::guard(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "context::local::sandbox::signal_tests::lifecycle_signal_child",
                "--nocapture",
            ])
            .env("MSB_LIFECYCLE_SIGNAL_CHILD", "1")
            .env("MSB_TEST_PRIVATE_CHILD", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
        |mut child| {
            drop(child.stdin.take());
            cleanup_child(&mut child);
        },
    );
    expect_line(&child_lines(child.stdout.take().unwrap()), "ready");
    let pid = child.id() as i32;
    let (backend, id) = backend_with_stale_running_pid(home.path(), "private", pid).await;
    // A privileged CI runner can inspect private children. Record which kernel
    // path ran while requiring generation reconciliation in either environment.
    let lock =
        microsandbox_runtime::ipc::lifecycle_lock_path(&backend.config().run_dir(), "private");
    match super::process_exit::RuntimeExit::capture(Some(pid), &lock) {
        Err(error) => {
            assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
            println!("verified denied descriptor access");
        }
        Ok(result) => assert!(result.is_none()),
    }
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        backend.stop_complete("private", id, false),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        recorded_sandbox_status(&backend, id).await,
        SandboxStatus::Crashed
    );
    assert!(child.try_wait().unwrap().is_none());
}

async fn assert_active_run(backend: &LocalContext, id: i32) {
    assert_eq!(
        recorded_sandbox_status(backend, id).await,
        SandboxStatus::Running
    );
    let pools = backend.db().await.unwrap();
    let run = LocalContext::load_active_run(pools.read(), id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(run.status, run_entity::RunStatus::Running);
}

#[tokio::test]
async fn live_socket_prevents_unverified_kill_and_drain() {
    let home = test_home();
    let (backend, id) =
        backend_with_stale_running_pid(home.path(), "socket", std::process::id() as i32).await;
    let socket =
        microsandbox_runtime::ipc::RuntimeSocketPaths::new(&backend.config().run_dir(), "socket")
            .legacy_agent;
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    assert!(backend.kill_sandbox("socket", Some(id)).await.is_err());
    assert_active_run(&backend, id).await;
    assert!(backend.drain_sandbox("socket", Some(id)).await.is_err());
    assert_active_run(&backend, id).await;
    assert!(
        socket.exists(),
        "uncertain ownership must preserve the endpoint"
    );
}

#[tokio::test]
async fn held_disk_prevents_unverified_kill_and_drain() {
    use crate::runtime::owned_volumes;
    use crate::sandbox::MountBuilder;
    use sea_orm::{ActiveModelTrait, IntoActiveModel};

    let home = test_home();
    let (backend, id) =
        backend_with_stale_running_pid(home.path(), "disk", std::process::id() as i32).await;
    let mount = MountBuilder::new("/data")
        .owned_with(|owned| owned.disk().size(1_u32))
        .build()
        .unwrap();
    let mut config = test_config("disk");
    config.spec.mounts.push(mount);
    let pools = backend.db().await.unwrap();
    let mut model = sandbox_entity::Entity::find_by_id(id)
        .one(pools.read())
        .await
        .unwrap()
        .unwrap()
        .into_active_model();
    model.config = Set(serde_json::to_string(&config).unwrap());
    model.update(pools.write()).await.unwrap();
    let sandbox_dir = backend.sandboxes_dir().join("disk");
    let backing = owned_volumes::backing_path(
        &sandbox_dir,
        "/data",
        &microsandbox_types::OwnedVolumeStorage::Disk { capacity_mib: 1 },
    );
    std::fs::create_dir_all(backing.parent().unwrap()).unwrap();
    let marker = owned_volumes::disk_lock_path(&sandbox_dir, "/data").unwrap();
    let guards = owned_volumes::try_acquire_disk_guards(&sandbox_dir, &config.spec.mounts)
        .unwrap()
        .unwrap();
    assert_eq!(guards.len(), 1);
    // No lifecycle owner or endpoint remains, but disk teardown has not completed.
    assert!(backend.kill_sandbox("disk", Some(id)).await.is_err());
    assert_active_run(&backend, id).await;
    assert!(backend.drain_sandbox("disk", Some(id)).await.is_err());
    assert_active_run(&backend, id).await;
    assert!(marker.exists(), "uncertain ownership must preserve storage");
    drop(guards);
    backend.kill_sandbox("disk", Some(id)).await.unwrap();
    assert_eq!(
        recorded_sandbox_status(&backend, id).await,
        SandboxStatus::Stopped
    );
}

#[cfg(target_os = "linux")]
async fn denied_inspection_case(signal: libc::c_int, owned: bool) {
    use std::process::Stdio;
    let home = test_home();
    let mut child = scopeguard::guard(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "context::local::sandbox::signal_tests::lifecycle_signal_child",
                "--nocapture",
            ])
            .env("MSB_LIFECYCLE_SIGNAL_CHILD", "1")
            .env("MSB_TEST_PRIVATE_CHILD", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
        |mut child| cleanup_child(&mut child),
    );
    expect_line(&child_lines(child.stdout.take().unwrap()), "ready");
    let (backend, id) =
        backend_with_stale_running_pid(home.path(), "denied", child.id() as i32).await;
    let lock =
        microsandbox_runtime::ipc::lifecycle_lock_path(&backend.config().run_dir(), "denied");
    match super::process_exit::RuntimeExit::capture(Some(child.id() as i32), &lock) {
        Err(error) => {
            assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
            println!("verified denied descriptor access: signal={signal}, owned={owned}");
        }
        // Privileged runners may bypass the kernel permission check. Keep the unrelated
        // child assertion, and make it visible that this run did not exercise EACCES.
        Ok(result) => {
            assert!(result.is_none());
            println!("descriptor access bypassed by test privileges");
        }
    }
    let owner = owned.then(|| {
        microsandbox_runtime::ipc::acquire_lifecycle_guard(&backend.config().run_dir(), "denied")
            .unwrap()
    });
    let result = if signal == libc::SIGKILL {
        backend.kill_sandbox("denied", Some(id)).await
    } else {
        backend.drain_sandbox("denied", Some(id)).await
    };
    if owned {
        assert!(result.is_err());
        assert_active_run(&backend, id).await;
    } else {
        result.unwrap();
        let expected = if signal == libc::SIGKILL {
            SandboxStatus::Stopped
        } else {
            SandboxStatus::Crashed
        };
        assert_eq!(recorded_sandbox_status(&backend, id).await, expected);
    }
    assert!(
        child.try_wait().unwrap().is_none(),
        "unverified child must survive"
    );
    drop(owner);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn denied_inspection_kill_reconciles_only_released_generation() {
    denied_inspection_case(libc::SIGKILL, false).await;
    denied_inspection_case(libc::SIGKILL, true).await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn denied_inspection_drain_reconciles_only_released_generation() {
    denied_inspection_case(libc::SIGUSR1, false).await;
    denied_inspection_case(libc::SIGUSR1, true).await;
}

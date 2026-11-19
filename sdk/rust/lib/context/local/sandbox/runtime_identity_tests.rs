//! Process fixtures exercise names, wall-clock offsets and inherited ownership separately.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::{RecordedRuntime, RuntimeSignal};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(in crate::context::local::sandbox) fn cleanup_child(child: &mut Child) {
    let _ = child.kill();
    let deadline = Instant::now() + Duration::from_secs(5);
    while matches!(child.try_wait(), Ok(None)) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn spawn_fixture(exe: &Path, inherited: Option<i32>) -> Child {
    let mut command = Command::new(exe);
    command
        .args(["runtime_identity_child", "--nocapture", "--test-threads=1"])
        .env("MSB_TEST_IDENTITY_CHILD", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    if let Some(fd) = inherited {
        unsafe {
            command.pre_exec(move || {
                let spare = libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 200);
                if spare < 0 || libc::dup2(spare, microsandbox_runtime::vm::LIFECYCLE_LOCK_FD) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                libc::close(spare);
                Ok(())
            });
        }
    }
    let mut child = command.spawn().unwrap();
    let stdout = child.stdout.take().unwrap();
    let (send, receive) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if line == "identity-child-ready" {
                let _ = send.send(());
                // Keep draining harness output until exit; closing it would inject SIGPIPE.
            }
        }
    });
    if receive.recv_timeout(Duration::from_secs(10)).is_err() {
        cleanup_child(&mut child);
        panic!("identity child failed to report readiness");
    }
    child
}

pub(in crate::context::local::sandbox) fn spawn_msb_child() -> (Child, tempfile::TempDir) {
    let bin = tempfile::tempdir().unwrap();
    let exe = bin.path().join("msb");
    let original = std::env::current_exe().unwrap();
    if std::fs::hard_link(&original, &exe).is_err() {
        std::fs::copy(original, &exe).unwrap();
    }
    (spawn_fixture(&exe, None), bin)
}

pub(in crate::context::local::sandbox) fn spawn_owned_child(run_dir: &Path, name: &str) -> Child {
    let owner = microsandbox_runtime::ipc::acquire_lifecycle_guard(run_dir, name).unwrap();
    spawn_fixture(&std::env::current_exe().unwrap(), Some(owner.as_raw_fd()))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn runtime_identity_child() {
    if std::env::var_os("MSB_TEST_IDENTITY_CHILD").is_none() {
        return;
    }
    unsafe {
        // A host's ignored/blocked SIGUSR1 must not make a wrong drain look harmless.
        libc::signal(libc::SIGUSR1, libc::SIG_DFL);
        let mut signals = std::mem::zeroed();
        libc::sigemptyset(&mut signals);
        libc::sigaddset(&mut signals, libc::SIGUSR1);
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &signals, std::ptr::null_mut());
    }
    println!("\nidentity-child-ready");
    std::io::stdout().flush().unwrap();
    let _ = std::io::stdin().read(&mut [0]);
}

#[test]
fn executable_name_does_not_prove_ownership() {
    let home = tempfile::tempdir().unwrap();
    let (child, _bin) = spawn_msb_child();
    let mut child = scopeguard::guard(child, |mut child| cleanup_child(&mut child));
    let lock = microsandbox_runtime::ipc::lifecycle_lock_path(home.path(), "unknown");
    let recorded = RecordedRuntime::inspect(Some(child.id() as i32), &lock);
    assert!(matches!(recorded, RecordedRuntime::Unverified { .. }));
    assert!(child.try_wait().unwrap().is_none());
}

#[test]
fn matching_lifecycle_owner_can_be_signaled() {
    let home = tempfile::tempdir().unwrap();
    let child = spawn_owned_child(home.path(), "owned");
    let mut child = scopeguard::guard(child, |mut child| cleanup_child(&mut child));
    let lock = microsandbox_runtime::ipc::lifecycle_lock_path(home.path(), "owned");
    let RecordedRuntime::Live(process) = RecordedRuntime::inspect(Some(child.id() as i32), &lock)
    else {
        panic!("inherited lifecycle ownership was not recognized");
    };
    process.signal(RuntimeSignal::Kill).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !process.has_exited() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(!child.wait().unwrap().success());
}

#[test]
fn another_home_or_sandbox_does_not_prove_ownership() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let child = spawn_owned_child(first.path(), "same-name");
    let mut child = scopeguard::guard(child, |mut child| cleanup_child(&mut child));
    for (root, name) in [
        (second.path(), "same-name"),
        (first.path(), "different-name"),
    ] {
        let lock = microsandbox_runtime::ipc::lifecycle_lock_path(root, name);
        assert!(matches!(
            RecordedRuntime::inspect(Some(child.id() as i32), &lock),
            RecordedRuntime::Unverified { .. }
        ));
    }
    assert!(child.try_wait().unwrap().is_none());
}

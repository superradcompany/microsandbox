//! Host VM-child reaping, distinct from agentd's in-guest child reaping tests.
//! Run on Linux KVM with `cargo test -p microsandbox --test detached_reaping -- --ignored`.

#![cfg(all(target_os = "linux", feature = "local"))]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use microsandbox::Sandbox;
use nix::errno::Errno;
use nix::sys::signal;
use nix::sys::wait::{WaitPidFlag, waitpid};
use nix::unistd::Pid;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const CASE_ENV: &str = "MSB_VM_REAP_CASE";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn run_isolated(case: &str) {
    let home = tempfile::Builder::new().prefix("reap-").tempdir().unwrap();
    // Resolve the installed runtime before selecting an empty per-case home. CI
    // supplies a build directory; local invocations can keep their MSB_PATH.
    let runtime = std::env::var_os("MSB_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            if let Some(directory) = std::env::var_os("MSB_TEST_RUNTIME_DIR") {
                std::path::PathBuf::from(directory).join("msb")
            } else {
                std::path::PathBuf::from(std::env::var_os("HOME").expect("HOME is required"))
                    .join(".microsandbox/bin/msb")
            }
        });
    assert!(
        runtime.is_file(),
        "missing test runtime: {}",
        runtime.display()
    );
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "isolated_vm", "--ignored", "--nocapture"])
        .env(CASE_ENV, case)
        .env("MSB_PATH", runtime)
        .env("MSB_HOME", home.path())
        .env_remove("MSB_TEST_ISOLATE_HOME")
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "VM case {case} failed");
            return;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("VM case {case} timed out");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

async fn scenario(case: &str) {
    let name = format!("reap-{case}");
    let builder = Sandbox::builder(&name)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(256);
    let sandbox = if case.starts_with("attached") {
        builder.create().await.unwrap()
    } else {
        builder.create_detached().await.unwrap()
    };
    let pid = sandbox
        .local_state()
        .unwrap()
        .handle
        .as_ref()
        .unwrap()
        .lock()
        .await
        .pid();
    let observer = Sandbox::get(&name).await.unwrap();
    assert!(sandbox.shell("echo ready").await.unwrap().status().success);
    if case.starts_with("attached") {
        sandbox.detach().await.unwrap();
    }
    // Isolate this process-wide change from other tests, reproducing Node/libuv's reset.
    unsafe { libc::signal(libc::SIGCHLD, libc::SIG_DFL) };
    let retained = if case.ends_with("drop") {
        drop(sandbox);
        None
    } else {
        Some(sandbox)
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        observer
            .shell("echo still-running")
            .await
            .unwrap()
            .status()
            .success
    );
    if case.ends_with("kill") {
        observer.kill().await.unwrap();
    } else {
        observer.stop().await.unwrap();
    }
    // A successful stop/status observation alone does not prove that the parent reaped it.
    tokio::time::timeout(Duration::from_secs(5), async {
        while signal::kill(Pid::from_raw(pid as i32), None) != Err(Errno::ESRCH) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("VM child remained a zombie");
    assert_eq!(
        waitpid(Pid::from_raw(pid as i32), Some(WaitPidFlag::WNOHANG)),
        Err(Errno::ECHILD)
    );
    if let Some(sandbox) = retained {
        // Detaching does not discard completion; wait remains repeatable on the same run.
        assert_eq!(sandbox.wait().await.unwrap(), sandbox.wait().await.unwrap());
    }
    observer.destroy().await.unwrap();
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
#[ignore = "requires Linux KVM and installed runtime"]
fn isolated_vm() {
    let Ok(case) = std::env::var(CASE_ENV) else {
        return;
    };
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
        .block_on(scenario(&case));
}

#[test]
#[ignore = "requires Linux KVM and installed runtime"]
fn retained_detached_vm_stopped_by_independent_lookup() {
    run_isolated("detached-stop");
}

#[test]
#[ignore = "requires Linux KVM and installed runtime"]
fn retained_detached_vm_killed_by_independent_lookup() {
    run_isolated("detached-kill");
}

#[test]
#[ignore = "requires Linux KVM and installed runtime"]
fn dropped_detached_vm_is_reaped() {
    run_isolated("detached-drop");
}

#[test]
#[ignore = "requires Linux KVM and installed runtime"]
fn attached_then_detached_retained_vm_is_reaped() {
    run_isolated("attached-stop");
}

//! Real-VM signal dispatch through independent SDK lookups on Linux and macOS.
//! Run with `cargo test -p microsandbox --test runtime_signals -- --ignored`.

// These fixtures exercise local runtime processes and require the local SDK surface.
#![cfg(all(feature = "local", any(target_os = "linux", target_os = "macos")))]

use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use microsandbox::Sandbox;
use microsandbox::sandbox::SandboxStatus;
use nix::errno::Errno;
use nix::sys::wait::{WaitPidFlag, waitpid};
use nix::unistd::Pid;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const CASE_ENV: &str = "MSB_RUNTIME_SIGNAL_CASE";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn run_isolated(case: &str) {
    let mut builder = tempfile::Builder::new();
    builder
        .prefix("sig-")
        .permissions(std::fs::Permissions::from_mode(0o700));
    #[cfg(target_os = "macos")]
    let home = builder.tempdir_in("/tmp").unwrap();
    #[cfg(target_os = "linux")]
    let home = builder.tempdir().unwrap();
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
            panic!("VM case {case} exceeded its deadline");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

async fn scenario(case: &str) {
    let name = format!("signal-{case}");
    let builder = Sandbox::builder(&name)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(256);
    let owner = if case.starts_with("attached") {
        let owner = builder.create().await.unwrap();
        owner.detach().await.unwrap();
        owner
    } else {
        builder.create_detached().await.unwrap()
    };
    let pid = owner
        .local_state()
        .unwrap()
        .handle
        .as_ref()
        .unwrap()
        .lock()
        .await
        .pid();
    assert!(owner.shell("echo ready").await.unwrap().status().success);
    let observer = Sandbox::get(&name).await.unwrap();
    assert_eq!(observer.status().await.unwrap(), SandboxStatus::Running);
    if case.ends_with("kill") {
        observer.kill().await.unwrap();
    } else {
        observer.drain().await.unwrap();
    }
    // Exit observation in #1862 must not steal the creator's completion. When combined
    // with #1953, background collection must leave the same recorded status available.
    let status = tokio::time::timeout(Duration::from_secs(20), owner.wait())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status, owner.wait().await.unwrap());
    tokio::time::timeout(Duration::from_secs(20), observer.wait_until_stopped())
        .await
        .unwrap()
        .unwrap();
    assert_ne!(observer.status().await.unwrap(), SandboxStatus::Running);
    assert_eq!(
        waitpid(Pid::from_raw(pid as i32), Some(WaitPidFlag::WNOHANG)),
        Err(Errno::ECHILD)
    );
    observer.destroy().await.unwrap();
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
#[ignore = "requires a supported local VM runtime"]
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
#[ignore = "requires a supported local VM runtime"]
fn retained_detached_owner_killed_through_lookup() {
    run_isolated("detached-kill");
}

#[test]
#[ignore = "requires a supported local VM runtime"]
fn retained_detached_owner_drained_through_lookup() {
    run_isolated("detached-drain");
}

#[test]
#[ignore = "requires a supported local VM runtime"]
fn attached_then_detached_owner_killed_through_lookup() {
    run_isolated("attached-kill");
}

#[test]
#[ignore = "requires a supported local VM runtime"]
fn attached_then_detached_owner_drained_through_lookup() {
    run_isolated("attached-drain");
}

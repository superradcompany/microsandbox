//! Integration tests for the parent-watchdog lifecycle.
//!
//! These tests require KVM (or libkrun on macOS). The `#[msb_test]`
//! attribute marks them `#[ignore]`, so plain `cargo test --workspace`
//! skips them. Run them via:
//!
//!     cargo nextest run -p microsandbox --test parent_watchdog --run-ignored=only

use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use microsandbox::{
    Sandbox,
    sandbox::{SandboxHandle, SandboxStatus},
};
use test_utils::msb_test;
use tokio::time::sleep;

const CHILD_NAME_ENV: &str = "MSB_PARENT_WATCHDOG_CHILD_NAME";
const CHILD_READY_ENV: &str = "MSB_PARENT_WATCHDOG_CHILD_READY";
const IMAGE: &str = "mirror.gcr.io/library/alpine";
const POLL_INTERVAL: Duration = Duration::from_millis(500);

async fn cleanup(name: &str) {
    if let Ok(mut h) = Sandbox::get(name).await {
        let _ = h.kill().await;
        let _ = h.remove().await;
    }
}

async fn assert_shell_ok(sandbox: &Sandbox, command: &str, expected: &str) {
    let output = sandbox.shell(command).await.expect("shell command");
    let stdout = output.stdout().unwrap_or_default();
    let stderr = output.stderr().unwrap_or_default();

    assert!(
        output.status().success,
        "shell command failed: stdout=`{stdout}` stderr=`{stderr}`"
    );
    assert_eq!(stdout.trim(), expected);
}

async fn wait_for_status(name: &str, expected: SandboxStatus, timeout: Duration) -> SandboxHandle {
    let deadline = Instant::now() + timeout;

    loop {
        match Sandbox::get(name).await {
            Ok(handle) if handle.status() == expected => return handle,
            Ok(handle) => {
                assert!(
                    Instant::now() < deadline,
                    "sandbox `{name}` stayed {:?}; expected {expected:?}",
                    handle.status()
                );
            }
            Err(err) => {
                assert!(
                    Instant::now() < deadline,
                    "sandbox `{name}` disappeared before reaching {expected:?}: {err}"
                );
            }
        }

        sleep(POLL_INTERVAL).await;
    }
}

fn wait_for_ready_file(path: &Path, timeout: Duration, child: &mut std::process::Child) {
    let deadline = Instant::now() + timeout;

    loop {
        if path.exists() {
            return;
        }

        if let Some(status) = child.try_wait().expect("poll child process") {
            panic!("child test process exited before creating ready file: {status}");
        }

        assert!(
            Instant::now() < deadline,
            "child test process did not create ready file at {}",
            path.display()
        );

        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Detach explicitly disarms the parent watchdog by sending the runtime
/// a control byte before closing the writer. The sandbox should keep
/// running after the owning SDK handle is dropped.
#[msb_test]
async fn detach_disarms_parent_watchdog_for_attached_sandbox() {
    let name = "parent-watchdog-detach";
    cleanup(name).await;

    let sandbox = Sandbox::builder(name)
        .image(IMAGE)
        .cpus(1)
        .memory(256)
        .replace()
        .create()
        .await
        .expect("create sandbox");

    sandbox.detach().await;

    sleep(Duration::from_secs(2)).await;

    let handle = wait_for_status(name, SandboxStatus::Running, Duration::from_secs(30)).await;
    let connected = handle.connect().await.expect("connect after detach");
    assert_shell_ok(&connected, "echo detached-ok", "detached-ok").await;

    let _ = connected.stop_and_wait().await;
    cleanup(name).await;
}

/// Child entrypoint used by `parent_exit_stops_but_preserves_named_sandbox`.
/// The parent kills this test process after the ready file appears so the
/// runtime observes real parent-watchdog EOF, not an SDK-level shutdown.
#[msb_test]
async fn parent_watchdog_child_process() {
    let Some(name) = std::env::var_os(CHILD_NAME_ENV) else {
        return;
    };
    let Some(ready_path) = std::env::var_os(CHILD_READY_ENV) else {
        return;
    };

    let name = name.to_string_lossy().into_owned();
    let ready_path = PathBuf::from(ready_path);

    cleanup(&name).await;

    let sandbox = Sandbox::builder(&name)
        .image(IMAGE)
        .cpus(1)
        .memory(256)
        .replace()
        .create()
        .await
        .expect("create child-owned sandbox");

    assert_shell_ok(&sandbox, "echo child-ready", "child-ready").await;
    std::fs::write(&ready_path, b"ready").expect("write ready file");

    std::future::pending::<()>().await;
}

/// When an attached SDK creator dies, the runtime should stop the VM but
/// preserve the named sandbox record and filesystem so it can be started
/// again later.
#[msb_test]
async fn parent_exit_stops_but_preserves_named_sandbox() {
    let name = "parent-watchdog-parent-exit";
    cleanup(name).await;

    let tempdir = tempfile::tempdir().expect("create tempdir");
    let ready_path = tempdir.path().join("ready");

    let mut child = Command::new(std::env::current_exe().expect("current test binary"))
        .arg("--ignored")
        .arg("--exact")
        .arg("parent_watchdog_child_process")
        .arg("--nocapture")
        .env(CHILD_NAME_ENV, name)
        .env(CHILD_READY_ENV, &ready_path)
        // This helper process must observe the same sandbox database as the
        // parent test. CI sets MSB_TEST_ISOLATE_HOME=1, and the #[msb_test]
        // wrapper would otherwise create a fresh MSB_HOME in the child.
        .env_remove(test_utils::ISOLATE_HOME_ENV)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn child test process");

    wait_for_ready_file(&ready_path, Duration::from_secs(180), &mut child);

    child.kill().expect("kill child test process");
    let _ = child.wait().expect("wait child test process");

    let handle = wait_for_status(name, SandboxStatus::Stopped, Duration::from_secs(90)).await;
    let restarted = handle.start().await.expect("restart stopped sandbox");
    assert_shell_ok(&restarted, "echo restarted-ok", "restarted-ok").await;

    let _ = restarted.stop_and_wait().await;
    cleanup(name).await;
}

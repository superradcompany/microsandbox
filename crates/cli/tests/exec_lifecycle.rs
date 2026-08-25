//! Lifecycle regression tests for `msb exec` against stopped and running sandboxes.

use std::process::{Output, Stdio};
use std::time::Duration;

use microsandbox::{Sandbox, sandbox::SandboxStatus};
use test_utils::msb_test;
use tokio::process::Command;
use tokio::time::timeout;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const IMAGE: &str = "mirror.gcr.io/library/alpine";

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Run the freshly built CLI with closed stdin and a hard timeout.
async fn msb(args: &[&str]) -> Output {
    timeout(
        Duration::from_secs(90),
        Command::new(env!("CARGO_BIN_EXE_msb"))
            .args(args)
            .stdin(Stdio::null())
            .output(),
    )
    .await
    .unwrap_or_else(|_| panic!("msb {args:?} timed out after 90s"))
    .unwrap_or_else(|error| panic!("msb {args:?} failed to spawn: {error}"))
}

/// Remove any sandbox left by an earlier interrupted test run.
async fn cleanup(name: &str) {
    if let Ok(handle) = Sandbox::get(name).await {
        let _ = handle.kill().await;
        let _ = handle.remove().await;
    }
}

/// Create a named sandbox, stop it cleanly, and release its process handle.
async fn create_stopped(name: &str) {
    let sandbox = Sandbox::builder(name)
        .image(IMAGE)
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await
        .expect("create sandbox");
    sandbox.stop().await.expect("stop sandbox");
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

/// Invalid CLI-only options must fail before `exec` temporarily starts a stopped sandbox.
#[msb_test]
async fn invalid_options_do_not_start_stopped_sandbox() {
    let name = "cli-exec-invalid-options-lifecycle";
    cleanup(name).await;
    create_stopped(name).await;

    let output = msb(&[
        "exec",
        "--quiet",
        "--rlimit",
        "definitely-invalid",
        name,
        "--",
        "true",
    ])
    .await;
    let status = Sandbox::get(name)
        .await
        .expect("get sandbox after invalid exec options")
        .status_snapshot();
    cleanup(name).await;

    assert!(!output.status.success(), "invalid rlimit must fail");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("rlimit must be in format"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        status,
        SandboxStatus::Stopped,
        "invalid options must not start a stopped sandbox"
    );
}

/// Errors after startup must stop an owned sandbox, without stopping one that was already running.
#[msb_test]
async fn exec_errors_restore_the_previous_lifecycle() {
    let name = "cli-exec-error-lifecycle";
    cleanup(name).await;

    let sandbox = Sandbox::builder(name)
        .image(IMAGE)
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await
        .expect("create running sandbox");

    let running_output = msb(&[
        "exec",
        "--quiet",
        "--user",
        "definitely-missing-user",
        name,
        "--",
        "true",
    ])
    .await;
    let running_status = Sandbox::get(name)
        .await
        .expect("get running sandbox after failed exec")
        .status_snapshot();

    sandbox.stop().await.expect("stop sandbox between cases");
    drop(sandbox);

    let stopped_output = msb(&[
        "exec",
        "--quiet",
        "--user",
        "definitely-missing-user",
        name,
        "--",
        "true",
    ])
    .await;
    let stopped_status = Sandbox::get(name)
        .await
        .expect("get stopped sandbox after failed exec")
        .status_snapshot();
    cleanup(name).await;

    assert!(
        !running_output.status.success(),
        "invalid guest user must fail"
    );
    assert!(
        !stopped_output.status.success(),
        "invalid guest user must fail"
    );
    assert_eq!(
        running_status,
        SandboxStatus::Running,
        "exec must not stop a sandbox that was already running"
    );
    assert_eq!(
        stopped_status,
        SandboxStatus::Stopped,
        "exec must stop a sandbox that it temporarily started"
    );
}

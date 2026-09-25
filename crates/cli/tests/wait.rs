//! Exercise `msb wait` against a real sandbox, using the freshly built CLI.
//! Run with the same isolated-home and signed-runtime setup as `exec_lifecycle`.

use std::process::{Output, Stdio};
use std::time::Duration;

use microsandbox::{Sandbox, sandbox::SandboxStatus};
use test_utils::msb_test;
use tokio::process::Command;
use tokio::time::timeout;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn msb(args: &[&str]) -> Output {
    timeout(
        Duration::from_secs(30),
        Command::new(env!("CARGO_BIN_EXE_msb"))
            .args(args)
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap_or_else(|_| panic!("msb {args:?} timed out"))
    .expect("spawn CLI")
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[msb_test]
async fn wait_observes_shutdown_and_timeout_leaves_sandbox_running() {
    let name = "cli-wait-lifecycle";
    let sandbox = Sandbox::builder(name)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await
        .expect("create running sandbox");

    let output = msb(&["wait", name, "-t", "100ms"]).await;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("timed out waiting"));
    assert_eq!(
        Sandbox::get(name).await.unwrap().status_snapshot(),
        SandboxStatus::Running,
    );

    let waiting = msb(&[
        "wait",
        "cli-wait-lifecycle",
        "--timeout",
        "10s",
        "--format",
        "json",
    ]);
    tokio::pin!(waiting);
    assert!(
        timeout(Duration::from_millis(250), &mut waiting)
            .await
            .is_err()
    );
    sandbox.stop().await.expect("stop sandbox");

    let output = waiting.await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["name"], name);
    assert_eq!(result["status"], "Stopped");
    assert_eq!(result["terminal"], true);
    assert!(result["exit_code"].is_null());
    assert!(result["signal"].is_null());

    // Already-stopped sandboxes return immediately, without requiring a timeout.
    let output = msb(&["wait", name]).await;
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        format!("{name} Stopped")
    );

    Sandbox::get(name).await.unwrap().remove().await.unwrap();
    let output = msb(&["wait", name]).await;
    assert!(
        !output.status.success(),
        "removed sandbox must not be treated as stopped"
    );
}

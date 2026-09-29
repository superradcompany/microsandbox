//! Failure-mode tests for `msb exec --stream`: that `--timeout` is enforced in
//! the streaming path, and that a broken host stdout pipe makes msb exit
//! promptly instead of hanging. Both deadlock or hang if the behavior
//! regresses, so completing within the timeout is the proof.

use std::process::Stdio;
use std::time::{Duration, Instant};

use microsandbox::Sandbox;
use test_utils::msb_test;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::time::timeout;

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

/// Invariant #1: `--timeout` is enforced in stream mode. Before the fix the
/// streaming path dropped the timeout, so this would run for the full 30s.
#[msb_test]
async fn exec_stream_timeout_kills_guest() {
    let name = "cli-exec-stream-timeout";
    let sandbox = Sandbox::builder(name)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await
        .expect("create sandbox");

    let start = Instant::now();
    let mut child = Command::new(env!("CARGO_BIN_EXE_msb"))
        .args([
            "exec",
            "--stream",
            "--quiet",
            "--timeout",
            "2",
            name,
            "--",
            "sleep",
            "30",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn msb exec --stream --timeout");

    // Keep the writer alive while waiting: EOF must not be needed to exit.
    let stdin = child.stdin.take().expect("child stdin");

    let status = timeout(Duration::from_secs(20), child.wait())
        .await
        .expect("msb exec --stream --timeout never exited (timeout not enforced)")
        .expect("wait for msb");
    let elapsed = start.elapsed();
    drop(stdin);

    sandbox.stop().await.ok();
    Sandbox::remove(name).await.ok();

    assert!(
        elapsed < Duration::from_secs(15),
        "expected timeout ~2s, but exec ran for {elapsed:?} (timeout not enforced)"
    );
    assert!(
        !status.success(),
        "a timed-out exec must exit non-zero, got {status:?}"
    );
}

/// Invariant #2: when the host stops reading stdout (broken pipe), msb stops
/// streaming and exits promptly instead of hanging forever.
#[msb_test]
async fn exec_stream_broken_pipe_exits() {
    let name = "cli-exec-stream-brokenpipe";
    let sandbox = Sandbox::builder(name)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await
        .expect("create sandbox");

    let mut child = Command::new(env!("CARGO_BIN_EXE_msb"))
        .args([
            "exec",
            "--stream",
            "--quiet",
            name,
            "--",
            "sh",
            "-c",
            "while true; do echo spam; done",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn msb exec --stream");

    let stdin = child.stdin.take().expect("child stdin");

    // Read a little, then drop the read end so the next guest write breaks.
    let mut lines = BufReader::new(child.stdout.take().expect("child stdout")).lines();
    let _ = timeout(Duration::from_secs(20), lines.next_line()).await;
    drop(lines);

    let status = timeout(Duration::from_secs(20), child.wait())
        .await
        .expect("msb did not exit after host closed stdout (broken pipe hung)")
        .expect("wait for msb");
    drop(stdin);

    sandbox.stop().await.ok();
    Sandbox::remove(name).await.ok();

    // Exit code is intentionally 0 on broken pipe (SIGPIPE-like); the invariant
    // under test is that it EXITS rather than blocking forever.
    let _ = status;
}

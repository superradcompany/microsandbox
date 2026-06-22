//! Integration test for `msb exec --stream`.
//!
//! Drives a long-lived guest turn by turn over a non-PTY stream: send a line,
//! read the reply, then send the next. The buffered `exec` path reads stdin to
//! EOF before producing any output, so it would deadlock here — completing
//! within the timeout is itself the proof that `--stream` streams both ways.

use std::process::Stdio;
use std::time::Duration;

use microsandbox::Sandbox;
use test_utils::msb_test;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::time::timeout;

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[msb_test]
async fn exec_stream_drives_guest_turn_by_turn() {
    let name = "cli-exec-stream-turns";
    let sandbox = Sandbox::builder(name)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await
        .expect("create sandbox");

    // busybox awk echoes each line back; fflush() keeps the reply from sitting
    // in the guest's stdio buffer until exit.
    let mut child = Command::new(env!("CARGO_BIN_EXE_msb"))
        .args([
            "exec",
            "--stream",
            "--quiet",
            name,
            "--",
            "awk",
            "{ print \"ack:\" $0; fflush() }",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn msb exec --stream");

    let mut stdin = child.stdin.take().expect("child stdin");
    let mut lines = BufReader::new(child.stdout.take().expect("child stdout")).lines();

    let driver = timeout(Duration::from_secs(60), async move {
        for i in 1..=3 {
            stdin
                .write_all(format!("turn{i}\n").as_bytes())
                .await
                .expect("write turn");
            stdin.flush().await.expect("flush turn");
            // Reading the reply *before* sending the next turn is the crux: it
            // can only arrive mid-process if output is streamed, not buffered
            // until the process exits.
            let reply = lines
                .next_line()
                .await
                .expect("read reply")
                .expect("guest closed stdout early");
            assert_eq!(reply, format!("ack:turn{i}"));
        }
        // EOF ends awk's input loop, so the process exits 0.
        drop(stdin);
        while lines.next_line().await.expect("drain stdout").is_some() {}
    })
    .await;

    if driver.is_err() {
        let _ = child.start_kill();
    }
    let status = child.wait().await.expect("wait for msb exec");

    // Clean up before asserting so a failure can't leak the sandbox.
    sandbox.stop().await.expect("stop sandbox");
    Sandbox::remove(name).await.expect("remove sandbox");

    driver.expect("`exec --stream` did not stream turn by turn (deadlocked)");
    assert!(
        status.success(),
        "msb exec --stream exited non-zero: {status:?}"
    );
}

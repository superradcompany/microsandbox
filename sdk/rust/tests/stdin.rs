//! Integration tests for stdin delivery.
//!
//! These tests require KVM (or libkrun on macOS). The `#[msb_test]`
//! attribute marks them `#[ignore]`, so plain `cargo test --workspace`
//! skips them. Run them via:
//!
//!     cargo nextest run -p microsandbox --test stdin --run-ignored=only --test-threads 1

use microsandbox::{ExecEvent, Sandbox};
use sha2::{Digest, Sha256};
use test_utils::msb_test;

const ONE_MIB: usize = 1024 * 1024;

async fn stop_and_remove(name: &str) {
    let handle = Sandbox::get(name).await.expect("get");
    handle.stop().await.expect("stop");
    Sandbox::remove(name).await.expect("remove");
}

/// Realistic large-payload test: reader (`cat`) starts immediately and
/// drains in parallel with the host write. Whether the guest pipe ever
/// fills (and trips EAGAIN) depends on scheduling, but the payload is
/// large enough that on most hosts it does at least once.
#[msb_test]
async fn stdin_bytes_writes_payload_larger_than_pipe_capacity() {
    let name = "stdin-bytes-1mib";
    let payload = vec![b'x'; ONE_MIB];
    let expected_sha = hex::encode(Sha256::digest(&payload));

    let sandbox = Sandbox::builder(name)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await
        .expect("create sandbox");

    let output = sandbox
        .exec_with("sh", |exec| {
            exec.args([
                "-c",
                "cat > /tmp/stdin-1mb.bin && wc -c /tmp/stdin-1mb.bin && sha256sum /tmp/stdin-1mb.bin",
            ])
            .stdin_bytes(payload)
        })
        .await
        .expect("write stdin payload");

    stop_and_remove(name).await;

    assert!(
        output.status().success,
        "guest command failed: stdout=`{}` stderr=`{}`",
        output.stdout().unwrap_or_default(),
        output.stderr().unwrap_or_default()
    );

    let (byte_count, actual_sha) = parse_wc_and_sha(&output.stdout().expect("stdout is utf8"));
    assert_eq!(byte_count, ONE_MIB.to_string());
    assert_eq!(actual_sha, expected_sha);
}

/// Deterministic EAGAIN test: the guest reader sleeps for a second before
/// starting to drain stdin. The host write therefore fills the kernel pipe
/// buffer and *must* hit EAGAIN, exercising the poll-and-retry path in
/// `blocking_write_fd` rather than relying on scheduling.
#[msb_test]
async fn stdin_bytes_waits_for_slow_reader() {
    let name = "stdin-bytes-slow-reader";
    let payload = vec![b'y'; ONE_MIB];
    let expected_sha = hex::encode(Sha256::digest(&payload));

    let sandbox = Sandbox::builder(name)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await
        .expect("create sandbox");

    let output = sandbox
        .exec_with("sh", |exec| {
            exec.args([
                "-c",
                "sleep 1; cat > /tmp/stdin-slow.bin && wc -c /tmp/stdin-slow.bin && sha256sum /tmp/stdin-slow.bin",
            ])
            .stdin_bytes(payload)
        })
        .await
        .expect("write stdin payload");

    stop_and_remove(name).await;

    assert!(
        output.status().success,
        "guest command failed: stdout=`{}` stderr=`{}`",
        output.stdout().unwrap_or_default(),
        output.stderr().unwrap_or_default()
    );

    let (byte_count, actual_sha) = parse_wc_and_sha(&output.stdout().expect("stdout is utf8"));
    assert_eq!(byte_count, ONE_MIB.to_string());
    assert_eq!(actual_sha, expected_sha);
}

/// Regression test for null stdin: `cat` should receive EOF immediately and
/// exit instead of waiting forever for more input.
#[msb_test]
async fn stdin_null_lets_cat_finish() {
    let name = "stdin-null-cat";

    let sandbox = Sandbox::builder(name)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await
        .expect("create sandbox");

    let output = sandbox
        .exec_with("cat", |exec| exec.stdin_null())
        .await
        .expect("run cat with null stdin");

    stop_and_remove(name).await;

    assert!(
        output.status().success,
        "cat failed: stdout=`{}` stderr=`{}`",
        output.stdout().unwrap_or_default(),
        output.stderr().unwrap_or_default()
    );
    assert_eq!(output.stdout().unwrap_or_default(), "");
    assert_eq!(output.stderr().unwrap_or_default(), "");
}

/// Streaming test: multiple sequential `ExecSink::write` calls, each
/// exceeding typical pipe capacity. Verifies that repeated invocations
/// of `write_stdin` (rather than a single bytes payload) all reach the
/// guest in order and the closing `ExecSink::close` propagates EOF.
#[msb_test]
async fn stdin_pipe_streams_chunks_in_order() {
    let name = "stdin-pipe-stream";
    let chunk_size = 256 * 1024;
    let chunk_count = 4;

    let mut payload = Vec::with_capacity(chunk_size * chunk_count);
    let mut chunks: Vec<Vec<u8>> = Vec::with_capacity(chunk_count);
    for i in 0..chunk_count {
        let byte = b'a' + i as u8;
        let chunk = vec![byte; chunk_size];
        payload.extend_from_slice(&chunk);
        chunks.push(chunk);
    }
    let expected_sha = hex::encode(Sha256::digest(&payload));
    let total_bytes = payload.len();

    let sandbox = Sandbox::builder(name)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await
        .expect("create sandbox");

    let mut handle = sandbox
        .exec_stream_with("sh", |exec| {
            exec.args([
                "-c",
                "cat > /tmp/stdin-stream.bin && wc -c /tmp/stdin-stream.bin && sha256sum /tmp/stdin-stream.bin",
            ])
            .stdin_pipe()
        })
        .await
        .expect("start exec");

    let stdin = handle.take_stdin().expect("stdin pipe");
    for chunk in &chunks {
        stdin.write(chunk).await.expect("write chunk");
    }
    stdin.close().await.expect("close stdin");

    let mut stdout = Vec::new();
    let mut exit_code: Option<i32> = None;
    while let Some(event) = handle.recv().await {
        match event {
            ExecEvent::Stdout(data) => stdout.extend_from_slice(&data),
            ExecEvent::Exited { code } => {
                exit_code = Some(code);
                break;
            }
            ExecEvent::Failed(payload) => {
                panic!("exec failed: {payload:?}");
            }
            _ => {}
        }
    }

    stop_and_remove(name).await;

    assert_eq!(exit_code, Some(0), "guest command exited non-zero");
    let stdout_text = String::from_utf8(stdout).expect("stdout is utf8");
    let (byte_count, actual_sha) = parse_wc_and_sha(&stdout_text);
    assert_eq!(byte_count, total_bytes.to_string());
    assert_eq!(actual_sha, expected_sha);
}

/// Broken-pipe test: the child reads only a short prefix of stdin and
/// exits, closing its read end before the host's full payload has been
/// delivered. The agent's stdin write fails with EPIPE and surfaces
/// mid-stream as `ExecEvent::StdinError`, while the session itself
/// still produces a normal `Exited { code: 0 }` event — the stdin
/// failure is non-terminal.
#[msb_test]
async fn stdin_bytes_reports_broken_pipe_when_child_exits_early() {
    let name = "stdin-broken-pipe";
    let payload = vec![b'z'; ONE_MIB];

    let sandbox = Sandbox::builder(name)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await
        .expect("create sandbox");

    let mut handle = sandbox
        .exec_stream_with("sh", |exec| {
            exec.args([
                "-c",
                "dd bs=1 count=16 of=/tmp/prefix.bin 2>/dev/null && wc -c /tmp/prefix.bin",
            ])
            .stdin_bytes(payload)
        })
        .await
        .expect("start exec");

    let mut stdout = Vec::new();
    let mut exit_code: Option<i32> = None;
    let mut stdin_error = None;
    while let Some(event) = handle.recv().await {
        match event {
            ExecEvent::Stdout(data) => stdout.extend_from_slice(&data),
            ExecEvent::StdinError(payload) => {
                if stdin_error.is_none() {
                    stdin_error = Some(payload);
                }
            }
            ExecEvent::Exited { code } => {
                exit_code = Some(code);
                break;
            }
            ExecEvent::Failed(payload) => {
                panic!("exec failed: {payload:?}");
            }
            _ => {}
        }
    }

    stop_and_remove(name).await;

    assert_eq!(exit_code, Some(0), "guest command exited non-zero");

    let stdout_text = String::from_utf8(stdout).expect("stdout is utf8");
    let prefix_count = stdout_text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().next())
        .expect("byte count line");
    assert_eq!(
        prefix_count, "16",
        "child should have read exactly 16 bytes"
    );

    let stdin_err = stdin_error.expect("host should observe a StdinError event");
    assert_eq!(
        stdin_err.errno,
        Some(libc::EPIPE),
        "expected EPIPE on broken pipe, got errno={:?} message={}",
        stdin_err.errno,
        stdin_err.message,
    );
}

fn parse_wc_and_sha(stdout: &str) -> (String, String) {
    let mut lines = stdout.lines();
    let byte_count = lines
        .next()
        .and_then(|line| line.split_whitespace().next())
        .expect("byte count line")
        .to_string();
    let sha = lines
        .next()
        .and_then(|line| line.split_whitespace().next())
        .expect("sha256 line")
        .to_string();
    (byte_count, sha)
}

/// Null and finite input must close only pipe stdin; cancelling a waiter must not close
/// retained input or a PTY. Run in one VM so each mode exercises the same guest agent.
#[msb_test]
async fn stdin_null_finite_retained_and_pty_lifetimes() {
    use std::time::Duration;
    use tokio::time::timeout;

    let name = "stdin-mode-lifetimes";
    let sandbox = Sandbox::builder(name)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await
        .expect("create sandbox");

    let default = timeout(Duration::from_secs(5), sandbox.exec("cat", ["-"]))
        .await
        .expect("default null must reach EOF")
        .unwrap();
    assert!(default.status().success && default.stdout_bytes().is_empty());
    let explicit = timeout(
        Duration::from_secs(5),
        sandbox.exec_with("cat", |e| e.stdin_null()),
    )
    .await
    .expect("explicit null must reach EOF")
    .unwrap();
    assert!(explicit.status().success && explicit.stdout_bytes().is_empty());
    for bytes in [Vec::new(), vec![0, 255, 10]] {
        let output = timeout(
            Duration::from_secs(5),
            sandbox.exec_with("cat", |e| e.stdin_bytes(bytes.clone())),
        )
        .await
        .expect("finite input must reach EOF")
        .unwrap();
        assert!(output.status().success);
        assert_eq!(output.stdout_bytes().as_ref(), bytes);
    }

    let mut retained = sandbox
        .exec_stream_with("cat", |e| e.stdin_pipe())
        .await
        .unwrap();
    assert!(
        timeout(Duration::from_millis(100), retained.wait())
            .await
            .is_err()
    );
    let input = retained.take_stdin().expect("retained pipe");
    input.write(b"after cancelled wait\n").await.unwrap();
    input.close().await.unwrap();
    let output = timeout(Duration::from_secs(5), retained.collect())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(output.stdout_bytes().as_ref(), b"after cancelled wait\n");

    let mut delayed = sandbox
        .exec_stream_with("sh", |e| e.args(["-c", "sleep 0.3; cat"]).stdin_null())
        .await
        .unwrap();
    assert!(
        timeout(Duration::from_millis(20), delayed.wait())
            .await
            .is_err()
    );
    assert!(
        timeout(Duration::from_secs(5), delayed.wait())
            .await
            .unwrap()
            .unwrap()
            .success
    );

    let mut pty = sandbox
        .exec_stream_with("sh", |e| {
            e.args(["-c", "test -t 0 && echo ready; cat"])
                .tty(true)
                .stdin_null()
        })
        .await
        .unwrap();
    timeout(Duration::from_secs(5), async {
        loop {
            let event = pty.recv().await.expect("PTY closed before readiness");
            if let ExecEvent::Stdout(bytes) = event
                && String::from_utf8_lossy(&bytes).contains("ready")
            {
                break;
            }
        }
    })
    .await
    .expect("PTY must become ready");
    assert!(
        timeout(Duration::from_millis(100), pty.wait())
            .await
            .is_err()
    );
    pty.kill().await.unwrap();
    assert!(
        !timeout(Duration::from_secs(5), pty.wait())
            .await
            .unwrap()
            .unwrap()
            .success
    );
    stop_and_remove(name).await;
}

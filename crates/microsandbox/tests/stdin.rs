//! Integration tests for stdin delivery.
//!
//! These tests require KVM (or libkrun on macOS). The `#[msb_test]`
//! attribute marks them `#[ignore]`, so plain `cargo test --workspace`
//! skips them. Run them via:
//!
//!     cargo nextest run -p microsandbox --test stdin --run-ignored=only

use microsandbox::{ExecEvent, Sandbox};
use sha2::{Digest, Sha256};
use test_utils::msb_test;

const ONE_MIB: usize = 1024 * 1024;

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

    sandbox.stop_and_wait().await.expect("stop");
    Sandbox::remove(name).await.expect("remove");

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

    sandbox.stop_and_wait().await.expect("stop");
    Sandbox::remove(name).await.expect("remove");

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

    sandbox.stop_and_wait().await.expect("stop");
    Sandbox::remove(name).await.expect("remove");

    assert_eq!(exit_code, Some(0), "guest command exited non-zero");
    let stdout_text = String::from_utf8(stdout).expect("stdout is utf8");
    let (byte_count, actual_sha) = parse_wc_and_sha(&stdout_text);
    assert_eq!(byte_count, total_bytes.to_string());
    assert_eq!(actual_sha, expected_sha);
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

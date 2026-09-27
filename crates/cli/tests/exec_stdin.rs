//! Piped CLI input must not delay guest startup, exit, or timeout until host EOF.

use std::process::Stdio;
use std::time::Duration;

use microsandbox::Sandbox;
use test_utils::msb_test;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::time::timeout;

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[msb_test]
async fn exec_exits_before_host_stdin_closes() {
    let name = "cli-exec-open-stdin";
    let sandbox = Sandbox::builder(name)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await
        .expect("create sandbox");

    let mut results = Vec::new();
    for flags in [&[][..], &["--no-tty"][..], &["--stream"][..]] {
        for code in [0, 7] {
            let code_arg = code.to_string();
            let mut child = Command::new(env!("CARGO_BIN_EXE_msb"))
            .args(["exec", "--quiet", name])
            .args(flags)
            .args([
                "--", "sh", "-c",
                "read -r line; printf 'out:%s\\n' \"$line\"; printf 'err:%s\\n' \"$line\" >&2; exit \"$1\"",
                "sh", &code_arg,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn exec");
            let mut stdin = child.stdin.take().expect("child stdin");
            stdin.write_all(b"hello\n").await.expect("write input");
            // wait_with_output normally closes child.stdin; taking it above ensures
            // this test really keeps host stdin open until after the exit deadline.
            let output = timeout(Duration::from_secs(10), child.wait_with_output()).await;
            drop(stdin);
            results.push((flags, code, output));
        }
    }

    sandbox.stop().await.expect("stop sandbox");
    Sandbox::remove(name).await.expect("remove sandbox");
    for (flags, code, output) in results {
        let output = output
            .unwrap_or_else(|_| panic!("exec {flags:?} waited for host stdin EOF"))
            .expect("wait for exec");
        assert_eq!(output.status.code(), Some(code), "flags: {flags:?}");
        assert_eq!(output.stdout, b"out:hello\n", "flags: {flags:?}");
        assert_eq!(output.stderr, b"err:hello\n", "flags: {flags:?}");
    }
}

#[msb_test]
async fn captured_exec_timeout_does_not_wait_for_host_stdin() {
    let name = "cli-exec-captured-timeout";
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
            "--no-tty",
            "--quiet",
            "--timeout",
            "2s",
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
        .expect("spawn exec");
    let stdin = child.stdin.take().expect("child stdin");
    let output = timeout(Duration::from_secs(10), child.wait_with_output()).await;
    drop(stdin);
    sandbox.stop().await.expect("stop sandbox");
    Sandbox::remove(name).await.expect("remove sandbox");

    let output = output
        .expect("exec timeout waited for host stdin EOF")
        .expect("wait for exec");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("timed out"));
}

#[msb_test]
async fn exec_forwards_input_and_handles_closed_guest_stdin() {
    let name = "cli-exec-stdin-bytes";
    let sandbox = Sandbox::builder(name)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await
        .expect("create sandbox");
    // More than one forwarding chunk, including NUL and invalid UTF-8.
    let input: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();
    let mut results = Vec::new();
    for flags in [&[][..], &["--no-tty"][..], &["--stream"][..]] {
        for (command, expected) in [
            ("cat", input.as_slice()),
            ("exec 0<&-; sleep 0.2; printf done", b"done".as_slice()),
        ] {
            // Streaming mode intentionally surfaces guest stdin errors.
            if flags == ["--stream"] && command != "cat" {
                continue;
            }
            let mut child = Command::new(env!("CARGO_BIN_EXE_msb"))
                .args(["exec", "--quiet", name])
                .args(flags)
                .args(["--", "sh", "-c", command])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .expect("spawn exec");
            let mut stdin = child.stdin.take().expect("child stdin");
            let output = timeout(Duration::from_secs(15), async {
                let writer = async {
                    let result = stdin.write_all(&input).await;
                    drop(stdin);
                    result
                };
                tokio::join!(writer, child.wait_with_output())
            })
            .await;
            results.push((flags, command, expected, output));
        }
    }
    sandbox.stop().await.expect("stop sandbox");
    Sandbox::remove(name).await.expect("remove sandbox");
    for (flags, command, expected, output) in results {
        let (write_result, output) = output.expect("exec failed to finish after EOF");
        // A command that intentionally closes stdin may exit before the host
        // finishes writing. A full-input consumer must receive every byte.
        if command == "cat" {
            write_result.expect("write input");
        }
        let output = output.expect("wait for exec");
        assert!(
            output.status.success(),
            "flags: {flags:?}, stderr: {:?}",
            output.stderr
        );
        assert_eq!(output.stdout, expected, "flags: {flags:?}");
        assert!(output.stderr.is_empty(), "flags: {flags:?}");
    }
}

#[cfg(unix)]
#[msb_test]
async fn exec_accepts_delayed_nonblocking_stdin() {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;

    use tokio::io::{AsyncBufReadExt, BufReader};

    let name = "cli-exec-nonblocking-stdin";
    let sandbox = Sandbox::builder(name)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await
        .expect("create sandbox");
    let (reader, writer) = UnixStream::pair().expect("stdin socket pair");
    reader.set_nonblocking(true).expect("nonblocking reader");
    writer.set_nonblocking(true).expect("nonblocking writer");
    let mut writer = tokio::net::UnixStream::from_std(writer).expect("async writer");
    let mut child = Command::new(env!("CARGO_BIN_EXE_msb"))
        .args([
            "exec",
            "--stream",
            "--quiet",
            name,
            "--",
            "sh",
            "-c",
            "printf 'ready\\n'; read -r line; printf 'ack:%s\\n' \"$line\"; exit 7",
        ])
        .stdin(Stdio::from(OwnedFd::from(reader)))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn exec");
    let mut lines = BufReader::new(child.stdout.take().expect("stdout")).lines();
    let result = timeout(Duration::from_secs(10), async {
        let ready = lines.next_line().await.expect("read ready");
        // Leave input empty after the guest starts, exercising WouldBlock.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let write_result = writer.write_all(b"hello\n").await;
        let ack = lines.next_line().await.expect("read ack");
        let output = child.wait_with_output().await.expect("wait for exec");
        (ready, write_result, ack, output)
    })
    .await;
    drop(writer);
    sandbox.stop().await.expect("stop sandbox");
    Sandbox::remove(name).await.expect("remove sandbox");

    let (ready, write_result, ack, output) = result.expect("nonblocking exec hung");
    assert_eq!(ready.as_deref(), Some("ready"));
    write_result.expect("send delayed input");
    assert_eq!(ack.as_deref(), Some("ack:hello"));
    assert_eq!(output.status.code(), Some(7));
    assert!(output.stderr.is_empty(), "{:?}", output.stderr);
}

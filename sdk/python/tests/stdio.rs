//! Exercise the same transport used by Python SSH without needing a running VM.

#[path = "../src/stdio.rs"]
mod stdio;

use std::io::{Seek, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn cancellation_joins_readers_and_writers_with_open_pipes() {
    for mode in [
        "read",
        "write",
        "runtime-drop",
        "cancel-retained-stream",
        "cancel-retained-writer",
    ] {
        let mut child = child(mode).spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "{mode} did not exit with pipes open: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            thread::sleep(Duration::from_millis(10));
        }
        // Keep stdin open and stdout undrained until exit. communicate-style
        // helpers would close stdin and accidentally hide a stuck read.
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{mode}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("stdio workers stopped"));
    }
}

#[test]
fn binary_stdio_round_trip_and_flag_restoration() {
    let payload: Vec<u8> = (0..262_144).map(|index| (index % 256) as u8).collect();
    let mut child = child("copy").spawn().unwrap();
    let mut input = child.stdin.take().unwrap();
    let bytes = payload.clone();
    let writer = thread::spawn(move || input.write_all(&bytes).unwrap());
    let output = child.wait_with_output().unwrap();
    writer.join().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.ends_with(&payload),
        "binary stream was truncated or changed"
    );
}

#[test]
fn redirected_files_and_null_stdin_remain_supported() {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(b"redirected file input").unwrap();
    file.rewind().unwrap();
    let output = child("copy").stdin(file).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.ends_with(b"redirected file input"));
    let output = child("copy").stdin(Stdio::null()).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn subprocess_stdio() {
    let Ok(mode) = std::env::var("MSB_PYTHON_STDIO_TEST") else {
        return;
    };
    #[cfg(unix)]
    let original_flags = [0, 1].map(|fd| unsafe { libc::fcntl(fd, libc::F_GETFL) });
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut stream = stdio::StdioStream::new().unwrap();
        match mode.as_str() {
            "cancel-retained-stream" | "cancel-retained-writer" => {
                let guard = stream.cancel_on_drop();
                let writing = mode == "cancel-retained-writer";
                let task = tokio::spawn(async move {
                    let error = if writing {
                        stream
                            .write_all(&vec![0; 16 * 1024 * 1024])
                            .await
                            .unwrap_err()
                    } else {
                        let mut byte = [0];
                        stream.read_exact(&mut byte).await.unwrap_err()
                    };
                    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
                });
                // The transport remains owned by another task, as it does in
                // russh. Dropping the caller's guard must wake that task.
                tokio::time::sleep(Duration::from_millis(50)).await;
                drop(guard);
                tokio::time::timeout(Duration::from_secs(2), task)
                    .await
                    .unwrap()
                    .unwrap();
                let _reopened = stdio::StdioStream::new().unwrap();
            }
            "read" => {
                let mut byte = [0];
                assert!(
                    tokio::time::timeout(Duration::from_millis(100), stream.read_exact(&mut byte))
                        .await
                        .is_err()
                );
            }
            "write" => {
                let bytes = vec![0; 16 * 1024 * 1024];
                assert!(
                    tokio::time::timeout(Duration::from_millis(100), stream.write_all(&bytes))
                        .await
                        .is_err()
                );
            }
            "copy" => {
                let (mut reader, mut writer) = tokio::io::split(stream);
                tokio::io::copy(&mut reader, &mut writer).await.unwrap();
                writer.shutdown().await.unwrap();
            }
            "runtime-drop" => {
                let (started, waiting) = tokio::sync::oneshot::channel();
                tokio::spawn(async move {
                    let mut byte = [0];
                    // Poll the read before signaling, ensuring native I/O has
                    // started instead of merely testing an unpolled future.
                    let read = stream.read_exact(&mut byte);
                    tokio::pin!(read);
                    assert!(futures::poll!(&mut read).is_pending());
                    started.send(()).unwrap();
                    let _ = read.await;
                });
                waiting.await.unwrap();
            }
            _ => panic!("unknown child mode"),
        }
    });
    drop(runtime);
    #[cfg(unix)]
    for (fd, original) in [0, 1].into_iter().zip(original_flags) {
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_GETFL) },
            original,
            "stdio flags changed"
        );
    }
    eprintln!("stdio workers stopped");
    // The write test deliberately fills stdout. Bypass libtest's final stdout
    // report only in this isolated child, after runtime/stdio cleanup is proven.
    std::process::exit(0);
}

fn child(mode: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "subprocess_stdio",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("MSB_PYTHON_STDIO_TEST", mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

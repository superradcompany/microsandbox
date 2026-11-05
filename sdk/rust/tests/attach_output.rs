//! A real host terminal must let an attached SDK command finish after printing output.

#![cfg(unix)]

use std::{
    fs::File,
    io::{ErrorKind, IsTerminal, Read, Write},
    os::fd::FromRawFd,
    process::Stdio,
    sync::mpsc,
    time::Duration,
};

use microsandbox::Sandbox;
use test_utils::msb_test;
use tokio::{process::Command, time::timeout};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const NAME: &str = "sdk-attach-output-exit";
const INPUT_NAME: &str = "sdk-attach-duplex-input";
const DETACH_NAME: &str = "sdk-attach-blocked-input-detach";
const CHILD_ENV: &str = "MSB_ATTACH_OUTPUT_CHILD";
const INPUT_CHILD_ENV: &str = "MSB_ATTACH_INPUT_CHILD";
const DETACH_CHILD_ENV: &str = "MSB_ATTACH_DETACH_CHILD";
const INPUT_BYTES: usize = 16 * 1024 * 1024;
const BLOCKED_INPUT_BYTES: usize = 256 * 1024;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn host_terminal() -> (File, File) {
    let mut master = -1;
    let mut slave = -1;

    // SAFETY: openpty writes two owned descriptors, each transferred into one File on success.
    unsafe {
        assert_eq!(
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ),
            0,
            "open host terminal: {}",
            std::io::Error::last_os_error()
        );

        (File::from_raw_fd(slave), File::from_raw_fd(master))
    }
}

fn terminal_output(mut master: File, ready: Option<mpsc::SyncSender<()>>) -> Vec<u8> {
    let mut output = Vec::new();
    let mut ready = ready;
    let mut chunk = [0_u8; 1024];
    loop {
        match master.read(&mut chunk) {
            Ok(0) => break,
            Ok(size) => {
                output.extend_from_slice(&chunk[..size]);
                if ready.is_some()
                    && output
                        .windows(b"READY\n".len())
                        .any(|part| part == b"READY\n")
                {
                    ready.take().unwrap().send(()).expect("send guest ready");
                }
            }
            Err(error) if error.kind() == ErrorKind::UnexpectedEof => break,
            Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
            Err(error) => panic!("read host terminal: {error}"),
        }
    }

    output
}

async fn attach_child_process() {
    let sandbox = Sandbox::get(NAME)
        .await
        .expect("get sandbox")
        .connect()
        .await
        .expect("connect to sandbox");

    let code = sandbox
        .attach("echo", ["hello"])
        .await
        .expect("attach SDK command");
    assert_eq!(code, 0);

    let code = sandbox
        .attach("sh", ["-c", "head -c 2097152 /dev/zero"])
        .await
        .expect("attach SDK command with output beyond the guest window");
    assert_eq!(code, 0);

    println!("SDK_ATTACH_EXIT");
}

async fn attach_input_child_process() {
    let sandbox = Sandbox::get(INPUT_NAME)
        .await
        .expect("get sandbox")
        .connect()
        .await
        .expect("connect to sandbox");

    let code = sandbox
        .attach(
            "sh",
            [
                "-c",
                "stty raw -echo; printf 'READY\\n'; sleep 1; head -c 16777216 | cat",
            ],
        )
        .await
        .expect("attach SDK command with duplex input");
    assert_eq!(code, 0);
}

async fn attach_detach_child_process() {
    let sandbox = Sandbox::get(DETACH_NAME)
        .await
        .expect("get sandbox")
        .connect()
        .await
        .expect("connect to sandbox");

    sandbox
        .attach("sh", ["-c", "stty raw -echo; printf 'READY\\n'; sleep 60"])
        .await
        .expect("detach while guest stdin is blocked");

    println!("SDK_ATTACH_DETACHED");
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[msb_test]
async fn attached_sdk_command_exits_after_output() {
    if std::env::var_os(CHILD_ENV).is_some() {
        attach_child_process().await;
        return;
    }

    let sandbox = Sandbox::builder(NAME)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(512)
        .create()
        .await
        .expect("create sandbox");

    let (terminal, master) = host_terminal();
    assert!(terminal.is_terminal());

    let mut child = Command::new(std::env::current_exe().expect("current test binary"))
        .args([
            "--exact",
            "attached_sdk_command_exits_after_output",
            "--ignored",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .env_remove(test_utils::ISOLATE_HOME_ENV)
        .stdin(Stdio::from(terminal.try_clone().expect("terminal stdin")))
        .stdout(Stdio::from(terminal.try_clone().expect("terminal stdout")))
        .stderr(Stdio::from(terminal))
        .kill_on_drop(true)
        .spawn()
        .expect("spawn SDK attach process");
    let reader = tokio::task::spawn_blocking(move || terminal_output(master, None));

    let status = timeout(Duration::from_secs(15), child.wait()).await;
    if status.is_err() {
        child.kill().await.expect("kill hung SDK attach process");
    }

    sandbox.stop().await.expect("stop sandbox");
    Sandbox::remove(NAME).await.expect("remove sandbox");

    let output = reader.await.expect("read terminal output");
    let status = status.expect("SDK attach waited for output acknowledgement");
    assert!(
        status.expect("wait for SDK attach process").success(),
        "SDK attach failed after {} output bytes",
        output.len()
    );
    assert!(
        output
            .windows(b"hello\r\n".len())
            .any(|part| part == b"hello\r\n"),
        "guest output missing from {} bytes",
        output.len()
    );
    assert_eq!(
        output.iter().filter(|&&byte| byte == 0).count(),
        2 * 1024 * 1024,
        "large guest output was incomplete"
    );
    assert!(
        output
            .windows(b"SDK_ATTACH_EXIT".len())
            .any(|part| part == b"SDK_ATTACH_EXIT"),
        "SDK attach never returned after {} output bytes",
        output.len()
    );
}

#[msb_test]
async fn attached_sdk_command_handles_duplex_input() {
    if std::env::var_os(INPUT_CHILD_ENV).is_some() {
        attach_input_child_process().await;
        return;
    }

    let sandbox = Sandbox::builder(INPUT_NAME)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(512)
        .create()
        .await
        .expect("create sandbox");

    let (terminal, master) = host_terminal();
    assert!(terminal.is_terminal());

    let mut child = Command::new(std::env::current_exe().expect("current test binary"))
        .args([
            "--exact",
            "attached_sdk_command_handles_duplex_input",
            "--ignored",
            "--nocapture",
        ])
        .env(INPUT_CHILD_ENV, "1")
        .env_remove(test_utils::ISOLATE_HOME_ENV)
        .stdin(Stdio::from(terminal.try_clone().expect("terminal stdin")))
        .stdout(Stdio::from(terminal.try_clone().expect("terminal stdout")))
        .stderr(Stdio::from(terminal))
        .kill_on_drop(true)
        .spawn()
        .expect("spawn SDK attach process");

    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let mut write_master = master.try_clone().expect("terminal writer");
    let reader = tokio::task::spawn_blocking(move || terminal_output(master, Some(ready_tx)));
    let writer = tokio::task::spawn_blocking(move || {
        ready_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("guest ready for stdin");

        let chunk = [b'A'; 4096];
        for _ in 0..INPUT_BYTES / chunk.len() {
            write_master
                .write_all(&chunk)
                .expect("write terminal input");
        }
    });

    let status = timeout(Duration::from_secs(60), child.wait()).await;
    if status.is_err() {
        child.kill().await.expect("kill hung SDK attach process");
    }

    sandbox.stop().await.expect("stop sandbox");
    Sandbox::remove(INPUT_NAME).await.expect("remove sandbox");

    let status = status.expect("SDK attach waited for duplex input");
    assert!(status.expect("wait for SDK attach process").success());
    writer.await.expect("write terminal input");
    let output = reader.await.expect("read terminal output");
    let ready_end = output
        .windows(b"READY\n".len())
        .position(|part| part == b"READY\n")
        .expect("guest ready marker")
        + b"READY\n".len();
    assert_eq!(
        output[ready_end..]
            .iter()
            .filter(|&&byte| byte == b'A')
            .count(),
        INPUT_BYTES,
        "guest did not echo every input byte"
    );
}

#[msb_test]
async fn attached_sdk_command_can_detach_while_guest_stdin_is_blocked() {
    if std::env::var_os(DETACH_CHILD_ENV).is_some() {
        attach_detach_child_process().await;
        return;
    }

    let sandbox = Sandbox::builder(DETACH_NAME)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(512)
        .create()
        .await
        .expect("create sandbox");

    let (terminal, master) = host_terminal();
    assert!(terminal.is_terminal());

    let mut child = Command::new(std::env::current_exe().expect("current test binary"))
        .args([
            "--exact",
            "attached_sdk_command_can_detach_while_guest_stdin_is_blocked",
            "--ignored",
            "--nocapture",
        ])
        .env(DETACH_CHILD_ENV, "1")
        .env_remove(test_utils::ISOLATE_HOME_ENV)
        .stdin(Stdio::from(terminal.try_clone().expect("terminal stdin")))
        .stdout(Stdio::from(terminal.try_clone().expect("terminal stdout")))
        .stderr(Stdio::from(terminal))
        .kill_on_drop(true)
        .spawn()
        .expect("spawn SDK attach process");

    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let mut write_master = master.try_clone().expect("terminal writer");
    let reader = tokio::task::spawn_blocking(move || terminal_output(master, Some(ready_tx)));
    let writer = tokio::task::spawn_blocking(move || {
        ready_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("guest ready for stdin");

        let chunk = [b'A'; 4096];
        for _ in 0..BLOCKED_INPUT_BYTES / chunk.len() {
            write_master
                .write_all(&chunk)
                .expect("write blocked terminal input");
        }
        write_master.write_all(&[0x1d]).expect("send detach key");
    });

    let status = timeout(Duration::from_secs(15), child.wait()).await;
    if status.is_err() {
        child.kill().await.expect("kill hung SDK attach process");
    }

    sandbox.stop().await.expect("stop sandbox");
    Sandbox::remove(DETACH_NAME).await.expect("remove sandbox");

    let status = status.expect("SDK attach did not read the detach key while stdin was blocked");
    assert!(status.expect("wait for SDK attach process").success());
    writer.await.expect("write terminal input and detach key");
    let output = reader.await.expect("read terminal output");
    assert!(
        output
            .windows(b"SDK_ATTACH_DETACHED".len())
            .any(|part| part == b"SDK_ATTACH_DETACHED"),
        "SDK attach did not return after the detach key"
    );
}

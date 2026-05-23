#![cfg(feature = "ssh")]

//! Integration tests for the `msb ssh` CLI surface.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use microsandbox::Sandbox;
use test_utils::msb_test;

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[msb_test]
async fn msb_ssh_remote_command_uses_native_client() {
    let name = "cli-ssh-remote-command";
    let sandbox = Sandbox::builder(name)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await
        .expect("create sandbox");

    let output = Command::new(env!("CARGO_BIN_EXE_msb"))
        .args([
            "ssh",
            name,
            "--",
            "printf 'cli-ssh-ok'; printf 'cli-ssh-err' >&2",
        ])
        .output()
        .expect("run msb ssh remote command");

    sandbox.stop_and_wait().await.expect("stop sandbox");
    Sandbox::remove(name).await.expect("remove sandbox");

    assert!(
        output.status.success(),
        "msb ssh failed: status={:?} stdout={} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "cli-ssh-ok");
    assert_eq!(String::from_utf8_lossy(&output.stderr), "cli-ssh-err");
}

#[msb_test]
async fn msb_ssh_interactive_session_works_under_tmux() {
    if std::env::var_os("MSB_SSH_TMUX_TEST").is_none() {
        eprintln!("skipping tmux SSH CLI test; set MSB_SSH_TMUX_TEST=1");
        return;
    }
    if !command_exists("tmux") {
        eprintln!("skipping tmux SSH CLI test; tmux is not installed");
        return;
    }

    let name = "cli-ssh-interactive-tmux";
    let sandbox = Sandbox::builder(name)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await
        .expect("create sandbox");

    let session = format!("msb-ssh-cli-{}", std::process::id());
    let log_path = std::env::temp_dir().join(format!("{session}.log"));
    let result = run_tmux_cli_session(name, &session, &log_path).await;

    let _ = Command::new("tmux")
        .args(["kill-session", "-t", &session])
        .output();

    let probe = sandbox
        .shell("cat /tmp/msb-ssh-interactive.txt; cat /tmp/msb-ssh-tty.txt")
        .await
        .expect("read interactive artifacts");

    sandbox.stop_and_wait().await.expect("stop sandbox");
    Sandbox::remove(name).await.expect("remove sandbox");

    if let Err(message) = result {
        panic!("{message}");
    }

    assert!(
        probe.status().success,
        "interactive artifacts missing: stdout={} stderr={}",
        probe.stdout().unwrap_or_default(),
        probe.stderr().unwrap_or_default()
    );
    let stdout = probe.stdout().expect("probe stdout is UTF-8");
    assert!(
        stdout.contains("tmux-cli-ok"),
        "interactive command did not write marker: {stdout:?}"
    );
    assert!(
        stdout.contains("tty-yes"),
        "interactive shell did not report a TTY: {stdout:?}"
    );
    assert!(
        stdout.lines().any(|line| {
            let mut parts = line.split_whitespace();
            parts.next().is_some_and(|part| part.parse::<u16>().is_ok())
                && parts.next().is_some_and(|part| part.parse::<u16>().is_ok())
        }),
        "stty size did not report rows and columns: {stdout:?}"
    );
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn run_tmux_cli_session(
    sandbox_name: &str,
    session: &str,
    log_path: &PathBuf,
) -> Result<(), String> {
    let _ = std::fs::remove_file(log_path);
    let _ = Command::new("tmux")
        .args(["kill-session", "-t", session])
        .output();

    let command = format!(
        "exec {} ssh {}",
        shell_quote(env!("CARGO_BIN_EXE_msb")),
        shell_quote(sandbox_name)
    );
    command_ok(
        Command::new("tmux").args([
            "new-session",
            "-d",
            "-s",
            session,
            "-x",
            "100",
            "-y",
            "30",
            &command,
        ]),
        "start tmux SSH session",
    )?;
    command_ok(
        Command::new("tmux").args([
            "pipe-pane",
            "-t",
            session,
            "-o",
            &format!("cat > {}", shell_quote(&log_path.to_string_lossy())),
        ]),
        "pipe tmux pane",
    )?;

    wait_for_pane(session, "/ #", Duration::from_secs(45)).await?;

    command_ok(
        Command::new("tmux").args([
            "send-keys",
            "-t",
            session,
            "printf 'tmux-cli-ok\\n' > /tmp/msb-ssh-interactive.txt; test -t 0 && echo tty-yes > /tmp/msb-ssh-tty.txt; stty size >> /tmp/msb-ssh-tty.txt; exit",
            "C-m",
        ]),
        "send interactive SSH command",
    )?;
    wait_for_session_exit(session, Duration::from_secs(45)).await
}

async fn wait_for_pane(session: &str, needle: &str, timeout: Duration) -> Result<(), String> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        let output = Command::new("tmux")
            .args(["capture-pane", "-t", session, "-p", "-S", "-200"])
            .output()
            .map_err(|e| format!("capture tmux pane: {e}"))?;
        if String::from_utf8_lossy(&output.stdout).contains(needle) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Err(format!(
        "timed out waiting for tmux pane to contain {needle:?}"
    ))
}

async fn wait_for_session_exit(session: &str, timeout: Duration) -> Result<(), String> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        let output = Command::new("tmux")
            .args(["has-session", "-t", session])
            .output()
            .map_err(|e| format!("check tmux session: {e}"))?;
        if !output.status.success() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Err("timed out waiting for tmux SSH session to exit".to_string())
}

fn command_exists(command: &str) -> bool {
    Command::new("sh")
        .args([
            "-lc",
            &format!("command -v {} >/dev/null 2>&1", shell_quote(command)),
        ])
        .status()
        .is_ok_and(|status| status.success())
}

fn command_ok(command: &mut Command, context: &str) -> Result<(), String> {
    let output = command
        .output()
        .map_err(|e| format!("{context}: failed to spawn: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "{context}: status={:?} stdout={} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

fn shell_quote(value: impl AsRef<str>) -> String {
    format!("'{}'", value.as_ref().replace('\'', "'\\''"))
}

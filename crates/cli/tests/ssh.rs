#![cfg(feature = "ssh")]

//! Integration tests for the `msb ssh` CLI surface.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{io::Read, net::TcpStream};

use microsandbox::Sandbox;
use russh::keys::{Algorithm, PrivateKey, PublicKeyBase64};
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

#[msb_test]
async fn msb_ssh_serve_supports_openssh_local_forwarding() {
    if !command_exists("ssh") {
        eprintln!("skipping OpenSSH forwarding test; ssh is not installed");
        return;
    }

    let name = "cli-ssh-direct-tcpip";
    let sandbox = Sandbox::builder(name)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await
        .expect("create sandbox");

    let nc_check = sandbox
        .shell("command -v nc >/dev/null")
        .await
        .expect("check guest nc");
    if !nc_check.status().success {
        cleanup_sandbox(sandbox, name).await;
        eprintln!("skipping OpenSSH forwarding test; guest image does not provide nc");
        return;
    }
    let mut listener = sandbox
        .exec_stream("sh", ["-lc", "printf 'tcp-forward-ok' | nc -l -p 18080"])
        .await
        .expect("start guest TCP listener");

    let temp = make_temp_dir("msb-ssh-forward");
    let key_path = temp.join("id_ed25519");
    let authorized_key = write_test_key(&key_path);
    command_ok(
        Command::new(env!("CARGO_BIN_EXE_msb")).args([
            "ssh",
            "authorize",
            "--key",
            &authorized_key,
        ]),
        "authorize OpenSSH test key",
    )
    .expect("authorize OpenSSH test key");

    let local_port = reserve_local_port();
    let mut ssh = spawn_ssh_forward(name, &key_path, local_port);
    let result = read_forwarded_bytes(local_port, Duration::from_secs(30)).await;

    terminate_child(&mut ssh);
    finish_guest_listener(&mut listener).await;
    cleanup_sandbox(sandbox, name).await;
    let _ = std::fs::remove_dir_all(&temp);

    let data = match result {
        Ok(data) => data,
        Err(error) => {
            let mut stderr = String::new();
            if let Some(mut pipe) = ssh.stderr.take() {
                let _ = pipe.read_to_string(&mut stderr);
            }
            panic!("{error}; ssh stderr={stderr}");
        }
    };
    assert_eq!(data, b"tcp-forward-ok");
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
            &format!("cat > {}", shell_quote(log_path.to_string_lossy())),
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

async fn cleanup_sandbox(sandbox: Sandbox, name: &str) {
    sandbox.stop_and_wait().await.expect("stop sandbox");
    Sandbox::remove(name).await.expect("remove sandbox");
}

async fn finish_guest_listener(listener: &mut microsandbox::ExecHandle) {
    if tokio::time::timeout(Duration::from_secs(2), listener.wait())
        .await
        .is_err()
    {
        let _ = listener.kill().await;
    }
}

fn write_test_key(path: &std::path::Path) -> String {
    let mut rng = russh::keys::key::safe_rng();
    let key = PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("generate SSH key");
    let encoded = key
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .expect("encode SSH private key");
    std::fs::write(path, encoded.as_bytes()).expect("write SSH private key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("set SSH private key permissions");
    }
    format!(
        "ssh-ed25519 {} msb-forward-test",
        key.public_key().public_key_base64()
    )
}

fn make_temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("{prefix}-{}-{}", std::process::id(), nanos));
    std::fs::create_dir_all(&path).expect("create temp dir");
    path
}

fn reserve_local_port() -> u16 {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("reserve local port");
    listener.local_addr().expect("local addr").port()
}

fn spawn_ssh_forward(sandbox_name: &str, key_path: &std::path::Path, local_port: u16) -> Child {
    let proxy = format!(
        "{} ssh serve {} --stdio",
        shell_quote(env!("CARGO_BIN_EXE_msb")),
        shell_quote(sandbox_name)
    );
    Command::new("ssh")
        .args([
            "-F",
            "/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "ExitOnForwardFailure=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            &format!("ProxyCommand={proxy}"),
            "-i",
            &key_path.to_string_lossy(),
            "-N",
            "-L",
            &format!("127.0.0.1:{local_port}:127.0.0.1:18080"),
            "root@msb-direct-tcpip",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn OpenSSH forwarding client")
}

async fn read_forwarded_bytes(local_port: u16, timeout: Duration) -> Result<Vec<u8>, String> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        match TcpStream::connect(("127.0.0.1", local_port)) {
            Ok(mut stream) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .map_err(|e| format!("set read timeout: {e}"))?;
                let mut data = Vec::new();
                match stream.read_to_end(&mut data) {
                    Ok(_) if !data.is_empty() => return Ok(data),
                    Ok(_) => {}
                    Err(e) => return Err(format!("read forwarded TCP stream: {e}")),
                }
            }
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    Err(format!(
        "timed out waiting for forwarded bytes on 127.0.0.1:{local_port}"
    ))
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
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

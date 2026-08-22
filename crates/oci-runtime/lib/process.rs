//! OCI guest-process execution, command resolution, signals, and pid files.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result, anyhow, bail};
use microsandbox::sandbox::exec::{ExecControl, ExecEvent, ExecHandle};
use microsandbox::sandbox::{ExecOptionsBuilder, Sandbox, SandboxStatus};
use microsandbox_runtime::oci::{OciProcess, sandbox_name_for_container, validate_process};
use nix::sys::signal::Signal;

use crate::console::{ConsoleBridge, process_console_size, wait_for_console_process_exit};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const DEFAULT_EXEC_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub(crate) struct StartedProcess {
    guest_pid: Option<u32>,
}

pub(crate) struct HostSignalForwarder {
    terminate: tokio::signal::unix::Signal,
    interrupt: tokio::signal::unix::Signal,
    hangup: tokio::signal::unix::Signal,
    quit: tokio::signal::unix::Signal,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl HostSignalForwarder {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self {
            terminate: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .context("install OCI signal forwarder SIGTERM handler")?,
            interrupt: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .context("install OCI signal forwarder SIGINT handler")?,
            hangup: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
                .context("install OCI signal forwarder SIGHUP handler")?,
            quit: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::quit())
                .context("install OCI signal forwarder SIGQUIT handler")?,
        })
    }

    pub(crate) async fn recv(&mut self) -> i32 {
        tokio::select! {
            _ = self.terminate.recv() => libc::SIGTERM,
            _ = self.interrupt.recv() => libc::SIGINT,
            _ = self.hangup.recv() => libc::SIGHUP,
            _ = self.quit.recv() => libc::SIGQUIT,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) async fn connect_sandbox(id: &str) -> Result<Sandbox> {
    let handle = Sandbox::get(&sandbox_name_for_container(id)).await?;
    match handle.status_snapshot() {
        SandboxStatus::Running | SandboxStatus::Draining => {
            handle.connect().await.map_err(Into::into)
        }
        SandboxStatus::Stopped | SandboxStatus::Crashed => {
            handle.start_detached().await.map_err(Into::into)
        }
        status => bail!("cannot connect to sandbox for container `{id}` while it is {status:?}"),
    }
}

pub(crate) async fn start_process_stream(
    sandbox: &Sandbox,
    process: &OciProcess,
    rootfs: &Path,
) -> Result<(StartedProcess, ExecHandle)> {
    let command = resolve_process_command(process, rootfs)?;
    let mut handle = sandbox
        .exec_stream_with(command, |exec| configure_exec(exec, process))
        .await?;
    let _session_id = handle
        .id()
        .parse::<u32>()
        .context("parse Microsandbox exec session ID")?;

    while let Some(event) = handle.recv().await {
        match event {
            ExecEvent::Started { pid } => {
                if let Some(size) = process_console_size(process) {
                    handle
                        .resize(size.rows, size.cols)
                        .await
                        .context("resize OCI init PTY from process.consoleSize")?;
                }
                return Ok((
                    StartedProcess {
                        guest_pid: Some(pid),
                    },
                    handle,
                ));
            }
            ExecEvent::Failed(payload) => {
                return Err(microsandbox::MicrosandboxError::ExecFailed(payload).into());
            }
            ExecEvent::Exited { code } => {
                bail!("OCI init process exited before start completed with code {code}")
            }
            ExecEvent::Stdout(_) | ExecEvent::Stderr(_) | ExecEvent::StdinError(_) => {}
        }
    }

    bail!("OCI init process stream ended before start completed")
}

pub(crate) async fn wait_for_process_exit(
    id: &str,
    handle: &mut ExecHandle,
    console: Option<&ConsoleBridge>,
    host_signals: &mut HostSignalForwarder,
) -> Result<i32> {
    if let Some(console) = console {
        return wait_for_console_process_exit(id, handle, console, host_signals).await;
    }

    let control = handle.control();
    loop {
        tokio::select! {
            signal = host_signals.recv() => {
                forward_host_signal(&control, signal).await?;
            }
            event = handle.recv() => {
                match event {
                    Some(ExecEvent::Exited { code }) => return Ok(code),
                    Some(ExecEvent::Failed(payload)) => {
                        return Err(microsandbox::MicrosandboxError::ExecFailed(payload).into());
                    }
                    Some(ExecEvent::Stdout(data)) => {
                        let mut stdout = std::io::stdout().lock();
                        stdout.write_all(&data).context("write OCI init stdout")?;
                        stdout.flush().context("flush OCI init stdout")?;
                    }
                    Some(ExecEvent::Stderr(data)) => {
                        let mut stderr = std::io::stderr().lock();
                        stderr.write_all(&data).context("write OCI init stderr")?;
                        stderr.flush().context("flush OCI init stderr")?;
                    }
                    Some(ExecEvent::Started { .. }) | Some(ExecEvent::StdinError(_)) => {}
                    None => bail!("OCI init process stream ended before exit event for `{id}`"),
                }
            }
        }
    }
}

pub(crate) async fn forward_host_signal(control: &ExecControl, signal: i32) -> Result<()> {
    control
        .signal(signal)
        .await
        .with_context(|| format!("forward host signal {signal} to OCI process"))
}

pub(crate) fn load_process(path: &Path) -> Result<OciProcess> {
    let data = std::fs::read_to_string(path)
        .with_context(|| format!("read OCI process JSON `{}`", path.display()))?;
    let process: OciProcess = serde_json::from_str(&data)
        .with_context(|| format!("parse OCI process JSON `{}`", path.display()))?;
    validate_process(&process, path.parent().unwrap_or_else(|| Path::new(".")))
        .map_err(Into::into)
        .map(|()| process)
}

pub(crate) fn process_args(process: &OciProcess) -> Result<&[String]> {
    let args = process.args().as_deref().unwrap_or_default();
    if args.is_empty() {
        bail!("OCI process args must contain at least one entry");
    }
    Ok(args)
}

pub(crate) fn write_exec_pid_file(path: Option<&Path>, started: &StartedProcess) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    let _guest_pid = started
        .guest_pid
        .ok_or_else(|| anyhow!("exec process started without a guest PID for pid-file"))?;
    write_pid_file(path, std::process::id() as i32)
}

pub(crate) fn env_pairs(env: &[String]) -> Result<Vec<(String, String)>> {
    env.iter()
        .map(|entry| {
            entry
                .split_once('=')
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .ok_or_else(|| anyhow!("OCI environment entry must be KEY=VALUE: `{entry}`"))
        })
        .collect()
}

pub(crate) fn parse_signal(signal: &str) -> Result<i32> {
    if let Ok(number) = signal.parse::<i32>() {
        return Ok(number);
    }

    let normalized = signal.trim_start_matches('-').to_ascii_uppercase();
    let name = if normalized.starts_with("SIG") {
        normalized
    } else {
        format!("SIG{normalized}")
    };
    Signal::from_str(&name)
        .map(|signal| signal as i32)
        .map_err(|_| anyhow!("unsupported signal `{signal}`"))
}

fn resolve_process_command(process: &OciProcess, rootfs: &Path) -> Result<String> {
    let args = process_args(process)?;
    let command = &args[0];
    if command.contains('/') {
        return Ok(command.clone());
    }

    for entry in process_path_entries(process) {
        let guest_path = if entry.is_empty() || entry == "." {
            PathBuf::from(command)
        } else {
            Path::new(&entry).join(command)
        };
        let host_path = if guest_path.is_absolute() {
            rootfs.join(guest_path.strip_prefix("/").unwrap_or(&guest_path))
        } else {
            rootfs.join(&guest_path)
        };
        if host_path.is_file() {
            return Ok(guest_path_for_exec(&guest_path));
        }
    }

    Ok(command.clone())
}

fn process_path_entries(process: &OciProcess) -> Vec<String> {
    process
        .env()
        .as_deref()
        .unwrap_or_default()
        .iter()
        .find_map(|entry| entry.strip_prefix("PATH="))
        .unwrap_or(DEFAULT_EXEC_PATH)
        .split(':')
        .map(str::to_string)
        .collect()
}

fn guest_path_for_exec(path: &Path) -> String {
    if path.is_absolute() {
        path.display().to_string()
    } else {
        format!("/{}", path.display())
    }
}

fn configure_exec(mut exec: ExecOptionsBuilder, process: &OciProcess) -> ExecOptionsBuilder {
    let args = process.args().as_deref().unwrap_or_default();
    let terminal = process.terminal().unwrap_or(false);
    exec = exec
        .args(args.iter().skip(1).cloned())
        .cwd(process.cwd().display().to_string())
        .tty(terminal);
    if terminal {
        exec = exec.stdin_pipe();
    }
    let user = process.user();
    if user.uid() != 0 || user.gid() != 0 {
        exec = exec.user(format!("{}:{}", user.uid(), user.gid()));
    }
    for (key, value) in env_pairs_lossy(process.env().as_deref().unwrap_or_default()) {
        exec = exec.env(key, value);
    }
    exec
}

fn write_pid_file(path: &Path, pid: i32) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create pid-file directory `{}`", parent.display()))?;
    }
    std::fs::write(path, pid.to_string())
        .with_context(|| format!("write pid-file `{}`", path.display()))
}

fn env_pairs_lossy(env: &[String]) -> Vec<(String, String)> {
    env.iter()
        .filter_map(|entry| {
            entry
                .split_once('=')
                .map(|(key, value)| (key.to_string(), value.to_string()))
        })
        .collect()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use microsandbox_runtime::oci::OciBundle;

    use super::*;

    #[test]
    fn parses_signal_names_and_numbers() {
        assert_eq!(parse_signal("0").expect("zero"), 0);
        assert_eq!(parse_signal("9").expect("number"), libc::SIGKILL);
        assert_eq!(parse_signal("SIGTERM").expect("sigterm"), libc::SIGTERM);
        assert_eq!(parse_signal("TERM").expect("term"), libc::SIGTERM);
        assert_eq!(parse_signal("sigusr1").expect("sigusr1"), libc::SIGUSR1);
        assert_eq!(parse_signal("USR2").expect("usr2"), libc::SIGUSR2);
        assert_eq!(parse_signal("WINCH").expect("winch"), libc::SIGWINCH);
        assert_eq!(parse_signal("-CONT").expect("cont"), libc::SIGCONT);
        assert!(parse_signal("SIGBOGUS").is_err());
    }

    #[test]
    fn rejects_invalid_env_entries() {
        assert!(env_pairs(&["PATH=/bin".to_string()]).is_ok());
        assert!(env_pairs(&["PATH".to_string()]).is_err());
    }

    #[test]
    fn write_pid_file_creates_parent_directory() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("nested").join("init.pid");

        write_pid_file(&path, 1234).expect("write pid file");

        let content = std::fs::read_to_string(path).expect("read pid file");
        assert_eq!(content, "1234");
    }

    #[test]
    fn write_exec_pid_file_uses_host_supervisor_pid() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("exec.pid");
        let started = StartedProcess {
            guest_pid: Some(4321),
        };

        write_exec_pid_file(Some(&path), &started).expect("write exec pid file");

        let content = std::fs::read_to_string(path).expect("read exec pid file");
        assert_eq!(content, std::process::id().to_string());
    }

    #[test]
    fn write_exec_pid_file_rejects_missing_guest_pid() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("exec.pid");
        let started = StartedProcess { guest_pid: None };

        let error = write_exec_pid_file(Some(&path), &started).expect_err("missing guest pid");

        assert!(error.to_string().contains("without a guest PID"));
    }

    #[test]
    fn terminal_process_uses_tty_and_piped_stdin() {
        let (_temp, bundle) = process_bundle("/bin/sh", true);
        let process = bundle.process().expect("process");
        let options = configure_exec(ExecOptionsBuilder::default(), process)
            .build()
            .expect("exec options");

        assert!(options.tty);
        assert!(matches!(
            options.stdin,
            microsandbox::sandbox::exec::StdinMode::Pipe
        ));
    }

    #[test]
    fn resolves_bare_process_command_from_rootfs_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let bash = temp.path().join("rootfs/usr/bin/bash");
        std::fs::create_dir_all(bash.parent().expect("parent")).expect("bin dir");
        std::fs::write(&bash, b"").expect("bash");
        write_bundle_config(temp.path(), "bash", false);
        let bundle = OciBundle::load(temp.path()).expect("load bundle");

        let command =
            resolve_process_command(bundle.process().expect("process"), &bundle.rootfs_path())
                .expect("resolve command");

        assert_eq!(command, "/usr/bin/bash");
    }

    #[test]
    fn leaves_explicit_process_command_unchanged() {
        let (_temp, bundle) = process_bundle("/custom/bash", false);

        let command =
            resolve_process_command(bundle.process().expect("process"), &bundle.rootfs_path())
                .expect("resolve command");

        assert_eq!(command, "/custom/bash");
    }

    #[test]
    fn reads_process_console_size_from_oci_config() {
        let (temp, _) = process_bundle("/bin/sh", true);
        let config = std::fs::read_to_string(temp.path().join("config.json")).expect("config");
        let config = config.replace(
            "\"terminal\": true,",
            "\"terminal\": true, \"consoleSize\": { \"height\": 45, \"width\": 160 },",
        );
        std::fs::write(temp.path().join("config.json"), config).expect("rewrite config");
        let bundle = OciBundle::load(temp.path()).expect("reload bundle");

        assert_eq!(
            process_console_size(bundle.process().expect("process")),
            Some(crate::console::PtySize {
                rows: 45,
                cols: 160,
            })
        );
    }

    fn process_bundle(command: &str, terminal: bool) -> (tempfile::TempDir, OciBundle) {
        let temp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(temp.path().join("rootfs")).expect("rootfs");
        write_bundle_config(temp.path(), command, terminal);
        let bundle = OciBundle::load(temp.path()).expect("load bundle");
        (temp, bundle)
    }

    fn write_bundle_config(path: &Path, command: &str, terminal: bool) {
        std::fs::write(
            path.join("config.json"),
            format!(
                r#"{{
                    "ociVersion": "1.2.0",
                    "root": {{ "path": "rootfs" }},
                    "process": {{
                        "terminal": {terminal},
                        "user": {{ "uid": 0, "gid": 0 }},
                        "cwd": "/",
                        "args": ["{command}"]
                    }}
                }}"#
            ),
        )
        .expect("config");
    }
}

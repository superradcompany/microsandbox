//! Spawning the supervisor process.
//!
//! [`spawn_supervisor`] creates a Unix socket pair for the agent channel,
//! assembles CLI arguments from [`SandboxConfig`], fork+execs `msb supervisor`,
//! and reads the startup JSON to obtain child PIDs.

use std::{
    ffi::OsString,
    os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd},
    path::Path,
    process::Stdio,
};

use serde::Deserialize;
use tokio::{io::AsyncBufReadExt, process::Command};

use crate::{
    MicrosandboxResult, config,
    runtime::handle::SupervisorHandle,
    sandbox::{RootfsSource, SandboxConfig, VolumeMount},
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// JSON structure read from supervisor stdout on startup.
#[derive(Debug, Deserialize)]
struct StartupInfo {
    vm_pid: u32,
    msbnet_pid: Option<u32>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Spawn the supervisor process for a sandbox.
///
/// Returns a [`SupervisorHandle`] and the host-side raw FD for the agent
/// channel (to be wrapped in an [`AgentBridge`](crate::agent::AgentBridge)).
///
/// The function:
/// 1. Creates a Unix socket pair for host↔agentd communication
/// 2. Resolves the `msb` binary path
/// 3. Creates sandbox directories (logs, runtime, scripts)
/// 4. Builds CLI arguments from the config
/// 5. Spawns `msb supervisor` with the guest FD inherited
/// 6. Reads startup JSON from stdout to get child PIDs
pub async fn spawn_supervisor(
    config: &SandboxConfig,
    sandbox_id: i32,
) -> MicrosandboxResult<(SupervisorHandle, RawFd)> {
    // Create the agent socket pair.
    let (host_fd, guest_fd) = create_socketpair()?;
    let guest_raw_fd = guest_fd.as_raw_fd();

    // Resolve paths.
    let msb_path = config::resolve_msb_path()?;
    let libkrunfw_path = config::resolve_libkrunfw_path()?;
    let global = config::config();
    let sandbox_dir = global.sandboxes_dir().join(&config.name);
    let log_dir = sandbox_dir.join("logs");
    let runtime_dir = sandbox_dir.join("runtime");
    let scripts_dir = runtime_dir.join("scripts");
    let db_dir = global.home().join(microsandbox_utils::DB_SUBDIR);
    let db_path = db_dir.join(microsandbox_utils::DB_FILENAME);

    // Create directories concurrently.
    tokio::try_join!(
        tokio::fs::create_dir_all(&log_dir),
        tokio::fs::create_dir_all(&scripts_dir),
    )?;

    // Write scripts to the runtime scripts directory.
    for (name, content) in &config.scripts {
        // Prevent path traversal: only use the filename component.
        let safe_name = Path::new(name).file_name().ok_or_else(|| {
            crate::MicrosandboxError::InvalidConfig(format!("invalid script name: {name}"))
        })?;
        let script_path = scripts_dir.join(safe_name);
        tokio::fs::write(&script_path, content).await?;
    }

    // Build the command.
    let mut cmd = Command::new(&msb_path);
    cmd.args(supervisor_cli_args(
        config,
        sandbox_id,
        &db_path,
        &log_dir,
        &runtime_dir,
        guest_raw_fd,
        &libkrunfw_path,
    ));

    // Capture stdout (for startup JSON), inherit stderr so errors are visible.
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::inherit());

    // Clear CLOEXEC on the guest FD so it's inherited by the child.
    unsafe {
        cmd.pre_exec(move || {
            clear_cloexec(guest_raw_fd)?;
            Ok(())
        });
    }

    // Spawn the supervisor.
    let mut child = cmd.spawn()?;
    let supervisor_pid = child.id().ok_or_else(|| {
        crate::MicrosandboxError::Runtime("supervisor process exited immediately".into())
    })?;

    // Close the guest FD in the parent by dropping it.
    drop(guest_fd);

    // Read the startup JSON from the supervisor's stdout.
    let stdout = child.stdout.take().ok_or_else(|| {
        crate::MicrosandboxError::Runtime("failed to capture supervisor stdout".into())
    })?;

    let mut reader = tokio::io::BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).await?;

    let startup: StartupInfo = match serde_json::from_str(line.trim()) {
        Ok(info) => info,
        Err(_) => {
            // Supervisor exited before writing JSON. Wait for it to get exit code.
            let status = child.wait().await?;
            return Err(crate::MicrosandboxError::Runtime(format!(
                "supervisor exited ({status}) before sending startup info \
                 (check stderr above for details)"
            )));
        }
    };

    // Transfer ownership of the host FD to the caller.
    let host_raw_fd = host_fd.into_raw_fd();

    let handle = SupervisorHandle::new(
        supervisor_pid,
        startup.vm_pid,
        startup.msbnet_pid,
        config.name.clone(),
        child,
    );

    Ok((handle, host_raw_fd))
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Create a Unix socket pair, returning (host_fd, guest_fd) as OwnedFds.
fn create_socketpair() -> MicrosandboxResult<(OwnedFd, OwnedFd)> {
    let mut fds = [0i32; 2];
    let ret = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    if ret != 0 {
        return Err(crate::MicrosandboxError::Io(std::io::Error::last_os_error()));
    }

    // Wrap immediately so FDs are closed on error.
    let fd1 = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let fd2 = unsafe { OwnedFd::from_raw_fd(fds[1]) };

    // Set CLOEXEC on both.
    set_cloexec(fd1.as_raw_fd())?;
    set_cloexec(fd2.as_raw_fd())?;

    Ok((fd1, fd2))
}

/// Set the close-on-exec flag on a file descriptor (preserving existing flags).
fn set_cloexec(fd: RawFd) -> MicrosandboxResult<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 {
        return Err(crate::MicrosandboxError::Io(std::io::Error::last_os_error()));
    }
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if ret == -1 {
        return Err(crate::MicrosandboxError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Clear the close-on-exec flag on a file descriptor (preserving other flags).
fn clear_cloexec(fd: RawFd) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 {
        return Err(std::io::Error::last_os_error());
    }
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
    if ret == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Convert ShutdownMode to CLI arg string.
fn shutdown_mode_str(mode: &microsandbox_runtime::policy::ShutdownMode) -> &'static str {
    use microsandbox_runtime::policy::ShutdownMode;
    match mode {
        ShutdownMode::Graceful => "graceful",
        ShutdownMode::Terminate => "terminate",
        ShutdownMode::Kill => "kill",
    }
}

/// Generate a virtiofs tag from a guest mount path.
///
/// Replaces `/` with `_` and strips leading underscores to produce a
/// valid tag name. For example, `/data/cache` becomes `data_cache`.
fn guest_mount_tag(guest_path: &str) -> String {
    guest_path
        .replace('/', "_")
        .trim_start_matches('_')
        .to_string()
}

/// Convert ExitAction to CLI arg string.
fn exit_action_str(action: &microsandbox_runtime::policy::ExitAction) -> &'static str {
    use microsandbox_runtime::policy::ExitAction;
    match action {
        ExitAction::ShutdownAll => "shutdown-all",
        ExitAction::Restart => "restart",
        ExitAction::Ignore => "ignore",
    }
}

/// Build the `msb supervisor` CLI args for a sandbox.
fn supervisor_cli_args(
    config: &SandboxConfig,
    sandbox_id: i32,
    db_path: &Path,
    log_dir: &Path,
    runtime_dir: &Path,
    agent_fd: RawFd,
    libkrunfw_path: &Path,
) -> Vec<OsString> {
    let mut args = vec![OsString::from("supervisor")];

    if let Some(log_level) = config.log_level {
        args.push(OsString::from(log_level.as_cli_flag()));
    }

    args.push(OsString::from("--name"));
    args.push(OsString::from(&config.name));
    args.push(OsString::from("--sandbox-id"));
    args.push(OsString::from(sandbox_id.to_string()));
    args.push(OsString::from("--db-path"));
    args.push(db_path.as_os_str().to_os_string());
    args.push(OsString::from("--log-dir"));
    args.push(log_dir.as_os_str().to_os_string());
    args.push(OsString::from("--runtime-dir"));
    args.push(runtime_dir.as_os_str().to_os_string());
    args.push(OsString::from("--agent-fd"));
    args.push(OsString::from(agent_fd.to_string()));

    let sp = &config.supervisor_policy;
    args.push(OsString::from("--shutdown-mode"));
    args.push(OsString::from(shutdown_mode_str(&sp.shutdown_mode)));
    args.push(OsString::from("--grace-secs"));
    args.push(OsString::from(sp.grace_secs.to_string()));
    if let Some(max_dur) = sp.max_duration_secs {
        args.push(OsString::from("--max-duration"));
        args.push(OsString::from(max_dur.to_string()));
    }
    if let Some(idle) = sp.idle_timeout_secs {
        args.push(OsString::from("--idle-timeout"));
        args.push(OsString::from(idle.to_string()));
    }

    let vp = &config.child_policies.vm;
    args.push(OsString::from("--vm-on-exit"));
    args.push(OsString::from(exit_action_str(&vp.on_exit)));
    args.push(OsString::from("--vm-max-restarts"));
    args.push(OsString::from(vp.max_restarts.to_string()));
    args.push(OsString::from("--vm-restart-delay-ms"));
    args.push(OsString::from(vp.restart_delay_ms.to_string()));
    args.push(OsString::from("--vm-restart-window"));
    args.push(OsString::from(vp.restart_window_secs.to_string()));
    args.push(OsString::from("--vm-shutdown-timeout-ms"));
    args.push(OsString::from(vp.shutdown_timeout_ms.to_string()));

    args.push(OsString::from("--libkrunfw-path"));
    args.push(libkrunfw_path.as_os_str().to_os_string());
    args.push(OsString::from("--vcpus"));
    args.push(OsString::from(config.cpus.to_string()));
    args.push(OsString::from("--memory-mib"));
    args.push(OsString::from(config.memory_mib.to_string()));

    match &config.image {
        RootfsSource::Bind(path) => {
            args.push(OsString::from("--rootfs-layer"));
            args.push(path.as_os_str().to_os_string());
        }
        RootfsSource::Oci(reference) => {
            unimplemented!("OCI image references are not yet supported: {reference}");
        }
    }

    for (key, value) in &config.env {
        args.push(OsString::from("--env"));
        args.push(OsString::from(format!("{key}={value}")));
    }

    for mount in &config.mounts {
        match mount {
            VolumeMount::Bind {
                host,
                guest,
                readonly,
            } => {
                let tag = guest_mount_tag(guest);
                let mut arg = format!("{tag}:{}", host.display());
                if *readonly {
                    arg.push_str(":ro");
                }
                args.push(OsString::from("--mount"));
                args.push(OsString::from(arg));
            }
            VolumeMount::Named {
                name,
                guest,
                readonly,
            } => {
                let vol_path = config::config().volumes_dir().join(name);
                let tag = guest_mount_tag(guest);
                let mut arg = format!("{tag}:{}", vol_path.display());
                if *readonly {
                    arg.push_str(":ro");
                }
                args.push(OsString::from("--mount"));
                args.push(OsString::from(arg));
            }
            VolumeMount::Tmpfs { .. } => {
                // Tmpfs mounts are handled by the guest kernel, not virtiofs.
            }
            VolumeMount::Backend { .. } => {
                // Backend mounts are guarded at Sandbox::create() — they cannot
                // reach this point in the subprocess path. If they do, skip them.
            }
        }
    }

    if let Some(ref workdir) = config.workdir {
        args.push(OsString::from("--workdir"));
        args.push(OsString::from(workdir));
    }

    args
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::supervisor_cli_args;
    use crate::{LogLevel, sandbox::SandboxBuilder};

    #[test]
    fn test_supervisor_cli_args_include_selected_log_level() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .log_level(LogLevel::Debug)
            .build()
            .unwrap();

        let args = supervisor_cli_args(
            &config,
            42,
            Path::new("/tmp/msb.db"),
            Path::new("/tmp/logs"),
            Path::new("/tmp/runtime"),
            9,
            Path::new("/tmp/libkrunfw.dylib"),
        );

        assert!(args.iter().any(|arg| arg == "--debug"));
    }

    #[test]
    fn test_supervisor_cli_args_are_silent_by_default() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .build()
            .unwrap();

        let args = supervisor_cli_args(
            &config,
            42,
            Path::new("/tmp/msb.db"),
            Path::new("/tmp/logs"),
            Path::new("/tmp/runtime"),
            9,
            Path::new("/tmp/libkrunfw.dylib"),
        );

        assert!(!args.iter().any(|arg| {
            matches!(
                arg.to_str(),
                Some("--error" | "--warn" | "--info" | "--debug" | "--trace")
            )
        }));
    }
}

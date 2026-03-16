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
    // Create the agent socket pair (SOCK_STREAM for virtio-console).
    let (host_fd, guest_fd) = create_socketpair(libc::SOCK_STREAM)?;
    let guest_raw_fd = guest_fd.as_raw_fd();

    // Create the network socket pair (SOCK_DGRAM for Unixgram frame relay)
    // if networking is enabled.
    let net_fds = if config.network.enabled {
        let (msbnet_fd, vm_fd) = create_socketpair(libc::SOCK_DGRAM)?;
        Some((msbnet_fd, vm_fd))
    } else {
        None
    };
    let net_msbnet_raw_fd = net_fds.as_ref().map(|(msbnet_fd, _)| msbnet_fd.as_raw_fd());
    let net_vm_raw_fd = net_fds.as_ref().map(|(_, vm_fd)| vm_fd.as_raw_fd());

    // Resolve paths.
    let msb_path = config::resolve_msb_path()?;
    let libkrunfw_path = config::resolve_libkrunfw_path()?;
    let global = config::config();
    let sandbox_dir = global.sandboxes_dir().join(&config.name);
    let log_dir = sandbox_dir.join("logs");
    let runtime_dir = sandbox_dir.join("runtime");
    let network_config_json = if config.network.enabled {
        Some(serde_json::to_string(&config.network)?)
    } else {
        None
    };
    let scripts_dir = runtime_dir.join("scripts");
    let empty_rootfs_dir = sandbox_dir.join("rootfs-base");
    let rw_dir = sandbox_dir.join("rw");
    let staging_dir = sandbox_dir.join("staging");
    let db_dir = global.home().join(microsandbox_utils::DB_SUBDIR);
    let db_path = db_dir.join(microsandbox_utils::DB_FILENAME);

    // Create directories concurrently.
    tokio::try_join!(
        tokio::fs::create_dir_all(&log_dir),
        tokio::fs::create_dir_all(&scripts_dir),
        tokio::fs::create_dir_all(&empty_rootfs_dir),
        tokio::fs::create_dir_all(&rw_dir),
        tokio::fs::create_dir_all(&staging_dir),
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
        network_config_json.as_deref(),
        &empty_rootfs_dir,
        &rw_dir,
        &staging_dir,
        guest_raw_fd,
        net_msbnet_raw_fd,
        net_vm_raw_fd,
        &libkrunfw_path,
    ));

    // Capture stdout (for startup JSON), inherit stderr so errors are visible.
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::inherit());

    // Clear CLOEXEC on inherited FDs so they survive exec.
    unsafe {
        cmd.pre_exec(move || {
            clear_cloexec(guest_raw_fd)?;
            if let Some(nfd) = net_msbnet_raw_fd {
                clear_cloexec(nfd)?;
            }
            if let Some(nfd) = net_vm_raw_fd {
                clear_cloexec(nfd)?;
            }
            Ok(())
        });
    }

    // Spawn the supervisor.
    let mut child = cmd.spawn()?;
    let supervisor_pid = child.id().ok_or_else(|| {
        crate::MicrosandboxError::Runtime("supervisor process exited immediately".into())
    })?;

    // Close inherited FDs in the parent by dropping them.
    drop(guest_fd);
    drop(net_fds);

    // Read the startup JSON from the supervisor's stdout.
    let stdout = child.stdout.take().ok_or_else(|| {
        crate::MicrosandboxError::Runtime("failed to capture supervisor stdout".into())
    })?;

    let mut reader = tokio::io::BufReader::new(stdout);
    let mut line = String::new();
    match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        reader.read_line(&mut line),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(err)) => {
            terminate_startup_supervisor(&mut child).await;
            return Err(err.into());
        }
        Err(_) => {
            terminate_startup_supervisor(&mut child).await;
            return Err(crate::MicrosandboxError::Runtime(
                "supervisor startup timeout: no JSON received within 30 seconds".into(),
            ));
        }
    }

    let startup: StartupInfo = match serde_json::from_str(line.trim()) {
        Ok(info) => info,
        Err(_) => {
            let status = terminate_startup_supervisor(&mut child).await;
            return Err(crate::MicrosandboxError::Runtime(format!(
                "supervisor exited ({status:?}) before sending startup info \
                 (line: {line:?}, check stderr above for details)"
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

/// Create a Unix socket pair with `FD_CLOEXEC` set on both ends.
///
/// We set `FD_CLOEXEC` with `fcntl()` instead of relying on `SOCK_CLOEXEC`
/// because Darwin's libc bindings do not expose that socket type flag.
///
/// `sock_type` is typically `libc::SOCK_STREAM` (for agent channel)
/// or `libc::SOCK_DGRAM` (for Unixgram network frame relay).
fn create_socketpair(sock_type: libc::c_int) -> MicrosandboxResult<(OwnedFd, OwnedFd)> {
    let mut fds = [0i32; 2];
    let ret = unsafe { libc::socketpair(libc::AF_UNIX, sock_type, 0, fds.as_mut_ptr()) };
    if ret != 0 {
        return Err(crate::MicrosandboxError::Io(std::io::Error::last_os_error()));
    }

    let fd1 = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let fd2 = unsafe { OwnedFd::from_raw_fd(fds[1]) };

    set_cloexec(fd1.as_raw_fd())?;
    set_cloexec(fd2.as_raw_fd())?;

    // Set non-blocking mode on both ends. Tokio's AsyncFd requires
    // non-blocking fds — a blocking fd can stall the single-threaded
    // runtime on spurious epoll/kqueue wakeups. SOCK_NONBLOCK is not
    // available on macOS, so we use fcntl instead.
    set_nonblock(fd1.as_raw_fd())?;
    set_nonblock(fd2.as_raw_fd())?;

    Ok((fd1, fd2))
}

/// Set non-blocking mode on a file descriptor (preserving other flags).
fn set_nonblock(fd: RawFd) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Set the close-on-exec flag on a file descriptor (preserving other flags).
fn set_cloexec(fd: RawFd) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 {
        return Err(std::io::Error::last_os_error());
    }
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if ret == -1 {
        return Err(std::io::Error::last_os_error());
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

async fn terminate_startup_supervisor(
    child: &mut tokio::process::Child,
) -> Option<std::process::ExitStatus> {
    let _ = child.start_kill();
    child.wait().await.ok()
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

/// Push a `--mount tag:host_path[:ro]` arg pair.
fn push_mount_arg(
    args: &mut Vec<OsString>,
    guest: &str,
    host_display: &impl std::fmt::Display,
    readonly: bool,
) {
    let tag = guest_mount_tag(guest);
    let mut arg = format!("{tag}:{host_display}");
    if readonly {
        arg.push_str(":ro");
    }
    args.push(OsString::from("--mount"));
    args.push(OsString::from(arg));
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
#[allow(clippy::too_many_arguments)]
fn supervisor_cli_args(
    config: &SandboxConfig,
    sandbox_id: i32,
    db_path: &Path,
    log_dir: &Path,
    runtime_dir: &Path,
    network_config_json: Option<&str>,
    empty_rootfs_dir: &Path,
    rw_dir: &Path,
    staging_dir: &Path,
    agent_fd: RawFd,
    net_msbnet_fd: Option<RawFd>,
    net_vm_fd: Option<RawFd>,
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
    if let Some(network_config_json) = network_config_json {
        args.push(OsString::from("--network-config-json"));
        args.push(OsString::from(network_config_json));
    }
    args.push(OsString::from("--agent-fd"));
    args.push(OsString::from(agent_fd.to_string()));

    if let Some(nfd) = net_msbnet_fd {
        args.push(OsString::from("--net-msbnet-fd"));
        args.push(OsString::from(nfd.to_string()));
    }

    if let Some(nfd) = net_vm_fd {
        args.push(OsString::from("--net-vm-fd"));
        args.push(OsString::from(nfd.to_string()));
    }

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
            args.push(OsString::from("--rootfs-path"));
            args.push(path.as_os_str().to_os_string());
        }
        RootfsSource::Oci(_) => {
            args.push(OsString::from("--rootfs-upper"));
            args.push(rw_dir.as_os_str().to_os_string());
            args.push(OsString::from("--rootfs-staging"));
            args.push(staging_dir.as_os_str().to_os_string());

            // Scratch-style OCI images can legitimately have zero filesystem layers.
            let synthetic_empty_lower;
            let lowers: &[std::path::PathBuf] = if config.resolved_rootfs_layers.is_empty() {
                synthetic_empty_lower = vec![empty_rootfs_dir.to_path_buf()];
                &synthetic_empty_lower
            } else {
                &config.resolved_rootfs_layers
            };

            for layer_dir in lowers {
                args.push(OsString::from("--rootfs-lower"));
                args.push(layer_dir.as_os_str().to_os_string());
            }
        }
        RootfsSource::DiskImage {
            path,
            format,
            fstype,
        } => {
            args.push(OsString::from("--rootfs-disk"));
            args.push(path.as_os_str().to_os_string());
            args.push(OsString::from("--rootfs-disk-format"));
            args.push(OsString::from(format.as_str()));

            // Build MSB_BLOCK_ROOT env var value.
            let mut block_root_val = String::from("/dev/vda");
            if let Some(ft) = fstype {
                block_root_val.push_str(&format!(",fstype={ft}"));
            }
            args.push(OsString::from("--env"));
            args.push(OsString::from(format!(
                "{}={block_root_val}",
                microsandbox_protocol::ENV_BLOCK_ROOT
            )));
        }
    }

    // Process mounts: emit --mount args for virtiofs mounts, collect tmpfs specs.
    let mut tmpfs_val = String::new();
    for mount in &config.mounts {
        match mount {
            VolumeMount::Bind {
                host,
                guest,
                readonly,
            } => {
                push_mount_arg(&mut args, guest, &host.display(), *readonly);
            }
            VolumeMount::Named {
                name,
                guest,
                readonly,
            } => {
                let vol_path = config::config().volumes_dir().join(name);
                push_mount_arg(&mut args, guest, &vol_path.display(), *readonly);
            }
            VolumeMount::Tmpfs { guest, size_mib } => {
                if !tmpfs_val.is_empty() {
                    tmpfs_val.push(';');
                }
                tmpfs_val.push_str(guest);
                if let Some(s) = size_mib {
                    tmpfs_val.push_str(&format!(",size={s}"));
                }
            }
            VolumeMount::Backend { .. } => {
                // Backend mounts are guarded at Sandbox::create() — they cannot
                // reach this point in the subprocess path. If they do, skip them.
            }
        }
    }

    if !tmpfs_val.is_empty() {
        args.push(OsString::from("--env"));
        args.push(OsString::from(format!(
            "{}={tmpfs_val}",
            microsandbox_protocol::ENV_TMPFS
        )));
    }

    for (key, value) in &config.env {
        args.push(OsString::from("--env"));
        args.push(OsString::from(format!("{key}={value}")));
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
    use crate::{
        LogLevel,
        sandbox::{RootfsSource, SandboxBuilder},
    };

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
            None,
            Path::new("/tmp/rootfs-base"),
            Path::new("/tmp/rw"),
            Path::new("/tmp/staging"),
            9,
            None,
            None,
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
            None,
            Path::new("/tmp/rootfs-base"),
            Path::new("/tmp/rw"),
            Path::new("/tmp/staging"),
            9,
            None,
            None,
            Path::new("/tmp/libkrunfw.dylib"),
        );

        assert!(!args.iter().any(|arg| {
            matches!(
                arg.to_str(),
                Some("--error" | "--warn" | "--info" | "--debug" | "--trace")
            )
        }));
    }

    #[test]
    fn test_supervisor_cli_args_use_passthrough_for_bind_rootfs() {
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
            None,
            Path::new("/tmp/rootfs-base"),
            Path::new("/tmp/rw"),
            Path::new("/tmp/staging"),
            9,
            None,
            None,
            Path::new("/tmp/libkrunfw.dylib"),
        );

        let rendered = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(rendered.contains(&"--rootfs-path".to_string()));
        assert!(rendered.contains(&"/tmp/rootfs".to_string()));
        assert!(!rendered.contains(&"--rootfs-lower".to_string()));
        assert!(!rendered.contains(&"--rootfs-upper".to_string()));
        assert!(!rendered.contains(&"--rootfs-staging".to_string()));
    }

    #[test]
    fn test_supervisor_cli_args_use_overlay_for_oci_rootfs() {
        let mut config = SandboxBuilder::new("test")
            .image("alpine:latest")
            .build()
            .unwrap();
        assert!(matches!(config.image, RootfsSource::Oci(_)));
        config.resolved_rootfs_layers = vec!["/tmp/layer0".into(), "/tmp/layer1".into()];

        let args = supervisor_cli_args(
            &config,
            42,
            Path::new("/tmp/msb.db"),
            Path::new("/tmp/logs"),
            Path::new("/tmp/runtime"),
            None,
            Path::new("/tmp/rootfs-base"),
            Path::new("/tmp/rw"),
            Path::new("/tmp/staging"),
            9,
            None,
            None,
            Path::new("/tmp/libkrunfw.dylib"),
        );

        let rendered = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(rendered.contains(&"--rootfs-lower".to_string()));
        assert!(rendered.contains(&"/tmp/layer0".to_string()));
        assert!(rendered.contains(&"/tmp/layer1".to_string()));
        assert!(rendered.contains(&"--rootfs-upper".to_string()));
        assert!(rendered.contains(&"/tmp/rw".to_string()));
        assert!(rendered.contains(&"--rootfs-staging".to_string()));
        assert!(rendered.contains(&"/tmp/staging".to_string()));
    }

    #[test]
    fn test_supervisor_cli_args_use_overlay_for_single_oci_lower_without_index_args() {
        let mut config = SandboxBuilder::new("test")
            .image("alpine:latest")
            .build()
            .unwrap();
        assert!(matches!(config.image, RootfsSource::Oci(_)));
        config.resolved_rootfs_layers = vec!["/tmp/layer0".into()];

        let args = supervisor_cli_args(
            &config,
            42,
            Path::new("/tmp/msb.db"),
            Path::new("/tmp/logs"),
            Path::new("/tmp/runtime"),
            None,
            Path::new("/tmp/rootfs-base"),
            Path::new("/tmp/rw"),
            Path::new("/tmp/staging"),
            9,
            None,
            None,
            Path::new("/tmp/libkrunfw.dylib"),
        );

        let rendered = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(!rendered.contains(&"--rootfs-path".to_string()));
        assert!(rendered.contains(&"--rootfs-lower".to_string()));
        assert!(rendered.contains(&"/tmp/layer0".to_string()));
        assert!(rendered.contains(&"--rootfs-upper".to_string()));
        assert!(rendered.contains(&"--rootfs-staging".to_string()));
        assert!(!rendered.iter().any(|arg| arg.ends_with(".index")));
    }

    #[test]
    fn test_supervisor_cli_args_use_synthetic_lower_for_zero_layer_oci_rootfs() {
        let config = SandboxBuilder::new("test")
            .image("scratch:latest")
            .build()
            .unwrap();

        let args = supervisor_cli_args(
            &config,
            42,
            Path::new("/tmp/msb.db"),
            Path::new("/tmp/logs"),
            Path::new("/tmp/runtime"),
            None,
            Path::new("/tmp/rootfs-base"),
            Path::new("/tmp/rw"),
            Path::new("/tmp/staging"),
            9,
            None,
            None,
            Path::new("/tmp/libkrunfw.dylib"),
        );

        let rendered = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(!rendered.contains(&"--rootfs-path".to_string()));
        assert!(rendered.contains(&"--rootfs-lower".to_string()));
        assert!(rendered.contains(&"/tmp/rootfs-base".to_string()));
    }

    #[test]
    fn test_supervisor_cli_args_inject_tmpfs_env_var() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/tmp", |m| m.tmpfs().size(256u32))
            .volume("/var/tmp", |m| m.tmpfs())
            .build()
            .unwrap();

        let args = supervisor_cli_args(
            &config,
            42,
            Path::new("/tmp/msb.db"),
            Path::new("/tmp/logs"),
            Path::new("/tmp/runtime"),
            None,
            Path::new("/tmp/rootfs-base"),
            Path::new("/tmp/rw"),
            Path::new("/tmp/staging"),
            9,
            None,
            None,
            Path::new("/tmp/libkrunfw.dylib"),
        );

        let rendered = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert!(rendered.contains(&"MSB_TMPFS=/tmp,size=256;/var/tmp".to_string()));
    }

    #[test]
    fn test_supervisor_cli_args_omit_tmpfs_env_var_when_no_tmpfs() {
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
            None,
            Path::new("/tmp/rootfs-base"),
            Path::new("/tmp/rw"),
            Path::new("/tmp/staging"),
            9,
            None,
            None,
            Path::new("/tmp/libkrunfw.dylib"),
        );

        let rendered = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert!(!rendered.iter().any(|a| a.starts_with("MSB_TMPFS=")));
    }

    #[test]
    fn test_supervisor_cli_args_disk_image_with_fstype() {
        let config = SandboxBuilder::new("test")
            .image(|i: crate::sandbox::ImageBuilder| i.disk("/tmp/ubuntu.qcow2").fstype("ext4"))
            .build()
            .unwrap();

        assert!(matches!(config.image, RootfsSource::DiskImage { .. }));

        let args = supervisor_cli_args(
            &config,
            42,
            Path::new("/tmp/msb.db"),
            Path::new("/tmp/logs"),
            Path::new("/tmp/runtime"),
            None,
            Path::new("/tmp/rootfs-base"),
            Path::new("/tmp/rw"),
            Path::new("/tmp/staging"),
            9,
            None,
            None,
            Path::new("/tmp/libkrunfw.dylib"),
        );

        let rendered = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert!(rendered.contains(&"--rootfs-disk".to_string()));
        assert!(rendered.contains(&"/tmp/ubuntu.qcow2".to_string()));
        assert!(rendered.contains(&"--rootfs-disk-format".to_string()));
        assert!(rendered.contains(&"qcow2".to_string()));
        assert!(rendered.contains(&"MSB_BLOCK_ROOT=/dev/vda,fstype=ext4".to_string()));

        // Should not contain bind or overlay args.
        assert!(!rendered.contains(&"--rootfs-path".to_string()));
        assert!(!rendered.contains(&"--rootfs-lower".to_string()));
        assert!(!rendered.contains(&"--rootfs-upper".to_string()));
        assert!(!rendered.contains(&"--rootfs-staging".to_string()));
    }

    #[test]
    fn test_supervisor_cli_args_disk_image_without_fstype() {
        let config = SandboxBuilder::new("test")
            .image(|i: crate::sandbox::ImageBuilder| i.disk("/tmp/alpine.raw"))
            .build()
            .unwrap();

        assert!(matches!(config.image, RootfsSource::DiskImage { .. }));

        let args = supervisor_cli_args(
            &config,
            42,
            Path::new("/tmp/msb.db"),
            Path::new("/tmp/logs"),
            Path::new("/tmp/runtime"),
            None,
            Path::new("/tmp/rootfs-base"),
            Path::new("/tmp/rw"),
            Path::new("/tmp/staging"),
            9,
            None,
            None,
            Path::new("/tmp/libkrunfw.dylib"),
        );

        let rendered = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert!(rendered.contains(&"--rootfs-disk".to_string()));
        assert!(rendered.contains(&"/tmp/alpine.raw".to_string()));
        assert!(rendered.contains(&"--rootfs-disk-format".to_string()));
        assert!(rendered.contains(&"raw".to_string()));
        assert!(rendered.contains(&"MSB_BLOCK_ROOT=/dev/vda".to_string()));

        // Should not contain bind or overlay args.
        assert!(!rendered.contains(&"--rootfs-path".to_string()));
        assert!(!rendered.contains(&"--rootfs-lower".to_string()));
    }
}

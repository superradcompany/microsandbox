//! Spawning the sandbox process.
//!
//! [`spawn_sandbox`] assembles CLI arguments from [`SandboxConfig`],
//! fork+execs `msb sandbox`, and reads the startup JSON to obtain the
//! sandbox process PID. The sandbox process runs the VMM and agent relay
//! internally.

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{ffi::OsString, path::Path, process::Stdio};

use serde::Deserialize;
use tokio::{io::AsyncBufReadExt, process::Command};

use crate::{
    MicrosandboxResult, config,
    runtime::handle::ProcessHandle,
    sandbox::{RootfsSource, SandboxConfig, VolumeMount},
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// JSON structure read from the sandbox process stdout on startup.
#[derive(Debug, Deserialize)]
struct StartupInfo {
    pid: u32,
}

/// How the sandbox process should behave relative to the creating process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpawnMode {
    /// The creating process keeps the sandbox handle and agent bridge alive.
    Attached,

    /// The sandbox must survive after the creating process exits.
    Detached,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Spawn the sandbox process for a sandbox.
///
/// Returns a [`ProcessHandle`] and the path to the agent relay socket.
///
/// The function:
/// 1. Resolves the `msb` binary path
/// 2. Creates sandbox directories (logs, runtime, scripts)
/// 3. Builds CLI arguments from the config
/// 4. Spawns the hidden `msb sandbox` process with `--agent-sock` for the relay
/// 5. Reads startup JSON from stdout to get child PIDs
pub async fn spawn_sandbox(
    config: &SandboxConfig,
    sandbox_id: i32,
    mode: SpawnMode,
) -> MicrosandboxResult<(ProcessHandle, std::path::PathBuf)> {
    // Resolve paths.
    let msb_path = config::resolve_msb_path()?;
    let libkrunfw_path = config::resolve_libkrunfw_path()?;
    tracing::debug!(
        msb = %msb_path.display(),
        libkrunfw = %libkrunfw_path.display(),
        sandbox = %config.name,
        cpus = config.cpus,
        memory_mib = config.memory_mib,
        mode = ?mode,
        "spawn_sandbox: resolved paths"
    );

    let global = config::config();
    let sandbox_dir = global.sandboxes_dir().join(&config.name);
    let log_dir = sandbox_dir.join("logs");
    let runtime_dir = sandbox_dir.join("runtime");
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
        #[cfg(unix)]
        tokio::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755)).await?;
    }

    // Compute the agent relay socket path.
    let agent_sock_path = runtime_dir.join("agent.sock");

    // Build the command.
    let mut cmd = Command::new(&msb_path);
    cmd.args(sandbox_cli_args(
        config,
        sandbox_id,
        &db_path,
        &log_dir,
        &runtime_dir,
        &empty_rootfs_dir,
        &rw_dir,
        &staging_dir,
        &agent_sock_path,
        &libkrunfw_path,
    ));

    // Prevent the sandbox process from inheriting the parent's terminal on
    // stdin — the VMM's implicit console auto-detects terminals and sets raw
    // mode, which corrupts the parent's terminal output (\n without \r).
    cmd.stdin(Stdio::null());

    if mode == SpawnMode::Detached {
        // Detached sandboxes outlive the creating CLI process, so the
        // sandbox must not stay coupled to the foreground job or terminal.
        cmd.process_group(0);
    }

    // Capture stdout (for startup JSON), inherit stderr so errors are visible.
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::inherit());

    // Spawn the sandbox process.
    let mut child = cmd.spawn()?;

    let _pid = child.id().ok_or_else(|| {
        crate::MicrosandboxError::Runtime("sandbox process exited immediately".into())
    })?;
    tracing::debug!(pid = _pid, sandbox = %config.name, "spawn_sandbox: process started");

    // Read the startup JSON from stdout.
    let stdout = child.stdout.take().ok_or_else(|| {
        crate::MicrosandboxError::Runtime("failed to capture sandbox stdout".into())
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
            terminate_startup_process(&mut child).await;
            return Err(err.into());
        }
        Err(_) => {
            terminate_startup_process(&mut child).await;
            return Err(crate::MicrosandboxError::Runtime(
                "sandbox startup timeout: no JSON received within 30 seconds".into(),
            ));
        }
    }

    let startup: StartupInfo = match serde_json::from_str(line.trim()) {
        Ok(info) => info,
        Err(_) => {
            let status = terminate_startup_process(&mut child).await;
            tracing::debug!(
                raw_line = ?line,
                exit_status = ?status,
                "spawn_sandbox: failed to parse startup JSON"
            );
            return Err(crate::MicrosandboxError::Runtime(format!(
                "sandbox process exited ({status:?}) before sending startup info \
                 (line: {line:?}, check stderr above for details)"
            )));
        }
    };

    tracing::debug!(
        vm_pid = startup.pid,
        agent_sock = %agent_sock_path.display(),
        "spawn_sandbox: startup JSON received"
    );

    let handle = ProcessHandle::new(startup.pid, config.name.clone(), child);

    Ok((handle, agent_sock_path))
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

async fn terminate_startup_process(
    child: &mut tokio::process::Child,
) -> Option<std::process::ExitStatus> {
    let _ = child.start_kill();
    child.wait().await.ok()
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

/// Append a `tag:guest_path[:ro]` entry to the `MSB_MOUNTS` env var value.
fn push_mounts_spec(mounts_val: &mut String, guest: &str, readonly: bool) {
    if !mounts_val.is_empty() {
        mounts_val.push(';');
    }
    let tag = guest_mount_tag(guest);
    mounts_val.push_str(&tag);
    mounts_val.push(':');
    mounts_val.push_str(guest);
    if readonly {
        mounts_val.push_str(":ro");
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

/// Build the `msb sandbox` CLI args for a sandbox.
#[allow(clippy::too_many_arguments)]
fn sandbox_cli_args(
    config: &SandboxConfig,
    sandbox_id: i32,
    db_path: &Path,
    log_dir: &Path,
    runtime_dir: &Path,
    empty_rootfs_dir: &Path,
    rw_dir: &Path,
    staging_dir: &Path,
    agent_sock_path: &Path,
    libkrunfw_path: &Path,
) -> Vec<OsString> {
    let mut args = vec![OsString::from("sandbox")];

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
    args.push(OsString::from("--agent-sock"));
    args.push(agent_sock_path.as_os_str().to_os_string());

    let sp = &config.policy;
    if let Some(max_dur) = sp.max_duration_secs {
        args.push(OsString::from("--max-duration"));
        args.push(OsString::from(max_dur.to_string()));
    }
    if let Some(idle) = sp.idle_timeout_secs {
        args.push(OsString::from("--idle-timeout"));
        args.push(OsString::from(idle.to_string()));
    }

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

    // Process mounts: emit --mount args for virtiofs mounts, collect tmpfs and
    // virtiofs guest-side mount specs as env vars for agentd.
    let mut tmpfs_val = String::new();
    let mut mounts_val = String::new();
    for mount in &config.mounts {
        match mount {
            VolumeMount::Bind {
                host,
                guest,
                readonly,
            } => {
                push_mount_arg(&mut args, guest, &host.display(), *readonly);
                push_mounts_spec(&mut mounts_val, guest, *readonly);
            }
            VolumeMount::Named {
                name,
                guest,
                readonly,
            } => {
                let vol_path = config::config().volumes_dir().join(name);
                push_mount_arg(&mut args, guest, &vol_path.display(), *readonly);
                push_mounts_spec(&mut mounts_val, guest, *readonly);
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
        }
    }

    if !tmpfs_val.is_empty() {
        args.push(OsString::from("--env"));
        args.push(OsString::from(format!(
            "{}={tmpfs_val}",
            microsandbox_protocol::ENV_TMPFS
        )));
    }

    if !mounts_val.is_empty() {
        args.push(OsString::from("--env"));
        args.push(OsString::from(format!(
            "{}={mounts_val}",
            microsandbox_protocol::ENV_MOUNTS
        )));
    }

    // Network configuration.
    #[cfg(feature = "net")]
    {
        let net_json =
            serde_json::to_string(&config.network).expect("failed to serialize network config");
        args.push(OsString::from("--network-config"));
        args.push(OsString::from(net_json));
        args.push(OsString::from("--sandbox-slot"));
        args.push(OsString::from(sandbox_id.to_string()));
    }

    for (key, value) in &config.env {
        args.push(OsString::from("--env"));
        args.push(OsString::from(format!("{key}={value}")));
    }

    if let Some(ref user) = config.user {
        args.push(OsString::from("--env"));
        args.push(OsString::from(format!(
            "{}={user}",
            microsandbox_protocol::ENV_USER
        )));
    }

    // Hostname: explicit value or fall back to sandbox name.
    {
        let hostname = config.hostname.as_deref().unwrap_or(&config.name);
        args.push(OsString::from("--env"));
        args.push(OsString::from(format!(
            "{}={hostname}",
            microsandbox_protocol::ENV_HOSTNAME
        )));
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

    use super::sandbox_cli_args;
    use crate::{
        LogLevel,
        sandbox::{RootfsSource, SandboxBuilder},
    };

    #[test]
    fn test_sandbox_cli_args_include_selected_log_level() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .log_level(LogLevel::Debug)
            .build()
            .unwrap();

        let args = sandbox_cli_args(
            &config,
            42,
            Path::new("/tmp/msb.db"),
            Path::new("/tmp/logs"),
            Path::new("/tmp/runtime"),
            Path::new("/tmp/rootfs-base"),
            Path::new("/tmp/rw"),
            Path::new("/tmp/staging"),
            Path::new("/tmp/agent.sock"),
            Path::new("/tmp/libkrunfw.dylib"),
        );

        assert!(args.iter().any(|arg| arg == "--debug"));
    }

    #[test]
    fn test_sandbox_cli_args_are_silent_by_default() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .build()
            .unwrap();

        let args = sandbox_cli_args(
            &config,
            42,
            Path::new("/tmp/msb.db"),
            Path::new("/tmp/logs"),
            Path::new("/tmp/runtime"),
            Path::new("/tmp/rootfs-base"),
            Path::new("/tmp/rw"),
            Path::new("/tmp/staging"),
            Path::new("/tmp/agent.sock"),
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
    fn test_sandbox_cli_args_include_agent_sock_path() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .build()
            .unwrap();

        let args = sandbox_cli_args(
            &config,
            42,
            Path::new("/tmp/msb.db"),
            Path::new("/tmp/logs"),
            Path::new("/tmp/runtime"),
            Path::new("/tmp/rootfs-base"),
            Path::new("/tmp/rw"),
            Path::new("/tmp/staging"),
            Path::new("/tmp/agent.sock"),
            Path::new("/tmp/libkrunfw.dylib"),
        );

        let rendered = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(
            rendered
                .windows(2)
                .any(|pair| pair == ["--agent-sock", "/tmp/agent.sock"])
        );
    }

    #[test]
    fn test_sandbox_cli_args_use_passthrough_for_bind_rootfs() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .build()
            .unwrap();

        let args = sandbox_cli_args(
            &config,
            42,
            Path::new("/tmp/msb.db"),
            Path::new("/tmp/logs"),
            Path::new("/tmp/runtime"),
            Path::new("/tmp/rootfs-base"),
            Path::new("/tmp/rw"),
            Path::new("/tmp/staging"),
            Path::new("/tmp/agent.sock"),
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
    fn test_sandbox_cli_args_use_overlay_for_oci_rootfs() {
        let mut config = SandboxBuilder::new("test").image("alpine").build().unwrap();
        assert!(matches!(config.image, RootfsSource::Oci(_)));
        config.resolved_rootfs_layers = vec!["/tmp/layer0".into(), "/tmp/layer1".into()];

        let args = sandbox_cli_args(
            &config,
            42,
            Path::new("/tmp/msb.db"),
            Path::new("/tmp/logs"),
            Path::new("/tmp/runtime"),
            Path::new("/tmp/rootfs-base"),
            Path::new("/tmp/rw"),
            Path::new("/tmp/staging"),
            Path::new("/tmp/agent.sock"),
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
    fn test_sandbox_cli_args_use_overlay_for_single_oci_lower_without_index_args() {
        let mut config = SandboxBuilder::new("test").image("alpine").build().unwrap();
        assert!(matches!(config.image, RootfsSource::Oci(_)));
        config.resolved_rootfs_layers = vec!["/tmp/layer0".into()];

        let args = sandbox_cli_args(
            &config,
            42,
            Path::new("/tmp/msb.db"),
            Path::new("/tmp/logs"),
            Path::new("/tmp/runtime"),
            Path::new("/tmp/rootfs-base"),
            Path::new("/tmp/rw"),
            Path::new("/tmp/staging"),
            Path::new("/tmp/agent.sock"),
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
    fn test_sandbox_cli_args_use_synthetic_lower_for_zero_layer_oci_rootfs() {
        let config = SandboxBuilder::new("test")
            .image("scratch")
            .build()
            .unwrap();

        let args = sandbox_cli_args(
            &config,
            42,
            Path::new("/tmp/msb.db"),
            Path::new("/tmp/logs"),
            Path::new("/tmp/runtime"),
            Path::new("/tmp/rootfs-base"),
            Path::new("/tmp/rw"),
            Path::new("/tmp/staging"),
            Path::new("/tmp/agent.sock"),
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
    fn test_sandbox_cli_args_inject_tmpfs_env_var() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/tmp", |m| m.tmpfs().size(256u32))
            .volume("/var/tmp", |m| m.tmpfs())
            .build()
            .unwrap();

        let args = sandbox_cli_args(
            &config,
            42,
            Path::new("/tmp/msb.db"),
            Path::new("/tmp/logs"),
            Path::new("/tmp/runtime"),
            Path::new("/tmp/rootfs-base"),
            Path::new("/tmp/rw"),
            Path::new("/tmp/staging"),
            Path::new("/tmp/agent.sock"),
            Path::new("/tmp/libkrunfw.dylib"),
        );

        let rendered = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert!(rendered.contains(&"MSB_TMPFS=/tmp,size=256;/var/tmp".to_string()));
    }

    #[test]
    fn test_sandbox_cli_args_omit_tmpfs_env_var_when_no_tmpfs() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .build()
            .unwrap();

        let args = sandbox_cli_args(
            &config,
            42,
            Path::new("/tmp/msb.db"),
            Path::new("/tmp/logs"),
            Path::new("/tmp/runtime"),
            Path::new("/tmp/rootfs-base"),
            Path::new("/tmp/rw"),
            Path::new("/tmp/staging"),
            Path::new("/tmp/agent.sock"),
            Path::new("/tmp/libkrunfw.dylib"),
        );

        let rendered = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert!(!rendered.iter().any(|a| a.starts_with("MSB_TMPFS=")));
    }

    #[test]
    fn test_sandbox_cli_args_disk_image_with_fstype() {
        let config = SandboxBuilder::new("test")
            .image(|i: crate::sandbox::ImageBuilder| i.disk("/tmp/ubuntu.qcow2").fstype("ext4"))
            .build()
            .unwrap();

        assert!(matches!(config.image, RootfsSource::DiskImage { .. }));

        let args = sandbox_cli_args(
            &config,
            42,
            Path::new("/tmp/msb.db"),
            Path::new("/tmp/logs"),
            Path::new("/tmp/runtime"),
            Path::new("/tmp/rootfs-base"),
            Path::new("/tmp/rw"),
            Path::new("/tmp/staging"),
            Path::new("/tmp/agent.sock"),
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
    fn test_sandbox_cli_args_disk_image_without_fstype() {
        let config = SandboxBuilder::new("test")
            .image(|i: crate::sandbox::ImageBuilder| i.disk("/tmp/alpine.raw"))
            .build()
            .unwrap();

        assert!(matches!(config.image, RootfsSource::DiskImage { .. }));

        let args = sandbox_cli_args(
            &config,
            42,
            Path::new("/tmp/msb.db"),
            Path::new("/tmp/logs"),
            Path::new("/tmp/runtime"),
            Path::new("/tmp/rootfs-base"),
            Path::new("/tmp/rw"),
            Path::new("/tmp/staging"),
            Path::new("/tmp/agent.sock"),
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

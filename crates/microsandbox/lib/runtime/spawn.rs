//! Spawning the sandbox process.
//!
//! [`spawn_sandbox`] assembles CLI arguments from [`SandboxConfig`],
//! fork+execs `msb sandbox`, and reads the startup JSON to obtain the
//! sandbox process PID. The sandbox process runs the VMM and agent relay
//! internally.

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    collections::HashMap,
    ffi::OsString,
    path::{Path, PathBuf},
    process::Stdio,
};

use rand::RngExt;
use serde::Deserialize;
use tempfile::TempDir;
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
) -> MicrosandboxResult<(ProcessHandle, PathBuf)> {
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

    // Stage file bind mounts: each file gets its own isolated directory so
    // that virtio-fs (which requires directories) can share it without
    // exposing adjacent files on the host.
    let (staged_file_mounts, file_mounts_staging) = stage_file_mounts(config).await?;

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
        &staged_file_mounts,
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

    let handle = ProcessHandle::new(startup.pid, config.name.clone(), child, file_mounts_staging);

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

/// Scan `config.mounts` for file bind mounts and stage each file in its own
/// isolated directory inside an ephemeral [`TempDir`].
///
/// Returns a map from guest path to `(file_mount_dir, filename, tag)` for
/// each staged file, plus the `TempDir` handle that must be kept alive for
/// the VM's lifetime.
async fn stage_file_mounts(
    config: &SandboxConfig,
) -> MicrosandboxResult<(HashMap<String, (PathBuf, String, String)>, Option<TempDir>)> {
    // Collect file bind mounts first so we can skip TempDir creation when
    // there are none.
    let file_mounts: Vec<_> = config
        .mounts
        .iter()
        .filter_map(|m| match m {
            VolumeMount::Bind {
                host,
                guest,
                readonly,
            } if host.is_file() => Some((host, guest, *readonly)),
            _ => None,
        })
        .collect();

    if file_mounts.is_empty() {
        return Ok((HashMap::new(), None));
    }

    let tempdir = tempfile::tempdir()?;
    let mut staged = HashMap::new();

    for (host, guest, readonly) in file_mounts {
        // Generate a random tag to avoid collisions.
        let id: u32 = rand::rng().random();
        let tag = format!("fm_{id:08x}");

        let file_mount_dir = tempdir.path().join(&tag);
        tokio::fs::create_dir_all(&file_mount_dir).await?;

        let filename_os = host.file_name().ok_or_else(|| {
            crate::MicrosandboxError::InvalidConfig(format!(
                "file mount has no filename: {}",
                host.display()
            ))
        })?;

        let filename = filename_os.to_str().ok_or_else(|| {
            crate::MicrosandboxError::InvalidConfig(format!(
                "file mount filename is not valid UTF-8: {}",
                host.display()
            ))
        })?;

        // The MSB_FILE_MOUNTS protocol uses `:` and `;` as delimiters.
        if filename.contains(':') || filename.contains(';') {
            return Err(crate::MicrosandboxError::InvalidConfig(format!(
                "file mount filename must not contain ':' or ';': {filename}"
            )));
        }

        let target = file_mount_dir.join(filename);

        // Hard-link preserves the same inode — writes in the guest propagate
        // to the host and vice-versa. Falls back to copy for cross-filesystem
        // mounts (different device IDs).
        match tokio::fs::hard_link(host, &target).await {
            Ok(()) => {
                tracing::debug!(
                    host = %host.display(),
                    file_mount_dir = %target.display(),
                    "file mount: hard-linked"
                );
            }
            Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
                if !readonly {
                    tracing::warn!(
                        host = %host.display(),
                        file_mount_dir = %target.display(),
                        "file mount: cross-filesystem, falling back to copy \
                         (guest writes will NOT propagate to host)"
                    );
                } else {
                    tracing::debug!(
                        host = %host.display(),
                        file_mount_dir = %target.display(),
                        "file mount: cross-filesystem, copying (read-only)"
                    );
                }
                tokio::fs::copy(host, &target).await?;
            }
            Err(e) => return Err(e.into()),
        }

        staged.insert(guest.clone(), (file_mount_dir, filename.to_string(), tag));
    }

    Ok((staged, Some(tempdir)))
}

/// Push a `--mount tag:host_path[:ro]` arg pair.
fn push_dir_mount_arg(
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

/// Append a `tag:guest_path[:ro]` entry to the `MSB_DIR_MOUNTS` env var value.
fn push_dir_mounts_spec(dir_mounts_val: &mut String, guest: &str, readonly: bool) {
    if !dir_mounts_val.is_empty() {
        dir_mounts_val.push(';');
    }
    let tag = guest_mount_tag(guest);
    dir_mounts_val.push_str(&tag);
    dir_mounts_val.push(':');
    dir_mounts_val.push_str(guest);
    if readonly {
        dir_mounts_val.push_str(":ro");
    }
}

/// Push a `--mount fm_tag:file_mount_dir[:ro]` arg pair.
fn push_file_mount_arg(args: &mut Vec<OsString>, tag: &str, file_mount_dir: &Path, readonly: bool) {
    let mut arg = format!("{tag}:{}", file_mount_dir.display());
    if readonly {
        arg.push_str(":ro");
    }
    args.push(OsString::from("--mount"));
    args.push(OsString::from(arg));
}

/// Append a `tag:filename:guest_path[:ro]` entry to the `MSB_FILE_MOUNTS` env var value.
fn push_file_mounts_spec(
    file_mounts_val: &mut String,
    tag: &str,
    filename: &str,
    guest: &str,
    readonly: bool,
) {
    if !file_mounts_val.is_empty() {
        file_mounts_val.push(';');
    }
    file_mounts_val.push_str(tag);
    file_mounts_val.push(':');
    file_mounts_val.push_str(filename);
    file_mounts_val.push(':');
    file_mounts_val.push_str(guest);
    if readonly {
        file_mounts_val.push_str(":ro");
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
    staged_file_mounts: &HashMap<String, (PathBuf, String, String)>,
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
    args.push(OsString::from("--db-connect-timeout"));
    args.push(OsString::from(
        config::config().database.connect_timeout_secs.to_string(),
    ));
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
            let lowers: &[PathBuf] = if config.resolved_rootfs_layers.is_empty() {
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
    let mut dir_mounts_val = String::new();
    let mut file_mounts_val = String::new();
    for mount in &config.mounts {
        match mount {
            VolumeMount::Bind {
                host,
                guest,
                readonly,
            } => {
                if let Some((file_mount_dir, filename, tag)) = staged_file_mounts.get(guest) {
                    push_file_mount_arg(&mut args, tag, file_mount_dir, *readonly);
                    push_file_mounts_spec(&mut file_mounts_val, tag, filename, guest, *readonly);
                } else {
                    push_dir_mount_arg(&mut args, guest, &host.display(), *readonly);
                    push_dir_mounts_spec(&mut dir_mounts_val, guest, *readonly);
                }
            }
            VolumeMount::Named {
                name,
                guest,
                readonly,
            } => {
                let vol_path = config::config().volumes_dir().join(name);
                push_dir_mount_arg(&mut args, guest, &vol_path.display(), *readonly);
                push_dir_mounts_spec(&mut dir_mounts_val, guest, *readonly);
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

    if !dir_mounts_val.is_empty() {
        args.push(OsString::from("--env"));
        args.push(OsString::from(format!(
            "{}={dir_mounts_val}",
            microsandbox_protocol::ENV_DIR_MOUNTS
        )));
    }

    if !file_mounts_val.is_empty() {
        args.push(OsString::from("--env"));
        args.push(OsString::from(format!(
            "{}={file_mounts_val}",
            microsandbox_protocol::ENV_FILE_MOUNTS
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
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};

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
            &HashMap::new(),
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
            &HashMap::new(),
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
            &HashMap::new(),
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
            &HashMap::new(),
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
            &HashMap::new(),
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
            &HashMap::new(),
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
            &HashMap::new(),
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
            &HashMap::new(),
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
            &HashMap::new(),
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
            .image_with(|i| i.disk("/tmp/ubuntu.qcow2").fstype("ext4"))
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
            &HashMap::new(),
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
            .image_with(|i| i.disk("/tmp/alpine.raw"))
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
            &HashMap::new(),
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

    #[test]
    fn test_sandbox_cli_args_file_mount_generates_correct_args() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/guest/config.txt", |m| m.bind("/host/config.txt"))
            .build()
            .unwrap();

        let mut staged_file_mounts = HashMap::new();
        staged_file_mounts.insert(
            "/guest/config.txt".to_string(),
            (
                PathBuf::from("/tmp/staging/fm_aabbccdd"),
                "config.txt".to_string(),
                "fm_aabbccdd".to_string(),
            ),
        );

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
            &staged_file_mounts,
        );

        let rendered = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        // File mount should use staging dir in --mount.
        assert!(
            rendered
                .windows(2)
                .any(|pair| pair[0] == "--mount"
                    && pair[1] == "fm_aabbccdd:/tmp/staging/fm_aabbccdd")
        );
        // MSB_FILE_MOUNTS should contain the spec.
        assert!(
            rendered
                .contains(&"MSB_FILE_MOUNTS=fm_aabbccdd:config.txt:/guest/config.txt".to_string())
        );
        // MSB_DIR_MOUNTS should NOT contain the file mount.
        assert!(!rendered.iter().any(|a| a.starts_with("MSB_DIR_MOUNTS=")));
    }

    #[test]
    fn test_sandbox_cli_args_mixed_file_and_dir_mounts() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/data", |m| m.bind("/host/data"))
            .volume("/guest/file.txt", |m| m.bind("/host/file.txt"))
            .build()
            .unwrap();

        let mut staged_file_mounts = HashMap::new();
        staged_file_mounts.insert(
            "/guest/file.txt".to_string(),
            (
                PathBuf::from("/tmp/staging/fm_11223344"),
                "file.txt".to_string(),
                "fm_11223344".to_string(),
            ),
        );

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
            &staged_file_mounts,
        );

        let rendered = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        // Directory mount in MSB_DIR_MOUNTS.
        assert!(rendered.contains(&"MSB_DIR_MOUNTS=data:/data".to_string()));
        // File mount in MSB_FILE_MOUNTS.
        assert!(
            rendered.contains(&"MSB_FILE_MOUNTS=fm_11223344:file.txt:/guest/file.txt".to_string())
        );
    }
}

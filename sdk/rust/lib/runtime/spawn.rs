//! Spawning the sandbox process.
//!
//! [`spawn_sandbox`] assembles CLI arguments from [`SandboxConfig`],
//! fork+execs `msb sandbox`, and reads the startup JSON to obtain the
//! sandbox process PID. The sandbox process runs the VMM and agent relay
//! internally.

#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::fd::{FromRawFd, OwnedFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    ffi::{OsStr, OsString},
    fmt::Write,
    fs::File,
    io::{Seek, SeekFrom, Write as IoWrite},
    path::{Path, PathBuf},
    process::Stdio,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
#[cfg(windows)]
use rand::Rng;
use rand::RngExt;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use tempfile::TempDir;
#[cfg(windows)]
use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt},
    process::Command,
};
#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation,
};
#[cfg(windows)]
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
#[cfg(windows)]
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS,
};

use microsandbox_image::{Digest, GlobalCache};
use microsandbox_metrics::{MetricsRegistry, ReserveSlot, SlotReservation};
use microsandbox_protocol::{
    ENV_BLOCK_ROOT, ENV_DIR_MOUNTS, ENV_DISK_MOUNTS, ENV_FILE_MOUNTS, ENV_HANDOFF_INIT,
    ENV_HANDOFF_INIT_ARGS, ENV_HANDOFF_INIT_CWD, ENV_HANDOFF_INIT_ENV, ENV_HOSTNAME,
    ENV_SECURITY_PROFILE, ENV_TMPFS, ENV_USER,
};
use microsandbox_runtime::launch::{LaunchConfig, Lifecycle};
use microsandbox_runtime::vm::{MetricsSlotHandoff, StartupCommand};
use microsandbox_types::SandboxLogLevel;
use microsandbox_utils::{DB_FILENAME, DB_SUBDIR};

use crate::runtime::handle::ProcessHandle;
#[cfg(windows)]
use crate::runtime::handle::WindowsJob;
use crate::{
    MicrosandboxError, MicrosandboxResult,
    backend::LocalBackend,
    db::entity::volume as volume_entity,
    runtime::handle::MetricsReservationCleanup,
    sandbox::{
        DiskImageFormat, HostPermissions, MountOptions, NamedVolumeMode, Rlimit, RootfsSource,
        SandboxConfig, StatVirtualization, VolumeMount, validate_named_disk_mount_options,
    },
    volume::{
        VolumeConfig, VolumeKind, lock_volume_name, materialize_volume_path,
        validate_volume_config, validate_volume_name,
    },
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

#[cfg(target_os = "linux")]
static SIGCHLD_ALT_STACK_INIT: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

const AGENT_SOCKET_HASH_HEX_LEN: usize = 32;
#[cfg(windows)]
const STARTUP_PIPE_HASH_HEX_LEN: usize = 32;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// JSON structure read from the sandbox process stdout on startup.
#[derive(Debug, Deserialize)]
struct StartupInfo {
    pid: u32,
}

#[derive(Clone)]
struct MetricsReservation {
    shm_name: String,
    slot: u32,
    generation: u64,
    registry: MetricsRegistry,
}

#[cfg(unix)]
struct Pipe {
    read_fd: OwnedFd,
    write_fd: OwnedFd,
}

#[cfg(windows)]
struct StartupPipe {
    name: OsString,
    server: NamedPipeServer,
}

#[cfg(windows)]
#[derive(Debug)]
struct HandleInheritState {
    handle: HANDLE,
    flags: u32,
}

#[cfg(windows)]
#[derive(Debug)]
struct StdioInheritGuard {
    states: Vec<HandleInheritState>,
}

/// Local storage metadata for a named volume mounted by a sandbox.
#[derive(Clone, Debug)]
struct ResolvedNamedVolume {
    kind: VolumeKind,
    path: PathBuf,
    format: Option<DiskImageFormat>,
    fstype: Option<String>,
    quota_mib: Option<u32>,
}

#[derive(Clone, Debug)]
struct DiskLockRequest {
    path: PathBuf,
    readonly: bool,
    label: String,
    volume_name: Option<String>,
}

/// Named volume row and path created for one sandbox create attempt.
#[derive(Debug)]
pub(crate) struct CreatedNamedVolume {
    pub(crate) id: i32,
    pub(crate) path: PathBuf,
}

/// Sandbox-create named volume preflight state.
#[derive(Debug)]
pub(crate) struct EnsuredNamedVolumes {
    created: Vec<CreatedNamedVolume>,
    _locks: Vec<File>,
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
// Methods
//--------------------------------------------------------------------------------------------------

impl EnsuredNamedVolumes {
    pub(crate) fn is_empty(&self) -> bool {
        self.created.is_empty()
    }
}

#[cfg(windows)]
impl StdioInheritGuard {
    fn new() -> MicrosandboxResult<Self> {
        let mut states = Vec::new();

        for std_handle in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
            let handle = unsafe { GetStdHandle(std_handle) };
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                continue;
            }
            if states
                .iter()
                .any(|state: &HandleInheritState| state.handle == handle)
            {
                continue;
            }

            let mut flags = 0u32;
            if unsafe { GetHandleInformation(handle, &mut flags) } == 0 {
                continue;
            }
            if flags & HANDLE_FLAG_INHERIT == 0 {
                continue;
            }

            // A redirected `msb create` can receive inheritable stdout/stderr
            // pipe handles from its own parent. Detached sandbox children must
            // not keep those pipes alive after the launcher exits.
            if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            states.push(HandleInheritState { handle, flags });
        }

        Ok(Self { states })
    }
}

#[cfg(windows)]
impl Drop for StdioInheritGuard {
    fn drop(&mut self) {
        for state in self.states.iter().rev() {
            let inherit = state.flags & HANDLE_FLAG_INHERIT;
            if unsafe { SetHandleInformation(state.handle, HANDLE_FLAG_INHERIT, inherit) } == 0 {
                tracing::debug!(
                    error = %std::io::Error::last_os_error(),
                    "failed to restore stdio handle inheritance flag"
                );
            }
        }
    }
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
    local: &LocalBackend,
    config: &SandboxConfig,
    sandbox_id: i32,
    mode: SpawnMode,
) -> MicrosandboxResult<(ProcessHandle, PathBuf)> {
    // Reference-model secrets store only a host-side source reference in the
    // durable config; resolve the actual values now so they travel to the
    // sandbox process on the private launch-config fd without ever being
    // persisted.
    #[cfg(feature = "net")]
    let resolved_config = crate::sandbox::config::resolve_config_secret_sources(config)?;
    #[cfg(feature = "net")]
    let config = resolved_config.as_ref().unwrap_or(config);

    // libkrunfw is process-level (one dylib per process address space). The
    // resolver consults MSB_LIBKRUNFW_PATH env, then SDK_LIBKRUNFW_PATH static,
    // then config.paths.libkrunfw, then filesystem fallbacks.
    let global = local.config();
    let msb_path = global.resolve_msb_path()?;
    let libkrunfw_path = global.resolve_libkrunfw_path()?;
    #[cfg(windows)]
    crate::setup::verify_windows_host_prerequisites()?;
    tracing::debug!(
        msb = %msb_path.display(),
        libkrunfw = %libkrunfw_path.display(),
        sandbox = %config.spec.name,
        cpus = config.spec.resources.vcpus,
        memory_mib = config.spec.resources.memory_mib,
        mode = ?mode,
        "spawn_sandbox: resolved paths"
    );

    let sandbox_dir = global.sandboxes_dir().join(&config.spec.name);
    let log_dir = sandbox_dir.join("logs");
    let runtime_dir = sandbox_dir.join("runtime");
    let scripts_dir = runtime_dir.join("scripts");
    let db_dir = global.home().join(DB_SUBDIR);
    let db_path = db_dir.join(DB_FILENAME);

    // Create directories concurrently.
    tokio::try_join!(
        tokio::fs::create_dir_all(&log_dir),
        tokio::fs::create_dir_all(&scripts_dir),
    )?;

    // Stopped-safe preparation: a `--next-start` upper grow persists only the
    // desired size, so the file itself grows here, before any virtio device
    // attaches the image.
    prepare_oci_upper(config, &sandbox_dir).await?;

    // Write scripts to the runtime scripts directory.
    for (name, content) in &config.spec.runtime.scripts {
        // Prevent path traversal: only use the filename component.
        let safe_name = Path::new(name).file_name().ok_or_else(|| {
            crate::MicrosandboxError::InvalidConfig(format!("invalid script name: {name}"))
        })?;
        let script_path = scripts_dir.join(safe_name);
        tokio::fs::write(&script_path, content).await?;
        #[cfg(unix)]
        tokio::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755)).await?;
        #[cfg(windows)]
        microsandbox_filesystem::PassthroughFs::set_path_virtual_permissions(
            &runtime_dir,
            &script_path,
            0,
            0,
            0o755,
        )?;
    }

    // Compute the agent relay socket path from the backend being used for
    // this spawn, not from the ambient default backend.
    let agent_sock_path = resolve_sandbox_agent_socket_path_for(local, &config.spec.name)?;

    // The pipe name is derived from the sandbox NAME, so a leaked VM process
    // from an earlier run would keep serving it and silently receive the new
    // sandbox's agent traffic. Refuse to boot on top of a live server.
    #[cfg(windows)]
    ensure_agent_pipe_unclaimed(&agent_sock_path, &config.spec.name).await?;

    // Stage file bind mounts: each file gets its own isolated directory so
    // that virtio-fs (which requires directories) can share it without
    // exposing adjacent files on the host.
    let (staged_file_mounts, file_mounts_staging) = stage_file_mounts(config).await?;
    let named_volumes = resolve_named_volumes(local, config).await?;
    let disk_locks = lock_disk_mounts(config, &named_volumes)?;
    let metrics_reservation = if config.effective_metrics_interval().is_some() {
        reserve_metrics_slot(local, config, sandbox_id)
    } else {
        None
    };
    #[cfg(unix)]
    let parent_watchdog = match mode {
        SpawnMode::Attached => match create_parent_watchdog_pipe() {
            Ok(pipe) => Some(pipe),
            Err(err) => {
                release_metrics_reservation(config, metrics_reservation.as_ref());
                return Err(err);
            }
        },
        SpawnMode::Detached => None,
    };

    #[cfg(windows)]
    let parent_watchdog: Option<()> = None;

    #[cfg(unix)]
    let startup_pipe = match mode {
        SpawnMode::Attached => None,
        SpawnMode::Detached => match create_startup_pipe() {
            Ok(pipe) => Some(pipe),
            Err(err) => {
                release_metrics_reservation(config, metrics_reservation.as_ref());
                return Err(err);
            }
        },
    };

    #[cfg(windows)]
    let startup_pipe = match mode {
        SpawnMode::Attached => None,
        SpawnMode::Detached => match create_startup_pipe(&config.spec.name, sandbox_id) {
            Ok(pipe) => Some(pipe),
            Err(err) => {
                release_metrics_reservation(config, metrics_reservation.as_ref());
                return Err(err);
            }
        },
    };

    #[cfg(windows)]
    let child_job = match mode {
        SpawnMode::Attached => match WindowsJob::new_kill_on_close() {
            Ok(job) => Some(job),
            Err(err) => {
                release_metrics_reservation(config, metrics_reservation.as_ref());
                return Err(crate::MicrosandboxError::Runtime(format!(
                    "failed to create Windows sandbox job: {err}"
                )));
            }
        },
        SpawnMode::Detached => None,
    };

    #[cfg(windows)]
    let startup_pipe_name = startup_pipe.as_ref().map(|pipe| pipe.name.as_os_str());

    // Split the config: `visible` stays on argv, the typed `LaunchConfig` is
    // delivered over the config fd (keeps the network-config blob and
    // secret-bearing env off `ps` / `/proc/<pid>/cmdline` — see issue #997).
    let (mut visible, launch) = sandbox_cli_args(
        local,
        config,
        sandbox_id,
        &db_path,
        global.database.connect_timeout_secs,
        &log_dir,
        &runtime_dir,
        &agent_sock_path,
        &libkrunfw_path,
        &staged_file_mounts,
        &named_volumes,
        metrics_reservation.as_ref(),
        parent_watchdog
            .as_ref()
            .map(|_| microsandbox_runtime::vm::PARENT_WATCH_FD),
        #[cfg(unix)]
        startup_pipe
            .as_ref()
            .map(|_| microsandbox_runtime::vm::STARTUP_FD),
        #[cfg(unix)]
        None,
        #[cfg(windows)]
        None,
        #[cfg(windows)]
        startup_pipe_name,
    );

    #[cfg(unix)]
    let config_file = match write_launch_config_fd(&launch) {
        Ok(file) => file,
        Err(err) => {
            release_metrics_reservation(config, metrics_reservation.as_ref());
            return Err(err);
        }
    };
    #[cfg(unix)]
    let config_raw_fd = config_file.as_raw_fd();
    #[cfg(unix)]
    {
        visible.push(OsString::from("--config-fd"));
        visible.push(OsString::from(
            microsandbox_runtime::vm::CONFIG_FD.to_string(),
        ));
    }

    #[cfg(windows)]
    let _config_file = match write_launch_config_file(&launch, &runtime_dir) {
        Ok(file) => {
            visible.push(OsString::from("--config-file"));
            visible.push(file.path().as_os_str().to_os_string());
            file
        }
        Err(err) => {
            release_metrics_reservation(config, metrics_reservation.as_ref());
            return Err(err);
        }
    };

    // Build the command.
    let mut cmd = Command::new(&msb_path);
    #[cfg(windows)]
    if matches!(mode, SpawnMode::Detached) {
        let flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB;
        cmd.creation_flags(flags);
    }
    cmd.args(visible);

    // Prevent the sandbox process from inheriting the parent's terminal on
    // stdin — the VMM's implicit console auto-detects terminals and sets raw
    // mode, which corrupts the parent's terminal output (\n without \r).
    cmd.stdin(Stdio::null());

    #[cfg(unix)]
    if parent_watchdog.is_some() || startup_pipe.is_some() {
        let parent_watch_fd = parent_watchdog
            .as_ref()
            .map(|pipe| pipe.read_fd.as_raw_fd());
        let startup_write_fd = startup_pipe.as_ref().map(|pipe| pipe.write_fd.as_raw_fd());
        unsafe {
            cmd.pre_exec(move || {
                if startup_write_fd.is_some() {
                    detach_from_launcher_session()?;
                }

                let mut config_mapping =
                    InheritedFdMapping::new(config_raw_fd, microsandbox_runtime::vm::CONFIG_FD);
                let mut parent_watch_mapping = parent_watch_fd.map(|fd| {
                    InheritedFdMapping::new(fd, microsandbox_runtime::vm::PARENT_WATCH_FD)
                });
                let mut startup_mapping = startup_write_fd
                    .map(|fd| InheritedFdMapping::new(fd, microsandbox_runtime::vm::STARTUP_FD));

                // Parent runtimes such as Vitest or Go tests can have enough
                // open files that pipe/tempfile allocation lands on one of the
                // fixed inherited fd numbers. Move those sources away before
                // any dup2 call can overwrite a later source fd.
                let mut next_spare_fd = microsandbox_runtime::vm::STARTUP_FD + 1;
                move_reserved_source_fd(&mut config_mapping, &mut next_spare_fd)?;
                if let Some(mapping) = parent_watch_mapping.as_mut() {
                    move_reserved_source_fd(mapping, &mut next_spare_fd)?;
                }
                if let Some(mapping) = startup_mapping.as_mut() {
                    move_reserved_source_fd(mapping, &mut next_spare_fd)?;
                }

                dup_inherited_fd(config_mapping.src, config_mapping.dst)?;
                if let Some(mapping) = parent_watch_mapping {
                    dup_inherited_fd(mapping.src, mapping.dst)?;
                }
                if let Some(mapping) = startup_mapping {
                    dup_inherited_fd(mapping.src, mapping.dst)?;
                }

                Ok(())
            });
        }
    }

    // Capture stdout for attached startup JSON. Detached mode uses a
    // dedicated startup fd so stdio can be severed from the launcher.
    #[cfg(unix)]
    if startup_pipe.is_some() {
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::null());
    } else {
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::inherit());
    }
    #[cfg(windows)]
    {
        let runtime_log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_dir.join("runtime.log"))?;

        if startup_pipe.is_some() {
            cmd.stdout(Stdio::null());
        } else {
            cmd.stdout(Stdio::piped());
        }
        cmd.stderr(Stdio::from(runtime_log));
    }

    ensure_sigchld_handler_uses_alt_stack_before_spawn().await?;

    // Spawn the sandbox process.
    let mut child = {
        #[cfg(windows)]
        let _stdio_inherit_guard = if matches!(mode, SpawnMode::Detached) {
            Some(StdioInheritGuard::new()?)
        } else {
            None
        };

        match cmd.spawn() {
            Ok(child) => child,
            Err(err) => {
                release_metrics_reservation(config, metrics_reservation.as_ref());
                return Err(err.into());
            }
        }
    };

    let _pid = match child.id() {
        Some(pid) => pid,
        None => {
            release_metrics_reservation(config, metrics_reservation.as_ref());
            return Err(crate::MicrosandboxError::Runtime(
                "sandbox process exited immediately".into(),
            ));
        }
    };
    tracing::debug!(pid = _pid, sandbox = %config.spec.name, "spawn_sandbox: process started");

    #[cfg(windows)]
    if let Some(job) = &child_job
        && let Err(err) = job.assign_pid(_pid)
    {
        let status = terminate_startup_process(&mut child).await;
        release_metrics_reservation(config, metrics_reservation.as_ref());
        return Err(crate::MicrosandboxError::Runtime(format!(
            "failed to assign sandbox process to Windows job (status: {status:?}): {err}"
        )));
    }

    let line = match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        read_startup_line(&mut child, startup_pipe),
    )
    .await
    {
        Ok(Ok(line)) => line,
        Ok(Err(err)) => {
            terminate_startup_process(&mut child).await;
            release_metrics_reservation(config, metrics_reservation.as_ref());
            return Err(err);
        }
        Err(_) => {
            terminate_startup_process(&mut child).await;
            release_metrics_reservation(config, metrics_reservation.as_ref());
            return Err(crate::MicrosandboxError::Runtime(
                "sandbox startup timeout: no JSON received within 30 seconds".into(),
            ));
        }
    };

    let startup: StartupInfo = match serde_json::from_str(line.trim()) {
        Ok(info) => info,
        Err(_) => {
            let status = terminate_startup_process(&mut child).await;
            release_metrics_reservation(config, metrics_reservation.as_ref());
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
    if startup.pid != _pid {
        let status = terminate_startup_process(&mut child).await;
        release_metrics_reservation(config, metrics_reservation.as_ref());
        return Err(crate::MicrosandboxError::Runtime(format!(
            "sandbox startup PID mismatch: spawned pid {_pid}, startup pid {} \
             (status: {status:?})",
            startup.pid
        )));
    }

    tracing::debug!(
        vm_pid = startup.pid,
        agent_sock = %agent_sock_path.display(),
        "spawn_sandbox: startup JSON received"
    );

    #[cfg(unix)]
    let handle = ProcessHandle::new(
        startup.pid,
        config.spec.name.clone(),
        child,
        file_mounts_staging,
        disk_locks,
        parent_watchdog.map(|pipe| pipe.write_fd),
        metrics_reservation.as_ref().map(|reservation| {
            MetricsReservationCleanup::new(
                reservation.shm_name.clone(),
                reservation.slot,
                reservation.generation,
                Some(reservation.registry.clone()),
            )
        }),
    );

    #[cfg(windows)]
    let handle = ProcessHandle::new(
        startup.pid,
        config.spec.name.clone(),
        child,
        file_mounts_staging,
        disk_locks,
        child_job,
        metrics_reservation.as_ref().map(|reservation| {
            MetricsReservationCleanup::new(
                reservation.shm_name.clone(),
                reservation.slot,
                reservation.generation,
                Some(reservation.registry.clone()),
            )
        }),
    );

    Ok((handle, agent_sock_path))
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Pre-boot preparation for the OCI writable upper: grow `upper.ext4` when
/// the persisted desired size exceeds the file's current size. This is where
/// a `--next-start` upper grow lands; ordinary starts no-op because create
/// formats the file at the desired size. A missing upper is not this hook's
/// problem — non-OCI rootfs and not-yet-materialized sandboxes skip it.
async fn prepare_oci_upper(config: &SandboxConfig, sandbox_dir: &Path) -> MicrosandboxResult<()> {
    let Some(desired_mib) = config.spec.image.oci_upper_size_mib() else {
        return Ok(());
    };
    let upper_path = sandbox_dir.join("upper.ext4");
    if !tokio::fs::try_exists(&upper_path).await.unwrap_or(false) {
        return Ok(());
    }
    crate::sandbox::upper::grow_upper_to_mib(upper_path, desired_mib).await
}

fn reserve_metrics_slot(
    local: &LocalBackend,
    config: &SandboxConfig,
    sandbox_id: i32,
) -> Option<MetricsReservation> {
    let shm_name = local.config().metrics_registry_shm_name();
    let capacity = local.config().metrics_registry_capacity();
    let registry = match MetricsRegistry::open_or_create(&shm_name, capacity) {
        Ok(registry) => registry,
        Err(err) => {
            tracing::warn!(error = %err, sandbox = %config.spec.name, "failed to open metrics registry");
            return None;
        }
    };
    let memory_limit_bytes = u64::from(config.spec.resources.memory_mib) * 1024 * 1024;
    match registry.reserve(ReserveSlot {
        sandbox_id,
        name: &config.spec.name,
        memory_limit_bytes,
    }) {
        Ok(SlotReservation { slot, generation }) => Some(MetricsReservation {
            shm_name,
            slot,
            generation,
            registry,
        }),
        Err(err) => {
            tracing::warn!(error = %err, sandbox = %config.spec.name, "failed to reserve metrics slot");
            None
        }
    }
}

#[cfg(unix)]
fn create_parent_watchdog_pipe() -> MicrosandboxResult<Pipe> {
    create_pipe()
}

#[cfg(unix)]
fn create_startup_pipe() -> MicrosandboxResult<Pipe> {
    create_pipe()
}

#[cfg(windows)]
fn create_startup_pipe(sandbox_name: &str, sandbox_id: i32) -> MicrosandboxResult<StartupPipe> {
    let pipe_name = startup_pipe_name(sandbox_name, sandbox_id);
    let server = ServerOptions::new()
        .first_pipe_instance(true)
        .pipe_mode(PipeMode::Byte)
        .create(&pipe_name)?;

    Ok(StartupPipe {
        name: OsString::from(pipe_name),
        server,
    })
}

#[cfg(windows)]
fn startup_pipe_name(sandbox_name: &str, sandbox_id: i32) -> String {
    let mut nonce = [0u8; 16];
    rand::rng().fill_bytes(&mut nonce);

    let mut hasher = Sha256::new();
    hasher.update(sandbox_name.as_bytes());
    hasher.update(b"\0");
    hasher.update(sandbox_id.to_le_bytes());
    hasher.update(nonce);
    let digest = hasher.finalize();

    let mut hash = String::with_capacity(STARTUP_PIPE_HASH_HEX_LEN);
    for byte in digest.iter().take(STARTUP_PIPE_HASH_HEX_LEN / 2) {
        let _ = write!(hash, "{byte:02x}");
    }

    format!(r"\\.\pipe\msb-startup-{sandbox_id}-{hash}")
}

#[cfg(unix)]
fn create_pipe() -> MicrosandboxResult<Pipe> {
    let mut fds = [0; 2];
    let rc = create_cloexec_pipe(&mut fds);
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    let read_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let write_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };

    #[cfg(not(target_os = "linux"))]
    {
        set_cloexec(&read_fd, true)?;
        set_cloexec(&write_fd, true)?;
    }

    Ok(Pipe { read_fd, write_fd })
}

/// Serialize the [`LaunchConfig`] as JSON into an anonymous temp file, rewound
/// to offset 0. The file is unlinked on creation, so there is no path to clean
/// up or race on; it is `dup2`'d onto
/// [`CONFIG_FD`](microsandbox_runtime::vm::CONFIG_FD) for the child to read.
#[cfg(unix)]
fn write_launch_config_fd(launch: &LaunchConfig) -> MicrosandboxResult<std::fs::File> {
    let mut file = tempfile::tempfile()?;
    let json = serde_json::to_vec(launch)
        .map_err(|e| crate::MicrosandboxError::Runtime(format!("serialize launch config: {e}")))?;
    file.write_all(&json)?;
    file.flush()?;
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

/// Serialize the [`LaunchConfig`] as JSON to a short-lived named file for Windows.
///
/// Windows does not have the Unix anonymous-fd handoff used above, so the
/// launcher keeps the file handle alive until the child reports startup and
/// passes only the path on argv.
#[cfg(windows)]
fn write_launch_config_file(
    launch: &LaunchConfig,
    runtime_dir: &Path,
) -> MicrosandboxResult<tempfile::NamedTempFile> {
    let mut file = tempfile::NamedTempFile::new_in(runtime_dir)?;
    let json = serde_json::to_vec(launch)
        .map_err(|e| crate::MicrosandboxError::Runtime(format!("serialize launch config: {e}")))?;
    file.write_all(&json)?;
    file.flush()?;
    file.as_file_mut().seek(SeekFrom::Start(0))?;
    Ok(file)
}

#[cfg(unix)]
async fn read_startup_line(
    child: &mut tokio::process::Child,
    startup_pipe: Option<Pipe>,
) -> MicrosandboxResult<String> {
    let mut reader: Box<dyn AsyncBufRead + Send + Unpin> = match startup_pipe {
        Some(pipe) => {
            let Pipe { read_fd, write_fd } = pipe;
            drop(write_fd);
            Box::new(tokio::io::BufReader::new(tokio::fs::File::from_std(
                std::fs::File::from(read_fd),
            )))
        }
        None => {
            let stdout = child.stdout.take().ok_or_else(|| {
                crate::MicrosandboxError::Runtime("failed to capture sandbox stdout".into())
            })?;
            Box::new(tokio::io::BufReader::new(stdout))
        }
    };

    let mut line = String::new();
    reader.read_line(&mut line).await?;
    Ok(line)
}

#[cfg(windows)]
async fn read_startup_line(
    child: &mut tokio::process::Child,
    startup_pipe: Option<StartupPipe>,
) -> MicrosandboxResult<String> {
    let mut reader: Box<dyn AsyncBufRead + Send + Unpin> = match startup_pipe {
        Some(pipe) => {
            let server = pipe.server;
            server.connect().await?;
            Box::new(tokio::io::BufReader::new(server))
        }
        None => {
            let stdout = child.stdout.take().ok_or_else(|| {
                crate::MicrosandboxError::Runtime("failed to capture sandbox stdout".into())
            })?;
            Box::new(tokio::io::BufReader::new(stdout))
        }
    };

    let mut line = String::new();
    reader.read_line(&mut line).await?;
    Ok(line)
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InheritedFdMapping {
    src: i32,
    dst: i32,
}

#[cfg(unix)]
impl InheritedFdMapping {
    fn new(src: i32, dst: i32) -> Self {
        Self { src, dst }
    }
}

#[cfg(unix)]
fn move_reserved_source_fd(
    mapping: &mut InheritedFdMapping,
    next_spare_fd: &mut i32,
) -> std::io::Result<()> {
    if !inherited_fd_source_needs_spare(mapping.src, mapping.dst) {
        return Ok(());
    }

    let spare = unsafe { libc::fcntl(mapping.src, libc::F_DUPFD, *next_spare_fd) };
    if spare < 0 {
        return Err(std::io::Error::last_os_error());
    }

    mapping.src = spare;
    *next_spare_fd = spare.saturating_add(1);
    Ok(())
}

#[cfg(unix)]
fn inherited_fd_source_needs_spare(src: i32, dst: i32) -> bool {
    src != dst
        && matches!(
            src,
            microsandbox_runtime::vm::CONFIG_FD
                | microsandbox_runtime::vm::PARENT_WATCH_FD
                | microsandbox_runtime::vm::STARTUP_FD
        )
}

#[cfg(unix)]
fn dup_inherited_fd(src: i32, dst: i32) -> std::io::Result<()> {
    if unsafe { libc::dup2(src, dst) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if src != dst && unsafe { libc::close(src) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let flags = unsafe { libc::fcntl(dst, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(dst, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn detach_from_launcher_session() -> std::io::Result<()> {
    if unsafe { libc::setsid() } < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = libc::SIG_IGN;
    if unsafe { libc::sigemptyset(&mut action.sa_mask) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::sigaction(libc::SIGHUP, &action, std::ptr::null_mut()) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn create_cloexec_pipe(fds: &mut [i32; 2]) -> i32 {
    unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn create_cloexec_pipe(fds: &mut [i32; 2]) -> i32 {
    unsafe { libc::pipe(fds.as_mut_ptr()) }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn set_cloexec(fd: &OwnedFd, enabled: bool) -> MicrosandboxResult<()> {
    let current = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    if current < 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    let mut next = current;
    if enabled {
        next |= libc::FD_CLOEXEC;
    } else {
        next &= !libc::FD_CLOEXEC;
    }

    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, next) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    Ok(())
}

fn release_metrics_reservation(config: &SandboxConfig, reservation: Option<&MetricsReservation>) {
    let Some(reservation) = reservation else {
        return;
    };
    if let Err(err) = reservation
        .registry
        .release_reserved(reservation.slot, reservation.generation)
    {
        tracing::debug!(error = %err, sandbox = %config.spec.name, "release: metrics slot release failed");
    }
}

#[cfg(target_os = "linux")]
async fn ensure_sigchld_handler_uses_alt_stack_before_spawn() -> MicrosandboxResult<()> {
    SIGCHLD_ALT_STACK_INIT
        .get_or_try_init(|| async {
            install_tokio_sigchld_handler()?;
            patch_sigchld_handler_uses_alt_stack();
            Ok::<(), MicrosandboxError>(())
        })
        .await?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
async fn ensure_sigchld_handler_uses_alt_stack_before_spawn() -> MicrosandboxResult<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_tokio_sigchld_handler() -> MicrosandboxResult<()> {
    let signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::child())?;
    let _ = Box::leak(Box::new(signal));
    Ok(())
}

#[cfg(target_os = "linux")]
fn patch_sigchld_handler_uses_alt_stack() {
    unsafe {
        let mut action = std::mem::MaybeUninit::<libc::sigaction>::uninit();
        if libc::sigaction(libc::SIGCHLD, std::ptr::null(), action.as_mut_ptr()) != 0 {
            return;
        }

        let mut action = action.assume_init();
        if action.sa_flags & libc::SA_ONSTACK != 0 {
            return;
        }

        action.sa_flags |= libc::SA_ONSTACK;
        let _ = libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut());
    }
}

pub(crate) async fn ensure_named_volumes(
    local: &LocalBackend,
    config: &SandboxConfig,
) -> MicrosandboxResult<EnsuredNamedVolumes> {
    let locks = lock_named_volume_mounts(local, config)?;
    let mut created = Vec::new();

    if let Err(err) = ensure_named_volumes_inner(local, config, &mut created).await {
        rollback_created_named_volume_records(local, &created).await;
        return Err(err);
    }

    Ok(EnsuredNamedVolumes {
        created,
        _locks: locks,
    })
}

async fn ensure_named_volumes_inner(
    local: &LocalBackend,
    config: &SandboxConfig,
    created: &mut Vec<CreatedNamedVolume>,
) -> MicrosandboxResult<()> {
    for mount in &config.spec.mounts {
        let Some(create) = mount.named_create() else {
            continue;
        };

        validate_volume_name(create.name())?;
        let pools = local.db().await?;
        let existing = volume_entity::Entity::find()
            .filter(volume_entity::Column::Name.eq(create.name()))
            .one(pools.read())
            .await?;

        if let Some(existing) = existing {
            match create.mode() {
                NamedVolumeMode::Create => {
                    return Err(MicrosandboxError::VolumeAlreadyExists(
                        create.name().to_string(),
                    ));
                }
                NamedVolumeMode::EnsureExists => {
                    validate_existing_named_volume(create, &existing)?;
                    continue;
                }
                NamedVolumeMode::Existing => continue,
            }
        }

        if create.mode() == NamedVolumeMode::Existing {
            return Err(MicrosandboxError::VolumeNotFound(create.name().to_string()));
        }

        let volume_config = VolumeConfig {
            name: create.name().to_string(),
            kind: create.kind(),
            quota_mib: create.quota_mib(),
            capacity_mib: create.capacity_mib(),
            labels: create.labels().to_vec(),
        };
        validate_volume_config(&volume_config)?;

        let labels_json = if create.labels().is_empty() {
            None
        } else {
            Some(serde_json::to_string(create.labels())?)
        };
        let now = chrono::Utc::now().naive_utc();
        let capacity_bytes = volume_config
            .capacity_mib
            .map(|mib| i64::from(mib) * 1024 * 1024);
        let model = volume_entity::ActiveModel {
            name: Set(volume_config.name.clone()),
            kind: Set(volume_config.kind.as_str().to_string()),
            quota_mib: Set(volume_config.quota_mib.map(|value| value as i32)),
            size_bytes: Set(None),
            capacity_bytes: Set(capacity_bytes),
            disk_format: Set((volume_config.kind == VolumeKind::Disk).then(|| "raw".to_string())),
            disk_fstype: Set((volume_config.kind == VolumeKind::Disk).then(|| "ext4".to_string())),
            labels: Set(labels_json),
            created_at: Set(Some(now)),
            updated_at: Set(Some(now)),
            ..Default::default()
        };
        let inserted = volume_entity::Entity::insert(model)
            .exec(pools.write())
            .await?;
        let volume_id = inserted.last_insert_id;

        let path = local.volume_path(&volume_config.name);
        if let Err(err) = materialize_volume_path(&volume_config, &path).await {
            let _ = volume_entity::Entity::delete_by_id(volume_id)
                .exec(pools.write())
                .await;
            let _ = tokio::fs::remove_dir_all(&path).await;
            return Err(err);
        }
        created.push(CreatedNamedVolume {
            id: volume_id,
            path,
        });
    }

    Ok(())
}

pub(crate) async fn rollback_created_named_volumes(
    local: &LocalBackend,
    volumes: &EnsuredNamedVolumes,
) {
    rollback_created_named_volume_records(local, &volumes.created).await;
}

async fn rollback_created_named_volume_records(
    local: &LocalBackend,
    volumes: &[CreatedNamedVolume],
) {
    if volumes.is_empty() {
        return;
    }

    for volume in volumes {
        let _ = tokio::fs::remove_dir_all(&volume.path).await;
    }

    let ids = volumes.iter().map(|volume| volume.id).collect::<Vec<_>>();
    if let Ok(pools) = local.db().await {
        let _ = volume_entity::Entity::delete_many()
            .filter(volume_entity::Column::Id.is_in(ids))
            .exec(pools.write())
            .await;
    }
}

fn lock_named_volume_mounts(
    local: &LocalBackend,
    config: &SandboxConfig,
) -> MicrosandboxResult<Vec<File>> {
    let mut names = BTreeSet::new();
    for mount in &config.spec.mounts {
        if let VolumeMount::Named { name, .. } = mount {
            validate_volume_name(name)?;
            names.insert(name.clone());
        }
    }

    let mut locks = Vec::with_capacity(names.len());
    for name in names {
        locks.push(lock_volume_name(local, &name)?);
    }
    Ok(locks)
}

async fn resolve_named_volumes(
    local: &LocalBackend,
    config: &SandboxConfig,
) -> MicrosandboxResult<HashMap<String, ResolvedNamedVolume>> {
    let mut resolved: HashMap<String, ResolvedNamedVolume> = HashMap::new();

    for mount in &config.spec.mounts {
        let VolumeMount::Named {
            name,
            stat_virtualization,
            host_permissions,
            ..
        } = mount
        else {
            continue;
        };

        if let Some(volume) = resolved.get(name) {
            if volume.kind == VolumeKind::Disk {
                validate_named_disk_mount_options(name, *stat_virtualization, *host_permissions)?;
            }
            continue;
        }

        let pools = local.db().await?;
        let model = volume_entity::Entity::find()
            .filter(volume_entity::Column::Name.eq(name))
            .one(pools.read())
            .await?
            .ok_or_else(|| MicrosandboxError::VolumeNotFound(name.clone()))?;

        let kind = VolumeKind::from_db_value(&model.kind);
        let path = local.volume_path(name);
        let volume = match kind {
            VolumeKind::Directory => ResolvedNamedVolume {
                kind,
                path,
                format: None,
                fstype: None,
                quota_mib: model.quota_mib.map(|value| value.max(0) as u32),
            },
            VolumeKind::Disk => {
                validate_named_disk_mount_options(name, *stat_virtualization, *host_permissions)?;
                let format = model
                    .disk_format
                    .as_deref()
                    .unwrap_or("raw")
                    .parse::<DiskImageFormat>()
                    .map_err(|err| {
                        MicrosandboxError::InvalidConfig(format!(
                            "disk named volume {name:?} has invalid disk format: {err}"
                        ))
                    })?;

                ResolvedNamedVolume {
                    kind,
                    path: path.join("disk.raw"),
                    format: Some(format),
                    fstype: model.disk_fstype,
                    quota_mib: None,
                }
            }
        };

        resolved.insert(name.clone(), volume);
    }

    Ok(resolved)
}

fn validate_existing_named_volume(
    requested: &microsandbox_types::NamedVolumeCreate,
    existing: &volume_entity::Model,
) -> MicrosandboxResult<()> {
    let actual_kind = VolumeKind::from_db_value(&existing.kind);
    if requested.kind() != actual_kind {
        return Err(MicrosandboxError::InvalidConfig(format!(
            "named volume {:?} already exists as {}, but this sandbox requested {}",
            requested.name(),
            actual_kind.as_str(),
            requested.kind().as_str()
        )));
    }

    if let Some(requested_quota_mib) = requested.quota_mib()
        && existing.quota_mib != Some(requested_quota_mib as i32)
    {
        return Err(MicrosandboxError::InvalidConfig(format!(
            "named volume {:?} already exists with quota {:?} MiB, but this sandbox requested {} MiB",
            requested.name(),
            existing.quota_mib,
            requested_quota_mib
        )));
    }

    if let Some(requested_capacity_mib) = requested.capacity_mib() {
        let requested_capacity_bytes = i64::from(requested_capacity_mib) * 1024 * 1024;
        if existing.capacity_bytes != Some(requested_capacity_bytes) {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "named volume {:?} already exists with capacity {:?} bytes, but this sandbox requested {} bytes",
                requested.name(),
                existing.capacity_bytes,
                requested_capacity_bytes
            )));
        }
    }

    validate_requested_named_volume_labels(requested, existing)?;

    Ok(())
}

fn validate_requested_named_volume_labels(
    requested: &microsandbox_types::NamedVolumeCreate,
    existing: &volume_entity::Model,
) -> MicrosandboxResult<()> {
    if requested.labels().is_empty() {
        return Ok(());
    }

    let existing_labels = existing
        .labels
        .as_deref()
        .map(serde_json::from_str::<Vec<(String, String)>>)
        .transpose()?
        .unwrap_or_default()
        .into_iter()
        .collect::<BTreeMap<_, _>>();

    for (key, requested_value) in requested.labels() {
        match existing_labels.get(key) {
            Some(existing_value) if existing_value == requested_value => {}
            Some(existing_value) => {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "named volume {:?} already exists with label {key:?}={existing_value:?}, but this sandbox requested {requested_value:?}",
                    requested.name()
                )));
            }
            None => {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "named volume {:?} already exists without requested label {key:?}",
                    requested.name()
                )));
            }
        }
    }

    Ok(())
}

fn lock_disk_mounts(
    config: &SandboxConfig,
    named_volumes: &HashMap<String, ResolvedNamedVolume>,
) -> MicrosandboxResult<Vec<File>> {
    let mut locks = Vec::new();
    let mut requests = Vec::new();

    if let RootfsSource::DiskImage { path, .. } = &config.spec.image {
        requests.push(DiskLockRequest {
            path: path.clone(),
            readonly: false,
            label: format!("disk image rootfs {}", path.display()),
            volume_name: None,
        });
    }

    for mount in &config.spec.mounts {
        match mount {
            VolumeMount::DiskImage { host, options, .. } => {
                requests.push(DiskLockRequest {
                    path: host.clone(),
                    readonly: options.readonly,
                    label: format!("disk image {}", host.display()),
                    volume_name: None,
                });
            }
            VolumeMount::Named { name, options, .. } => {
                if let Some(ResolvedNamedVolume {
                    kind: VolumeKind::Disk,
                    path,
                    ..
                }) = named_volumes.get(name)
                {
                    requests.push(DiskLockRequest {
                        path: path.clone(),
                        readonly: options.readonly,
                        label: format!("named disk volume {name:?}"),
                        volume_name: Some(name.clone()),
                    });
                }
            }
            _ => {}
        }
    }

    let mut seen = HashMap::new();
    for request in requests {
        let canonical = std::fs::canonicalize(&request.path).map_err(|err| {
            MicrosandboxError::InvalidConfig(format!(
                "disk image host path does not exist: {} ({err})",
                request.path.display()
            ))
        })?;
        if let Some(previous) = seen.insert(canonical.clone(), request.label.clone()) {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "disk images cannot be attached more than once per sandbox: {} ({previous}; {})",
                canonical.display(),
                request.label
            )));
        }
        locks.push(lock_disk_image(
            &canonical,
            request.readonly,
            request.volume_name.as_deref(),
        )?);
    }

    Ok(locks)
}

fn lock_disk_image(
    path: &Path,
    readonly: bool,
    volume_name: Option<&str>,
) -> MicrosandboxResult<File> {
    #[cfg(unix)]
    {
        lock_disk_image_unix(path, readonly, volume_name)
    }

    #[cfg(windows)]
    {
        lock_disk_image_windows(path, readonly, volume_name)
    }
}

#[cfg(unix)]
fn lock_disk_image_unix(
    path: &Path,
    readonly: bool,
    volume_name: Option<&str>,
) -> MicrosandboxResult<File> {
    let file = if readonly {
        std::fs::OpenOptions::new().read(true).open(path)
    } else {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
    }
    .map_err(|err| {
        MicrosandboxError::InvalidConfig(format!("open disk image lock {}: {err}", path.display()))
    })?;

    let operation = if readonly {
        libc::LOCK_SH | libc::LOCK_NB
    } else {
        libc::LOCK_EX | libc::LOCK_NB
    };

    if unsafe { libc::flock(file.as_raw_fd(), operation) } != 0 {
        let err = std::io::Error::last_os_error();
        let message = if matches!(err.kind(), std::io::ErrorKind::WouldBlock) {
            match volume_name {
                Some(name) => {
                    format!("volume {name:?} is already attached with an incompatible disk mode")
                }
                None => format!(
                    "disk image {:?} is already attached with an incompatible disk mode",
                    path.display().to_string()
                ),
            }
        } else {
            format!("lock disk image {}: {err}", path.display())
        };
        return Err(MicrosandboxError::InvalidConfig(message));
    }

    clear_cloexec(file.as_raw_fd())?;
    Ok(file)
}

#[cfg(windows)]
fn lock_disk_image_windows(
    path: &Path,
    _readonly: bool,
    volume_name: Option<&str>,
) -> MicrosandboxResult<File> {
    let lock_path = windows_disk_lock_path(path)?;
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Windows share modes are mandatory. Holding an exclusive handle on the
    // disk image itself would also block the child VMM from opening it, so use
    // a sidecar lock file while leaving the image handle-free until launch.
    let mut options = std::fs::OpenOptions::new();
    options
        .create(true)
        .read(true)
        .truncate(false)
        .write(true)
        .share_mode(0);

    options.open(&lock_path).map_err(|err| {
        let message = if is_windows_lock_conflict(&err) {
            match volume_name {
                Some(name) => {
                    format!("volume {name:?} is already attached with an incompatible disk mode")
                }
                None => format!(
                    "disk image {:?} is already attached with an incompatible disk mode",
                    path.display().to_string()
                ),
            }
        } else {
            format!("lock disk image {}: {err}", path.display())
        };
        MicrosandboxError::InvalidConfig(message)
    })
}

#[cfg(windows)]
fn windows_disk_lock_path(path: &Path) -> MicrosandboxResult<PathBuf> {
    let file_name = path.file_name().ok_or_else(|| {
        MicrosandboxError::InvalidConfig(format!(
            "disk image path has no file name: {}",
            path.display()
        ))
    })?;

    let mut lock_name = file_name.to_os_string();
    lock_name.push(".lock");
    Ok(path.with_file_name(lock_name))
}

#[cfg(windows)]
fn is_windows_lock_conflict(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::WouldBlock
    ) || err.raw_os_error() == Some(32)
}

#[cfg(unix)]
fn clear_cloexec(fd: i32) -> MicrosandboxResult<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// Return agent relay socket paths in preferred connection order.
pub(crate) fn sandbox_agent_socket_path_candidates(name: &str) -> Vec<PathBuf> {
    let (run_dir, sandboxes_dir) = crate::backend::default_backend()
        .as_local()
        .map(|local| (local.config().run_dir(), local.config().sandboxes_dir()))
        .unwrap_or_else(|| {
            let home = microsandbox_utils::resolve_home();
            (
                home.join(microsandbox_utils::RUN_SUBDIR),
                home.join(microsandbox_utils::SANDBOXES_SUBDIR),
            )
        });
    sandbox_agent_socket_path_candidates_with_roots(&run_dir, &sandboxes_dir, name)
}

pub(crate) fn sandbox_agent_socket_path_candidates_for(
    local: &LocalBackend,
    name: &str,
) -> Vec<PathBuf> {
    sandbox_agent_socket_path_candidates_with_roots(
        &local.config().run_dir(),
        &local.config().sandboxes_dir(),
        name,
    )
}

fn sandbox_agent_socket_path_candidates_with_roots(
    run_dir: &Path,
    sandboxes_dir: &Path,
    name: &str,
) -> Vec<PathBuf> {
    let primary = sandbox_agent_socket_path(run_dir, name);

    // On Unix a long sandbox name or a deep MSB_HOME can overflow the AF_UNIX
    // `sun_path` limit, so keep the legacy
    // `<sandboxes>/<name>/runtime/agent.sock` path as a fallback. Windows named
    // pipes have no such length limit and never shipped a pre-hash naming
    // scheme, so the primary pipe is the only candidate.
    #[cfg(unix)]
    let candidates = vec![
        primary,
        legacy_sandbox_agent_socket_path(sandboxes_dir, name),
    ];
    #[cfg(not(unix))]
    let candidates = {
        let _ = sandboxes_dir;
        vec![primary]
    };

    candidates
}

/// Pick the first explicit-backend socket path usable on this platform.
pub(crate) fn resolve_sandbox_agent_socket_path_for(
    local: &LocalBackend,
    name: &str,
) -> MicrosandboxResult<PathBuf> {
    let candidates = sandbox_agent_socket_path_candidates_for(local, name);
    resolve_sandbox_agent_socket_path_from_candidates(candidates)
}

/// Pick the first socket path usable on this platform.
pub(crate) fn resolve_sandbox_agent_socket_path(name: &str) -> MicrosandboxResult<PathBuf> {
    let candidates = sandbox_agent_socket_path_candidates(name);
    resolve_sandbox_agent_socket_path_from_candidates(candidates)
}

#[cfg(unix)]
fn resolve_sandbox_agent_socket_path_from_candidates(
    candidates: Vec<PathBuf>,
) -> MicrosandboxResult<PathBuf> {
    for path in &candidates {
        if sandbox_agent_socket_path_fits(path) {
            return Ok(path.clone());
        }
    }

    let shortest = candidates
        .iter()
        .map(|path| sandbox_agent_socket_path_len(path))
        .min()
        .unwrap_or(0);
    Err(crate::MicrosandboxError::InvalidConfig(format!(
        "agent relay socket path is too long: shortest derived path is {shortest} bytes, \
         but Unix socket paths on this platform must be shorter than {} bytes; set \
         MSB_HOME or paths.sandboxes to a shorter directory",
        unix_socket_path_capacity()
    )))
}

#[cfg(not(unix))]
fn resolve_sandbox_agent_socket_path_from_candidates(
    candidates: Vec<PathBuf>,
) -> MicrosandboxResult<PathBuf> {
    // Named pipes have no `sun_path`-style length limit, so the primary
    // candidate is always usable.
    candidates.into_iter().next().ok_or_else(|| {
        crate::MicrosandboxError::InvalidConfig(
            "no agent relay socket candidates were derived".to_string(),
        )
    })
}

#[cfg(unix)]
fn sandbox_agent_socket_path(run_dir: &Path, name: &str) -> PathBuf {
    run_dir
        .join("agent")
        .join(format!("{}.sock", agent_socket_hash(name)))
}

#[cfg(windows)]
fn sandbox_agent_socket_path(_run_dir: &Path, name: &str) -> PathBuf {
    PathBuf::from(format!(r"\\.\pipe\msb-agent-{}", agent_socket_hash(name)))
}

fn agent_socket_hash(name: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    let digest = hasher.finalize();

    let mut hash = String::with_capacity(AGENT_SOCKET_HASH_HEX_LEN);
    for byte in digest.iter().take(AGENT_SOCKET_HASH_HEX_LEN / 2) {
        let _ = Write::write_fmt(&mut hash, format_args!("{byte:02x}"));
    }
    hash
}

/// What a client-side open of the agent pipe name revealed.
#[cfg(windows)]
enum AgentPipeProbe {
    /// No server instance exists — the name is free to bind.
    Free,

    /// A live server holds the name. The serving PID is best-effort.
    Served { server_pid: Option<u32> },
}

/// Fail the spawn when another process already serves this sandbox's agent
/// pipe, naming the stale PID so the operator can terminate it.
///
/// Unix sockets are files the new runtime simply unlinks and rebinds; Windows
/// named pipes have no such steal path — the child's `first_pipe_instance`
/// bind would fail deep in boot, and agent clients would keep silently
/// reaching the stale server in the meantime.
#[cfg(windows)]
async fn ensure_agent_pipe_unclaimed(
    pipe_path: &Path,
    sandbox_name: &str,
) -> MicrosandboxResult<()> {
    // A just-stopped runtime closes its pipe within moments of its DB row
    // going terminal; retry briefly so stop→start (restart) flows don't trip
    // on ordinary teardown.
    const PROBE_ATTEMPTS: u32 = 10;
    const PROBE_INTERVAL: std::time::Duration = std::time::Duration::from_millis(200);

    let mut last_seen_pid = None;
    for attempt in 0..PROBE_ATTEMPTS {
        match probe_agent_pipe_server(pipe_path) {
            Ok(AgentPipeProbe::Free) => return Ok(()),
            Ok(AgentPipeProbe::Served { server_pid }) => last_seen_pid = server_pid,
            Err(err) => {
                // Unexpected probe failure must not block the spawn — if the
                // name really is taken, the child's first-instance bind fails
                // loudly on its own.
                tracing::debug!(
                    error = %err,
                    pipe = %pipe_path.display(),
                    "agent pipe probe failed; proceeding with spawn"
                );
                return Ok(());
            }
        }
        if attempt + 1 < PROBE_ATTEMPTS {
            tokio::time::sleep(PROBE_INTERVAL).await;
        }
    }

    let pid_note = match last_seen_pid {
        Some(pid) => format!(" (pid {pid})"),
        None => String::new(),
    };
    Err(crate::MicrosandboxError::Runtime(format!(
        "agent pipe {} for sandbox '{sandbox_name}' is already being served by a stale sandbox \
         process{pid_note}; terminate that process and retry",
        pipe_path.display()
    )))
}

#[cfg(windows)]
fn probe_agent_pipe_server(pipe_path: &Path) -> std::io::Result<AgentPipeProbe> {
    const ERROR_PIPE_BUSY: i32 = 231;

    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(pipe_path)
    {
        Ok(client) => {
            let mut pid = 0u32;
            let ok =
                unsafe { GetNamedPipeServerProcessId(client.as_raw_handle() as HANDLE, &mut pid) };
            Ok(AgentPipeProbe::Served {
                server_pid: (ok != 0).then_some(pid),
            })
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(AgentPipeProbe::Free),
        // Every instance being busy still proves a live server.
        Err(err) if err.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
            Ok(AgentPipeProbe::Served { server_pid: None })
        }
        Err(err) => Err(err),
    }
}

// The legacy `<sandboxes>/<name>/runtime/agent.sock` fallback only exists for
// backward compatibility with the pre-hash Unix layout; Windows never shipped a
// different agent-pipe scheme, so this is Unix-only.
#[cfg(unix)]
fn legacy_sandbox_agent_socket_path(sandboxes_dir: &Path, name: &str) -> PathBuf {
    sandboxes_dir.join(name).join("runtime").join("agent.sock")
}

// Agent socket path length only constrains AF_UNIX `sun_path` on Unix; Windows
// named pipes have no equivalent limit, so these helpers are Unix-only.
#[cfg(unix)]
fn sandbox_agent_socket_path_fits(path: &Path) -> bool {
    sandbox_agent_socket_path_len(path) < unix_socket_path_capacity()
}

#[cfg(unix)]
fn sandbox_agent_socket_path_len(path: &Path) -> usize {
    path.as_os_str().as_bytes().len()
}

#[cfg(unix)]
fn unix_socket_path_capacity() -> usize {
    let storage = unsafe { std::mem::zeroed::<libc::sockaddr_un>() };
    storage.sun_path.len()
}

async fn terminate_startup_process(
    child: &mut tokio::process::Child,
) -> Option<std::process::ExitStatus> {
    let _ = child.start_kill();
    child.wait().await.ok()
}

/// Scan `config.spec.mounts` for file bind mounts and stage each file in its own
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
        .spec
        .mounts
        .iter()
        .filter_map(|m| match m {
            VolumeMount::Bind {
                host,
                guest,
                options,
                ..
            } if host.is_file() => Some((host, guest, options.readonly)),
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
            Err(e) if is_cross_device_link_error(&e) => {
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

/// Return whether a host hard-link failed because the target is on another device.
fn is_cross_device_link_error(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::CrossesDevices || is_platform_cross_device_link_error(error)
}

#[cfg(unix)]
fn is_platform_cross_device_link_error(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(libc::EXDEV)
}

#[cfg(windows)]
fn is_platform_cross_device_link_error(error: &std::io::Error) -> bool {
    // CreateHardLinkW reports cross-volume links as ERROR_NOT_SAME_DEVICE.
    const ERROR_NOT_SAME_DEVICE: i32 = 17;

    error.raw_os_error() == Some(ERROR_NOT_SAME_DEVICE)
}

#[cfg(not(any(unix, windows)))]
fn is_platform_cross_device_link_error(_error: &std::io::Error) -> bool {
    false
}

/// Push a `--mount tag:host_path[:ro]` arg pair.
#[allow(clippy::too_many_arguments)]
fn push_dir_mount_arg(
    mounts: &mut Vec<String>,
    guest: &str,
    host_display: &impl std::fmt::Display,
    options: MountOptions,
    stat_virtualization: StatVirtualization,
    host_permissions: HostPermissions,
    quota_mib: Option<u32>,
) {
    let tag = guest_mount_tag(guest);
    let mut arg = format!("{tag}:{host_display}");
    let mut opts = mount_option_tokens(options);
    append_policy_options(&mut opts, stat_virtualization, host_permissions);
    if let Some(mib) = quota_mib {
        opts.push(format!("quota={mib}"));
    }
    append_option_block(&mut arg, opts);
    mounts.push(arg);
}

/// Append a `tag:guest_path[:ro]` entry to the `MSB_DIR_MOUNTS` env var value.
fn push_dir_mounts_spec(dir_mounts_val: &mut String, guest: &str, options: MountOptions) {
    if !dir_mounts_val.is_empty() {
        dir_mounts_val.push(';');
    }
    let tag = guest_mount_tag(guest);
    dir_mounts_val.push_str(&tag);
    dir_mounts_val.push(':');
    dir_mounts_val.push_str(guest);
    append_option_block(dir_mounts_val, mount_option_tokens(options));
}

/// Collect a `fm_tag:file_mount_dir[:ro]` mount entry.
fn push_file_mount_arg(
    mounts: &mut Vec<String>,
    tag: &str,
    file_mount_dir: &Path,
    options: MountOptions,
    stat_virtualization: StatVirtualization,
    host_permissions: HostPermissions,
) {
    let mut arg = format!("{tag}:{}", file_mount_dir.display());
    let mut opts = mount_option_tokens(options);
    append_policy_options(&mut opts, stat_virtualization, host_permissions);
    append_option_block(&mut arg, opts);
    mounts.push(arg);
}

/// Collect a `id:host_path:format[:ro]` disk entry.
fn push_disk_mount_arg(
    disks: &mut Vec<String>,
    id: &str,
    host_display: &impl std::fmt::Display,
    format: &DiskImageFormat,
    options: MountOptions,
) {
    let mut arg = format!("{id}:{host_display}:{}", format.as_str());
    if options.readonly {
        arg.push_str(":ro");
    }
    disks.push(arg);
}

/// Append a `id:guest_path[:opts]` entry to the `MSB_DISK_MOUNTS` env var value.
fn push_disk_mounts_spec(
    disk_mounts_val: &mut String,
    id: &str,
    guest: &str,
    fstype: Option<&str>,
    options: MountOptions,
) {
    if !disk_mounts_val.is_empty() {
        disk_mounts_val.push(';');
    }
    disk_mounts_val.push_str(id);
    disk_mounts_val.push(':');
    disk_mounts_val.push_str(guest);
    let mut opts = mount_option_tokens(options);
    if let Some(fs) = fstype {
        opts.push(format!("fstype={fs}"));
    }
    append_option_block(disk_mounts_val, opts);
}

/// Append a `tag:filename:guest_path[:ro]` entry to the `MSB_FILE_MOUNTS` env var value.
fn push_file_mounts_spec(
    file_mounts_val: &mut String,
    tag: &str,
    filename: &str,
    guest: &str,
    options: MountOptions,
) {
    if !file_mounts_val.is_empty() {
        file_mounts_val.push(';');
    }
    file_mounts_val.push_str(tag);
    file_mounts_val.push(':');
    file_mounts_val.push_str(filename);
    file_mounts_val.push(':');
    file_mounts_val.push_str(guest);
    append_option_block(file_mounts_val, mount_option_tokens(options));
}

fn mount_option_tokens(options: MountOptions) -> Vec<String> {
    let mut tokens = Vec::new();
    if options.readonly {
        tokens.push("ro".to_string());
    }
    if options.noexec {
        tokens.push("noexec".to_string());
    }
    if options.nosuid {
        tokens.push("nosuid".to_string());
    }
    if options.nodev {
        tokens.push("nodev".to_string());
    }
    tokens
}

fn append_policy_options(
    opts: &mut Vec<String>,
    stat_virtualization: StatVirtualization,
    host_permissions: HostPermissions,
) {
    match stat_virtualization {
        StatVirtualization::Strict => {}
        StatVirtualization::Relaxed => opts.push("stat-virt=relaxed".to_string()),
        StatVirtualization::Off => opts.push("stat-virt=off".to_string()),
    }
    match host_permissions {
        HostPermissions::Private => {}
        HostPermissions::Mirror => opts.push("host-perms=mirror".to_string()),
    }
}

fn append_option_block(spec: &mut String, opts: Vec<String>) {
    if opts.is_empty() {
        return;
    }
    spec.push(':');
    spec.push_str(&opts.join(","));
}

/// Encodes sandbox-wide rlimits for the guest init environment.
fn encode_rlimits(rlimits: &[Rlimit]) -> String {
    use std::fmt::Write;

    let mut out = String::with_capacity(rlimits.len() * 32);
    for (i, rlimit) in rlimits.iter().enumerate() {
        if i > 0 {
            out.push(';');
        }
        write!(
            out,
            "{}={}:{}",
            rlimit.resource.as_str(),
            rlimit.soft,
            rlimit.hard
        )
        .expect("writing to String cannot fail");
    }
    out
}

/// Encodes a handoff-init argv/env payload into printable env-var text.
fn encode_handoff_json<T: Serialize>(value: &T) -> String {
    let json = serde_json::to_vec(value).expect("handoff init payload is JSON-serializable");
    URL_SAFE_NO_PAD.encode(json)
}

/// Derive a stable, collision-resistant identifier from a guest mount path.
///
/// Used for virtiofs tags and for virtio-blk `serial` fields (the block id
/// agentd resolves via `/dev/disk/by-id/virtio-<id>`). The naive `/` → `_`
/// mangling collides for adversarial inputs (`/var/log` and `/var_log` both
/// produce `var_log`), so we append a short sha256-derived suffix.
///
/// Output is at most 20 bytes — the kernel's virtio-blk serial length limit.
/// Layout: `<slug[..11]>_<8-hex>`. The slug-part is a debugging hint; the
/// 8-hex suffix is what actually disambiguates.
fn guest_mount_tag(guest_path: &str) -> String {
    use std::fmt::Write as _;

    const SLUG_MAX: usize = 11;
    const HASH_HEX_LEN: usize = 8;

    let slug: String = guest_path
        .replace('/', "_")
        .trim_start_matches('_')
        .chars()
        .take(SLUG_MAX)
        .collect();

    let mut hasher = Sha256::new();
    hasher.update(guest_path.as_bytes());
    let digest = hasher.finalize();

    // Total layout: optional `<slug>_` prefix + HASH_HEX_LEN hex chars.
    let mut out = String::with_capacity(slug.len() + 1 + HASH_HEX_LEN);
    if !slug.is_empty() {
        out.push_str(&slug);
        out.push('_');
    }
    for byte in digest.iter().take(HASH_HEX_LEN / 2) {
        // write! to a String can't fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Build the `msb sandbox` CLI args for a sandbox.
#[allow(clippy::too_many_arguments)]
fn sandbox_cli_args(
    local: &LocalBackend,
    config: &SandboxConfig,
    sandbox_id: i32,
    db_path: &Path,
    db_connect_timeout_secs: u64,
    log_dir: &Path,
    runtime_dir: &Path,
    agent_sock_path: &Path,
    libkrunfw_path: &Path,
    staged_file_mounts: &HashMap<String, (PathBuf, String, String)>,
    named_volumes: &HashMap<String, ResolvedNamedVolume>,
    metrics_reservation: Option<&MetricsReservation>,
    parent_watch_fd: Option<i32>,
    startup_fd: Option<i32>,
    startup_pipe: Option<&OsStr>,
) -> (Vec<OsString>, LaunchConfig) {
    // `visible` stays on the process argv: a small set of operator-readable
    // labels (name, id, sizing, fds) so the sandbox is identifiable in `ps`
    // and logs. Everything bulky, structured, or secret-bearing goes into the
    // typed `LaunchConfig`, delivered over the config fd. See issue #997.
    let mut visible = vec![OsString::from("sandbox")];

    if let Some(log_level) = config.spec.runtime.log_level {
        visible.push(OsString::from(sandbox_log_level_cli_flag(log_level)));
    }

    visible.push(OsString::from("--name"));
    visible.push(OsString::from(&config.spec.name));
    visible.push(OsString::from("--sandbox-id"));
    visible.push(OsString::from(sandbox_id.to_string()));
    if let Some(fd) = parent_watch_fd {
        visible.push(OsString::from("--parent-watch-fd"));
        visible.push(OsString::from(fd.to_string()));
    }
    if let Some(fd) = startup_fd {
        visible.push(OsString::from("--startup-fd"));
        visible.push(OsString::from(fd.to_string()));
    }
    if let Some(pipe) = startup_pipe {
        visible.push(OsString::from("--startup-pipe"));
        visible.push(pipe.to_os_string());
    }
    visible.push(OsString::from("--vcpus"));
    visible.push(OsString::from(config.spec.resources.vcpus.to_string()));
    visible.push(OsString::from("--memory-mib"));
    visible.push(OsString::from(config.spec.resources.memory_mib.to_string()));
    if config.spec.resources.max_vcpus > config.spec.resources.vcpus {
        visible.push(OsString::from("--max-vcpus"));
        visible.push(OsString::from(config.spec.resources.max_vcpus.to_string()));
    }
    if config.spec.resources.max_memory_mib > config.spec.resources.memory_mib {
        visible.push(OsString::from("--max-memory-mib"));
        visible.push(OsString::from(
            config.spec.resources.max_memory_mib.to_string(),
        ));
    }

    let mut launch = LaunchConfig {
        db_path: db_path.to_path_buf(),
        db_connect_timeout_secs,
        log_dir: log_dir.to_path_buf(),
        runtime_dir: runtime_dir.to_path_buf(),
        sandboxes_dir: local.sandboxes_dir(),
        agent_sock: agent_sock_path.to_path_buf(),
        libkrunfw_path: libkrunfw_path.to_path_buf(),
        startup: startup_command(config),
        lifecycle: Lifecycle {
            max_duration_secs: config.spec.lifecycle.max_duration_secs,
            idle_timeout_secs: config.spec.lifecycle.idle_timeout_secs,
        },
        workdir: config.spec.runtime.workdir.as_ref().map(PathBuf::from),
        ..Default::default()
    };

    match config.effective_metrics_interval() {
        Some(ms) => launch.metrics.sample_interval_ms = ms.get(),
        None => launch.metrics.disabled = true,
    }
    if let Some(reservation) = metrics_reservation {
        launch.metrics.slot = Some(MetricsSlotHandoff {
            shm_name: reservation.shm_name.clone(),
            slot: reservation.slot,
            generation: reservation.generation,
        });
    }

    match &config.spec.image {
        RootfsSource::Bind(path) => {
            launch.rootfs.path = Some(path.clone());
        }
        RootfsSource::Oci(_) => {
            // Derive VMDK + upper paths from the stored manifest digest.
            if let Some(ref digest_str) = config.manifest_digest {
                let cache_dir = local.cache_dir();
                let cache = GlobalCache::new(&cache_dir).expect("cache init");
                let digest: Digest = digest_str.parse().expect("invalid manifest digest");
                let vmdk_path = cache.vmdk_path(&digest);

                let sandbox_dir = local.sandboxes_dir().join(&config.spec.name);
                let upper_path = sandbox_dir.join("upper.ext4");

                // VMDK (fsmeta + layers) read-only + upper.ext4 writable.
                launch.rootfs.disk = Some(vmdk_path);
                launch.rootfs.disk_format = Some("vmdk".to_string());
                launch.rootfs.upper = Some(upper_path);

                // MSB_BLOCK_ROOT: always 2 devices.
                let block_root = "kind=oci-erofs,lower=/dev/vda,upper=/dev/vdb,upper_fstype=ext4";
                launch.env.push(format!("{}={block_root}", ENV_BLOCK_ROOT));
            }
        }
        RootfsSource::DiskImage {
            path,
            format,
            fstype,
        } => {
            launch.rootfs.disk = Some(path.clone());
            launch.rootfs.disk_format = Some(format.as_str().to_string());

            // Build MSB_BLOCK_ROOT env var value.
            let mut block_root_val = String::from("kind=disk-image,device=/dev/vda");
            if let Some(ft) = fstype {
                block_root_val.push_str(&format!(",fstype={ft}"));
            }
            launch
                .env
                .push(format!("{}={block_root_val}", ENV_BLOCK_ROOT));
        }
    }

    // Process mounts: emit --mount args for virtiofs mounts, --disk args
    // for disk-image mounts, and collect guest-side mount specs as env
    // vars for agentd.
    let mut tmpfs_val = String::new();
    let mut dir_mounts_val = String::new();
    let mut file_mounts_val = String::new();
    let mut disk_mounts_val = String::new();
    for mount in &config.spec.mounts {
        match mount {
            VolumeMount::Bind {
                host,
                guest,
                options,
                stat_virtualization,
                host_permissions,
                quota_mib,
            } => {
                if let Some((file_mount_dir, filename, tag)) = staged_file_mounts.get(guest) {
                    push_file_mount_arg(
                        &mut launch.mounts,
                        tag,
                        file_mount_dir,
                        *options,
                        *stat_virtualization,
                        *host_permissions,
                    );
                    push_file_mounts_spec(&mut file_mounts_val, tag, filename, guest, *options);
                } else {
                    // A directory bind mount gets a protective guest-write
                    // quota: the caller's override, or the default.
                    let quota = quota_mib.unwrap_or(crate::sandbox::config::DEFAULT_BIND_QUOTA_MIB);
                    push_dir_mount_arg(
                        &mut launch.mounts,
                        guest,
                        &host.display(),
                        *options,
                        *stat_virtualization,
                        *host_permissions,
                        Some(quota),
                    );
                    push_dir_mounts_spec(&mut dir_mounts_val, guest, *options);
                }
            }
            VolumeMount::Named {
                name,
                guest,
                options,
                stat_virtualization,
                host_permissions,
                create: _,
            } => {
                let named_volume = named_volumes
                    .get(name)
                    .expect("resolve_named_volumes must resolve every named volume before render");
                match named_volume {
                    ResolvedNamedVolume {
                        kind: VolumeKind::Disk,
                        path,
                        format,
                        fstype,
                        ..
                    } => {
                        let format = format
                            .as_ref()
                            .expect("resolved disk named volumes must carry a disk format");
                        let id = guest_mount_tag(guest);
                        push_disk_mount_arg(
                            &mut launch.disks,
                            &id,
                            &path.display(),
                            format,
                            *options,
                        );
                        push_disk_mounts_spec(
                            &mut disk_mounts_val,
                            &id,
                            guest,
                            fstype.as_deref(),
                            *options,
                        );
                    }
                    ResolvedNamedVolume {
                        path, quota_mib, ..
                    } => {
                        push_dir_mount_arg(
                            &mut launch.mounts,
                            guest,
                            &path.display(),
                            *options,
                            *stat_virtualization,
                            *host_permissions,
                            *quota_mib,
                        );
                        push_dir_mounts_spec(&mut dir_mounts_val, guest, *options);
                    }
                }
            }
            VolumeMount::Tmpfs {
                guest,
                size_mib,
                options,
            } => {
                if !tmpfs_val.is_empty() {
                    tmpfs_val.push(';');
                }
                tmpfs_val.push_str(guest);
                let mut opts = Vec::new();
                if let Some(s) = size_mib {
                    opts.push(format!("size={s}"));
                }
                opts.extend(mount_option_tokens(*options));
                append_option_block(&mut tmpfs_val, opts);
            }
            VolumeMount::DiskImage {
                host,
                guest,
                format,
                fstype,
                options,
            } => {
                let id = guest_mount_tag(guest);
                push_disk_mount_arg(&mut launch.disks, &id, &host.display(), format, *options);
                push_disk_mounts_spec(
                    &mut disk_mounts_val,
                    &id,
                    guest,
                    fstype.as_deref(),
                    *options,
                );
            }
        }
    }

    if !tmpfs_val.is_empty() {
        launch.env.push(format!("{}={tmpfs_val}", ENV_TMPFS));
    }
    if !dir_mounts_val.is_empty() {
        launch
            .env
            .push(format!("{}={dir_mounts_val}", ENV_DIR_MOUNTS));
    }
    if !file_mounts_val.is_empty() {
        launch
            .env
            .push(format!("{}={file_mounts_val}", ENV_FILE_MOUNTS));
    }
    if !disk_mounts_val.is_empty() {
        launch
            .env
            .push(format!("{}={disk_mounts_val}", ENV_DISK_MOUNTS));
    }

    if !config.spec.rlimits.is_empty() {
        launch.env.push(format!(
            "{}={}",
            microsandbox_protocol::ENV_RLIMITS,
            encode_rlimits(&config.spec.rlimits)
        ));
    }

    // Network configuration travels as a typed value inside the JSON payload.
    #[cfg(feature = "net")]
    {
        launch.network = Some(
            config
                .local_network_config()
                .expect("sandbox network spec should decode to local network config"),
        );
        launch.sandbox_slot = sandbox_id as u64;
    }

    for var in &config.spec.env {
        launch.env.push(format!("{}={}", var.key, var.value));
    }

    if let Some(ref user) = config.spec.runtime.user {
        launch.env.push(format!("{}={user}", ENV_USER));
    }

    launch.env.push(format!(
        "{}={}",
        ENV_SECURITY_PROFILE,
        match config.spec.security_profile {
            crate::sandbox::SecurityProfile::Default => "default",
            crate::sandbox::SecurityProfile::Restricted => "restricted",
        }
    ));

    // Hostname: explicit value or fall back to a sandbox-name-derived form
    // that fits within the Linux UTS limit.
    {
        let hostname = match config.spec.runtime.hostname.as_deref() {
            Some(h) => h.to_string(),
            None => crate::sandbox::hostname_from_sandbox_name(&config.spec.name),
        };
        launch.env.push(format!("{}={hostname}", ENV_HOSTNAME));
    }

    // Handoff-init: PID 1 hand-off to a user-supplied init binary.
    // The builder's `validate()` rejects non-UTF-8 cmd paths, args/env
    // containing NUL, and env keys containing `=`, so the JSON payloads
    // below can't produce a corrupted execve wire format.
    if let Some(ref init) = config.spec.init {
        let cmd = init
            .cmd
            .to_str()
            .expect("validate() rejects non-UTF-8 cmd paths");
        launch.env.push(format!("{ENV_HANDOFF_INIT}={cmd}"));

        if !init.args.is_empty() {
            let argv_val = encode_handoff_json(&init.args);
            launch
                .env
                .push(format!("{ENV_HANDOFF_INIT_ARGS}={argv_val}"));
        }

        if let Some(ref workdir) = config.spec.runtime.workdir {
            launch.env.push(format!("{ENV_HANDOFF_INIT_CWD}={workdir}"));
        }

        if !init.env.is_empty() {
            let env_val = encode_handoff_json(&init.env);
            launch.env.push(format!("{ENV_HANDOFF_INIT_ENV}={env_val}"));
        }
    }

    (visible, launch)
}

fn startup_command(config: &SandboxConfig) -> Option<StartupCommand> {
    let (cmd, cmd_args) = resolve_startup_command(config)?;
    Some(StartupCommand {
        cmd,
        args: cmd_args,
        env: config
            .spec
            .env
            .iter()
            .map(|var| format!("{}={}", var.key, var.value))
            .collect(),
        cwd: config.spec.runtime.workdir.clone(),
        user: config.spec.runtime.user.clone(),
    })
}

fn resolve_startup_command(config: &SandboxConfig) -> Option<(String, Vec<String>)> {
    if !config.startup_command_requested {
        return None;
    }

    match (&config.spec.runtime.entrypoint, &config.spec.runtime.cmd) {
        (Some(entrypoint), cmd) if !entrypoint.is_empty() => {
            let bin = entrypoint[0].clone();
            let args = entrypoint[1..]
                .iter()
                .chain(cmd.iter().flatten())
                .cloned()
                .collect();
            Some((bin, args))
        }
        (_, Some(cmd)) if !cmd.is_empty() => {
            let bin = cmd[0].clone();
            let args = cmd[1..].to_vec();
            Some((bin, args))
        }
        _ => None,
    }
}

fn sandbox_log_level_cli_flag(level: SandboxLogLevel) -> &'static str {
    match level {
        SandboxLogLevel::Error => "--error",
        SandboxLogLevel::Warn => "--warn",
        SandboxLogLevel::Info => "--info",
        SandboxLogLevel::Debug => "--debug",
        SandboxLogLevel::Trace => "--trace",
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::ffi::{OsStr, OsString};
    use std::path::{Path, PathBuf};

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use microsandbox_types::HandoffInit;
    use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
    use serde::de::DeserializeOwned;
    use tempfile::tempdir;

    use microsandbox_runtime::launch::LaunchConfig;

    use super::sandbox_cli_args;
    use crate::{
        LogLevel,
        backend::LocalBackend,
        sandbox::{
            DiskImageFormat, HostPermissions, MountOptions, OciRootfsSource, Rlimit,
            RlimitResource, RootfsSource, SandboxBuilder, SandboxConfig, StatVirtualization,
            VolumeMount,
        },
        volume::VolumeKind,
    };

    #[test]
    #[cfg(unix)]
    fn test_inherited_fd_source_needs_spare_for_cross_reserved_fd() {
        assert!(super::inherited_fd_source_needs_spare(
            microsandbox_runtime::vm::CONFIG_FD,
            microsandbox_runtime::vm::PARENT_WATCH_FD,
        ));
        assert!(super::inherited_fd_source_needs_spare(
            microsandbox_runtime::vm::PARENT_WATCH_FD,
            microsandbox_runtime::vm::STARTUP_FD,
        ));
    }

    #[test]
    #[cfg(unix)]
    fn test_inherited_fd_source_keeps_own_reserved_fd_in_place() {
        assert!(!super::inherited_fd_source_needs_spare(
            microsandbox_runtime::vm::CONFIG_FD,
            microsandbox_runtime::vm::CONFIG_FD,
        ));
        assert!(!super::inherited_fd_source_needs_spare(
            microsandbox_runtime::vm::PARENT_WATCH_FD,
            microsandbox_runtime::vm::PARENT_WATCH_FD,
        ));
    }

    #[test]
    #[cfg(unix)]
    fn test_inherited_fd_source_leaves_ordinary_fd_in_place() {
        assert!(!super::inherited_fd_source_needs_spare(
            42,
            microsandbox_runtime::vm::CONFIG_FD,
        ));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_sigchld_handler_uses_alt_stack_after_prepare() {
        super::ensure_sigchld_handler_uses_alt_stack_before_spawn()
            .await
            .unwrap();

        unsafe {
            let mut action = std::mem::MaybeUninit::<libc::sigaction>::uninit();
            let rc = libc::sigaction(libc::SIGCHLD, std::ptr::null(), action.as_mut_ptr());
            assert_eq!(rc, 0, "failed to read SIGCHLD action");

            let action = action.assume_init();
            assert_ne!(
                action.sa_flags & libc::SA_ONSTACK,
                0,
                "SIGCHLD handler should run on the alternate signal stack"
            );
        }
    }

    //----------------------------------------------------------------------------------------------
    // Functions: Helpers
    //----------------------------------------------------------------------------------------------

    /// Build a `LocalBackend` for tests. Uses `lazy()` since these tests only
    /// exercise the pure-rendering `sandbox_cli_args` path — no DB / FS
    /// touches.
    fn test_local_backend() -> LocalBackend {
        LocalBackend::lazy()
    }

    /// Re-expand a [`LaunchConfig`] into the historical `--flag value` token
    /// stream so the token-based assertions below keep working. Mirrors the
    /// former producer output field-for-field.
    fn flatten_launch(launch: &LaunchConfig) -> Vec<String> {
        fn pair(out: &mut Vec<String>, flag: &str, val: String) {
            out.push(flag.to_string());
            out.push(val);
        }
        fn path(p: &Path) -> String {
            p.to_string_lossy().into_owned()
        }

        let mut out: Vec<String> = Vec::new();
        pair(&mut out, "--db-path", path(&launch.db_path));
        pair(
            &mut out,
            "--db-connect-timeout-secs",
            launch.db_connect_timeout_secs.to_string(),
        );
        pair(&mut out, "--log-dir", path(&launch.log_dir));
        pair(&mut out, "--runtime-dir", path(&launch.runtime_dir));
        pair(&mut out, "--sandboxes-dir", path(&launch.sandboxes_dir));
        pair(&mut out, "--agent-sock", path(&launch.agent_sock));
        if let Some(s) = &launch.startup {
            out.push(format!("--startup-cmd={}", s.cmd));
            for a in &s.args {
                out.push(format!("--startup-arg={a}"));
            }
            for e in &s.env {
                out.push(format!("--startup-env={e}"));
            }
            if let Some(c) = &s.cwd {
                out.push(format!("--startup-cwd={c}"));
            }
            if let Some(u) = &s.user {
                out.push(format!("--startup-user={u}"));
            }
        }
        if let Some(d) = launch.lifecycle.max_duration_secs {
            pair(&mut out, "--max-duration", d.to_string());
        }
        if let Some(i) = launch.lifecycle.idle_timeout_secs {
            pair(&mut out, "--idle-timeout", i.to_string());
        }
        pair(&mut out, "--libkrunfw-path", path(&launch.libkrunfw_path));
        if launch.metrics.disabled {
            out.push("--disable-metrics-sample".to_string());
        } else {
            pair(
                &mut out,
                "--metrics-sample-interval-ms",
                launch.metrics.sample_interval_ms.to_string(),
            );
        }
        if let Some(slot) = &launch.metrics.slot {
            pair(&mut out, "--metrics-shm-name", slot.shm_name.clone());
            pair(&mut out, "--metrics-slot", slot.slot.to_string());
            pair(
                &mut out,
                "--metrics-generation",
                slot.generation.to_string(),
            );
        }
        if let Some(p) = &launch.rootfs.path {
            pair(&mut out, "--rootfs-path", path(p));
        }
        if let Some(d) = &launch.rootfs.disk {
            pair(&mut out, "--rootfs-disk", path(d));
        }
        if let Some(f) = &launch.rootfs.disk_format {
            pair(&mut out, "--rootfs-disk-format", f.clone());
        }
        if let Some(u) = &launch.rootfs.upper {
            pair(&mut out, "--rootfs-blk", path(u));
        }
        for m in &launch.mounts {
            pair(&mut out, "--mount", m.clone());
        }
        for d in &launch.disks {
            pair(&mut out, "--disk", d.clone());
        }
        for e in &launch.env {
            pair(&mut out, "--env", e.clone());
        }
        #[cfg(feature = "net")]
        if let Some(net) = &launch.network {
            pair(
                &mut out,
                "--network-config",
                serde_json::to_string(net).unwrap(),
            );
            pair(&mut out, "--sandbox-slot", launch.sandbox_slot.to_string());
        }
        if let Some(w) = &launch.workdir {
            pair(&mut out, "--workdir", path(w));
        }
        out
    }

    /// Render the full arg set (visible argv + the flattened config payload)
    /// as strings. Tests assert on the union since both feed `msb sandbox`.
    fn render_args(config: &SandboxConfig) -> Vec<String> {
        render_args_with_named_volumes(config, &HashMap::new())
    }

    fn render_args_with_named_volumes(
        config: &SandboxConfig,
        named_volumes: &HashMap<String, super::ResolvedNamedVolume>,
    ) -> Vec<String> {
        let local = test_local_backend();
        let (visible, launch) = sandbox_cli_args(
            &local,
            config,
            42,
            Path::new("/tmp/msb.db"),
            30,
            Path::new("/tmp/logs"),
            Path::new("/tmp/runtime"),
            Path::new("/tmp/agent.sock"),
            Path::new("/tmp/libkrunfw.dylib"),
            &HashMap::new(),
            named_volumes,
            None,
            None,
            None,
            None,
        );
        visible
            .into_iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .chain(flatten_launch(&launch))
            .collect()
    }

    fn named_disk(path: impl Into<PathBuf>) -> super::ResolvedNamedVolume {
        super::ResolvedNamedVolume {
            kind: VolumeKind::Disk,
            path: path.into(),
            format: Some(DiskImageFormat::Raw),
            fstype: Some("ext4".to_string()),
            quota_mib: None,
        }
    }

    fn named_directory(
        path: impl Into<PathBuf>,
        quota_mib: Option<u32>,
    ) -> super::ResolvedNamedVolume {
        super::ResolvedNamedVolume {
            kind: VolumeKind::Directory,
            path: path.into(),
            format: None,
            fstype: None,
            quota_mib,
        }
    }

    fn named_volume_create(
        name: &str,
        kind: VolumeKind,
        quota_mib: Option<u32>,
        capacity_mib: Option<u32>,
        labels: Vec<(String, String)>,
    ) -> microsandbox_types::NamedVolumeCreate {
        microsandbox_types::NamedVolumeCreate {
            mode: crate::sandbox::NamedVolumeMode::EnsureExists,
            name: name.to_string(),
            kind,
            quota_mib,
            capacity_mib,
            labels,
        }
    }

    fn existing_volume_model(
        name: &str,
        kind: VolumeKind,
        quota_mib: Option<i32>,
        capacity_bytes: Option<i64>,
        labels: Option<Vec<(String, String)>>,
    ) -> super::volume_entity::Model {
        super::volume_entity::Model {
            id: 1,
            name: name.to_string(),
            kind: kind.as_str().to_string(),
            quota_mib,
            size_bytes: None,
            capacity_bytes,
            disk_format: (kind == VolumeKind::Disk).then(|| "raw".to_string()),
            disk_fstype: (kind == VolumeKind::Disk).then(|| "ext4".to_string()),
            labels: labels.map(|labels| serde_json::to_string(&labels).unwrap()),
            created_at: Some(chrono::Utc::now().naive_utc()),
            updated_at: Some(chrono::Utc::now().naive_utc()),
        }
    }

    /// Render only the `visible` argv (what shows up in `ps`).
    fn render_visible_args(config: &SandboxConfig) -> Vec<String> {
        let local = test_local_backend();
        let (visible, _piped) = sandbox_cli_args(
            &local,
            config,
            42,
            Path::new("/tmp/msb.db"),
            30,
            Path::new("/tmp/logs"),
            Path::new("/tmp/runtime"),
            Path::new("/tmp/agent.sock"),
            Path::new("/tmp/libkrunfw.dylib"),
            &HashMap::new(),
            &HashMap::new(),
            None,
            None,
            None,
            None,
        );
        visible
            .into_iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    fn decode_handoff_json<T: DeserializeOwned>(value: &str) -> T {
        let json = URL_SAFE_NO_PAD.decode(value).expect("base64url payload");
        serde_json::from_slice(&json).expect("handoff JSON payload")
    }

    fn render_args_with_file_mounts(
        config: &SandboxConfig,
        staged_file_mounts: &HashMap<String, (PathBuf, String, String)>,
    ) -> Vec<String> {
        let local = test_local_backend();
        let (visible, launch) = sandbox_cli_args(
            &local,
            config,
            42,
            Path::new("/tmp/msb.db"),
            30,
            Path::new("/tmp/logs"),
            Path::new("/tmp/runtime"),
            Path::new("/tmp/agent.sock"),
            Path::new("/tmp/libkrunfw.dylib"),
            staged_file_mounts,
            &HashMap::new(),
            None,
            None,
            None,
            None,
        );
        visible
            .into_iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .chain(flatten_launch(&launch))
            .collect()
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_include_selected_log_level() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .log_level(LogLevel::Debug)
            .build()
            .await
            .unwrap();

        let args = render_args(&config);

        assert!(args.iter().any(|arg| arg == "--debug"));
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_are_silent_by_default() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .build()
            .await
            .unwrap();

        let args = render_args(&config);

        assert!(!args.iter().any(|arg| {
            matches!(
                arg.as_str(),
                "--error" | "--warn" | "--info" | "--debug" | "--trace"
            )
        }));
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_include_agent_sock_path() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);

        assert!(
            rendered
                .windows(2)
                .any(|pair| pair == ["--agent-sock", "/tmp/agent.sock"])
        );
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_include_startup_fd_when_supplied() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .build()
            .await
            .unwrap();

        let local = test_local_backend();
        let (visible, _piped) = sandbox_cli_args(
            &local,
            &config,
            42,
            Path::new("/tmp/msb.db"),
            30,
            Path::new("/tmp/logs"),
            Path::new("/tmp/runtime"),
            Path::new("/tmp/agent.sock"),
            Path::new("/tmp/libkrunfw.dylib"),
            &HashMap::new(),
            &HashMap::new(),
            None,
            None,
            Some(microsandbox_runtime::vm::STARTUP_FD),
            None,
        );

        // The startup fd is an operator-visible label, so it stays on argv.
        assert!(visible.windows(2).any(|pair| pair
            == [
                OsString::from("--startup-fd"),
                OsString::from(microsandbox_runtime::vm::STARTUP_FD.to_string()),
            ]));
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_include_detached_startup_command() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .entrypoint(["/entrypoint"])
            .env("APP_ENV", "test")
            .workdir("/workspace")
            .user("nobody")
            .persistent_initial_command(["/bin/sh", "-lc", "echo detached"])
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);

        assert!(rendered.contains(&"--startup-cmd=/entrypoint".to_string()));
        assert!(rendered.contains(&"--startup-arg=/bin/sh".to_string()));
        assert!(rendered.contains(&"--startup-arg=-lc".to_string()));
        assert!(rendered.contains(&"--startup-arg=echo detached".to_string()));
        assert!(rendered.contains(&"--startup-env=APP_ENV=test".to_string()));
        assert!(rendered.contains(&"--startup-cwd=/workspace".to_string()));
        assert!(rendered.contains(&"--startup-user=nobody".to_string()));
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_include_startup_pipe_when_supplied() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .build()
            .await
            .unwrap();
        let local = test_local_backend();
        let (visible, _launch) = sandbox_cli_args(
            &local,
            &config,
            42,
            Path::new("/tmp/msb.db"),
            30,
            Path::new("/tmp/logs"),
            Path::new("/tmp/runtime"),
            Path::new("/tmp/agent.sock"),
            Path::new("/tmp/libkrunfw.dylib"),
            &HashMap::new(),
            &HashMap::new(),
            None,
            None,
            None,
            Some(OsStr::new(r"\\.\pipe\msb-startup-test")),
        );

        assert!(visible.windows(2).any(|pair| pair
            == [
                OsString::from("--startup-pipe"),
                OsString::from(r"\\.\pipe\msb-startup-test"),
            ]));
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_skip_startup_exec_when_init_owns_argv() {
        let mut config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .workdir("/opt/hermes")
            .persistent_initial_command(["gateway", "run"])
            .build()
            .await
            .unwrap();
        config.spec.init = Some(HandoffInit {
            cmd: PathBuf::from("/init"),
            args: vec![
                "/opt/hermes/docker/main-wrapper.sh".to_string(),
                "gateway".to_string(),
                "run".to_string(),
            ],
            env: Vec::new(),
        });
        config.startup_command_requested = false;

        let rendered = render_args(&config);

        assert_eq!(
            find_env(&rendered, "MSB_HANDOFF_INIT").as_deref(),
            Some("/init")
        );
        let argv = find_env(&rendered, "MSB_HANDOFF_INIT_ARGS").expect("argv env present");
        let decoded: Vec<String> = decode_handoff_json(&argv);
        assert_eq!(
            decoded,
            vec![
                "/opt/hermes/docker/main-wrapper.sh".to_string(),
                "gateway".to_string(),
                "run".to_string(),
            ]
        );
        assert_eq!(
            find_env(&rendered, "MSB_HANDOFF_INIT_CWD").as_deref(),
            Some("/opt/hermes")
        );
        assert!(!rendered.iter().any(|arg| arg.starts_with("--startup-cmd")));
        assert!(!rendered.iter().any(|arg| arg.starts_with("--startup-arg")));
    }

    #[tokio::test]
    async fn test_agent_socket_candidates_follow_explicit_local_backend_paths() {
        let temp = tempdir().unwrap();
        let home = temp.path().join("msb-home");
        let backend = LocalBackend::builder().home(&home).build().await.unwrap();

        let candidates =
            super::sandbox_agent_socket_path_candidates_for(&backend, "sdk-socket-test");

        #[cfg(unix)]
        {
            assert_eq!(candidates.len(), 2);
            assert!(candidates[0].starts_with(backend.config().run_dir().join("agent")));
            assert_eq!(
                candidates[1],
                backend
                    .config()
                    .sandboxes_dir()
                    .join("sdk-socket-test")
                    .join("runtime")
                    .join("agent.sock")
            );
        }
        #[cfg(windows)]
        {
            assert_eq!(candidates.len(), 1);
            assert!(
                candidates[0]
                    .to_string_lossy()
                    .starts_with(r"\\.\pipe\msb-agent-")
            );
        }
    }

    #[tokio::test]
    async fn test_agent_socket_resolution_uses_explicit_local_backend_paths() {
        // Root the backend home under a short directory so the derived AF_UNIX
        // socket path stays within the platform `sun_path` limit (104 bytes on
        // macOS). The default system temp dir on macOS lives under
        // `/var/folders/...`, long enough to overflow that limit and make
        // resolution fail spuriously. Windows uses named pipes (no length
        // limit), so the default temp dir is fine there.
        #[cfg(unix)]
        let temp = tempfile::Builder::new()
            .prefix("msb")
            .tempdir_in("/tmp")
            .unwrap();
        #[cfg(not(unix))]
        let temp = tempfile::Builder::new().prefix("msb").tempdir().unwrap();
        let home = temp.path().join("msb-home");
        let backend = LocalBackend::builder().home(&home).build().await.unwrap();

        let resolved =
            super::resolve_sandbox_agent_socket_path_for(&backend, "sdk-socket-test").unwrap();

        #[cfg(unix)]
        assert!(resolved.starts_with(backend.config().run_dir().join("agent")));
        #[cfg(windows)]
        assert!(
            resolved
                .to_string_lossy()
                .starts_with(r"\\.\pipe\msb-agent-")
        );
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_include_rlimits_env() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .rlimit(RlimitResource::Nofile, 65_535)
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);

        assert!(rendered.windows(2).any(|pair| {
            pair[0] == "--env"
                && pair[1] == format!("{}=nofile=65535:65535", microsandbox_protocol::ENV_RLIMITS)
        }));
    }

    #[tokio::test]
    async fn test_visible_args_keep_labels_and_omit_bulk() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .env("TOKEN", "secret")
            .build()
            .await
            .unwrap();

        let visible = render_visible_args(&config);
        let all = render_args(&config);

        // Operator-readable labels stay on argv.
        assert_eq!(visible.first().map(String::as_str), Some("sandbox"));
        assert!(visible.windows(2).any(|p| p == ["--name", "test"]));
        assert!(visible.iter().any(|a| a == "--vcpus"));
        assert!(visible.iter().any(|a| a == "--memory-mib"));

        // Bulk / secret-bearing flags never appear on argv...
        for flag in ["--env", "--db-path", "--log-dir", "--agent-sock"] {
            assert!(
                !visible.iter().any(|a| a == flag),
                "visible argv unexpectedly contains {flag}"
            );
        }
        assert!(!visible.iter().any(|a| a.contains("TOKEN=secret")));

        // ...but are present in the full (piped) arg set.
        assert!(all.iter().any(|a| a == "--db-path"));
        assert!(all.iter().any(|a| a.contains("TOKEN=secret")));
    }

    #[tokio::test]
    async fn test_encode_rlimits_round_trips_through_protocol_parser() {
        use microsandbox_protocol::exec::ExecRlimit;

        let rlimits = vec![
            Rlimit {
                resource: RlimitResource::Nofile,
                soft: 4096,
                hard: 65_535,
            },
            Rlimit {
                resource: RlimitResource::Nproc,
                soft: 1024,
                hard: 1024,
            },
        ];

        let encoded = super::encode_rlimits(&rlimits);
        let parsed: Vec<ExecRlimit> = encoded
            .split(';')
            .map(|entry| entry.parse::<ExecRlimit>().unwrap())
            .collect();

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].resource, "nofile");
        assert_eq!(parsed[0].soft, 4096);
        assert_eq!(parsed[0].hard, 65_535);
        assert_eq!(parsed[1].resource, "nproc");
        assert_eq!(parsed[1].soft, 1024);
        assert_eq!(parsed[1].hard, 1024);
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_emit_metrics_interval_flag() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .metrics_sample_interval(std::time::Duration::from_millis(1000))
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);

        assert!(
            rendered
                .windows(2)
                .any(|pair| pair == ["--metrics-sample-interval-ms", "1000"]),
            "expected metrics interval flag in {rendered:?}"
        );
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_include_custom_metrics_sample_interval() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .metrics_sample_interval(std::time::Duration::from_millis(2500))
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);

        assert!(
            rendered
                .windows(2)
                .any(|pair| pair == ["--metrics-sample-interval-ms", "2500"]),
            "expected custom metrics interval flag in {rendered:?}"
        );
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_disabled_metrics_emit_disable_flag() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .metrics_sample_interval(std::time::Duration::ZERO)
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);

        assert!(
            rendered.iter().any(|arg| arg == "--disable-metrics-sample"),
            "expected `--disable-metrics-sample` flag; got {rendered:?}"
        );
        assert!(
            !rendered
                .iter()
                .any(|arg| arg == "--metrics-sample-interval-ms"),
            "should not also emit interval flag; got {rendered:?}"
        );
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_disable_overrides_positive_interval() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .metrics_sample_interval(std::time::Duration::from_millis(2500))
            .disable_metrics_sample()
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);

        assert!(
            rendered.iter().any(|arg| arg == "--disable-metrics-sample"),
            "expected disable flag to win over positive interval; got {rendered:?}"
        );
        assert!(
            !rendered
                .iter()
                .any(|arg| arg == "--metrics-sample-interval-ms"),
            "should not emit interval flag when disable is set; got {rendered:?}"
        );
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_include_db_connect_timeout() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);

        assert!(
            rendered
                .windows(2)
                .any(|pair| pair == ["--db-connect-timeout-secs", "30"])
        );
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_use_passthrough_for_bind_rootfs() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);
        assert!(rendered.contains(&"--rootfs-path".to_string()));
        assert!(rendered.contains(&"/tmp/rootfs".to_string()));
        assert!(!rendered.contains(&"--rootfs-lower".to_string()));
        assert!(!rendered.contains(&"--rootfs-upper".to_string()));
        assert!(!rendered.contains(&"--rootfs-staging".to_string()));
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_oci_without_manifest_digest_emits_no_block_root() {
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .build()
            .await
            .unwrap();
        assert!(matches!(config.spec.image, RootfsSource::Oci(_)));

        let rendered = render_args(&config);
        // Without a manifest_digest set, no block root args should be emitted.
        assert!(!rendered.contains(&"--rootfs-blk".to_string()));
        assert!(!rendered.contains(&"--rootfs-disk".to_string()));
        assert!(!rendered.iter().any(|a| a.starts_with("MSB_BLOCK_ROOT=")));
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_inject_tmpfs_env_var() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/tmp", |m| m.tmpfs().size(256u32))
            .volume("/var/tmp", |m| m.tmpfs())
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);

        assert!(rendered.contains(&"MSB_TMPFS=/tmp:size=256;/var/tmp".to_string()));
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_tmpfs_readonly_appends_ro() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/seed", |m| m.tmpfs().size(64u32).readonly())
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);

        assert!(rendered.contains(&"MSB_TMPFS=/seed:size=64,ro".to_string()));
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_apply_default_oci_tmpfs() {
        let mut config = SandboxConfig {
            spec: microsandbox_types::SandboxSpec {
                name: "test".into(),
                image: RootfsSource::Oci(OciRootfsSource {
                    reference: "alpine".into(),
                    upper_size_mib: None,
                }),
                resources: microsandbox_types::SandboxResources {
                    memory_mib: 1024,
                    ..Default::default()
                },
                ..Default::default()
            },
            manifest_digest: Some(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            ),
            ..Default::default()
        };
        config.apply_runtime_defaults();

        let rendered = render_args(&config);

        assert!(rendered.contains(&"MSB_TMPFS=/tmp:size=256".to_string()));
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_omit_tmpfs_env_var_when_no_tmpfs() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);

        assert!(!rendered.iter().any(|a| a.starts_with("MSB_TMPFS=")));
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_disk_image_with_fstype() {
        let config = SandboxBuilder::new("test")
            .image_with(|i| i.disk("/tmp/ubuntu.qcow2").fstype("ext4"))
            .build()
            .await
            .unwrap();

        assert!(matches!(config.spec.image, RootfsSource::DiskImage { .. }));

        let rendered = render_args(&config);

        assert!(rendered.contains(&"--rootfs-disk".to_string()));
        assert!(rendered.contains(&"/tmp/ubuntu.qcow2".to_string()));
        assert!(rendered.contains(&"--rootfs-disk-format".to_string()));
        assert!(rendered.contains(&"qcow2".to_string()));
        assert!(
            rendered.contains(
                &"MSB_BLOCK_ROOT=kind=disk-image,device=/dev/vda,fstype=ext4".to_string()
            )
        );

        // Should not contain bind or overlay args.
        assert!(!rendered.contains(&"--rootfs-path".to_string()));
        assert!(!rendered.contains(&"--rootfs-lower".to_string()));
        assert!(!rendered.contains(&"--rootfs-upper".to_string()));
        assert!(!rendered.contains(&"--rootfs-staging".to_string()));
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_disk_image_without_fstype() {
        let config = SandboxBuilder::new("test")
            .image_with(|i| i.disk("/tmp/alpine.raw"))
            .build()
            .await
            .unwrap();

        assert!(matches!(config.spec.image, RootfsSource::DiskImage { .. }));

        let rendered = render_args(&config);

        assert!(rendered.contains(&"--rootfs-disk".to_string()));
        assert!(rendered.contains(&"/tmp/alpine.raw".to_string()));
        assert!(rendered.contains(&"--rootfs-disk-format".to_string()));
        assert!(rendered.contains(&"raw".to_string()));
        assert!(rendered.contains(&"MSB_BLOCK_ROOT=kind=disk-image,device=/dev/vda".to_string()));

        // Should not contain bind or overlay args.
        assert!(!rendered.contains(&"--rootfs-path".to_string()));
        assert!(!rendered.contains(&"--rootfs-lower".to_string()));
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_file_mount_generates_correct_args() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/guest/config.txt", |m| {
                m.bind("/host/config.txt").readonly().noexec()
            })
            .build()
            .await
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

        let rendered = render_args_with_file_mounts(&config, &staged_file_mounts);

        // File mount should use staging dir in --mount.
        assert!(rendered.windows(2).any(|pair| pair[0] == "--mount"
            && pair[1] == "fm_aabbccdd:/tmp/staging/fm_aabbccdd:ro,noexec"));
        // MSB_FILE_MOUNTS should contain the spec.
        assert!(rendered.contains(
            &"MSB_FILE_MOUNTS=fm_aabbccdd:config.txt:/guest/config.txt:ro,noexec".to_string()
        ));
        // MSB_DIR_MOUNTS should NOT contain the file mount.
        assert!(!rendered.iter().any(|a| a.starts_with("MSB_DIR_MOUNTS=")));
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_mixed_file_and_dir_mounts() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/data", |m| m.bind("/host/data"))
            .volume("/guest/file.txt", |m| m.bind("/host/file.txt"))
            .build()
            .await
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

        let rendered = render_args_with_file_mounts(&config, &staged_file_mounts);

        // Directory mount in MSB_DIR_MOUNTS.
        let data_tag = super::guest_mount_tag("/data");
        assert!(rendered.contains(&format!("MSB_DIR_MOUNTS={data_tag}:/data")));
        // File mount in MSB_FILE_MOUNTS.
        assert!(
            rendered.contains(&"MSB_FILE_MOUNTS=fm_11223344:file.txt:/guest/file.txt".to_string())
        );
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_bind_mount_gets_default_quota() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/data", |m| m.bind("/host/data"))
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);
        let data_tag = super::guest_mount_tag("/data");
        let expected = format!(
            "{data_tag}:/host/data:quota={}",
            crate::sandbox::config::DEFAULT_BIND_QUOTA_MIB
        );
        assert!(
            rendered
                .windows(2)
                .any(|pair| pair[0] == "--mount" && pair[1] == expected),
            "missing default-quota --mount arg in {rendered:?}"
        );
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_bind_mount_quota_override() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/data", |m| m.bind("/host/data").quota(2048u32))
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);
        let data_tag = super::guest_mount_tag("/data");
        let expected = format!("{data_tag}:/host/data:quota=2048");
        assert!(
            rendered
                .windows(2)
                .any(|pair| pair[0] == "--mount" && pair[1] == expected),
            "missing override-quota --mount arg in {rendered:?}"
        );
    }

    #[tokio::test]
    #[cfg(windows)]
    async fn test_sandbox_cli_args_windows_drive_bind_mount_preserves_drive_colon() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/data", |m| {
                m.bind(r"C:\Users\Stephen\data")
                    .readonly()
                    .stat_virtualization(StatVirtualization::Relaxed)
                    .host_permissions(HostPermissions::Mirror)
            })
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);
        let data_tag = super::guest_mount_tag("/data");
        let expected = format!(
            r"{data_tag}:C:\Users\Stephen\data:ro,stat-virt=relaxed,host-perms=mirror,quota={}",
            crate::sandbox::config::DEFAULT_BIND_QUOTA_MIB
        );

        assert!(
            rendered
                .windows(2)
                .any(|pair| pair[0] == "--mount" && pair[1] == expected),
            "missing Windows drive bind --mount arg in {rendered:?}"
        );
        assert!(rendered.contains(&format!("MSB_DIR_MOUNTS={data_tag}:/data:ro")));
    }

    #[tokio::test]
    #[cfg(windows)]
    async fn test_sandbox_cli_args_windows_drive_file_mount_preserves_drive_colon() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/guest/config.txt", |m| {
                m.bind(r"C:\Users\Stephen\config.txt").readonly()
            })
            .build()
            .await
            .unwrap();

        let mut staged_file_mounts = HashMap::new();
        staged_file_mounts.insert(
            "/guest/config.txt".to_string(),
            (
                PathBuf::from(r"C:\Users\Stephen\AppData\Local\Temp\msb\fm_deadbeef"),
                "config.txt".to_string(),
                "fm_deadbeef".to_string(),
            ),
        );

        let rendered = render_args_with_file_mounts(&config, &staged_file_mounts);

        assert!(rendered.windows(2).any(|pair| pair[0] == "--mount"
            && pair[1] == r"fm_deadbeef:C:\Users\Stephen\AppData\Local\Temp\msb\fm_deadbeef:ro"));
        assert!(
            rendered.contains(
                &"MSB_FILE_MOUNTS=fm_deadbeef:config.txt:/guest/config.txt:ro".to_string()
            )
        );
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_named_disk_volume() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/var/lib/docker", |m| {
                m.named_with("docker-data", |v| v.disk().size(2048u32).ensure_exists())
            })
            .build()
            .await
            .unwrap();

        let mut named_volumes = HashMap::new();
        let raw_path = PathBuf::from("/tmp/docker-data/disk.raw");
        named_volumes.insert("docker-data".to_string(), named_disk(&raw_path));

        let rendered = render_args_with_named_volumes(&config, &named_volumes);
        let tag = super::guest_mount_tag("/var/lib/docker");

        assert!(
            rendered.windows(2).any(|pair| pair[0] == "--disk"
                && pair[1] == format!("{tag}:{}:raw", raw_path.display()))
        );
        assert!(rendered.contains(&format!(
            "MSB_DISK_MOUNTS={tag}:/var/lib/docker:fstype=ext4"
        )));
        assert!(
            !rendered
                .iter()
                .any(|arg| arg.starts_with("MSB_DIR_MOUNTS=") && arg.contains("/var/lib/docker")),
            "named disk volume must not be routed through virtiofs: {rendered:?}"
        );
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_named_directory_volume() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/data", |m| {
                m.named_with("mydir", |v| v.quota(512u32).ensure_exists())
            })
            .build()
            .await
            .unwrap();

        let mut named_volumes = HashMap::new();
        named_volumes.insert(
            "mydir".to_string(),
            named_directory("/tmp/mydir", Some(512)),
        );

        let rendered = render_args_with_named_volumes(&config, &named_volumes);
        let tag = super::guest_mount_tag("/data");

        assert!(
            rendered.windows(2).any(
                |pair| pair[0] == "--mount" && pair[1] == format!("{tag}:/tmp/mydir:quota=512")
            )
        );
        assert!(rendered.contains(&format!("MSB_DIR_MOUNTS={tag}:/data")));
        assert!(
            !rendered.windows(2).any(|pair| pair[0] == "--disk"),
            "named directory volume must not emit --disk: {rendered:?}"
        );
        assert!(
            !rendered
                .iter()
                .any(|arg| arg.starts_with("MSB_DISK_MOUNTS=")),
            "named directory volume must not emit disk mount metadata: {rendered:?}"
        );
    }

    #[test]
    fn test_validate_existing_named_volume_rejects_quota_mismatch() {
        let requested =
            named_volume_create("mydir", VolumeKind::Directory, Some(1024), None, Vec::new());
        let existing = existing_volume_model("mydir", VolumeKind::Directory, Some(512), None, None);

        let err = super::validate_existing_named_volume(&requested, &existing).unwrap_err();

        assert!(err.to_string().contains("quota"), "got: {err}");
    }

    #[test]
    fn test_validate_existing_named_volume_rejects_capacity_mismatch() {
        let requested =
            named_volume_create("mydisk", VolumeKind::Disk, None, Some(2048), Vec::new());
        let existing_capacity_bytes = 1024_i64 * 1024 * 1024;
        let existing = existing_volume_model(
            "mydisk",
            VolumeKind::Disk,
            None,
            Some(existing_capacity_bytes),
            None,
        );

        let err = super::validate_existing_named_volume(&requested, &existing).unwrap_err();

        assert!(err.to_string().contains("capacity"), "got: {err}");
    }

    #[test]
    fn test_validate_existing_named_volume_rejects_requested_label_mismatch() {
        let requested = named_volume_create(
            "mydir",
            VolumeKind::Directory,
            None,
            None,
            vec![("env".to_string(), "prod".to_string())],
        );
        let existing = existing_volume_model(
            "mydir",
            VolumeKind::Directory,
            None,
            None,
            Some(vec![("env".to_string(), "dev".to_string())]),
        );

        let err = super::validate_existing_named_volume(&requested, &existing).unwrap_err();

        assert!(err.to_string().contains("label"), "got: {err}");
    }

    #[test]
    fn test_validate_existing_named_volume_allows_extra_existing_labels() {
        let requested = named_volume_create(
            "mydir",
            VolumeKind::Directory,
            None,
            None,
            vec![("env".to_string(), "prod".to_string())],
        );
        let existing = existing_volume_model(
            "mydir",
            VolumeKind::Directory,
            None,
            None,
            Some(vec![
                ("env".to_string(), "prod".to_string()),
                ("team".to_string(), "runtime".to_string()),
            ]),
        );

        super::validate_existing_named_volume(&requested, &existing).unwrap();
    }

    #[tokio::test]
    async fn test_ensure_named_volumes_rolls_back_db_row_on_provision_failure() {
        let temp = tempdir().unwrap();
        let home = temp.path().join("home");
        let volumes_dir = temp.path().join("volumes");
        std::fs::create_dir_all(&volumes_dir).unwrap();
        std::fs::write(volumes_dir.join("broken"), b"not a directory").unwrap();
        let local = LocalBackend::builder()
            .home(&home)
            .volumes_dir(&volumes_dir)
            .build()
            .await
            .unwrap();
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/data", |m| m.named_with("broken", |v| v.ensure_exists()))
            .build()
            .await
            .unwrap();

        let err = super::ensure_named_volumes(&local, &config)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("already exists"), "got: {err}");
        let pools = local.db().await.unwrap();
        let existing = super::volume_entity::Entity::find()
            .filter(super::volume_entity::Column::Name.eq("broken"))
            .one(pools.read())
            .await
            .unwrap();
        assert!(
            existing.is_none(),
            "failed sandbox-time provisioning must not leave a phantom volume row"
        );
    }

    #[tokio::test]
    async fn test_ensure_named_volumes_rolls_back_earlier_created_volumes_on_later_failure() {
        let temp = tempdir().unwrap();
        let home = temp.path().join("home");
        let volumes_dir = temp.path().join("volumes");
        let local = LocalBackend::builder()
            .home(&home)
            .volumes_dir(&volumes_dir)
            .build()
            .await
            .unwrap();
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/ok", |m| {
                m.named_with("first-created", |v| v.ensure_exists())
            })
            .volume("/bad", |m| {
                m.named_with("bad-disk", |v| v.ensure_exists().disk())
            })
            .build()
            .await
            .unwrap();

        let err = super::ensure_named_volumes(&local, &config)
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("disk named volumes require"),
            "got: {err}"
        );
        assert!(!local.volume_path("first-created").exists());
        let pools = local.db().await.unwrap();
        let existing = super::volume_entity::Entity::find()
            .filter(super::volume_entity::Column::Name.eq("first-created"))
            .one(pools.read())
            .await
            .unwrap();
        assert!(
            existing.is_none(),
            "later sandbox-time provisioning failure must roll back earlier created volumes"
        );
    }

    #[tokio::test]
    async fn test_resolve_named_volumes_recovers_disk_metadata_from_store() {
        let temp = tempdir().unwrap();
        let local = LocalBackend::builder()
            .home(temp.path())
            .build()
            .await
            .unwrap();
        let pools = local.db().await.unwrap();
        super::volume_entity::ActiveModel {
            name: Set("mydata".to_string()),
            kind: Set(VolumeKind::Disk.as_str().to_string()),
            disk_format: Set(Some("raw".to_string())),
            disk_fstype: Set(Some("ext4".to_string())),
            created_at: Set(Some(chrono::Utc::now().naive_utc())),
            updated_at: Set(Some(chrono::Utc::now().naive_utc())),
            ..Default::default()
        }
        .insert(pools.write())
        .await
        .unwrap();

        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/data", |m| m.named("mydata"))
            .build()
            .await
            .unwrap();

        let resolved = super::resolve_named_volumes(&local, &config).await.unwrap();
        let volume = resolved.get("mydata").expect("volume should resolve");
        assert_eq!(volume.kind, VolumeKind::Disk);
        assert_eq!(volume.format, Some(DiskImageFormat::Raw));
        assert_eq!(volume.fstype.as_deref(), Some("ext4"));
        assert_eq!(volume.path, local.volume_path("mydata").join("disk.raw"));

        let rendered = render_args_with_named_volumes(&config, &resolved);
        let tag = super::guest_mount_tag("/data");
        assert!(
            rendered.windows(2).any(|pair| pair[0] == "--disk"
                && pair[1] == format!("{tag}:{}:raw", volume.path.display()))
        );
        assert!(rendered.contains(&format!("MSB_DISK_MOUNTS={tag}:/data:fstype=ext4")));
    }

    #[tokio::test]
    async fn test_existing_named_volume_mode_does_not_validate_default_metadata() {
        let temp = tempdir().unwrap();
        let local = LocalBackend::builder()
            .home(temp.path())
            .build()
            .await
            .unwrap();
        let pools = local.db().await.unwrap();
        super::volume_entity::ActiveModel {
            name: Set("docker-data".to_string()),
            kind: Set(VolumeKind::Disk.as_str().to_string()),
            capacity_bytes: Set(Some(2048_i64 * 1024 * 1024)),
            disk_format: Set(Some("raw".to_string())),
            disk_fstype: Set(Some("ext4".to_string())),
            created_at: Set(Some(chrono::Utc::now().naive_utc())),
            updated_at: Set(Some(chrono::Utc::now().naive_utc())),
            ..Default::default()
        }
        .insert(pools.write())
        .await
        .unwrap();

        let mut config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/var/lib/docker", |m| m.named("docker-data"))
            .build()
            .await
            .unwrap();
        if let VolumeMount::Named { create, .. } = &mut config.spec.mounts[0] {
            // Directly deserialized configs can still carry an explicit
            // Existing create object even though the builder normalizes this
            // path to a plain named mount.
            *create = Some(microsandbox_types::NamedVolumeCreate {
                mode: crate::sandbox::NamedVolumeMode::Existing,
                name: "docker-data".to_string(),
                kind: VolumeKind::Directory,
                quota_mib: None,
                capacity_mib: None,
                labels: Vec::new(),
            });
        }

        let ensured = super::ensure_named_volumes(&local, &config).await.unwrap();
        assert!(ensured.is_empty());
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_disk_image_volume() {
        // SandboxBuilder::validate canonicalizes disk hosts, so the file
        // must exist. Stage one in a tempdir.
        let dir = tempfile::tempdir().unwrap();
        let host = dir.path().join("data.qcow2");
        std::fs::write(&host, []).unwrap();

        let host_clone = host.clone();
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/data", |m| {
                m.disk(host_clone)
                    .format(DiskImageFormat::Qcow2)
                    .fstype("ext4")
            })
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);

        // --disk arg present with correct layout.
        let data_tag = super::guest_mount_tag("/data");
        let expected_disk_arg = format!("{data_tag}:{}:qcow2", host.display());
        assert!(
            rendered
                .windows(2)
                .any(|pair| pair[0] == "--disk" && pair[1] == expected_disk_arg),
            "missing --disk arg in {rendered:?}"
        );

        // MSB_DISK_MOUNTS env entry carries the guest path and fstype.
        let expected_env = format!("MSB_DISK_MOUNTS={data_tag}:/data:fstype=ext4");
        assert!(rendered.contains(&expected_env));
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_disk_image_readonly() {
        let dir = tempfile::tempdir().unwrap();
        let host = dir.path().join("seed.raw");
        std::fs::write(&host, []).unwrap();

        let host_clone = host.clone();
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/seed", |m| m.disk(host_clone).readonly().noexec())
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);
        let tag = super::guest_mount_tag("/seed");

        assert!(rendered.windows(2).any(
            |pair| pair[0] == "--disk" && pair[1] == format!("{tag}:{}:raw:ro", host.display())
        ));
        assert!(rendered.contains(&format!("MSB_DISK_MOUNTS={tag}:/seed:ro,noexec")));
    }

    #[test]
    fn test_lock_disk_mounts_rejects_rootfs_and_mount_same_path() {
        let dir = tempfile::tempdir().unwrap();
        let disk = dir.path().join("root.raw");
        std::fs::write(&disk, b"disk").unwrap();

        let config = SandboxConfig {
            spec: microsandbox_types::SandboxSpec {
                image: RootfsSource::DiskImage {
                    path: disk.clone(),
                    format: DiskImageFormat::Raw,
                    fstype: None,
                },
                mounts: vec![VolumeMount::DiskImage {
                    host: disk,
                    guest: "/data".to_string(),
                    format: DiskImageFormat::Raw,
                    fstype: None,
                    options: MountOptions::default(),
                }],
                ..Default::default()
            },
            ..Default::default()
        };

        let err = super::lock_disk_mounts(&config, &HashMap::new()).unwrap_err();
        assert!(err.to_string().contains("more than once per sandbox"));
    }

    #[test]
    fn test_lock_disk_mounts_rejects_duplicate_named_disk_volume() {
        let dir = tempfile::tempdir().unwrap();
        let disk = dir.path().join("disk.raw");
        std::fs::write(&disk, b"disk").unwrap();

        let config = SandboxConfig {
            spec: microsandbox_types::SandboxSpec {
                mounts: vec![
                    VolumeMount::Named {
                        name: "data".to_string(),
                        guest: "/data-a".to_string(),
                        create: None,
                        options: MountOptions::default(),
                        stat_virtualization: StatVirtualization::Strict,
                        host_permissions: HostPermissions::Private,
                    },
                    VolumeMount::Named {
                        name: "data".to_string(),
                        guest: "/data-b".to_string(),
                        create: None,
                        options: MountOptions::default(),
                        stat_virtualization: StatVirtualization::Strict,
                        host_permissions: HostPermissions::Private,
                    },
                ],
                ..Default::default()
            },
            ..Default::default()
        };
        let mut named_volumes = HashMap::new();
        named_volumes.insert("data".to_string(), named_disk(disk));

        let err = super::lock_disk_mounts(&config, &named_volumes).unwrap_err();
        assert!(err.to_string().contains("more than once per sandbox"));
    }

    #[cfg(windows)]
    #[test]
    fn test_lock_disk_image_windows_uses_sidecar_lock() {
        let dir = tempfile::tempdir().unwrap();
        let disk = dir.path().join("disk.raw");
        std::fs::write(&disk, b"disk").unwrap();

        let _lock = super::lock_disk_image_windows(&disk, false, Some("data")).unwrap();
        let _disk_handle = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&disk)
            .unwrap();

        let lock_path = super::windows_disk_lock_path(&disk).unwrap();
        assert_eq!(lock_path.file_name().unwrap(), "disk.raw.lock");
        assert!(lock_path.exists());

        let err = super::lock_disk_image_windows(&disk, false, Some("data")).unwrap_err();
        assert!(err.to_string().contains("already attached"));
    }

    #[tokio::test]
    async fn test_guest_mount_tag_is_deterministic() {
        let a = super::guest_mount_tag("/data");
        let b = super::guest_mount_tag("/data");
        assert_eq!(a, b);
    }

    #[tokio::test]
    async fn test_guest_mount_tag_disambiguates_colliding_paths() {
        // The naive `/` → `_` mangling treats these as identical. The
        // slug+hash form must not.
        let a = super::guest_mount_tag("/var/log");
        let b = super::guest_mount_tag("/var_log");
        assert_ne!(a, b);
        assert!(a.starts_with("var_log_"));
        assert!(b.starts_with("var_log_"));
    }

    #[tokio::test]
    async fn test_guest_mount_tag_fits_virtio_blk_serial_limit() {
        // virtio-blk serial is capped at 20 bytes. Long guest paths must still fit.
        let long = "/a/very/deeply/nested/guest/mount/point/that/exceeds/the/slug/cap";
        let tag = super::guest_mount_tag(long);
        assert!(tag.len() <= 20, "tag {tag:?} exceeds 20 bytes");
    }

    #[tokio::test]
    async fn test_guest_mount_tag_slug_prefix_is_readable() {
        assert!(super::guest_mount_tag("/data").starts_with("data_"));
        assert!(super::guest_mount_tag("/var/log").starts_with("var_log_"));
    }

    //----------------------------------------------------------------------------------------------
    // Tests: Handoff init env-var construction
    //----------------------------------------------------------------------------------------------

    /// Helper to grep the rendered args for an `--env KEY=...` entry.
    fn find_env(args: &[String], key: &str) -> Option<String> {
        let prefix = format!("{key}=");
        args.windows(2).find_map(|pair| {
            if pair[0] == "--env" && pair[1].starts_with(&prefix) {
                Some(pair[1][prefix.len()..].to_string())
            } else {
                None
            }
        })
    }

    #[tokio::test]
    async fn test_handoff_init_emits_only_cmd_when_args_and_env_empty() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .init("/lib/systemd/systemd")
            .build()
            .await
            .unwrap();

        let args = render_args(&config);

        assert_eq!(
            find_env(&args, "MSB_HANDOFF_INIT").as_deref(),
            Some("/lib/systemd/systemd")
        );
        assert!(find_env(&args, "MSB_HANDOFF_INIT_ARGS").is_none());
        assert!(find_env(&args, "MSB_HANDOFF_INIT_CWD").is_none());
        assert!(find_env(&args, "MSB_HANDOFF_INIT_ENV").is_none());
    }

    #[tokio::test]
    async fn test_handoff_init_emits_cwd_when_workdir_set() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .init("/init")
            .workdir("/opt/hermes")
            .build()
            .await
            .unwrap();

        let args = render_args(&config);

        assert_eq!(
            find_env(&args, "MSB_HANDOFF_INIT_CWD").as_deref(),
            Some("/opt/hermes")
        );
    }

    #[tokio::test]
    async fn test_handoff_init_encodes_argv_as_base64url_json() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .init_with("/lib/systemd/systemd", |i| {
                i.args([
                    "--unit=multi-user.target",
                    "--log-level=warning",
                    "literal\x1funit-separator",
                ])
            })
            .build()
            .await
            .unwrap();

        let args = render_args(&config);
        let argv = find_env(&args, "MSB_HANDOFF_INIT_ARGS").expect("argv env present");
        let decoded: Vec<String> = decode_handoff_json(&argv);

        assert_eq!(
            decoded,
            vec![
                "--unit=multi-user.target",
                "--log-level=warning",
                "literal\x1funit-separator"
            ]
        );
    }

    #[tokio::test]
    async fn test_handoff_init_encodes_env_pairs_as_base64url_json() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .init_with("/sbin/init", |i| {
                i.env("container", "microsandbox")
                    .env("LANG", "C.UTF-8")
                    .env("TOKEN", "a=b;c\x1fd")
            })
            .build()
            .await
            .unwrap();

        let args = render_args(&config);
        let env_val = find_env(&args, "MSB_HANDOFF_INIT_ENV").expect("env present");
        let decoded: Vec<(String, String)> = decode_handoff_json(&env_val);

        assert_eq!(
            decoded,
            vec![
                ("container".to_string(), "microsandbox".to_string()),
                ("LANG".to_string(), "C.UTF-8".to_string()),
                ("TOKEN".to_string(), "a=b;c\x1fd".to_string())
            ]
        );
    }

    #[tokio::test]
    async fn test_handoff_init_omitted_when_unset() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .build()
            .await
            .unwrap();

        let args = render_args(&config);

        assert!(find_env(&args, "MSB_HANDOFF_INIT").is_none());
        assert!(find_env(&args, "MSB_HANDOFF_INIT_ARGS").is_none());
        assert!(find_env(&args, "MSB_HANDOFF_INIT_ENV").is_none());
    }

    #[tokio::test]
    async fn test_handoff_init_unit_separator_in_arg_allowed() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .init_with("/sbin/init", |i| i.args(["foo\x1fbar"]))
            .build()
            .await
            .unwrap();
        let args = render_args(&config);
        let argv = find_env(&args, "MSB_HANDOFF_INIT_ARGS").expect("argv env present");
        let decoded: Vec<String> = decode_handoff_json(&argv);

        assert_eq!(decoded, vec!["foo\x1fbar"]);
    }

    #[tokio::test]
    async fn test_handoff_init_equals_in_env_key_rejected_at_build_time() {
        let err = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .init_with("/sbin/init", |i| i.env("BAD=KEY", "v"))
            .build()
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("must not contain '='"));
    }
}

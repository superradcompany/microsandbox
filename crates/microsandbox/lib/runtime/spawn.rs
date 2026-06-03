//! Spawning the sandbox process.
//!
//! [`spawn_sandbox`] assembles CLI arguments from [`SandboxConfig`],
//! fork+execs `msb sandbox`, and reads the startup JSON to obtain the
//! sandbox process PID. The sandbox process runs the VMM and agent relay
//! internally.

#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    collections::HashMap,
    ffi::OsString,
    fmt::Write,
    os::fd::{FromRawFd, OwnedFd},
    path::{Path, PathBuf},
    process::Stdio,
};

use rand::RngExt;
use serde::Deserialize;
use sha2::{Digest as Sha2Digest, Sha256};
use tempfile::TempDir;
use tokio::{io::AsyncBufReadExt, process::Command};

use microsandbox_image::{Digest, GlobalCache};
use microsandbox_metrics::{MetricsRegistry, ReleaseMode, ReserveSlot, SlotReservation};
use microsandbox_protocol::{
    ENV_BLOCK_ROOT, ENV_DIR_MOUNTS, ENV_DISK_MOUNTS, ENV_FILE_MOUNTS, ENV_HANDOFF_INIT,
    ENV_HANDOFF_INIT_ARGS, ENV_HANDOFF_INIT_ENV, ENV_HOSTNAME, ENV_TMPFS, ENV_USER,
    HANDOFF_INIT_SEP_STR,
};
use microsandbox_utils::{DB_FILENAME, DB_SUBDIR};

use crate::{
    MicrosandboxError, MicrosandboxResult, config,
    runtime::handle::ProcessHandle,
    sandbox::{
        DiskImageFormat, HostPermissions, MountOptions, Rlimit, RootfsSource, SandboxConfig,
        StatVirtualization, VolumeMount,
    },
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

#[cfg(target_os = "linux")]
static SIGCHLD_ALT_STACK_INIT: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

const AGENT_SOCKET_HASH_HEX_LEN: usize = 32;

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
    // Resolve paths. Per-sandbox `libkrunfw_path` takes precedence over the
    // global resolver so SDK callers can point at a custom firmware bundle.
    let msb_path = config::resolve_msb_path()?;
    let libkrunfw_path = match &config.libkrunfw_path {
        Some(path) => path.clone(),
        None => config::resolve_libkrunfw_path()?,
    };
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
    let db_dir = global.home().join(DB_SUBDIR);
    let db_path = db_dir.join(DB_FILENAME);

    // Create directories concurrently.
    tokio::try_join!(
        tokio::fs::create_dir_all(&log_dir),
        tokio::fs::create_dir_all(&scripts_dir),
    )?;

    // Write scripts to the runtime scripts directory.
    for (name, content) in &config.scripts {
        // Prevent path traversal: only use the filename component.
        let safe_name = Path::new(name).file_name().ok_or_else(|| {
            MicrosandboxError::InvalidConfig(format!("invalid script name: {name}"))
        })?;
        let script_path = scripts_dir.join(safe_name);
        tokio::fs::write(&script_path, content).await?;
        #[cfg(unix)]
        tokio::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755)).await?;
    }

    // Compute the agent relay socket path. This intentionally lives outside
    // the name-derived sandbox tree so long sandbox names do not exceed the
    // platform Unix-domain socket path limit.
    let agent_sock_path = resolve_sandbox_agent_socket_path(&config.name)?;

    // Stage file bind mounts: each file gets its own isolated directory so
    // that virtio-fs (which requires directories) can share it without
    // exposing adjacent files on the host. Done BEFORE the metrics
    // reservation so that a staging failure does not leak a slot.
    let (staged_file_mounts, file_mounts_staging) = stage_file_mounts(config).await?;

    // Reserve a metrics slot before spawning. Only do this when metrics are
    // enabled so disabled sandboxes don't pay for an entry. Failures here are
    // surfaced as warnings — the runtime will skip the sampler if no slot is
    // present, but the sandbox itself should still boot.
    let metrics_reservation = if config.effective_metrics_interval().is_some() {
        reserve_metrics_slot(config, sandbox_id)
    } else {
        None
    };

    let parent_watchdog = match mode {
        SpawnMode::Attached => match create_parent_watchdog_pipe() {
            Ok(pipe) => Some(pipe),
            Err(err) => {
                release_metrics_reservation(
                    config,
                    metrics_reservation.as_ref(),
                    ReleaseMode::Free,
                );
                return Err(err);
            }
        },
        SpawnMode::Detached => None,
    };

    // Build the command.
    let mut cmd = Command::new(&msb_path);
    cmd.args(sandbox_cli_args(
        config,
        sandbox_id,
        &db_path,
        global.database.connect_timeout_secs,
        &log_dir,
        &runtime_dir,
        &agent_sock_path,
        &libkrunfw_path,
        &staged_file_mounts,
        metrics_reservation.as_ref(),
        parent_watchdog
            .as_ref()
            .map(|_| microsandbox_runtime::vm::PARENT_WATCH_FD),
    ));

    // Prevent the sandbox process from inheriting the parent's terminal on
    // stdin — the VMM's implicit console auto-detects terminals and sets raw
    // mode, which corrupts the parent's terminal output (\n without \r).
    cmd.stdin(Stdio::null());

    if let Some(pipe) = parent_watchdog.as_ref() {
        let read_fd = pipe.read_fd.as_raw_fd();
        unsafe {
            cmd.pre_exec(move || {
                if libc::dup2(read_fd, microsandbox_runtime::vm::PARENT_WATCH_FD) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if read_fd != microsandbox_runtime::vm::PARENT_WATCH_FD && libc::close(read_fd) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                let flags = libc::fcntl(microsandbox_runtime::vm::PARENT_WATCH_FD, libc::F_GETFD);
                if flags < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::fcntl(
                    microsandbox_runtime::vm::PARENT_WATCH_FD,
                    libc::F_SETFD,
                    flags & !libc::FD_CLOEXEC,
                ) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    if mode == SpawnMode::Detached {
        // Detached sandboxes outlive the creating CLI process, so the
        // sandbox must not stay coupled to the foreground job or terminal.
        cmd.process_group(0);
    }

    // Capture stdout (for startup JSON), inherit stderr so errors are visible.
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::inherit());

    ensure_sigchld_handler_uses_alt_stack_before_spawn().await?;

    // Spawn the sandbox process. On failure, release the metrics reservation
    // so the slot does not leak.
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            release_metrics_reservation(config, metrics_reservation.as_ref(), ReleaseMode::Free);
            return Err(e.into());
        }
    };

    let _pid = match child.id() {
        Some(pid) => pid,
        None => {
            release_metrics_reservation(config, metrics_reservation.as_ref(), ReleaseMode::Free);
            return Err(MicrosandboxError::Runtime(
                "sandbox process exited immediately".into(),
            ));
        }
    };
    tracing::debug!(pid = _pid, sandbox = %config.name, "spawn_sandbox: process started");

    // Read the startup JSON from stdout.
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            release_metrics_reservation(config, metrics_reservation.as_ref(), ReleaseMode::Free);
            return Err(MicrosandboxError::Runtime(
                "failed to capture sandbox stdout".into(),
            ));
        }
    };

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
            release_metrics_reservation(config, metrics_reservation.as_ref(), ReleaseMode::Free);
            return Err(err.into());
        }
        Err(_) => {
            terminate_startup_process(&mut child).await;
            release_metrics_reservation(config, metrics_reservation.as_ref(), ReleaseMode::Free);
            return Err(MicrosandboxError::Runtime(
                "sandbox startup timeout: no JSON received within 30 seconds".into(),
            ));
        }
    }

    let startup: StartupInfo = match serde_json::from_str(line.trim()) {
        Ok(info) => info,
        Err(_) => {
            let status = terminate_startup_process(&mut child).await;
            release_metrics_reservation(config, metrics_reservation.as_ref(), ReleaseMode::Free);
            tracing::debug!(
                raw_line = ?line,
                exit_status = ?status,
                "spawn_sandbox: failed to parse startup JSON"
            );
            return Err(MicrosandboxError::Runtime(format!(
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

    let handle = ProcessHandle::new(
        startup.pid,
        config.name.clone(),
        child,
        file_mounts_staging,
        parent_watchdog.map(|pipe| pipe.write_fd),
    );

    Ok((handle, agent_sock_path))
}

//--------------------------------------------------------------------------------------------------
// Types: Metrics reservation
//--------------------------------------------------------------------------------------------------

/// Slot reservation handed off to the spawned sandbox process.
struct MetricsReservation {
    shm_name: String,
    slot: u32,
    generation: u64,
}

struct ParentWatchdogPipe {
    read_fd: OwnedFd,
    write_fd: OwnedFd,
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Open the registry and reserve a slot for an upcoming sandbox spawn.
///
/// Logs and returns `None` on any failure: the spawn should still succeed
/// (the sandbox just runs without live metrics) so a registry hiccup does
/// not block sandbox creation.
fn reserve_metrics_slot(config: &SandboxConfig, sandbox_id: i32) -> Option<MetricsReservation> {
    let shm_name = config::config().metrics_registry_shm_name();
    let capacity = config::config().metrics_registry_capacity();
    let registry = match MetricsRegistry::open_or_create(&shm_name, capacity) {
        Ok(reg) => reg,
        Err(err) => {
            tracing::warn!(error = %err, sandbox = %config.name, "failed to open metrics registry");
            return None;
        }
    };
    let memory_limit_bytes = u64::from(config.memory_mib) * 1024 * 1024;
    match registry.reserve(ReserveSlot {
        sandbox_id,
        name: &config.name,
        memory_limit_bytes,
    }) {
        Ok(SlotReservation { slot, generation }) => Some(MetricsReservation {
            shm_name,
            slot,
            generation,
        }),
        Err(err) => {
            tracing::warn!(error = %err, sandbox = %config.name, "failed to reserve metrics slot");
            None
        }
    }
}

fn create_parent_watchdog_pipe() -> MicrosandboxResult<ParentWatchdogPipe> {
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

    Ok(ParentWatchdogPipe { read_fd, write_fd })
}

#[cfg(target_os = "linux")]
fn create_cloexec_pipe(fds: &mut [i32; 2]) -> i32 {
    unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }
}

#[cfg(not(target_os = "linux"))]
fn create_cloexec_pipe(fds: &mut [i32; 2]) -> i32 {
    unsafe { libc::pipe(fds.as_mut_ptr()) }
}

#[cfg(not(target_os = "linux"))]
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

/// Build the host-side agent relay socket path for a sandbox name.
fn sandbox_agent_socket_path(name: &str) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    let digest = hasher.finalize();

    let mut filename = String::with_capacity(AGENT_SOCKET_HASH_HEX_LEN + ".sock".len());
    for byte in digest.iter().take(AGENT_SOCKET_HASH_HEX_LEN / 2) {
        let _ = Write::write_fmt(&mut filename, format_args!("{byte:02x}"));
    }
    filename.push_str(".sock");

    config::config().run_dir().join("agent").join(filename)
}

/// Build the legacy name-derived agent relay socket path.
fn legacy_sandbox_agent_socket_path(name: &str) -> PathBuf {
    config::config()
        .sandboxes_dir()
        .join(name)
        .join("runtime")
        .join("agent.sock")
}

/// Return agent relay socket paths in preferred connection order.
pub(crate) fn sandbox_agent_socket_path_candidates(name: &str) -> [PathBuf; 2] {
    [
        sandbox_agent_socket_path(name),
        legacy_sandbox_agent_socket_path(name),
    ]
}

/// Pick the first socket path usable on this platform.
pub(crate) fn resolve_sandbox_agent_socket_path(name: &str) -> MicrosandboxResult<PathBuf> {
    let candidates = sandbox_agent_socket_path_candidates(name);
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
    Err(MicrosandboxError::InvalidConfig(format!(
        "agent relay socket path is too long: shortest derived path is {shortest} bytes, \
         but Unix socket paths on this platform must be shorter than {} bytes; set \
         MSB_HOME or paths.sandboxes to a shorter directory",
        unix_socket_path_capacity()
    )))
}

#[cfg(unix)]
fn sandbox_agent_socket_path_fits(path: &Path) -> bool {
    sandbox_agent_socket_path_len(path) < unix_socket_path_capacity()
}

#[cfg(not(unix))]
fn sandbox_agent_socket_path_fits(_path: &Path) -> bool {
    true
}

#[cfg(unix)]
fn sandbox_agent_socket_path_len(path: &Path) -> usize {
    path.as_os_str().as_bytes().len()
}

#[cfg(not(unix))]
fn sandbox_agent_socket_path_len(_path: &Path) -> usize {
    0
}

#[cfg(unix)]
fn unix_socket_path_capacity() -> usize {
    // SAFETY: a zeroed sockaddr_un is valid, and we only inspect the fixed-size
    // sun_path array length to mirror the UnixListener/socket2 precondition.
    let storage = unsafe { std::mem::zeroed::<libc::sockaddr_un>() };
    storage.sun_path.len()
}

#[cfg(not(unix))]
fn unix_socket_path_capacity() -> usize {
    usize::MAX
}

/// Best-effort release of a reservation when spawn cannot continue.
fn release_metrics_reservation(
    config: &SandboxConfig,
    reservation: Option<&MetricsReservation>,
    mode: ReleaseMode,
) {
    let Some(reservation) = reservation else {
        return;
    };
    let registry = match MetricsRegistry::open(&reservation.shm_name) {
        Ok(reg) => reg,
        Err(err) => {
            tracing::debug!(error = %err, sandbox = %config.name, "release: failed to open metrics registry");
            return;
        }
    };
    if let Err(err) = registry.release(reservation.slot, reservation.generation, mode) {
        tracing::debug!(error = %err, sandbox = %config.name, "release: metrics slot release failed");
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
    // Go's cgo runtime requires non-Go signal handlers to use SA_ONSTACK.
    // The caller initializes Tokio's SIGCHLD handler first, before spawning
    // sandbox children, then this preserves the handler while adding the flag.
    //
    // SAFETY: sigaction is called with valid pointers to read and then rewrite
    // the current SIGCHLD action, preserving the existing handler and mask.
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

#[cfg(all(target_os = "linux", test))]
fn sigchld_handler_uses_alt_stack() -> bool {
    // SAFETY: sigaction is called with a valid output pointer and a null new
    // action pointer, which only reads the current process handler state.
    unsafe {
        let mut action = std::mem::MaybeUninit::<libc::sigaction>::uninit();
        if libc::sigaction(libc::SIGCHLD, std::ptr::null(), action.as_mut_ptr()) != 0 {
            return false;
        }

        action.assume_init().sa_flags & libc::SA_ONSTACK != 0
    }
}

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
                options,
                stat_virtualization,
                host_permissions,
            } if host.is_file() => Some((
                host,
                guest,
                *options,
                *stat_virtualization,
                *host_permissions,
            )),
            _ => None,
        })
        .collect();

    if file_mounts.is_empty() {
        return Ok((HashMap::new(), None));
    }

    let tempdir = tempfile::tempdir()?;
    let mut staged = HashMap::new();

    for (host, guest, options, _stat_virt, _host_perms) in file_mounts {
        // Generate a random tag to avoid collisions.
        let id: u32 = rand::rng().random();
        let tag = format!("fm_{id:08x}");

        let file_mount_dir = tempdir.path().join(&tag);
        tokio::fs::create_dir_all(&file_mount_dir).await?;

        let filename_os = host.file_name().ok_or_else(|| {
            MicrosandboxError::InvalidConfig(format!(
                "file mount has no filename: {}",
                host.display()
            ))
        })?;

        let filename = filename_os.to_str().ok_or_else(|| {
            MicrosandboxError::InvalidConfig(format!(
                "file mount filename is not valid UTF-8: {}",
                host.display()
            ))
        })?;

        // The MSB_FILE_MOUNTS protocol uses `:` and `;` as delimiters.
        if filename.contains(':') || filename.contains(';') {
            return Err(MicrosandboxError::InvalidConfig(format!(
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
                if !options.readonly {
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

/// Push a `--mount tag:host_path[:opts]` arg pair.
fn push_dir_mount_arg(
    args: &mut Vec<OsString>,
    guest: &str,
    host_display: &impl std::fmt::Display,
    options: MountOptions,
    stat_virtualization: StatVirtualization,
    host_permissions: HostPermissions,
) {
    let tag = guest_mount_tag(guest);
    let mut arg = format!("{tag}:{host_display}");
    let mut opts = mount_option_tokens(options);
    append_policy_options(&mut opts, stat_virtualization, host_permissions);
    append_option_block(&mut arg, opts);
    args.push(OsString::from("--mount"));
    args.push(OsString::from(arg));
}

/// Return common guest mount option tokens.
fn mount_option_tokens(options: MountOptions) -> Vec<String> {
    let mut tokens = Vec::new();
    if options.readonly {
        tokens.push("ro".to_string());
    }
    if options.noexec {
        tokens.push("noexec".to_string());
    }
    tokens
}

/// Append policy options when they deviate from the runtime defaults.
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

/// Append `:opt[,opt...]` to a spec when at least one option is set.
fn append_option_block(spec: &mut String, opts: Vec<String>) {
    if opts.is_empty() {
        return;
    }
    spec.push(':');
    spec.push_str(&opts.join(","));
}

/// Append a `tag:guest_path[:opts]` entry to the `MSB_DIR_MOUNTS` env var value.
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

/// Push a `--mount fm_tag:file_mount_dir[:opts]` arg pair.
fn push_file_mount_arg(
    args: &mut Vec<OsString>,
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
    args.push(OsString::from("--mount"));
    args.push(OsString::from(arg));
}

/// Push a `--disk id:host_path:format[:ro]` arg pair.
fn push_disk_mount_arg(
    args: &mut Vec<OsString>,
    id: &str,
    host_display: &impl std::fmt::Display,
    format: &DiskImageFormat,
    options: MountOptions,
) {
    let mut arg = format!("{id}:{host_display}:{}", format.as_str());
    if options.readonly {
        arg.push_str(":ro");
    }
    args.push(OsString::from("--disk"));
    args.push(OsString::from(arg));
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

/// Append a `tag:filename:guest_path[:opts]` entry to the `MSB_FILE_MOUNTS` env var value.
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
    config: &SandboxConfig,
    sandbox_id: i32,
    db_path: &Path,
    db_connect_timeout_secs: u64,
    log_dir: &Path,
    runtime_dir: &Path,
    agent_sock_path: &Path,
    libkrunfw_path: &Path,
    staged_file_mounts: &HashMap<String, (PathBuf, String, String)>,
    metrics_reservation: Option<&MetricsReservation>,
    parent_watch_fd: Option<i32>,
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
    args.push(OsString::from("--db-connect-timeout-secs"));
    args.push(OsString::from(db_connect_timeout_secs.to_string()));
    args.push(OsString::from("--log-dir"));
    args.push(log_dir.as_os_str().to_os_string());
    args.push(OsString::from("--runtime-dir"));
    args.push(runtime_dir.as_os_str().to_os_string());
    args.push(OsString::from("--agent-sock"));
    args.push(agent_sock_path.as_os_str().to_os_string());
    if let Some(fd) = parent_watch_fd {
        args.push(OsString::from("--parent-watch-fd"));
        args.push(OsString::from(fd.to_string()));
    }

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
    match config.effective_metrics_interval() {
        Some(ms) => {
            args.push(OsString::from("--metrics-sample-interval-ms"));
            args.push(OsString::from(ms.get().to_string()));
        }
        None => args.push(OsString::from("--disable-metrics-sample")),
    }

    if let Some(reservation) = metrics_reservation {
        args.push(OsString::from("--metrics-shm-name"));
        args.push(OsString::from(&reservation.shm_name));
        args.push(OsString::from("--metrics-slot"));
        args.push(OsString::from(reservation.slot.to_string()));
        args.push(OsString::from("--metrics-generation"));
        args.push(OsString::from(reservation.generation.to_string()));
    }

    match &config.image {
        RootfsSource::Bind(path) => {
            args.push(OsString::from("--rootfs-path"));
            args.push(path.as_os_str().to_os_string());
        }
        RootfsSource::Oci(_) => {
            // Derive VMDK + upper paths from the stored manifest digest.
            if let Some(ref digest_str) = config.manifest_digest {
                let cache_dir = config::config().cache_dir();
                let cache = GlobalCache::new(&cache_dir).expect("cache init");
                let digest: Digest = digest_str.parse().expect("invalid manifest digest");
                let vmdk_path = cache.vmdk_path(&digest);

                let sandbox_dir = config::config().sandboxes_dir().join(&config.name);
                let upper_path = sandbox_dir.join("upper.ext4");

                // VMDK (fsmeta + layers) as read-only block device.
                args.push(OsString::from("--rootfs-disk"));
                args.push(vmdk_path.as_os_str().to_os_string());
                args.push(OsString::from("--rootfs-disk-format"));
                args.push(OsString::from("vmdk"));

                // upper.ext4 as writable block device.
                args.push(OsString::from("--rootfs-blk"));
                args.push(upper_path.as_os_str().to_os_string());

                // MSB_BLOCK_ROOT: always 2 devices.
                let block_root = "kind=oci-erofs,lower=/dev/vda,upper=/dev/vdb,upper_fstype=ext4";
                args.push(OsString::from("--env"));
                args.push(OsString::from(format!("{}={block_root}", ENV_BLOCK_ROOT)));
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
            let mut block_root_val = String::from("kind=disk-image,device=/dev/vda");
            if let Some(ft) = fstype {
                block_root_val.push_str(&format!(",fstype={ft}"));
            }
            args.push(OsString::from("--env"));
            args.push(OsString::from(format!(
                "{}={block_root_val}",
                ENV_BLOCK_ROOT
            )));
        }
    }

    // Process mounts: emit --mount args for virtiofs mounts, --disk args
    // for disk-image mounts, and collect guest-side mount specs as env
    // vars for agentd.
    let mut tmpfs_val = String::new();
    let mut dir_mounts_val = String::new();
    let mut file_mounts_val = String::new();
    let mut disk_mounts_val = String::new();
    for mount in &config.mounts {
        match mount {
            VolumeMount::Bind {
                host,
                guest,
                options,
                stat_virtualization,
                host_permissions,
            } => {
                if let Some((file_mount_dir, filename, tag)) = staged_file_mounts.get(guest) {
                    push_file_mount_arg(
                        &mut args,
                        tag,
                        file_mount_dir,
                        *options,
                        *stat_virtualization,
                        *host_permissions,
                    );
                    push_file_mounts_spec(&mut file_mounts_val, tag, filename, guest, *options);
                } else {
                    push_dir_mount_arg(
                        &mut args,
                        guest,
                        &host.display(),
                        *options,
                        *stat_virtualization,
                        *host_permissions,
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
            } => {
                let vol_path = config::config().volumes_dir().join(name);
                push_dir_mount_arg(
                    &mut args,
                    guest,
                    &vol_path.display(),
                    *options,
                    *stat_virtualization,
                    *host_permissions,
                );
                push_dir_mounts_spec(&mut dir_mounts_val, guest, *options);
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
                push_disk_mount_arg(&mut args, &id, &host.display(), format, *options);
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
        args.push(OsString::from("--env"));
        args.push(OsString::from(format!("{}={tmpfs_val}", ENV_TMPFS)));
    }

    if !dir_mounts_val.is_empty() {
        args.push(OsString::from("--env"));
        args.push(OsString::from(format!(
            "{}={dir_mounts_val}",
            ENV_DIR_MOUNTS
        )));
    }

    if !file_mounts_val.is_empty() {
        args.push(OsString::from("--env"));
        args.push(OsString::from(format!(
            "{}={file_mounts_val}",
            ENV_FILE_MOUNTS
        )));
    }

    if !disk_mounts_val.is_empty() {
        args.push(OsString::from("--env"));
        args.push(OsString::from(format!(
            "{}={disk_mounts_val}",
            ENV_DISK_MOUNTS
        )));
    }

    if !config.rlimits.is_empty() {
        args.push(OsString::from("--env"));
        args.push(OsString::from(format!(
            "{}={}",
            microsandbox_protocol::ENV_RLIMITS,
            encode_rlimits(&config.rlimits)
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
        args.push(OsString::from(format!("{}={user}", ENV_USER)));
    }

    // Hostname: explicit value or fall back to sandbox name.
    {
        let hostname = config.hostname.as_deref().unwrap_or(&config.name);
        args.push(OsString::from("--env"));
        args.push(OsString::from(format!("{}={hostname}", ENV_HOSTNAME)));
    }

    // Handoff-init: PID 1 hand-off to a user-supplied init binary.
    // The builder's `validate()` rejects non-UTF-8 cmd paths, args/env
    // containing the separator byte (\x1f) or NUL, and env keys containing
    // `=`, so the joins below can't produce a corrupted wire format.
    if let Some(ref init) = config.init {
        let cmd = init
            .cmd
            .to_str()
            .expect("validate() rejects non-UTF-8 cmd paths");
        args.push(OsString::from("--env"));
        args.push(OsString::from(format!("{ENV_HANDOFF_INIT}={cmd}")));

        if !init.args.is_empty() {
            let argv_val = init.args.join(HANDOFF_INIT_SEP_STR);
            args.push(OsString::from("--env"));
            args.push(OsString::from(format!(
                "{ENV_HANDOFF_INIT_ARGS}={argv_val}"
            )));
        }

        if !init.env.is_empty() {
            let env_val = init
                .env
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(HANDOFF_INIT_SEP_STR);
            args.push(OsString::from("--env"));
            args.push(OsString::from(format!("{ENV_HANDOFF_INIT_ENV}={env_val}")));
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
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};

    use super::{
        legacy_sandbox_agent_socket_path, resolve_sandbox_agent_socket_path,
        sandbox_agent_socket_path, sandbox_agent_socket_path_candidates, sandbox_cli_args,
    };
    use crate::{
        LogLevel,
        sandbox::{
            DiskImageFormat, Rlimit, RlimitResource, RootfsSource, SandboxBuilder, SandboxConfig,
        },
    };

    //----------------------------------------------------------------------------------------------
    // Functions: Helpers
    //----------------------------------------------------------------------------------------------

    fn render_args(config: &SandboxConfig) -> Vec<String> {
        sandbox_cli_args(
            config,
            42,
            Path::new("/tmp/msb.db"),
            30,
            Path::new("/tmp/logs"),
            Path::new("/tmp/runtime"),
            Path::new("/tmp/agent.sock"),
            Path::new("/tmp/libkrunfw.dylib"),
            &HashMap::new(),
            None,
            None,
        )
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect()
    }

    #[test]
    fn test_sandbox_agent_socket_path_is_independent_of_sandbox_name_length() {
        let short = sandbox_agent_socket_path("test");
        let max_len =
            sandbox_agent_socket_path(&"x".repeat(crate::sandbox::MAX_SANDBOX_NAME_BYTES));

        let expected_len = "0123456789abcdef0123456789abcdef.sock".len();
        assert_eq!(
            short.file_name().unwrap().to_string_lossy().len(),
            expected_len
        );
        assert_eq!(
            max_len.file_name().unwrap().to_string_lossy().len(),
            expected_len
        );
        assert_eq!(short.parent(), max_len.parent());
        assert_ne!(short.file_name(), max_len.file_name());
    }

    #[test]
    fn test_sandbox_agent_socket_path_candidates_include_legacy_fallback() {
        let candidates = sandbox_agent_socket_path_candidates("test");

        assert_eq!(candidates[0], sandbox_agent_socket_path("test"));
        assert_eq!(candidates[1], legacy_sandbox_agent_socket_path("test"));
        assert!(candidates[1].ends_with("sandboxes/test/runtime/agent.sock"));
    }

    #[test]
    fn test_resolve_sandbox_agent_socket_path_prefers_hashed_path() {
        assert_eq!(
            resolve_sandbox_agent_socket_path("test").unwrap(),
            sandbox_agent_socket_path("test")
        );
    }

    fn render_args_with_file_mounts(
        config: &SandboxConfig,
        staged_file_mounts: &HashMap<String, (PathBuf, String, String)>,
    ) -> Vec<String> {
        sandbox_cli_args(
            config,
            42,
            Path::new("/tmp/msb.db"),
            30,
            Path::new("/tmp/logs"),
            Path::new("/tmp/runtime"),
            Path::new("/tmp/agent.sock"),
            Path::new("/tmp/libkrunfw.dylib"),
            staged_file_mounts,
            None,
            None,
        )
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect()
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_sigchld_handler_uses_alt_stack_after_prepare() {
        super::ensure_sigchld_handler_uses_alt_stack_before_spawn()
            .await
            .unwrap();

        assert!(super::sigchld_handler_uses_alt_stack());
    }

    //----------------------------------------------------------------------------------------------
    // Tests: stat-virt + host-perms encoding in --mount args
    //----------------------------------------------------------------------------------------------

    #[tokio::test]
    async fn test_dir_mount_arg_omits_defaults() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/data", |m| m.bind("/host/data"))
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);
        // Default Strict + Private must not show up in the wire format.
        let mount_args: Vec<&String> = rendered
            .windows(2)
            .filter(|p| p[0] == "--mount")
            .map(|p| &p[1])
            .collect();
        assert!(!mount_args.is_empty());
        let m = mount_args[0];
        assert!(
            !m.contains("stat-virt") && !m.contains("host-perms"),
            "default-policy mount leaked policy options into wire format: {m}"
        );
    }

    #[tokio::test]
    async fn test_dir_mount_arg_encodes_relaxed_stat_virt() {
        use crate::sandbox::StatVirtualization;
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/host-tmp", |m| {
                m.bind("/tmp")
                    .readonly()
                    .noexec()
                    .stat_virtualization(StatVirtualization::Relaxed)
            })
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);
        let m = rendered
            .windows(2)
            .find(|p| p[0] == "--mount")
            .map(|p| p[1].clone())
            .expect("expected --mount arg");
        assert!(m.contains(":ro"), "expected ro flag: {m}");
        assert!(m.contains("noexec"), "expected noexec flag: {m}");
        assert!(m.contains(",stat-virt=relaxed"), "missing policy: {m}");
    }

    #[tokio::test]
    async fn test_dir_mount_arg_encodes_mirror_host_perms() {
        use crate::sandbox::HostPermissions;
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/work", |m| {
                m.bind("./project")
                    .host_permissions(HostPermissions::Mirror)
            })
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);
        let m = rendered
            .windows(2)
            .find(|p| p[0] == "--mount")
            .map(|p| p[1].clone())
            .expect("expected --mount arg");
        assert!(m.ends_with(":host-perms=mirror"), "missing policy: {m}");
    }

    #[tokio::test]
    async fn test_dir_mount_arg_encodes_both_policies_off_plus_private() {
        // `Off + Mirror` is rejected at build time; combine `Off` with the
        // explicit (matching default) `Private` to verify both encoders fire.
        use crate::sandbox::{HostPermissions, StatVirtualization};
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/host", |m| {
                m.bind("/mnt/windows")
                    .readonly()
                    .stat_virtualization(StatVirtualization::Off)
                    .host_permissions(HostPermissions::Private)
            })
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);
        let m = rendered
            .windows(2)
            .find(|p| p[0] == "--mount")
            .map(|p| p[1].clone())
            .expect("expected --mount arg");
        assert!(m.contains(",stat-virt=off"));
        // host-perms=private is the default and is omitted from the wire format.
        assert!(!m.contains("host-perms"));
    }

    #[tokio::test]
    async fn test_off_plus_mirror_rejected_at_build_time() {
        use crate::sandbox::{HostPermissions, StatVirtualization};
        let err = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/host", |m| {
                m.bind("/mnt/windows")
                    .stat_virtualization(StatVirtualization::Off)
                    .host_permissions(HostPermissions::Mirror)
            })
            .build()
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("Off cannot be combined with"),
            "got: {err}"
        );
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
    async fn test_sandbox_cli_args_include_parent_watch_fd_when_present() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .build()
            .await
            .unwrap();

        let rendered = sandbox_cli_args(
            &config,
            42,
            Path::new("/tmp/msb.db"),
            30,
            Path::new("/tmp/logs"),
            Path::new("/tmp/runtime"),
            Path::new("/tmp/agent.sock"),
            Path::new("/tmp/libkrunfw.dylib"),
            &HashMap::new(),
            None,
            Some(microsandbox_runtime::vm::PARENT_WATCH_FD),
        )
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>();

        assert!(
            rendered
                .windows(2)
                .any(|pair| pair == ["--parent-watch-fd", "97"])
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

        let args = sandbox_cli_args(
            &config,
            42,
            Path::new("/tmp/msb.db"),
            30,
            Path::new("/tmp/logs"),
            Path::new("/tmp/runtime"),
            Path::new("/tmp/agent.sock"),
            Path::new("/tmp/libkrunfw.dylib"),
            &HashMap::new(),
            None,
            None,
        );

        let rendered = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert!(rendered.windows(2).any(|pair| {
            pair[0] == "--env"
                && pair[1] == format!("{}=nofile=65535:65535", microsandbox_protocol::ENV_RLIMITS)
        }));
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
    async fn test_sandbox_cli_args_include_metrics_handoff_when_provided() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .metrics_sample_interval(std::time::Duration::from_millis(500))
            .build()
            .await
            .unwrap();

        let reservation = super::MetricsReservation {
            shm_name: "/msb-met-deadbeef-v1".to_string(),
            slot: 17,
            generation: 99,
        };

        let rendered = sandbox_cli_args(
            &config,
            42,
            Path::new("/tmp/msb.db"),
            30,
            Path::new("/tmp/logs"),
            Path::new("/tmp/runtime"),
            Path::new("/tmp/agent.sock"),
            Path::new("/tmp/libkrunfw.dylib"),
            &HashMap::new(),
            Some(&reservation),
            None,
        )
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect::<Vec<_>>();

        assert!(
            rendered
                .windows(2)
                .any(|p| p == ["--metrics-shm-name", "/msb-met-deadbeef-v1"]),
            "missing --metrics-shm-name in {rendered:?}"
        );
        assert!(
            rendered.windows(2).any(|p| p == ["--metrics-slot", "17"]),
            "missing --metrics-slot in {rendered:?}"
        );
        assert!(
            rendered
                .windows(2)
                .any(|p| p == ["--metrics-generation", "99"]),
            "missing --metrics-generation in {rendered:?}"
        );
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_omit_metrics_handoff_when_absent() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);

        assert!(!rendered.iter().any(|a| a == "--metrics-shm-name"));
        assert!(!rendered.iter().any(|a| a == "--metrics-slot"));
        assert!(!rendered.iter().any(|a| a == "--metrics-generation"));
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
        assert!(matches!(config.image, RootfsSource::Oci(_)));

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
    async fn test_sandbox_cli_args_tmpfs_noexec_appends_noexec() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/tools", |m| m.tmpfs().noexec())
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);

        assert!(rendered.contains(&"MSB_TMPFS=/tools:noexec".to_string()));
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_apply_default_oci_tmpfs() {
        let mut config = SandboxConfig {
            name: "test".into(),
            image: RootfsSource::oci("alpine"),
            memory_mib: 1024,
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

        assert!(matches!(config.image, RootfsSource::DiskImage { .. }));

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

        assert!(matches!(config.image, RootfsSource::DiskImage { .. }));

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
        assert!(find_env(&args, "MSB_HANDOFF_INIT_ENV").is_none());
    }

    #[tokio::test]
    async fn test_handoff_init_joins_argv_with_unit_separator() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .init_with("/lib/systemd/systemd", |i| {
                i.args(["--unit=multi-user.target", "--log-level=warning"])
            })
            .build()
            .await
            .unwrap();

        let args = render_args(&config);
        let argv = find_env(&args, "MSB_HANDOFF_INIT_ARGS").expect("argv env present");

        assert_eq!(argv, "--unit=multi-user.target\x1f--log-level=warning");
    }

    #[tokio::test]
    async fn test_handoff_init_emits_env_pairs_separated_by_unit_separator() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .init_with("/sbin/init", |i| {
                i.env("container", "microsandbox").env("LANG", "C.UTF-8")
            })
            .build()
            .await
            .unwrap();

        let args = render_args(&config);
        let env_val = find_env(&args, "MSB_HANDOFF_INIT_ENV").expect("env present");

        assert_eq!(env_val, "container=microsandbox\x1fLANG=C.UTF-8");
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
    async fn test_handoff_init_separator_in_arg_rejected_at_build_time() {
        let err = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .init_with("/sbin/init", |i| i.args(["foo\x1fbar"]))
            .build()
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("0x1F"));
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

//! Sandbox process entry point and VM configuration.
//!
//! The [`enter()`] function starts background services (agent relay,
//! heartbeat, idle timeout), configures the VMM, and hands control to
//! `Vm::enter()` from msb_krun. It **never returns** — the VMM calls
//! `_exit()` on guest shutdown after running exit observers.

use std::io::Write;
use std::num::NonZero;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(unix)]
use std::sync::OnceLock;
use std::time::Duration;

use microsandbox_db::DbWriteConnection;
use microsandbox_db::entity::run as run_entity;
#[cfg(unix)]
use microsandbox_filesystem::{BindIdentityMapHandle, DynFileSystem};
use microsandbox_filesystem::{
    HostPermissions, PassthroughConfig, PassthroughFs, StatVirtualization,
};
use microsandbox_metrics::{ActivateSlot, MetricsRegistry, ReleaseMode};
use microsandbox_protocol::{
    codec,
    message::{Message, MessageType},
};
use msb_krun::VmBuilder;
use sea_orm::{ColumnTrait, EntityTrait, Set};
use serde::{Deserialize, Serialize};

#[cfg(windows)]
use crate::bootstrap_fs::AgentBootstrapFs;
#[cfg(windows)]
use crate::console::AgentConsolePipeBridge;
use crate::console::{AgentConsoleBackend, ConsoleSharedState};
use crate::heartbeat::{self, HeartbeatDecision, HeartbeatReader};
use crate::logging::LogLevel;
use crate::metrics::run_metrics_sampler;
use crate::relay::{self, AgentRelay};
use crate::{RuntimeError, RuntimeResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Exit reason tags stored in the shared `AtomicU8`.
const EXIT_REASON_COMPLETED: u8 = 0;
const EXIT_REASON_IDLE_TIMEOUT: u8 = 1;
const EXIT_REASON_MAX_DURATION: u8 = 2;
const EXIT_REASON_SIGNAL: u8 = 3;
const EXIT_REASON_PARENT_EXIT: u8 = 4;
/// Termination reason when agentd never signals readiness within the relay's
/// boot window (the guest failed to come up). Reused for the boot-failure exit
/// triggered from the relay's `wait_ready` path.
const EXIT_REASON_AGENT_UNRESPONSIVE: u8 = 5;
const EXIT_REASON_SHUTDOWN_REQUESTED: u8 = 6;
const EXIT_REASON_STARTUP_COMMAND_FAILED: u8 = 7;

/// Fixed fd carrying the bulk `msb sandbox` config (argv overflow) as
/// NUL-terminated argument records. Keeps the network-config blob and the
/// repeated `--env` flags off the process argv — see issue #997.
pub const CONFIG_FD: i32 = 96;

/// Fixed fd used to pass the attached-parent watchdog pipe into `msb sandbox`.
pub const PARENT_WATCH_FD: i32 = 97;

/// Fixed fd used to pass startup JSON from `msb sandbox` to its launcher.
pub const STARTUP_FD: i32 = 98;

/// Control byte sent by the owner to stop parent-watch monitoring without stopping the sandbox.
pub const PARENT_WATCH_DETACH: u8 = 1;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Full configuration for the sandbox process.
///
/// Combines VM hardware settings with sandbox-level metadata (name, DB,
/// agent relay, lifecycle policies). Passed to [`enter()`].
#[derive(Debug)]
pub struct Config {
    /// Name of the sandbox.
    pub sandbox_name: String,

    /// Database ID of the sandbox row.
    pub sandbox_id: i32,

    /// Selected tracing verbosity.
    pub log_level: Option<LogLevel>,

    /// Path to the sandbox database file.
    pub sandbox_db_path: PathBuf,

    /// Timeout when acquiring a sandbox database connection from the pool.
    pub sandbox_db_connect_timeout_secs: u64,

    /// Directory for log files.
    pub log_dir: PathBuf,

    /// Runtime directory (scripts, heartbeat).
    pub runtime_dir: PathBuf,

    /// Root directory holding every sandbox's persisted state
    /// (`<sandboxes_dir>/<name>`). Passed explicitly so runtime-owned
    /// lifecycle maintenance can remove ephemeral sandbox directories without
    /// inferring the path from `log_dir`.
    pub sandboxes_dir: PathBuf,

    /// Path to the Unix domain socket for the agent relay.
    pub agent_sock_path: PathBuf,

    /// Startup command to execute after agentd reports ready.
    pub startup_command: Option<StartupCommand>,

    /// Dedicated startup JSON write fd.
    ///
    /// When present, startup info is written here instead of stdout so
    /// detached launchers can detach stdout/stderr from birth.
    #[cfg(unix)]
    pub startup_fd: Option<OwnedFd>,

    /// Dedicated Windows startup JSON pipe.
    ///
    /// When present, startup info is written here instead of stdout so
    /// detached launchers can detach stdout/stderr from birth.
    #[cfg(windows)]
    pub startup_pipe: Option<String>,

    /// Read end of the attached-parent watchdog pipe.
    #[cfg(unix)]
    pub parent_watchdog: Option<OwnedFd>,

    /// Whether to forward VM console output to stdout.
    pub forward_output: bool,

    /// Idle timeout in seconds (None = no idle timeout).
    pub idle_timeout_secs: Option<u64>,

    /// Maximum sandbox lifetime in seconds (None = no limit).
    pub max_duration_secs: Option<u64>,

    /// Metrics sampling interval in milliseconds; `None` disables sampling.
    pub metrics_sample_interval_ms: Option<NonZero<u64>>,

    /// Shared-memory metrics registry coordinates passed in by the host.
    ///
    /// When `None`, the runtime skips metrics activation entirely — either
    /// metrics sampling is disabled or the host could not reserve a slot.
    pub metrics_slot: Option<MetricsSlotHandoff>,

    /// VM hardware and rootfs configuration.
    pub vm: VmConfig,
}

/// Hidden CLI handoff describing the metrics slot the host reserved for this
/// sandbox.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetricsSlotHandoff {
    /// Name of the POSIX shared-memory object holding the registry.
    pub shm_name: String,
    /// Reserved slot index.
    pub slot: u32,
    /// Generation paired with the reservation.
    pub generation: u64,
}

/// User workload that the sandbox process should start after boot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StartupCommand {
    /// Path or command name to execute inside the guest.
    pub cmd: String,

    /// Arguments to pass to the command.
    pub args: Vec<String>,

    /// Environment variables as `KEY=VALUE` strings.
    pub env: Vec<String>,

    /// Working directory for the command.
    pub cwd: Option<String>,

    /// Guest user override for the command.
    pub user: Option<String>,
}

#[cfg(unix)]
#[derive(Debug, Eq, PartialEq)]
enum ParentWatchdogSignal {
    ParentExited,
    Detached,
}

/// Specification for the writable upper layer attached as virtio-blk.
///
/// The managed root disk is a flat raw ext4 file (`format = Raw`, empty
/// `backing`); a user-supplied disk-image root disk carries its own path
/// and format. A tmpfs root disk attaches no upper device at all — the
/// caller leaves both `rootfs_upper` and `rootfs_upper_spec` unset and
/// signals tmpfs through `MSB_BLOCK_ROOT`. The shape stays
/// forward-compatible with qcow2 backing chains: when chains land,
/// `backing` lists ancestor files that the runtime attaches read-only
/// ahead of the head file.
#[derive(Debug, Clone)]
pub struct UpperSpec {
    /// Path to the head upper file. Mounted writable.
    pub primary: PathBuf,
    /// On-disk format. `Raw` today; `Qcow2` once chains land.
    pub format: msb_krun::DiskImageFormat,
    /// Ancestor files in the backing chain, oldest-first. Empty today.
    pub backing: Vec<PathBuf>,
    /// Whether the head file is read-only. Should be `false` for the
    /// running sandbox's upper.
    pub read_only: bool,
}

/// Specification for a disk-image volume mount attached to the guest.
///
/// Each entry becomes one extra virtio-blk device. Agentd consumes the
/// companion `MSB_DISK_MOUNTS` env var to know which device to mount where.
#[derive(Debug, Clone)]
pub struct DiskMountSpec {
    /// Stable block id. Surfaced in the guest as the virtio-blk `serial`
    /// so agentd can resolve it via `/dev/disk/by-id/virtio-<id>`.
    pub id: String,

    /// Host path to the disk image file.
    pub host: PathBuf,

    /// Guest mount path. Not needed by the VMM, but carried here for
    /// logging/validation; agentd reads the canonical value from the env.
    pub guest: String,

    /// Disk image format.
    pub format: msb_krun::DiskImageFormat,

    /// Inner filesystem type, if specified; otherwise agentd probes.
    pub fstype: Option<String>,

    /// Whether the mount is read-only.
    pub readonly: bool,
}

/// VM hardware and rootfs configuration.
pub struct VmConfig {
    /// Path to the libkrunfw shared library.
    pub libkrunfw_path: PathBuf,

    /// Number of virtual CPUs online at boot.
    pub vcpus: u8,

    /// Memory in MiB at boot.
    pub memory_mib: u32,

    /// Maximum possible virtual CPUs; CPUs above `vcpus` boot parked for later hotplug.
    pub max_cpus: u8,

    /// Maximum guest memory in MiB reserved for future hotplug (virtio-mem).
    pub max_memory_mib: u32,

    /// Root filesystem path for direct passthrough mounts.
    pub rootfs_path: Option<PathBuf>,

    /// Whether to follow symlinks when resolving a bind (`rootfs_path`) rootfs.
    ///
    /// Defaults to `false`: the caller/tenant-provided rootfs path is resolved
    /// following no symlink, matching the `--mount` protection. Set `true` to
    /// opt out when the host rootfs path legitimately traverses a symlink.
    pub rootfs_follow_root_symlinks: bool,

    /// Disk image path for virtio-blk rootfs (single disk, legacy).
    pub rootfs_disk: Option<PathBuf>,

    /// Disk image format string ("qcow2", "raw", "vmdk").
    pub rootfs_disk_format: Option<String>,

    /// Whether the disk image is read-only.
    pub rootfs_disk_readonly: bool,

    /// VMDK descriptor path for EROFS fsmerge OCI rootfs (read-only).
    pub rootfs_vmdk: Option<PathBuf>,

    /// Upper ext4 disk path for writable overlay (paired with rootfs_vmdk).
    ///
    /// Convenience field equivalent to `rootfs_upper_spec` with format
    /// `Raw` and no backing chain. When `rootfs_upper_spec` is set, it
    /// takes precedence; this field is the fast path for the common case.
    pub rootfs_upper: Option<PathBuf>,

    /// Full spec for the writable upper layer.
    ///
    /// Forward-compat seam for qcow2 backing chains. Today this always
    /// produces `Raw` with an empty backing chain — equivalent to
    /// `rootfs_upper`. The qcow2 future populates `format = Qcow2`
    /// and a non-empty `backing` chain without touching every call
    /// site.
    pub rootfs_upper_spec: Option<UpperSpec>,

    /// Additional mounts as `tag:host_path[:opts]` strings.
    pub mounts: Vec<String>,

    /// Disk-image volume mounts attached as extra virtio-blk devices.
    pub disks: Vec<DiskMountSpec>,

    /// Pre-built filesystem backends as `(tag, backend)` pairs.
    #[cfg(unix)]
    pub backends: Vec<(String, Box<dyn DynFileSystem + Send + Sync>)>,

    /// Path to the init binary in the guest.
    pub init_path: Option<PathBuf>,

    /// Environment variables as `KEY=VALUE` pairs.
    pub env: Vec<String>,

    /// Working directory inside the guest.
    pub workdir: Option<PathBuf>,

    /// Path to the executable to run in the guest.
    pub exec_path: Option<PathBuf>,

    /// Arguments to the executable.
    pub exec_args: Vec<String>,

    /// Network configuration for the smoltcp in-process stack.
    #[cfg(feature = "net")]
    pub network: microsandbox_network::config::NetworkConfig,

    /// Sandbox slot for deterministic network address derivation.
    #[cfg(feature = "net")]
    pub sandbox_slot: u64,
}

/// JSON structure written to stdout on startup.
#[derive(Debug, Serialize)]
struct StartupInfo {
    pid: u32,
}

/// Shared bind identity map registration for user-volume passthrough mounts.
struct BindIdentityMapRegistration {
    #[cfg(unix)]
    handle: Option<BindIdentityMapHandle>,
    #[cfg(unix)]
    mount_count: usize,
}

#[cfg(feature = "net")]
type NetworkTerminationHandle = microsandbox_network::network::TerminationHandle;

#[cfg(not(feature = "net"))]
type NetworkTerminationHandle = ();

#[cfg(feature = "net")]
type NetworkMetricsHandle = microsandbox_network::network::MetricsHandle;

#[cfg(not(feature = "net"))]
type NetworkMetricsHandle = ();

#[cfg(feature = "net")]
type NetworkSecretsHandle = microsandbox_network::secrets::handle::SecretsHandle;

#[cfg(not(feature = "net"))]
type NetworkSecretsHandle = ();

type VmBuildOutput = (
    msb_krun::Vm,
    Option<NetworkTerminationHandle>,
    Option<NetworkMetricsHandle>,
    Option<NetworkSecretsHandle>,
    BindIdentityMapRegistration,
);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl BindIdentityMapRegistration {
    fn new() -> Self {
        Self {
            #[cfg(unix)]
            handle: None,
            #[cfg(unix)]
            mount_count: 0,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl std::fmt::Debug for VmConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("VmConfig");
        debug
            .field("libkrunfw_path", &self.libkrunfw_path)
            .field("vcpus", &self.vcpus)
            .field("memory_mib", &self.memory_mib)
            .field("max_cpus", &self.max_cpus)
            .field("max_memory_mib", &self.max_memory_mib)
            .field("rootfs_path", &self.rootfs_path)
            .field("rootfs_vmdk", &self.rootfs_vmdk)
            .field("rootfs_upper", &self.rootfs_upper)
            .field("rootfs_upper_spec", &self.rootfs_upper_spec)
            .field("rootfs_disk", &self.rootfs_disk)
            .field("rootfs_disk_format", &self.rootfs_disk_format)
            .field("rootfs_disk_readonly", &self.rootfs_disk_readonly)
            .field("mounts", &self.mounts)
            .field("disks", &self.disks);
        #[cfg(unix)]
        debug.field("backends", &format!("[{} backend(s)]", self.backends.len()));
        debug
            .field("init_path", &self.init_path)
            .field("env", &self.env)
            .field("workdir", &self.workdir)
            .field("exec_path", &self.exec_path)
            .field("exec_args", &self.exec_args)
            .finish()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Enter the sandbox process.
///
/// This function **never returns**. It starts background services (agent
/// relay, heartbeat, idle timeout), configures the VMM, writes a startup
/// JSON to stdout, and calls `Vm::enter()` which takes over the process.
pub fn enter(config: Config) -> ! {
    // Capture log_dir before moving config into run() — we need it after
    // a failure to write boot-error.json, regardless of how far run() got.
    let log_dir = config.log_dir.clone();
    let metrics_slot = config.metrics_slot.clone();
    let result = run(config);
    match result {
        Ok(infallible) => match infallible {},
        Err(e) => {
            release_reserved_metrics_slot(metrics_slot.as_ref());
            // Write the structured boot-error record so the parent CLI
            // can surface a real cause inline. Best-effort: any failure
            // to write falls back to the existing eprintln path, which
            // is already captured into runtime.log via setup_log_capture.
            let boot_err = crate::boot_error::BootError::from_runtime_error(&e);
            if let Err(write_err) = boot_err.write_atomic(&log_dir) {
                eprintln!("failed to write boot-error.json: {write_err}");
            }
            eprintln!("sandbox error: {e}");
            std::process::exit(1);
        }
    }
}

fn run(config: Config) -> RuntimeResult<std::convert::Infallible> {
    // Raise the fd limit before anything else: every guest-held open file on a virtiofs share pins one fd in this process, so the shell's default soft limit
    // (1024 on many distros) is nowhere near enough for real workloads. Reference virtiofsd raises its own limit for the same reason. Best-effort: failure is
    // not fatal, just a smaller fd budget.
    #[cfg(unix)]
    raise_nofile_limit();

    // Write startup JSON and redirect output FIRST, before any tracing.
    // This ensures all tracing goes to runtime.log, not the terminal.
    let pid = std::process::id();
    let startup = StartupInfo { pid };
    let startup_json = serde_json::to_string(&startup)
        .map_err(|e| RuntimeError::Custom(format!("serialize startup: {e}")))?;

    #[cfg(unix)]
    write_startup_info(config.startup_fd.as_ref(), &startup_json)?;
    #[cfg(windows)]
    write_startup_info(config.startup_pipe.as_deref(), &startup_json)?;
    setup_log_capture(&config.log_dir, config.forward_output)?;

    tracing::info!(sandbox = %config.sandbox_name, "sandbox starting");

    let shutdown_flush_timeout = guest_shutdown_flush_timeout(config.vm.init_path.is_some());

    // Create console shared state (ring buffers + wake pipes).
    let shared = Arc::new(ConsoleSharedState::new());
    let console_backend = AgentConsoleBackend::new(Arc::clone(&shared));

    // Build tokio runtime for relay, heartbeat, and timer tasks.
    let tokio_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| RuntimeError::Custom(format!("tokio runtime: {e}")))?;

    // Set up runtime directory.
    std::fs::create_dir_all(&config.runtime_dir)?;
    std::fs::create_dir_all(config.runtime_dir.join("scripts"))?;
    // Heartbeats are per boot, while the runtime directory persists across starts.
    heartbeat::clear_stale(&config.runtime_dir)?;

    // Create the relay and persist the run record with a single runtime hop.
    let (mut relay, db, run_db_id) = tokio_rt.block_on(async {
        let relay = AgentRelay::new(&config.agent_sock_path, Arc::clone(&shared));
        let db = connect_db(
            &config.sandbox_db_path,
            config.sandbox_db_connect_timeout_secs,
        );
        let (relay, db) = tokio::try_join!(relay, db)?;
        let run_db_id = insert_run(&db, config.sandbox_id, pid).await?;
        Ok::<_, RuntimeError>((relay, db, run_db_id))
    })?;

    // Attach the exec.log writer so the ring reader can capture the
    // primary session's stdout/stderr. Failure to open the file is
    // non-fatal — log capture is best-effort and must not block boot.
    let exec_log_writer: Option<Arc<crate::exec_log::LogWriter>> =
        match crate::exec_log::LogWriter::open(&config.log_dir) {
            Ok(writer) => {
                let arc = Arc::new(writer);
                relay = relay.with_log_writer(Arc::clone(&arc));
                Some(arc)
            }
            Err(err) => {
                tracing::warn!(error = %err, "exec_log: open failed, capture disabled");
                None
            }
        };

    // Shared termination reason — background tasks store the reason before
    // triggering exit; the exit observer reads it for the DB update.
    let exit_reason: Arc<std::sync::atomic::AtomicU8> =
        Arc::new(std::sync::atomic::AtomicU8::new(EXIT_REASON_COMPLETED));

    // Activate the shared-memory metrics writer if the host reserved a slot.
    // The host always reserves and passes a handoff when sampling is enabled,
    // so a missing handoff means sampling is disabled for this sandbox.
    let metrics_writer = activate_metrics_writer(
        config.metrics_slot.as_ref(),
        config.metrics_sample_interval_ms,
        run_db_id,
        pid,
    );

    // If the host reserved a slot but activation failed (registry I/O error,
    // generation mismatch from a stale reservation, etc.), the slot would
    // otherwise stay in `Reserved` until the catalog reaper notices. Release
    // it eagerly so it can be reused by other sandboxes.
    if metrics_writer.is_none()
        && config.metrics_slot.is_some()
        && config.metrics_sample_interval_ms.is_some()
    {
        release_reserved_metrics_slot(config.metrics_slot.as_ref());
    }

    // Build the VM with an exit observer for DB cleanup and socket removal.
    // The on_exit closure runs synchronously on the VMM thread before _exit().
    let rt_handle = tokio_rt.handle().clone();
    let exit_db = db.clone();
    let exit_sandbox_id = config.sandbox_id;
    let exit_run_id = run_db_id;
    let exit_reason_for_observer = Arc::clone(&exit_reason);
    let exit_sock_path = config.agent_sock_path.clone();
    let exit_sandboxes_dir = config.sandboxes_dir.clone();
    let exit_log_writer = exec_log_writer.clone();
    // Capture the activated writer so the exit observer can release the slot
    // without re-opening the registry (saving two mmap syscalls and a
    // potential `wait_for_ready` round-trip on the VMM's exit path).
    let exit_metrics_writer = metrics_writer.clone();
    #[cfg(windows)]
    let _agent_console_pipe_bridge = AgentConsolePipeBridge::spawn(
        agent_console_pipe_name(config.sandbox_id),
        Arc::clone(&shared),
        tokio_rt.handle(),
    )
    .map_err(|e| RuntimeError::Custom(format!("agent console pipe bridge: {e}")))?;
    let build_result = build_vm(
        &config,
        console_backend,
        move |exit_code: i32| {
            use microsandbox_db::entity::sandbox as sandbox_entity;
            use sea_orm::QueryFilter;
            use sea_orm::sea_query::Expr;

            // Map (exit_code, reason tag) → TerminationReason.
            let reason_tag = exit_reason_for_observer.load(std::sync::atomic::Ordering::SeqCst);
            let reason = match reason_tag {
                EXIT_REASON_IDLE_TIMEOUT => run_entity::TerminationReason::IdleTimeout,
                EXIT_REASON_AGENT_UNRESPONSIVE => run_entity::TerminationReason::AgentUnresponsive,
                EXIT_REASON_SHUTDOWN_REQUESTED => run_entity::TerminationReason::ShutdownRequested,
                EXIT_REASON_STARTUP_COMMAND_FAILED => run_entity::TerminationReason::Failed,
                EXIT_REASON_MAX_DURATION => run_entity::TerminationReason::MaxDurationExceeded,
                EXIT_REASON_PARENT_EXIT => run_entity::TerminationReason::Signal,
                EXIT_REASON_SIGNAL => run_entity::TerminationReason::Signal,
                _ if exit_code == 0 => run_entity::TerminationReason::Completed,
                _ => run_entity::TerminationReason::Failed,
            };

            rt_handle.block_on(async {
                let now = chrono::Utc::now().naive_utc();

                // Mark run as terminated with exit code and reason.
                let _ = run_entity::Entity::update_many()
                    .col_expr(
                        run_entity::Column::Status,
                        Expr::value(run_entity::RunStatus::Terminated),
                    )
                    .col_expr(run_entity::Column::TerminationReason, Expr::value(reason))
                    .col_expr(run_entity::Column::ExitCode, Expr::value(exit_code))
                    .col_expr(run_entity::Column::TerminatedAt, Expr::value(now))
                    .filter(run_entity::Column::Id.eq(exit_run_id))
                    .exec(&exit_db)
                    .await;

                // Mark sandbox as stopped.
                let _ = sandbox_entity::Entity::update_many()
                    .col_expr(
                        sandbox_entity::Column::Status,
                        Expr::value(sandbox_entity::SandboxStatus::Stopped),
                    )
                    .col_expr(
                        sandbox_entity::Column::ActiveConfig,
                        Expr::value(Option::<String>::None),
                    )
                    .col_expr(sandbox_entity::Column::UpdatedAt, Expr::value(now))
                    .filter(sandbox_entity::Column::Id.eq(exit_sandbox_id))
                    .exec(&exit_db)
                    .await;

                // Self-clean: if this sandbox was created ephemeral, drop its
                // persisted row + directory now that it is terminal. Reads
                // `sandbox.ephemeral` from the DB (the runtime is handed
                // discrete flags, not the full policy) and no-ops for
                // persistent sandboxes. Best-effort; recovery sweeps from
                // other runtimes cover any failure here.
                match crate::maintenance::cleanup_terminal_ephemeral_sandbox(
                    &exit_db,
                    &exit_sandboxes_dir,
                    exit_sandbox_id,
                )
                .await
                {
                    Ok(outcome) => {
                        tracing::debug!(?outcome, "ephemeral exit self-clean")
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "ephemeral exit self-clean failed")
                    }
                }
            });

            // Inject the exec.log lifecycle-stop marker before _exit().
            // The relay's async run() loop won't get a chance to write
            // it because _exit() bypasses task cleanup.
            if let Some(ref writer) = exit_log_writer {
                writer.write_system("--- sandbox stopped ---");
            }

            // Release the metrics slot. `Stale` preserves the last sample
            // for observers until the slot is reused. Best-effort — the
            // host's reaper will eventually reclaim it if this path is
            // bypassed. We reuse the writer's Arc-backed registry handle
            // rather than re-opening the segment, since `_exit()` is about
            // to run and extra syscalls here delay the VMM teardown.
            if let Some(ref writer) = exit_metrics_writer
                && let Err(err) = writer.clone().release(ReleaseMode::Stale)
            {
                tracing::debug!(error = %err, slot = writer.slot(), "metrics slot release at exit");
            }

            // Clean up agent.sock — the relay's async cleanup won't run because
            // _exit() is called immediately after this observer returns.
            let _ = std::fs::remove_file(&exit_sock_path);
        },
        tokio_rt.handle().clone(),
    );
    let (
        vm,
        _network_termination_handle,
        network_metrics_handle,
        _network_secrets_handle,
        bind_identity_map,
    ) = match build_result {
        Ok(vm) => vm,
        Err(e) => {
            let _ = tokio_rt.block_on(mark_run_failed(&db, run_db_id));
            // Free the slot: build_vm never started the sampler, so no live
            // sample is worth preserving. Prefer the writer (already holds
            // the registry handle) when activation succeeded; otherwise
            // open the registry once via the handoff fields.
            if let Some(writer) = metrics_writer.clone() {
                let _ = writer.release(ReleaseMode::Free);
            } else {
                release_reserved_metrics_slot(config.metrics_slot.as_ref());
            }
            return Err(e);
        }
    };
    #[cfg(unix)]
    {
        relay =
            relay.with_bind_identity_map(bind_identity_map.handle, bind_identity_map.mount_count);
    }
    #[cfg(windows)]
    {
        let _ = bind_identity_map;
    }
    let krun_metrics_handle = vm.metrics_handle();
    let exit_handle = vm.exit_handle();
    let upper_host_path = oci_upper_host_path(&config.vm);

    // Serve host-side live control when this VM booted with reserved resize
    // capacity or with secrets to live-reconfigure. Failure is non-fatal: the
    // SDK treats a missing socket as "no live control capability" and
    // classifies restart-required.
    {
        let control = vm.control_handle();
        #[cfg(feature = "net")]
        let secrets = _network_secrets_handle.clone();
        #[cfg(not(feature = "net"))]
        let secrets: Option<()> = None;
        if control.memory_resize_supported() || control.cpu_resize_supported() || secrets.is_some()
        {
            let control_sock_path =
                crate::control::control_socket_path_for(&config.agent_sock_path);
            let context = crate::control::ControlContext {
                vm: control,
                #[cfg(feature = "net")]
                secrets,
            };
            if let Err(e) =
                crate::control::spawn_control_listener(control_sock_path.clone(), context)
            {
                tracing::warn!(
                    "failed to start runtime control listener at {}: {e}",
                    control_sock_path.display()
                );
            }
        }
    }

    #[cfg(unix)]
    {
        if let Some(parent_watchdog) = config.parent_watchdog
            && let Err(e) = spawn_parent_watchdog(
                parent_watchdog,
                Arc::clone(&shared),
                Arc::clone(&exit_reason),
                exit_handle.clone(),
                config.sandbox_name.clone(),
                shutdown_flush_timeout,
            )
        {
            let _ = tokio_rt.block_on(mark_run_failed(&db, run_db_id));
            if let Some(writer) = metrics_writer.clone() {
                let _ = writer.release(ReleaseMode::Free);
            } else {
                release_reserved_metrics_slot(config.metrics_slot.as_ref());
            }
            let _ = std::fs::remove_file(&config.agent_sock_path);
            return Err(e);
        }
    }

    #[cfg(feature = "net")]
    if let Some(network_termination_handle) = _network_termination_handle {
        let network_exit_handle = exit_handle.clone();
        let network_reason = Arc::clone(&exit_reason);
        network_termination_handle.set_hook(Arc::new(move || {
            tracing::warn!("secret violation requested sandbox termination");
            network_reason.store(EXIT_REASON_SIGNAL, std::sync::atomic::Ordering::SeqCst);
            network_exit_handle.trigger();
        }));
    }

    let metrics_sampler = match (config.metrics_sample_interval_ms, metrics_writer.clone()) {
        (None, _) => {
            tracing::debug!(
                sandbox = %config.sandbox_name,
                "metrics sampling disabled; not spawning sampler"
            );
            None
        }
        (Some(_), None) => {
            // Distinguish "host did not reserve a slot" from "host reserved
            // but runtime activation failed" so operators reading the warn
            // can tell which path needs investigation.
            if config.metrics_slot.is_some() {
                tracing::warn!(
                    sandbox = %config.sandbox_name,
                    "metrics activation failed; slot was released and sampler not spawned"
                );
            } else {
                tracing::warn!(
                    sandbox = %config.sandbox_name,
                    "metrics sampling enabled but no slot was reserved by the host; not spawning sampler"
                );
            }
            None
        }
        (Some(interval_ms), Some(writer)) => Some((
            writer,
            interval_ms,
            krun_metrics_handle,
            network_metrics_handle
                .map(|handle| Box::new(handle) as Box<dyn crate::metrics::NetworkMetrics>),
            upper_host_path,
        )),
    };
    let metrics_sandbox_id = config.sandbox_id;
    let metrics_sandbox_name = config.sandbox_name.clone();
    let metrics_pid = pid;
    // Same effective ceiling the VMM boots with (max_vcpus is clamped to at
    // least the online count); used to cap physically impossible CPU spikes.
    let metrics_max_cpus = config.vm.max_cpus.max(config.vm.vcpus);

    // Opportunistic host-runtime lifecycle maintenance: reconcile stale active
    // sandboxes and clean terminal ephemeral leftovers from runtimes that died
    // before they could self-clean. A read-gated DB lease keeps a burst of
    // starts to one indexed read each; this runs as a bounded background task
    // so it never delays boot.
    {
        let maintenance_db = db.clone();
        let maintenance_dir = config.sandboxes_dir.clone();
        tokio_rt.spawn(async move {
            crate::maintenance::run_startup_maintenance(&maintenance_db, &maintenance_dir).await;
        });
    }

    // Spawn background tasks.
    let (_relay_shutdown_tx, relay_shutdown_rx) = tokio::sync::watch::channel(false);
    let (relay_drain_tx, mut relay_drain_rx) = tokio::sync::mpsc::channel::<()>(1);

    // Relay: spawn a blocking task for wait_ready, then run the accept loop.
    // wait_ready() must run AFTER enter() starts the VM (agentd sends core.ready),
    // so it runs on a background thread, not blocking the main thread.
    let relay_exit_handle = exit_handle.clone();
    let relay_exit_reason = Arc::clone(&exit_reason);
    tokio_rt.spawn(async move {
        let ready_result =
            tokio::task::spawn_blocking(move || relay.wait_ready().map(|()| relay)).await;

        match ready_result {
            Ok(Ok(relay)) => {
                if let Some((
                    writer,
                    interval_ms,
                    krun_metrics_handle,
                    network_metrics_handle,
                    upper_host_path,
                )) = metrics_sampler
                {
                    tracing::debug!(
                        sandbox = %metrics_sandbox_name,
                        interval_ms = interval_ms.get(),
                        "starting metrics sampler after agent ready"
                    );
                    tokio::spawn(run_metrics_sampler(crate::metrics::MetricsSamplerSpec {
                        writer,
                        sandbox_id: metrics_sandbox_id,
                        pid: metrics_pid,
                        interval_ms,
                        max_cpus: metrics_max_cpus,
                        krun_metrics: krun_metrics_handle,
                        network_metrics: network_metrics_handle,
                        upper_host_path,
                    }));
                }
                if let Err(e) = relay.run(relay_shutdown_rx, relay_drain_tx).await {
                    tracing::error!("agent relay error: {e}");
                }
            }
            Ok(Err(e)) => {
                tracing::error!("agent relay wait_ready failed: {e}");
                // agentd never signalled readiness within the relay's boot window
                // — the guest failed to come up. Reclaim the VM. This is the boot-
                // failure backstop that used to live in the heartbeat monitor's
                // boot-grace path (same 180s deadline), now owned by the relay so
                // the heartbeat monitor can be purely about idle detection.
                relay_exit_reason.store(
                    EXIT_REASON_AGENT_UNRESPONSIVE,
                    std::sync::atomic::Ordering::SeqCst,
                );
                relay_exit_handle.trigger();
            }
            Err(e) => {
                tracing::error!("agent relay wait_ready task panicked: {e}");
                relay_exit_reason.store(
                    EXIT_REASON_AGENT_UNRESPONSIVE,
                    std::sync::atomic::Ordering::SeqCst,
                );
                relay_exit_handle.trigger();
            }
        }
    });

    // Shutdown listener: when the relay forwards a `core.shutdown` frame to
    // agentd, we give the guest a mode-specific window to flush block-backed
    // roots and power off cleanly. Normal agentd-as-PID1 sandboxes use a short
    // fallback; handoff-init sandboxes keep the longer PID-1 grace.
    {
        let shutdown_exit_handle = exit_handle.clone();
        let shutdown_reason = Arc::clone(&exit_reason);
        tokio_rt.spawn(async move {
            if relay_drain_rx.recv().await.is_some() {
                shutdown_reason.store(
                    EXIT_REASON_SHUTDOWN_REQUESTED,
                    std::sync::atomic::Ordering::SeqCst,
                );
                tracing::info!(
                    "core.shutdown forwarded to agentd, allowing flush window before host fallback"
                );
                tokio::time::sleep(shutdown_flush_timeout).await;
                tracing::info!("flush window elapsed, triggering host exit");
                shutdown_exit_handle.trigger();
            }
        });
    }

    // Startup workload: detached `msb run -- CMD` makes the sandbox process
    // own the command lifecycle. Once the command terminates, stop the VM so
    // named sandboxes become stopped and ephemeral sandboxes can self-clean.
    if let Some(startup_command) = config.startup_command.clone() {
        let startup_agent_sock_path = config.agent_sock_path.clone();
        let startup_shared = Arc::clone(&shared);
        let startup_exit_handle = exit_handle.clone();
        let startup_reason = Arc::clone(&exit_reason);
        let startup_shutdown_flush_timeout = shutdown_flush_timeout;
        tokio_rt.spawn(async move {
            tracing::info!(
                cmd = %startup_command.cmd,
                args = ?startup_command.args,
                "starting startup command"
            );

            match crate::startup::run_startup_command(&startup_agent_sock_path, startup_command)
                .await
            {
                Ok(crate::startup::StartupCommandExit::Exited(0)) => {
                    tracing::info!("startup command exited successfully");
                }
                Ok(crate::startup::StartupCommandExit::Exited(code)) => {
                    startup_reason.store(
                        EXIT_REASON_STARTUP_COMMAND_FAILED,
                        std::sync::atomic::Ordering::SeqCst,
                    );
                    tracing::warn!(code, "startup command exited with non-zero status");
                }
                Ok(crate::startup::StartupCommandExit::Failed(failed)) => {
                    startup_reason.store(
                        EXIT_REASON_STARTUP_COMMAND_FAILED,
                        std::sync::atomic::Ordering::SeqCst,
                    );
                    tracing::warn!(error = %failed.message, "startup command failed to spawn");
                }
                Err(err) => {
                    startup_reason.store(
                        EXIT_REASON_STARTUP_COMMAND_FAILED,
                        std::sync::atomic::Ordering::SeqCst,
                    );
                    tracing::warn!(error = %err, "startup command failed");
                }
            }

            match request_guest_shutdown(&startup_shared) {
                Ok(()) => {
                    tokio::time::sleep(startup_shutdown_flush_timeout).await;
                    tracing::info!("startup command shutdown flush window elapsed");
                }
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        "startup command shutdown request failed, triggering host exit"
                    );
                }
            }
            startup_exit_handle.trigger();
        });
    }

    // Idle monitor. Reclaims the sandbox only when an optional idle timeout is
    // configured and the guest has been inactive that long. A stale or missing
    // heartbeat is NOT treated as a failure here — a busy agent is still healthy,
    // and a guest that never boots is reclaimed by the relay's wait_ready path.
    {
        let mut heartbeat_reader = HeartbeatReader::new(&config.runtime_dir);
        let idle_timeout = config.idle_timeout_secs.map(Duration::from_secs);
        let heartbeat_exit_handle = exit_handle.clone();
        let heartbeat_reason = Arc::clone(&exit_reason);
        let heartbeat_shared = Arc::clone(&shared);
        let heartbeat_shutdown_flush_timeout = shutdown_flush_timeout;
        tokio_rt.spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                let decision = heartbeat_reader.check(idle_timeout);

                match decision {
                    HeartbeatDecision::Idle(status) => {
                        let idle_secs = idle_timeout.map(|timeout| timeout.as_secs()).unwrap_or(0);
                        tracing::info!(
                            idle_secs,
                            heartbeat_seq = ?status.heartbeat_seq,
                            activity_seq = ?status.activity_seq,
                            idle_for = ?status.idle_for,
                            active_exec_sessions = status.active_exec_sessions,
                            active_fs_streams = status.active_fs_streams,
                            active_tcp_streams = status.active_tcp_streams,
                            "sandbox idle, requesting guest shutdown"
                        );
                        heartbeat_reason.store(
                            EXIT_REASON_IDLE_TIMEOUT,
                            std::sync::atomic::Ordering::SeqCst,
                        );
                        match request_guest_shutdown(&heartbeat_shared) {
                            Ok(()) => {
                                tokio::time::sleep(heartbeat_shutdown_flush_timeout).await;
                                tracing::info!(
                                    "idle shutdown flush window elapsed, triggering host exit"
                                );
                            }
                            Err(err) => {
                                tracing::warn!(
                                    error = %err,
                                    "idle shutdown request failed, triggering host exit"
                                );
                            }
                        }
                        heartbeat_exit_handle.trigger();
                        break;
                    }
                    HeartbeatDecision::PendingBoot(_) | HeartbeatDecision::Active(_) => {}
                }
            }
        });
    }

    // Max duration timer.
    if let Some(max_secs) = config.max_duration_secs {
        let max_exit_handle = exit_handle.clone();
        let max_reason = Arc::clone(&exit_reason);
        tokio_rt.spawn(async move {
            tokio::time::sleep(Duration::from_secs(max_secs)).await;
            tracing::info!("max duration {max_secs}s exceeded, triggering exit");
            max_reason.store(
                EXIT_REASON_MAX_DURATION,
                std::sync::atomic::Ordering::SeqCst,
            );
            max_exit_handle.trigger();
        });
    }

    // Forget the tokio runtime (keep background tasks alive).
    std::mem::forget(tokio_rt);

    // Enter the VM (never returns).
    tracing::info!(sandbox = %config.sandbox_name, "entering VM");
    match vm.enter() {
        Ok(infallible) => Ok(infallible),
        Err(e) => {
            if let Some(writer) = metrics_writer {
                let _ = writer.release(ReleaseMode::Free);
            }
            Err(RuntimeError::Custom(format!("VM enter: {e}")))
        }
    }
}

fn oci_upper_host_path(vm: &VmConfig) -> Option<PathBuf> {
    vm.rootfs_vmdk.as_ref()?;

    vm.rootfs_upper_spec
        .as_ref()
        .map(|spec| spec.primary.clone())
        .or_else(|| vm.rootfs_upper.clone())
}

#[cfg(windows)]
fn agent_console_pipe_name(sandbox_id: i32) -> String {
    format!(
        r"\\.\pipe\msb-agent-console-{sandbox_id}-{}",
        std::process::id()
    )
}

//--------------------------------------------------------------------------------------------------
// Functions: VM Builder
//--------------------------------------------------------------------------------------------------

/// Build the `Vm` from config with an exit observer for cleanup.
fn build_vm(
    config: &Config,
    console_backend: AgentConsoleBackend,
    on_exit: impl Fn(i32) + Send + 'static,
    tokio_handle: tokio::runtime::Handle,
) -> RuntimeResult<VmBuildOutput> {
    let mut exec_env = config.vm.env.clone();
    let vm = &config.vm;
    let balloon_stats_interval = config
        .metrics_sample_interval_ms
        .map(|interval_ms| Duration::from_millis(interval_ms.get()));
    #[cfg(unix)]
    let mut bind_identity_map = BindIdentityMapRegistration::new();
    #[cfg(windows)]
    let bind_identity_map = BindIdentityMapRegistration::new();

    let mut builder = VmBuilder::new()
        .machine(|m| {
            let m = m
                .vcpus(vm.vcpus)
                .memory_mib(vm.memory_mib as usize)
                .max_vcpus(vm.max_cpus.max(vm.vcpus))
                .max_memory_mib((vm.max_memory_mib.max(vm.memory_mib)) as usize)
                .balloon_stats_interval(balloon_stats_interval);
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            {
                m.split_irqchip(true)
            }
            #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
            {
                m
            }
        })
        .kernel(|k| {
            let k = k.krunfw_path(&vm.libkrunfw_path);
            if let Some(ref init_path) = vm.init_path {
                k.init_path(init_path)
            } else {
                k
            }
        });

    // Root filesystem.
    if let Some(ref rootfs_path) = vm.rootfs_path {
        let backend = bind_rootfs_backend(rootfs_path, vm.rootfs_follow_root_symlinks)?;
        builder = builder.fs(move |fs| fs.tag("/dev/root").custom(Box::new(backend)));
    } else if let Some(ref vmdk_path) = vm.rootfs_vmdk {
        // EROFS fsmerge OCI rootfs: VMDK (read-only) + upper.ext4 (writable).
        #[cfg(unix)]
        {
            let empty_trampoline = tempfile::tempdir()?;
            let trampoline_path = canonicalize_owned_mount_root(empty_trampoline.path())?;
            let cfg = PassthroughConfig {
                root_dir: trampoline_path,
                no_symlink_root: true,
                ..Default::default()
            };
            let backend = PassthroughFs::new(cfg)
                .map_err(|e| RuntimeError::Custom(format!("trampoline rootfs: {e}")))?;
            builder = builder.fs(move |fs| fs.tag("/dev/root").custom(Box::new(backend)));
            let _ = empty_trampoline.keep();
        }
        #[cfg(windows)]
        {
            let backend = AgentBootstrapFs::new()
                .map_err(|e| RuntimeError::Custom(format!("bootstrap rootfs: {e}")))?;
            builder = builder.fs(move |fs| fs.tag("/dev/root").custom(Box::new(backend)));
        }

        // Attach VMDK as read-only VMDK-format block device.
        let vmdk = vmdk_path.clone();
        builder = builder.disk(move |d| {
            d.path(&vmdk)
                .format(msb_krun::DiskImageFormat::Vmdk)
                .read_only(true)
        });

        // Attach the writable upper. Prefer the typed `UpperSpec` if
        // provided; otherwise fall back to the legacy raw-only field.
        // When chains are populated (qcow2 future), each ancestor is
        // attached read-only ahead of the head file.
        if let Some(ref spec) = vm.rootfs_upper_spec {
            for backing in spec.backing.clone() {
                builder = builder.disk(move |d| {
                    d.path(&backing)
                        .format(msb_krun::DiskImageFormat::Qcow2)
                        .read_only(true)
                });
            }
            let primary = spec.primary.clone();
            let format = spec.format;
            let read_only = spec.read_only;
            builder = builder.disk(move |d| d.path(&primary).format(format).read_only(read_only));
        } else if let Some(ref upper) = vm.rootfs_upper {
            let upper = upper.clone();
            builder = builder.disk(move |d| {
                d.path(&upper)
                    .format(msb_krun::DiskImageFormat::Raw)
                    .read_only(false)
            });
        }

        // MSB_BLOCK_ROOT env var is set by the caller (spawn_sandbox).
    } else if let Some(ref disk_path) = vm.rootfs_disk {
        #[cfg(unix)]
        {
            let empty_trampoline = tempfile::tempdir()?;
            let trampoline_path = canonicalize_owned_mount_root(empty_trampoline.path())?;
            let cfg = PassthroughConfig {
                root_dir: trampoline_path,
                no_symlink_root: true,
                ..Default::default()
            };
            let backend = PassthroughFs::new(cfg)
                .map_err(|e| RuntimeError::Custom(format!("trampoline rootfs: {e}")))?;
            builder = builder.fs(move |fs| fs.tag("/dev/root").custom(Box::new(backend)));
            let _ = empty_trampoline.keep();
        }
        #[cfg(windows)]
        {
            let backend = AgentBootstrapFs::new()
                .map_err(|e| RuntimeError::Custom(format!("bootstrap rootfs: {e}")))?;
            builder = builder.fs(move |fs| fs.tag("/dev/root").custom(Box::new(backend)));
        }

        let format = validate_disk_format(vm.rootfs_disk_format.as_deref())
            .map_err(|e| RuntimeError::Custom(format!("disk format: {e}")))?;
        let disk_path = disk_path.clone();
        let readonly = vm.rootfs_disk_readonly;
        builder = builder.disk(move |d| d.path(&disk_path).format(format).read_only(readonly));
        append_block_root_env(&mut exec_env);
    }

    // Runtime directory mount — agentd mounts this at /.msb for scripts
    // and heartbeat. It is a host↔guest control channel (the host writes
    // scripts/TLS certs and reads heartbeat.json through it), so it stays a
    // virtiofs share rather than a block device. A fixed budget caps guest
    // writes so the channel can never be used to fill the host disk; the
    // legitimate guest footprint is a ~1 KiB heartbeat, so the budget is
    // almost entirely abuse headroom and is not user-configurable.
    {
        let runtime_tag = microsandbox_protocol::RUNTIME_FS_TAG.to_string();
        let cfg = PassthroughConfig {
            root_dir: canonicalize_owned_mount_root(&config.runtime_dir)?,
            inject_init: false,
            quota_bytes: Some(microsandbox_protocol::RUNTIME_FS_QUOTA_BYTES),
            no_symlink_root: true,
            ..Default::default()
        };
        let backend = PassthroughFs::new(cfg)
            .map_err(|e| RuntimeError::Custom(format!("runtime mount: {e}")))?;
        builder = builder.fs(move |fs| fs.tag(&runtime_tag).custom(Box::new(backend)));
    }

    // Additional mounts.
    for mount_spec in &vm.mounts {
        let parsed = parse_mount_spec(mount_spec)
            .map_err(|e| RuntimeError::Custom(format!("--mount {mount_spec:?}: {e}")))?;

        let tag = parsed.tag;
        #[cfg(unix)]
        let mount_bind_identity_map =
            bind_identity_map_for_mount(&mut bind_identity_map, parsed.stat_virtualization);
        let cfg = PassthroughConfig {
            root_dir: PathBuf::from(parsed.host_path),
            inject_init: false,
            stat_virtualization: parsed.stat_virtualization,
            host_permissions: parsed.host_permissions,
            readonly: parsed.readonly,
            // Default-on protection: resolve the mount root following no symlink
            // unless the mount opted out via `follow-root-symlinks`.
            no_symlink_root: !parsed.follow_root_symlinks,
            #[cfg(unix)]
            bind_identity_map: mount_bind_identity_map,
            quota_bytes: parsed.quota_bytes,
            ..Default::default()
        };
        let backend = PassthroughFs::new(cfg)
            .map_err(|e| RuntimeError::Custom(format!("mount {tag}: {e}")))?;
        builder = builder.fs(move |fs| fs.tag(&tag).custom(Box::new(backend)));
    }

    // Disk-image volume mounts. Each adds an extra virtio-blk device with
    // a stable block id so agentd can find it via /dev/disk/by-id/virtio-<id>.
    for disk in &vm.disks {
        if !disk.host.exists() {
            return Err(RuntimeError::Custom(format!(
                "disk {}: host path not found: {}",
                disk.id,
                disk.host.display()
            )));
        }
        tracing::debug!(
            id = %disk.id,
            guest = %disk.guest,
            host = %disk.host.display(),
            ?disk.format,
            fstype = ?disk.fstype,
            readonly = disk.readonly,
            "attaching disk-image volume",
        );
        let id = disk.id.clone();
        let host = disk.host.clone();
        let format = disk.format;
        let readonly = disk.readonly;
        builder = builder.disk(move |d| {
            let mut d = d.id(&id).path(&host).format(format).read_only(readonly);
            if readonly {
                // Read-only images can skip host-side sync entirely.
                d = d
                    .cache(msb_krun::CacheMode::Unsafe)
                    .sync(msb_krun::SyncMode::None);
            }
            d
        });
    }

    let mut network_termination_handle = None;
    let mut network_metrics_handle = None;
    let mut network_secrets_handle = None;

    // Network.
    #[cfg(feature = "net")]
    if vm.network.enabled {
        let _ = rustls::crypto::ring::default_provider().install_default();
        vm.network
            .secrets
            .validate()
            .map_err(|err| RuntimeError::Custom(format!("invalid network secrets: {err}")))?;

        let mut network =
            microsandbox_network::network::SmoltcpNetwork::new(vm.network.clone(), vm.sandbox_slot);
        network_termination_handle = Some(network.termination_handle());
        network_metrics_handle = Some(network.metrics_handle());
        // Only sandboxes that booted with secrets can be live-reconfigured:
        // new placeholders cannot be introduced into a running guest, so a
        // secret-free boot never needs the secrets side of the control socket.
        if !vm.network.secrets.secrets.is_empty() {
            network_secrets_handle = Some(network.secrets_handle());
        }

        network.start(tokio_handle.clone());

        let guest_mac = network.guest_mac();
        let net_backend = network.take_backend();

        {
            let tls_dir = config.runtime_dir.join("tls");
            let _ = std::fs::create_dir_all(&tls_dir);
            if let Some(ca_pem) = network.ca_cert_pem() {
                let _ = std::fs::write(tls_dir.join("ca.pem"), &ca_pem);
            }
            if let Some(host_cas_pem) = network.host_cas_cert_pem() {
                let _ = std::fs::write(tls_dir.join("host-cas.pem"), &host_cas_pem);
            }
        }

        for (key, value) in network.guest_env_vars() {
            exec_env.push(format!("{key}={value}"));
        }

        builder = builder.net(move |n| n.mac(guest_mac).custom(net_backend));
    }

    // Execution configuration.
    prepend_scripts_path(&mut exec_env);
    builder = builder.exec(|mut e| {
        if let Some(ref path) = vm.exec_path {
            e = e.path(path);
        }
        if !vm.exec_args.is_empty() {
            e = e.args(&vm.exec_args);
        }
        for env_str in &exec_env {
            if let Some((key, value)) = env_str.split_once('=') {
                e = e.env(key, value);
            }
        }
        if let Some(ref workdir) = vm.workdir {
            e = e.workdir(workdir);
        }
        e
    });

    // Console — ring-buffer-based custom backend for agent protocol, plus
    // console output routed to kernel.log for kernel/init logs.
    let kernel_log_path = config.log_dir.join("kernel.log");
    #[cfg(unix)]
    {
        builder = builder.console(|c| {
            c.output(&kernel_log_path).custom(
                microsandbox_protocol::AGENT_PORT_NAME,
                Box::new(console_backend),
            )
        });
    }
    #[cfg(windows)]
    {
        let _ = console_backend;
        let agent_pipe = agent_console_pipe_name(config.sandbox_id);
        builder = builder.console(|c| {
            // Windows WHP/x64 currently uses virtio-console for reliable
            // guest logs; the implicit serial console is present but silent
            // on the dev hosts used for WHP testing.
            c.disable_implicit()
                .virtio_output(&kernel_log_path)
                .named_pipe(microsandbox_protocol::AGENT_PORT_NAME, agent_pipe)
        });
    }

    // Exit observer — runs synchronously before _exit() for DB cleanup.
    builder = builder.on_exit(on_exit);

    let vm = builder
        .build()
        .map_err(|e| RuntimeError::Custom(format!("build VM: {e}")))?;

    Ok((
        vm,
        network_termination_handle,
        network_metrics_handle,
        network_secrets_handle,
        bind_identity_map,
    ))
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Raise `RLIMIT_NOFILE` to the hard limit, capped at 1M (the reference virtiofsd default). On macOS the soft limit is additionally clamped to
/// `kern.maxfilesperproc`, which `setrlimit` enforces even when the hard limit is unlimited.
#[cfg(unix)]
fn raise_nofile_limit() {
    const TARGET: libc::rlim_t = 1_048_576;

    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
        tracing::warn!(
            error = %std::io::Error::last_os_error(),
            "getrlimit(RLIMIT_NOFILE) failed; keeping inherited fd limit"
        );
        return;
    }

    let want = lim.rlim_max.min(TARGET);
    #[cfg(target_os = "macos")]
    let want = macos_maxfilesperproc().map_or(want, |max| want.min(max));

    if want <= lim.rlim_cur {
        return;
    }

    let new = libc::rlimit {
        rlim_cur: want,
        rlim_max: lim.rlim_max,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &new) } != 0 {
        tracing::warn!(
            error = %std::io::Error::last_os_error(),
            soft = lim.rlim_cur,
            wanted = want,
            "setrlimit(RLIMIT_NOFILE) failed; keeping inherited fd limit"
        );
    } else {
        tracing::debug!(from = lim.rlim_cur, to = want, "raised RLIMIT_NOFILE");
    }
}

/// Read `kern.maxfilesperproc`, the ceiling macOS enforces on the `RLIMIT_NOFILE` soft limit.
#[cfg(target_os = "macos")]
fn macos_maxfilesperproc() -> Option<libc::rlim_t> {
    let mut maxfiles: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>();
    let ret = unsafe {
        libc::sysctlbyname(
            c"kern.maxfilesperproc".as_ptr(),
            &mut maxfiles as *mut _ as *mut libc::c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    (ret == 0 && maxfiles > 0).then_some(maxfiles as libc::rlim_t)
}

/// Build the host-directory rootfs backend used for `RootfsSource::Bind`.
///
/// The path is caller/tenant-provided, so it gets the same default no-follow
/// root protection as a `--mount`: a symlink at or under the rootfs path is
/// refused rather than followed out of its intended target. `follow_root_symlinks`
/// opts out when the host rootfs path legitimately traverses a symlink.
fn bind_rootfs_backend(
    rootfs_path: &Path,
    follow_root_symlinks: bool,
) -> RuntimeResult<PassthroughFs> {
    let cfg = PassthroughConfig {
        root_dir: rootfs_path.to_path_buf(),
        no_symlink_root: !follow_root_symlinks,
        ..Default::default()
    };
    PassthroughFs::new(cfg).map_err(|e| RuntimeError::Custom(format!("rootfs: {e}")))
}

/// Canonicalize a microsandbox-owned mount root so it is symlink-free.
///
/// These roots are created and owned by the runtime (temp trampolines, the
/// control-channel directory), never attacker-controlled, so resolving the one
/// benign system symlink in their prefix (e.g. macOS `/var` -> `/private/var`)
/// here is safe and lets them keep the default no-follow protection at mount
/// time instead of following symlinks.
fn canonicalize_owned_mount_root(path: &Path) -> RuntimeResult<PathBuf> {
    std::fs::canonicalize(path).map_err(|e| {
        RuntimeError::Custom(format!("canonicalize mount root {}: {e}", path.display()))
    })
}

/// Open the shared-memory registry and promote the host-reserved slot to
/// `Active`, returning a writer handle for the sampler.
fn activate_metrics_writer(
    handoff: Option<&MetricsSlotHandoff>,
    interval: Option<NonZero<u64>>,
    run_id: i32,
    pid: u32,
) -> Option<microsandbox_metrics::MetricsSlotWriter> {
    interval?;
    let handoff = handoff?;
    let registry = match MetricsRegistry::open(&handoff.shm_name) {
        Ok(reg) => reg,
        Err(err) => {
            tracing::warn!(error = %err, shm = %handoff.shm_name, "failed to open metrics registry");
            return None;
        }
    };
    let started_at = chrono::Utc::now();
    match registry.activate_writer(ActivateSlot {
        slot: handoff.slot,
        generation: handoff.generation,
        run_id,
        pid: pid as i32,
        started_at,
    }) {
        Ok(writer) => Some(writer),
        Err(err) => {
            tracing::warn!(error = %err, "failed to activate metrics slot");
            None
        }
    }
}

/// Best-effort release of a metrics slot that has not been activated yet.
fn release_reserved_metrics_slot(handoff: Option<&MetricsSlotHandoff>) {
    let Some(handoff) = handoff else { return };
    if let Ok(reg) = MetricsRegistry::open(&handoff.shm_name) {
        let _ = reg.release_reserved(handoff.slot, handoff.generation);
    }
}

#[cfg(unix)]
fn bind_identity_map_for_mount(
    registration: &mut BindIdentityMapRegistration,
    stat_virtualization: StatVirtualization,
) -> Option<BindIdentityMapHandle> {
    if matches!(stat_virtualization, StatVirtualization::Off) {
        return None;
    }

    registration.mount_count += 1;
    let handle = registration
        .handle
        .get_or_insert_with(|| Arc::new(OnceLock::new()));
    Some(Arc::clone(handle))
}

/// Set up host log capture.
///
/// Redirects stderr through a pipe so a background thread can write to a
/// rotating log file (`runtime.log`). Stdout is redirected to `/dev/null`
/// because kernel console output is routed to `kernel.log` directly via
/// `console_output` in the VM builder.
///
/// If `forward` is true, stderr is also tee'd to the original fd.
#[cfg(unix)]
fn setup_log_capture(log_dir: &std::path::Path, forward: bool) -> RuntimeResult<()> {
    // Redirect stdout to /dev/null — kernel console goes to kernel.log
    // via console_output, so nothing useful writes to stdout after the
    // startup JSON. This prevents SIGPIPE when the parent drops the pipe.
    let devnull = std::fs::OpenOptions::new().write(true).open("/dev/null")?;
    unsafe {
        libc::dup2(devnull.as_raw_fd(), libc::STDOUT_FILENO);
    }
    drop(devnull);

    // Capture stderr → runtime.log (rotating).
    let (stderr_read, stderr_write) = create_pipe()?;

    let orig_stderr: Option<std::fs::File> = if forward {
        Some(unsafe { std::fs::File::from_raw_fd(libc::dup(libc::STDERR_FILENO)) })
    } else {
        None
    };

    unsafe {
        libc::dup2(stderr_write.as_raw_fd(), libc::STDERR_FILENO);
    }
    drop(stderr_write);

    spawn_log_thread("log-runtime", stderr_read, log_dir, "runtime", orig_stderr)?;

    Ok(())
}

/// Set up host log capture.
#[cfg(windows)]
fn setup_log_capture(_log_dir: &std::path::Path, _forward: bool) -> RuntimeResult<()> {
    Ok(())
}

/// Write startup info JSON to the dedicated startup fd when supplied,
/// otherwise stdout.
#[cfg(unix)]
fn write_startup_info(startup_fd: Option<&OwnedFd>, json: &str) -> RuntimeResult<()> {
    if let Some(fd) = startup_fd {
        let dup = unsafe { libc::dup(fd.as_raw_fd()) };
        if dup < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut file = unsafe { std::fs::File::from_raw_fd(dup) };
        writeln!(file, "{json}")?;
        file.flush()?;
        return Ok(());
    }

    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{json}")?;
    stdout.flush()?;
    Ok(())
}

/// Write startup info JSON to the dedicated startup pipe when supplied,
/// otherwise stdout.
#[cfg(windows)]
fn write_startup_info(startup_pipe: Option<&str>, json: &str) -> RuntimeResult<()> {
    if let Some(pipe) = startup_pipe {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(pipe)
            .map_err(|err| RuntimeError::Custom(format!("open startup pipe {pipe}: {err}")))?;
        writeln!(file, "{json}")?;
        file.flush()?;
        return Ok(());
    }

    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{json}")?;
    stdout.flush()?;
    Ok(())
}

/// Connect to the sandbox database.
///
/// Busy timeout uses [`microsandbox_db::pool::DEFAULT_BUSY_TIMEOUT_SECS`]:
/// the in-VM runtime is not user-configurable, so DB tuning policy lives
/// with the host (which honours `~/.microsandbox/config.json`).
async fn connect_db(
    db_path: &std::path::Path,
    connect_timeout_secs: u64,
) -> RuntimeResult<DbWriteConnection> {
    DbWriteConnection::open(
        db_path,
        Duration::from_secs(connect_timeout_secs),
        Duration::from_secs(microsandbox_db::pool::DEFAULT_BUSY_TIMEOUT_SECS),
    )
    .await
    .map_err(|e| RuntimeError::Custom(format!("database connect: {e}")))
}

/// Insert a run record into the database.
async fn insert_run(db: &DbWriteConnection, sandbox_id: i32, pid: u32) -> RuntimeResult<i32> {
    let now = chrono::Utc::now().naive_utc();
    let record = run_entity::ActiveModel {
        sandbox_id: Set(sandbox_id),
        pid: Set(Some(pid as i32)),
        status: Set(run_entity::RunStatus::Running),
        started_at: Set(Some(now)),
        ..Default::default()
    };
    let result = run_entity::Entity::insert(record)
        .exec(db)
        .await
        .map_err(|e| RuntimeError::Custom(format!("insert run: {e}")))?;
    Ok(result.last_insert_id)
}

/// Mark a run record as failed (Terminated + InternalError) on startup error.
async fn mark_run_failed(db: &DbWriteConnection, run_id: i32) -> RuntimeResult<()> {
    use sea_orm::QueryFilter;
    use sea_orm::sea_query::Expr;

    let now = chrono::Utc::now().naive_utc();
    run_entity::Entity::update_many()
        .col_expr(
            run_entity::Column::Status,
            Expr::value(run_entity::RunStatus::Terminated),
        )
        .col_expr(
            run_entity::Column::TerminationReason,
            Expr::value(run_entity::TerminationReason::InternalError),
        )
        .col_expr(run_entity::Column::TerminatedAt, Expr::value(now))
        .filter(run_entity::Column::Id.eq(run_id))
        .exec(db)
        .await
        .map_err(|e| RuntimeError::Custom(format!("mark run failed: {e}")))?;
    Ok(())
}

/// Request guest poweroff through agentd without requiring a client connection.
fn request_guest_shutdown(shared: &ConsoleSharedState) -> RuntimeResult<()> {
    request_guest_shutdown_with_timeout(shared, Duration::from_secs(60))
}

fn request_guest_shutdown_with_timeout(
    shared: &ConsoleSharedState,
    timeout: Duration,
) -> RuntimeResult<()> {
    let msg = Message::with_payload(MessageType::Shutdown, 0, &())
        .map_err(|e| RuntimeError::Custom(format!("encode idle shutdown: {e}")))?;
    let mut frame = Vec::new();
    codec::encode_to_buf(&msg, &mut frame)
        .map_err(|e| RuntimeError::Custom(format!("encode idle shutdown frame: {e}")))?;
    relay::push_guest_frame_until(shared, frame, timeout)
}

fn guest_shutdown_flush_timeout(has_handoff_init: bool) -> Duration {
    let override_ms = std::env::var("MSB_SHUTDOWN_FLUSH_TIMEOUT_MS").ok();
    guest_shutdown_flush_timeout_with_override(has_handoff_init, override_ms.as_deref())
}

fn guest_shutdown_flush_timeout_with_override(
    has_handoff_init: bool,
    override_ms: Option<&str>,
) -> Duration {
    if let Some(raw) = override_ms {
        match raw.parse::<u64>() {
            Ok(ms) => return Duration::from_millis(ms),
            Err(error) => {
                tracing::warn!(
                    value = raw,
                    error = %error,
                    "ignoring invalid MSB_SHUTDOWN_FLUSH_TIMEOUT_MS override"
                );
            }
        }
    }

    if has_handoff_init {
        microsandbox_protocol::HANDOFF_SHUTDOWN_FLUSH_TIMEOUT
    } else {
        microsandbox_protocol::NORMAL_SHUTDOWN_FLUSH_TIMEOUT
    }
}

#[cfg(unix)]
fn spawn_parent_watchdog(
    parent_watchdog: OwnedFd,
    shared: Arc<ConsoleSharedState>,
    exit_reason: Arc<std::sync::atomic::AtomicU8>,
    exit_handle: msb_krun::ExitHandle,
    sandbox_name: String,
    shutdown_flush_timeout: Duration,
) -> RuntimeResult<()> {
    std::thread::Builder::new()
        .name(format!("msb-parent-watch-{sandbox_name}"))
        .spawn(move || {
            let mut file = std::fs::File::from(parent_watchdog);

            match read_parent_watchdog_signal(&mut file) {
                Ok(ParentWatchdogSignal::ParentExited) => {
                    tracing::info!("creator process exited; stopping attached sandbox");
                    exit_reason.store(EXIT_REASON_PARENT_EXIT, std::sync::atomic::Ordering::SeqCst);
                    if let Err(err) = request_guest_shutdown(&shared) {
                        tracing::warn!(error = %err, "parent-watch shutdown request failed");
                    } else {
                        std::thread::sleep(shutdown_flush_timeout);
                    }
                    exit_handle.trigger();
                }
                Ok(ParentWatchdogSignal::Detached) => {
                    tracing::debug!("attached-parent watchdog detached; leaving sandbox running");
                }
                Err(err) => {
                    tracing::warn!(error = %err, "parent-watch read failed; stopping sandbox");
                    exit_reason.store(EXIT_REASON_SIGNAL, std::sync::atomic::Ordering::SeqCst);
                    exit_handle.trigger();
                }
            }
        })
        .map_err(RuntimeError::Io)?;

    Ok(())
}

#[cfg(unix)]
fn read_parent_watchdog_signal(file: &mut std::fs::File) -> std::io::Result<ParentWatchdogSignal> {
    let mut buf = [0_u8; 1];

    loop {
        match std::io::Read::read(file, &mut buf) {
            Ok(0) => return Ok(ParentWatchdogSignal::ParentExited),
            Ok(_) if buf[0] == PARENT_WATCH_DETACH => return Ok(ParentWatchdogSignal::Detached),
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
}

/// Create a pipe pair, returning `(read_end, write_end)` as `OwnedFd`.
#[cfg(unix)]
fn create_pipe() -> RuntimeResult<(OwnedFd, OwnedFd)> {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(RuntimeError::Io(std::io::Error::last_os_error()));
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Spawn a background thread that reads from a pipe and writes to a
/// rotating log file. If `forward` is `Some`, also tees to that file
/// (typically the original stdout/stderr saved before redirect).
#[cfg(unix)]
fn spawn_log_thread(
    name: &str,
    pipe_read: OwnedFd,
    log_dir: &std::path::Path,
    log_prefix: &str,
    forward: Option<std::fs::File>,
) -> RuntimeResult<()> {
    use crate::logging::RotatingLog;
    use std::io::Read;

    const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;

    let log_dir = log_dir.to_path_buf();
    let log_prefix = log_prefix.to_string();

    std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            let mut log = match RotatingLog::new(&log_dir, &log_prefix, MAX_LOG_BYTES) {
                Ok(log) => log,
                Err(e) => {
                    let _ = writeln!(std::io::stderr(), "failed to create {log_prefix} log: {e}");
                    return;
                }
            };
            let mut reader = unsafe { std::fs::File::from_raw_fd(pipe_read.into_raw_fd()) };
            let mut fwd = forward;
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let _ = log.write(&buf[..n]);
                        if let Some(ref mut f) = fwd {
                            let _ = std::io::Write::write_all(f, &buf[..n]);
                        }
                    }
                    Err(_) => break,
                }
            }
        })
        .map_err(|e| RuntimeError::Custom(format!("spawn {name} thread: {e}")))?;

    Ok(())
}

/// Parsed `--mount` spec: tag, host path, plus optional policies.
///
/// Wire format: `tag:host_path[:opts]`.
/// Defaults: `rw`, `stat-virt=strict`, `host-perms=private`. The `ro` flag is
/// enforced by the host filesystem server; execution and suid flags are applied
/// by agentd when the guest mount is installed.
#[derive(Debug)]
struct ParsedMountSpec {
    tag: String,
    host_path: String,
    stat_virtualization: StatVirtualization,
    host_permissions: HostPermissions,
    readonly: bool,
    follow_root_symlinks: bool,
    quota_bytes: Option<u64>,
}

/// Parse a `--mount` spec into [`ParsedMountSpec`].
///
/// Wire grammar: `tag:host_path[:opts]`, where `opts` is a comma-separated
/// option block of flags (`ro`, `rw`, `noexec`, `nosuid`, `nodev`,
/// `follow-root-symlinks`) and keyed policies (`stat-virt=...`, `host-perms=...`).
/// The `follow-root-symlinks` flag opts the mount out of the default no-follow
/// root resolution; its absence keeps the protective default on.
fn parse_mount_spec(spec: &str) -> Result<ParsedMountSpec, String> {
    let (tag, rest) = spec
        .split_once(':')
        .ok_or_else(|| format!("expected tag:host_path[:opts] shape, got {spec:?}"))?;
    if tag.is_empty() {
        return Err(format!("empty tag in mount spec {spec:?}"));
    }

    let (host_path, options) = split_mount_host_options(rest);

    if host_path.is_empty() {
        return Err(format!("empty host path in mount spec {spec:?}"));
    }
    if host_path.contains(',') {
        return Err(format!(
            "mount options must use tag:host_path:opts syntax, got comma in host path {host_path:?}"
        ));
    }

    let mut stat_virtualization = StatVirtualization::Strict;
    let mut host_permissions = HostPermissions::Private;
    let mut readonly = false;
    let mut follow_root_symlinks = false;
    let mut quota_bytes = None;
    let mut seen_stat_virt = false;
    let mut seen_host_perms = false;
    let mut seen_access = false;
    let mut seen_noexec = false;
    let mut seen_nosuid = false;
    let mut seen_nodev = false;
    let mut seen_follow_root = false;
    let mut seen_quota = false;

    if let Some(opts) = options {
        for opt in opts.split(',') {
            let opt = opt.trim();
            if opt.is_empty() {
                continue;
            }
            match opt {
                "ro" | "rw" => {
                    if seen_access {
                        return Err("mount option `ro`/`rw` specified more than once".to_string());
                    }
                    seen_access = true;
                    readonly = opt == "ro";
                }
                "noexec" => {
                    if seen_noexec {
                        return Err("mount option `noexec` specified more than once".to_string());
                    }
                    seen_noexec = true;
                }
                "nosuid" => {
                    if seen_nosuid {
                        return Err("mount option `nosuid` specified more than once".to_string());
                    }
                    seen_nosuid = true;
                }
                "nodev" => {
                    if seen_nodev {
                        return Err("mount option `nodev` specified more than once".to_string());
                    }
                    seen_nodev = true;
                }
                "follow-root-symlinks" => {
                    if seen_follow_root {
                        return Err(
                            "mount option `follow-root-symlinks` specified more than once"
                                .to_string(),
                        );
                    }
                    seen_follow_root = true;
                    follow_root_symlinks = true;
                }
                "suid" | "exec" | "dev" => {
                    return Err(format!("unsupported mount option {opt:?}"));
                }
                _ => {
                    let (key, value) = opt
                        .split_once('=')
                        .ok_or_else(|| format!("expected flag or key=value option, got {opt:?}"))?;
                    match key {
                        "stat-virt" => {
                            if seen_stat_virt {
                                return Err(
                                    "mount option `stat-virt` specified more than once".to_string()
                                );
                            }
                            seen_stat_virt = true;
                            stat_virtualization = match value {
                                "strict" => StatVirtualization::Strict,
                                "relaxed" => StatVirtualization::Relaxed,
                                "off" => StatVirtualization::Off,
                                other => {
                                    return Err(format!(
                                        "invalid stat-virt {other:?} (expected strict|relaxed|off)"
                                    ));
                                }
                            }
                        }
                        "host-perms" => {
                            if seen_host_perms {
                                return Err("mount option `host-perms` specified more than once"
                                    .to_string());
                            }
                            seen_host_perms = true;
                            host_permissions = match value {
                                "private" => HostPermissions::Private,
                                "mirror" => HostPermissions::Mirror,
                                other => {
                                    return Err(format!(
                                        "invalid host-perms {other:?} (expected private|mirror)"
                                    ));
                                }
                            }
                        }
                        "quota" => {
                            if seen_quota {
                                return Err(
                                    "mount option `quota` specified more than once".to_string()
                                );
                            }
                            seen_quota = true;
                            let mib = value.parse::<u64>().map_err(|_| {
                                format!(
                                    "invalid quota {value:?} (expected an integer count of MiB)"
                                )
                            })?;
                            quota_bytes = Some(mib.saturating_mul(1024 * 1024));
                        }
                        other => return Err(format!("unknown mount option {other:?}")),
                    }
                }
            }
        }
    }

    Ok(ParsedMountSpec {
        tag: tag.to_string(),
        host_path: host_path.to_string(),
        stat_virtualization,
        host_permissions,
        readonly,
        follow_root_symlinks,
        quota_bytes,
    })
}

/// Split `host_path[:opts]`, skipping the drive colon in Windows paths.
fn split_mount_host_options(rest: &str) -> (&str, Option<&str>) {
    let search = if windows_drive_path_prefix_len(rest).is_some() {
        &rest[2..]
    } else {
        rest
    };

    match search.rsplit_once(':') {
        Some((_prefix, opts)) => {
            let split_at = rest.len() - opts.len() - 1;
            let host = &rest[..split_at];
            (host, Some(opts))
        }
        None => (rest, None),
    }
}

/// Return the length of a Windows drive prefix when this target accepts one.
fn windows_drive_path_prefix_len(rest: &str) -> Option<usize> {
    #[cfg(windows)]
    {
        microsandbox_utils::is_windows_drive_path_text(rest).then_some(2)
    }
    #[cfg(not(windows))]
    {
        let _ = rest;
        None
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Mount Spec Parsing
//--------------------------------------------------------------------------------------------------

/// Validate a disk image format string.
pub fn validate_disk_format(format: Option<&str>) -> msb_krun::Result<msb_krun::DiskImageFormat> {
    match format.unwrap_or("raw") {
        "qcow2" => Ok(msb_krun::DiskImageFormat::Qcow2),
        "raw" => Ok(msb_krun::DiskImageFormat::Raw),
        "vmdk" => Ok(msb_krun::DiskImageFormat::Vmdk),
        other => Err(msb_krun::Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unknown disk image format: {other}"),
        ))),
    }
}

/// Append the default block root env var if not already set.
pub fn append_block_root_env(env: &mut Vec<String>) {
    let prefix = format!("{}=", microsandbox_protocol::ENV_BLOCK_ROOT);
    if env.iter().any(|entry| entry.starts_with(&prefix)) {
        return;
    }
    env.push(format!("{prefix}/dev/vda"));
}

/// Prepend `/.msb/scripts` to PATH for the initial guest command.
pub fn prepend_scripts_path(env: &mut Vec<String>) {
    let scripts = microsandbox_protocol::SCRIPTS_PATH;
    let prefix = "PATH=";

    if let Some(entry) = env.iter_mut().find(|entry| entry.starts_with(prefix)) {
        let existing = &entry[prefix.len()..];
        if !existing.split(':').any(|segment| segment == scripts) {
            *entry = format!("{prefix}{scripts}:{existing}");
        }
    } else {
        env.push(format!(
            "{prefix}{scripts}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        ));
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::{
        BindIdentityMapRegistration, PARENT_WATCH_DETACH, ParentWatchdogSignal,
        bind_identity_map_for_mount, read_parent_watchdog_signal,
    };
    use super::{
        ConsoleSharedState, HostPermissions, StatVirtualization, append_block_root_env,
        bind_rootfs_backend, guest_shutdown_flush_timeout,
        guest_shutdown_flush_timeout_with_override, parse_mount_spec, prepend_scripts_path,
        request_guest_shutdown, request_guest_shutdown_with_timeout, validate_disk_format,
    };

    use microsandbox_filesystem::{Context, DynFileSystem, FsOptions};
    use microsandbox_protocol::{codec, message::MessageType};
    #[cfg(unix)]
    use std::io::Write;
    #[cfg(unix)]
    use std::sync::Arc;
    use std::time::Duration;

    fn fs_context() -> Context {
        Context {
            uid: 0,
            gid: 0,
            pid: 1,
        }
    }

    #[test]
    fn test_bind_rootfs_backend_exposes_host_file_and_init() {
        let rootfs = tempfile::tempdir().unwrap();
        std::fs::write(rootfs.path().join("host.txt"), b"from host").unwrap();

        // follow=true: the tempdir path may traverse a symlinked prefix (macOS
        // `/var`); this test exercises backend behavior, not root protection.
        let fs = bind_rootfs_backend(rootfs.path(), true).unwrap();
        fs.init(FsOptions::empty()).unwrap();

        let host = fs.lookup(fs_context(), 1, c"host.txt").unwrap();
        let init = fs.lookup(fs_context(), 1, c"init.krun").unwrap();

        assert_ne!(host.inode, init.inode);
        assert_eq!(init.inode, 2);
    }

    #[test]
    fn test_parse_mount_spec_minimal() {
        let p = parse_mount_spec("foo:/host/data").unwrap();
        assert_eq!(p.tag, "foo");
        assert_eq!(p.host_path, "/host/data");
        assert!(matches!(p.stat_virtualization, StatVirtualization::Strict));
        assert!(matches!(p.host_permissions, HostPermissions::Private));
        assert!(!p.readonly);
    }

    #[test]
    fn test_parse_mount_spec_with_ro_and_policies() {
        let p = parse_mount_spec("foo:/host/data:ro,noexec,stat-virt=relaxed,host-perms=mirror")
            .unwrap();
        assert_eq!(p.host_path, "/host/data");
        assert!(matches!(p.stat_virtualization, StatVirtualization::Relaxed));
        assert!(matches!(p.host_permissions, HostPermissions::Mirror));
        assert!(p.readonly);
    }

    #[test]
    fn test_parse_mount_spec_stat_virt_off() {
        let p = parse_mount_spec("foo:/host/data:stat-virt=off").unwrap();
        assert!(matches!(p.stat_virtualization, StatVirtualization::Off));
        assert!(!p.readonly);
    }

    #[test]
    fn test_parse_mount_spec_follow_root_symlinks_default_protected() {
        // Absent token: protected by default (follow_root_symlinks stays false,
        // which the construction site inverts into no_symlink_root = true).
        let p = parse_mount_spec("foo:/host/data").unwrap();
        assert!(!p.follow_root_symlinks);
    }

    #[test]
    fn test_parse_mount_spec_follow_root_symlinks_opt_out() {
        let p = parse_mount_spec("foo:/host/data:follow-root-symlinks").unwrap();
        assert!(p.follow_root_symlinks);
        // Coexists with other options.
        let p = parse_mount_spec("foo:/host/data:ro,follow-root-symlinks,stat-virt=off").unwrap();
        assert!(p.follow_root_symlinks);
        assert!(p.readonly);
        assert!(matches!(p.stat_virtualization, StatVirtualization::Off));
    }

    #[test]
    fn test_parse_mount_spec_rejects_duplicate_follow_root_symlinks() {
        let err = parse_mount_spec("foo:/host/data:follow-root-symlinks,follow-root-symlinks")
            .unwrap_err();
        assert!(err.contains("follow-root-symlinks"), "got: {err}");
    }

    #[test]
    fn test_parse_mount_spec_quota_in_mib() {
        let p = parse_mount_spec("foo:/host/data:quota=2048").unwrap();
        assert_eq!(p.quota_bytes, Some(2048 * 1024 * 1024));
    }

    #[test]
    fn test_parse_mount_spec_quota_default_none() {
        let p = parse_mount_spec("foo:/host/data:ro").unwrap();
        assert_eq!(p.quota_bytes, None);
    }

    #[test]
    fn test_parse_mount_spec_rejects_duplicate_quota() {
        let err = parse_mount_spec("foo:/host/data:quota=1,quota=2").unwrap_err();
        assert!(
            err.contains("`quota` specified more than once"),
            "got: {err}"
        );
    }

    #[test]
    fn test_parse_mount_spec_rejects_non_numeric_quota() {
        let err = parse_mount_spec("foo:/host/data:quota=big").unwrap_err();
        assert!(err.contains("invalid quota"), "got: {err}");
    }

    #[test]
    fn test_parse_mount_spec_rejects_unknown_key() {
        let err = parse_mount_spec("foo:/host/data:bogus=1").unwrap_err();
        assert!(err.contains("unknown mount option"), "got: {err}");
    }

    #[test]
    fn test_parse_mount_spec_rejects_invalid_stat_virt() {
        let err = parse_mount_spec("foo:/host/data:stat-virt=nope").unwrap_err();
        assert!(err.contains("invalid stat-virt"), "got: {err}");
    }

    #[test]
    fn test_parse_mount_spec_rejects_invalid_host_perms() {
        let err = parse_mount_spec("foo:/host/data:host-perms=public").unwrap_err();
        assert!(err.contains("invalid host-perms"), "got: {err}");
    }

    #[test]
    fn test_parse_mount_spec_missing_colon_errors() {
        let err = parse_mount_spec("nopath").unwrap_err();
        assert!(err.contains("expected tag:host_path"), "got: {err}");
    }

    #[test]
    fn test_parse_mount_spec_empty_tag_errors() {
        let err = parse_mount_spec(":/host").unwrap_err();
        assert!(err.contains("empty tag"), "got: {err}");
    }

    #[test]
    fn test_parse_mount_spec_with_flags_before_policies() {
        let p = parse_mount_spec("foo:/host/data:ro,nosuid,stat-virt=relaxed").unwrap();
        assert_eq!(p.host_path, "/host/data");
        assert!(matches!(p.stat_virtualization, StatVirtualization::Relaxed));
    }

    #[test]
    fn test_parse_mount_spec_rejects_duplicate_stat_virt() {
        let err = parse_mount_spec("foo:/host:stat-virt=strict,stat-virt=off").unwrap_err();
        assert!(err.contains("more than once"), "got: {err}");
    }

    #[test]
    fn test_parse_mount_spec_rejects_legacy_comma_options() {
        let err = parse_mount_spec("foo:/host/data,stat-virt=off").unwrap_err();
        assert!(err.contains("tag:host_path:opts"), "got: {err}");
    }

    #[test]
    fn test_parse_mount_spec_rejects_duplicate_flags() {
        let err = parse_mount_spec("foo:/host:ro,rw").unwrap_err();
        assert!(err.contains("ro`/`rw"), "got: {err}");
    }

    #[test]
    fn test_parse_mount_spec_rejects_unsupported_flags() {
        let err = parse_mount_spec("foo:/host:exec").unwrap_err();
        assert!(err.contains("unsupported mount option"), "got: {err}");
    }

    #[test]
    #[cfg(windows)]
    fn test_parse_mount_spec_accepts_windows_drive_path() {
        let p = parse_mount_spec(r"work:C:\Users\Stephen\data:ro,host-perms=mirror").unwrap();
        assert_eq!(p.tag, "work");
        assert_eq!(p.host_path, r"C:\Users\Stephen\data");
        assert!(matches!(p.host_permissions, HostPermissions::Mirror));
        assert!(p.readonly);
    }

    #[test]
    #[cfg(unix)]
    fn test_bind_identity_map_registration_shares_handle_for_virtualized_mounts() {
        let mut registration = BindIdentityMapRegistration {
            handle: None,
            mount_count: 0,
        };

        let first =
            bind_identity_map_for_mount(&mut registration, StatVirtualization::Strict).unwrap();
        let second =
            bind_identity_map_for_mount(&mut registration, StatVirtualization::Relaxed).unwrap();
        let off = bind_identity_map_for_mount(&mut registration, StatVirtualization::Off);

        assert!(Arc::ptr_eq(&first, &second));
        assert!(off.is_none());
        assert_eq!(registration.mount_count, 2);
    }

    #[test]
    fn test_request_guest_shutdown_enqueues_shutdown_frame() {
        let shared = ConsoleSharedState::new();

        request_guest_shutdown(&shared).unwrap();

        let mut frame = shared.rx_ring.pop().unwrap();
        let msg = codec::try_decode_from_buf(&mut frame).unwrap().unwrap();
        assert_eq!(msg.t, MessageType::Shutdown);
        assert_eq!(msg.id, 0);
    }

    #[test]
    fn test_guest_shutdown_flush_timeout_tracks_handoff_mode() {
        assert_eq!(
            guest_shutdown_flush_timeout(false),
            microsandbox_protocol::NORMAL_SHUTDOWN_FLUSH_TIMEOUT
        );
        assert_eq!(
            guest_shutdown_flush_timeout(true),
            microsandbox_protocol::HANDOFF_SHUTDOWN_FLUSH_TIMEOUT
        );
    }

    #[test]
    fn test_guest_shutdown_flush_timeout_accepts_ms_override() {
        assert_eq!(
            guest_shutdown_flush_timeout_with_override(false, Some("0")),
            Duration::ZERO
        );
        assert_eq!(
            guest_shutdown_flush_timeout_with_override(true, Some("125")),
            Duration::from_millis(125)
        );
    }

    #[test]
    fn test_guest_shutdown_flush_timeout_ignores_invalid_override() {
        assert_eq!(
            guest_shutdown_flush_timeout_with_override(false, Some("nope")),
            microsandbox_protocol::NORMAL_SHUTDOWN_FLUSH_TIMEOUT
        );
        assert_eq!(
            guest_shutdown_flush_timeout_with_override(true, Some("nope")),
            microsandbox_protocol::HANDOFF_SHUTDOWN_FLUSH_TIMEOUT
        );
    }

    #[test]
    fn test_request_guest_shutdown_with_timeout_fails_when_ring_full() {
        let shared = ConsoleSharedState::with_capacity(1);
        shared.rx_ring.push(b"occupied".to_vec()).unwrap();

        let err = request_guest_shutdown_with_timeout(&shared, Duration::ZERO).unwrap_err();

        assert!(
            err.to_string()
                .contains("timed out sending frame to agentd")
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_parent_watchdog_signal_reports_parent_exit_on_eof() {
        let (read_fd, write_fd) = super::create_pipe().unwrap();
        drop(write_fd);
        let mut reader = std::fs::File::from(read_fd);

        let signal = read_parent_watchdog_signal(&mut reader).unwrap();

        assert_eq!(signal, ParentWatchdogSignal::ParentExited);
    }

    #[test]
    #[cfg(unix)]
    fn test_parent_watchdog_signal_reports_detach_byte() {
        let (read_fd, write_fd) = super::create_pipe().unwrap();
        let mut writer = std::fs::File::from(write_fd);
        writer.write_all(&[PARENT_WATCH_DETACH]).unwrap();
        let mut reader = std::fs::File::from(read_fd);

        let signal = read_parent_watchdog_signal(&mut reader).unwrap();

        assert_eq!(signal, ParentWatchdogSignal::Detached);
    }

    #[test]
    fn test_validate_disk_format_rejects_unknown_values() {
        let err = validate_disk_format(Some("iso")).unwrap_err();
        assert!(err.to_string().contains("unknown disk image format"));
    }

    #[test]
    fn test_append_block_root_env_adds_default_device() {
        let mut env = vec!["FOO=bar".to_string()];
        append_block_root_env(&mut env);
        assert!(env.contains(&"FOO=bar".to_string()));
        assert!(env.contains(&format!(
            "{}=/dev/vda",
            microsandbox_protocol::ENV_BLOCK_ROOT
        )));
    }

    #[test]
    fn test_append_block_root_env_preserves_existing_value() {
        let existing = format!(
            "{}=/dev/vdb,fstype=xfs",
            microsandbox_protocol::ENV_BLOCK_ROOT
        );
        let mut env = vec![existing.clone()];
        append_block_root_env(&mut env);
        assert_eq!(env, vec![existing]);
    }

    #[test]
    fn test_prepend_scripts_path_updates_existing_path() {
        let mut env = vec!["PATH=/usr/bin:/bin".to_string()];
        prepend_scripts_path(&mut env);
        assert_eq!(env, vec!["PATH=/.msb/scripts:/usr/bin:/bin".to_string()]);
    }

    #[test]
    fn test_prepend_scripts_path_adds_default_path_when_missing() {
        let mut env = vec!["LANG=C.UTF-8".to_string()];
        prepend_scripts_path(&mut env);
        assert!(
            env.contains(
                &"PATH=/.msb/scripts:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
                    .to_string()
            )
        );
    }

    #[test]
    fn test_prepend_scripts_path_avoids_duplicates() {
        let mut env = vec!["PATH=/.msb/scripts:/usr/bin".to_string()];
        prepend_scripts_path(&mut env);
        assert_eq!(env, vec!["PATH=/.msb/scripts:/usr/bin".to_string()]);
    }
}

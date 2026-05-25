//! Sandbox process entry point and VM configuration.
//!
//! The [`enter()`] function starts background services (agent relay,
//! heartbeat, idle timeout), configures the VMM, and hands control to
//! `Vm::enter()` from msb_krun. It **never returns** — the VMM calls
//! `_exit()` on guest shutdown after running exit observers.

use std::io::Write;
use std::num::NonZero;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use microsandbox_db::DbWriteConnection;
use microsandbox_db::entity::run as run_entity;
use microsandbox_filesystem::{
    DynFileSystem, HostPermissions, PassthroughConfig, PassthroughFs, StatVirtualization,
};
use microsandbox_metrics::{ActivateSlot, MetricsRegistry, ReleaseMode};
use msb_krun::VmBuilder;
use sea_orm::{ColumnTrait, EntityTrait, Set};
use serde::Serialize;

use crate::console::{AgentConsoleBackend, ConsoleSharedState};
use crate::heartbeat::HeartbeatReader;
use crate::logging::LogLevel;
use crate::metrics::run_metrics_sampler;
use crate::relay::AgentRelay;
use crate::{RuntimeError, RuntimeResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Exit reason tags stored in the shared `AtomicU8`.
const EXIT_REASON_COMPLETED: u8 = 0;
const EXIT_REASON_IDLE_TIMEOUT: u8 = 1;
const EXIT_REASON_MAX_DURATION: u8 = 2;
const EXIT_REASON_SIGNAL: u8 = 3;

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

    /// Path to the Unix domain socket for the agent relay.
    pub agent_sock_path: PathBuf,

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
#[derive(Clone, Debug)]
pub struct MetricsSlotHandoff {
    /// Name of the POSIX shared-memory object holding the registry.
    pub shm_name: String,
    /// Reserved slot index.
    pub slot: u32,
    /// Generation paired with the reservation.
    pub generation: u64,
}

/// Specification for the writable upper layer attached as virtio-blk.
///
/// Today the upper is always a flat raw ext4 file, so `format = Raw`
/// and `backing` is empty. The shape is forward-compatible with
/// qcow2 backing chains: when chains land, `format = Qcow2` and
/// `backing` lists ancestor files that the VMM must also map. The
/// runtime walks `backing` and attaches each as a read-only disk.
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

    /// Number of virtual CPUs.
    pub vcpus: u8,

    /// Memory in MiB.
    pub memory_mib: u32,

    /// Root filesystem path for direct passthrough mounts.
    pub rootfs_path: Option<PathBuf>,

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

    /// Additional mounts as `tag:host_path[:ro]` strings.
    pub mounts: Vec<String>,

    /// Disk-image volume mounts attached as extra virtio-blk devices.
    pub disks: Vec<DiskMountSpec>,

    /// Pre-built filesystem backends as `(tag, backend)` pairs.
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

#[cfg(feature = "net")]
type NetworkTerminationHandle = microsandbox_network::network::TerminationHandle;

#[cfg(not(feature = "net"))]
type NetworkTerminationHandle = ();

#[cfg(feature = "net")]
type NetworkMetricsHandle = microsandbox_network::network::MetricsHandle;

#[cfg(not(feature = "net"))]
type NetworkMetricsHandle = ();

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl std::fmt::Debug for VmConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmConfig")
            .field("libkrunfw_path", &self.libkrunfw_path)
            .field("vcpus", &self.vcpus)
            .field("memory_mib", &self.memory_mib)
            .field("rootfs_path", &self.rootfs_path)
            .field("rootfs_vmdk", &self.rootfs_vmdk)
            .field("rootfs_upper", &self.rootfs_upper)
            .field("rootfs_upper_spec", &self.rootfs_upper_spec)
            .field("rootfs_disk", &self.rootfs_disk)
            .field("rootfs_disk_format", &self.rootfs_disk_format)
            .field("rootfs_disk_readonly", &self.rootfs_disk_readonly)
            .field("mounts", &self.mounts)
            .field("disks", &self.disks)
            .field("backends", &format!("[{} backend(s)]", self.backends.len()))
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
    let result = run(config);
    match result {
        Ok(infallible) => match infallible {},
        Err(e) => {
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
    // Write startup JSON and redirect output FIRST, before any tracing.
    // This ensures all tracing goes to runtime.log, not the terminal.
    let pid = std::process::id();
    let startup = StartupInfo { pid };
    let startup_json = serde_json::to_string(&startup)
        .map_err(|e| RuntimeError::Custom(format!("serialize startup: {e}")))?;

    write_startup_info(&startup_json)?;
    setup_log_capture(&config.log_dir, config.forward_output)?;

    tracing::info!(sandbox = %config.sandbox_name, "sandbox starting");

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
        release_metrics_slot(config.metrics_slot.as_ref(), ReleaseMode::Free);
    }

    // Build the VM with an exit observer for DB cleanup and socket removal.
    // The on_exit closure runs synchronously on the VMM thread before _exit().
    let rt_handle = tokio_rt.handle().clone();
    let exit_db = db.clone();
    let exit_sandbox_id = config.sandbox_id;
    let exit_run_id = run_db_id;
    let exit_reason_for_observer = Arc::clone(&exit_reason);
    let exit_sock_path = config.agent_sock_path.clone();
    let exit_log_writer = exec_log_writer.clone();
    // Capture the activated writer so the exit observer can release the slot
    // without re-opening the registry (saving two mmap syscalls and a
    // potential `wait_for_ready` round-trip on the VMM's exit path).
    let exit_metrics_writer = metrics_writer.clone();
    let (vm, _network_termination_handle, network_metrics_handle) = match build_vm(
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
                EXIT_REASON_MAX_DURATION => run_entity::TerminationReason::MaxDurationExceeded,
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
                    .col_expr(sandbox_entity::Column::UpdatedAt, Expr::value(now))
                    .filter(sandbox_entity::Column::Id.eq(exit_sandbox_id))
                    .exec(&exit_db)
                    .await;
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
    ) {
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
                release_metrics_slot(config.metrics_slot.as_ref(), ReleaseMode::Free);
            }
            return Err(e);
        }
    };
    let exit_handle = vm.exit_handle();

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

    match (config.metrics_sample_interval_ms, metrics_writer.clone()) {
        (None, _) => tracing::debug!(
            sandbox = %config.sandbox_name,
            "metrics sampling disabled; not spawning sampler"
        ),
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
        }
        (Some(interval_ms), Some(writer)) => {
            tracing::debug!(
                sandbox = %config.sandbox_name,
                interval_ms = interval_ms.get(),
                "starting metrics sampler"
            );
            tokio_rt.spawn(run_metrics_sampler(
                writer,
                config.sandbox_id,
                pid,
                interval_ms,
                network_metrics_handle
                    .map(|handle| Box::new(handle) as Box<dyn crate::metrics::NetworkMetrics>),
            ));
        }
    }

    // Spawn background tasks.
    let (_relay_shutdown_tx, relay_shutdown_rx) = tokio::sync::watch::channel(false);
    let (relay_drain_tx, mut relay_drain_rx) = tokio::sync::mpsc::channel::<()>(1);

    // Relay: spawn a blocking task for wait_ready, then run the accept loop.
    // wait_ready() must run AFTER enter() starts the VM (agentd sends core.ready),
    // so it runs on a background thread, not blocking the main thread.
    tokio_rt.spawn(async move {
        let ready_result =
            tokio::task::spawn_blocking(move || relay.wait_ready().map(|()| relay)).await;

        match ready_result {
            Ok(Ok(relay)) => {
                if let Err(e) = relay.run(relay_shutdown_rx, relay_drain_tx).await {
                    tracing::error!("agent relay error: {e}");
                }
            }
            Ok(Err(e)) => tracing::error!("agent relay wait_ready failed: {e}"),
            Err(e) => tracing::error!("agent relay wait_ready task panicked: {e}"),
        }
    });

    // Shutdown listener: when the relay forwards a `core.shutdown` frame to
    // agentd, we give the guest a window to flush block-backed roots and
    // power off cleanly. If the VM doesn't exit on its own within
    // `SHUTDOWN_FLUSH_TIMEOUT`, the host triggers exit as a fallback so a
    // wedged guest doesn't strand the VMM. The window's relationship to
    // agentd's internal `HANDOFF_POWEROFF_TIMEOUT` is enforced at compile
    // time in microsandbox-protocol.
    {
        let shutdown_exit_handle = exit_handle.clone();
        tokio_rt.spawn(async move {
            if relay_drain_rx.recv().await.is_some() {
                tracing::info!(
                    "core.shutdown forwarded to agentd, allowing flush window before host fallback"
                );
                tokio::time::sleep(microsandbox_protocol::SHUTDOWN_FLUSH_TIMEOUT).await;
                tracing::info!("flush window elapsed, triggering host exit");
                shutdown_exit_handle.trigger();
            }
        });
    }

    // Heartbeat/idle timeout monitor.
    if let Some(idle_secs) = config.idle_timeout_secs {
        let heartbeat_reader = HeartbeatReader::new(&config.runtime_dir);
        let idle_exit_handle = exit_handle.clone();
        let idle_reason = Arc::clone(&exit_reason);
        tokio_rt.spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                if heartbeat_reader.is_idle(idle_secs) {
                    tracing::info!("sandbox idle for {idle_secs}s, triggering exit");
                    idle_reason.store(
                        EXIT_REASON_IDLE_TIMEOUT,
                        std::sync::atomic::Ordering::SeqCst,
                    );
                    idle_exit_handle.trigger();
                    break;
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
    vm.enter()
        .map_err(|e| RuntimeError::Custom(format!("VM enter: {e}")))
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
) -> RuntimeResult<(
    msb_krun::Vm,
    Option<NetworkTerminationHandle>,
    Option<NetworkMetricsHandle>,
)> {
    let mut exec_env = config.vm.env.clone();
    let vm = &config.vm;

    let mut builder = VmBuilder::new()
        .machine(|m| m.vcpus(vm.vcpus).memory_mib(vm.memory_mib as usize))
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
        let cfg = PassthroughConfig {
            root_dir: rootfs_path.clone(),
            ..Default::default()
        };
        let backend =
            PassthroughFs::new(cfg).map_err(|e| RuntimeError::Custom(format!("rootfs: {e}")))?;
        builder = builder.fs(move |fs| fs.tag("/dev/root").custom(Box::new(backend)));
    } else if let Some(ref vmdk_path) = vm.rootfs_vmdk {
        // EROFS fsmerge OCI rootfs: VMDK (read-only) + upper.ext4 (writable).
        let empty_trampoline = tempfile::tempdir()?;
        let cfg = PassthroughConfig {
            root_dir: empty_trampoline.path().to_path_buf(),
            ..Default::default()
        };
        let backend = PassthroughFs::new(cfg)
            .map_err(|e| RuntimeError::Custom(format!("trampoline rootfs: {e}")))?;
        builder = builder.fs(move |fs| fs.tag("/dev/root").custom(Box::new(backend)));

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
        let _ = empty_trampoline.keep();
    } else if let Some(ref disk_path) = vm.rootfs_disk {
        let empty_trampoline = tempfile::tempdir()?;
        let cfg = PassthroughConfig {
            root_dir: empty_trampoline.path().to_path_buf(),
            ..Default::default()
        };
        let backend = PassthroughFs::new(cfg)
            .map_err(|e| RuntimeError::Custom(format!("trampoline rootfs: {e}")))?;
        builder = builder.fs(move |fs| fs.tag("/dev/root").custom(Box::new(backend)));

        let format = validate_disk_format(vm.rootfs_disk_format.as_deref())
            .map_err(|e| RuntimeError::Custom(format!("disk format: {e}")))?;
        let disk_path = disk_path.clone();
        let readonly = vm.rootfs_disk_readonly;
        builder = builder.disk(move |d| d.path(&disk_path).format(format).read_only(readonly));
        append_block_root_env(&mut exec_env);

        let _ = empty_trampoline.keep();
    }

    // Runtime directory mount — agentd mounts this at /.msb for scripts
    // and heartbeat.
    {
        let runtime_tag = microsandbox_protocol::RUNTIME_FS_TAG.to_string();
        let cfg = PassthroughConfig {
            root_dir: config.runtime_dir.clone(),
            inject_init: false,
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
        let cfg = PassthroughConfig {
            root_dir: PathBuf::from(parsed.host_path),
            inject_init: false,
            stat_virtualization: parsed.stat_virtualization,
            host_permissions: parsed.host_permissions,
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

    // Network.
    #[cfg(feature = "net")]
    if vm.network.enabled {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let mut network =
            microsandbox_network::network::SmoltcpNetwork::new(vm.network.clone(), vm.sandbox_slot);
        network_termination_handle = Some(network.termination_handle());
        network_metrics_handle = Some(network.metrics_handle());

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
    // implicit console output routed to kernel.log for kernel/init logs.
    // NOTE: The implicit console must remain enabled (do not call
    // `disable_implicit()`) because disk image rootfs boots depend on it.
    let kernel_log_path = config.log_dir.join("kernel.log");
    builder = builder.console(|c| {
        c.output(&kernel_log_path).custom(
            microsandbox_protocol::AGENT_PORT_NAME,
            Box::new(console_backend),
        )
    });

    // Exit observer — runs synchronously before _exit() for DB cleanup.
    builder = builder.on_exit(on_exit);

    let vm = builder
        .build()
        .map_err(|e| RuntimeError::Custom(format!("build VM: {e}")))?;

    Ok((vm, network_termination_handle, network_metrics_handle))
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

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

/// Best-effort release of a metrics slot. Used when activation has not yet
/// happened (e.g. build_vm failure) and the slot would otherwise leak.
fn release_metrics_slot(handoff: Option<&MetricsSlotHandoff>, mode: ReleaseMode) {
    let Some(handoff) = handoff else { return };
    if let Ok(reg) = MetricsRegistry::open(&handoff.shm_name) {
        let _ = reg.release(handoff.slot, handoff.generation, mode);
    }
}

/// Set up host log capture.
///
/// Redirects stderr through a pipe so a background thread can write to a
/// rotating log file (`runtime.log`). Stdout is redirected to `/dev/null`
/// because kernel console output is routed to `kernel.log` directly via
/// `console_output` in the VM builder.
///
/// If `forward` is true, stderr is also tee'd to the original fd.
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

/// Write startup info JSON to stdout.
fn write_startup_info(json: &str) -> RuntimeResult<()> {
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

/// Create a pipe pair, returning `(read_end, write_end)` as `OwnedFd`.
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
/// Wire format: `tag:host_path[:ro][,stat-virt=strict|relaxed|off][,host-perms=private|mirror]`.
/// Defaults: `stat-virt=strict`, `host-perms=private`. The `:ro` segment is
/// kept for protocol compatibility but only used by agentd, not the host fs.
#[derive(Debug)]
struct ParsedMountSpec {
    tag: String,
    host_path: String,
    stat_virtualization: StatVirtualization,
    host_permissions: HostPermissions,
}

/// Parse a `--mount` spec into [`ParsedMountSpec`].
///
/// Wire grammar: `tag:host_path[:ro][,key=value]*`. The host path may contain
/// commas — the comma-option suffix is identified relative to the trailing
/// `:ro` (if present) or, when absent, by the first `,` after the host path.
///
/// To make this unambiguous we split on the first `:` (tag/host boundary) and
/// then peel the option suffix off the right side rather than splitting the
/// whole spec on `,` first.
fn parse_mount_spec(spec: &str) -> Result<ParsedMountSpec, String> {
    let (tag, rest) = spec
        .split_once(':')
        .ok_or_else(|| format!("expected tag:host_path[:ro][,opts] shape, got {spec:?}"))?;
    if tag.is_empty() {
        return Err(format!("empty tag in mount spec {spec:?}"));
    }

    // Peel the trailing options block. Strategy:
    //   1) If `:ro` is present in the spec (only ever after host_path), the
    //      options block starts at the first `,` *after* the `:ro` token.
    //   2) Otherwise the options block starts at the first `,` after the
    //      first `:` that follows the host path. We accept that paths
    //      containing both `:` and `,` outside this contract may be
    //      misparsed — the producer side never emits such paths.
    let (host_path_with_ro, options) = split_path_and_options(rest);

    let (host_path, _readonly) = match host_path_with_ro.strip_suffix(":ro") {
        Some(p) => (p, true),
        None => (host_path_with_ro, false),
    };

    if host_path.is_empty() {
        return Err(format!("empty host path in mount spec {spec:?}"));
    }

    let mut stat_virtualization = StatVirtualization::Strict;
    let mut host_permissions = HostPermissions::Private;
    let mut seen_stat_virt = false;
    let mut seen_host_perms = false;

    if let Some(opts) = options {
        for opt in opts.split(',') {
            let opt = opt.trim();
            if opt.is_empty() {
                continue;
            }
            let (key, value) = opt
                .split_once('=')
                .ok_or_else(|| format!("expected key=value option, got {opt:?}"))?;
            match key {
                "stat-virt" => {
                    if seen_stat_virt {
                        return Err("mount option `stat-virt` specified more than once".to_string());
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
                        return Err(
                            "mount option `host-perms` specified more than once".to_string()
                        );
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
                other => return Err(format!("unknown mount option {other:?}")),
            }
        }
    }

    Ok(ParsedMountSpec {
        tag: tag.to_string(),
        host_path: host_path.to_string(),
        stat_virtualization,
        host_permissions,
    })
}

/// Split `rest = "host_path[:ro][,opts]"` into `(host_path_with_ro, opts)`.
///
/// The split point is the first `,` that follows either `:ro` (if present) or
/// the entire `rest` (if no `,` exists). Producer-side encoding never embeds
/// `,` in host paths, so the first comma after `:ro` (or anywhere, if no
/// `:ro`) is always the options separator.
fn split_path_and_options(rest: &str) -> (&str, Option<&str>) {
    // If we have ":ro" anywhere, the option block is the first comma after the
    // ":ro" position. Otherwise, the option block is the first comma anywhere.
    let comma_start = if let Some(ro_idx) = rest.find(":ro") {
        let after_ro = ro_idx + ":ro".len();
        rest[after_ro..].find(',').map(|i| after_ro + i)
    } else {
        rest.find(',')
    };

    match comma_start {
        Some(i) => (&rest[..i], Some(&rest[i + 1..])),
        None => (rest, None),
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
    use super::{
        HostPermissions, StatVirtualization, append_block_root_env, parse_mount_spec,
        prepend_scripts_path, validate_disk_format,
    };

    #[test]
    fn test_parse_mount_spec_minimal() {
        let p = parse_mount_spec("foo:/host/data").unwrap();
        assert_eq!(p.tag, "foo");
        assert_eq!(p.host_path, "/host/data");
        assert!(matches!(p.stat_virtualization, StatVirtualization::Strict));
        assert!(matches!(p.host_permissions, HostPermissions::Private));
    }

    #[test]
    fn test_parse_mount_spec_with_ro_and_policies() {
        let p = parse_mount_spec("foo:/host/data:ro,stat-virt=relaxed,host-perms=mirror").unwrap();
        assert_eq!(p.host_path, "/host/data");
        assert!(matches!(p.stat_virtualization, StatVirtualization::Relaxed));
        assert!(matches!(p.host_permissions, HostPermissions::Mirror));
    }

    #[test]
    fn test_parse_mount_spec_stat_virt_off() {
        let p = parse_mount_spec("foo:/host/data,stat-virt=off").unwrap();
        assert!(matches!(p.stat_virtualization, StatVirtualization::Off));
    }

    #[test]
    fn test_parse_mount_spec_rejects_unknown_key() {
        let err = parse_mount_spec("foo:/host/data,bogus=1").unwrap_err();
        assert!(err.contains("unknown mount option"), "got: {err}");
    }

    #[test]
    fn test_parse_mount_spec_rejects_invalid_stat_virt() {
        let err = parse_mount_spec("foo:/host/data,stat-virt=nope").unwrap_err();
        assert!(err.contains("invalid stat-virt"), "got: {err}");
    }

    #[test]
    fn test_parse_mount_spec_rejects_invalid_host_perms() {
        let err = parse_mount_spec("foo:/host/data,host-perms=public").unwrap_err();
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
    fn test_parse_mount_spec_with_ro_anchors_options_block() {
        // The SDK rejects commas in host paths, so the producer can guarantee
        // commas in the wire format are always option separators. But the
        // `:ro`-anchored split is still load-bearing: it ensures the option
        // block starts after the `:ro` token even if a future relaxation of
        // the path rules ever lets `,` slip through, the option scanner
        // operates on the correct slice.
        let p = parse_mount_spec("foo:/host/data:ro,stat-virt=relaxed").unwrap();
        assert_eq!(p.host_path, "/host/data");
        assert!(matches!(p.stat_virtualization, StatVirtualization::Relaxed));
    }

    #[test]
    fn test_parse_mount_spec_rejects_duplicate_stat_virt() {
        let err = parse_mount_spec("foo:/host,stat-virt=strict,stat-virt=off").unwrap_err();
        assert!(err.contains("more than once"), "got: {err}");
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

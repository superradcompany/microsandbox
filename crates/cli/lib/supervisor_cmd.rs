//! Handler for the `msb supervisor` subcommand.
//!
//! Parses CLI arguments, builds a `SupervisorConfig`, and delegates to
//! `microsandbox_runtime::supervisor::run()`.

use std::path::PathBuf;

use clap::Args;
use microsandbox_runtime::{
    RuntimeResult,
    logging::LogLevel,
    policy::{ChildPolicies, ChildPolicy, ExitAction, ShutdownMode, SupervisorPolicy},
    supervisor::SupervisorConfig,
    vm::VmConfig,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Arguments for the `msb supervisor` subcommand.
#[derive(Debug, Args)]
pub struct SupervisorArgs {
    /// Name of the sandbox.
    #[arg(long = "name")]
    pub sandbox_name: String,

    /// Database ID of the sandbox.
    #[arg(long = "sandbox-id")]
    pub sandbox_id: i32,

    /// Path to the sandbox database file.
    #[arg(long = "db-path")]
    pub sandbox_db_path: PathBuf,

    /// Directory for log files.
    #[arg(long)]
    pub log_dir: PathBuf,

    /// Runtime directory (scripts, heartbeat).
    #[arg(long)]
    pub runtime_dir: PathBuf,

    /// Path to the Unix domain socket for the agent relay.
    #[arg(long)]
    pub agent_sock: PathBuf,

    /// Forward VM console output to supervisor stdout.
    #[arg(long = "forward")]
    pub forward_output: bool,

    // ── Supervisor policy ────────────────────────────────────────────────
    /// Shutdown mode: graceful, terminate, or kill.
    #[arg(long, default_value = "graceful")]
    pub shutdown_mode: ShutdownMode,

    /// Grace period in seconds between drain escalation steps.
    #[arg(long, default_value_t = 3)]
    pub grace_secs: u64,

    /// Hard cap on total sandbox lifetime in seconds.
    #[arg(long)]
    pub max_duration: Option<u64>,

    /// Idle timeout in seconds.
    #[arg(long)]
    pub idle_timeout: Option<u64>,

    // ── VM child policy ──────────────────────────────────────────────────
    /// VM exit action: shutdown-all, restart, or ignore.
    #[arg(long, default_value = "shutdown-all")]
    pub vm_on_exit: ExitAction,

    /// Max VM restart attempts before falling back to shutdown-all.
    #[arg(long, default_value_t = 0)]
    pub vm_max_restarts: u32,

    /// Delay in milliseconds between VM restart attempts.
    #[arg(long, default_value_t = 0)]
    pub vm_restart_delay_ms: u64,

    /// Window in seconds for counting VM restart attempts.
    #[arg(long, default_value_t = 0)]
    pub vm_restart_window: u64,

    /// Grace period in milliseconds before SIGKILL on VM shutdown.
    #[arg(long, default_value_t = 0)]
    pub vm_shutdown_timeout_ms: u64,

    // ── VM passthrough args ──────────────────────────────────────────────
    /// Path to the libkrunfw shared library.
    #[arg(long)]
    pub libkrunfw_path: PathBuf,

    /// Number of virtual CPUs.
    #[arg(long, default_value_t = 1)]
    pub vcpus: u8,

    /// Memory in MiB.
    #[arg(long, default_value_t = 512)]
    pub memory_mib: u32,

    /// Root filesystem path for direct passthrough mounts.
    #[arg(long)]
    pub rootfs_path: Option<PathBuf>,

    /// Root filesystem lower layer paths for OverlayFs (repeatable).
    #[arg(long)]
    pub rootfs_lower: Vec<PathBuf>,

    /// Writable upper layer directory for OverlayFs rootfs.
    #[arg(long)]
    pub rootfs_upper: Option<PathBuf>,

    /// Staging directory for OverlayFs rootfs.
    #[arg(long)]
    pub rootfs_staging: Option<PathBuf>,

    /// Disk image file path for virtio-blk rootfs.
    #[arg(long)]
    pub rootfs_disk: Option<PathBuf>,

    /// Disk image format (qcow2, raw, vmdk).
    #[arg(long)]
    pub rootfs_disk_format: Option<String>,

    /// Mount disk image as read-only.
    #[arg(long)]
    pub rootfs_disk_readonly: bool,

    /// Additional mounts as `tag:host_path` (repeatable).
    #[arg(long)]
    pub mount: Vec<String>,

    /// Path to the init binary in the guest.
    #[arg(long)]
    pub init_path: Option<PathBuf>,

    /// Environment variables as `KEY=VALUE` (repeatable).
    #[arg(long)]
    pub env: Vec<String>,

    /// Working directory inside the guest.
    #[arg(long)]
    pub workdir: Option<PathBuf>,

    /// Path to the executable to run in the guest.
    #[arg(long)]
    pub exec_path: Option<PathBuf>,

    /// Network configuration as JSON.
    #[cfg(feature = "net")]
    #[arg(long)]
    pub network_config: Option<String>,

    /// Sandbox slot for deterministic network address derivation.
    #[cfg(feature = "net")]
    #[arg(long, default_value_t = 0)]
    pub sandbox_slot: u64,

    /// Arguments to pass to the executable.
    #[arg(last = true)]
    pub exec_args: Vec<String>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Run the supervisor with the given CLI arguments.
pub async fn run(args: SupervisorArgs, log_level: Option<LogLevel>) -> RuntimeResult<()> {
    let child_policies = ChildPolicies {
        vm: ChildPolicy {
            on_exit: args.vm_on_exit,
            max_restarts: args.vm_max_restarts,
            restart_delay_ms: args.vm_restart_delay_ms,
            restart_window_secs: args.vm_restart_window,
            shutdown_timeout_ms: args.vm_shutdown_timeout_ms,
        },
    };

    let supervisor_policy = SupervisorPolicy {
        shutdown_mode: args.shutdown_mode,
        grace_secs: args.grace_secs,
        max_duration_secs: args.max_duration,
        idle_timeout_secs: args.idle_timeout,
    };

    let vm_config = VmConfig {
        libkrunfw_path: args.libkrunfw_path,
        vcpus: args.vcpus,
        memory_mib: args.memory_mib,
        rootfs_path: args.rootfs_path,
        rootfs_lowers: args.rootfs_lower,
        rootfs_upper: args.rootfs_upper,
        rootfs_staging: args.rootfs_staging,
        rootfs_disk: args.rootfs_disk,
        rootfs_disk_format: args.rootfs_disk_format,
        rootfs_disk_readonly: args.rootfs_disk_readonly,
        mounts: args.mount,
        backends: vec![],
        init_path: args.init_path,
        env: args.env,
        workdir: args.workdir,
        exec_path: args.exec_path,
        exec_args: args.exec_args,
        #[cfg(feature = "net")]
        network: args
            .network_config
            .as_deref()
            .map(|json| {
                serde_json::from_str::<microsandbox_network::config::NetworkConfig>(json)
                    .expect("invalid network config JSON")
            })
            .unwrap_or_default(),
        #[cfg(feature = "net")]
        sandbox_slot: args.sandbox_slot,
        agent_fd: None,
    };

    let config = SupervisorConfig {
        sandbox_name: args.sandbox_name,
        sandbox_id: args.sandbox_id,
        log_level,
        sandbox_db_path: args.sandbox_db_path,
        log_dir: args.log_dir,
        runtime_dir: args.runtime_dir,
        agent_sock_path: args.agent_sock,
        sandbox_slot: u32::try_from(args.sandbox_id).map_err(|_| {
            microsandbox_runtime::RuntimeError::Custom(format!(
                "sandbox_id {} is negative and cannot be used as a network slot",
                args.sandbox_id
            ))
        })?,
        forward_output: args.forward_output,
        child_policies,
        supervisor_policy,
        vm_config,
    };

    microsandbox_runtime::supervisor::run(config).await
}

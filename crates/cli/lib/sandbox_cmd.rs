//! Handler for the `msb sandbox` subcommand.
//!
//! Parses CLI arguments, builds a [`microsandbox_runtime::vm::Config`], and delegates to
//! [`microsandbox_runtime::vm::enter()`]. This command **never returns**
//! — the VMM calls `_exit()` on guest shutdown.

use std::path::PathBuf;

use clap::Args;
use microsandbox_runtime::{
    logging::LogLevel,
    vm::{Config, VmConfig},
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Arguments for the `msb sandbox` subcommand.
#[derive(Debug, Args)]
pub struct SandboxArgs {
    /// Name of the sandbox.
    #[arg(long = "name")]
    pub sandbox_name: String,

    /// Database ID of the sandbox.
    #[arg(long = "sandbox-id")]
    pub sandbox_id: i32,

    /// Path to the sandbox database file.
    #[arg(long = "db-path")]
    pub sandbox_db_path: PathBuf,

    /// Timeout when acquiring a sandbox database connection from the pool.
    #[arg(long = "db-connect-timeout-secs", default_value_t = 30)]
    pub sandbox_db_connect_timeout_secs: u64,

    /// Directory for log files.
    #[arg(long)]
    pub log_dir: PathBuf,

    /// Runtime directory (scripts, heartbeat).
    #[arg(long)]
    pub runtime_dir: PathBuf,

    /// Path to the Unix domain socket for the agent relay.
    #[arg(long)]
    pub agent_sock: PathBuf,

    /// Forward VM console output to stdout.
    #[arg(long = "forward")]
    pub forward_output: bool,

    /// Hard cap on total sandbox lifetime in seconds.
    #[arg(long)]
    pub max_duration: Option<u64>,

    /// Idle timeout in seconds.
    #[arg(long)]
    pub idle_timeout: Option<u64>,

    // ── VM configuration ─────────────────────────────────────────────────
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

    /// Disk image file path for virtio-blk rootfs.
    #[arg(long)]
    pub rootfs_disk: Option<PathBuf>,

    /// Disk image format (qcow2, raw, vmdk).
    #[arg(long)]
    pub rootfs_disk_format: Option<String>,

    /// Mount disk image as read-only.
    #[arg(long)]
    pub rootfs_disk_readonly: bool,

    /// Block device files for EROFS OCI rootfs (repeatable, order matters).
    #[arg(long = "rootfs-blk")]
    pub rootfs_disks: Vec<PathBuf>,

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

/// Run the sandbox process. This function **never returns**.
pub fn run(args: SandboxArgs, log_level: Option<LogLevel>) -> ! {
    let vm_config = VmConfig {
        libkrunfw_path: args.libkrunfw_path,
        vcpus: args.vcpus,
        memory_mib: args.memory_mib,
        rootfs_path: args.rootfs_path,
        rootfs_disk: args.rootfs_disk,
        rootfs_disk_format: args.rootfs_disk_format,
        rootfs_disk_readonly: args.rootfs_disk_readonly,
        rootfs_disks: args.rootfs_disks,
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
    };

    let config = Config {
        sandbox_name: args.sandbox_name,
        sandbox_id: args.sandbox_id,
        log_level,
        sandbox_db_path: args.sandbox_db_path,
        sandbox_db_connect_timeout_secs: args.sandbox_db_connect_timeout_secs,
        log_dir: args.log_dir,
        runtime_dir: args.runtime_dir,
        agent_sock_path: args.agent_sock,
        forward_output: args.forward_output,
        idle_timeout_secs: args.idle_timeout,
        max_duration_secs: args.max_duration,
        vm: vm_config,
    };

    microsandbox_runtime::vm::enter(config)
}

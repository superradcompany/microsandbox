//! Handler for the hidden `msb microvm` subcommand.
//!
//! Parses CLI arguments, builds a `VmConfig`, and delegates to
//! `microsandbox_runtime::vm::enter()`. This function never returns.

use std::{os::fd::RawFd, path::PathBuf};

use clap::Args;
use microsandbox_runtime::{RuntimeResult, vm::VmConfig};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Arguments for the hidden `msb microvm` subcommand.
#[derive(Debug, Args)]
pub struct MicrovmArgs {
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

    /// Additional mounts as `tag:host_path[:ro]` (repeatable).
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

    /// Socket pair FD for RelayNetBackend (msbnet communication).
    #[arg(long)]
    pub net_fd: Option<RawFd>,

    /// Agent FD for virtio-console (agentd communication).
    #[arg(long)]
    pub agent_fd: Option<RawFd>,

    /// Arguments to pass to the executable.
    #[arg(last = true)]
    pub exec_args: Vec<String>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Run the microVM with the given CLI arguments.
///
/// This function calls `vm::enter()` which never returns.
pub fn run(args: MicrovmArgs) -> RuntimeResult<()> {
    let config = VmConfig {
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
        net_fd: args.net_fd,
        agent_fd: args.agent_fd,
    };

    microsandbox_runtime::vm::enter(config)
    // enter() is -> !, so this line is unreachable
}

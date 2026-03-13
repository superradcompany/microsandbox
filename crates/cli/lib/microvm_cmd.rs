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

    /// Root filesystem layer paths (repeatable).
    #[arg(long)]
    pub rootfs_layer: Vec<PathBuf>,

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
        rootfs_layers: args.rootfs_layer,
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

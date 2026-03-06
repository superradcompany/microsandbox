//! Handler for the hidden `msb supervisor` subcommand.
//!
//! Parses CLI arguments, decodes base64-encoded JSON policies, builds a
//! `SupervisorConfig`, and delegates to `microsandbox_runtime::supervisor::run()`.

use std::os::fd::RawFd;
use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use clap::Args;
use microsandbox_runtime::RuntimeResult;
use microsandbox_runtime::policy::{ChildPolicies, SupervisorPolicy};
use microsandbox_runtime::supervisor::SupervisorConfig;
use microsandbox_runtime::vm::VmConfig;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Arguments for the hidden `msb supervisor` subcommand.
#[derive(Debug, Args)]
pub struct SupervisorArgs {
    /// Name of the sandbox.
    #[arg(long)]
    pub sandbox_name: String,

    /// Path to the sandbox database file.
    #[arg(long)]
    pub sandbox_db_path: PathBuf,

    /// Directory for log files.
    #[arg(long)]
    pub log_dir: PathBuf,

    /// Runtime directory (scripts, heartbeat).
    #[arg(long)]
    pub runtime_dir: PathBuf,

    /// Agent FD (inherited from parent, for VM's virtio-console).
    #[arg(long)]
    pub agent_fd: RawFd,

    /// Forward VM console output to supervisor stdout.
    #[arg(long, default_value_t = false)]
    pub forward_output: bool,

    /// Child policies as base64-encoded JSON.
    #[arg(long, default_value = "")]
    pub child_policies: String,

    /// Supervisor policy as base64-encoded JSON.
    #[arg(long, default_value = "")]
    pub supervisor_policy: String,

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

    /// Arguments to pass to the executable.
    #[arg(last = true)]
    pub exec_args: Vec<String>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Run the supervisor with the given CLI arguments.
pub async fn run(args: SupervisorArgs) -> RuntimeResult<()> {
    let child_policies = decode_or_default::<ChildPolicies>(&args.child_policies)?;
    let supervisor_policy = decode_or_default::<SupervisorPolicy>(&args.supervisor_policy)?;

    let vm_config = VmConfig {
        libkrunfw_path: args.libkrunfw_path,
        vcpus: args.vcpus,
        memory_mib: args.memory_mib,
        rootfs_layers: args.rootfs_layer,
        mounts: args.mount,
        init_path: args.init_path,
        env: args.env,
        workdir: args.workdir,
        exec_path: args.exec_path,
        exec_args: args.exec_args,
        net_fd: None,
        agent_fd: Some(args.agent_fd),
    };

    let config = SupervisorConfig {
        sandbox_name: args.sandbox_name,
        sandbox_db_path: args.sandbox_db_path,
        log_dir: args.log_dir,
        runtime_dir: args.runtime_dir,
        agent_fd: args.agent_fd,
        forward_output: args.forward_output,
        child_policies,
        supervisor_policy,
        vm_config,
    };

    microsandbox_runtime::supervisor::run(config).await
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Decode a base64-encoded JSON string, or return Default if empty.
fn decode_or_default<T: serde::de::DeserializeOwned + Default>(
    input: &str,
) -> RuntimeResult<T> {
    if input.is_empty() {
        return Ok(T::default());
    }

    let bytes = BASE64
        .decode(input)
        .map_err(|e| microsandbox_runtime::RuntimeError::Custom(format!("base64 decode error: {e}")))?;

    let value = serde_json::from_slice(&bytes)?;
    Ok(value)
}

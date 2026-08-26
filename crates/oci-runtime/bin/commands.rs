//! OCI lifecycle command definitions.

use std::path::PathBuf;

use clap::{Args, Subcommand};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// OCI lifecycle commands.
#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Create a container environment from an OCI bundle.
    Create(CreateCommand),

    /// Start the configured OCI init process.
    Start(ContainerIdCommand),

    /// Create and start a container in one command.
    Run(RunCommand),

    /// Execute an additional process in a running container.
    Exec(Box<ExecCommand>),

    /// Send a signal to a container.
    Kill(KillCommand),

    /// Delete container state.
    Delete(DeleteCommand),

    /// Print OCI state JSON.
    State(ContainerIdCommand),

    /// Pause a running container.
    Pause(ContainerIdCommand),

    /// Resume a paused container.
    Resume(ContainerIdCommand),

    /// Print runtime feature metadata.
    Features,

    /// Run the host-side proxy for one detached OCI exec process.
    #[command(name = "__exec-supervisor", hide = true)]
    ExecSupervisor(ExecSupervisorCommand),
}

/// Arguments for `create`.
#[derive(Debug, Args)]
pub(crate) struct CreateCommand {
    /// Options shared by `create` and `run`.
    #[command(flatten)]
    pub(crate) options: CreateRunOptions,

    /// OCI container ID.
    pub(crate) id: String,
}

/// Arguments for `run`.
#[derive(Debug, Args)]
pub(crate) struct RunCommand {
    /// Options shared by `create` and `run`.
    #[command(flatten)]
    pub(crate) options: CreateRunOptions,

    /// OCI container ID.
    pub(crate) id: String,
}

/// Options shared by `create` and `run`.
#[derive(Debug, Args)]
pub(crate) struct CreateRunOptions {
    /// Path to the OCI bundle directory.
    #[arg(short = 'b', long, value_name = "DIR", default_value = ".")]
    pub(crate) bundle: PathBuf,

    /// Write the Microsandbox VMM host PID to this file.
    #[arg(long, value_name = "FILE")]
    pub(crate) pid_file: Option<PathBuf>,

    /// Console socket path supplied by Docker/containerd for TTY containers.
    #[arg(long, value_name = "SOCKET")]
    pub(crate) console_socket: Option<PathBuf>,

    /// Pidfd socket path supplied by newer runc callers.
    #[arg(long, value_name = "SOCKET")]
    pub(crate) pidfd_socket: Option<PathBuf>,

    /// Accept runc-compatible no-pivot flag.
    #[arg(long)]
    pub(crate) no_pivot: bool,

    /// Accept runc-compatible no-new-keyring flag.
    #[arg(long)]
    pub(crate) no_new_keyring: bool,

    /// Accept runc-compatible preserved file descriptor count.
    #[arg(long, value_name = "N", default_value_t = 0)]
    pub(crate) preserve_fds: u32,
}

/// Arguments for `exec`.
#[derive(Debug, Args)]
pub(crate) struct ExecCommand {
    /// Path to an OCI process JSON file.
    #[arg(short = 'p', long, value_name = "FILE")]
    pub(crate) process: Option<PathBuf>,

    /// Console socket path supplied by Docker/containerd for TTY exec.
    #[arg(long, value_name = "SOCKET")]
    pub(crate) console_socket: Option<PathBuf>,

    /// Pidfd socket path supplied by newer runc callers.
    #[arg(long, value_name = "SOCKET")]
    pub(crate) pidfd_socket: Option<PathBuf>,

    /// Working directory for command-style exec.
    #[arg(long, value_name = "DIR")]
    pub(crate) cwd: Option<PathBuf>,

    /// Environment entry for command-style exec.
    #[arg(short = 'e', long, value_name = "KEY=VALUE")]
    pub(crate) env: Vec<String>,

    /// Allocate a pseudo-TTY.
    #[arg(short = 't', long)]
    pub(crate) tty: bool,

    /// User for command-style exec.
    #[arg(short = 'u', long, value_name = "UID[:GID]")]
    pub(crate) user: Option<String>,

    /// Additional group IDs.
    #[arg(short = 'g', long, value_name = "GID")]
    pub(crate) additional_gids: Vec<String>,

    /// Detach from the exec process.
    #[arg(short = 'd', long)]
    pub(crate) detach: bool,

    /// Write the exec process PID to this file.
    #[arg(long, value_name = "FILE")]
    pub(crate) pid_file: Option<PathBuf>,

    /// SELinux process label.
    #[arg(long, value_name = "LABEL")]
    pub(crate) process_label: Option<String>,

    /// AppArmor profile.
    #[arg(long, value_name = "PROFILE")]
    pub(crate) apparmor: Option<String>,

    /// Set no-new-privileges for the exec process.
    #[arg(long)]
    pub(crate) no_new_privs: bool,

    /// Add a capability to the exec process.
    #[arg(short = 'c', long, value_name = "CAP")]
    pub(crate) cap: Vec<String>,

    /// Accept runc-compatible preserved file descriptor count.
    #[arg(long, value_name = "N", default_value_t = 0)]
    pub(crate) preserve_fds: u32,

    /// Run the process in a sub-cgroup.
    #[arg(long, value_name = "CGROUP")]
    pub(crate) cgroup: Option<String>,

    /// Allow exec in a paused container.
    #[arg(long)]
    pub(crate) ignore_paused: bool,

    /// OCI container ID.
    pub(crate) id: String,

    /// Command-style exec arguments.
    #[arg(trailing_var_arg = true)]
    pub(crate) command: Vec<String>,
}

/// Internal arguments used by the detached OCI exec supervisor.
#[derive(Debug, Args)]
pub(crate) struct ExecSupervisorCommand {
    /// Path to the OCI process JSON supplied by containerd.
    #[arg(long, value_name = "FILE")]
    pub(crate) process: PathBuf,

    /// Host PTY slave used to bridge a terminal exec session.
    #[arg(long, value_name = "PATH")]
    pub(crate) console: Option<PathBuf>,

    /// File where the supervisor publishes its host PID after guest startup.
    #[arg(long, value_name = "FILE")]
    pub(crate) pid_file: PathBuf,

    /// OCI container ID.
    pub(crate) id: String,
}

/// Arguments for commands that only need a container ID.
#[derive(Debug, Args)]
pub(crate) struct ContainerIdCommand {
    /// OCI container ID.
    pub(crate) id: String,
}

/// Arguments for `kill`.
#[derive(Debug, Args)]
pub(crate) struct KillCommand {
    /// Signal all processes in the container.
    #[arg(long)]
    pub(crate) all: bool,

    /// OCI container ID.
    pub(crate) id: String,

    /// Signal number or name.
    #[arg(default_value = "TERM")]
    pub(crate) signal: String,
}

/// Arguments for `delete`.
#[derive(Debug, Args)]
pub(crate) struct DeleteCommand {
    /// Force deletion by first killing the Microsandbox VM.
    #[arg(short = 'f', long)]
    pub(crate) force: bool,

    /// OCI container ID.
    pub(crate) id: String,
}

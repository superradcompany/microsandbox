//! Options accepted by OCI lifecycle operations.

use std::os::fd::OwnedFd;
use std::path::PathBuf;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Options for `create`.
#[derive(Debug)]
pub struct CreateOptions {
    /// OCI container ID.
    pub id: String,

    /// OCI bundle directory.
    pub bundle: PathBuf,

    /// Optional host PTY slave inherited by the Microsandbox VMM process.
    pub console: Option<OwnedFd>,
}

/// Options for `exec`.
#[derive(Debug, Clone)]
pub struct ExecOptions {
    /// OCI container ID.
    pub id: String,

    /// OCI process descriptor path.
    pub process: PathBuf,

    /// Optional pid-file path requested by Docker/containerd.
    pub pid_file: Option<PathBuf>,
}

/// Options for `kill`.
#[derive(Debug, Clone)]
pub struct KillOptions {
    /// OCI container ID.
    pub id: String,

    /// Signal number or name.
    pub signal: String,

    /// Whether to signal all processes.
    pub all: bool,
}

/// Options for `delete`.
#[derive(Debug, Clone)]
pub struct DeleteOptions {
    /// OCI container ID.
    pub id: String,

    /// Force removal even if OCI state is not stopped.
    pub force: bool,
}

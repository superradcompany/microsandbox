//! Error types for microsandbox.

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The result type for microsandbox operations.
pub type MicrosandboxResult<T> = Result<T, MicrosandboxError>;

/// Errors that can occur in microsandbox operations.
#[derive(Debug, thiserror::Error)]
pub enum MicrosandboxError {
    /// An I/O error occurred.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// An HTTP request error occurred.
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    /// The libkrunfw library was not found at the expected location.
    #[error("libkrunfw not found: {0}")]
    LibkrunfwNotFound(String),

    /// A database error occurred.
    #[error("database error: {0}")]
    Database(#[from] sea_orm::DbErr),

    /// Invalid configuration.
    #[error("invalid config: {0}")]
    InvalidConfig(String),

    /// The requested sandbox was not found.
    #[error("sandbox not found: {0}")]
    SandboxNotFound(String),

    /// The sandbox is still running and cannot be removed.
    #[error("sandbox still running: {0}")]
    SandboxStillRunning(String),

    /// A runtime error occurred.
    #[error("runtime error: {0}")]
    Runtime(String),

    /// The sandbox process exited before the agent relay became
    /// available. Carries the sandbox name and the structured
    /// `boot-error.json` record so the CLI can render a useful inline
    /// error with hints.
    #[error("failed to start {name:?}: {}", .err.message)]
    BootStart {
        /// The name of the sandbox that failed to start.
        name: String,
        /// Structured failure record loaded from `boot-error.json`.
        err: microsandbox_runtime::boot_error::BootError,
    },

    /// A JSON serialization/deserialization error occurred.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// A protocol error occurred.
    #[error("protocol error: {0}")]
    Protocol(#[from] microsandbox_protocol::ProtocolError),

    /// A nix/errno error occurred.
    #[error("nix error: {0}")]
    Nix(#[from] nix::errno::Errno),

    /// Command execution timed out.
    #[error("exec timed out after {0:?}")]
    ExecTimeout(std::time::Duration),

    /// A command failed to spawn (binary not found, permission
    /// denied, etc.). Distinct from a non-zero exit status: the
    /// user code never ran. The CLI renders this as a styled
    /// error block with hints; SDK consumers can branch on
    /// [`microsandbox_protocol::exec::ExecFailureKind`].
    #[error("exec failed: {}", .0.message)]
    ExecFailed(microsandbox_protocol::exec::ExecFailed),

    /// A terminal operation failed.
    #[error("terminal error: {0}")]
    Terminal(String),

    /// A filesystem operation failed inside the sandbox.
    #[error("sandbox fs error: {0}")]
    SandboxFs(String),

    /// The requested image was not found.
    #[error("image not found: {0}")]
    ImageNotFound(String),

    /// The image is in use by one or more sandboxes.
    #[error("image in use by sandbox(es): {0}")]
    ImageInUse(String),

    /// The requested volume was not found.
    #[error("volume not found: {0}")]
    VolumeNotFound(String),

    /// The volume already exists.
    #[error("volume already exists: {0}")]
    VolumeAlreadyExists(String),

    /// An OCI image operation failed.
    #[error("image error: {0}")]
    Image(#[from] microsandbox_image::ImageError),

    /// A network builder accumulated a parse / validation error.
    /// Surfaces from `NetworkBuilder::build()` (and its nested
    /// `DnsBuilder::build()`) when chained inside
    /// `SandboxBuilder::network(|n| ...)`.
    #[cfg(feature = "net")]
    #[error("network builder: {0}")]
    NetworkBuilder(#[from] microsandbox_network::policy::BuildError),

    /// A rootfs patch operation failed.
    #[error("patch failed: {0}")]
    PatchFailed(String),

    /// A snapshot artifact was not found.
    #[error("snapshot not found: {0}")]
    SnapshotNotFound(String),

    /// A snapshot artifact already exists at the given path.
    #[error("snapshot already exists: {0}")]
    SnapshotAlreadyExists(String),

    /// Snapshotting requires the source sandbox to be stopped.
    #[error("snapshot source sandbox '{0}' is not stopped")]
    SnapshotSandboxRunning(String),

    /// The image referenced by a snapshot is not in the local cache.
    #[error("snapshot image missing from cache: {0}")]
    SnapshotImageMissing(String),

    /// The snapshot artifact failed integrity verification.
    #[error("snapshot integrity check failed: {0}")]
    SnapshotIntegrity(String),

    /// A custom error message.
    #[error("{0}")]
    Custom(String),
}

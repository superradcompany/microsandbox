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

    /// A custom error message.
    #[error("{0}")]
    Custom(String),
}

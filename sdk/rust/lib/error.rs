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

    /// A cloud control-plane request failed with an HTTP status.
    #[error("cloud HTTP {status}: {message}")]
    CloudHttp {
        /// HTTP status code returned by msb-cloud.
        status: u16,
        /// Machine-readable msb-cloud error code, when present.
        code: Option<String>,
        /// Human-readable msb-cloud error message.
        message: String,
    },

    /// The libkrunfw library was not found at the expected location.
    #[error("libkrunfw not found: {0}")]
    LibkrunfwNotFound(String),

    /// A database error occurred.
    #[error("database error: {0}")]
    Database(#[from] sea_orm::DbErr),

    /// Invalid configuration.
    #[error("invalid config: {0}")]
    InvalidConfig(String),

    /// The sandbox's effective entrypoint and CMD do not provide an executable default command.
    #[error(
        "sandbox has no default command; configure an entrypoint or cmd, or execute a literal command"
    )]
    NoDefaultCommand,

    /// The requested sandbox was not found.
    #[error("sandbox not found: {0}")]
    SandboxNotFound(String),

    /// A sandbox with the given name already exists. Returned by
    /// `Sandbox::create` when the name is taken and `replace_existing`
    /// was not set, and by `Sandbox::create` with `replace_existing`
    /// when an in-process `Sandbox` handle for that name is still
    /// alive (the caller must drop or stop the existing handle first).
    #[error("sandbox already exists: {0}")]
    SandboxAlreadyExists(String),

    /// The sandbox is still running and cannot be removed.
    #[error("sandbox still running: {0}")]
    SandboxStillRunning(String),

    /// The sandbox exists but is not running.
    #[error("sandbox {0}")]
    SandboxNotRunning(String),

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

    /// An agent client error occurred.
    #[error("agent client error: {0}")]
    AgentClient(#[from] crate::agent::AgentClientError),

    /// A nix/errno error occurred.
    #[cfg(unix)]
    #[error("nix error: {0}")]
    Nix(#[from] nix::errno::Errno),

    /// A Windows host prerequisite is missing for local sandbox execution.
    #[cfg(windows)]
    #[error("{0}")]
    WindowsHostSetup(#[from] crate::setup::WindowsHostSetupError),

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
    SandboxFsOps(String),

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

    /// An adjacent-release snapshot artifact migration is blocked.
    #[error("snapshot artifact migration failed for {artifact} during {phase}: {code}: {detail}")]
    SnapshotMigration {
        /// Stable machine-readable failure code.
        code: String,
        /// Last safe durable phase.
        phase: String,
        /// Artifact name or explicitly supplied path.
        artifact: String,
        /// Bounded repair-oriented detail.
        detail: String,
    },

    /// Metrics sampling is disabled for this sandbox.
    #[error("metrics disabled for sandbox: {0}")]
    MetricsDisabled(String),

    /// Live metrics are enabled but no valid guest sample is available yet.
    #[error("metrics unavailable for sandbox: {0}")]
    MetricsUnavailable(String),

    /// A log stream fell behind enough that the file it was reading
    /// rotated out of the on-disk retention window. The stream
    /// yields this error and ends; restart from
    /// `LogStreamStart::Beginning`, `LogStreamStart::Since(now)`,
    /// or `LogStreamStart::From(c)` with the cursor of the last
    /// entry that was successfully consumed.
    #[error("log stream missed rotation (dropped from offset {dropped_from_offset})")]
    MissedRotation {
        /// Byte offset within the lost file at which streamed
        /// entries stop. Useful for diagnostics.
        dropped_from_offset: u64,
    },

    /// An opaque cursor passed to an SDK operation could not be decoded or no longer identifies a
    /// valid position. For log streams, this is yielded once at stream start before the stream ends.
    #[error("invalid cursor: {0}")]
    InvalidCursor(String),

    /// A backend does not support a requested SDK operation.
    #[error("{} is not supported by this backend: {}", .op.api_path(), .reason.hint())]
    Unsupported {
        /// Operation requested by the caller.
        op: Operation,
        /// Why the operation is unavailable, and what to do instead.
        reason: UnsupportedReason,
    },

    /// A custom error message.
    #[error("{0}")]
    Custom(String),
}

/// An SDK operation that a backend may decline to perform.
///
/// Carried by [`MicrosandboxError::Unsupported`] so callers can branch on
/// exactly which API was rejected instead of parsing a message string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Operation {
    /// `Sandbox::create`.
    SandboxCreate,
    /// `Sandbox::start`.
    SandboxStart,
    /// `Sandbox::stop`.
    SandboxStop,
    /// `Sandbox::remove`.
    SandboxRemove,
    /// `Sandbox::remove_persisted`.
    SandboxRemovePersisted,
    /// `Sandbox::kill`.
    SandboxKill,
    /// `Sandbox::drain`.
    SandboxDrain,
    /// `Sandbox::ping`.
    SandboxPing,
    /// `Sandbox::touch`.
    SandboxTouch,
    /// `Sandbox::stop_and_wait`.
    SandboxStopAndWait,
    /// `Sandbox::wait`.
    SandboxWait,
    /// `Sandbox::logs`.
    SandboxLogs,
    /// `Sandbox::log_stream`.
    SandboxLogStream,
    /// `Sandbox::log_stream` with `follow: false`.
    SandboxLogStreamNoFollow,
    /// `Sandbox::log_stream` with `follow: true`.
    SandboxLogStreamFollow,
    /// `Sandbox::logger`.
    SandboxLogger,
    /// `Sandbox::metrics`.
    SandboxMetrics,
    /// `Sandbox::metrics_stream`.
    SandboxMetricsStream,
    /// `Sandbox::modify`.
    SandboxModify,
    /// `Sandbox::fs`.
    SandboxFs,
    /// The free function `all_sandbox_metrics`.
    AllSandboxMetrics,
    /// Dialing a sandbox's agent (exec, attach, and guest-fs transport).
    AgentConnect,
    /// `SandboxHandle::config`.
    SandboxHandleConfig,
    /// `SandboxHandle::connect`.
    SandboxHandleConnect,
    /// `SandboxHandle::metrics`.
    SandboxHandleMetrics,
    /// `SandboxHandle::remove`.
    SandboxHandleRemove,
    /// `SandboxHandle::snapshot`.
    SandboxHandleSnapshot,
    /// `SandboxHandle::snapshot_to`.
    SandboxHandleSnapshotTo,
    /// `SandboxFsOps::open_file`.
    SandboxFsOpenFile,
    /// `SandboxFsOps::open_dir`.
    SandboxFsOpenDir,
    /// `SandboxFsOps::close_handle`.
    SandboxFsCloseHandle,
    /// `SandboxFsOps::read_handle`.
    SandboxFsReadHandle,
    /// `SandboxFsOps::read_handle_stream`.
    SandboxFsReadHandleStream,
    /// `SandboxFsOps::write_handle`.
    SandboxFsWriteHandle,
    /// `SandboxFsOps::write_handle_stream`.
    SandboxFsWriteHandleStream,
    /// `SandboxFsOps::read_dir_handle`.
    SandboxFsReadDirHandle,
    /// `SandboxFsOps::stat_handle`.
    SandboxFsStatHandle,
    /// `SandboxFsOps::set_stat_handle`.
    SandboxFsSetStatHandle,
    /// `SandboxSshOps::server`.
    SandboxSshServer,
    /// `SshServer::serve`.
    SshServerServe,
    /// `Volume::create`.
    VolumeCreate,
    /// `Volume::get`.
    VolumeGet,
    /// `Volume::get_default`.
    VolumeGetDefault,
    /// `Volume::list`.
    VolumeList,
    /// `Volume::remove`.
    VolumeRemove,
    /// `Volume::path`.
    VolumePath,
    /// `VolumeFs::read`.
    VolumeFsRead,
    /// `VolumeFs::read_to_string`.
    VolumeFsReadToString,
    /// `VolumeFs::write`.
    VolumeFsWrite,
    /// `VolumeFs::list`.
    VolumeFsList,
    /// `VolumeFs::stat`.
    VolumeFsStat,
    /// `VolumeFs::mkdir`.
    VolumeFsMkdir,
    /// `VolumeFs::remove`.
    VolumeFsRemove,
    /// `VolumeFs::copy`.
    VolumeFsCopy,
    /// `VolumeFs::rename`.
    VolumeFsRename,
    /// `VolumeFs::exists`.
    VolumeFsExists,
    /// `VolumeFs::read_stream`.
    VolumeFsReadStream,
    /// `VolumeFs::write_stream`.
    VolumeFsWriteStream,
    /// `Image::get`.
    ImageGet,
    /// `Image::list`.
    ImageList,
    /// `Image::inspect`.
    ImageInspect,
    /// `Image::remove`.
    ImageRemove,
    /// `Image::prune`.
    ImagePrune,
    /// `Image::load`.
    ImageLoad,
    /// `Image::save`.
    ImageSave,
    /// Snapshot operations (`Snapshot::*`).
    SnapshotOps,
    /// The free function `config` (ambient local-config accessor).
    Config,
}

/// Why a backend declined an [`Operation`].
///
/// Carried by [`MicrosandboxError::Unsupported`]; [`hint`](Self::hint)
/// renders it as a brief remedy for error messages.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnsupportedReason {
    /// Only local backends perform this operation.
    LocalOnly,
    /// Only cloud backends perform this operation.
    CloudOnly,
    /// Another operation covers this on the active backend.
    UseInstead(Operation),
    /// The operation needs a unix host.
    RequiresUnixHost,
    /// The operation needs a crate feature that is not enabled.
    RequiresCrateFeature(&'static str),
    /// The named configuration option is not accepted by this backend.
    ConfigField(&'static str),
    /// Volume contents are reached by mounting the volume into a sandbox.
    MountIntoSandbox,
    /// The operation is unavailable for the supplied state or format.
    NotAvailable(String),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Operation {
    /// The user-facing API path for this operation, e.g. `"Sandbox::kill"`.
    pub fn api_path(&self) -> &'static str {
        match self {
            Operation::SandboxCreate => "Sandbox::create",
            Operation::SandboxStart => "Sandbox::start",
            Operation::SandboxStop => "Sandbox::stop",
            Operation::SandboxRemove => "Sandbox::remove",
            Operation::SandboxRemovePersisted => "Sandbox::remove_persisted",
            Operation::SandboxKill => "Sandbox::kill",
            Operation::SandboxDrain => "Sandbox::drain",
            Operation::SandboxPing => "Sandbox::ping",
            Operation::SandboxTouch => "Sandbox::touch",
            Operation::SandboxStopAndWait => "Sandbox::stop_and_wait",
            Operation::SandboxWait => "Sandbox::wait",
            Operation::SandboxLogs => "Sandbox::logs",
            Operation::SandboxLogStream => "Sandbox::log_stream",
            Operation::SandboxLogStreamNoFollow => "Sandbox::log_stream(follow=false)",
            Operation::SandboxLogStreamFollow => "Sandbox::log_stream(follow=true)",
            Operation::SandboxLogger => "Sandbox::logger",
            Operation::SandboxMetrics => "Sandbox::metrics",
            Operation::SandboxMetricsStream => "Sandbox::metrics_stream",
            Operation::SandboxModify => "Sandbox::modify",
            Operation::SandboxFs => "Sandbox::fs",
            Operation::AllSandboxMetrics => "all_sandbox_metrics",
            Operation::AgentConnect => "agent connections",
            Operation::SandboxHandleConfig => "SandboxHandle::config",
            Operation::SandboxHandleConnect => "SandboxHandle::connect",
            Operation::SandboxHandleMetrics => "SandboxHandle::metrics",
            Operation::SandboxHandleRemove => "SandboxHandle::remove",
            Operation::SandboxHandleSnapshot => "SandboxHandle::snapshot",
            Operation::SandboxHandleSnapshotTo => "SandboxHandle::snapshot_to",
            Operation::SandboxFsOpenFile => "SandboxFsOps::open_file",
            Operation::SandboxFsOpenDir => "SandboxFsOps::open_dir",
            Operation::SandboxFsCloseHandle => "SandboxFsOps::close_handle",
            Operation::SandboxFsReadHandle => "SandboxFsOps::read_handle",
            Operation::SandboxFsReadHandleStream => "SandboxFsOps::read_handle_stream",
            Operation::SandboxFsWriteHandle => "SandboxFsOps::write_handle",
            Operation::SandboxFsWriteHandleStream => "SandboxFsOps::write_handle_stream",
            Operation::SandboxFsReadDirHandle => "SandboxFsOps::read_dir_handle",
            Operation::SandboxFsStatHandle => "SandboxFsOps::stat_handle",
            Operation::SandboxFsSetStatHandle => "SandboxFsOps::set_stat_handle",
            Operation::SandboxSshServer => "SandboxSshOps::server",
            Operation::SshServerServe => "SshServer::serve",
            Operation::VolumeCreate => "Volume::create",
            Operation::VolumeGet => "Volume::get",
            Operation::VolumeGetDefault => "Volume::get_default",
            Operation::VolumeList => "Volume::list",
            Operation::VolumeRemove => "Volume::remove",
            Operation::VolumePath => "Volume::path",
            Operation::VolumeFsRead => "VolumeFs::read",
            Operation::VolumeFsReadToString => "VolumeFs::read_to_string",
            Operation::VolumeFsWrite => "VolumeFs::write",
            Operation::VolumeFsList => "VolumeFs::list",
            Operation::VolumeFsStat => "VolumeFs::stat",
            Operation::VolumeFsMkdir => "VolumeFs::mkdir",
            Operation::VolumeFsRemove => "VolumeFs::remove",
            Operation::VolumeFsCopy => "VolumeFs::copy",
            Operation::VolumeFsRename => "VolumeFs::rename",
            Operation::VolumeFsExists => "VolumeFs::exists",
            Operation::VolumeFsReadStream => "VolumeFs::read_stream",
            Operation::VolumeFsWriteStream => "VolumeFs::write_stream",
            Operation::ImageGet => "Image::get",
            Operation::ImageList => "Image::list",
            Operation::ImageInspect => "Image::inspect",
            Operation::ImageRemove => "Image::remove",
            Operation::ImagePrune => "Image::prune",
            Operation::ImageLoad => "Image::load",
            Operation::ImageSave => "Image::save",
            Operation::SnapshotOps => "snapshot operations",
            Operation::Config => "config",
        }
    }
}

impl UnsupportedReason {
    /// Render this reason as a brief remedy hint for error messages.
    pub fn hint(&self) -> String {
        match self {
            UnsupportedReason::LocalOnly => "use a local backend".to_string(),
            UnsupportedReason::CloudOnly => "use a cloud backend".to_string(),
            UnsupportedReason::UseInstead(op) => format!("use {}", op.api_path()),
            UnsupportedReason::RequiresUnixHost => "unix hosts only".to_string(),
            UnsupportedReason::RequiresCrateFeature(feature) => {
                format!("enable the {feature} feature")
            }
            UnsupportedReason::ConfigField(field) => {
                format!("the {field} option is not accepted here")
            }
            UnsupportedReason::MountIntoSandbox => "mount the volume into a sandbox".to_string(),
            UnsupportedReason::NotAvailable(reason) => reason.clone(),
        }
    }
}

impl MicrosandboxError {
    /// Build an [`Unsupported`](Self::Unsupported) error for an operation the
    /// active backend cannot honor.
    pub fn unsupported(op: Operation, reason: UnsupportedReason) -> MicrosandboxError {
        MicrosandboxError::Unsupported { op, reason }
    }

    /// [`Unsupported`](Self::Unsupported) for operations only a local backend honors.
    pub fn local_only(op: Operation) -> MicrosandboxError {
        Self::unsupported(op, UnsupportedReason::LocalOnly)
    }

    /// [`Unsupported`](Self::Unsupported) for operations only a cloud backend honors.
    pub fn cloud_only(op: Operation) -> MicrosandboxError {
        Self::unsupported(op, UnsupportedReason::CloudOnly)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl From<microsandbox_types::TypesError> for MicrosandboxError {
    fn from(value: microsandbox_types::TypesError) -> Self {
        match value {
            microsandbox_types::TypesError::InvalidConfig(message) => Self::InvalidConfig(message),
        }
    }
}

impl From<microsandbox_types::CommandResolutionError> for MicrosandboxError {
    fn from(value: microsandbox_types::CommandResolutionError) -> Self {
        match value {
            microsandbox_types::CommandResolutionError::NoDefaultCommand => Self::NoDefaultCommand,
            error => Self::InvalidConfig(error.to_string()),
        }
    }
}

impl microsandbox_db::retry::IsSqliteBusy for MicrosandboxError {
    fn is_sqlite_busy(&self) -> bool {
        matches!(self, MicrosandboxError::Database(db_err) if microsandbox_db::retry::is_sqlite_busy(db_err))
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_renders_operation_and_reason() {
        let err = MicrosandboxError::unsupported(
            Operation::SandboxKill,
            UnsupportedReason::UseInstead(Operation::SandboxStop),
        );
        assert_eq!(
            err.to_string(),
            "Sandbox::kill is not supported by this backend: use Sandbox::stop"
        );

        let err = MicrosandboxError::local_only(Operation::ImagePrune);
        assert_eq!(
            err.to_string(),
            "Image::prune is not supported by this backend: use a local backend"
        );

        let err = MicrosandboxError::unsupported(
            Operation::SandboxCreate,
            UnsupportedReason::ConfigField("ca_certs"),
        );
        assert_eq!(
            err.to_string(),
            "Sandbox::create is not supported by this backend: the ca_certs option is not accepted here"
        );
    }
}

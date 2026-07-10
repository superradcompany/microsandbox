//! `microsandbox` is the core library for the microsandbox project.

#![warn(missing_docs)]
#![allow(clippy::module_inception)]

mod error;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub mod agent;
pub mod backend;
pub mod config;
#[allow(dead_code)]
pub(crate) mod db;
pub mod image;
pub mod logs;
pub mod runtime;
pub mod sandbox;
pub mod setup;
pub mod snapshot;
pub mod volume;

pub use agent::{
    AgentBridge, AgentClient, AgentClientError, AgentClientResult, AgentProtocol, BridgeFrame,
    RawFrame, StreamHandle,
};
pub use backend::{
    Backend, BackendKind, CloudBackend, CloudBackendBuilder, CloudCreateSandboxRequest,
    CloudCreateSandboxResponse, CloudErrorBody, CloudErrorDetails, CloudMessageResponse,
    CloudPaginated, CloudSandboxStatus, LocalBackend, LocalBackendBuilder, Profile, ProfileBackend,
    SandboxBackend, SandboxCloudState, SandboxHandleCloudState, SandboxHandleInner,
    SandboxHandleLocalState, SandboxInner, SandboxList, SandboxLocalState, SdkConfig,
    VolumeBackend, VolumeCloudState, VolumeHandleCloudState, VolumeHandleInner,
    VolumeHandleLocalState, VolumeInner, VolumeLocalState, default_backend, load_sdk_config,
    resolve_default_backend, set_default_backend, swap_default_backend, with_backend,
};
pub use config::set_sdk_libkrunfw_path as set_libkrunfw_path;
pub use error::*;
pub use image::{
    Image, ImageConfigDetail, ImageDetail, ImageHandle, ImageLayerDetail, ImagePruneReport,
};
pub use microsandbox_image::{ImageArchiveFormat, RegistryAuth};
pub use microsandbox_protocol as protocol;
pub use microsandbox_runtime::logging::LogLevel;
pub use microsandbox_utils::size;
#[cfg(feature = "net")]
pub use sandbox::NetworkPolicy;
pub use sandbox::exec::{ExecControl, ExecEvent, ExecHandle};
#[cfg(feature = "ssh")]
pub use sandbox::ssh::{
    DEFAULT_SSH_HOST, DEFAULT_SSH_PORT, SandboxSshOps, SftpClient, SshAttachOptionsBuilder,
    SshClient, SshClientOptionsBuilder, SshExecOptionsBuilder, SshOutput, SshServer,
    SshServerOptionsBuilder, SshStdioStream,
};
pub use sandbox::{
    ChangeKind, ConfigPlannedChange, ExecOutput, MAX_HOSTNAME_BYTES, MAX_SANDBOX_NAME_BYTES,
    ModificationConflict, ModificationDisposition, ModificationPolicy, ModificationWarning,
    PlannedChange, ResourceConvergenceState, ResourceKind, ResourceResizeStatus, Sandbox,
    SandboxConfig, SandboxMetrics, SandboxMetricsReport, SandboxMetricsState,
    SandboxModificationBuilder, SandboxModificationPatch, SandboxModificationPlan,
    SandboxPingResult, SandboxTouchResult, SecretChangeKind, SecretModificationPatch,
    SecretPatchBuilder, SecretPlannedChange, SecretSource, all_sandbox_metrics,
    all_sandbox_metrics_local, all_sandbox_metrics_reports_local, sandbox_metrics_report_local,
    validate_sandbox_name,
};
pub use snapshot::{
    Snapshot, SnapshotBuilder, SnapshotConfig, SnapshotDestination, SnapshotFormat, SnapshotHandle,
    SnapshotSpec, SnapshotVerifyReport, UpperIntegrity, UpperVerifyStatus,
};
pub use volume::{Volume, VolumeConfig, VolumeHandle, VolumeKind, VolumeSpec};

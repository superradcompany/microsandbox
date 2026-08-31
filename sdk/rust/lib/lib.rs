//! `microsandbox` is the core library for the microsandbox project.

#![warn(missing_docs)]
#![allow(clippy::module_inception)]

mod error;
#[cfg(test)]
mod test_support;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub mod agent;
pub mod backend;
#[cfg(feature = "local")]
pub mod config;
#[cfg(feature = "local")]
#[allow(dead_code)]
pub(crate) mod db;
#[cfg(feature = "local")]
pub mod image;
pub mod logs;
#[cfg(feature = "local")]
pub mod runtime;
pub mod sandbox;
#[cfg(feature = "local")]
pub mod setup;
#[cfg(feature = "local")]
pub mod snapshot;
pub mod volume;

pub use agent::{
    AgentBridge, AgentClient, AgentClientError, AgentClientResult, AgentProtocol, BridgeFrame,
    RawFrame, StreamHandle,
};
pub use backend::{
    Backend, BackendInfo, BackendKind, BackendSelectionSource, CloudCreateSandboxRequest,
    CloudCreateSandboxResponse, CloudErrorBody, CloudErrorDetails, CloudMessageResponse,
    CloudPaginated, CloudSandboxStatus, CloudSandboxStatusReason, CloudVolumeKind,
    CloudVolumeStatus, Profile, ProfileBackend, SandboxBackend, SandboxCloudState,
    SandboxHandleCloudState, SandboxHandleInner, SandboxInner, SdkConfig, VolumeBackend,
    VolumeCloudState, VolumeHandleCloudState, VolumeHandleInner, VolumeInner, default_backend,
    default_backend_info, load_sdk_config, resolve_default_backend, set_default_backend,
    swap_default_backend, with_backend,
};
#[cfg(feature = "cloud")]
pub use backend::{CloudBackend, CloudBackendBuilder, DEFAULT_CLOUD_API_URL};
#[cfg(feature = "local")]
pub use backend::{
    LocalBackend, LocalBackendBuilder, SandboxHandleLocalState, SandboxLocalState,
    VolumeHandleLocalState, VolumeLocalState,
};
#[cfg(feature = "local")]
pub use config::set_sdk_libkrunfw_path as set_libkrunfw_path;
pub use error::*;
#[cfg(feature = "local")]
pub use image::{
    Image, ImageConfigDetail, ImageDetail, ImageHandle, ImageLayerDetail, ImagePruneReport,
};
#[cfg(feature = "local")]
pub use microsandbox_image::ImageArchiveFormat;
pub use microsandbox_protocol as protocol;
pub use microsandbox_types::RegistryAuth;
pub use microsandbox_types::SandboxLogLevel as LogLevel;
pub use microsandbox_utils::size;
pub use sandbox::exec::{ExecControl, ExecEvent, ExecHandle};
#[cfg(feature = "ssh")]
pub use sandbox::ssh::{
    DEFAULT_SSH_HOST, DEFAULT_SSH_PORT, SandboxSshOps, SftpClient, SshAttachOptionsBuilder,
    SshClient, SshClientOptionsBuilder, SshExecOptionsBuilder, SshOutput, SshServer,
    SshServerOptionsBuilder, SshStdioStream,
};
#[cfg(feature = "local")]
pub use sandbox::{
    ChangeKind, ConfigPlannedChange, FilesystemConfigPatch, InitConfigPatch, ModificationConflict,
    ModificationDisposition, ModificationPolicy, ModificationWarning, PlannedChange,
    ResourceConfigPatch, ResourceConvergenceState, ResourceKind, ResourceResizeStatus,
    RuntimeConfigPatch, SandboxConfigPatch, SandboxImagePatch, SandboxMetricsReport,
    SandboxMetricsState, SandboxModificationBuilder, SandboxModificationPatch,
    SandboxModificationPlan, ScriptConfigPatch, SecretChangeKind, SecretModificationPatch,
    SecretPatchBuilder, SecretPlannedChange, SecretSource, all_sandbox_metrics,
    all_sandbox_metrics_local, all_sandbox_metrics_reports_local, sandbox_metrics_report_local,
};
#[cfg(feature = "net")]
pub use sandbox::{
    DnsConfigPatch, HostPattern, Nameserver, NetworkAction, NetworkConfigPatch, NetworkPolicy,
    NetworkPolicyConfigPatch, NetworkProfile, NetworkRule, PublishedPort, SecretConfigPatch,
    SecretEntryConfigPatch, SecretSubstitution, SecretViolationAction, TlsConfigPatch,
};
pub use sandbox::{
    ExecOutput, MAX_HOSTNAME_BYTES, MAX_SANDBOX_NAME_BYTES, Sandbox, SandboxConfig,
    SandboxListBuilder, SandboxMetrics, SandboxPage, SandboxPingResult, SandboxTouchResult,
    validate_sandbox_name,
};
#[cfg(feature = "local")]
pub use snapshot::{
    CheckpointSnapshotState, FileSnapshotState, SaveOpts, Snapshot, SnapshotBuilder,
    SnapshotConfig, SnapshotDescriptor, SnapshotFormat, SnapshotHandle, SnapshotScope,
    SnapshotSpec, SnapshotState, SnapshotVerifyReport, UpperIntegrity, UpperVerifyStatus,
};
pub use volume::{Volume, VolumeConfig, VolumeHandle, VolumeKind, VolumeSpec};

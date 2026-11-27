//! `microsandbox` is the core library for the microsandbox project.

#![warn(missing_docs)]
#![allow(clippy::module_inception)]

#[cfg(doctest)]
mod api_boundary;
mod error;
mod host_file;
#[cfg(test)]
mod test_support;
#[cfg(any(feature = "local", feature = "cloud"))]
mod timing;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub mod agent;
pub mod config;
pub mod context;
#[allow(dead_code)]
pub(crate) mod db;
#[cfg(feature = "local")]
pub mod image;
pub mod logs;
pub mod progress;
#[cfg(feature = "local")]
pub mod runtime;
pub mod sandbox;
pub mod service;
#[cfg(feature = "local")]
pub mod setup;
pub mod snapshot;
pub mod storage;
pub mod volume;

pub use agent::{
    AgentBridge, AgentClient, AgentClientError, AgentClientResult, AgentProtocol, BridgeFrame,
    RawFrame, StreamHandle,
};
#[cfg(feature = "local")]
pub use config::set_sdk_libkrunfw_path as set_libkrunfw_path;
pub use context::{
    Checkpoints, CloudCreateSandboxRequest, CloudCreateSandboxResponse, CloudCreateServiceRequest,
    CloudErrorBody, CloudErrorDetails, CloudMessageResponse, CloudPaginated, CloudSandboxStatus,
    CloudSandboxStatusReason, CloudService, CloudServiceStatus, CloudServiceTarget,
    CloudUpdateServiceRequest, CloudVolumeKind, CloudVolumeStatus, ComputeType, Context,
    ContextInfo, ContextKind, ContextSelectionSource, Profile, ProfileKind, SandboxInner,
    SandboxOps, SandboxRecordCloudState, SandboxRecordInner, SandboxRemoteState, Sandboxes,
    ServiceOps, Snapshots, VolumeInner, VolumeOps, VolumeRemoteState, Volumes, configured_context,
    default_local_context, resolve_context, resolve_default_backend,
};
/// Previous name for [`ComputeType`].
#[deprecated(note = "use ComputeType instead")]
pub use microsandbox_types::CloudComputeType;

#[cfg(feature = "cloud")]
pub use context::{DEFAULT_CLOUD_API_URL, RemoteContext, RemoteContextBuilder};
#[cfg(feature = "local")]
pub use context::{
    LocalContext, LocalContextBuilder, SandboxLocalState, SandboxRecordLocalState, VolumeLocalState,
};
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
pub use progress::{CreationProgress, CreationProgressHandle, StartupPhase, StartupProgress};
pub use sandbox::exec::{ExecControl, ExecEvent, ExecHandle};
pub use sandbox::jobs;
pub use sandbox::jobs::{Job, JobAttachment, JobError, JobId, JobInfo, JobResult};
#[cfg(feature = "ssh")]
pub use sandbox::ssh::{
    DEFAULT_SSH_HOST, DEFAULT_SSH_PORT, SandboxSshOps, SftpClient, SshAttachOptionsBuilder,
    SshClient, SshClientOptionsBuilder, SshExecOptionsBuilder, SshOutput, SshServer,
    SshServerOptionsBuilder, SshStdioStream,
};
#[cfg(any(feature = "local", feature = "cloud"))]
pub use sandbox::{
    ChangeKind, ConfigPlannedChange, ModificationConflict, ModificationDisposition,
    ModificationPolicy, ModificationWarning, PlannedChange, ResourceConvergenceState, ResourceKind,
    ResourceResizeStatus, SandboxModificationBuilder, SandboxModificationPatch,
    SandboxModificationPlan, SecretChangeKind, SecretModificationPatch, SecretPatchBuilder,
    SecretPlannedChange, SecretSource,
};
#[cfg(feature = "net")]
pub use sandbox::{
    DnsConfigPatch, HostPattern, HttpConnectCredentials, InterfaceOverridesPatch, Nameserver,
    NetworkAction, NetworkPolicy, NetworkProfile, NetworkRateLimiterConfigPatch, NetworkRule,
    OutboundProxy, PublishedPort, SecretSubstitution, SecretViolationAction, SecretsConfigPatch,
    Socks5Credentials, TlsConfigPatch,
};
pub use sandbox::{
    ExecOutput, ExternalMountRestorePolicy, ExternalMountWarning, MAX_HOSTNAME_BYTES,
    MAX_SANDBOX_NAME_BYTES, NetworkSpecPatch, Sandbox, SandboxConfig, SandboxConfigInspection,
    SandboxConfigPatch, SandboxInfo, SandboxInspectedSettings, SandboxLaunchInfo,
    SandboxListBuilder, SandboxMetrics, SandboxPage, SandboxPingResult, SandboxPolicyPatch,
    SandboxResourcesPatch, SandboxRuntimeOptionsPatch, SandboxSpecPatch, SandboxTouchResult,
    StorageRecovery, StorageRecoveryOptions, StorageRecoverySelection, VsockSpecPatch,
    validate_sandbox_name,
};
#[cfg(feature = "local")]
pub use sandbox::{
    SandboxMetricsReport, SandboxMetricsState, all_sandbox_metrics, all_sandbox_metrics_local,
    all_sandbox_metrics_reports_local, sandbox_metrics_report_local,
};
pub use service::{
    Service, ServiceBuilder, ServiceListBuilder, ServicePage, ServiceStatus, ServiceTarget,
    ServiceUpdate,
};
pub use snapshot::{
    ArchiveCompatibility, Checkpoint, CheckpointCaptureResult, CheckpointRemoveOptions,
    CheckpointRemoveResult, CheckpointSnapshotState, FileSnapshotState, HeadUpdate,
    HeadUpdateReason, LoadOpts, SaveOpts, Snapshot, SnapshotArchive, SnapshotBuilder,
    SnapshotCaptureOptions, SnapshotConfig, SnapshotCopyBuilder, SnapshotCreateResult,
    SnapshotDescriptor, SnapshotFormat, SnapshotGroupInfo, SnapshotImportOptions,
    SnapshotImportResult, SnapshotReference, SnapshotRemoveResult, SnapshotRootDisk, SnapshotScope,
    SnapshotSourceBinding, SnapshotSourceStatus, SnapshotSpec, SnapshotState, SnapshotStateKind,
    SnapshotVerifyReport, UpperIntegrity, UpperVerifyStatus,
};
pub use storage::{Storage, StorageCategoryUsage, StorageItemUsage, StorageUsage};
pub use volume::{Volume, VolumeConfig, VolumeId, VolumeKind, VolumeSpec};

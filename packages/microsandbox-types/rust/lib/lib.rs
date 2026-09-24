//! Shared task and wire contract types for microsandbox.

#![warn(missing_docs)]

mod cloud;
mod command;
mod domain;
mod error;

#[doc(hidden)]
pub mod compat;
mod guest_flush;
#[doc(hidden)]
pub mod helpers;
pub mod modify;
mod registry;
pub mod snapshot;
mod validation;

#[cfg(feature = "ts")]
pub mod typescript;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub use microsandbox_types_macros::ConfigPatch;

pub use cloud::{
    CloudCreateSandboxRequest, CloudCreateSandboxResponse, CloudCreateSnapshotRequest,
    CloudDiskImageFormat, CloudErrorBody, CloudErrorDetails, CloudHostPattern,
    CloudMessageResponse, CloudNetworkSpec, CloudPaginated, CloudPatch, CloudPullPolicy,
    CloudRlimit, CloudRlimitResource, CloudRootfsSource, CloudSandboxComputeResources,
    CloudSandboxResources, CloudSandboxRuntimeOptions, CloudSandboxSpec, CloudSandboxStatus,
    CloudSandboxStatusReason, CloudSecretEntry, CloudSecretSource, CloudSecretsConfig,
    CloudSnapshot, CloudSnapshotDetails, CloudSnapshotKind, CloudSnapshotLocation,
    CloudSnapshotOperation, CloudSnapshotOperationStatus, CloudSnapshotSpec, CloudViolationAction,
    CloudVolumeMount,
};
#[doc(hidden)]
pub use command::{CommandResolutionError, ResolvedCommand, resolve_default_command};
pub use domain::{
    Action, CertCacheConfig, CpuPlacement, DEFAULT_METRICS_SAMPLE_INTERVAL_MS,
    DEFAULT_SANDBOX_CPUS, DEFAULT_SANDBOX_MEMORY_MIB, DeploymentProfile, Destination,
    DestinationGroup, Direction, DiskImageFormat, DnsConfig, DnsConfigPatch, EnvVar, FlatClone,
    HandoffInit, HostPattern, HostPermissions, InterceptCaConfig, InterfaceOverrides,
    InterfaceOverridesPatch, LogSource, MAX_SECRET_PLACEHOLDER_BYTES, MemoryPlacement,
    MountOptions, NamedVolumeCreate, NamedVolumeMode, NetworkPolicy, NetworkRateLimitDirection,
    NetworkRateLimiterConfig, NetworkRateLimiterConfigPatch, NetworkSpec, NetworkSpecPatch,
    NumaPlacement, OciRootfsSource, OutboundProxy, OwnedVolumeStorage, Patch, PlacementProfile,
    PortProtocol, PortRange, Protocol, PublishedPortSpec, PullPolicy, RateLimitConfigError,
    RateLimiterConfig, Rlimit, RlimitResource, RootDisk, RootfsSource, Rule, SandboxLogLevel,
    SandboxPolicy, SandboxPolicyPatch, SandboxResources, SandboxResourcesPatch,
    SandboxRuntimeOptions, SandboxRuntimeOptionsPatch, SandboxSpec, SandboxSpecPatch,
    ScopedUpstreamCaCert, ScopedVerifyUpstream, SecretConfigError, SecretEntry, SecretSubstitution,
    SecretViolationAction, SecretsConfig, SecretsConfigPatch, SecurityProfile, SnapshotSpec,
    Socks5Credentials, StatVirtualization, TlsConfig, TlsConfigPatch, TokenBucketConfig,
    TransparentHugePagePolicy, VolumeKind, VolumeMount, VolumeSpec, VsockRouteSpec,
    VsockSocketType, VsockSpec, VsockSpecPatch, canonicalize_volume_mounts, owned_volume_mount_id,
};
pub use error::{SnapshotManifestError, SnapshotManifestResult, TypesError, TypesResult};
pub use guest_flush::GuestFlush;
pub use modify::{
    ChangeKind, ConfigPlannedChange, ModificationConflict, ModificationDisposition,
    ModificationPolicy, ModificationWarning, PlannedChange, ResourceConvergenceState, ResourceKind,
    ResourceResizeStatus, SandboxModificationPatch, SandboxModificationPlan, SecretChangeKind,
    SecretModificationPatch, SecretPlannedChange, SecretSource,
};
pub use registry::RegistryAuth;
pub use snapshot::manifest::Manifest as SnapshotManifest;
pub use snapshot::{
    DiskCompactionDiskResult, DiskCompactionResult, DiskCompactionTarget,
    ExternalMountRestorePolicy, ExternalMountWarning,
};
pub use validation::{
    MAX_HOSTNAME_BYTES, MAX_SANDBOX_NAME_BYTES, hostname_from_sandbox_name, validate_hostname,
    validate_sandbox_name,
};

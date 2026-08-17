//! Shared task and wire contract types for microsandbox.

#![warn(missing_docs)]

mod cloud;
mod command;
mod domain;
mod error;
pub mod modify;
mod validation;

#[cfg(feature = "ts")]
pub mod typescript;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub use cloud::{
    CloudCreateSandboxRequest, CloudCreateSandboxResponse, CloudDiskImageFormat, CloudErrorBody,
    CloudErrorDetails, CloudHostPattern, CloudMessageResponse, CloudNetworkSpec, CloudPaginated,
    CloudPatch, CloudPullPolicy, CloudRlimit, CloudRlimitResource, CloudRootfsSource,
    CloudSandboxResources, CloudSandboxRuntimeOptions, CloudSandboxSpec, CloudSandboxStatus,
    CloudSandboxStatusReason, CloudSecretEntry, CloudSecretSource, CloudSecretsConfig,
    CloudViolationAction, CloudVolumeMount,
};
#[doc(hidden)]
pub use command::{CommandResolutionError, ResolvedCommand, resolve_default_command};
pub use domain::{
    Action, CertCacheConfig, CpuPlacement, DEFAULT_METRICS_SAMPLE_INTERVAL_MS,
    DEFAULT_SANDBOX_CPUS, DEFAULT_SANDBOX_MEMORY_MIB, DeploymentProfile, Destination,
    DestinationGroup, Direction, DiskImageFormat, DnsConfig, EnvVar, FlatClone, HandoffInit,
    HostPattern, HostPermissions, InterceptCaConfig, InterfaceOverrides, LogSource,
    MAX_SECRET_PLACEHOLDER_BYTES, MemoryPlacement, MountOptions, NamedVolumeCreate,
    NamedVolumeMode, NetworkPolicy, NetworkRateLimitDirection, NetworkRateLimiterConfig,
    NetworkSpec, NumaPlacement, OciRootfsSource, Patch, PlacementProfile, PortProtocol, PortRange,
    Protocol, PublishedPortSpec, PullPolicy, RateLimitConfigError, RateLimiterConfig, Rlimit,
    RlimitResource, RootDisk, RootfsSource, Rule, SandboxLogLevel, SandboxPolicy, SandboxResources,
    SandboxRuntimeOptions, SandboxSpec, ScopedUpstreamCaCert, ScopedVerifyUpstream,
    SecretConfigError, SecretEntry, SecretInjection, SecretsConfig, SecurityProfile, SnapshotSpec,
    StatVirtualization, TlsConfig, TokenBucketConfig, TransparentHugePagePolicy, ViolationAction,
    VolumeKind, VolumeMount, VolumeSpec, VsockRouteSpec, VsockSocketType, VsockSpec,
    canonicalize_volume_mounts,
};
pub use error::{TypesError, TypesResult};
pub use modify::{
    ChangeKind, ConfigPlannedChange, ModificationConflict, ModificationDisposition,
    ModificationPolicy, ModificationWarning, PlannedChange, ResourceConvergenceState, ResourceKind,
    ResourceResizeStatus, SandboxModificationPatch, SandboxModificationPlan, SecretChangeKind,
    SecretModificationPatch, SecretPlannedChange, SecretSource,
};
pub use validation::{
    MAX_HOSTNAME_BYTES, MAX_SANDBOX_NAME_BYTES, hostname_from_sandbox_name, validate_hostname,
    validate_sandbox_name,
};

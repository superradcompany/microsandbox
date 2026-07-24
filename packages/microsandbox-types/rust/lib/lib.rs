//! Shared task and wire contract types for microsandbox.

#![warn(missing_docs)]

mod cloud;
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
pub use domain::{
    Action, CertCacheConfig, DEFAULT_METRICS_SAMPLE_INTERVAL_MS, DEFAULT_SANDBOX_CPUS,
    DEFAULT_SANDBOX_MEMORY_MIB, Destination, DestinationGroup, Direction, DiskImageFormat,
    DnsConfig, EnvVar, HandoffInit, HostPattern, HostPermissions, InterceptCaConfig,
    InterfaceOverrides, LogSource, MAX_SECRET_PLACEHOLDER_BYTES, MountOptions, NamedVolumeCreate,
    NamedVolumeMode, NetworkPolicy, NetworkSpec, OciRootfsSource, Patch, PortProtocol, PortRange,
    Protocol, PublishedPortSpec, PullPolicy, Rlimit, RlimitResource, RootDisk, RootfsSource, Rule,
    SandboxLogLevel, SandboxPolicy, SandboxResources, SandboxRuntimeOptions, SandboxSpec,
    ScopedUpstreamCaCert, ScopedVerifyUpstream, SecretConfigError, SecretEntry, SecretInjection,
    SecretsConfig, SecurityProfile, SnapshotSpec, StatVirtualization, TlsConfig, ViolationAction,
    VolumeKind, VolumeMount, VolumeSpec,
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

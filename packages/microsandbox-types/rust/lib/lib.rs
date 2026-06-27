//! Shared task and wire contract types for microsandbox.

#![warn(missing_docs)]

mod cloud;
mod domain;
mod error;
#[cfg(feature = "ts")]
pub mod typescript;
mod validation;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub use cloud::{
    CloudCreateSandboxRequest, CloudCreateSandboxResponse, CloudErrorBody, CloudErrorDetails,
    CloudMessageResponse, CloudPaginated, CloudSandboxStatus,
};
pub use domain::{
    CertCacheConfig, DEFAULT_METRICS_SAMPLE_INTERVAL_MS, DEFAULT_SANDBOX_CPUS,
    DEFAULT_SANDBOX_MEMORY_MIB, DiskImageFormat, EnvVar, HandoffInit, HostPattern, HostPermissions,
    InterceptCaConfig, LogSource, MAX_SECRET_PLACEHOLDER_BYTES, MountOptions, NamedVolumeCreate,
    NamedVolumeMode, NetworkSpec, OciRootfsSource, Patch, PortProtocol, PublishedPortSpec,
    PullPolicy, Rlimit, RlimitResource, RootfsSource, SandboxLogLevel, SandboxPolicy,
    SandboxResources, SandboxRuntimeOptions, SandboxSpec, SecretConfigError, SecretEntry,
    SecretInjection, SecretsConfig, SecurityProfile, SnapshotDestination, SnapshotSpec,
    StatVirtualization, TlsConfig, ViolationAction, VolumeKind, VolumeMount, VolumeSpec,
};
pub use error::{TypesError, TypesResult};
pub use validation::{
    MAX_HOSTNAME_BYTES, MAX_SANDBOX_NAME_BYTES, hostname_from_sandbox_name, validate_hostname,
    validate_sandbox_name,
};

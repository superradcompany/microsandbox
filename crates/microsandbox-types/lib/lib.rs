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
    CloudCreateSandboxRequest, CloudErrorBody, CloudErrorDetails, CloudMessageResponse,
    CloudPaginated, CloudSandbox, CloudSandboxStatus,
};
pub use domain::{
    DEFAULT_METRICS_SAMPLE_INTERVAL_MS, DEFAULT_SANDBOX_CPUS, DEFAULT_SANDBOX_MEMORY_MIB,
    DiskImageFormat, EnvVar, HandoffInit, HostPermissions, LogSource, MountOptions,
    NamedVolumeCreate, NamedVolumeMode, NetworkSpec, OciRootfsSource, Patch, PortProtocol,
    PublishedPortSpec, PullPolicy, Rlimit, RlimitResource, RootfsSource, SandboxLogLevel,
    SandboxPolicy, SandboxResources, SandboxRuntimeOptions, SandboxSpec, SecurityProfile,
    SnapshotDestination, SnapshotSpec, StatVirtualization, VolumeKind, VolumeMount, VolumeSpec,
};
pub use error::{TypesError, TypesResult};
pub use validation::{
    MAX_HOSTNAME_BYTES, MAX_SANDBOX_NAME_BYTES, hostname_from_sandbox_name, validate_hostname,
    validate_sandbox_name,
};

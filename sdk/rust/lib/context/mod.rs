//! Explicit SDK destinations and retained resource collections.
//!
//! Contexts own shared configuration and transport state. Collections and builders
//! retain that state without requiring callers to own an `Arc`.

#[cfg(feature = "cloud")]
mod cloud;
mod collections;
mod dispatch;
pub use collections::{Checkpoints, Sandboxes, Snapshots, Volumes};
#[cfg(feature = "local")]
pub(crate) mod local;

#[cfg(feature = "local")]
pub(crate) use local::ControlSession;
mod misconfigured;
#[cfg(test)]
pub(crate) use misconfigured::ConfigurationErrorBackend;
mod profile;
pub(crate) mod sandbox;
mod service;
pub use service::ServiceOps;
pub(crate) mod snapshot;
pub(crate) mod volume;

#[cfg(feature = "cloud")]
pub use cloud::{DEFAULT_CLOUD_API_URL, RemoteContext, RemoteContextBuilder};
pub use dispatch::Context;
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub use local::fuzz_unpack_local_snapshot_archive;
#[cfg(feature = "local")]
#[doc(hidden)]
pub use local::snapshot_downgrade as local_snapshot_downgrade;
#[cfg(feature = "local")]
pub use local::{LocalContext, LocalContextBuilder};
/// Compute capacity for new remote sandboxes.
pub use microsandbox_types::CloudComputeType as ComputeType;

/// Previous name for [`ComputeType`].
#[deprecated(note = "use ComputeType instead")]
pub use microsandbox_types::CloudComputeType;
pub use microsandbox_types::{
    CloudCreateSandboxRequest, CloudCreateSandboxResponse, CloudCreateServiceRequest,
    CloudErrorBody, CloudErrorDetails, CloudMessageResponse, CloudPaginated, CloudSandboxStatus,
    CloudSandboxStatusReason, CloudService, CloudServiceStatus, CloudServiceTarget,
    CloudUpdateServiceRequest,
};

pub use profile::{
    Profile, ProfileKind, configured_context, configured_provider_kind, resolve_cli_context,
    resolve_context, resolve_default_backend,
};
pub use sandbox::{
    SandboxIdentity, SandboxInner, SandboxOps, SandboxRecordCloudState, SandboxRecordInner,
    SandboxRemoteState,
};
pub use sandbox::{SandboxLocalState, SandboxRecordLocalState};
pub use snapshot::SnapshotOps;
pub use volume::VolumeLocalState;
pub use volume::{CloudVolumeKind, CloudVolumeStatus, VolumeInner, VolumeOps, VolumeRemoteState};

mod default_local;
mod metadata;
mod options;
pub use default_local::default_local_context;
pub use metadata::{ContextInfo, ContextKind, ContextSelectionSource};
#[doc(hidden)]
pub use options::{derive_remote_from_options_json, from_options_json, remote_from_env};

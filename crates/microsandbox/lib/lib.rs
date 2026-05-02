//! `microsandbox` is the core library for the microsandbox project.

#![warn(missing_docs)]
#![allow(clippy::module_inception)]

mod error;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub mod agent;
pub mod config;
#[allow(dead_code)]
pub(crate) mod db;
pub mod image;
pub mod runtime;
pub mod sandbox;
pub mod setup;
pub mod snapshot;
pub mod volume;

pub use error::*;
pub use microsandbox_image::RegistryAuth;
pub use microsandbox_runtime::logging::LogLevel;
pub use microsandbox_utils::size;
#[cfg(feature = "net")]
pub use sandbox::NetworkPolicy;
pub use sandbox::exec::{ExecEvent, ExecHandle};
pub use sandbox::{ExecOutput, Sandbox, SandboxConfig};
pub use snapshot::{
    Snapshot, SnapshotBuilder, SnapshotConfig, SnapshotDestination, SnapshotFormat, SnapshotHandle,
    SnapshotVerifyReport, UpperIntegrity, UpperVerifyStatus,
};
pub use volume::Volume;

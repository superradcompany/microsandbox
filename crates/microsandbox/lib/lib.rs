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
pub use error::*;
pub use image::{Image, ImageConfigDetail, ImageDetail, ImageHandle, ImageLayerDetail};
pub use microsandbox_image::RegistryAuth;
pub use microsandbox_protocol as protocol;
pub use microsandbox_runtime::logging::LogLevel;
pub use microsandbox_utils::size;
#[cfg(feature = "net")]
pub use sandbox::NetworkPolicy;
pub use sandbox::exec::{ExecControl, ExecEvent, ExecHandle};
#[cfg(feature = "ssh")]
pub use sandbox::ssh::{
    DEFAULT_SSH_HOST, DEFAULT_SSH_PORT, SandboxSsh, SftpClient, SshAttachOptionsBuilder, SshClient,
    SshClientOptionsBuilder, SshExecOptionsBuilder, SshOutput, SshServer, SshServerOptionsBuilder,
    SshStdioStream,
};
pub use sandbox::{ExecOutput, Sandbox, SandboxConfig};
pub use snapshot::{
    Snapshot, SnapshotBuilder, SnapshotConfig, SnapshotDestination, SnapshotFormat, SnapshotHandle,
    SnapshotVerifyReport, UpperIntegrity, UpperVerifyStatus,
};
pub use volume::Volume;

//! `microsandbox-protocol` defines the shared protocol types used for communication
//! between the host and the guest agent over CBOR-over-virtio-serial.

#![warn(missing_docs)]

mod error;

//--------------------------------------------------------------------------------------------------
// Constants: Host↔Guest Protocol
//--------------------------------------------------------------------------------------------------

/// Virtio-console port name for the agent channel.
pub const AGENT_PORT_NAME: &str = "agent";

/// Virtiofs tag for the runtime filesystem (scripts, heartbeat).
pub const RUNTIME_FS_TAG: &str = "msb_runtime";

/// Guest mount point for the runtime filesystem.
pub const RUNTIME_MOUNT_POINT: &str = "/.msb";

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub mod codec;
pub mod core;
pub mod exec;
pub mod fs;
pub mod heartbeat;
pub mod message;

pub use error::*;

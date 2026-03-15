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
// Constants: Guest Init Environment Variables
//--------------------------------------------------------------------------------------------------

/// Environment variable carrying tmpfs mount specs for guest init.
///
/// Format: `path[,key=value,...][;path[,key=value,...];...]`
///
/// - `path` — guest mount path (required, always the first element)
/// - `size=N` — size limit in MiB (optional)
/// - `noexec` — mount with noexec flag (optional)
/// - `mode=N` — permission mode as octal integer (optional, e.g. `mode=1777`)
///
/// Entries are separated by `;`. Within an entry, the path comes first
/// followed by comma-separated options.
///
/// Examples:
/// - `MSB_TMPFS=/tmp,size=256` — 256 MiB tmpfs at `/tmp`
/// - `MSB_TMPFS=/tmp,size=256;/var/tmp,size=128` — two tmpfs mounts
/// - `MSB_TMPFS=/tmp` — tmpfs at `/tmp` with defaults
/// - `MSB_TMPFS=/tmp,size=256,noexec` — with noexec flag
pub const ENV_TMPFS: &str = "MSB_TMPFS";

/// Environment variable specifying the block device for rootfs switch.
///
/// Format: `device[,key=value,...]`
/// - `device` — block device path (required, always first element)
/// - `fstype=TYPE` — filesystem type (optional; auto-detected if absent)
pub const ENV_BLOCK_ROOT: &str = "MSB_BLOCK_ROOT";

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

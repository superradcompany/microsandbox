//! In-process virtual-mount provider servers, registry, and lifecycle hooks.
//!
//! A **virtual mount** connects guest filesystem I/O to a [`PathFs`] implementation
//! in the SDK process over a Unix socket. This module owns:
//!
//! - [`VirtualMountServer`] — one background `rpc::serve` loop per mount
//! - [`VirtualMountServers`] — bundle of servers for one sandbox create
//! - registry helpers — process-local session tracking and connect gating

pub(crate) mod registry;
mod server;

pub use registry::VirtualMountSession;
pub(crate) use registry::{
    acquire_session, check_virtual_mount_connect, clear_live_slot, connect_error, has_live_servers,
    install_session, is_live_session, register_servers, snapshot_servers, teardown_bundle,
    teardown_servers,
};
pub(crate) use server::RuntimeVirtualMountServers;
pub use server::{VirtualMountServer, VirtualMountServers};

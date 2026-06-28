//! RPC bridge for [`PathFs`](super::PathFs) providers in another process.
//!
//! Because the `msb` runtime serves FUSE in a **separate process** from the SDK
//! that defines the filesystem semantics (see
//! `docs/sandboxes/virtual-filesystem.mdx`), the provider cannot be a set of
//! in-process callbacks. Instead the runtime runs [`super::VirtualFs<RpcPathFs<T>>`],
//! where [`RpcPathFs`] turns each FUSE op into a [`VfsRequest`] sent over a [`VfsTransport`] to the
//! controlling process, which runs the real provider and replies with a
//! [`VfsResponse`].
//!
//! Layout:
//! - `client` — runtime-side [`RpcPathFs`] proxy over a [`VfsTransport`]
//! - [`dispatch`] — provider-side request handler
//! - [`serve`] — provider-side I/O loop (Rust counterpart to Go `vfs.Serve`)
//! - `transport` — multiplexed socket transport
//! - `mount` — build a runtime [`super::VirtualFs`] over a connected socket

mod client;
mod dispatch;
mod limits;
mod mount;
pub mod protocol;
mod readdir_cache;
mod serve;
mod transport;
#[cfg(test)]
mod wire_vectors;

#[cfg(test)]
mod tests;

pub use client::{RpcPathFs, VfsTransport};
pub use dispatch::{DispatchState, dispatch, dispatch_with_state};
pub use mount::{unix_socket_backend, unix_socket_backend_with_config};
pub use protocol::{
    GETATTR_MANY_RPC_CHUNK, PROTOCOL_VERSION, StatFsWire, VAttrWire, VDirEntryWire, VfsRequest,
    VfsResponse, decode_error_errno, decode_request, from_cbor, read_frame, read_hello, to_cbor,
    validate_request_limits, write_frame, write_hello,
};
pub use serve::{MAX_CONCURRENT_OPS, SERVE_SHUTDOWN_JOIN_TIMEOUT, serve, serve_unix};
pub use transport::{IoStream, SocketTransport};

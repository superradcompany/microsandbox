//! Construct a runtime-side [`super::super::VirtualFs`] backed by an RPC socket to the provider.

use std::io;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use super::super::{VirtualFs, VirtualFsConfig};
use super::client::RpcPathFs;
use super::protocol;
use super::transport::{DEFAULT_CALL_TIMEOUT, HELLO_TIMEOUT, SocketTransport};

/// Build a [`super::super::VirtualFs`] backend served over a connected Unix-domain socket.
///
/// The socket's peer must run a virtual mount provider server (e.g. Go `vfs.Serve`
/// or Rust `rpc::serve`) that answers [`super::protocol::VfsRequest`]s. This is the construction the `msb` runtime uses to
/// turn an inherited socketpair fd into a mountable filesystem backend.
pub fn unix_socket_backend(
    stream: UnixStream,
) -> io::Result<VirtualFs<RpcPathFs<SocketTransport<UnixStream>>>> {
    unix_socket_backend_with_config(stream, None, None)
}

/// Like [`unix_socket_backend`] with an explicit [`VirtualFsConfig`] and an
/// optional per-op call timeout (`None` uses the 30-second default).
pub fn unix_socket_backend_with_config(
    mut stream: UnixStream,
    cfg: Option<VirtualFsConfig>,
    call_timeout: Option<Duration>,
) -> io::Result<VirtualFs<RpcPathFs<SocketTransport<UnixStream>>>> {
    // Bound the handshake with a read timeout so an absent/never-serving peer
    // can't stall boot indefinitely, then clear it before the multiplexed
    // reader/writer threads (which use blocking I/O) take over.
    stream.set_read_timeout(Some(HELLO_TIMEOUT))?;
    protocol::write_hello(&mut stream)?;
    let peer_version = protocol::read_hello(&mut stream)?;
    stream.set_read_timeout(None)?;
    let transport = SocketTransport::with_call_timeout_and_peer_version(
        stream,
        call_timeout.unwrap_or(DEFAULT_CALL_TIMEOUT),
        peer_version,
    )?;
    let provider = RpcPathFs::new(transport);
    match cfg {
        Some(cfg) => VirtualFs::with_config(provider, cfg),
        None => VirtualFs::new(provider),
    }
}

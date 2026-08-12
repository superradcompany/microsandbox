use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixDatagram as StdUnixDatagram;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use msb_krun::backends::vsock::{
    VsockDatagramBackend, VsockDatagramPeer, VsockDatagramPortBackend, VsockDatagramRead,
    VsockNotifier,
};
use nix::sys::socket::{MsgFlags, recv, send};
use tempfile::TempDir;

use crate::common::{DEFAULT_MAX_ACTIVE_PEERS, PeerLease, PeerLimit, validate_socket_path};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Factory that connects guest datagram peers to one host Unix datagram service.
pub struct UnixDatagramPortBackend {
    path: PathBuf,
    peer_dir: TempDir,
    next_peer: AtomicU64,
    peers: PeerLimit,
}

struct UnixDatagramBackend {
    fd: OwnedFd,
    bound_path: PathBuf,
    _lease: PeerLease,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl UnixDatagramPortBackend {
    /// Create a route to an existing host `SOCK_DGRAM` Unix socket.
    pub fn new(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::with_max_active_peers(path, DEFAULT_MAX_ACTIVE_PEERS)
    }

    /// Create a route with an explicit cap on active guest source peers.
    pub fn with_max_active_peers(path: impl AsRef<Path>, max: usize) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        validate_socket_path(&path)?;
        if max == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "vsock datagram peer limit must be non-zero",
            ));
        }

        // A short private directory keeps reply addresses within macOS's
        // smaller sockaddr_un path limit. TempDir handles normal cleanup.
        // Use the short, stable Unix temporary root rather than macOS's long
        // per-user TMPDIR. `sockaddr_un` is only 104 bytes there and nix may
        // otherwise return a truncated peer address that cannot be replied to.
        let peer_dir = tempfile::Builder::new()
            .prefix("msb-vsock-")
            .tempdir_in("/tmp")?;
        Ok(Self {
            path,
            peer_dir,
            next_peer: AtomicU64::new(1),
            peers: PeerLimit::new(max),
        })
    }

    fn next_peer_path(&self) -> PathBuf {
        let id = self.next_peer.fetch_add(1, Ordering::Relaxed);
        self.peer_dir.path().join(format!("{id:x}.sock"))
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl VsockDatagramPortBackend for UnixDatagramPortBackend {
    fn open_peer(
        &self,
        _peer: VsockDatagramPeer,
        _notifier: VsockNotifier,
    ) -> io::Result<Box<dyn VsockDatagramBackend>> {
        let lease = self.peers.acquire()?;
        let bound_path = self.next_peer_path();
        // std includes the terminating NUL in sockaddr_un on BSD hosts. nix's
        // shorter bind length makes macOS report a one-byte-truncated reply
        // pathname to the receiving service.
        let socket = StdUnixDatagram::bind(&bound_path)?;
        if let Err(err) = socket.set_nonblocking(true) {
            let _ = std::fs::remove_file(&bound_path);
            return Err(err);
        }
        if let Err(err) = socket.connect(&self.path) {
            let _ = std::fs::remove_file(&bound_path);
            return Err(err);
        }
        let fd = socket.into();

        Ok(Box::new(UnixDatagramBackend {
            fd,
            bound_path,
            _lease: lease,
        }))
    }
}

impl VsockDatagramBackend for UnixDatagramBackend {
    fn send(&self, payload: &[u8]) -> io::Result<()> {
        let written =
            send(self.fd.as_raw_fd(), payload, MsgFlags::empty()).map_err(io::Error::from)?;
        if written != payload.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "Unix datagram send did not consume the complete message",
            ));
        }
        Ok(())
    }

    fn receive(&self, buf: &mut [u8]) -> io::Result<VsockDatagramRead> {
        let received = recv(
            self.fd.as_raw_fd(),
            buf,
            MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_TRUNC,
        )
        .map_err(io::Error::from)?;
        Ok(VsockDatagramRead {
            len: received.min(buf.len()),
            truncated: received > buf.len(),
        })
    }

    fn pollable(&self) -> Option<RawFd> {
        Some(self.fd.as_raw_fd())
    }
}

impl Drop for UnixDatagramBackend {
    fn drop(&mut self) {
        if let Err(err) = std::fs::remove_file(&self.bound_path)
            && err.kind() != io::ErrorKind::NotFound
        {
            tracing::debug!(
                path = %self.bound_path.display(),
                %err,
                "failed to remove vsock datagram peer socket"
            );
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixDatagram;

    use super::*;

    #[test]
    fn datagram_backend_preserves_messages_and_reply_address() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("service.sock");
        let host = UnixDatagram::bind(&path).unwrap();
        host.set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();

        let service = UnixDatagramPortBackend::new(&path).unwrap();
        let endpoint = service
            .open_peer(
                VsockDatagramPeer {
                    guest_cid: 3,
                    guest_port: 4000,
                    host_port: 5000,
                },
                VsockNotifier::new().unwrap(),
            )
            .unwrap();

        endpoint.send(b"guest-event").unwrap();
        let mut request = [0; 32];
        let (len, peer) = host.recv_from(&mut request).unwrap();
        assert_eq!(&request[..len], b"guest-event");
        let reply_path = peer.as_pathname().unwrap();
        assert!(
            reply_path.exists(),
            "reply path missing: {}",
            reply_path.display()
        );
        host.send_to(b"host-event", reply_path).unwrap();

        let mut response = [0; 32];
        let mut read = None;
        for _ in 0..100 {
            match endpoint.receive(&mut response) {
                Ok(received) => {
                    read = Some(received);
                    break;
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => std::thread::yield_now(),
                result => panic!("unexpected datagram receive result: {result:?}"),
            }
        }
        let read = read.expect("reply datagram should become readable");
        assert_eq!(&response[..read.len], b"host-event");
        assert!(!read.truncated);
    }
}

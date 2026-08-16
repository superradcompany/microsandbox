use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use msb_krun::backends::vsock::{
    VsockConnectRequest, VsockConnectState, VsockNotifier, VsockPortBackend, VsockShutdown,
    VsockStreamBackend,
};
use nix::errno::Errno;
use nix::sys::socket::{
    MsgFlags, Shutdown, SockType, UnixAddr, connect, getsockopt, recv, send, shutdown, sockopt,
};

use crate::common::{
    DEFAULT_MAX_ACTIVE_PEERS, PeerLease, PeerLimit, nonblocking_unix_socket, validate_socket_path,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Factory that connects guest streams to one existing host Unix socket.
pub struct UnixStreamPortBackend {
    path: PathBuf,
    peers: PeerLimit,
}

struct UnixStreamBackend {
    fd: OwnedFd,
    connected: AtomicBool,
    defer_connect_check: AtomicBool,
    _lease: PeerLease,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl UnixStreamPortBackend {
    /// Create a route to an existing host `SOCK_STREAM` Unix socket.
    pub fn new(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::with_max_active_peers(path, DEFAULT_MAX_ACTIVE_PEERS)
    }

    /// Create a route with an explicit cap on active guest connections.
    pub fn with_max_active_peers(path: impl AsRef<Path>, max: usize) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        validate_socket_path(&path)?;
        if max == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "vsock stream peer limit must be non-zero",
            ));
        }
        Ok(Self {
            path,
            peers: PeerLimit::new(max),
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl VsockPortBackend for UnixStreamPortBackend {
    fn connect(
        &self,
        _request: VsockConnectRequest,
        _notifier: VsockNotifier,
    ) -> io::Result<Box<dyn VsockStreamBackend>> {
        let lease = self.peers.acquire()?;
        let fd = nonblocking_unix_socket(SockType::Stream)?;
        let address = UnixAddr::new(&self.path)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

        let (connected, pending) = match connect(fd.as_raw_fd(), &address) {
            Ok(()) => (true, false),
            // Linux reports EAGAIN for an in-progress nonblocking AF_UNIX
            // connect, while BSD hosts normally use EINPROGRESS.
            Err(Errno::EINPROGRESS | Errno::EAGAIN) => (false, true),
            Err(err) => return Err(io::Error::from(err)),
        };

        Ok(Box::new(UnixStreamBackend {
            fd,
            connected: AtomicBool::new(connected),
            // libkrun queries once immediately after `connect`. Defer SO_ERROR
            // until the next writable event so zero cannot be mistaken for a
            // completed nonblocking connection.
            defer_connect_check: AtomicBool::new(pending),
            _lease: lease,
        }))
    }
}

impl VsockStreamBackend for UnixStreamBackend {
    fn connect_state(&self) -> io::Result<VsockConnectState> {
        if self.connected.load(Ordering::Acquire) {
            return Ok(VsockConnectState::Connected);
        }
        if self.defer_connect_check.swap(false, Ordering::AcqRel) {
            return Ok(VsockConnectState::Connecting);
        }

        let error = getsockopt(&self.fd, sockopt::SocketError).map_err(io::Error::from)?;
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error));
        }
        self.connected.store(true, Ordering::Release);
        Ok(VsockConnectState::Connected)
    }

    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        recv(self.fd.as_raw_fd(), buf, MsgFlags::MSG_DONTWAIT).map_err(io::Error::from)
    }

    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        #[cfg(target_os = "linux")]
        let flags = MsgFlags::MSG_NOSIGNAL;
        #[cfg(not(target_os = "linux"))]
        let flags = MsgFlags::empty();
        send(self.fd.as_raw_fd(), buf, flags).map_err(io::Error::from)
    }

    fn shutdown(&self, how: VsockShutdown) -> io::Result<()> {
        let how = match how {
            VsockShutdown::Read => Shutdown::Read,
            VsockShutdown::Write => Shutdown::Write,
            VsockShutdown::Both => Shutdown::Both,
        };
        shutdown(self.fd.as_raw_fd(), how).map_err(io::Error::from)
    }

    fn pollable(&self) -> Option<RawFd> {
        Some(self.fd.as_raw_fd())
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;

    use msb_krun::backends::vsock::{VsockConnectRequest, VsockPortBackend};

    use super::*;

    #[test]
    fn stream_backend_connects_and_moves_bytes_in_both_directions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("service.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let service = UnixStreamPortBackend::new(&path).unwrap();
        let endpoint = service
            .connect(
                VsockConnectRequest {
                    guest_cid: 3,
                    guest_port: 4000,
                    host_port: 5000,
                },
                VsockNotifier::new().unwrap(),
            )
            .unwrap();
        let (mut host, _) = listener.accept().unwrap();

        for _ in 0..100 {
            if endpoint.connect_state().unwrap() == VsockConnectState::Connected {
                break;
            }
            std::thread::yield_now();
        }
        assert_eq!(
            endpoint.connect_state().unwrap(),
            VsockConnectState::Connected
        );

        endpoint.write(b"guest").unwrap();
        let mut request = [0; 5];
        host.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"guest");

        host.write_all(b"host").unwrap();
        let mut response = [0; 4];
        for _ in 0..100 {
            match endpoint.read(&mut response) {
                Ok(4) => break,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => std::thread::yield_now(),
                result => panic!("unexpected stream read result: {result:?}"),
            }
        }
        assert_eq!(&response, b"host");
    }
}

use std::io;
#[cfg(unix)]
use std::os::fd::RawFd;
#[cfg(windows)]
use std::os::windows::io::RawHandle;
use std::sync::Arc;

use utils::eventfd::{EventFd, EFD_NONBLOCK};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Platform-native object that can be registered with libkrun's event loop.
#[cfg(unix)]
pub type VsockPollable = RawFd;

/// Platform-native object that can be registered with libkrun's event loop.
#[cfg(windows)]
pub type VsockPollable = RawHandle;

/// Metadata for a guest-initiated connection to a registered host port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VsockConnectRequest {
    /// CID of the guest opening the connection.
    pub guest_cid: u64,
    /// Ephemeral source port selected by the guest.
    pub guest_port: u32,
    /// Host port on which the backend was registered.
    pub host_port: u32,
}

/// State of the host endpoint behind a guest stream connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VsockConnectState {
    /// The nonblocking host connection is still being established.
    Connecting,
    /// The host endpoint is ready for stream traffic.
    Connected,
}

/// Metadata identifying one guest datagram peer for a registered host port.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct VsockDatagramPeer {
    /// CID of the guest sending datagrams.
    pub guest_cid: u64,
    /// Source port selected or bound by the guest.
    pub guest_port: u32,
    /// Host port on which the backend was registered.
    pub host_port: u32,
}

/// Result of receiving one complete datagram from a host backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VsockDatagramRead {
    /// Number of bytes written into the supplied buffer.
    pub len: usize,
    /// Whether the original message exceeded the supplied buffer.
    pub truncated: bool,
}

/// Direction requested by a guest shutdown packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VsockShutdown {
    Read,
    Write,
    Both,
}

/// Cloneable wake handle for a custom vsock stream.
///
/// Call [`notify`](Self::notify) whenever a previously blocked stream read or
/// write may make progress. libkrun owns the platform event primitive and its
/// registration with the VMM event loop.
#[derive(Clone, Debug)]
pub struct VsockNotifier {
    event: Arc<EventFd>,
}

/// Factory for custom, in-process services exposed on one host vsock port.
///
/// The factory is shared between connections and may be called concurrently.
/// It should return promptly; expensive setup belongs in backend-managed work.
pub trait VsockPortBackend: Send + Sync {
    /// Accept a guest connection and return its byte-stream endpoint.
    fn connect(
        &self,
        request: VsockConnectRequest,
        notifier: VsockNotifier,
    ) -> io::Result<Box<dyn VsockStreamBackend>>;
}

/// One nonblocking byte stream served by a custom vsock backend.
///
/// Implementations return [`io::ErrorKind::WouldBlock`] when progress is not
/// currently possible. The [`VsockNotifier`] supplied at connection time must
/// be signaled whenever a blocked operation may make progress; libkrun
/// continues to own virtio-vsock framing, credit flow, shutdown, and reset
/// handling around this stream.
pub trait VsockStreamBackend: Send {
    /// Report whether a nonblocking host connection has completed.
    ///
    /// In-process backends are ready immediately. Socket-backed implementations
    /// can return [`VsockConnectState::Connecting`] until their poll fd becomes
    /// writable and then surface the result of `SO_ERROR` here.
    fn connect_state(&self) -> io::Result<VsockConnectState> {
        Ok(VsockConnectState::Connected)
    }

    /// Read bytes that should be delivered to the guest.
    fn read(&self, buf: &mut [u8]) -> io::Result<usize>;

    /// Consume bytes received from the guest.
    fn write(&self, buf: &[u8]) -> io::Result<usize>;

    /// Apply a guest-requested half-close or full shutdown.
    fn shutdown(&self, how: VsockShutdown) -> io::Result<()>;

    /// Return a pollable host object when the backend has one.
    ///
    /// Returning `None` keeps the existing notifier-driven behavior. Returning
    /// a native object lets libkrun poll a real socket or handle directly.
    fn pollable(&self) -> Option<VsockPollable> {
        None
    }
}

/// Factory for message-oriented services exposed on one host vsock port.
///
/// libkrun opens one endpoint for every `(guest CID, guest source port, host
/// port)` tuple. This preserves connectionless guest semantics while giving a
/// host Unix datagram backend a stable reply address for each guest peer.
pub trait VsockDatagramPortBackend: Send + Sync {
    /// Open the host endpoint associated with one guest datagram peer.
    fn open_peer(
        &self,
        peer: VsockDatagramPeer,
        notifier: VsockNotifier,
    ) -> io::Result<Box<dyn VsockDatagramBackend>>;
}

/// One nonblocking message-oriented endpoint behind a guest datagram peer.
pub trait VsockDatagramBackend: Send {
    /// Atomically deliver one guest message to the host endpoint.
    ///
    /// Implementations must never report partial delivery. `WouldBlock` means
    /// the best-effort datagram may be dropped by the device.
    fn send(&self, payload: &[u8]) -> io::Result<()>;

    /// Receive one complete host message for delivery to the guest peer.
    fn receive(&self, buf: &mut [u8]) -> io::Result<VsockDatagramRead>;

    /// Return a pollable host object, or `None` to use [`VsockNotifier`].
    fn pollable(&self) -> Option<VsockPollable> {
        None
    }
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl VsockNotifier {
    /// Create an independent notifier suitable for backend tests or adapters.
    ///
    /// libkrun normally constructs the notifier passed to a route backend.
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            event: Arc::new(EventFd::new(EFD_NONBLOCK)?),
        })
    }

    /// Wake libkrun so it retries this stream's nonblocking operations.
    pub fn notify(&self) -> io::Result<()> {
        self.event.write(1)
    }

    #[cfg(any(unix, test))]
    pub(crate) fn event(&self) -> &EventFd {
        &self.event
    }

    pub(crate) fn pollable(&self) -> VsockPollable {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;

            self.event.as_raw_fd()
        }

        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;

            self.event.as_raw_handle()
        }
    }

    pub(crate) fn clear(&self) -> io::Result<()> {
        match self.event.read() {
            Ok(_) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(err) => Err(err),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notifier_clone_wakes_shared_libkrun_event() {
        let notifier = VsockNotifier::new().unwrap();
        notifier.clone().notify().unwrap();

        notifier.clear().unwrap();
        assert_eq!(
            notifier.event().read().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}

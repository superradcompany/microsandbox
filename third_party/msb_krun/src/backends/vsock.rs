//! Custom virtio-vsock service backends.
//!
//! These traits expose byte streams rather than virtio packets. libkrun keeps
//! responsibility for the transport protocol, flow control, and interrupts.

pub use devices::virtio::vsock::{
    VsockConnectRequest, VsockConnectState, VsockNotifier, VsockPortBackend, VsockShutdown,
    VsockStreamBackend,
};
#[cfg(not(target_os = "windows"))]
pub use devices::virtio::vsock::{
    VsockDatagramBackend, VsockDatagramPeer, VsockDatagramPortBackend, VsockDatagramRead,
};

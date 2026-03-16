//! Platform-specific host network backends.
//!
//! Each backend creates the OS-level networking infrastructure (TAP device on
//! Linux, vmnet interface on macOS) and provides raw ethernet frame RX/TX.

use std::os::fd::RawFd;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Host network backend interface used by the packet relay engine.
pub trait FrameTransport {
    /// Returns the fd used for readiness notifications.
    fn ready_fd(&self) -> RawFd;

    /// Reads one ethernet frame from the backend.
    fn read_frame(&self, buf: &mut [u8]) -> std::io::Result<usize>;

    /// Writes one ethernet frame to the backend.
    fn write_frame(&self, buf: &[u8]) -> std::io::Result<()>;
}

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

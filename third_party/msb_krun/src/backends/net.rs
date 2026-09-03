//! Network backend support.
//!
//! This module re-exports the `NetBackend` trait from the devices crate,
//! allowing users to implement custom network backends for their VMs.
//!
//! # Example
//!
//! ```rust,no_run
//! use krun::backends::net::{
//!     EventFd, EventSource, EventToken, NetBackend, ReadError, WriteError, EFD_NONBLOCK,
//! };
//! #[cfg(unix)]
//! use std::os::fd::{AsRawFd, RawFd};
//! #[cfg(windows)]
//! use std::os::windows::io::AsRawHandle;
//!
//! struct MyNetBackend {
//!     event: EventFd,
//! }
//!
//! impl NetBackend for MyNetBackend {
//!     fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize, ReadError> {
//!         // Read an ethernet frame from the backend
//!         todo!()
//!     }
//!
//!     fn write_frame(&mut self, hdr_len: usize, buf: &mut [u8]) -> Result<(), WriteError> {
//!         // Write an ethernet frame to the backend
//!         todo!()
//!     }
//!
//!     fn has_unfinished_write(&self) -> bool {
//!         false
//!     }
//!
//!     fn try_finish_write(&mut self, hdr_len: usize, buf: &[u8]) -> Result<(), WriteError> {
//!         Ok(())
//!     }
//!
//!     #[cfg(unix)]
//!     fn raw_socket_fd(&self) -> RawFd {
//!         self.event.as_raw_fd()
//!     }
//!
//!     #[cfg(windows)]
//!     fn event_source(&self, token: EventToken) -> EventSource {
//!         EventSource::waitable_handle(self.event.as_raw_handle(), token)
//!     }
//! }
//! ```

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "net")]
pub use devices::virtio::net::backend::{ConnectError, NetBackend, ReadError, WriteError};

#[cfg(feature = "net")]
pub use utils::event::{EventSource, EventToken};

#[cfg(feature = "net")]
pub use utils::eventfd::{EventFd, EFD_NONBLOCK};

#[cfg(all(feature = "net", unix))]
pub use devices::virtio::net::unixgram::Unixgram;

#[cfg(all(feature = "net", unix))]
pub use devices::virtio::net::unixstream::Unixstream;

#[cfg(all(feature = "net", windows))]
pub use devices::virtio::net::namedpipe::NamedPipe;

//! Custom console port backend support.
//!
//! Re-exports [`ConsolePortBackend`] from the devices crate, following the
//! same pattern as [`NetBackend`](super::net::NetBackend) and
//! [`DynFileSystem`](super::fs::DynFileSystem).

pub use devices::virtio::console::port_io::ConsolePortBackend;

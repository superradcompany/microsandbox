//! Host-only control on the existing socket or Windows named pipe.
//!
//! The first byte selects persistent framed CBOR or the legacy one-line JSON
//! exchange. Both formats dispatch through the same serialized host operations.

mod dispatch;
mod handler;
mod server;
#[cfg(windows)]
mod windows;

#[cfg(all(test, feature = "net"))]
mod delivery_tests;
#[cfg(test)]
mod tests;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use executor::RuntimeControlExecutor;
pub use handler::ControlContext;
pub use server::spawn_control_listener;

mod executor;
mod legacy;
#[cfg(all(test, feature = "net"))]
mod legacy_tests;

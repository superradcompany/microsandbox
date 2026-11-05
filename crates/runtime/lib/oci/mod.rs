//! OCI Runtime Specification compatibility primitives.
//!
//! Shared durable state, bundle parsing and lifecycle validation for `runmsb`.
//! The Linux `oci-runtime` feature also supplies host cgroup placement used by
//! the VMM before allocating guest memory. Ordinary OCI data types remain
//! available without enabling the VM runner.

mod bundle;
#[cfg(all(target_os = "linux", feature = "oci-runtime"))]
pub mod cgroup;
mod error;
mod lifecycle;
mod state;
mod store;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub use bundle::*;
pub use error::*;
pub use lifecycle::*;
pub use state::*;
pub use store::*;

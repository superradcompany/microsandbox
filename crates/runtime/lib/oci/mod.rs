//! OCI Runtime Specification compatibility primitives.
//!
//! This module contains the host-side contracts that a future
//! `microsandbox-runtime` OCI binary and a containerd shim can share. It does
//! not launch VMs directly; instead it defines the durable state model,
//! bundle parsing, lifecycle validation, and engine boundary used to map OCI
//! commands onto Microsandbox's existing microVM runtime.

mod bundle;
mod engine;
mod error;
mod lifecycle;
mod state;
mod store;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub use bundle::*;
pub use engine::*;
pub use error::*;
pub use lifecycle::*;
pub use state::*;
pub use store::*;

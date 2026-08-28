//! Filesystem backends for microsandbox.
//!
//! Provides host-directory passthrough, isolated single-file views, and the
//! in-memory composition backends used by the runtime.

#[cfg(unix)]
pub mod dualfs;
#[cfg(unix)]
pub mod memfs;
pub mod passthroughfs;
#[cfg(unix)]
pub(crate) mod shared;
pub mod singlefilefs;

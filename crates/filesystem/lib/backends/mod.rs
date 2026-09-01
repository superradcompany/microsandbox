//! Filesystem backends for microsandbox.
//!
//! Currently provides [`PassthroughFs`](passthroughfs::PassthroughFs), which exposes
//! a single host directory to the guest VM via virtio-fs.

#[cfg(unix)]
pub mod dualfs;
#[cfg(unix)]
pub mod memfs;
pub(crate) mod mobility;
pub mod passthroughfs;
#[cfg(unix)]
pub(crate) mod shared;

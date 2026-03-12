//! Filesystem backends for microsandbox.
//!
//! Currently provides [`PassthroughFs`](passthrough::PassthroughFs) which exposes
//! a single host directory to the guest VM via virtio-fs with stat virtualization.

pub mod dualfs;
pub mod memfs;
pub mod overlayfs;
pub mod passthroughfs;
pub mod proxy;
pub(crate) mod shared;

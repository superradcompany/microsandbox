//! Filesystem backends for microsandbox.
//!
//! Currently provides [`PassthroughFs`](passthroughfs::PassthroughFs) which exposes
//! a single host directory to the guest VM via virtio-fs with stat virtualization.

pub mod dualfs;
pub mod memfs;
pub mod passthroughfs;
pub(crate) mod shared;

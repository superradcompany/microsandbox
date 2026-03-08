//! Filesystem backends for microsandbox.
//!
//! Currently provides [`PassthroughFs`](passthrough::PassthroughFs) which exposes
//! a single host directory to the guest VM via virtio-fs with stat virtualization.

pub mod passthrough;
pub(crate) mod shared;

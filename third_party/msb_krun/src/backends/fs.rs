//! Filesystem backend support.
//!
//! This module re-exports the `DynFileSystem` trait from the devices crate,
//! providing an object-safe filesystem interface for custom implementations.
//!
//! # Example
//!
//! ```rust,no_run
//! use std::ffi::CStr;
//! use std::io;
//! use std::time::Duration;
//! use msb_krun::backends::fs::{DynFileSystem, Context, Entry, FsOptions};
//!
//! struct MyFileSystem {
//!     // ... your implementation
//! }
//!
//! impl DynFileSystem for MyFileSystem {
//!     fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
//!         Ok(FsOptions::empty())
//!     }
//!
//!     fn lookup(&self, ctx: Context, parent: u64, name: &CStr) -> io::Result<Entry> {
//!         // Implement file lookup
//!         todo!()
//!     }
//!
//!     // ... implement other methods as needed
//! }
//! ```

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use devices::virtio::bindings::{stat64, statvfs64};
pub use devices::virtio::fs::dyn_filesystem::{AddDirEntry, AddDirEntryPlus, DynFileSystem};
pub use devices::virtio::fs::filesystem::{
    Context, DirEntry, Entry, Extensions, FsOptions, GetxattrReply, ListxattrReply, OpenOptions,
    RemovemappingOne, SecContext, SetattrValid, ZeroCopyReader, ZeroCopyWriter,
};

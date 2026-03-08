//! `microsandbox-filesystem` provides filesystem backends and utilities for microsandbox,
//! including the embedded agentd binary and the passthrough filesystem backend.

#![warn(missing_docs)]

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub mod agentd;
pub mod backends;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use backends::passthrough::{CachePolicy, PassthroughConfig, PassthroughFs};
pub use msb_krun::backends::fs::{
    stat64, statvfs64, Context, DirEntry, DynFileSystem, Entry, Extensions, FsOptions,
    GetxattrReply, ListxattrReply, OpenOptions, RemovemappingOne, SetattrValid, ZeroCopyReader,
    ZeroCopyWriter,
};

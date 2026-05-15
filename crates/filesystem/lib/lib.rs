//! `microsandbox-filesystem` provides filesystem backends and utilities for microsandbox,
//! including the embedded agentd binary and the passthrough filesystem backend.

#![warn(missing_docs)]
// New lints introduced in rustc 1.95 fire on a few test fixtures;
// cleanup tracked separately.
#![allow(
    clippy::useless_conversion,
    clippy::needless_update,
    clippy::manual_c_str_literals,
    clippy::manual_contains
)]

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub mod agentd;
pub mod backends;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use backends::{
    dualfs::{
        BackendAFallbackToBackendBRead, BackendAOnly, CachePolicy as DualCachePolicy, DualFs,
        DualFsConfig, MergeReadsBackendAPrecedence, ReadBackendBWriteBackendA,
    },
    memfs::{CachePolicy as MemCachePolicy, MemFs, MemFsConfig},
    passthroughfs::{CachePolicy, PassthroughConfig, PassthroughFs, PassthroughFsBuilder},
};
pub use microsandbox_utils::size::{ByteSize, Bytes, Mebibytes, SizeExt};
pub use msb_krun::backends::fs::{
    Context, DirEntry, DynFileSystem, Entry, Extensions, FsOptions, GetxattrReply, ListxattrReply,
    OpenOptions, RemovemappingOne, SetattrValid, ZeroCopyReader, ZeroCopyWriter, stat64, statvfs64,
};

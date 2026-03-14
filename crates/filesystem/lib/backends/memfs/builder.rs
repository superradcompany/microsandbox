//! Builder API for constructing a MemFs instance.
//!
//! ```ignore
//! use microsandbox_filesystem::SizeExt;
//!
//! MemFs::builder()
//!     .capacity(64.mib())
//!     .max_inodes(10_000)
//!     .build()?
//! ```

use std::{
    collections::BTreeMap,
    fs::File,
    io,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64},
    },
    time::Duration,
};

use microsandbox_utils::size::Bytes;

use super::{
    MemFs, inode,
    types::{CachePolicy, InodeContent, InodeMeta, MemFsConfig, MemNode, ROOT_INODE},
};
use crate::backends::shared::init_binary;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Builder for constructing a [`MemFs`] instance.
pub struct MemFsBuilder {
    capacity: Option<u64>,
    max_inodes: Option<u64>,
    entry_timeout: Duration,
    attr_timeout: Duration,
    cache_policy: CachePolicy,
    writeback: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl MemFsBuilder {
    /// Create a new builder with default settings.
    pub(crate) fn new() -> Self {
        Self {
            capacity: None,
            max_inodes: None,
            entry_timeout: Duration::from_secs(5),
            attr_timeout: Duration::from_secs(5),
            cache_policy: CachePolicy::Always,
            writeback: true,
        }
    }

    /// Set the maximum capacity for file data.
    ///
    /// Accepts bare `u64` (interpreted as bytes) or a [`SizeExt`](microsandbox_utils::size::SizeExt) helper:
    ///
    /// ```ignore
    /// .capacity(64.mib())   // 64 MiB
    /// .capacity(1.gib())    // 1 GiB
    /// .capacity(4096)       // 4096 bytes
    /// ```
    pub fn capacity(mut self, size: impl Into<Bytes>) -> Self {
        self.capacity = Some(size.into().as_u64());
        self
    }

    /// Set the maximum number of inodes.
    pub fn max_inodes(mut self, count: u64) -> Self {
        self.max_inodes = Some(count);
        self
    }

    /// Set the FUSE entry cache timeout.
    pub fn entry_timeout(mut self, timeout: Duration) -> Self {
        self.entry_timeout = timeout;
        self
    }

    /// Set the FUSE attribute cache timeout.
    pub fn attr_timeout(mut self, timeout: Duration) -> Self {
        self.attr_timeout = timeout;
        self
    }

    /// Set the cache policy.
    pub fn cache_policy(mut self, policy: CachePolicy) -> Self {
        self.cache_policy = policy;
        self
    }

    /// Enable or disable writeback caching.
    pub fn writeback(mut self, enabled: bool) -> Self {
        self.writeback = enabled;
        self
    }

    /// Build the MemFs instance.
    pub fn build(self) -> io::Result<MemFs> {
        let now = inode::current_time();

        let root = Arc::new(MemNode {
            inode: ROOT_INODE,
            kind: libc::S_IFDIR as u32,
            lookup_refs: AtomicU64::new(u64::MAX / 2),
            meta: RwLock::new(InodeMeta {
                uid: 0,
                gid: 0,
                mode: libc::S_IFDIR as u32 | 0o755,
                rdev: 0,
                nlink: 2,
                size: 0,
                atime: now,
                mtime: now,
                ctime: now,
            }),
            content: InodeContent::Directory {
                children: RwLock::new(BTreeMap::new()),
                parent: AtomicU64::new(ROOT_INODE),
            },
            xattrs: RwLock::new(BTreeMap::new()),
        });

        let mut nodes = BTreeMap::new();
        nodes.insert(ROOT_INODE, root);

        let init_file = init_binary::create_init_file()?;
        let staging_file = create_staging_file()?;

        let cfg = MemFsConfig {
            capacity: self.capacity,
            max_inodes: self.max_inodes,
            entry_timeout: self.entry_timeout,
            attr_timeout: self.attr_timeout,
            cache_policy: self.cache_policy,
            writeback: self.writeback,
        };

        Ok(MemFs {
            nodes: RwLock::new(nodes),
            file_handles: RwLock::new(BTreeMap::new()),
            dir_handles: RwLock::new(BTreeMap::new()),
            next_inode: AtomicU64::new(3),  // 1=root, 2=init
            next_handle: AtomicU64::new(1), // 0=init handle
            used_bytes: AtomicU64::new(0),
            inode_count: AtomicU64::new(1), // root
            writeback: AtomicBool::new(false),
            staging_file: Mutex::new(staging_file),
            init_file,
            cfg,
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Create a staging file for ZeroCopy I/O data transfer.
fn create_staging_file() -> io::Result<File> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::FromRawFd;

        let name = std::ffi::CString::new("memfs-staging").unwrap();
        let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    #[cfg(target_os = "macos")]
    {
        tempfile::tempfile()
    }
}

//! Configuration and construction for the Windows passthrough backend.

use super::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Stat virtualization policy for the Windows passthrough filesystem backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatVirtualization {
    /// Require the Windows metadata store and fail the mount if it is unavailable.
    Strict,

    /// Use the Windows metadata store when available and tolerate an unavailable store.
    Relaxed,

    /// Do not apply virtual uid/gid/mode/rdev metadata.
    Off,
}

/// Host permission propagation policy for the Windows passthrough filesystem backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostPermissions {
    /// Keep guest permission changes in the virtual metadata store only.
    Private,

    /// Mirror ordinary writability to the host readonly attribute where Windows supports it.
    Mirror,
}

/// Configuration for the Windows passthrough filesystem backend.
#[derive(Debug, Clone)]
pub struct PassthroughConfig {
    /// Path to the root directory on the host.
    pub root_dir: PathBuf,

    /// Stat virtualization policy.
    ///
    /// Default: [`StatVirtualization::Strict`].
    pub stat_virtualization: StatVirtualization,

    /// Host permission propagation policy.
    ///
    /// Default: [`HostPermissions::Private`].
    pub host_permissions: HostPermissions,

    /// Whether mutating guest filesystem operations should be rejected.
    pub readonly: bool,

    /// FUSE entry cache timeout.
    pub entry_timeout: Duration,

    /// FUSE attribute cache timeout.
    pub attr_timeout: Duration,

    /// Whether to expose the synthetic `init.krun` entry at the mount root.
    pub inject_init: bool,

    /// Optional guest-write byte budget for this mount's subtree.
    ///
    /// `None` means unbounded. When set, guest-attributable growth past this
    /// many bytes is rejected with `ENOSPC`.
    pub quota_bytes: Option<u64>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PassthroughConfig {
    /// Create a Windows passthrough configuration for `root_dir`.
    pub fn new(root_dir: PathBuf) -> Self {
        Self {
            root_dir,
            ..Default::default()
        }
    }

    /// Whether the virtual stat metadata store is enabled.
    pub(crate) fn stat_virtualization_enabled(&self) -> bool {
        !matches!(self.stat_virtualization, StatVirtualization::Off)
    }

    /// Whether guest chmod/create permission bits should affect host metadata.
    pub(crate) fn mirror_host_permissions(&self) -> bool {
        matches!(self.host_permissions, HostPermissions::Mirror)
    }
}

impl PassthroughFs {
    /// Create a Windows passthrough filesystem rooted at `cfg.root_dir`.
    pub fn new(cfg: PassthroughConfig) -> io::Result<Self> {
        let root = std::fs::canonicalize(&cfg.root_dir).map_err(host_error)?;
        let metadata = std::fs::symlink_metadata(&root).map_err(host_error)?;
        reject_reparse_metadata(&metadata)?;
        if !metadata.file_type().is_dir() {
            return Err(linux_error(LINUX_ENOTDIR));
        }
        let stat_store = StatStore::new(&root, cfg.stat_virtualization)?;

        let init_file = if cfg.inject_init {
            let mut file = tempfile::tempfile().map_err(host_error)?;
            file.write_all(AGENTD_BYTES).map_err(host_error)?;
            file.sync_data().map_err(host_error)?;
            Some(Mutex::new(file))
        } else {
            None
        };

        let quota = cfg
            .quota_bytes
            .map(|limit| super::super::quota::DirQuota::new(root.clone(), limit));

        Ok(Self {
            cfg,
            root,
            inodes: RwLock::new(InodeTable::default()),
            next_inode: AtomicU64::new(INIT_INODE + 1),
            handles: RwLock::new(BTreeMap::new()),
            dir_handles: RwLock::new(BTreeMap::new()),
            next_handle: AtomicU64::new(1),
            init_file,
            stat_store,
            quota,
        })
    }

    pub(super) fn require_writable(&self) -> io::Result<()> {
        if self.cfg.readonly {
            Err(linux_error(LINUX_EROFS))
        } else {
            Ok(())
        }
    }

    /// Seed guest-visible permission bits for an existing host path.
    ///
    /// This is used before the backend is mounted, for host files that need
    /// Linux permission bits Windows cannot represent directly. The same
    /// strict metadata store is used by the mounted backend, so failure here
    /// matches a mount-time stat-virtualization failure.
    pub fn set_path_virtual_permissions(
        root_dir: &Path,
        path: &Path,
        uid: u32,
        gid: u32,
        permissions: u32,
    ) -> io::Result<()> {
        let root = std::fs::canonicalize(root_dir).map_err(host_error)?;
        let root_metadata = std::fs::symlink_metadata(&root).map_err(host_error)?;
        reject_reparse_metadata(&root_metadata)?;
        if !root_metadata.file_type().is_dir() {
            return Err(linux_error(LINUX_ENOTDIR));
        }

        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            root.join(path)
        };
        let path = std::fs::canonicalize(path).map_err(host_error)?;
        let metadata = safe_metadata_under_root(&root, &path)?;
        let mode = (mode_from_metadata(&metadata) & S_IFMT) | (permissions & 0o7777);
        let store = StatStore::new(&root, StatVirtualization::Strict)?
            .ok_or_else(|| linux_error(LINUX_EIO))?;
        store.write(&path, uid, gid, mode, 0)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for PassthroughConfig {
    fn default() -> Self {
        Self {
            root_dir: PathBuf::new(),
            stat_virtualization: StatVirtualization::Strict,
            host_permissions: HostPermissions::Private,
            readonly: false,
            entry_timeout: Duration::from_secs(5),
            attr_timeout: Duration::from_secs(5),
            inject_init: true,
            quota_bytes: None,
        }
    }
}

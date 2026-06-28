//! The [`PathFs`] provider trait and its portable supporting types.
//!
//! A [`PathFs`] implementation is the *semantic* half of a programmable
//! filesystem: it answers operations addressed by **absolute guest path**
//! (e.g. `read("/inbox/msg1.txt")`, `readdir("/inbox")`) and is free to back
//! them with anything — an in-memory map, a database, an object store, or a
//! remote API.
//!
//! The [`VirtualFs`](super::VirtualFs) scaffold owns everything FUSE-shaped —
//! inode allocation, the inode↔path map, open-handle tables, lookup
//! reference counting, `stat64`/`Entry` construction, readdir cookie paging,
//! and zero-copy plumbing — and translates each FUSE request into one of the
//! path-addressed calls below. Providers never see inodes or handles.
//!
//! ## Error reporting
//!
//! Every method returns [`io::Result`]. Errors propagate to the guest as the
//! underlying errno, so construct them with
//! [`io::Error::from_raw_os_error`] using `libc::ENOENT`, `libc::EACCES`, etc.
//! A plain [`io::Error`] without an OS code is surfaced to the guest as `EIO`.
//!
//! ## Trust boundary
//!
//! Providers run in the controlling process and are trusted code. The scaffold
//! filters invalid `readdir` names from guest-visible listings. `.` and `..` in
//! `readdir` output are ignored (the scaffold adds them for the guest). A
//! provider that returns only other invalid names on `rmdir` gets `EIO` rather
//! than silently removing a possibly non-empty directory.

use std::{io, path::Path, time::SystemTime};

use crate::backends::shared::{name_validation, platform};
use crate::{SetattrValid, statvfs64};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The kind of a filesystem node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    /// Regular file.
    File,
    /// Directory.
    Dir,
    /// Symbolic link.
    Symlink,
    /// Character device.
    Char,
    /// Block device.
    Block,
    /// Named pipe (FIFO).
    Fifo,
    /// Unix domain socket.
    Socket,
}

impl NodeKind {
    /// The `S_IF*` type bits for this kind, as a mode value.
    pub fn type_bits(self) -> u32 {
        let bits = match self {
            NodeKind::File => libc::S_IFREG,
            NodeKind::Dir => libc::S_IFDIR,
            NodeKind::Symlink => libc::S_IFLNK,
            NodeKind::Char => libc::S_IFCHR,
            NodeKind::Block => libc::S_IFBLK,
            NodeKind::Fifo => libc::S_IFIFO,
            NodeKind::Socket => libc::S_IFSOCK,
        };
        bits as u32
    }

    /// The directory-entry `d_type` value for this kind.
    pub fn dirent_type(self) -> u32 {
        let dt = match self {
            NodeKind::File => libc::DT_REG,
            NodeKind::Dir => libc::DT_DIR,
            NodeKind::Symlink => libc::DT_LNK,
            NodeKind::Char => libc::DT_CHR,
            NodeKind::Block => libc::DT_BLK,
            NodeKind::Fifo => libc::DT_FIFO,
            NodeKind::Socket => libc::DT_SOCK,
        };
        dt as u32
    }

    /// Recover a kind from `S_IF*` type bits, if recognized.
    pub fn from_mode(mode: u32) -> Option<NodeKind> {
        let ty = mode & (libc::S_IFMT as u32);
        Some(match ty as libc::mode_t {
            libc::S_IFREG => NodeKind::File,
            libc::S_IFDIR => NodeKind::Dir,
            libc::S_IFLNK => NodeKind::Symlink,
            libc::S_IFCHR => NodeKind::Char,
            libc::S_IFBLK => NodeKind::Block,
            libc::S_IFIFO => NodeKind::Fifo,
            libc::S_IFSOCK => NodeKind::Socket,
            _ => return None,
        })
    }
}

/// Portable attributes for a node.
///
/// This is the scaffold-facing metadata shape. The scaffold translates it to
/// the platform `stat64`, filling sensible defaults for any `None` timestamp
/// (current time) and computing `st_blocks` from `size`.
#[derive(Debug, Clone)]
pub struct VAttr {
    /// Node kind. Combined with `mode` to form the full `st_mode`.
    pub kind: NodeKind,
    /// Permission bits (e.g. `0o644`). Type bits are derived from `kind`.
    pub mode: u32,
    /// Size in bytes (0 for non-regular files).
    pub size: u64,
    /// Owner user id.
    pub uid: u32,
    /// Owner group id.
    pub gid: u32,
    /// Hard-link count. `None` lets the scaffold default it (2 for dirs, 1
    /// otherwise).
    pub nlink: Option<u64>,
    /// Device number for `Char`/`Block` nodes; ignored otherwise.
    pub rdev: u32,
    /// Last-access time; `None` => current time.
    pub atime: Option<SystemTime>,
    /// Last-modification time; `None` => current time.
    pub mtime: Option<SystemTime>,
    /// Last status-change time; `None` => current time.
    pub ctime: Option<SystemTime>,
}

impl VAttr {
    /// Construct a regular-file attr with the given permission bits and size.
    pub fn file(mode: u32, size: u64) -> VAttr {
        VAttr::new(NodeKind::File, mode, size)
    }

    /// Construct a directory attr with the given permission bits.
    pub fn dir(mode: u32) -> VAttr {
        VAttr::new(NodeKind::Dir, mode, 0)
    }

    /// Construct an attr of the given kind with current-time stamps and
    /// uid/gid 0.
    pub fn new(kind: NodeKind, mode: u32, size: u64) -> VAttr {
        VAttr {
            kind,
            mode,
            size,
            uid: 0,
            gid: 0,
            nlink: None,
            rdev: 0,
            atime: None,
            mtime: None,
            ctime: None,
        }
    }
}

/// A single entry returned by [`PathFs::readdir`].
///
/// The `.` and `..` entries are synthesized by the scaffold and must **not**
/// be included.
#[derive(Debug, Clone)]
pub struct VDirEntry {
    /// Entry name (a single path component; no `/`).
    pub name: Vec<u8>,
    /// Entry kind, used for the directory-entry `d_type`.
    pub kind: NodeKind,
}

impl VDirEntry {
    /// Construct an entry from a name and kind.
    pub fn new(name: impl Into<Vec<u8>>, kind: NodeKind) -> VDirEntry {
        VDirEntry {
            name: name.into(),
            kind,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait
//--------------------------------------------------------------------------------------------------

/// A path-addressed filesystem backend.
///
/// Implement the required methods to expose a readable, navigable tree;
/// override the provided methods to add writes, links, xattrs, and tuned
/// `statfs`. All paths are absolute and begin with `/`; the root is `/`.
///
/// Implementations must be `Send + Sync`: the scaffold may call methods
/// concurrently from multiple FUSE worker threads.
///
/// Writable providers should override [`rename_with_flags`](Self::rename_with_flags)
/// and enforce `RENAME_NOREPLACE` atomically when the guest must not overwrite
/// an existing destination. The default implementation is best-effort only.
pub trait PathFs: Send + Sync {
    // ---- required: a readable tree -------------------------------------------------------------

    /// Return attributes for the node at `path`, or `ENOENT` if absent.
    fn getattr(&self, path: &Path) -> io::Result<VAttr>;

    /// Fetch attributes for several paths at once, returning one result per
    /// path in order. The outer `Result` is a transport-level failure (e.g. the
    /// channel broke); the inner per-path `Result` is that path's own getattr
    /// outcome. The default calls [`getattr`](Self::getattr) for each path; an
    /// RPC-backed provider overrides it to collapse N round-trips into one.
    fn getattr_many(&self, paths: &[&Path]) -> io::Result<Vec<io::Result<VAttr>>> {
        Ok(paths.iter().map(|p| self.getattr(p)).collect())
    }

    /// List the children of the directory at `path` (excluding `.`/`..`).
    fn readdir(&self, path: &Path) -> io::Result<Vec<VDirEntry>>;

    /// Read up to `size` bytes from the file at `path` starting at `offset`.
    ///
    /// A short read (fewer than `size` bytes) signals end-of-file; returning
    /// an empty `Vec` means EOF.
    fn read(&self, path: &Path, offset: u64, size: u32) -> io::Result<Vec<u8>>;

    // ---- provided: mutations (default `ENOSYS`) ------------------------------------------------

    /// Write `data` to the file at `path` starting at `offset`, returning the
    /// number of bytes accepted. Default: `ENOSYS` (read-only filesystem).
    fn write(&self, path: &Path, offset: u64, data: &[u8]) -> io::Result<usize> {
        let _ = (path, offset, data);
        Err(enosys())
    }

    /// Create a regular file (or special node per `attr.kind`) at `path`.
    /// Default: `ENOSYS`.
    fn create(&self, path: &Path, attr: &VAttr) -> io::Result<VAttr> {
        let _ = (path, attr);
        Err(enosys())
    }

    /// Create a directory at `path` with the given permission bits. Default:
    /// `ENOSYS`.
    fn mkdir(&self, path: &Path, mode: u32) -> io::Result<VAttr> {
        let _ = (path, mode);
        Err(enosys())
    }

    /// Remove the file, symlink, special node, or **empty** directory at
    /// `path`. The scaffold enforces directory-emptiness before calling.
    /// Default: `ENOSYS`.
    fn remove(&self, path: &Path) -> io::Result<()> {
        let _ = path;
        Err(enosys())
    }

    /// Remove an empty directory at `path`.
    ///
    /// The default implementation checks emptiness (with the same readdir-name
    /// filtering as the scaffold) then calls [`remove`](Self::remove).
    /// RPC-backed providers should route this through a single server-side
    /// `Remove` so the check and deletion are atomic.
    fn rmdir(&self, path: &Path) -> io::Result<()> {
        let attr = self.getattr(path)?;
        if attr.kind != NodeKind::Dir {
            return Err(platform::enotdir());
        }
        check_dir_empty_for_rmdir(&self.readdir(path)?)?;
        self.remove(path)
    }

    /// Rename `from` to `to`. The scaffold updates its inode↔path map for the
    /// moved subtree afterward. Default: `ENOSYS`.
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        let _ = (from, to);
        Err(enosys())
    }

    /// Rename `from` to `to`, honoring Linux `renameat2` flags when supported.
    ///
    /// `flags` uses the Linux constants (`RENAME_NOREPLACE` = 1,
    /// `RENAME_EXCHANGE` = 2). The default rejects `RENAME_EXCHANGE` with
    /// `ENOSYS`, performs a best-effort `RENAME_NOREPLACE` pre-check via
    /// [`getattr`](Self::getattr), then calls [`rename`](Self::rename).
    /// Providers that need atomic noreplace semantics should override this
    /// method and enforce them under their own lock.
    fn rename_with_flags(&self, from: &Path, to: &Path, flags: u32) -> io::Result<()> {
        const RENAME_NOREPLACE: u32 = 1;
        const RENAME_EXCHANGE: u32 = 2;
        if flags & RENAME_EXCHANGE != 0 {
            return Err(enosys());
        }
        if flags & RENAME_NOREPLACE != 0 && self.getattr(to).is_ok() {
            return Err(io::Error::from_raw_os_error(libc::EEXIST));
        }
        self.rename(from, to)
    }

    /// Apply the subset of `attr` selected by `valid` to the node at `path`,
    /// returning the resulting attributes. Default: `ENOSYS`.
    fn setattr(&self, path: &Path, attr: &VAttr, valid: SetattrValid) -> io::Result<VAttr> {
        let _ = (path, attr, valid);
        Err(enosys())
    }

    // ---- provided: links (default `ENOSYS`) ----------------------------------------------------

    /// Create a symbolic link at `path` pointing to `target`. Default:
    /// `ENOSYS`.
    fn symlink(&self, path: &Path, target: &[u8]) -> io::Result<VAttr> {
        let _ = (path, target);
        Err(enosys())
    }

    /// Return the target of the symbolic link at `path`. Default: `ENOSYS`.
    fn readlink(&self, path: &Path) -> io::Result<Vec<u8>> {
        let _ = path;
        Err(enosys())
    }

    // ---- provided: extended attributes (default `ENOSYS`) --------------------------------------

    /// Set extended attribute `name` on `path`. Default: `ENOSYS`.
    fn setxattr(&self, path: &Path, name: &[u8], value: &[u8], flags: u32) -> io::Result<()> {
        let _ = (path, name, value, flags);
        Err(enosys())
    }

    /// Get extended attribute `name` from `path`. Default: `ENOSYS`.
    fn getxattr(&self, path: &Path, name: &[u8]) -> io::Result<Vec<u8>> {
        let _ = (path, name);
        Err(enosys())
    }

    /// List the extended-attribute names on `path`. Default: empty list.
    fn listxattr(&self, path: &Path) -> io::Result<Vec<Vec<u8>>> {
        let _ = path;
        Ok(Vec::new())
    }

    /// Remove extended attribute `name` from `path`. Default: `ENOSYS`.
    fn removexattr(&self, path: &Path, name: &[u8]) -> io::Result<()> {
        let _ = (path, name);
        Err(enosys())
    }

    // ---- provided: durability (default no-op) --------------------------------------------------

    /// Flush buffered writes for the file at `path`. Default: success without
    /// calling the provider (no buffered state in the scaffold).
    fn flush(&self, path: &Path) -> io::Result<()> {
        let _ = path;
        Ok(())
    }

    /// Sync the file at `path` to stable storage. When `datasync` is true, only
    /// file data (not metadata) need be synced. Default: success without calling
    /// the provider.
    fn fsync(&self, path: &Path, datasync: bool) -> io::Result<()> {
        let _ = (path, datasync);
        Ok(())
    }

    /// Refresh directory listing state for the directory at `path`.
    ///
    /// The scaffold calls this from [`VirtualFs`](super::VirtualFs) `fsyncdir`
    /// before rebuilding an open handle's snapshot so RPC-backed providers can
    /// drop their paginated `ReadDir` cache. In-process providers may leave
    /// this as a no-op. Default: success without calling the provider.
    fn fsyncdir(&self, path: &Path) -> io::Result<()> {
        let _ = path;
        Ok(())
    }

    // ---- provided: volume stats ----------------------------------------------------------------

    /// Report filesystem statistics. Default: a generic unbounded volume.
    fn statfs(&self) -> io::Result<statvfs64> {
        Ok(default_statvfs())
    }
}

//--------------------------------------------------------------------------------------------------
// Helpers
//--------------------------------------------------------------------------------------------------

/// Enforce scaffold rmdir emptiness rules on a full directory listing.
pub fn check_dir_empty_for_rmdir(entries: &[VDirEntry]) -> io::Result<()> {
    let mut visible = 0usize;
    let mut has_invalid = false;
    for entry in entries {
        if entry.name == b"." || entry.name == b".." {
            continue;
        }
        if name_validation::validate_readdir_name(&entry.name).is_ok() {
            visible += 1;
        } else {
            has_invalid = true;
        }
    }
    if visible > 0 {
        return Err(platform::enotempty());
    }
    if has_invalid {
        return Err(platform::eio());
    }
    Ok(())
}

/// An `ENOSYS` error: "operation not supported by this provider".
fn enosys() -> io::Error {
    io::Error::from_raw_os_error(platform::LINUX_ENOSYS)
}

/// A generic, effectively-unbounded `statvfs64`.
fn default_statvfs() -> statvfs64 {
    let mut st: statvfs64 = unsafe { std::mem::zeroed() };
    st.f_bsize = 4096;
    st.f_frsize = 4096;
    st.f_namemax = 255;
    st
}

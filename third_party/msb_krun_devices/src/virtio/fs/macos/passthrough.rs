// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::btree_map;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::mem::{self, MaybeUninit};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::ptr::null_mut;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use crossbeam_channel::{unbounded, Sender};
use nix::errno::Errno;
use utils::worker_message::WorkerMessage;

use crate::virtio::fs::filesystem::SecContext;

use super::super::super::linux_errno::{linux_error, LINUX_ERANGE};
use super::super::bindings;
use super::super::filesystem::{
    Context, DirEntry, Entry, ExportTable, Extensions, FileSystem, FsOptions, GetxattrReply,
    ListxattrReply, OpenOptions, SetattrValid, ZeroCopyReader, ZeroCopyWriter,
};
use super::super::fuse;
use super::super::multikey::MultikeyBTreeMap;

const INIT_CSTR: &[u8] = b"init.krun\0";
const XATTR_KEY: &[u8] = b"user.containers.override_stat\0";
const SECURITY_CAPABILITY: &[u8] = b"security.capability\0";

const UID_MAX: u32 = u32::MAX - 1;

static INIT_BINARY: &[u8] = include_bytes!("../../../../init");

type Inode = u64;
type Handle = u64;

#[derive(Clone, Copy, PartialOrd, Ord, PartialEq, Eq)]
struct InodeAltKey {
    ino: u64,
    dev: i32,
}

struct InodeData {
    inode: Inode,
    ino: u64,
    dev: i32,
    refcount: AtomicU64,
    unlinked_fd: AtomicI64,
}

enum InodeHandle {
    Fd(RawFd),
    Path(CString),
}

struct CachedDirEntry {
    ino: bindings::ino64_t,
    name: Box<[u8]>,
    type_: u8,
}

struct DirStream {
    entries: Vec<CachedDirEntry>,
    ready: bool,
}

impl DirStream {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            ready: false,
        }
    }

    fn get_entry<'a>(&'a self, offset: u64) -> Option<DirEntry<'a>> {
        self.entries.get(offset as usize).map(|e| DirEntry {
            ino: e.ino,
            // offset points to the next entry, not the current one
            offset: offset + 1,
            type_: u32::from(e.type_),
            name: &e.name,
        })
    }

    fn fill_from_fd(&mut self, fd: RawFd) -> io::Result<()> {
        // fdopendir() takes ownership of the fd, so we need to obtain a new one
        // to be donated.
        let newfd = unsafe { libc::dup(fd) };
        if newfd < 0 {
            return Err(linux_error(io::Error::last_os_error()));
        }
        let dir = unsafe { libc::fdopendir(newfd) };
        if dir.is_null() {
            let err = io::Error::last_os_error();
            let _ = unsafe { libc::close(newfd) };
            return Err(linux_error(err));
        }

        loop {
            // To detect if error happened in readdir we should clear errno
            // before the call and then verify it after
            Errno::clear();
            let dentry = unsafe { libc::readdir(dir) };
            if dentry.is_null() {
                let errno = Errno::last_raw();
                if errno != 0 {
                    let err = io::Error::from_raw_os_error(errno);
                    let _ = unsafe { libc::closedir(dir) };
                    // Error happened in readdir, but we keep the entries we
                    // already read to handle the partial read.
                    return Err(linux_error(err));
                }
                break;
            }
            // SAFETY: dentry is not null.
            // We trust macOS to return correct number of bytes for the name
            // length. The lifetime of a slice does not escape the unsafe block
            // as we copy the data into box right away.
            let name = unsafe {
                let name_len = usize::from((*dentry).d_namlen);
                let name_ptr = (*dentry).d_name.as_ptr().cast();
                let name = std::slice::from_raw_parts(name_ptr, name_len);

                if name == b"." || name == b".." {
                    continue;
                }
                Box::<[u8]>::from(name)
            };

            // SAFETY: dentry is not null.
            let ino = unsafe { (*dentry).d_ino };
            // SAFETY: dentry is not null. The entry types use the same
            // exact constants (`libc::DT_*`) on macOS, Linux, and FUSE.
            let type_ = unsafe { (*dentry).d_type };

            self.entries.push(CachedDirEntry { ino, name, type_ });
        }

        unsafe { libc::closedir(dir) };
        Ok(())
    }
}

struct HandleData {
    inode: Inode,
    file: RwLock<File>,
    dirstream: Mutex<DirStream>,
}

fn ebadf() -> io::Error {
    linux_error(io::Error::from_raw_os_error(libc::EBADF))
}

fn einval() -> io::Error {
    linux_error(io::Error::from_raw_os_error(libc::EINVAL))
}

fn item_to_value(item: &[u8], radix: u32) -> Option<u32> {
    match std::str::from_utf8(item) {
        Ok(val) => match u32::from_str_radix(val, radix) {
            Ok(i) => Some(i),
            Err(e) => {
                debug!("invalid value: {radix} err={e}");
                None
            }
        },
        Err(_) => None,
    }
}

fn get_xattr_common(buf: &[u8]) -> io::Result<(Option<u32>, Option<u32>, Option<u32>)> {
    let mut items = buf.split(|c| *c == b':');

    let uid = match items.next() {
        Some(item) => item_to_value(item, 10),
        None => None,
    };
    let gid = match items.next() {
        Some(item) => item_to_value(item, 10),
        None => None,
    };
    let mode = match items.next() {
        Some(item) => item_to_value(item, 8),
        None => None,
    };

    Ok((uid, gid, mode))
}

fn get_xattr_fstat(
    fd: RawFd,
    st: bindings::stat64,
) -> io::Result<(Option<u32>, Option<u32>, Option<u32>)> {
    let mut buf: Vec<u8> = vec![0; 32];
    let options = if (st.st_mode & libc::S_IFMT) == libc::S_IFLNK {
        libc::XATTR_NOFOLLOW
    } else {
        0
    };
    let res = unsafe {
        libc::fgetxattr(
            fd,
            XATTR_KEY.as_ptr() as *const i8,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            0,
            options,
        )
    };
    if res < 0 {
        debug!("fget_xattr error: {res}");
        return Ok((None, None, None));
    }

    buf.resize(res as usize, 0);

    get_xattr_common(&buf)
}

fn get_xattr_lstat(
    path: &CString,
    st: bindings::stat64,
) -> io::Result<(Option<u32>, Option<u32>, Option<u32>)> {
    let mut buf: Vec<u8> = vec![0; 32];
    let options = if (st.st_mode & libc::S_IFMT) == libc::S_IFLNK {
        libc::XATTR_NOFOLLOW
    } else {
        0
    };
    let res = unsafe {
        libc::getxattr(
            path.as_ptr(),
            XATTR_KEY.as_ptr() as *const i8,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            0,
            options,
        )
    };
    if res < 0 {
        debug!("fget_xattr error: {res}");
        return Ok((None, None, None));
    }

    buf.resize(res as usize, 0);

    get_xattr_common(&buf)
}

fn is_valid_owner(owner: Option<(u32, u32)>) -> bool {
    if let Some(owner) = owner {
        if owner.0 < UID_MAX && owner.1 < UID_MAX {
            return true;
        }
    }

    false
}
// We won't need this once expressions like "if let ... &&" are allowed.
#[allow(clippy::unnecessary_unwrap)]
fn set_xattr_stat(
    file: &InodeHandle,
    st: Option<bindings::stat64>,
    owner: Option<(u32, u32)>,
    mode: Option<u32>,
) -> io::Result<()> {
    let st = st.unwrap_or(istat(file, true)?);
    let options = if (st.st_mode & libc::S_IFMT) == libc::S_IFLNK {
        libc::XATTR_NOFOLLOW
    } else {
        0
    };

    let buf = if is_valid_owner(owner) && mode.is_some() {
        let owner = owner.unwrap();
        let mode = mode.unwrap();
        format!("{}:{}:0{:o}", owner.0, owner.1, mode)
    } else {
        let (orig_uid, orig_gid, orig_mode) = match file {
            InodeHandle::Fd(fd) => get_xattr_fstat(*fd, st)?,
            InodeHandle::Path(ref c_path) => get_xattr_lstat(c_path, st)?,
        };

        let (uid, gid) = match owner {
            Some(o) => {
                let uid = if o.0 < UID_MAX { Some(o.0) } else { orig_uid };
                let gid = if o.1 < UID_MAX { Some(o.1) } else { orig_gid };
                (uid, gid)
            }
            None => (orig_uid, orig_gid),
        };

        let mut buf = String::new();
        if let Some(uid) = uid {
            buf.push_str(&format!("{uid}"));
        } else {
            buf.push('x');
        }
        if let Some(gid) = gid {
            buf.push_str(&format!(":{gid}:"));
        } else {
            buf.push_str(":x:");
        }
        if let Some(mode) = mode {
            buf.push_str(&format!("0{:o}", mode));
        } else if let Some(orig_mode) = orig_mode {
            buf.push_str(&format!("0{:o}", orig_mode));
        } else {
            buf.push('x');
        }
        buf
    };

    let res = match file {
        InodeHandle::Path(path) => unsafe {
            libc::setxattr(
                path.as_ptr(),
                XATTR_KEY.as_ptr() as *const i8,
                buf.as_ptr() as *mut libc::c_void,
                buf.len() as libc::size_t,
                0,
                options,
            )
        },
        InodeHandle::Fd(fd) => unsafe {
            libc::fsetxattr(
                *fd,
                XATTR_KEY.as_ptr() as *const i8,
                buf.as_ptr() as *mut libc::c_void,
                buf.len() as libc::size_t,
                0,
                options,
            )
        },
    };

    if res < 0 {
        Err(linux_error(io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

fn stat_common(
    mut st: bindings::stat64,
    uid: Option<u32>,
    gid: Option<u32>,
    mode: Option<u32>,
    host: bool,
) -> io::Result<bindings::stat64> {
    if !host {
        if let Some(uid) = uid {
            st.st_uid = uid;
        }
        if let Some(gid) = gid {
            st.st_gid = gid;
        }
        if let Some(mode) = mode {
            if mode as u16 & libc::S_IFMT == 0 {
                st.st_mode = (st.st_mode & libc::S_IFMT) | mode as u16;
            } else {
                st.st_mode = mode as u16;
            }
        }
    }

    Ok(st)
}

fn fstat(fd: RawFd, host: bool) -> io::Result<bindings::stat64> {
    let mut st = MaybeUninit::<bindings::stat64>::zeroed();

    // Safe because the kernel will only write data in `st` and we check the return
    // value.
    let res = unsafe { libc::fstat(fd, st.as_mut_ptr()) };
    if res >= 0 {
        // Safe because the kernel guarantees that the struct is now fully initialized.
        let st = unsafe { st.assume_init() };
        if !host {
            let (uid, gid, mode) = get_xattr_fstat(fd, st)?;
            stat_common(st, uid, gid, mode, host)
        } else {
            Ok(st)
        }
    } else {
        Err(linux_error(io::Error::last_os_error()))
    }
}

fn lstat(c_path: &CString, host: bool) -> io::Result<bindings::stat64> {
    let mut st = MaybeUninit::<bindings::stat64>::zeroed();

    // Safe because the kernel will only write data in `st` and we check the return
    // value.
    let res = unsafe { libc::lstat(c_path.as_ptr(), st.as_mut_ptr()) };
    if res >= 0 {
        // Safe because the kernel guarantees that the struct is now fully initialized.
        let st = unsafe { st.assume_init() };
        if !host {
            let (uid, gid, mode) = get_xattr_lstat(c_path, st)?;
            stat_common(st, uid, gid, mode, host)
        } else {
            Ok(st)
        }
    } else {
        Err(linux_error(io::Error::last_os_error()))
    }
}

fn istat(ihandle: &InodeHandle, host: bool) -> io::Result<bindings::stat64> {
    match ihandle {
        InodeHandle::Fd(fd) => fstat(*fd, host),
        InodeHandle::Path(ref c_path) => lstat(c_path, host),
    }
}

/// The caching policy that the file system should report to the FUSE client. By default the FUSE
/// protocol uses close-to-open consistency. This means that any cached contents of the file are
/// invalidated the next time that file is opened.
#[derive(Debug, Default, Clone)]
pub enum CachePolicy {
    /// The client should never cache file data and all I/O should be directly forwarded to the
    /// server. This policy must be selected when file contents may change without the knowledge of
    /// the FUSE client (i.e., the file system does not have exclusive access to the directory).
    Never,

    /// The client is free to choose when and how to cache file data. This is the default policy and
    /// uses close-to-open consistency as described in the enum documentation.
    #[default]
    Auto,

    /// The client should always cache file data. This means that the FUSE client will not
    /// invalidate any cached data that was returned by the file system the last time the file was
    /// opened. This policy should only be selected when the file system has exclusive access to the
    /// directory.
    Always,
}

impl FromStr for CachePolicy {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "never" | "Never" | "NEVER" => Ok(CachePolicy::Never),
            "auto" | "Auto" | "AUTO" => Ok(CachePolicy::Auto),
            "always" | "Always" | "ALWAYS" => Ok(CachePolicy::Always),
            _ => Err("invalid cache policy"),
        }
    }
}

/// Options that configure the behavior of the file system.
#[derive(Debug, Clone)]
pub struct Config {
    /// How long the FUSE client should consider directory entries to be valid. If the contents of a
    /// directory can only be modified by the FUSE client (i.e., the file system has exclusive
    /// access), then this should be a large value.
    ///
    /// The default value for this option is 5 seconds.
    pub entry_timeout: Duration,

    /// How long the FUSE client should consider file and directory attributes to be valid. If the
    /// attributes of a file or directory can only be modified by the FUSE client (i.e., the file
    /// system has exclusive access), then this should be set to a large value.
    ///
    /// The default value for this option is 5 seconds.
    pub attr_timeout: Duration,

    /// The caching policy the file system should use. See the documentation of `CachePolicy` for
    /// more details.
    pub cache_policy: CachePolicy,

    /// Whether the file system should enabled writeback caching. This can improve performance as it
    /// allows the FUSE client to cache and coalesce multiple writes before sending them to the file
    /// system. However, enabling this option can increase the risk of data corruption if the file
    /// contents can change without the knowledge of the FUSE client (i.e., the server does **NOT**
    /// have exclusive access). Additionally, the file system should have read access to all files
    /// in the directory it is serving as the FUSE client may send read requests even for files
    /// opened with `O_WRONLY`.
    ///
    /// Therefore callers should only enable this option when they can guarantee that: 1) the file
    /// system has exclusive access to the directory and 2) the file system has read permissions for
    /// all files in that directory.
    ///
    /// The default value for this option is `false`.
    pub writeback: bool,

    /// The path of the root directory.
    ///
    /// The default is `/`.
    pub root_dir: String,

    /// Whether the file system should support Extended Attributes (xattr). Enabling this feature may
    /// have a significant impact on performance, especially on write parallelism. This is the result
    /// of FUSE attempting to remove the special file privileges after each write request.
    ///
    /// The default value for this options is `false`.
    pub xattr: bool,

    /// Optional file descriptor for /proc/self/fd. Callers can obtain a file descriptor and pass it
    /// here, so there's no need to open it in PassthroughFs::new(). This is specially useful for
    /// sandboxing.
    ///
    /// The default is `None`.
    pub proc_sfd_rawfd: Option<RawFd>,

    /// ID of this filesystem to uniquely identify exports. Not supported for macos.
    pub export_fsid: u64,
    /// Table of exported FDs to share with other subsystems. Not supported for macos.
    pub export_table: Option<ExportTable>,
    pub allow_root_dir_delete: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            entry_timeout: Duration::from_secs(5),
            attr_timeout: Duration::from_secs(5),
            cache_policy: Default::default(),
            writeback: false,
            root_dir: String::from("/"),
            xattr: true,
            proc_sfd_rawfd: None,
            export_fsid: 0,
            export_table: None,
            allow_root_dir_delete: false,
        }
    }
}

/// A file system that simply "passes through" all requests it receives to the underlying file
/// system. To keep the implementation simple it servers the contents of its root directory. Users
/// that wish to serve only a specific directory should set up the environment so that that
/// directory ends up as the root of the file system process. One way to accomplish this is via a
/// combination of mount namespaces and the pivot_root system call.
pub struct PassthroughFs {
    inodes: RwLock<MultikeyBTreeMap<Inode, InodeAltKey, Arc<InodeData>>>,
    next_inode: AtomicU64,
    init_inode: u64,

    handles: RwLock<BTreeMap<Handle, Arc<HandleData>>>,
    next_handle: AtomicU64,
    init_handle: u64,

    map_windows: Mutex<HashMap<u64, u64>>,

    // Whether writeback caching is enabled for this directory. This will only be true when
    // `cfg.writeback` is true and `init` was called with `FsOptions::WRITEBACK_CACHE`.
    writeback: AtomicBool,
    announce_submounts: AtomicBool,
    cfg: Config,
}

impl PassthroughFs {
    pub fn new(cfg: Config) -> io::Result<PassthroughFs> {
        let root = CString::new(cfg.root_dir.as_str()).expect("CString::new failed");

        // Safe because this doesn't modify any memory and we check the return value.
        let fd = unsafe {
            libc::openat(
                libc::AT_FDCWD,
                root.as_ptr(),
                libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(linux_error(io::Error::last_os_error()));
        }

        unsafe { libc::close(fd) };

        Ok(PassthroughFs {
            inodes: RwLock::new(MultikeyBTreeMap::new()),
            next_inode: AtomicU64::new(fuse::ROOT_ID + 2),
            init_inode: fuse::ROOT_ID + 1,

            handles: RwLock::new(BTreeMap::new()),
            next_handle: AtomicU64::new(1),
            init_handle: 0,

            map_windows: Mutex::new(HashMap::new()),

            writeback: AtomicBool::new(false),
            announce_submounts: AtomicBool::new(false),
            cfg,
        })
    }

    fn inode_to_handle(&self, inode: Inode, supports_fd: bool) -> io::Result<InodeHandle> {
        debug!("inode_to_handle: inode={inode}");
        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&inode)
            .cloned()
            .ok_or_else(ebadf)?;

        let cstr =
            CString::new(format!("/.vol/{}/{}", data.dev, data.ino)).map_err(|_| einval())?;
        debug!("inode_to_handle: path={}", cstr.to_string_lossy());

        if supports_fd {
            let unlinked_fd = data.unlinked_fd.load(Ordering::Acquire);
            if unlinked_fd >= 0 {
                return Ok(InodeHandle::Fd(unlinked_fd as RawFd));
            }
        }

        Ok(InodeHandle::Path(cstr))
    }

    fn name_to_path(&self, parent: Inode, name: &CStr) -> io::Result<CString> {
        debug!(
            "name_to_path: parent={} name={}",
            parent,
            name.to_string_lossy()
        );
        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&parent)
            .cloned()
            .ok_or_else(ebadf)?;

        let cstr = CString::new(format!(
            "/.vol/{}/{}/{}",
            data.dev,
            data.ino,
            name.to_string_lossy()
        ))
        .map_err(|_| einval())?;
        debug!("name_to_path: path={}", cstr.to_string_lossy());
        Ok(cstr)
    }

    fn open_inode(&self, inode: Inode, mut flags: i32) -> io::Result<File> {
        // When writeback caching is enabled, the kernel may send read requests even if the
        // userspace program opened the file write-only. So we need to ensure that we have opened
        // the file for reading as well as writing.
        let writeback = self.writeback.load(Ordering::Relaxed);
        if writeback && flags & libc::O_ACCMODE == libc::O_WRONLY {
            flags &= !libc::O_ACCMODE;
            flags |= libc::O_RDWR;
        }

        // When writeback caching is enabled the kernel is responsible for handling `O_APPEND`.
        // However, this breaks atomicity as the file may have changed on disk, invalidating the
        // cached copy of the data in the kernel and the offset that the kernel thinks is the end of
        // the file. Just allow this for now as it is the user's responsibility to enable writeback
        // caching only for directories that are not shared. It also means that we need to clear the
        // `O_APPEND` flag.
        if writeback && flags & libc::O_APPEND != 0 {
            flags &= !libc::O_APPEND;
        }

        let ihandle = self.inode_to_handle(inode, true)?;
        let fd = match ihandle {
            InodeHandle::Path(c_path) => unsafe {
                libc::open(
                    c_path.as_ptr(),
                    (flags | libc::O_CLOEXEC) & (!libc::O_NOFOLLOW) & (!libc::O_EXLOCK),
                )
            },
            // Check if we have recently unlinked the inode and kept open a file descriptor to it.
            InodeHandle::Fd(fd) => unsafe { libc::dup(fd) },
        };
        if fd < 0 {
            return Err(linux_error(io::Error::last_os_error()));
        }

        // Safe because we just opened this fd.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn do_lookup(&self, parent: Inode, name: &CStr) -> io::Result<Entry> {
        let parent_data = self
            .inodes
            .read()
            .unwrap()
            .get(&parent)
            .cloned()
            .ok_or_else(ebadf)?;

        let c_path = self.name_to_path(parent, name)?;
        let st = lstat(&c_path, false)?;

        debug!(
            "do_lookup: inode={} path={}",
            st.st_ino,
            c_path.to_str().unwrap()
        );

        let mut attr_flags: u32 = 0;

        if st.st_mode & libc::S_IFMT == libc::S_IFDIR
            && self.announce_submounts.load(Ordering::Relaxed)
            && (st.st_dev != parent_data.dev)
        {
            attr_flags |= fuse::ATTR_SUBMOUNT;
        }

        let altkey = InodeAltKey {
            ino: st.st_ino,
            dev: st.st_dev,
        };
        let data = self.inodes.read().unwrap().get_alt(&altkey).cloned();

        let inode = if let Some(data) = data {
            // Matches with the release store in `forget`.
            data.refcount.fetch_add(1, Ordering::Acquire);
            data.inode
        } else {
            // There is a possible race here where 2 threads end up adding the same file
            // into the inode list.  However, since each of those will get a unique Inode
            // value and unique file descriptors this shouldn't be that much of a problem.
            let inode = self.next_inode.fetch_add(1, Ordering::Relaxed);
            self.inodes.write().unwrap().insert(
                inode,
                InodeAltKey {
                    ino: st.st_ino,
                    dev: st.st_dev,
                },
                Arc::new(InodeData {
                    inode,
                    ino: st.st_ino,
                    dev: st.st_dev,
                    refcount: AtomicU64::new(1),
                    unlinked_fd: AtomicI64::new(-1),
                }),
            );

            inode
        };

        Ok(Entry {
            inode,
            generation: 0,
            attr: st,
            attr_flags,
            attr_timeout: self.cfg.attr_timeout,
            entry_timeout: self.cfg.entry_timeout,
        })
    }

    fn do_readdir<F>(
        &self,
        inode: Inode,
        handle: Handle,
        size: u32,
        mut offset: u64,
        mut add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry) -> io::Result<usize>,
    {
        if size == 0 {
            return Ok(());
        }

        let data = self
            .handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .cloned()
            .ok_or_else(ebadf)?;

        let mut ds = data.dirstream.lock().unwrap();

        if !ds.ready {
            // Fill the cache on first call
            if let Err(e) = ds.fill_from_fd(data.file.write().unwrap().as_raw_fd()) {
                if ds.entries.is_empty() {
                    return Err(e);
                }
                // If we got some valid entries before error happened,
                // treat this partial read as success and just log
                // the error.
                warn!("virtio-fs: error in readdir {}: {:?}", inode, e);
            }
            ds.ready = true;
        }

        while let Some(entry) = ds.get_entry(offset) {
            offset += 1;

            let name = entry.name;
            match add_entry(entry) {
                Ok(size) => {
                    if size == 0 {
                        break;
                    }
                }
                Err(e) => {
                    warn!(
                        "virtio-fs: error adding entry {}: {:?}",
                        String::from_utf8_lossy(name),
                        e
                    );
                    break;
                }
            }
        }

        Ok(())
    }

    fn do_open(
        &self,
        inode: Inode,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        let flags = self.parse_open_flags(flags as i32);

        let file = RwLock::new(self.open_inode(inode, flags)?);

        // If O_TRUNC and kill_priv (OPEN_KILL_SUIDGID), clear security.capability and suid/sgid
        if (flags & libc::O_TRUNC) != 0 && kill_priv {
            let fd = file.read().unwrap().as_raw_fd();
            let ihandle = InodeHandle::Fd(fd);

            remove_security_capability(&ihandle);

            if let Ok(st) = fstat(fd, false) {
                let new_mode = clear_suid_sgid(st.st_mode as u32);
                if new_mode != st.st_mode as u32 {
                    if let Err(err) = set_xattr_stat(&ihandle, Some(st), None, Some(new_mode)) {
                        error!("Couldn't clear suid/sgid for inode {inode}: {err}");
                    }
                }
            }
        }

        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let data = HandleData {
            inode,
            file,
            dirstream: Mutex::new(DirStream::new()),
        };

        self.handles.write().unwrap().insert(handle, Arc::new(data));

        let mut opts = OpenOptions::empty();
        match self.cfg.cache_policy {
            // We only set the direct I/O option on files.
            CachePolicy::Never => opts.set(OpenOptions::DIRECT_IO, flags & libc::O_DIRECTORY == 0),
            CachePolicy::Always => {
                if flags & libc::O_DIRECTORY == 0 {
                    opts |= OpenOptions::KEEP_CACHE;
                } else {
                    opts |= OpenOptions::CACHE_DIR;
                }
            }
            _ => {}
        };

        Ok((Some(handle), opts))
    }

    fn do_release(&self, inode: Inode, handle: Handle) -> io::Result<()> {
        let mut handles = self.handles.write().unwrap();

        if let btree_map::Entry::Occupied(e) = handles.entry(handle) {
            if e.get().inode == inode {
                // We don't need to close the file here because that will happen automatically when
                // the last `Arc` is dropped.
                e.remove();
                return Ok(());
            }
        }

        Err(ebadf())
    }

    fn do_getattr(&self, inode: Inode) -> io::Result<(bindings::stat64, Duration)> {
        let ihandle = self.inode_to_handle(inode, true)?;
        let st = match ihandle {
            InodeHandle::Path(c_path) => lstat(&c_path, false)?,
            InodeHandle::Fd(fd) => fstat(fd, false)?,
        };

        Ok((st, self.cfg.attr_timeout))
    }

    fn grab_unlinked_fd(&self, parent_fd: RawFd, name: &CStr) -> io::Result<RawFd> {
        let fd =
            unsafe { libc::openat(parent_fd, name.as_ptr(), libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fd)
    }

    fn store_unlinked_fd(&self, unlinked_fd: RawFd) -> io::Result<()> {
        let st = fstat(unlinked_fd, true)?;
        let altkey = InodeAltKey {
            ino: st.st_ino,
            dev: st.st_dev,
        };
        if let Some(data) = self.inodes.read().unwrap().get_alt(&altkey).cloned() {
            data.unlinked_fd
                .store(unlinked_fd as i64, Ordering::Release);
        }
        Ok(())
    }

    fn do_unlink(
        &self,
        _ctx: Context,
        parent: Inode,
        name: &CStr,
        flags: libc::c_int,
    ) -> io::Result<()> {
        let ihandle = self.inode_to_handle(parent, true)?;

        let (fd, close_fd) = match ihandle {
            InodeHandle::Path(c_path) => unsafe {
                (
                    libc::open(c_path.as_ptr(), libc::O_NOFOLLOW | libc::O_CLOEXEC),
                    true,
                )
            },
            InodeHandle::Fd(fd) => (fd, false),
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // After unlinking this inode, we can't keep relying on getting a "/.vol/..." path
        // to operate on it. Before unlinking the inode, grab a file descriptor so we can
        // still operate on it. This one will be closed on "forget_one".
        let unlinked_fd = match self.grab_unlinked_fd(fd, name) {
            Ok(fd) => Some(fd),
            Err(err) => {
                warn!(
                    "Couldn't grab a file descriptor for file \"{}\": {err}",
                    name.to_string_lossy()
                );
                None
            }
        };

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::unlinkat(fd, name.as_ptr(), flags) };
        let err = io::Error::last_os_error();

        if close_fd {
            unsafe { libc::close(fd) };
        }

        if res == 0 {
            if let Some(unlinked_fd) = unlinked_fd {
                if let Err(err) = self.store_unlinked_fd(unlinked_fd) {
                    unsafe { libc::close(unlinked_fd) };
                    warn!("Couldn't store unlinked fd \"{}\": {err}", unlinked_fd);
                }
            }
            Ok(())
        } else {
            if let Some(unlinked_fd) = unlinked_fd {
                unsafe { libc::close(unlinked_fd) };
            }
            Err(linux_error(err))
        }
    }

    fn parse_open_flags(&self, flags: i32) -> i32 {
        let mut mflags: i32 = flags & 0b11;

        if (flags & bindings::LINUX_O_NONBLOCK) != 0 {
            mflags |= libc::O_NONBLOCK;
        }
        if (flags & bindings::LINUX_O_APPEND) != 0 {
            mflags |= libc::O_APPEND;
        }
        if (flags & bindings::LINUX_O_CREAT) != 0 {
            mflags |= libc::O_CREAT;
        }
        if (flags & bindings::LINUX_O_TRUNC) != 0 {
            mflags |= libc::O_TRUNC;
        }
        if (flags & bindings::LINUX_O_EXCL) != 0 {
            mflags |= libc::O_EXCL;
        }
        if (flags & bindings::LINUX_O_NOFOLLOW) != 0 {
            mflags |= libc::O_NOFOLLOW;
        }
        if (flags & bindings::LINUX_O_CLOEXEC) != 0 {
            mflags |= libc::O_CLOEXEC;
        }

        mflags
    }
}

fn set_secctx(file: &InodeHandle, secctx: SecContext, symlink: bool) -> io::Result<()> {
    let options = if symlink { libc::XATTR_NOFOLLOW } else { 0 };
    let ret = match file {
        InodeHandle::Path(path) => unsafe {
            libc::setxattr(
                path.as_ptr(),
                secctx.name.as_ptr(),
                secctx.secctx.as_ptr() as *const libc::c_void,
                secctx.secctx.len(),
                0,
                options,
            )
        },
        InodeHandle::Fd(fd) => unsafe {
            libc::fsetxattr(
                *fd,
                secctx.name.as_ptr(),
                secctx.secctx.as_ptr() as *const libc::c_void,
                secctx.secctx.len(),
                0,
                options,
            )
        },
    };

    if ret != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Remove the security.capability extended attribute
fn remove_security_capability(file: &InodeHandle) {
    let ret = match file {
        InodeHandle::Path(path) => unsafe {
            libc::removexattr(path.as_ptr(), SECURITY_CAPABILITY.as_ptr() as *const i8, 0)
        },
        InodeHandle::Fd(fd) => unsafe {
            libc::fremovexattr(*fd, SECURITY_CAPABILITY.as_ptr() as *const i8, 0)
        },
    };

    // ENODATA means the attribute didn't exist, which is fine
    if ret != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ENODATA) {
        warn!("Error removing security.capability from file");
    }
}

/// Clear suid/sgid bits from mode.
/// sgid is cleared only if group executable bit is set.
fn clear_suid_sgid(mode: u32) -> u32 {
    let mut new_mode = mode;

    // Clear suid bit
    new_mode &= !libc::S_ISUID as u32;

    // Clear sgid bit only if group executable bit is set
    if (mode & libc::S_IXGRP as u32) != 0 {
        new_mode &= !libc::S_ISGID as u32;
    }

    new_mode
}

fn forget_one(
    inodes: &mut MultikeyBTreeMap<Inode, InodeAltKey, Arc<InodeData>>,
    inode: Inode,
    count: u64,
) {
    if let Some(data) = inodes.get(&inode) {
        // Acquiring the write lock on the inode map prevents new lookups from incrementing the
        // refcount but there is the possibility that a previous lookup already acquired a
        // reference to the inode data and is in the process of updating the refcount so we need
        // to loop here until we can decrement successfully.
        loop {
            let refcount = data.refcount.load(Ordering::Relaxed);

            // Saturating sub because it doesn't make sense for a refcount to go below zero and
            // we don't want misbehaving clients to cause integer overflow.
            let new_count = refcount.saturating_sub(count);

            // Synchronizes with the acquire load in `do_lookup`.
            if data
                .refcount
                .compare_exchange(refcount, new_count, Ordering::Release, Ordering::Relaxed)
                .unwrap()
                == refcount
            {
                if new_count == 0 {
                    // If we have unlinked this inode, we have opened a file descriptor to be
                    // able to operate on it without a path. Close it now.
                    let fd = data.unlinked_fd.load(Ordering::Acquire);
                    if fd >= 0 {
                        unsafe { libc::close(fd as RawFd) };
                    }
                    // We just removed the last refcount for this inode. There's no need for an
                    // acquire fence here because we hold a write lock on the inode map and any
                    // thread that is waiting to do a forget on the same inode will have to wait
                    // until we release the lock. So there's is no other release store for us to
                    // synchronize with before deleting the entry.
                    inodes.remove(&inode);
                }
                break;
            }
        }
    }
}

impl FileSystem for PassthroughFs {
    type Inode = Inode;
    type Handle = Handle;

    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        let root = CString::new(self.cfg.root_dir.as_str()).expect("CString::new failed");

        // Safe because this doesn't modify any memory and we check the return value.
        // We use `O_PATH` because we just want this for traversing the directory tree
        // and not for actually reading the contents.
        let fd = unsafe {
            libc::openat(
                libc::AT_FDCWD,
                root.as_ptr(),
                libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Safe because we just opened this fd above.
        let f = unsafe { File::from_raw_fd(fd) };

        let st = fstat(f.as_raw_fd(), true)?;

        // Safe because this doesn't modify any memory and there is no need to check the return
        // value because this system call always succeeds. We need to clear the umask here because
        // we want the client to be able to set all the bits in the mode.
        unsafe { libc::umask(0o000) };

        let mut inodes = self.inodes.write().unwrap();

        // Not sure why the root inode gets a refcount of 2 but that's what libfuse does.
        inodes.insert(
            fuse::ROOT_ID,
            InodeAltKey {
                ino: st.st_ino,
                dev: st.st_dev,
            },
            Arc::new(InodeData {
                inode: fuse::ROOT_ID,
                ino: st.st_ino,
                dev: st.st_dev,
                refcount: AtomicU64::new(2),
                unlinked_fd: AtomicI64::new(-1),
            }),
        );

        let mut opts = FsOptions::empty();
        if self.cfg.writeback && capable.contains(FsOptions::WRITEBACK_CACHE) {
            opts |= FsOptions::WRITEBACK_CACHE;
            self.writeback.store(true, Ordering::Relaxed);
        }

        if capable.contains(FsOptions::SUBMOUNTS) {
            opts |= FsOptions::SUBMOUNTS;
            self.announce_submounts.store(true, Ordering::Relaxed);
        }

        Ok(opts)
    }

    fn destroy(&self) {
        self.handles.write().unwrap().clear();
        self.inodes.write().unwrap().clear();
    }

    fn statfs(&self, _ctx: Context, inode: Inode) -> io::Result<bindings::statvfs64> {
        let mut out = MaybeUninit::<bindings::statvfs64>::zeroed();

        let res = match self.inode_to_handle(inode, true)? {
            InodeHandle::Path(c_path) => unsafe {
                bindings::statvfs64(c_path.as_ptr(), out.as_mut_ptr())
            },
            InodeHandle::Fd(fd) => unsafe { bindings::fstatvfs64(fd, out.as_mut_ptr()) },
        };
        if res == 0 {
            // Safe because the kernel guarantees that `out` has been initialized.
            Ok(unsafe { out.assume_init() })
        } else {
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn lookup(&self, _ctx: Context, parent: Inode, name: &CStr) -> io::Result<Entry> {
        debug!("lookup: {name:?}");
        let _init_name = unsafe { CStr::from_bytes_with_nul_unchecked(INIT_CSTR) };

        if self.init_inode != 0 && name == _init_name {
            let mut st: bindings::stat64 = unsafe { mem::zeroed() };
            st.st_size = INIT_BINARY.len() as i64;
            st.st_ino = self.init_inode;
            st.st_mode = 0o100_755;

            Ok(Entry {
                inode: self.init_inode,
                generation: 0,
                attr: st,
                attr_flags: 0,
                attr_timeout: self.cfg.attr_timeout,
                entry_timeout: self.cfg.entry_timeout,
            })
        } else {
            self.do_lookup(parent, name)
        }
    }

    fn forget(&self, _ctx: Context, inode: Inode, count: u64) {
        let mut inodes = self.inodes.write().unwrap();

        forget_one(&mut inodes, inode, count)
    }

    fn batch_forget(&self, _ctx: Context, requests: Vec<(Inode, u64)>) {
        let mut inodes = self.inodes.write().unwrap();

        for (inode, count) in requests {
            forget_one(&mut inodes, inode, count)
        }
    }

    fn opendir(
        &self,
        _ctx: Context,
        inode: Inode,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        self.do_open(inode, false, flags | libc::O_DIRECTORY as u32)
    }

    fn releasedir(
        &self,
        _ctx: Context,
        inode: Inode,
        _flags: u32,
        handle: Handle,
    ) -> io::Result<()> {
        self.do_release(inode, handle)
    }

    fn mkdir(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        let c_path = self.name_to_path(parent, name)?;

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::mkdir(c_path.as_ptr(), 0o700) };
        if res == 0 {
            let ihandle = InodeHandle::Path(c_path);
            // Set security context
            if let Some(secctx) = extensions.secctx {
                set_secctx(&ihandle, secctx, false)?
            };

            set_xattr_stat(
                &ihandle,
                None,
                Some((ctx.uid, ctx.gid)),
                Some(mode & !umask),
            )?;
            self.do_lookup(parent, name)
        } else {
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn rmdir(&self, ctx: Context, parent: Inode, name: &CStr) -> io::Result<()> {
        self.do_unlink(ctx, parent, name, libc::AT_REMOVEDIR)
    }

    fn readdir<F>(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        size: u32,
        offset: u64,
        add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry) -> io::Result<usize>,
    {
        self.do_readdir(inode, handle, size, offset, add_entry)
    }

    fn readdirplus<F>(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        size: u32,
        offset: u64,
        mut add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry, Entry) -> io::Result<usize>,
    {
        self.do_readdir(inode, handle, size, offset, |dir_entry| {
            // Safe because the kernel guarantees that the buffer is nul-terminated. Additionally,
            // the kernel will pad the name with '\0' bytes up to 8-byte alignment and there's no
            // way for us to know exactly how many padding bytes there are. This would cause
            // `CStr::from_bytes_with_nul` to return an error because it would think there are
            // interior '\0' bytes. We trust the kernel to provide us with properly formatted data
            // so we'll just skip the checks here.
            let name = unsafe { CStr::from_bytes_with_nul_unchecked(dir_entry.name) };
            let entry = self.do_lookup(inode, name)?;

            add_entry(dir_entry, entry)
        })
    }

    fn open(
        &self,
        _ctx: Context,
        inode: Inode,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        if inode == self.init_inode {
            Ok((Some(self.init_handle), OpenOptions::empty()))
        } else {
            self.do_open(inode, kill_priv, flags)
        }
    }

    fn release(
        &self,
        _ctx: Context,
        inode: Inode,
        _flags: u32,
        handle: Handle,
        _flush: bool,
        _flock_release: bool,
        _lock_owner: Option<u64>,
    ) -> io::Result<()> {
        self.do_release(inode, handle)
    }

    fn create(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        kill_priv: bool,
        flags: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<(Entry, Option<Handle>, OpenOptions)> {
        let c_path = self.name_to_path(parent, name)?;

        let flags = self.parse_open_flags(flags as i32);
        let hostmode = if (flags & libc::O_DIRECTORY) != 0 {
            0o700
        } else {
            0o600
        };

        // Safe because this doesn't modify any memory and we check the return value. We don't
        // really check `flags` because if the kernel can't handle poorly specified flags then we
        // have much bigger problems.
        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                flags | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                hostmode,
            )
        };
        if fd < 0 {
            return Err(linux_error(io::Error::last_os_error()));
        }
        let ihandle = InodeHandle::Fd(fd);

        if let Err(e) = set_xattr_stat(
            &ihandle,
            None,
            Some((ctx.uid, ctx.gid)),
            Some(libc::S_IFREG as u32 | (mode & !(umask & 0o777))),
        ) {
            unsafe { libc::close(fd) };
            return Err(e);
        }

        // Set security context
        if let Some(secctx) = extensions.secctx {
            set_secctx(&ihandle, secctx, false)?
        };

        // If O_TRUNC and kill_priv (OPEN_KILL_SUIDGID), clear security.capability.
        // We don't need to clear suid/sgid here because we've just updated them
        // unconditionally above.
        if (flags & libc::O_TRUNC) != 0 && kill_priv {
            remove_security_capability(&ihandle);
        }

        // Safe because we just opened this fd.
        let file = RwLock::new(unsafe { File::from_raw_fd(fd) });

        let entry = self.do_lookup(parent, name)?;

        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let data = HandleData {
            inode: entry.inode,
            file,
            dirstream: Mutex::new(DirStream::new()),
        };

        self.handles.write().unwrap().insert(handle, Arc::new(data));

        let mut opts = OpenOptions::empty();
        match self.cfg.cache_policy {
            CachePolicy::Never => opts |= OpenOptions::DIRECT_IO,
            CachePolicy::Always => opts |= OpenOptions::KEEP_CACHE,
            _ => {}
        };

        Ok((entry, Some(handle), opts))
    }

    fn unlink(&self, ctx: Context, parent: Inode, name: &CStr) -> io::Result<()> {
        self.do_unlink(ctx, parent, name, 0)
    }

    fn read<W: io::Write + ZeroCopyWriter>(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        mut w: W,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _flags: u32,
    ) -> io::Result<usize> {
        debug!("read: {inode:?}");
        if inode == self.init_inode {
            let off: usize = offset
                .try_into()
                .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
            let len = if off + (size as usize) < INIT_BINARY.len() {
                size as usize
            } else {
                INIT_BINARY.len() - off
            };
            return w.write(&INIT_BINARY[off..(off + len)]);
        }

        let data = self
            .handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .cloned()
            .ok_or_else(ebadf)?;

        // This is safe because write_from uses preadv64, so the underlying file descriptor
        // offset is not affected by this operation.
        let f = data.file.read().unwrap();
        w.write_from(&f, size as usize, offset)
    }

    fn write<R: io::Read + ZeroCopyReader>(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        mut r: R,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _delayed_write: bool,
        kill_priv: bool,
        _flags: u32,
    ) -> io::Result<usize> {
        let data = self
            .handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .cloned()
            .ok_or_else(ebadf)?;

        // This is safe because read_to uses pwritev64, so the underlying file descriptor
        // offset is not affected by this operation.
        let f = data.file.read().unwrap();
        let result = r.read_to(&f, size as usize, offset);

        // If write succeeded and kill_priv is set, clear security.capability and suid/sgid
        if result.is_ok() && kill_priv {
            let fd = f.as_raw_fd();
            let ihandle = InodeHandle::Fd(fd);

            remove_security_capability(&ihandle);

            if let Ok(st) = fstat(fd, false) {
                let new_mode = clear_suid_sgid(st.st_mode as u32);
                if new_mode != st.st_mode as u32 {
                    // Update mode in xattr
                    if let Err(err) = set_xattr_stat(&ihandle, Some(st), None, Some(new_mode)) {
                        error!("Couldn't clear suid/sgid for inode {inode}: {err}");
                    }
                }
            }
        }

        result
    }

    fn getattr(
        &self,
        _ctx: Context,
        inode: Inode,
        _handle: Option<Handle>,
    ) -> io::Result<(bindings::stat64, Duration)> {
        self.do_getattr(inode)
    }

    fn setattr(
        &self,
        _ctx: Context,
        inode: Inode,
        attr: bindings::stat64,
        handle: Option<Handle>,
        valid: SetattrValid,
    ) -> io::Result<(bindings::stat64, Duration)> {
        // If we have a handle then use it otherwise get a new fd from the inode.
        let ihandle = if let Some(handle) = handle {
            let hd = self
                .handles
                .read()
                .unwrap()
                .get(&handle)
                .filter(|hd| hd.inode == inode)
                .cloned()
                .ok_or_else(ebadf)?;

            let fd = hd.file.write().unwrap().as_raw_fd();
            InodeHandle::Fd(fd)
        } else {
            self.inode_to_handle(inode, true)?
        };

        if valid.contains(SetattrValid::MODE) {
            set_xattr_stat(&ihandle, None, None, Some(attr.st_mode as u32))?
        }

        if valid.intersects(SetattrValid::UID | SetattrValid::GID) {
            let uid = if valid.contains(SetattrValid::UID) {
                attr.st_uid
            } else {
                // Cannot use -1 here because these are unsigned values.
                u32::MAX
            };
            let gid = if valid.contains(SetattrValid::GID) {
                attr.st_gid
            } else {
                // Cannot use -1 here because these are unsigned values.
                u32::MAX
            };

            remove_security_capability(&ihandle);
            let st = istat(&ihandle, false)?;

            // Clear suid/sgid if UID or GID is being changed
            let new_mode = clear_suid_sgid(st.st_mode as u32);
            let new_mode = if new_mode != st.st_mode as u32 {
                Some(new_mode)
            } else {
                None
            };
            set_xattr_stat(&ihandle, Some(st), Some((uid, gid)), new_mode)?;
        }

        if valid.contains(SetattrValid::SIZE) {
            // Safe because this doesn't modify any memory and we check the return value.
            match ihandle {
                InodeHandle::Fd(fd) => {
                    let res = unsafe { libc::ftruncate(fd, attr.st_size) };
                    if res < 0 {
                        return Err(linux_error(io::Error::last_os_error()));
                    }

                    // Clear security.capability on truncate unconditionally
                    remove_security_capability(&ihandle);
                    let st = fstat(fd, false)?;
                    let new_mode = clear_suid_sgid(st.st_mode as u32);
                    if new_mode != st.st_mode as u32 {
                        set_xattr_stat(&ihandle, Some(st), None, Some(new_mode))?;
                    }
                }
                InodeHandle::Path(_) => {
                    // There is no `ftruncateat` so we need to get a new fd and truncate it.
                    let f = self.open_inode(inode, libc::O_NONBLOCK | libc::O_RDWR)?;
                    let res = unsafe { libc::ftruncate(f.as_raw_fd(), attr.st_size) };
                    if res < 0 {
                        return Err(linux_error(io::Error::last_os_error()));
                    }

                    // Clear security.capability on truncate unconditionally
                    //
                    // Do this here even if it means duplicating the code above to be able to
                    // reuse the FD we just opened, thus reducing the number of syscalls.
                    let ihandle = InodeHandle::Fd(f.as_raw_fd());
                    remove_security_capability(&ihandle);
                    let st = istat(&ihandle, false)?;
                    let new_mode = clear_suid_sgid(st.st_mode as u32);
                    if new_mode != st.st_mode as u32 {
                        set_xattr_stat(&ihandle, Some(st), None, Some(new_mode))?;
                    }
                }
            };
        }

        if valid.intersects(SetattrValid::ATIME | SetattrValid::MTIME) {
            let mut tvs = [
                libc::timespec {
                    tv_sec: 0,
                    tv_nsec: libc::UTIME_OMIT,
                },
                libc::timespec {
                    tv_sec: 0,
                    tv_nsec: libc::UTIME_OMIT,
                },
            ];

            if valid.contains(SetattrValid::ATIME_NOW) {
                tvs[0].tv_nsec = libc::UTIME_NOW;
            } else if valid.contains(SetattrValid::ATIME) {
                tvs[0].tv_sec = attr.st_atime;
                tvs[0].tv_nsec = attr.st_atime_nsec;
            }

            if valid.contains(SetattrValid::MTIME_NOW) {
                tvs[1].tv_nsec = libc::UTIME_NOW;
            } else if valid.contains(SetattrValid::MTIME) {
                tvs[1].tv_sec = attr.st_mtime;
                tvs[1].tv_nsec = attr.st_mtime_nsec;
            }

            // Safe because this doesn't modify any memory and we check the return value.
            let res = match ihandle {
                InodeHandle::Fd(fd) => unsafe { libc::futimens(fd, tvs.as_ptr()) },
                InodeHandle::Path(ref c_path) => unsafe {
                    let fd = libc::open(c_path.as_ptr(), libc::O_SYMLINK | libc::O_CLOEXEC);
                    let res = libc::futimens(fd, tvs.as_ptr());
                    libc::close(fd);
                    res
                },
            };
            if res < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        self.do_getattr(inode)
    }

    fn rename(
        &self,
        ctx: Context,
        olddir: Inode,
        oldname: &CStr,
        newdir: Inode,
        newname: &CStr,
        flags: u32,
    ) -> io::Result<()> {
        let mut mflags: u32 = 0;
        if ((flags as i32) & bindings::LINUX_RENAME_NOREPLACE) != 0 {
            mflags |= libc::RENAME_EXCL;
        }
        if ((flags as i32) & bindings::LINUX_RENAME_EXCHANGE) != 0 {
            mflags |= libc::RENAME_SWAP;
        }

        if ((flags as i32) & bindings::LINUX_RENAME_WHITEOUT) != 0
            && ((flags as i32) & bindings::LINUX_RENAME_EXCHANGE) != 0
        {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EINVAL)));
        }

        let old_cpath = self.name_to_path(olddir, oldname)?;
        let new_cpath = self.name_to_path(newdir, newname)?;

        let res = unsafe { libc::renamex_np(old_cpath.as_ptr(), new_cpath.as_ptr(), mflags) };
        if res == 0 {
            if ((flags as i32) & bindings::LINUX_RENAME_WHITEOUT) != 0 {
                let fd = unsafe {
                    libc::open(
                        old_cpath.as_ptr(),
                        libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                        0o600,
                    )
                };
                if fd > 0 {
                    if let Err(e) = set_xattr_stat(
                        &InodeHandle::Fd(fd),
                        None,
                        None,
                        Some((libc::S_IFCHR | 0o600) as u32),
                    ) {
                        unsafe { libc::close(fd) };
                        return Err(e);
                    }
                    unsafe { libc::close(fd) };
                }
            }

            let entry = self.do_lookup(newdir, newname)?;
            self.forget(ctx, entry.inode, 1);

            Ok(())
        } else {
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn mknod(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        _rdev: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        let c_path = self.name_to_path(parent, name)?;

        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if fd < 0 {
            Err(linux_error(io::Error::last_os_error()))
        } else {
            let ihandle = InodeHandle::Fd(fd);

            // Set security context
            if let Some(secctx) = extensions.secctx {
                set_secctx(&ihandle, secctx, false)?
            };

            if let Err(e) = set_xattr_stat(
                &ihandle,
                None,
                Some((ctx.uid, ctx.gid)),
                Some(mode & !umask),
            ) {
                unsafe { libc::close(fd) };
                return Err(e);
            }

            unsafe { libc::close(fd) };
            self.do_lookup(parent, name)
        }
    }

    fn link(
        &self,
        _ctx: Context,
        inode: Inode,
        newparent: Inode,
        newname: &CStr,
    ) -> io::Result<Entry> {
        let orig_c_path = match self.inode_to_handle(inode, false)? {
            InodeHandle::Path(c_path) => c_path,
            InodeHandle::Fd(_) => return Err(ebadf()),
        };
        let link_c_path = self.name_to_path(newparent, newname)?;

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::link(orig_c_path.as_ptr(), link_c_path.as_ptr()) };
        if res == 0 {
            self.do_lookup(newparent, newname)
        } else {
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn symlink(
        &self,
        ctx: Context,
        linkname: &CStr,
        parent: Inode,
        name: &CStr,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        let c_path = self.name_to_path(parent, name)?;

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::symlink(linkname.as_ptr(), c_path.as_ptr()) };
        if res == 0 {
            let ihandle = InodeHandle::Path(c_path);

            // Set security context
            if let Some(secctx) = extensions.secctx {
                set_secctx(&ihandle, secctx, true)?
            };

            let mut entry = self.do_lookup(parent, name)?;
            let mode = libc::S_IFLNK | 0o777;
            set_xattr_stat(&ihandle, None, Some((ctx.uid, ctx.gid)), Some(mode as u32))?;
            entry.attr.st_uid = ctx.uid;
            entry.attr.st_gid = ctx.gid;
            entry.attr.st_mode = mode;
            Ok(entry)
        } else {
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn readlink(&self, _ctx: Context, inode: Inode) -> io::Result<Vec<u8>> {
        let mut buf = vec![0; libc::PATH_MAX as usize];

        let res = match self.inode_to_handle(inode, true)? {
            InodeHandle::Path(c_path) => unsafe {
                libc::readlink(
                    c_path.as_ptr(),
                    buf.as_mut_ptr() as *mut libc::c_char,
                    buf.len(),
                )
            },
            InodeHandle::Fd(fd) => unsafe {
                libc::freadlink(fd, buf.as_mut_ptr() as *mut libc::c_char, buf.len()) as isize
            },
        };
        if res < 0 {
            return Err(linux_error(io::Error::last_os_error()));
        }

        buf.resize(res as usize, 0);
        Ok(buf)
    }

    fn flush(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        _lock_owner: u64,
    ) -> io::Result<()> {
        let data = self
            .handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .cloned()
            .ok_or_else(ebadf)?;

        // Since this method is called whenever an fd is closed in the client, we can emulate that
        // behavior by doing the same thing (dup-ing the fd and then immediately closing it). Safe
        // because this doesn't modify any memory and we check the return values.
        unsafe {
            let newfd = libc::dup(data.file.write().unwrap().as_raw_fd());
            if newfd < 0 {
                return Err(linux_error(io::Error::last_os_error()));
            }

            if libc::close(newfd) < 0 {
                Err(linux_error(io::Error::last_os_error()))
            } else {
                Ok(())
            }
        }
    }

    fn fsync(
        &self,
        _ctx: Context,
        inode: Inode,
        _datasync: bool,
        handle: Handle,
    ) -> io::Result<()> {
        let data = self
            .handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .cloned()
            .ok_or_else(ebadf)?;

        let fd = data.file.write().unwrap().as_raw_fd();

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::fsync(fd) };

        if res == 0 {
            Ok(())
        } else {
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn fsyncdir(
        &self,
        ctx: Context,
        inode: Inode,
        datasync: bool,
        handle: Handle,
    ) -> io::Result<()> {
        self.fsync(ctx, inode, datasync, handle)
    }

    fn access(&self, ctx: Context, inode: Inode, mask: u32) -> io::Result<()> {
        let st = match self.inode_to_handle(inode, true)? {
            InodeHandle::Path(c_path) => lstat(&c_path, false)?,
            InodeHandle::Fd(fd) => fstat(fd, false)?,
        };

        let mode = mask as i32 & (libc::R_OK | libc::W_OK | libc::X_OK);

        if mode == libc::F_OK {
            // The file exists since we were able to call `stat(2)` on it.
            return Ok(());
        }

        // We use ctx.uid/ctx.gid for these checks, but when idmapped mounts
        // support is enabled on the guest side, it means that "default_permissions"
        // flag is set on virtiofs mount and FUSE_ACCESS request should never be
        // sent to the userspace. Please, refer to the kernel commit
        // ("fs/fuse: warn if fuse_access is called when idmapped mounts are allowed").
        // In case when idmapped mounts are not enabled we are good to rely on ctx.uid/ctx.gid values.

        if (mode & libc::R_OK) != 0
            && ctx.uid != 0
            && (st.st_uid != ctx.uid || st.st_mode & 0o400 == 0)
            && (st.st_gid != ctx.gid || st.st_mode & 0o040 == 0)
            && st.st_mode & 0o004 == 0
        {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EACCES)));
        }

        if (mode & libc::W_OK) != 0
            && ctx.uid != 0
            && (st.st_uid != ctx.uid || st.st_mode & 0o200 == 0)
            && (st.st_gid != ctx.gid || st.st_mode & 0o020 == 0)
            && st.st_mode & 0o002 == 0
        {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EACCES)));
        }

        // root can only execute something if it is executable by one of the owner, the group, or
        // everyone.
        if (mode & libc::X_OK) != 0
            && (ctx.uid != 0 || st.st_mode & 0o111 == 0)
            && (st.st_uid != ctx.uid || st.st_mode & 0o100 == 0)
            && (st.st_gid != ctx.gid || st.st_mode & 0o010 == 0)
            && st.st_mode & 0o001 == 0
        {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EACCES)));
        }

        Ok(())
    }

    fn setxattr(
        &self,
        _ctx: Context,
        inode: Inode,
        name: &CStr,
        value: &[u8],
        flags: u32,
    ) -> io::Result<()> {
        debug!("setxattr: inode={inode} name={name:?} value={value:?}");

        if !self.cfg.xattr {
            return Err(linux_error(io::Error::from_raw_os_error(libc::ENOSYS)));
        }

        if name.to_bytes() == XATTR_KEY {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EACCES)));
        }

        let mut mflags: i32 = 0;
        if (flags as i32) & bindings::LINUX_XATTR_CREATE != 0 {
            mflags |= libc::XATTR_CREATE;
        }
        if (flags as i32) & bindings::LINUX_XATTR_REPLACE != 0 {
            mflags |= libc::XATTR_REPLACE;
        }

        // Safe because this doesn't modify any memory and we check the return value.
        let res = match self.inode_to_handle(inode, true)? {
            InodeHandle::Path(c_path) => unsafe {
                libc::setxattr(
                    c_path.as_ptr(),
                    name.as_ptr(),
                    value.as_ptr() as *const libc::c_void,
                    value.len(),
                    0,
                    mflags as libc::c_int,
                )
            },
            InodeHandle::Fd(fd) => unsafe {
                libc::fsetxattr(
                    fd,
                    name.as_ptr(),
                    value.as_ptr() as *const libc::c_void,
                    value.len(),
                    0,
                    mflags as libc::c_int,
                )
            },
        };

        if res == 0 {
            Ok(())
        } else {
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn getxattr(
        &self,
        _ctx: Context,
        inode: Inode,
        name: &CStr,
        size: u32,
    ) -> io::Result<GetxattrReply> {
        debug!("getxattr: inode={inode} name={name:?}, size={size}");

        if !self.cfg.xattr {
            return Err(linux_error(io::Error::from_raw_os_error(libc::ENOSYS)));
        }

        if inode == self.init_inode {
            return Err(linux_error(io::Error::from_raw_os_error(libc::ENODATA)));
        }

        if name.to_bytes() == XATTR_KEY {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EACCES)));
        }

        let mut buf = vec![0; size as usize];

        // Safe because this will only modify the contents of `buf`
        let res = match self.inode_to_handle(inode, true)? {
            InodeHandle::Path(c_path) => unsafe {
                if size == 0 {
                    libc::getxattr(
                        c_path.as_ptr(),
                        name.as_ptr(),
                        std::ptr::null_mut(),
                        size as libc::size_t,
                        0,
                        0,
                    )
                } else {
                    libc::getxattr(
                        c_path.as_ptr(),
                        name.as_ptr(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        size as libc::size_t,
                        0,
                        0,
                    )
                }
            },
            InodeHandle::Fd(fd) => unsafe {
                if size == 0 {
                    libc::fgetxattr(
                        fd,
                        name.as_ptr(),
                        std::ptr::null_mut(),
                        size as libc::size_t,
                        0,
                        0,
                    )
                } else {
                    libc::fgetxattr(
                        fd,
                        name.as_ptr(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        size as libc::size_t,
                        0,
                        0,
                    )
                }
            },
        };
        if res < 0 {
            return Err(linux_error(io::Error::last_os_error()));
        }

        if size == 0 {
            Ok(GetxattrReply::Count(res as u32))
        } else {
            buf.resize(res as usize, 0);
            Ok(GetxattrReply::Value(buf))
        }
    }

    fn listxattr(&self, _ctx: Context, inode: Inode, size: u32) -> io::Result<ListxattrReply> {
        if !self.cfg.xattr {
            return Err(linux_error(io::Error::from_raw_os_error(libc::ENOSYS)));
        }

        let mut buf = vec![0; 512_usize];

        // Safe because this will only modify the contents of `buf`.
        let res = match self.inode_to_handle(inode, true)? {
            InodeHandle::Path(c_path) => unsafe {
                libc::listxattr(
                    c_path.as_ptr(),
                    buf.as_mut_ptr() as *mut libc::c_char,
                    512,
                    0,
                )
            },
            InodeHandle::Fd(fd) => unsafe {
                libc::flistxattr(fd, buf.as_mut_ptr() as *mut libc::c_char, 512, 0)
            },
        };
        if res < 0 {
            return Err(linux_error(io::Error::last_os_error()));
        }

        buf.truncate(res as usize);

        if size == 0 {
            let mut clean_size = res as usize;

            for attr in buf.split(|c| *c == 0) {
                if attr.starts_with(&XATTR_KEY[..XATTR_KEY.len() - 1]) {
                    clean_size -= XATTR_KEY.len();
                }
            }

            Ok(ListxattrReply::Count(clean_size as u32))
        } else {
            let mut clean_buf = Vec::new();

            for attr in buf.split(|c| *c == 0) {
                if attr.is_empty() || attr.starts_with(&XATTR_KEY[..XATTR_KEY.len() - 1]) {
                    continue;
                }

                clean_buf.extend_from_slice(attr);
                clean_buf.push(0);
            }

            clean_buf.shrink_to_fit();

            if clean_buf.len() > size as usize {
                Err(io::Error::from_raw_os_error(LINUX_ERANGE))
            } else {
                Ok(ListxattrReply::Names(clean_buf))
            }
        }
    }

    fn removexattr(&self, _ctx: Context, inode: Inode, name: &CStr) -> io::Result<()> {
        if !self.cfg.xattr {
            return Err(linux_error(io::Error::from_raw_os_error(libc::ENOSYS)));
        }

        if name.to_bytes() == XATTR_KEY {
            return Err(linux_error(io::Error::from_raw_os_error(
                bindings::LINUX_EACCES,
            )));
        }

        // Safe because this doesn't modify any memory and we check the return value.
        let res = match self.inode_to_handle(inode, true)? {
            InodeHandle::Path(c_path) => unsafe {
                libc::removexattr(c_path.as_ptr(), name.as_ptr(), 0)
            },
            InodeHandle::Fd(fd) => unsafe { libc::fremovexattr(fd, name.as_ptr(), 0) },
        };
        if res == 0 {
            Ok(())
        } else {
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn fallocate(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        _mode: u32,
        offset: u64,
        length: u64,
    ) -> io::Result<()> {
        let data = self
            .handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .cloned()
            .ok_or_else(ebadf)?;

        let fd = data.file.write().unwrap().as_raw_fd();

        let proposed_length = (offset + length) as i64;
        let mut fs = libc::fstore_t {
            fst_flags: libc::F_ALLOCATECONTIG,
            fst_posmode: libc::F_PEOFPOSMODE,
            fst_offset: 0,
            fst_length: proposed_length,
            fst_bytesalloc: 0,
        };

        let res = unsafe { libc::fcntl(fd, libc::F_PREALLOCATE, &mut fs as *mut _) };
        if res < 0 {
            fs.fst_flags = libc::F_ALLOCATEALL;
            let res = unsafe { libc::fcntl(fd, libc::F_PREALLOCATE, &mut fs as &mut _) };
            if res < 0 {
                return Err(linux_error(io::Error::last_os_error()));
            }
        }

        let st = fstat(fd, true)?;
        if st.st_size >= proposed_length {
            // fallocate should not shrink the file. The file is already larger than needed.
            return Ok(());
        }
        let res = unsafe { libc::ftruncate(fd, proposed_length) };

        if res == 0 {
            Ok(())
        } else {
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn lseek(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        offset: u64,
        whence: u32,
    ) -> io::Result<u64> {
        let data = self
            .handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .cloned()
            .ok_or_else(ebadf)?;

        // SEEK_DATA and SEEK_HOLE have slightly different semantics
        // in Linux vs. macOS, which means we can't support them.
        let mwhence = if whence == 3 {
            // SEEK_DATA
            return Ok(offset);
        } else if whence == 4 {
            // SEEK_HOLE
            libc::SEEK_END
        } else {
            whence as i32
        };

        let fd = data.file.write().unwrap().as_raw_fd();

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::lseek(fd, offset as bindings::off64_t, mwhence as libc::c_int) };
        if res < 0 {
            Err(linux_error(io::Error::last_os_error()))
        } else {
            Ok(res as u64)
        }
    }

    fn setupmapping(
        &self,
        _ctx: Context,
        inode: Inode,
        _handle: Handle,
        foffset: u64,
        len: u64,
        flags: u64,
        moffset: u64,
        guest_shm_base: u64,
        shm_size: u64,
        map_sender: &Option<Sender<WorkerMessage>>,
    ) -> io::Result<()> {
        if map_sender.is_none() {
            return Err(linux_error(io::Error::from_raw_os_error(libc::ENOSYS)));
        }

        let prot_flags = if (flags & fuse::SetupmappingFlags::WRITE.bits()) != 0 {
            libc::PROT_READ | libc::PROT_WRITE
        } else {
            libc::PROT_READ
        };

        if (moffset + len) > shm_size {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EINVAL)));
        }

        let guest_addr = guest_shm_base + moffset;

        debug!("setupmapping: ino {inode:?} guest_addr={guest_addr:x} len={len}");

        let file = self.open_inode(inode, libc::O_RDWR)?;
        let fd = file.as_raw_fd();

        let host_addr = unsafe {
            libc::mmap(
                null_mut(),
                len as usize,
                prot_flags,
                libc::MAP_SHARED,
                fd,
                foffset as libc::off_t,
            )
        };
        if host_addr == libc::MAP_FAILED {
            return Err(linux_error(io::Error::last_os_error()));
        }

        let ret = unsafe { libc::close(fd) };
        if ret == -1 {
            return Err(linux_error(io::Error::last_os_error()));
        }

        // We've checked that map_sender is something above.
        let sender = map_sender.as_ref().unwrap();
        let (reply_sender, reply_receiver) = unbounded();
        sender
            .send(WorkerMessage::GpuAddMapping(
                reply_sender,
                host_addr as u64,
                guest_addr,
                len,
            ))
            .unwrap();
        if !reply_receiver.recv().unwrap() {
            error!("Error requesting HVF the addition of a DAX window");
            unsafe { libc::munmap(host_addr, len as usize) };
            return Err(linux_error(io::Error::from_raw_os_error(libc::EINVAL)));
        }

        self.map_windows
            .lock()
            .unwrap()
            .insert(guest_addr, host_addr as u64);

        Ok(())
    }

    fn removemapping(
        &self,
        _ctx: Context,
        requests: Vec<fuse::RemovemappingOne>,
        guest_shm_base: u64,
        shm_size: u64,
        map_sender: &Option<Sender<WorkerMessage>>,
    ) -> io::Result<()> {
        if map_sender.is_none() {
            return Err(linux_error(io::Error::from_raw_os_error(libc::ENOSYS)));
        }

        for req in requests {
            let guest_addr = guest_shm_base + req.moffset;
            if (req.moffset + req.len) > shm_size {
                return Err(linux_error(io::Error::from_raw_os_error(libc::EINVAL)));
            }
            let host_addr = match self.map_windows.lock().unwrap().remove(&guest_addr) {
                Some(a) => a,
                None => return Err(linux_error(io::Error::from_raw_os_error(libc::EINVAL))),
            };
            debug!(
                "removemapping: guest_addr={:x} len={:?}",
                guest_addr, req.len
            );

            let sender = map_sender.as_ref().unwrap();
            let (reply_sender, reply_receiver) = unbounded();
            sender
                .send(WorkerMessage::GpuRemoveMapping(
                    reply_sender,
                    guest_addr,
                    req.len,
                ))
                .unwrap();
            if !reply_receiver.recv().unwrap() {
                error!("Error requesting HVF the removal of a DAX window");
                return Err(linux_error(io::Error::from_raw_os_error(libc::EINVAL)));
            }

            let ret = unsafe { libc::munmap(host_addr as *mut libc::c_void, req.len as usize) };
            if ret == -1 {
                error!("Error unmapping DAX window");
                return Err(linux_error(io::Error::last_os_error()));
            }
        }

        Ok(())
    }

    fn ioctl(
        &self,
        _ctx: Context,
        _inode: Self::Inode,
        _handle: Self::Handle,
        _flags: u32,
        cmd: u32,
        arg: u64,
        _in_size: u32,
        _out_size: u32,
        exit_code: &Arc<AtomicI32>,
    ) -> io::Result<Vec<u8>> {
        // We can't use nix::request_code_none here since it's system-dependent
        // and we need the value from Linux.
        const VIRTIO_IOC_EXIT_CODE_REQ: u32 = 0x7602;
        const VIRTIO_IOC_REMOVE_ROOT_DIR_REQ: u32 = 0x7603;

        match cmd {
            VIRTIO_IOC_EXIT_CODE_REQ => {
                exit_code.store(arg as i32, Ordering::SeqCst);
                Ok(Vec::new())
            }
            VIRTIO_IOC_REMOVE_ROOT_DIR_REQ if self.cfg.allow_root_dir_delete => {
                std::fs::remove_dir_all(&self.cfg.root_dir)?;
                Ok(Vec::new())
            }
            _ => Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP)),
        }
    }
}

//! Inode management: lookup, forget, and reference counting.
//!
//! ## Lookup Strategy
//!
//! Linux lookup uses a "collapse" optimization: open → statx(AT_EMPTY_PATH) → getxattr,
//! yielding 3 syscalls instead of the naive 4 (fstatat + statx + open + getxattr). The stat
//! is taken on the *opened* fd, eliminating TOCTOU between stat and open.
//!
//! macOS lookup uses fstatat → inode table check → register, with a separate fd open
//! via `/.vol/dev/ino` for xattr access (since macOS doesn't store per-inode O_PATH fds).
//!
//! ## Security: Procfd Reopen
//!
//! `open_inode_fd` reopens inodes for I/O via `openat(proc_self_fd, "N", O_NOFOLLOW)`.
//! This prevents procfd magic-link symlink following: without O_NOFOLLOW, `open("/proc/self/fd/N")`
//! on an O_PATH fd pointing to a real host symlink would follow the target, potentially
//! escaping the exported root. Using `openat` relative to `/proc/self/fd` with `O_NOFOLLOW`
//! ensures the kernel resolves the fd reference without following any symlinks.

use std::ffi::CStr;
use std::io;
use std::os::fd::AsRawFd;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use super::PassthroughFs;
use crate::backends::shared::inode_table::{InodeAltKey, InodeData, MultikeyBTreeMap};
use crate::backends::shared::platform;
use crate::{stat64, Entry};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Look up a child name in a parent directory and return an [`Entry`].
///
/// If the inode is already in the table (matched by host identity), its
/// refcount is incremented and the existing inode number is returned.
/// Otherwise a new inode is allocated.
pub(crate) fn do_lookup(fs: &PassthroughFs, parent: u64, name: &CStr) -> io::Result<Entry> {
    crate::backends::shared::name_validation::validate_name(name)?;

    let parent_fd = get_inode_fd(fs, parent)?;

    #[cfg(target_os = "linux")]
    return do_lookup_linux(fs, parent_fd, name);

    #[cfg(target_os = "macos")]
    return do_lookup_macos(fs, parent_fd, name);
}

/// Linux lookup: open → statx(AT_EMPTY_PATH) → patched_stat (3 syscalls).
///
/// This is more efficient than the fstatat + statx + open path (4 syscalls),
/// and also more correct: the stat is on the *opened* fd, eliminating TOCTOU
/// between stat and open.
///
/// The open uses `RESOLVE_BENEATH` (Linux 5.6+) for kernel-enforced containment,
/// which atomically blocks `..` traversal, absolute symlinks, and handles concurrent
/// rename races. Falls back to `openat(O_NOFOLLOW)` on older kernels.
#[cfg(target_os = "linux")]
fn do_lookup_linux(fs: &PassthroughFs, parent_fd: i32, name: &CStr) -> io::Result<Entry> {
    use std::os::fd::FromRawFd;

    // Syscall 1: Open with RESOLVE_BENEATH containment.
    let fd = platform::open_beneath(
        parent_fd,
        name.as_ptr(),
        libc::O_PATH | libc::O_NOFOLLOW,
        fs.has_openat2.load(Ordering::Relaxed),
    );
    if fd < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }

    // Syscall 2: statx with AT_EMPTY_PATH on the opened fd.
    // Gets stat data + mnt_id in one call.
    let mut stx: libc::statx = unsafe { std::mem::zeroed() };
    let ret = unsafe {
        libc::statx(
            fd,
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW | libc::AT_STATX_SYNC_AS_STAT,
            libc::STATX_BASIC_STATS | libc::STATX_MNT_ID,
            &mut stx,
        )
    };
    if ret < 0 {
        let err = platform::linux_error(io::Error::last_os_error());
        unsafe { libc::close(fd) };
        return Err(err);
    }

    let st = platform::statx_to_stat64(&stx);
    let mnt_id = stx.stx_mnt_id;
    let alt_key = InodeAltKey::new(st.st_ino, st.st_dev, mnt_id);

    // Check if this host file is already tracked.
    {
        let inodes = fs.inodes.read().unwrap();
        if let Some(data) = inodes.get_alt(&alt_key) {
            data.refcount.fetch_add(1, Ordering::Acquire);
            // Close the fd — we already have one for this inode.
            unsafe { libc::close(fd) };
            // Syscall 3: getxattr for override stat.
            let patched = crate::backends::shared::stat_override::patched_stat(
                inode_raw_fd(data),
                st,
            )?;
            return Ok(Entry {
                inode: data.inode,
                generation: 0,
                attr: patched,
                attr_flags: 0,
                attr_timeout: fs.cfg.attr_timeout,
                entry_timeout: fs.cfg.entry_timeout,
            });
        }
    }

    // New inode — take ownership of the fd.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let inode_num = fs.next_inode.fetch_add(1, Ordering::Relaxed);

    let data = Arc::new(InodeData {
        inode: inode_num,
        ino: st.st_ino,
        dev: st.st_dev,
        refcount: std::sync::atomic::AtomicU64::new(1),
        file,
        mnt_id,
    });

    let raw_fd = inode_raw_fd(&data);
    // Syscall 3: getxattr for override stat.
    let patched = crate::backends::shared::stat_override::patched_stat(raw_fd, st)?;

    {
        let mut inodes = fs.inodes.write().unwrap();
        inodes.insert(inode_num, alt_key, data);
    }

    Ok(Entry {
        inode: inode_num,
        generation: 0,
        attr: patched,
        attr_flags: 0,
        attr_timeout: fs.cfg.attr_timeout,
        entry_timeout: fs.cfg.entry_timeout,
    })
}

/// macOS lookup: fstatat → check table → register.
///
/// Opens a real fd via `/.vol/dev/ino` for xattr access since macOS
/// doesn't store per-inode fds (inode_raw_fd returns -1). The `/.vol/`
/// path scheme references files by device+inode identity, making it
/// stable across renames — similar to Linux's `/proc/self/fd/N`.
#[cfg(target_os = "macos")]
fn do_lookup_macos(fs: &PassthroughFs, parent_fd: i32, name: &CStr) -> io::Result<Entry> {
    let st = platform::fstatat_nofollow(parent_fd, name)?;
    let alt_key = InodeAltKey::new(st.st_ino as u64, st.st_dev as u64);

    // Open a real fd for xattr access via /.vol/dev/ino.
    let patched = open_and_patch_stat_macos(st.st_dev as u64, st.st_ino as u64, st)?;

    // Check if this host file is already tracked.
    {
        let inodes = fs.inodes.read().unwrap();
        if let Some(data) = inodes.get_alt(&alt_key) {
            data.refcount.fetch_add(1, Ordering::Acquire);
            return Ok(Entry {
                inode: data.inode,
                generation: 0,
                attr: patched,
                attr_flags: 0,
                attr_timeout: fs.cfg.attr_timeout,
                entry_timeout: fs.cfg.entry_timeout,
            });
        }
    }

    let inode_num = fs.next_inode.fetch_add(1, Ordering::Relaxed);

    let data = Arc::new(InodeData {
        inode: inode_num,
        ino: st.st_ino as u64,
        dev: st.st_dev as u64,
        refcount: std::sync::atomic::AtomicU64::new(1),
    });

    {
        let mut inodes = fs.inodes.write().unwrap();
        inodes.insert(inode_num, alt_key, data);
    }

    Ok(Entry {
        inode: inode_num,
        generation: 0,
        attr: patched,
        attr_flags: 0,
        attr_timeout: fs.cfg.attr_timeout,
        entry_timeout: fs.cfg.entry_timeout,
    })
}

/// Open a real fd via `/.vol/dev/ino` for xattr access and apply stat patching.
///
/// Tries O_RDONLY first, then O_RDONLY|O_DIRECTORY (for directories that reject
/// plain O_RDONLY), falls back to unpatched stat if neither succeeds. This is
/// necessary because macOS doesn't store per-inode fds, so we must open a
/// temporary fd solely for `fgetxattr` to read the override stat.
#[cfg(target_os = "macos")]
fn open_and_patch_stat_macos(dev: u64, ino: u64, st: stat64) -> io::Result<stat64> {
    let path = format!("/.vol/{}/{}\0", dev, ino);

    // Try regular file open.
    let fd = unsafe {
        libc::open(
            path.as_ptr() as *const libc::c_char,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd >= 0 {
        let result = crate::backends::shared::stat_override::patched_stat(fd, st);
        unsafe { libc::close(fd) };
        return result;
    }

    // Try directory open.
    let fd = unsafe {
        libc::open(
            path.as_ptr() as *const libc::c_char,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY,
        )
    };
    if fd >= 0 {
        let result = crate::backends::shared::stat_override::patched_stat(fd, st);
        unsafe { libc::close(fd) };
        return result;
    }

    // Can't open — return unpatched stat.
    Ok(st)
}

/// Decrement the reference count for an inode. Remove it from the table
/// when the count reaches zero.
pub(crate) fn forget_one(fs: &PassthroughFs, inode: u64, count: u64) {
    let mut inodes = fs.inodes.write().unwrap();
    forget_one_locked(&mut inodes, inode, count);
}

/// Decrement the reference count under an already-held write lock.
///
/// Used by [`super::PassthroughFs::batch_forget`] to process all entries
/// under a single lock acquisition (O(1) lock ops vs O(n) for per-entry locking).
///
/// Uses a CAS loop to handle the race where a concurrent `lookup` may increment
/// the refcount between our load and compare_exchange. `saturating_sub` prevents
/// underflow if the kernel sends a forget count larger than the current refcount.
pub(crate) fn forget_one_locked(
    inodes: &mut MultikeyBTreeMap<u64, InodeAltKey, Arc<InodeData>>,
    inode: u64,
    count: u64,
) {
    if let Some(data) = inodes.get(&inode) {
        loop {
            let old = data.refcount.load(Ordering::Relaxed);
            let new = old.saturating_sub(count);
            if data
                .refcount
                .compare_exchange(old, new, Ordering::Release, Ordering::Relaxed)
                .is_ok()
            {
                if new == 0 {
                    inodes.remove(&inode);
                }
                break;
            }
        }
    }
}

/// Get the raw fd for an inode. On Linux this is the O_PATH fd.
/// On macOS this opens via `/.vol/dev/ino`.
pub(crate) fn get_inode_fd(fs: &PassthroughFs, inode: u64) -> io::Result<i32> {
    // Root inode uses the stored root fd.
    if inode == 1 {
        return Ok(fs.root_fd.as_raw_fd());
    }

    let inodes = fs.inodes.read().unwrap();
    let data = inodes.get(&inode).ok_or_else(platform::ebadf)?;

    Ok(inode_raw_fd(data))
}

/// Get the raw fd from an InodeData.
#[cfg(target_os = "linux")]
fn inode_raw_fd(data: &InodeData) -> i32 {
    data.file.as_raw_fd()
}

/// Get the raw fd from an InodeData on macOS.
/// On macOS we don't store fds per inode; we open via `/.vol/dev/ino`.
/// For the simple case, we return -1 and callers use path-based operations.
#[cfg(target_os = "macos")]
fn inode_raw_fd(_data: &InodeData) -> i32 {
    // On macOS, we use path-based xattr operations.
    // Return -1 to signal that path-based access is needed.
    -1
}

/// Open a file for I/O by inode. Returns a real file descriptor (not O_PATH).
///
/// On Linux, uses `openat(proc_self_fd, "N", flags | O_NOFOLLOW)` to prevent
/// procfd magic-link symlink following, which could escape the exported root.
pub(crate) fn open_inode_fd(fs: &PassthroughFs, inode: u64, flags: i32) -> io::Result<i32> {
    #[cfg(target_os = "linux")]
    {
        let inode_fd = get_inode_fd(fs, inode)?;
        let mut buf = [0u8; 20];
        let fd_str = format_fd_cstr(inode_fd, &mut buf);
        let fd = unsafe {
            libc::openat(
                fs.proc_self_fd.as_raw_fd(),
                fd_str.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
        Ok(fd)
    }

    #[cfg(target_os = "macos")]
    {
        let inodes = fs.inodes.read().unwrap();
        let data = inodes.get(&inode).ok_or_else(platform::ebadf)?;
        let path = format!("/.vol/{}/{}\0", data.dev, data.ino);
        let fd = unsafe {
            libc::open(
                path.as_ptr() as *const libc::c_char,
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
        Ok(fd)
    }
}

/// Format a file descriptor number as a null-terminated C string into a stack buffer.
///
/// Avoids the heap allocation of `format!("/proc/self/fd/{fd}")` on the hot
/// reopen path. A 20-byte stack buffer is sufficient for any i32 fd number
/// plus null terminator.
#[cfg(target_os = "linux")]
fn format_fd_cstr(fd: i32, buf: &mut [u8; 20]) -> *const libc::c_char {
    use std::io::Write;
    let mut cursor = std::io::Cursor::new(&mut buf[..]);
    write!(cursor, "{}\0", fd).unwrap();
    buf.as_ptr() as *const libc::c_char
}

/// Stat an inode (with override xattr applied).
pub(crate) fn stat_inode(fs: &PassthroughFs, inode: u64) -> io::Result<stat64> {
    #[cfg(target_os = "linux")]
    {
        let fd = get_inode_fd(fs, inode)?;
        let st = platform::fstat(fd)?;
        crate::backends::shared::stat_override::patched_stat(fd, st)
    }

    #[cfg(target_os = "macos")]
    {
        let inodes = fs.inodes.read().unwrap();
        let data = inodes.get(&inode).ok_or_else(platform::ebadf)?;
        let path = format!("/.vol/{}/{}\0", data.dev, data.ino);
        let path_cstr = unsafe { CStr::from_ptr(path.as_ptr() as *const _) };
        let mut st = unsafe { std::mem::zeroed::<stat64>() };
        let ret = unsafe { libc::lstat(path_cstr.as_ptr(), &mut st) };
        if ret < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
        open_and_patch_stat_macos(data.dev, data.ino, st)
    }
}

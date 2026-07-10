//! Directory operations: opendir, readdir, readdirplus, releasedir.
//!
//! Passthrough directory handles build a point-in-time snapshot on the first
//! `readdir`/`readdirplus` call. This avoids backend-specific cookie semantics
//! such as macOS `telldir`/`seekdir` values leaking into guest-visible offsets,
//! and gives every handle stable, monotonic offsets for its lifetime.

use std::{
    io,
    os::fd::{AsRawFd, FromRawFd},
    sync::{Arc, RwLock, atomic::Ordering},
    time::Duration,
};

use super::{DirSnapshot, PassthroughDirEntry, PassthroughDirHandle, PassthroughFs, inode};
use crate::{
    AddDirEntry, AddDirEntryPlus, Context, DirEntry, Entry, OpenOptions,
    backends::shared::{
        dir_snapshot::{self, SnapshotEntry},
        init_binary, platform,
    },
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Open a directory and return a handle.
pub(crate) fn do_opendir(
    fs: &PassthroughFs,
    _ctx: Context,
    inode: u64,
    _flags: u32,
) -> io::Result<(Option<u64>, OpenOptions)> {
    let fd = inode::open_inode_fd(fs, inode, libc::O_RDONLY | libc::O_DIRECTORY)?;
    let file = unsafe { std::fs::File::from_raw_fd(fd) };

    let handle = fs.next_handle.fetch_add(1, Ordering::Relaxed);
    let data = Arc::new(PassthroughDirHandle {
        file: RwLock::new(file),
        snapshot: std::sync::Mutex::new(None),
    });

    fs.dir_handles.write().unwrap().insert(handle, data);
    Ok((Some(handle), fs.cache_dir_options()))
}

/// Read directory entries from a point-in-time snapshot.
pub(crate) fn do_readdir(
    fs: &PassthroughFs,
    _ctx: Context,
    inode: u64,
    handle: u64,
    _size: u32,
    offset: u64,
) -> io::Result<Vec<DirEntry<'static>>> {
    let handles = fs.dir_handles.read().unwrap();
    let data = handles.get(&handle).ok_or_else(platform::ebadf)?;

    let mut snapshot_lock = data.snapshot.lock().unwrap();
    if snapshot_lock.is_none() {
        #[allow(clippy::readonly_write_lock)]
        let file = data.file.write().unwrap();
        let inject_init = fs.injects_init() && inode == 1;
        *snapshot_lock = Some(build_snapshot(file.as_raw_fd(), inject_init)?);
    }

    let snapshot = snapshot_lock.as_ref().unwrap();
    Ok(dir_snapshot::serve_snapshot_entries(
        &snapshot.entries,
        offset,
    ))
}

/// Stream directory entries from a point-in-time snapshot.
pub(crate) fn do_readdir_for_each(
    fs: &PassthroughFs,
    _ctx: Context,
    inode: u64,
    handle: u64,
    _size: u32,
    offset: u64,
    add_entry: &mut AddDirEntry<'_>,
) -> io::Result<()> {
    let handles = fs.dir_handles.read().unwrap();
    let data = handles.get(&handle).ok_or_else(platform::ebadf)?;

    let mut snapshot_lock = data.snapshot.lock().unwrap();
    if snapshot_lock.is_none() {
        #[allow(clippy::readonly_write_lock)]
        let file = data.file.write().unwrap();
        let inject_init = fs.injects_init() && inode == 1;
        *snapshot_lock = Some(build_snapshot(file.as_raw_fd(), inject_init)?);
    }

    let snapshot = snapshot_lock.as_ref().unwrap();
    dir_snapshot::serve_snapshot_entries_for_each(&snapshot.entries, offset, add_entry)
}

/// Read directory entries with attributes (readdirplus).
pub(crate) fn do_readdirplus(
    fs: &PassthroughFs,
    ctx: Context,
    inode: u64,
    handle: u64,
    size: u32,
    offset: u64,
) -> io::Result<Vec<(DirEntry<'static>, Entry)>> {
    let dir_entries = do_readdir(fs, ctx, inode, handle, size, offset)?;
    let mut result = Vec::with_capacity(dir_entries.len());

    for de in dir_entries {
        let name_bytes = de.name;
        if name_bytes == b"." || name_bytes == b".." {
            continue;
        }

        if name_bytes == init_binary::INIT_FILENAME {
            let entry = init_binary::init_entry(fs.cfg.entry_timeout, fs.cfg.attr_timeout);
            result.push((de, entry));
            continue;
        }

        let name_cstr = match std::ffi::CString::new(name_bytes.to_vec()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        match inode::do_lookup(fs, inode, &name_cstr) {
            Ok(entry) => {
                let mut de = de;
                let file_type = platform::mode_file_type(entry.attr.st_mode);
                de.type_ = mode_to_dtype(file_type);
                result.push((de, entry));
            }
            Err(err) if lookup_says_gone(&err) => continue,
            Err(_) => result.push((de, no_lookup_entry())),
        }
    }

    Ok(result)
}

/// Stream directory entries with attributes.
pub(crate) fn do_readdirplus_for_each(
    fs: &PassthroughFs,
    _ctx: Context,
    inode: u64,
    handle: u64,
    _size: u32,
    offset: u64,
    add_entry: &mut AddDirEntryPlus<'_>,
) -> io::Result<()> {
    let handles = fs.dir_handles.read().unwrap();
    let data = handles.get(&handle).ok_or_else(platform::ebadf)?;

    let mut snapshot_lock = data.snapshot.lock().unwrap();
    if snapshot_lock.is_none() {
        #[allow(clippy::readonly_write_lock)]
        let file = data.file.write().unwrap();
        let inject_init = fs.injects_init() && inode == 1;
        *snapshot_lock = Some(build_snapshot(file.as_raw_fd(), inject_init)?);
    }

    let snapshot = snapshot_lock.as_ref().unwrap();
    let mut emitted_lookup_refs = Vec::new();

    for snapshot_entry in dir_snapshot::snapshot_entries_after(&snapshot.entries, offset) {
        let name_bytes = snapshot_entry.name();
        if name_bytes == b"." || name_bytes == b".." {
            continue;
        }

        let mut dir_entry = DirEntry {
            ino: snapshot_entry.inode(),
            offset: snapshot_entry.offset(),
            type_: snapshot_entry.file_type(),
            name: name_bytes,
        };

        if name_bytes == init_binary::INIT_FILENAME {
            let entry = init_binary::init_entry(fs.cfg.entry_timeout, fs.cfg.attr_timeout);
            if add_entry(dir_entry, entry)? == 0 {
                break;
            }
            continue;
        }

        let name_cstr = match std::ffi::CString::new(name_bytes.to_vec()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let (entry, looked_up_inode) = match inode::do_lookup(fs, inode, &name_cstr) {
            Ok(entry) => {
                let file_type = platform::mode_file_type(entry.attr.st_mode);
                dir_entry.type_ = mode_to_dtype(file_type);
                let looked_up_inode = entry.inode;
                (entry, Some(looked_up_inode))
            }
            Err(err) if lookup_says_gone(&err) => continue,
            Err(_) => (no_lookup_entry(), None),
        };

        match add_entry(dir_entry, entry) {
            Ok(0) => {
                if let Some(ino) = looked_up_inode {
                    inode::forget_one(fs, ino, 1);
                }
                break;
            }
            Ok(_) => {
                if let Some(ino) = looked_up_inode {
                    emitted_lookup_refs.push(ino);
                }
            }
            Err(err) => {
                if let Some(ino) = looked_up_inode {
                    inode::forget_one(fs, ino, 1);
                }
                for emitted_inode in emitted_lookup_refs {
                    inode::forget_one(fs, emitted_inode, 1);
                }
                return Err(err);
            }
        }
    }

    Ok(())
}

/// Release an open directory handle.
pub(crate) fn do_releasedir(
    fs: &PassthroughFs,
    _ctx: Context,
    _inode: u64,
    _flags: u32,
    handle: u64,
) -> io::Result<()> {
    fs.dir_handles.write().unwrap().remove(&handle);
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl SnapshotEntry for PassthroughDirEntry {
    fn inode(&self) -> u64 {
        self.inode
    }

    fn offset(&self) -> u64 {
        self.offset
    }

    fn file_type(&self) -> u32 {
        self.file_type
    }

    fn name(&self) -> &[u8] {
        &self.name
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Convert a file mode type to a directory entry type.
fn mode_to_dtype(mode_type: u32) -> u32 {
    platform::dirent_type_from_mode(mode_type)
}

/// Whether a failed per-entry lookup means the name is truly gone from the directory (deleted or replaced between snapshot and lookup) rather than temporarily unresolvable.
///
/// Errors from `do_lookup` are already translated to Linux errno values; `ENOENT` and `ENOTDIR` are numerically identical on Linux and macOS.
fn lookup_says_gone(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(libc::ENOENT) | Some(libc::ENOTDIR))
}

/// Entry for a dirent whose lookup failed for a reason other than the name being gone (fd exhaustion, I/O error, permissions). `inode: 0` tells the guest kernel that no
/// lookup was performed: the name still appears in the listing and the real error surfaces when the entry is accessed, instead of silently vanishing from the guest's view.
fn no_lookup_entry() -> Entry {
    Entry {
        inode: 0,
        generation: 0,
        attr: unsafe { std::mem::zeroed() },
        attr_flags: 0,
        attr_timeout: Duration::ZERO,
        entry_timeout: Duration::ZERO,
    }
}

/// Build a point-in-time directory snapshot with stable synthetic offsets.
fn build_snapshot(fd: i32, inject_init: bool) -> io::Result<DirSnapshot> {
    let mut entries = read_dir_entries(fd)?;

    if inject_init
        && !entries
            .iter()
            .any(|entry| entry.name == init_binary::INIT_FILENAME)
    {
        entries.push(PassthroughDirEntry {
            inode: init_binary::INIT_INODE,
            name: init_binary::INIT_FILENAME.to_vec(),
            offset: 0,
            file_type: platform::DIRENT_REG,
        });
    }

    for (index, entry) in entries.iter_mut().enumerate() {
        entry.offset = (index + 1) as u64;
    }

    Ok(DirSnapshot { entries })
}

/// Read all directory entries from a file descriptor on Linux.
#[cfg(target_os = "linux")]
fn read_dir_entries(fd: i32) -> io::Result<Vec<PassthroughDirEntry>> {
    let ret = unsafe { libc::lseek64(fd, 0, libc::SEEK_SET) };
    if ret < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }

    let mut buf = vec![0u8; 65536];
    let mut entries = Vec::new();

    loop {
        let nread = unsafe { libc::syscall(libc::SYS_getdents64, fd, buf.as_mut_ptr(), buf.len()) };

        if nread < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
        if nread == 0 {
            break;
        }

        let mut pos = 0usize;
        while pos < nread as usize {
            let d_ino = u64::from_ne_bytes(buf[pos..pos + 8].try_into().unwrap());
            let d_reclen = u16::from_ne_bytes(buf[pos + 16..pos + 18].try_into().unwrap());
            let d_type = buf[pos + 18] as u32;

            let name_start = pos + 19;
            let name_end = pos + d_reclen as usize;
            let name_slice = &buf[name_start..name_end];
            let name_len = name_slice
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(name_slice.len());

            entries.push(PassthroughDirEntry {
                inode: d_ino,
                name: name_slice[..name_len].to_vec(),
                offset: 0,
                file_type: d_type,
            });

            pos += d_reclen as usize;
        }
    }

    Ok(entries)
}

/// Read all directory entries from a file descriptor on macOS.
#[cfg(target_os = "macos")]
fn read_dir_entries(fd: i32) -> io::Result<Vec<PassthroughDirEntry>> {
    let ret = unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
    if ret < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }

    let dup_fd = unsafe { libc::dup(fd) };
    if dup_fd < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }

    let dirp = unsafe { libc::fdopendir(dup_fd) };
    if dirp.is_null() {
        unsafe { libc::close(dup_fd) };
        return Err(platform::linux_error(io::Error::last_os_error()));
    }

    let mut entries = Vec::new();

    loop {
        unsafe { *libc::__error() = 0 };

        let ent = unsafe { libc::readdir(dirp) };
        if ent.is_null() {
            let errno = unsafe { *libc::__error() };
            if errno != 0 {
                unsafe { libc::closedir(dirp) };
                return Err(platform::linux_error(io::Error::from_raw_os_error(errno)));
            }
            break;
        }

        let entry = unsafe { &*ent };
        let name_len = entry.d_namlen as usize;
        let name =
            unsafe { std::slice::from_raw_parts(entry.d_name.as_ptr() as *const u8, name_len) };

        entries.push(PassthroughDirEntry {
            inode: entry.d_ino,
            name: name.to_vec(),
            offset: 0,
            file_type: entry.d_type as u32,
        });
    }

    unsafe { libc::closedir(dirp) };

    Ok(entries)
}

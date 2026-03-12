//! Inode management: allocation, lookup, forget, stat building, capacity tracking.

use std::io;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use super::MemFs;
use super::types::{InodeContent, InodeMeta, MemNode, Timespec};
use crate::backends::shared::platform;
use crate::{Entry, stat64};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Get the current time as a `Timespec`.
pub(crate) fn current_time() -> Timespec {
    let mut tp = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut tp) };
    Timespec {
        sec: tp.tv_sec as i64,
        nsec: tp.tv_nsec as i64,
    }
}

/// Allocate a new inode number, checking the max_inodes limit.
pub(crate) fn alloc_inode(fs: &MemFs) -> io::Result<u64> {
    if let Some(max) = fs.cfg.max_inodes {
        let current = fs.inode_count.load(Ordering::Relaxed);
        if current >= max {
            return Err(platform::enospc());
        }
    }

    let ino = fs.next_inode.fetch_add(1, Ordering::Relaxed);
    fs.inode_count.fetch_add(1, Ordering::Relaxed);
    Ok(ino)
}

/// Get a node by inode number.
///
/// Returns EBADF for unknown inodes — an inode is analogous to a file
/// descriptor in the FUSE protocol.
pub(crate) fn get_node(fs: &MemFs, ino: u64) -> io::Result<Arc<MemNode>> {
    let nodes = fs.nodes.read().unwrap();
    nodes.get(&ino).cloned().ok_or_else(platform::ebadf)
}

/// Build a `stat64` from a `MemNode`.
pub(crate) fn build_stat(node: &MemNode) -> stat64 {
    let meta = node.meta.read().unwrap();
    build_stat_from_meta(node.inode, &meta)
}

/// Build a `stat64` from inode number and metadata.
pub(crate) fn build_stat_from_meta(ino: u64, meta: &InodeMeta) -> stat64 {
    let mut st: stat64 = unsafe { std::mem::zeroed() };

    st.st_ino = ino;

    #[cfg(target_os = "linux")]
    {
        st.st_mode = meta.mode;
        st.st_nlink = meta.nlink;
        st.st_rdev = meta.rdev as u64;
    }

    #[cfg(target_os = "macos")]
    {
        st.st_mode = meta.mode as u16;
        st.st_nlink = meta.nlink as u16;
        st.st_rdev = meta.rdev as i32;
    }

    st.st_uid = meta.uid;
    st.st_gid = meta.gid;
    st.st_size = meta.size as i64;
    st.st_blksize = 4096;
    st.st_blocks = (meta.size as i64 + 511) / 512;
    st.st_atime = meta.atime.sec;
    st.st_atime_nsec = meta.atime.nsec;
    st.st_mtime = meta.mtime.sec;
    st.st_mtime_nsec = meta.mtime.nsec;
    st.st_ctime = meta.ctime.sec;
    st.st_ctime_nsec = meta.ctime.nsec;

    st
}

/// Build a FUSE `Entry` from a `MemNode`.
pub(crate) fn build_entry(fs: &MemFs, node: &MemNode) -> Entry {
    let st = build_stat(node);
    Entry {
        inode: node.inode,
        generation: 0,
        attr: st,
        attr_flags: 0,
        attr_timeout: fs.cfg.attr_timeout,
        entry_timeout: fs.cfg.entry_timeout,
    }
}

/// Increment lookup reference count for a node.
pub(crate) fn inc_lookup(node: &MemNode) {
    node.lookup_refs.fetch_add(1, Ordering::Relaxed);
}

/// Forget an inode: decrement lookup refs and evict if unreferenced.
pub(crate) fn forget_one(fs: &MemFs, ino: u64, count: u64) {
    let should_evict = {
        let nodes = fs.nodes.read().unwrap();
        match nodes.get(&ino) {
            Some(node) => {
                let prev = node.lookup_refs.fetch_sub(count, Ordering::Relaxed);
                if prev < count {
                    node.lookup_refs.store(0, Ordering::Relaxed);
                }
                let refs = node.lookup_refs.load(Ordering::Relaxed);
                let nlink = node.meta.read().unwrap().nlink;
                refs == 0 && nlink == 0
            }
            None => false,
        }
    };

    if should_evict {
        evict_inode(fs, ino);
    }
}

/// Try to evict a node if it's unreferenced (nlink == 0 && lookup_refs == 0).
pub(crate) fn try_evict(fs: &MemFs, ino: u64) {
    let should_evict = {
        let nodes = fs.nodes.read().unwrap();
        match nodes.get(&ino) {
            Some(node) => {
                let refs = node.lookup_refs.load(Ordering::Relaxed);
                let nlink = node.meta.read().unwrap().nlink;
                refs == 0 && nlink == 0
            }
            None => false,
        }
    };

    if should_evict {
        evict_inode(fs, ino);
    }
}

/// Remove an inode from the nodes table and release its resources.
///
/// Capacity for regular file data is released only when no open handles
/// still pin the node alive. If handles exist, the bytes remain charged
/// until the last handle is released (see `do_release`).
fn evict_inode(fs: &MemFs, ino: u64) {
    let removed = fs.nodes.write().unwrap().remove(&ino);
    if let Some(node) = removed {
        // Only release bytes if this is the last Arc holder (no open handles).
        if Arc::strong_count(&node) == 1 {
            if let InodeContent::RegularFile { ref data } = node.content {
                let size = data.read().unwrap().len() as u64;
                if size > 0 {
                    release_bytes(fs, size);
                }
            }
        }
        fs.inode_count.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Reserve bytes against the capacity limit using a CAS loop.
pub(crate) fn reserve_bytes(fs: &MemFs, amount: u64) -> io::Result<()> {
    if amount == 0 {
        return Ok(());
    }

    let cap = match fs.cfg.capacity {
        Some(c) => c,
        None => return Ok(()),
    };

    loop {
        let current = fs.used_bytes.load(Ordering::Relaxed);
        let new = current.checked_add(amount).ok_or_else(platform::enospc)?;
        if new > cap {
            return Err(platform::enospc());
        }
        if fs
            .used_bytes
            .compare_exchange_weak(current, new, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return Ok(());
        }
    }
}

/// Release bytes from the capacity tracker.
pub(crate) fn release_bytes(fs: &MemFs, amount: u64) {
    if amount > 0 {
        fs.used_bytes.fetch_sub(amount, Ordering::Relaxed);
    }
}

/// Convert a file mode type to a directory entry type.
pub(crate) fn mode_to_dtype(mode_type: u32) -> u32 {
    match mode_type & libc::S_IFMT as u32 {
        m if m == libc::S_IFLNK as u32 => libc::DT_LNK as u32,
        m if m == libc::S_IFDIR as u32 => libc::DT_DIR as u32,
        m if m == libc::S_IFCHR as u32 => libc::DT_CHR as u32,
        m if m == libc::S_IFBLK as u32 => libc::DT_BLK as u32,
        m if m == libc::S_IFIFO as u32 => libc::DT_FIFO as u32,
        m if m == libc::S_IFSOCK as u32 => libc::DT_SOCK as u32,
        _ => libc::DT_REG as u32,
    }
}

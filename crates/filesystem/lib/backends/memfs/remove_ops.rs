//! Deletion operations: unlink, rmdir, rename.

use std::ffi::CStr;
use std::io;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use super::MemFs;
use super::inode;
use super::types::{InodeContent, ROOT_INODE};
use crate::backends::shared::init_binary;
use crate::backends::shared::name_validation;
use crate::backends::shared::platform;
use crate::Context;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Unlink a file (remove directory entry).
pub(crate) fn do_unlink(
    fs: &MemFs,
    _ctx: Context,
    parent: u64,
    name: &CStr,
) -> io::Result<()> {
    name_validation::validate_memfs_name(name)?;

    if parent == ROOT_INODE && init_binary::is_init_name(name.to_bytes()) {
        return Err(platform::eacces());
    }

    let parent_node = inode::get_node(fs, parent)?;
    let name_bytes = name.to_bytes().to_vec();
    let now = inode::current_time();

    // Remove from parent and get child inode.
    let child_ino = match &parent_node.content {
        InodeContent::Directory { children, .. } => {
            let mut ch = children.write().unwrap();
            ch.remove(&name_bytes).ok_or_else(platform::enoent)?
        }
        _ => return Err(platform::enotdir()),
    };

    // Verify it's not a directory.
    let child_node = inode::get_node(fs, child_ino)?;
    if child_node.kind == libc::S_IFDIR as u32 {
        // Re-insert the entry since we shouldn't have removed it.
        if let InodeContent::Directory { children, .. } = &parent_node.content {
            children.write().unwrap().insert(name_bytes, child_ino);
        }
        return Err(platform::eisdir());
    }

    // Decrement nlink.
    {
        let mut meta = child_node.meta.write().unwrap();
        meta.nlink = meta.nlink.saturating_sub(1);
        meta.ctime = now;
    }

    // Update parent timestamps.
    {
        let mut meta = parent_node.meta.write().unwrap();
        meta.mtime = now;
        meta.ctime = now;
    }

    // Try to evict if unreferenced.
    inode::try_evict(fs, child_ino);

    Ok(())
}

/// Remove an empty directory.
pub(crate) fn do_rmdir(
    fs: &MemFs,
    _ctx: Context,
    parent: u64,
    name: &CStr,
) -> io::Result<()> {
    name_validation::validate_memfs_name(name)?;

    if parent == ROOT_INODE && init_binary::is_init_name(name.to_bytes()) {
        return Err(platform::eacces());
    }

    let parent_node = inode::get_node(fs, parent)?;
    let name_bytes = name.to_bytes().to_vec();
    let now = inode::current_time();

    // Look up child inode first (don't remove yet).
    let child_ino = match &parent_node.content {
        InodeContent::Directory { children, .. } => {
            let ch = children.read().unwrap();
            *ch.get(&name_bytes).ok_or_else(platform::enoent)?
        }
        _ => return Err(platform::enotdir()),
    };

    let child_node = inode::get_node(fs, child_ino)?;

    // Verify it's a directory.
    if child_node.kind != libc::S_IFDIR as u32 {
        return Err(platform::enotdir());
    }

    // Verify it's empty.
    if let InodeContent::Directory { children, .. } = &child_node.content {
        if !children.read().unwrap().is_empty() {
            return Err(platform::enotempty());
        }
    }

    // Now remove from parent.
    if let InodeContent::Directory { children, .. } = &parent_node.content {
        children.write().unwrap().remove(&name_bytes);
    }

    // Set child nlink to 0.
    {
        let mut meta = child_node.meta.write().unwrap();
        meta.nlink = 0;
        meta.ctime = now;
    }

    // Decrement parent nlink (lost a subdirectory) and update timestamps.
    {
        let mut meta = parent_node.meta.write().unwrap();
        meta.nlink = meta.nlink.saturating_sub(1);
        meta.mtime = now;
        meta.ctime = now;
    }

    // Try to evict if unreferenced.
    inode::try_evict(fs, child_ino);

    Ok(())
}

/// Rename a file or directory.
pub(crate) fn do_rename(
    fs: &MemFs,
    _ctx: Context,
    olddir: u64,
    oldname: &CStr,
    newdir: u64,
    newname: &CStr,
    _flags: u32,
) -> io::Result<()> {
    name_validation::validate_memfs_name(oldname)?;
    name_validation::validate_memfs_name(newname)?;

    let old_bytes = oldname.to_bytes().to_vec();
    let new_bytes = newname.to_bytes().to_vec();

    // Protect init.krun.
    if olddir == ROOT_INODE && init_binary::is_init_name(&old_bytes) {
        return Err(platform::eacces());
    }
    if newdir == ROOT_INODE && init_binary::is_init_name(&new_bytes) {
        return Err(platform::eacces());
    }

    // No-op if same parent and same name.
    if olddir == newdir && old_bytes == new_bytes {
        return Ok(());
    }

    let old_parent = inode::get_node(fs, olddir)?;
    let new_parent = if newdir == olddir {
        Arc::clone(&old_parent)
    } else {
        inode::get_node(fs, newdir)?
    };

    let now = inode::current_time();

    // Get source inode.
    let source_ino = match &old_parent.content {
        InodeContent::Directory { children, .. } => {
            let ch = children.read().unwrap();
            *ch.get(&old_bytes).ok_or_else(platform::enoent)?
        }
        _ => return Err(platform::enotdir()),
    };

    let source_node = inode::get_node(fs, source_ino)?;
    let source_is_dir = source_node.kind == libc::S_IFDIR as u32;

    // Check destination.
    let dest_ino = match &new_parent.content {
        InodeContent::Directory { children, .. } => {
            let ch = children.read().unwrap();
            ch.get(&new_bytes).copied()
        }
        _ => return Err(platform::enotdir()),
    };

    // Handle existing destination.
    let mut evict_dest = None;
    if let Some(dest) = dest_ino {
        let dest_node = inode::get_node(fs, dest)?;
        let dest_is_dir = dest_node.kind == libc::S_IFDIR as u32;

        // Type compatibility checks.
        if source_is_dir && !dest_is_dir {
            return Err(platform::enotdir());
        }
        if !source_is_dir && dest_is_dir {
            return Err(platform::eisdir());
        }

        // If destination is a directory, it must be empty.
        if dest_is_dir {
            if let InodeContent::Directory { children, .. } = &dest_node.content {
                if !children.read().unwrap().is_empty() {
                    return Err(platform::enotempty());
                }
            }
        }

        // Decrement destination nlink.
        {
            let mut meta = dest_node.meta.write().unwrap();
            if dest_is_dir {
                meta.nlink = 0;
            } else {
                meta.nlink = meta.nlink.saturating_sub(1);
            }
            meta.ctime = now;
        }

        // If destination is a directory, decrement new_parent nlink.
        if dest_is_dir {
            let mut meta = new_parent.meta.write().unwrap();
            meta.nlink = meta.nlink.saturating_sub(1);
        }

        evict_dest = Some(dest);
    }

    // Perform the rename: remove from old, insert into new.
    if olddir == newdir {
        // Same parent — single children lock.
        if let InodeContent::Directory { children, .. } = &old_parent.content {
            let mut ch = children.write().unwrap();
            ch.remove(&old_bytes);
            ch.insert(new_bytes, source_ino);
        }
    } else {
        // Different parents — lock old first, then new.
        if let InodeContent::Directory { children, .. } = &old_parent.content {
            children.write().unwrap().remove(&old_bytes);
        }
        if let InodeContent::Directory { children, .. } = &new_parent.content {
            children.write().unwrap().insert(new_bytes, source_ino);
        }
    }

    // Update nlinks and parent pointer for directory moves.
    if source_is_dir && olddir != newdir {
        // Old parent lost a subdirectory.
        {
            let mut meta = old_parent.meta.write().unwrap();
            meta.nlink = meta.nlink.saturating_sub(1);
        }
        // New parent gained a subdirectory.
        {
            let mut meta = new_parent.meta.write().unwrap();
            meta.nlink += 1;
        }
        // Update source's parent pointer.
        if let InodeContent::Directory { parent, .. } = &source_node.content {
            parent.store(newdir, Ordering::Relaxed);
        }
    }

    // Update timestamps.
    {
        let mut meta = source_node.meta.write().unwrap();
        meta.ctime = now;
    }
    {
        let mut meta = old_parent.meta.write().unwrap();
        meta.mtime = now;
        meta.ctime = now;
    }
    if olddir != newdir {
        let mut meta = new_parent.meta.write().unwrap();
        meta.mtime = now;
        meta.ctime = now;
    }

    // Evict replaced destination if unreferenced.
    if let Some(dest) = evict_dest {
        inode::try_evict(fs, dest);
    }

    Ok(())
}

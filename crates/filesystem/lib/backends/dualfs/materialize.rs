//! Materialization orchestration: chunked streaming, directory promotion,
//! ancestor materialization.

use super::{
    DualFs,
    lookup::{backend, get_node, resolve_backend_inode},
    types::{BackendId, FileKind, NodeState, ROOT_INODE},
};
use crate::{Context, Extensions, SetattrValid};
use std::{ffi::CString, io, sync::atomic::Ordering};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Materialize a guest inode from source backend to target backend.
///
/// After completion, the node is single-backed on the target backend.
pub(crate) fn do_materialize(
    fs: &DualFs,
    ctx: Context,
    guest_inode: u64,
    source: BackendId,
    target: BackendId,
) -> io::Result<()> {
    let node = get_node(&fs.state, guest_inode)?;

    // Fast check: already on target?
    {
        let state = node.state.read().unwrap();
        if state.backend_inode(target).is_some() && state.current_backend() == Some(target) {
            return Ok(());
        }
    }

    // Acquire copy_up_lock.
    let _lock = node.copy_up_lock.lock().unwrap();

    // Double-check under lock.
    {
        let state = node.state.read().unwrap();
        if state.current_backend() == Some(target) {
            return Ok(());
        }
    }

    // Get source inode.
    let source_inode = {
        let state = node.state.read().unwrap();
        state
            .backend_inode(source)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?
    };

    // Ensure ancestors are present on target.
    ensure_ancestors(fs, ctx, guest_inode, target)?;

    // Resolve parent's inode on target.
    let (parent_ino, name) = {
        fs.state
            .alias_index
            .read()
            .unwrap()
            .get(&guest_inode)
            .and_then(|s| s.iter().next().cloned())
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))?
    };

    let parent_target_inode = resolve_backend_inode(&fs.state, parent_ino, target)
        .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))?;

    let cname =
        CString::new(name.clone()).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;

    // Copy based on file type.
    let target_inode = match node.kind {
        FileKind::RegularFile => materialize_regular_file(
            fs,
            ctx,
            source,
            target,
            source_inode,
            parent_target_inode,
            &cname,
            guest_inode,
        )?,
        FileKind::Symlink => materialize_symlink(
            fs,
            ctx,
            source,
            target,
            source_inode,
            parent_target_inode,
            &cname,
        )?,
        FileKind::Special => materialize_special(
            fs,
            ctx,
            source,
            target,
            source_inode,
            parent_target_inode,
            &cname,
        )?,
        FileKind::Directory => {
            // Directories are handled by promote_directory_to_merged, not materialize.
            return Err(io::Error::from_raw_os_error(libc::EISDIR));
        }
    };

    // Transition state.
    let state_before = node.state.read().unwrap().clone();
    let new_state = match target {
        BackendId::BackendA => NodeState::BackendA {
            backend_a_inode: target_inode,
            former_backend_b_inode: Some(source_inode),
        },
        BackendId::BackendB => NodeState::BackendB {
            backend_b_inode: target_inode,
            former_backend_a_inode: Some(source_inode),
        },
    };
    *node.state.write().unwrap() = new_state;
    node.metadata_backend.store(target, Ordering::Relaxed);

    // Register target inode in dedup map.
    fs.state
        .inode_map(target)
        .write()
        .unwrap()
        .insert(target_inode, guest_inode);

    // Release retained source pin.
    backend(fs, source).forget(
        Context {
            uid: 0,
            gid: 0,
            pid: 0,
        },
        source_inode,
        1,
    );

    // hooks.after_commit
    super::hooks::notify_observers(&fs.hooks, |h| {
        h.after_commit(&super::hooks::CommitEvent {
            op: super::policy::OpKind::Open,
            guest_inode,
            transition: Some((state_before.clone(), node.state.read().unwrap().clone())),
            dentry_changes: vec![],
        });
    });

    Ok(())
}

/// Promote a single-backed directory to MergedDir.
pub(crate) fn promote_directory_to_merged(
    fs: &DualFs,
    ctx: Context,
    guest_inode: u64,
    target: BackendId,
) -> io::Result<()> {
    let node = get_node(&fs.state, guest_inode)?;

    let (src_backend, src_inode) = {
        let state = node.state.read().unwrap();
        match &*state {
            NodeState::MergedDir { .. } | NodeState::Root { .. } => return Ok(()),
            NodeState::BackendA {
                backend_a_inode, ..
            } if target == BackendId::BackendA => {
                return Ok(());
            }
            NodeState::BackendB {
                backend_b_inode, ..
            } if target == BackendId::BackendB => {
                return Ok(());
            }
            NodeState::BackendA {
                backend_a_inode, ..
            } => (BackendId::BackendA, *backend_a_inode),
            NodeState::BackendB {
                backend_b_inode, ..
            } => (BackendId::BackendB, *backend_b_inode),
            NodeState::Init => return Err(io::Error::from_raw_os_error(libc::ENOTDIR)),
        }
    };

    // Get source metadata.
    let (src_stat, _) = backend(fs, src_backend).getattr(ctx, src_inode, None)?;

    // Resolve parent on target.
    let (parent_ino, name) = fs
        .state
        .alias_index
        .read()
        .unwrap()
        .get(&guest_inode)
        .and_then(|s| s.iter().next().cloned())
        .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))?;

    // Ensure parent has target presence (recursive, root-to-leaf).
    ensure_backend_presence_recursive(fs, ctx, parent_ino, target)?;

    let parent_target_inode = resolve_backend_inode(&fs.state, parent_ino, target)
        .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))?;

    let cname = CString::new(name).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;

    // Create directory in target backend.
    let mode = (src_stat.st_mode as u32) & 0o7777;
    let entry = backend(fs, target).mkdir(
        ctx,
        parent_target_inode,
        &cname,
        mode,
        0,
        Extensions::default(),
    )?;

    // Copy xattrs.
    copy_xattrs(fs, ctx, src_backend, src_inode, target, entry.inode)?;

    // Copy timestamps and ownership.
    copy_metadata(fs, ctx, target, entry.inode, &src_stat)?;

    // Transition to MergedDir.
    let new_state = match (target, src_backend) {
        (BackendId::BackendA, BackendId::BackendB) => NodeState::MergedDir {
            backend_a_inode: entry.inode,
            backend_b_inode: src_inode,
        },
        (BackendId::BackendB, BackendId::BackendA) => NodeState::MergedDir {
            backend_a_inode: src_inode,
            backend_b_inode: entry.inode,
        },
        _ => unreachable!("promotion requires opposite backends"),
    };

    *node.state.write().unwrap() = new_state;
    node.metadata_backend.store(target, Ordering::Relaxed);

    // Register target inode.
    fs.state
        .inode_map(target)
        .write()
        .unwrap()
        .insert(entry.inode, guest_inode);

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Ensure all ancestors of a guest inode have presence on the target backend.
fn ensure_ancestors(
    fs: &DualFs,
    ctx: Context,
    guest_inode: u64,
    target: BackendId,
) -> io::Result<()> {
    // Walk from inode up to root, collecting ancestors.
    let mut ancestors = Vec::new();
    let mut current = guest_inode;

    while current != ROOT_INODE {
        let alias = fs
            .state
            .alias_index
            .read()
            .unwrap()
            .get(&current)
            .and_then(|s| s.iter().next().cloned());

        match alias {
            Some((parent, _)) => {
                ancestors.push(parent);
                current = parent;
            }
            None => break,
        }
    }

    // Process root-to-leaf (skip root itself — always has both).
    ancestors.reverse();
    for &ancestor in &ancestors {
        if ancestor == ROOT_INODE {
            continue;
        }
        let node = match fs.state.nodes.read().unwrap().get(&ancestor).cloned() {
            Some(n) => n,
            None => continue,
        };
        let needs_promotion = {
            let state = node.state.read().unwrap();
            match &*state {
                NodeState::MergedDir { .. } | NodeState::Root { .. } => false,
                NodeState::BackendA { .. } if target == BackendId::BackendA => false,
                NodeState::BackendB { .. } if target == BackendId::BackendB => false,
                _ => node.kind == FileKind::Directory,
            }
        };
        if needs_promotion {
            promote_directory_to_merged(fs, ctx, ancestor, target)?;
        }
    }

    Ok(())
}

/// Recursively ensure backend presence (used by promotion itself).
fn ensure_backend_presence_recursive(
    fs: &DualFs,
    ctx: Context,
    guest_inode: u64,
    target: BackendId,
) -> io::Result<()> {
    if guest_inode == ROOT_INODE {
        return Ok(());
    }

    let node = match fs.state.nodes.read().unwrap().get(&guest_inode).cloned() {
        Some(n) => n,
        None => return Err(io::Error::from_raw_os_error(libc::ENOENT)),
    };

    let needs_promotion = {
        let state = node.state.read().unwrap();
        match &*state {
            NodeState::MergedDir { .. } | NodeState::Root { .. } => false,
            NodeState::BackendA { .. } if target == BackendId::BackendA => false,
            NodeState::BackendB { .. } if target == BackendId::BackendB => false,
            _ => node.kind == FileKind::Directory,
        }
    };

    if needs_promotion {
        // Ensure parent first.
        let parent_ino = fs
            .state
            .alias_index
            .read()
            .unwrap()
            .get(&guest_inode)
            .and_then(|s| s.iter().next().map(|(p, _)| *p))
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))?;

        ensure_backend_presence_recursive(fs, ctx, parent_ino, target)?;
        promote_directory_to_merged(fs, ctx, guest_inode, target)?;
    }

    Ok(())
}

/// Materialize a regular file.
#[allow(clippy::too_many_arguments)]
fn materialize_regular_file(
    fs: &DualFs,
    ctx: Context,
    source: BackendId,
    target: BackendId,
    source_inode: u64,
    parent_target_inode: u64,
    name: &std::ffi::CStr,
    guest_inode: u64,
) -> io::Result<u64> {
    // Read source metadata.
    let (src_stat, _) = backend(fs, source).getattr(ctx, source_inode, None)?;
    let file_size = src_stat.st_size as u64;

    // Create temp file in staging directory.
    let staging_inode = *fs
        .state
        .staging_dirs
        .read()
        .unwrap()
        .get(&target)
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EIO))?;

    let temp_name_str = format!("tmp_{}", guest_inode);
    let temp_name =
        CString::new(temp_name_str).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;

    let mode = (src_stat.st_mode as u32) & 0o7777;
    let (temp_entry, temp_handle, _) = backend(fs, target).create(
        ctx,
        staging_inode,
        &temp_name,
        mode,
        false,
        libc::O_WRONLY as u32,
        0,
        Extensions::default(),
    )?;

    // Stream data from source to target in chunks.
    if file_size > 0 {
        let (src_handle, _) =
            backend(fs, source).open(ctx, source_inode, false, libc::O_RDONLY as u32)?;
        let src_handle = src_handle.unwrap_or(0);

        let mut offset = 0u64;
        while offset < file_size {
            let chunk_size =
                std::cmp::min(fs.cfg.copy_chunk_size as u64, file_size - offset) as u32;

            // Use a pipe/staging approach: read from source, write to target.
            // We use the init_file as a staging buffer for the transfer.
            let staging = &fs.init_file;
            let _read_bytes = backend(fs, source).read(
                ctx,
                source_inode,
                src_handle,
                &mut StagingWriter { file: staging },
                chunk_size,
                offset,
                None,
                0,
            )?;

            let write_handle = temp_handle.unwrap_or(0);
            let _write_bytes = backend(fs, target).write(
                ctx,
                temp_entry.inode,
                write_handle,
                &mut StagingReader {
                    file: staging,
                    size: _read_bytes,
                },
                _read_bytes as u32,
                offset,
                None,
                false,
                false,
                0,
            )?;

            offset += chunk_size as u64;
        }

        backend(fs, source).release(ctx, source_inode, 0, src_handle, false, false, None)?;
    }

    let temp_handle_val = temp_handle.unwrap_or(0);
    backend(fs, target).release(
        ctx,
        temp_entry.inode,
        0,
        temp_handle_val,
        false,
        false,
        None,
    )?;

    // Copy xattrs.
    copy_xattrs(fs, ctx, source, source_inode, target, temp_entry.inode)?;

    // Copy timestamps and ownership.
    copy_metadata(fs, ctx, target, temp_entry.inode, &src_stat)?;

    // Install: rename from staging to final location.
    backend(fs, target).rename(ctx, staging_inode, &temp_name, parent_target_inode, name, 0)?;

    Ok(temp_entry.inode)
}

/// Materialize a symlink.
fn materialize_symlink(
    fs: &DualFs,
    ctx: Context,
    source: BackendId,
    target: BackendId,
    source_inode: u64,
    parent_target_inode: u64,
    name: &std::ffi::CStr,
) -> io::Result<u64> {
    let link_target = backend(fs, source).readlink(ctx, source_inode)?;
    let (src_stat, _) = backend(fs, source).getattr(ctx, source_inode, None)?;

    let link_cstr =
        CString::new(link_target).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;

    let entry = backend(fs, target).symlink(
        ctx,
        &link_cstr,
        parent_target_inode,
        name,
        Extensions::default(),
    )?;

    copy_xattrs(fs, ctx, source, source_inode, target, entry.inode)?;
    copy_metadata(fs, ctx, target, entry.inode, &src_stat)?;

    Ok(entry.inode)
}

/// Materialize a special file (FIFO, socket, block/char device).
fn materialize_special(
    fs: &DualFs,
    ctx: Context,
    source: BackendId,
    target: BackendId,
    source_inode: u64,
    parent_target_inode: u64,
    name: &std::ffi::CStr,
) -> io::Result<u64> {
    let (src_stat, _) = backend(fs, source).getattr(ctx, source_inode, None)?;

    let entry = backend(fs, target).mknod(
        ctx,
        parent_target_inode,
        name,
        src_stat.st_mode as u32,
        src_stat.st_rdev as u32,
        0,
        Extensions::default(),
    )?;

    copy_xattrs(fs, ctx, source, source_inode, target, entry.inode)?;
    copy_metadata(fs, ctx, target, entry.inode, &src_stat)?;

    Ok(entry.inode)
}

/// Copy xattrs from source to target.
fn copy_xattrs(
    fs: &DualFs,
    ctx: Context,
    source: BackendId,
    source_inode: u64,
    target: BackendId,
    target_inode: u64,
) -> io::Result<()> {
    let list = match backend(fs, source).listxattr(ctx, source_inode, 0) {
        Ok(crate::ListxattrReply::Names(names)) => names,
        Ok(crate::ListxattrReply::Count(_)) => return Ok(()),
        Err(_) => return Ok(()), // Some backends don't support xattrs.
    };

    // Parse null-separated xattr name list.
    for xattr_name in list.split(|&b| b == 0) {
        if xattr_name.is_empty() {
            continue;
        }
        let cname = match CString::new(xattr_name) {
            Ok(c) => c,
            Err(_) => continue,
        };
        match backend(fs, source).getxattr(ctx, source_inode, &cname, 0) {
            Ok(crate::GetxattrReply::Value(value)) => {
                let _ = backend(fs, target).setxattr(ctx, target_inode, &cname, &value, 0);
            }
            _ => continue,
        }
    }

    Ok(())
}

/// Copy timestamps and ownership from stat to target inode.
fn copy_metadata(
    fs: &DualFs,
    ctx: Context,
    target: BackendId,
    target_inode: u64,
    src_stat: &crate::stat64,
) -> io::Result<()> {
    let valid = SetattrValid::UID | SetattrValid::GID | SetattrValid::ATIME | SetattrValid::MTIME;

    backend(fs, target).setattr(ctx, target_inode, *src_stat, None, valid)?;

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Types: Staging Adapters
//--------------------------------------------------------------------------------------------------

/// Adapter: writes data from a backend read into the staging file.
struct StagingWriter<'a> {
    file: &'a std::fs::File,
}

impl crate::ZeroCopyWriter for StagingWriter<'_> {
    fn write_from(&mut self, f: &std::fs::File, count: usize, off: u64) -> io::Result<usize> {
        // Read from f at off, write to our staging file at 0.
        use std::os::fd::AsRawFd;

        let mut buf = vec![0u8; count];
        let fd = f.as_raw_fd();
        let n = unsafe {
            libc::pread(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                count,
                off as libc::off_t,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n as usize;

        let staging_fd = self.file.as_raw_fd();
        let w = unsafe { libc::pwrite(staging_fd, buf.as_ptr() as *const libc::c_void, n, 0) };
        if w < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(w as usize)
    }
}

/// Adapter: reads data from the staging file for a backend write.
struct StagingReader<'a> {
    file: &'a std::fs::File,
    size: usize,
}

impl crate::ZeroCopyReader for StagingReader<'_> {
    fn read_to(&mut self, f: &std::fs::File, count: usize, off: u64) -> io::Result<usize> {
        use std::os::fd::AsRawFd;

        let to_read = std::cmp::min(count, self.size);
        let mut buf = vec![0u8; to_read];

        let staging_fd = self.file.as_raw_fd();
        let n = unsafe {
            libc::pread(
                staging_fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                to_read,
                0,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n as usize;

        let fd = f.as_raw_fd();
        let w = unsafe {
            libc::pwrite(
                fd,
                buf.as_ptr() as *const libc::c_void,
                n,
                off as libc::off_t,
            )
        };
        if w < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(w as usize)
    }
}

//! Opendir, readdir, readdirplus, releasedir, and snapshot building.

use std::{
    collections::HashSet,
    io,
    sync::{Arc, atomic::Ordering},
};

use super::{
    DualFs,
    lookup::{auto_register_readdir, backend, get_node},
    policy::{BackendChoice, DualDispatchPlan, DualNamespaceView, HintBag, OpKind, RequestCtx},
    types::{
        BackendId, DirSnapshot, DualDirHandle, FileKind, MergedDirEntry, NodeState, ROOT_INODE,
    },
};
use crate::{
    Context, DirEntry, Entry, OpenOptions,
    backends::shared::{
        dir_snapshot::{self, SnapshotEntry},
        init_binary, platform,
    },
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Name of the hidden staging directory (filtered from readdir).
const STAGING_DIR_NAME: &[u8] = b".dualfs_staging";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Handle opendir. Compute readdir plan and allocate handle.
pub(crate) fn do_opendir(
    fs: &DualFs,
    _ctx: Context,
    ino: u64,
    _flags: u32,
) -> io::Result<(Option<u64>, OpenOptions)> {
    let node = get_node(&fs.state, ino)?;
    if node.kind != FileKind::Directory {
        return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
    }

    // Determine readdir plan from policy.
    let node_state = node.state.read().unwrap().clone();
    let req_ctx = RequestCtx {
        op: OpKind::Readdir,
        guest_inode: ino,
        node_state: node_state.clone(),
        file_kind: node.kind,
        flags: 0,
        name: Vec::new(),
        parent_inode: 0,
    };
    let view = DualNamespaceView { state: &fs.state };
    let hints = HintBag::new();

    let readdir_plan = fs.policy.plan(&req_ctx, &view, &hints)?;

    // Validate plan type.
    match &readdir_plan {
        DualDispatchPlan::MergeReaddir { .. }
        | DualDispatchPlan::UseBackendA { .. }
        | DualDispatchPlan::UseBackendB { .. } => {}
        _ => return Err(io::Error::from_raw_os_error(libc::EINVAL)),
    }

    // Extract child inode IDs for the handle.
    let (backend_a_inode, backend_b_inode) = {
        let state = node.state.read().unwrap();
        match &*state {
            NodeState::Root {
                backend_a_root,
                backend_b_root,
            } => (Some(*backend_a_root), Some(*backend_b_root)),
            NodeState::BackendA {
                backend_a_inode, ..
            } => (Some(*backend_a_inode), None),
            NodeState::BackendB {
                backend_b_inode, ..
            } => (None, Some(*backend_b_inode)),
            NodeState::MergedDir {
                backend_a_inode,
                backend_b_inode,
            } => (Some(*backend_a_inode), Some(*backend_b_inode)),
            NodeState::Init => return Err(io::Error::from_raw_os_error(libc::ENOTDIR)),
        }
    };

    let handle = fs.state.next_handle.fetch_add(1, Ordering::Relaxed);

    fs.state.dir_handles.write().unwrap().insert(
        handle,
        Arc::new(DualDirHandle {
            guest_inode: ino,
            backend_a_inode,
            backend_b_inode,
            readdir_plan,
            snapshot: std::sync::Mutex::new(None),
        }),
    );

    Ok((Some(handle), OpenOptions::empty()))
}

/// Handle readdir. Build or serve from snapshot.
pub(crate) fn do_readdir(
    fs: &DualFs,
    ctx: Context,
    _ino: u64,
    handle: u64,
    _size: u32,
    offset: u64,
) -> io::Result<Vec<DirEntry<'static>>> {
    let dh = get_dir_handle(fs, handle)?;
    let mut snapshot_guard = dh.snapshot.lock().unwrap();

    // Build snapshot on first call.
    if snapshot_guard.is_none() {
        *snapshot_guard = Some(build_readdir_snapshot(fs, ctx, dh.guest_inode, &dh)?);
    }

    let snapshot = snapshot_guard.as_ref().unwrap();
    serve_readdir(snapshot, offset)
}

/// Handle readdirplus.
pub(crate) fn do_readdirplus(
    fs: &DualFs,
    ctx: Context,
    _ino: u64,
    handle: u64,
    _size: u32,
    offset: u64,
) -> io::Result<Vec<(DirEntry<'static>, Entry)>> {
    let dh = get_dir_handle(fs, handle)?;
    let mut snapshot_guard = dh.snapshot.lock().unwrap();

    if snapshot_guard.is_none() {
        *snapshot_guard = Some(build_readdir_snapshot(fs, ctx, dh.guest_inode, &dh)?);
    }

    let snapshot = snapshot_guard.as_ref().unwrap();
    let dir_entries = serve_readdir(snapshot, offset)?;

    let mut result = Vec::with_capacity(dir_entries.len());
    for de in dir_entries {
        // Build entry with attrs.
        let entry = if de.ino == init_binary::INIT_INODE {
            init_binary::init_entry(fs.cfg.entry_timeout, fs.cfg.attr_timeout)
        } else if let Some(node) = fs.state.nodes.read().unwrap().get(&de.ino).cloned() {
            node.lookup_refs.fetch_add(1, Ordering::Relaxed);
            let (backend_id, child_inode) = super::lookup::resolve_active_backend_inode(&node);
            match backend(fs, backend_id).getattr(ctx, child_inode, None) {
                Ok((mut st, _)) => {
                    st.st_ino = de.ino;
                    Entry {
                        inode: de.ino,
                        generation: 0,
                        attr: st,
                        attr_flags: 0,
                        attr_timeout: fs.cfg.attr_timeout,
                        entry_timeout: fs.cfg.entry_timeout,
                    }
                }
                Err(_) => {
                    // Fallback: minimal entry.
                    Entry {
                        inode: de.ino,
                        generation: 0,
                        attr: unsafe { std::mem::zeroed() },
                        attr_flags: 0,
                        attr_timeout: fs.cfg.attr_timeout,
                        entry_timeout: fs.cfg.entry_timeout,
                    }
                }
            }
        } else {
            Entry {
                inode: de.ino,
                generation: 0,
                attr: unsafe { std::mem::zeroed() },
                attr_flags: 0,
                attr_timeout: fs.cfg.attr_timeout,
                entry_timeout: fs.cfg.entry_timeout,
            }
        };

        result.push((de, entry));
    }

    Ok(result)
}

/// Handle releasedir.
pub(crate) fn do_releasedir(
    fs: &DualFs,
    _ctx: Context,
    _ino: u64,
    _flags: u32,
    handle: u64,
) -> io::Result<()> {
    fs.state.dir_handles.write().unwrap().remove(&handle);
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl SnapshotEntry for MergedDirEntry {
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

/// Build a merged readdir snapshot.
fn build_readdir_snapshot(
    fs: &DualFs,
    ctx: Context,
    guest_inode: u64,
    dh: &DualDirHandle,
) -> io::Result<DirSnapshot> {
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    let mut entries: Vec<MergedDirEntry> = Vec::new();
    let mut off = 1u64;

    // Standard "." and ".." entries.
    entries.push(MergedDirEntry {
        name: b".".to_vec(),
        inode: guest_inode,
        offset: off,
        file_type: platform::DIRENT_DIR,
    });
    off += 1;
    seen.insert(b".".to_vec());

    // ".." — use parent or self for root.
    let parent_inode = fs
        .state
        .alias_index
        .read()
        .unwrap()
        .get(&guest_inode)
        .and_then(|s| s.iter().next().map(|(p, _)| *p))
        .unwrap_or(guest_inode);
    entries.push(MergedDirEntry {
        name: b"..".to_vec(),
        inode: parent_inode,
        offset: off,
        file_type: platform::DIRENT_DIR,
    });
    off += 1;
    seen.insert(b"..".to_vec());

    // init.krun injection for root.
    if guest_inode == ROOT_INODE {
        entries.push(MergedDirEntry {
            name: init_binary::INIT_FILENAME.to_vec(),
            inode: init_binary::INIT_INODE,
            offset: off,
            file_type: platform::DIRENT_REG,
        });
        off += 1;
        seen.insert(init_binary::INIT_FILENAME.to_vec());
    }

    // Collect whiteout/opaque state.
    let whiteouts = fs.state.whiteouts.read().unwrap();
    let opaque_dirs = fs.state.opaque_dirs.read().unwrap();
    let opaque_a = opaque_dirs.contains(&(guest_inode, BackendId::BackendA));
    let opaque_b = opaque_dirs.contains(&(guest_inode, BackendId::BackendB));

    match &dh.readdir_plan {
        DualDispatchPlan::MergeReaddir {
            precedence: BackendChoice::BackendBFirst,
        } => {
            // Pass 1: backend_b via readdir.
            if !opaque_b && let Some(bb_inode) = dh.backend_b_inode {
                collect_backend_entries(
                    fs,
                    ctx,
                    BackendId::BackendB,
                    bb_inode,
                    guest_inode,
                    &mut seen,
                    &mut entries,
                    &mut off,
                    &whiteouts,
                    BackendId::BackendB,
                )?;
            }

            // Pass 2: backend_a children from dentries.
            if !opaque_a {
                collect_dentry_entries(
                    fs,
                    guest_inode,
                    BackendId::BackendA,
                    &mut seen,
                    &mut entries,
                    &mut off,
                    &whiteouts,
                );
            }
        }

        DualDispatchPlan::MergeReaddir {
            precedence: BackendChoice::BackendAFirst,
        } => {
            // Pass 1: backend_a via readdir.
            if !opaque_a && let Some(ba_inode) = dh.backend_a_inode {
                collect_backend_entries(
                    fs,
                    ctx,
                    BackendId::BackendA,
                    ba_inode,
                    guest_inode,
                    &mut seen,
                    &mut entries,
                    &mut off,
                    &whiteouts,
                    BackendId::BackendA,
                )?;
            }

            // Pass 2: backend_b via readdir.
            if !opaque_b && let Some(bb_inode) = dh.backend_b_inode {
                collect_backend_entries(
                    fs,
                    ctx,
                    BackendId::BackendB,
                    bb_inode,
                    guest_inode,
                    &mut seen,
                    &mut entries,
                    &mut off,
                    &whiteouts,
                    BackendId::BackendB,
                )?;
            }
        }

        DualDispatchPlan::UseBackendA { .. } => {
            if !opaque_a && let Some(ba_inode) = dh.backend_a_inode {
                collect_backend_entries(
                    fs,
                    ctx,
                    BackendId::BackendA,
                    ba_inode,
                    guest_inode,
                    &mut seen,
                    &mut entries,
                    &mut off,
                    &whiteouts,
                    BackendId::BackendA,
                )?;
            }
        }

        DualDispatchPlan::UseBackendB { .. } => {
            if !opaque_b && let Some(bb_inode) = dh.backend_b_inode {
                collect_backend_entries(
                    fs,
                    ctx,
                    BackendId::BackendB,
                    bb_inode,
                    guest_inode,
                    &mut seen,
                    &mut entries,
                    &mut off,
                    &whiteouts,
                    BackendId::BackendB,
                )?;
            }
        }

        _ => {} // Invalid plan — return what we have.
    }

    Ok(DirSnapshot { entries })
}

/// Collect entries from a backend via readdir, auto-registering unknown ones.
#[allow(clippy::too_many_arguments)]
fn collect_backend_entries(
    fs: &DualFs,
    ctx: Context,
    backend_id: BackendId,
    backend_inode: u64,
    guest_parent: u64,
    seen: &mut HashSet<Vec<u8>>,
    entries: &mut Vec<MergedDirEntry>,
    off: &mut u64,
    whiteouts: &std::collections::HashSet<(u64, Vec<u8>, BackendId)>,
    hidden_check_backend: BackendId,
) -> io::Result<()> {
    let (dir_handle, _) = backend(fs, backend_id).opendir(ctx, backend_inode, 0)?;
    let dir_handle_val = dir_handle.unwrap_or(0);

    let child_entries =
        backend(fs, backend_id).readdir(ctx, backend_inode, dir_handle_val, u32::MAX, 0)?;
    let _ = backend(fs, backend_id).releasedir(ctx, backend_inode, 0, dir_handle_val);

    for entry in child_entries {
        let name = entry.name.to_vec();

        // Skip . and ..
        if name == b"." || name == b".." {
            continue;
        }

        // Skip staging dir.
        if guest_parent == ROOT_INODE && name == STAGING_DIR_NAME {
            continue;
        }

        // Already seen?
        if seen.contains(&name) {
            continue;
        }

        // Whited out?
        if whiteouts.contains(&(guest_parent, name.clone(), hidden_check_backend)) {
            continue;
        }

        seen.insert(name.clone());

        // Auto-register if needed.
        if let Some(guest_ino) = auto_register_readdir(
            fs,
            ctx,
            entry.ino,
            &name,
            entry.type_,
            guest_parent,
            backend_inode,
            backend_id,
        ) {
            entries.push(MergedDirEntry {
                name,
                inode: guest_ino,
                offset: *off,
                file_type: entry.type_,
            });
            *off += 1;
        }
    }

    Ok(())
}

/// Collect entries from dentries for a specific backend side.
fn collect_dentry_entries(
    fs: &DualFs,
    guest_parent: u64,
    backend_filter: BackendId,
    seen: &mut HashSet<Vec<u8>>,
    entries: &mut Vec<MergedDirEntry>,
    off: &mut u64,
    whiteouts: &std::collections::HashSet<(u64, Vec<u8>, BackendId)>,
) {
    let dentries = fs.state.dentries.read().unwrap();
    let nodes = fs.state.nodes.read().unwrap();

    for ((parent, name), &child_ino) in dentries.iter() {
        if *parent != guest_parent {
            continue;
        }
        if seen.contains(name) {
            continue;
        }
        if whiteouts.contains(&(guest_parent, name.clone(), backend_filter)) {
            continue;
        }

        let child_node = match nodes.get(&child_ino) {
            Some(n) => n,
            None => continue,
        };

        // Only include nodes that are on the filter backend or merged.
        let state = child_node.state.read().unwrap();
        let include = matches!(
            (&*state, backend_filter),
            (NodeState::BackendA { .. }, BackendId::BackendA)
                | (NodeState::BackendB { .. }, BackendId::BackendB)
                | (NodeState::MergedDir { .. }, _)
        );

        if include {
            seen.insert(name.clone());
            entries.push(MergedDirEntry {
                name: name.clone(),
                inode: child_ino,
                offset: *off,
                file_type: child_node.kind.to_dtype(),
            });
            *off += 1;
        }
    }
}

/// Serve readdir results from a snapshot starting at the given offset.
fn serve_readdir(snapshot: &DirSnapshot, offset: u64) -> io::Result<Vec<DirEntry<'static>>> {
    Ok(dir_snapshot::serve_snapshot_entries(
        &snapshot.entries,
        offset,
    ))
}

/// Get a directory handle by guest handle ID.
fn get_dir_handle(fs: &DualFs, handle: u64) -> io::Result<Arc<DualDirHandle>> {
    fs.state
        .dir_handles
        .read()
        .unwrap()
        .get(&handle)
        .cloned()
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))
}

//! Owned passthrough state, including regular files whose final namespace link was removed.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::{self, File},
    io,
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd},
        unix::ffi::OsStrExt,
    },
    sync::{Arc, RwLock, atomic::Ordering},
};

use serde::{Deserialize, Serialize};

use super::{
    DirEntryState, DirHandleState, FileHandleState, InodeState, PassthroughFs, PassthroughState,
    PreparedState, capture_inodes, inode, inode_data_from_fd, invalid_state, mobility, rebuild,
    restored_open_flags, validate_semantics,
};
use crate::backends::{
    passthroughfs::owned::{DirectoryCapture, ObjectKind, OwnedDirectorySnapshot},
    shared::{handle_table::HandleData, inode_table::MultikeyBTreeMap},
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const KIND: &[u8; 8] = b"MSBPTOW1";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct OwnedState {
    descriptor_digest: String,
    linked: PassthroughState,
    detached: Vec<DetachedInode>,
}

#[derive(Serialize, Deserialize)]
struct DetachedInode {
    inode: u64,
    refcount: u64,
    object: u64,
    handles: Vec<FileHandleState>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn capture(fs: &PassthroughFs) -> io::Result<Vec<u8>> {
    if fs.writeback.load(Ordering::Acquire) {
        return Err(invalid_state(
            "owned checkpoint requires a completed guest writeback boundary",
        ));
    }
    let checkpoint = fs
        .cfg
        .owned_checkpoint
        .as_ref()
        .expect("owned capture selected");
    let destination = checkpoint.take_capture()?;
    let mut generation = DirectoryCapture::new(&fs.cfg.root_dir, &destination)?;
    let detached_inodes = fs
        .inodes
        .read()
        .unwrap()
        .iter()
        .filter_map(|(id, data)| {
            #[cfg(target_os = "linux")]
            let detached = data.retained_fd.lock().unwrap().is_some();
            #[cfg(target_os = "macos")]
            let detached = data.unlinked_fd.load(Ordering::Acquire) >= 0;
            detached.then_some((*id, data.refcount.load(Ordering::Acquire)))
        })
        .collect::<Vec<_>>();
    let detached_ids = detached_inodes
        .iter()
        .map(|(id, _)| *id)
        .collect::<BTreeSet<_>>();
    if fs
        .dir_handles
        .read()
        .unwrap()
        .values()
        .any(|handle| detached_ids.contains(&handle.inode))
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "owned checkpoint does not support detached directory handles",
        ));
    }
    let mut detached = Vec::new();
    for (id, refcount) in detached_inodes {
        // Reopen/duplicate the retained inode, never the removed path or its replacement.
        let fd = inode::open_inode_fd(fs, id, libc::O_RDONLY)?;
        let file = unsafe { File::from_raw_fd(fd) };
        let object = generation.add_detached(&file)?;
        if fs.cfg.xattr_enabled() {
            let stat = inode::stat_inode(fs, id)?;
            generation.set_guest_metadata(
                object,
                stat.st_uid,
                stat.st_gid,
                stat.st_mode as u32,
                stat.st_rdev as u32,
            )?;
        }
        let handles = fs
            .handles
            .read()
            .unwrap()
            .iter()
            .filter(|(_, handle)| handle.inode == id)
            .map(|(handle, data)| FileHandleState {
                handle: *handle,
                inode: id,
                flags: data.flags,
            })
            .collect();
        detached.push(DetachedInode {
            inode: id,
            refcount,
            object,
            handles,
        });
    }
    let linked = PassthroughState {
        next_inode: fs.next_inode.load(Ordering::Acquire),
        next_handle: fs.next_handle.load(Ordering::Acquire),
        writeback: false,
        quota: fs.quota.as_ref().map(|quota| quota.capture_state()),
        inodes: capture_inodes(fs, &detached_ids)?,
        files: fs
            .handles
            .read()
            .unwrap()
            .iter()
            .filter(|(_, data)| !detached_ids.contains(&data.inode))
            .map(|(handle, data)| FileHandleState {
                handle: *handle,
                inode: data.inode,
                flags: data.flags,
            })
            .collect(),
        dirs: fs
            .dir_handles
            .read()
            .unwrap()
            .iter()
            .map(|(handle, data)| DirHandleState {
                handle: *handle,
                inode: data.inode,
                flags: data.flags,
                entries: data.snapshot.lock().unwrap().as_ref().map(|snapshot| {
                    snapshot
                        .entries
                        .iter()
                        .map(|entry| DirEntryState {
                            inode: entry.inode,
                            name: entry.name.clone(),
                            offset: entry.offset,
                            file_type: entry.file_type,
                        })
                        .collect()
                }),
            })
            .collect(),
    };
    let snapshot = generation.finish()?;
    let state = OwnedState {
        descriptor_digest: snapshot.digest()?,
        linked,
        detached,
    };
    validate(fs, &state, &snapshot)?;
    let bytes = mobility::encode(KIND, &state)?;
    checkpoint.completed(snapshot)?;
    Ok(bytes)
}

pub(super) fn prepare(fs: &PassthroughFs, bytes: &[u8]) -> io::Result<PreparedState> {
    let state: OwnedState = mobility::decode(KIND, bytes)?;
    let generation = fs
        .cfg
        .owned_checkpoint
        .as_ref()
        .expect("owned prepare selected")
        .restore()?;
    let snapshot = OwnedDirectorySnapshot::open_expected(&generation, &state.descriptor_digest)?;
    validate(fs, &state, &snapshot)?;
    let mut prepared = rebuild(fs, state.linked, None)?;
    let parent = fs
        .cfg
        .root_dir
        .parent()
        .ok_or_else(|| invalid_state("owned root has no storage parent"))?;
    let staging = tempfile::Builder::new()
        .prefix(".owned-detached-")
        .tempdir_in(parent)?;
    for detached in state.detached {
        let visible = snapshot.visible_object_path(&fs.cfg.root_dir, detached.object)?;
        let temporary = visible.is_none();
        let path =
            visible.unwrap_or_else(|| staging.path().join(format!("inode-{}", detached.inode)));
        if temporary {
            snapshot.materialize_object(&generation, detached.object, &path)?;
        }
        let pinned = fs::OpenOptions::new().read(true).write(true).open(&path)?;
        // The shared constructor obtains destination-local inode identity. Detached Linux
        // nodes immediately lose the synthetic anchor and keep only a retained descriptor.
        let saved = InodeState {
            inode: detached.inode,
            components: vec![b"detached".to_vec()],
            refcount: detached.refcount,
        };
        let (key, data) = inode_data_from_fd(
            fs,
            &MultikeyBTreeMap::new(),
            &saved,
            &BTreeMap::from([(Vec::new(), 1)]),
            pinned.as_raw_fd(),
        )?;
        if prepared.inodes.get_alt(&key).is_some() {
            return Err(invalid_state(
                "multiple owned guest inodes resolve to one child object",
            ));
        }
        #[cfg(target_os = "linux")]
        {
            data.anchor_parent.store(0, Ordering::Release);
            data.anchor_name.write().unwrap().clear();
            data.aliases.write().unwrap().clear();
        }
        for handle in detached.handles {
            let cpath = CString::new(path.as_os_str().as_bytes())
                .map_err(|error| invalid_state(error.to_string()))?;
            let flags =
                restored_open_flags(handle.flags, false) | libc::O_NOFOLLOW | libc::O_CLOEXEC;
            let fd = unsafe { libc::open(cpath.as_ptr(), flags) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let file = unsafe { File::from_raw_fd(fd) };
            prepared.files.insert(
                handle.handle,
                Arc::new(HandleData {
                    inode: detached.inode,
                    flags: handle.flags,
                    file: RwLock::new(file),
                }),
            );
        }
        inode::store_unlinked_fd(&data, pinned.into_raw_fd());
        if temporary {
            fs::remove_file(&path)?;
        }
        prepared.inodes.insert(detached.inode, key, data);
    }
    Ok(prepared)
}

fn validate(
    fs: &PassthroughFs,
    state: &OwnedState,
    snapshot: &OwnedDirectorySnapshot,
) -> io::Result<()> {
    if state.linked.writeback {
        return Err(invalid_state(
            "owned restore cannot retain negotiated writeback cache",
        ));
    }
    validate_semantics(fs, &state.linked, false)?;
    let mut inodes = state
        .linked
        .inodes
        .iter()
        .map(|inode| inode.inode)
        .collect::<BTreeSet<_>>();
    let mut handles = state
        .linked
        .files
        .iter()
        .map(|handle| handle.handle)
        .chain(state.linked.dirs.iter().map(|handle| handle.handle))
        .collect::<BTreeSet<_>>();
    let mut objects = BTreeSet::new();
    for detached in &state.detached {
        if detached.inode <= 2
            || detached.inode >= state.linked.next_inode
            || !inodes.insert(detached.inode)
            || !objects.insert(detached.object)
            || !matches!(snapshot.object(detached.object)?.kind, ObjectKind::File(_))
        {
            return Err(invalid_state("invalid owned detached inode"));
        }
        for handle in &detached.handles {
            if handle.inode != detached.inode
                || handle.handle == 0
                || handle.handle >= state.linked.next_handle
                || !handles.insert(handle.handle)
                || handle.flags & 0b11 == 0b11
                || (fs.cfg.readonly() && handle.flags & 0b11 != 0)
            {
                return Err(invalid_state("invalid owned detached handle"));
            }
        }
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{FileExt, MetadataExt};

    use super::*;
    use crate::{
        Context, DynFileSystem, FsOptions, OwnedDirectoryCheckpoint, PassthroughConfig,
        StatVirtualization,
    };

    fn backend(root: &std::path::Path, checkpoint: OwnedDirectoryCheckpoint) -> PassthroughFs {
        PassthroughFs::new(PassthroughConfig {
            root_dir: root.into(),
            inject_init: false,
            stat_virtualization: StatVirtualization::Off,
            owned_checkpoint: Some(checkpoint),
            ..Default::default()
        })
        .unwrap()
    }

    #[test]
    fn detached_regular_file_survives_source_removal_and_repeated_capture() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("source");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("unlinked"), b"original data").unwrap();
        fs::write(root.join("never-looked-up"), b"whole namespace").unwrap();
        let checkpoint = OwnedDirectoryCheckpoint::default();
        let source = backend(&root, checkpoint.clone());
        source.init(FsOptions::empty()).unwrap();
        let ctx = Context {
            uid: 0,
            gid: 0,
            pid: 0,
        };
        let entry = source.lookup(ctx, 1, c"unlinked").unwrap();
        let handle = source.open(ctx, entry.inode, false, 2).unwrap().0.unwrap();
        source.unlink(ctx, 1, c"unlinked").unwrap();
        let generation = temp.path().join("generation");
        checkpoint.prepare_capture(&generation).unwrap();
        let state = source.capture_state().unwrap();
        let snapshot = checkpoint.finish_capture().unwrap();
        assert!(state.len() < 4096);
        drop(source);
        fs::remove_dir_all(&root).unwrap();
        let child = temp.path().join("child");
        snapshot.materialize(&generation, &child).unwrap();
        assert!(!child.join("unlinked").exists());
        assert_eq!(
            fs::read(child.join("never-looked-up")).unwrap(),
            b"whole namespace"
        );
        let restore = OwnedDirectoryCheckpoint::default();
        restore.set_restore(&generation).unwrap();
        let destination = backend(&child, restore.clone());
        destination.validate_state(&state).unwrap();
        destination.validate_state(&state).unwrap();
        destination.restore_state(&state).unwrap();
        let restored = destination.handles.read().unwrap()[&handle].clone();
        let file = restored.file.read().unwrap();
        assert_eq!(file.metadata().unwrap().nlink(), 0);
        let mut content = [0; 13];
        file.read_exact_at(&mut content, 0).unwrap();
        assert_eq!(&content, b"original data");
        file.write_all_at(b"modified", 0).unwrap();
        drop(file);
        let second = temp.path().join("second");
        restore.prepare_capture(&second).unwrap();
        destination.capture_state().unwrap();
        assert!(!restore.finish_capture().unwrap().payloads().is_empty());
        assert!(!child.join("unlinked").exists());
    }

    #[test]
    fn linked_handles_and_directory_iterator_relocate_with_logical_identities() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("source");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("data"), b"linked content").unwrap();
        let checkpoint = OwnedDirectoryCheckpoint::default();
        let source = backend(&root, checkpoint.clone());
        source.init(FsOptions::empty()).unwrap();
        let ctx = Context {
            uid: 0,
            gid: 0,
            pid: 0,
        };
        let entry = source.lookup(ctx, 1, c"data").unwrap();
        let handle = source.open(ctx, entry.inode, false, 2).unwrap().0.unwrap();
        let dir = source.opendir(ctx, 1, 0).unwrap().0.unwrap();
        let entries = source
            .readdir(ctx, 1, dir, 65536, 0)
            .unwrap()
            .into_iter()
            .map(|entry| (entry.name.to_owned(), entry.offset))
            .collect::<Vec<_>>();
        let generation = temp.path().join("generation");
        checkpoint.prepare_capture(&generation).unwrap();
        let state = source.capture_state().unwrap();
        let snapshot = checkpoint.finish_capture().unwrap();
        let child = temp.path().join("child");
        snapshot.materialize(&generation, &child).unwrap();
        let restore = OwnedDirectoryCheckpoint::default();
        restore.set_restore(&generation).unwrap();
        let destination = backend(&child, restore);
        destination.restore_state(&state).unwrap();
        assert_eq!(
            destination.lookup(ctx, 1, c"data").unwrap().inode,
            entry.inode
        );
        assert_eq!(
            destination
                .readdir(ctx, 1, dir, 65536, 0)
                .unwrap()
                .into_iter()
                .map(|entry| (entry.name.to_owned(), entry.offset))
                .collect::<Vec<_>>(),
            entries
        );
        let restored = destination.handles.read().unwrap()[&handle].clone();
        restored
            .file
            .read()
            .unwrap()
            .write_all_at(b"child", 0)
            .unwrap();
        assert_eq!(fs::read(root.join("data")).unwrap(), b"linked content");
        assert_eq!(&fs::read(child.join("data")).unwrap()[..5], b"child");
    }

    #[test]
    fn retained_inode_reuses_its_unobserved_namespace_hardlink() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("source");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("data"), b"linked content").unwrap();
        fs::hard_link(root.join("data"), root.join("alias")).unwrap();
        let checkpoint = OwnedDirectoryCheckpoint::default();
        let source = backend(&root, checkpoint.clone());
        source.init(FsOptions::empty()).unwrap();
        let ctx = Context {
            uid: 0,
            gid: 0,
            pid: 0,
        };
        let entry = source.lookup(ctx, 1, c"data").unwrap();
        let handle = source.open(ctx, entry.inode, false, 2).unwrap().0.unwrap();
        source.unlink(ctx, 1, c"data").unwrap();
        let generation = temp.path().join("generation");
        checkpoint.prepare_capture(&generation).unwrap();
        let state = source.capture_state().unwrap();
        let child = temp.path().join("child");
        checkpoint
            .finish_capture()
            .unwrap()
            .materialize(&generation, &child)
            .unwrap();
        let restore = OwnedDirectoryCheckpoint::default();
        restore.set_restore(&generation).unwrap();
        let destination = backend(&child, restore);
        destination.restore_state(&state).unwrap();
        let restored = destination.handles.read().unwrap()[&handle].clone();
        restored
            .file
            .read()
            .unwrap()
            .write_all_at(b"alias", 0)
            .unwrap();
        assert_eq!(&fs::read(child.join("alias")).unwrap()[..5], b"alias");
        assert_eq!(
            destination.lookup(ctx, 1, c"alias").unwrap().inode,
            entry.inode
        );
    }

    #[test]
    fn native_symlink_aliases_keep_fuse_identity_after_full_restore() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("source");
        fs::create_dir(&root).unwrap();
        let checkpoint = OwnedDirectoryCheckpoint::default();
        let source = backend(&root, checkpoint.clone());
        source.init(FsOptions::empty()).unwrap();
        let ctx = Context {
            uid: 0,
            gid: 0,
            pid: 0,
        };
        let entry = source
            .symlink(
                ctx,
                c"/absent-owned-test-target",
                1,
                c"link",
                crate::Extensions::default(),
            )
            .unwrap();
        let alias = source.link(ctx, entry.inode, 1, c"alias").unwrap();
        assert_eq!(entry.inode, alias.inode);
        assert_eq!(alias.attr.st_nlink, 2);
        let generation = temporary.path().join("generation");
        checkpoint.prepare_capture(&generation).unwrap();
        let state = source.capture_state().unwrap();
        let snapshot = checkpoint.finish_capture().unwrap();
        drop(source);
        fs::remove_dir_all(&root).unwrap();
        let child = temporary.path().join("child");
        snapshot.materialize(&generation, &child).unwrap();
        let restored_checkpoint = OwnedDirectoryCheckpoint::default();
        restored_checkpoint.set_restore(&generation).unwrap();
        let destination = backend(&child, restored_checkpoint.clone());
        destination.restore_state(&state).unwrap();
        for name in [c"link", c"alias"] {
            let restored = destination.lookup(ctx, 1, name).unwrap();
            assert_eq!(restored.inode, entry.inode);
            assert_eq!(restored.attr.st_nlink, 2);
            assert_eq!(restored.attr.st_mode as u32 & 0o170000, 0o120000);
        }
        destination.unlink(ctx, 1, c"link").unwrap();
        let remaining = destination.lookup(ctx, 1, c"alias").unwrap();
        assert_eq!(remaining.inode, entry.inode);
        assert_eq!(remaining.attr.st_nlink, 1);
        assert_eq!(
            destination.readlink(ctx, entry.inode).unwrap(),
            b"/absent-owned-test-target"
        );
        restored_checkpoint
            .prepare_capture(&temporary.path().join("recapture"))
            .unwrap();
        destination.capture_state().unwrap();
        restored_checkpoint.finish_capture().unwrap();
    }
}

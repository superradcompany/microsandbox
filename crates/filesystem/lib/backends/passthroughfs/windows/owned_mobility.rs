//! Windows owned backend state: linked namespace plus retained, unnamed regular files.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

use serde::{Deserialize, Serialize};
use std::os::windows::ffi::OsStrExt;
use std::path::Component;

use super::super::{HandleData, InodeData, inode::VirtualMetadata};
use super::{
    FileHandleState, PassthroughFs, PassthroughState, PreparedState, capture_linked, invalid_state,
    mobility, open_options_from_flags, rebuild, validate_quota, validate_shape,
};
use crate::backends::passthroughfs::owned::{DirectoryCapture, ObjectKind, OwnedDirectorySnapshot};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const KIND: &[u8; 8] = b"MSBPTWW1";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct OwnedState {
    descriptor_digest: String,
    linked: PassthroughState,
    detached: Vec<DetachedInode>,
    lookups: BTreeMap<u64, u64>,
    aliases: Vec<OwnedAlias>,
}

#[derive(Serialize, Deserialize)]
struct OwnedAlias {
    inode: u64,
    components: Vec<Vec<u16>>,
}

#[derive(Serialize, Deserialize)]
struct DetachedInode {
    inode: u64,
    object: u64,
    guest: [u32; 4],
    handles: Vec<FileHandleState>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn capture(fs: &PassthroughFs) -> io::Result<Vec<u8>> {
    let checkpoint = fs
        .cfg
        .owned_checkpoint
        .as_ref()
        .expect("owned capture selected");
    let destination = checkpoint.take_capture()?;
    let mut generation = DirectoryCapture::new(&fs.root, &destination)?;
    let retained = fs
        .inodes
        .read()
        .unwrap()
        .by_inode
        .values()
        .filter(|data| data.retained.lock().unwrap().is_some())
        .cloned()
        .collect::<Vec<_>>();
    let ids = retained
        .iter()
        .map(|data| data.inode)
        .collect::<BTreeSet<_>>();
    if fs
        .dir_handles
        .read()
        .unwrap()
        .values()
        .any(|handle| ids.contains(&handle.inode))
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "owned Windows checkpoint does not support detached directories",
        ));
    }
    let mut detached = Vec::new();
    for data in retained {
        let file = data
            .retained
            .lock()
            .unwrap()
            .as_ref()
            .expect("retained inode remains pinned")
            .try_clone()?;
        let object = generation.add_detached(&file)?;
        let meta = fs.current_override(&file.metadata()?, &data)?;
        let mode = meta.mode;
        let rdev = meta.rdev;
        if mode & 0o170000 != 0o100000 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "owned detached Windows inode is not a regular file",
            ));
        }
        if fs.cfg.stat_virtualization_enabled() {
            generation.set_guest_metadata(object, meta.uid, meta.gid, mode, rdev)?;
        }
        let handles = fs
            .handles
            .read()
            .unwrap()
            .iter()
            .filter(|(_, handle)| handle.inode == data.inode)
            .map(|(id, handle)| FileHandleState {
                handle: *id,
                inode: data.inode,
                flags: handle.flags,
            })
            .collect();
        detached.push(DetachedInode {
            inode: data.inode,
            object,
            guest: [meta.uid, meta.gid, mode, rdev],
            handles,
        });
    }
    let linked = capture_linked(fs, &ids)?;
    let snapshot = generation.finish()?;
    let lookups = fs
        .inodes
        .read()
        .unwrap()
        .by_inode
        .iter()
        .map(|(id, data)| (*id, data.lookups.load(Ordering::Acquire)))
        .collect();
    let state = OwnedState {
        descriptor_digest: snapshot.digest()?,
        linked,
        detached,
        lookups,
        aliases: fs
            .inodes
            .read()
            .unwrap()
            .by_path
            .iter()
            .map(|(path, data)| {
                let relative = path
                    .strip_prefix(&fs.root)
                    .map_err(|error| invalid_state(error.to_string()))?;
                let components = relative
                    .components()
                    .map(|part| match part {
                        Component::Normal(name) => Ok(name.encode_wide().collect()),
                        _ => Err(invalid_state("invalid owned alias path")),
                    })
                    .collect::<io::Result<_>>()?;
                Ok(OwnedAlias {
                    inode: data.inode,
                    components,
                })
            })
            .collect::<io::Result<_>>()?,
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
        .expect("owned restore selected")
        .restore()?;
    let snapshot = OwnedDirectorySnapshot::open_expected(&generation, &state.descriptor_digest)?;
    validate(fs, &state, &snapshot)?;
    let mut prepared = rebuild(fs, state.linked, None)?;
    let parent = fs
        .root
        .parent()
        .ok_or_else(|| invalid_state("owned root has no storage parent"))?;
    let staging = tempfile::Builder::new()
        .prefix(".owned-detached-")
        .tempdir_in(parent)?;
    let mut temporary_objects = BTreeMap::new();
    for detached in state.detached {
        // A never-looked-up hardlink can still name the retained object. Reuse that
        // destination-local inode so the old handle and live namespace stay coherent.
        let visible = snapshot.visible_object_path(&fs.root, detached.object)?;
        let temporary = visible.is_none();
        let path =
            visible.unwrap_or_else(|| staging.path().join(format!("object-{}", detached.object)));
        if temporary && !temporary_objects.contains_key(&detached.object) {
            snapshot.materialize_object(&generation, detached.object, &path)?;
            temporary_objects.insert(detached.object, path.clone());
        }
        let metadata = fs::metadata(&path)?;
        let pinned = fs::OpenOptions::new()
            .read(true)
            .write(!metadata.permissions().readonly())
            .open(&path)?;
        for handle in detached.handles {
            let flags = handle.flags
                & !((super::super::LINUX_O_CREAT
                    | super::super::LINUX_O_EXCL
                    | super::super::LINUX_O_TRUNC) as u32);
            let file = open_options_from_flags(flags, false)?.open(&path)?;
            prepared.files.insert(
                handle.handle,
                Arc::new(HandleData {
                    inode: detached.inode,
                    flags: handle.flags,
                    file: Mutex::new(file),
                }),
            );
        }
        let [uid, gid, mode, rdev] = detached.guest;
        let stat_file =
            fs.pin_owned_stat(&path, super::super::OverrideStat::new(uid, gid, mode, rdev))?;
        let data = Arc::new(InodeData {
            inode: detached.inode,
            path: RwLock::new(path.clone()),
            identity: fs.owned_identity(&path)?,
            virtual_meta: RwLock::new(VirtualMetadata {
                uid,
                gid,
                mode: Some(mode),
                rdev: u64::from(rdev),
            }),
            retained: Mutex::new(temporary.then_some(pinned)),
            retained_stat: Mutex::new(if temporary { stat_file } else { None }),
            lookups: AtomicU64::new(0),
        });
        if let Some(identity) = data.identity
            && prepared
                .inodes
                .by_identity
                .insert(identity, data.clone())
                .is_some()
        {
            return Err(invalid_state(
                "owned restored aliases have conflicting logical inode ids",
            ));
        }
        if !temporary {
            prepared.inodes.by_path.insert(path, data.clone());
        }
        prepared.inodes.by_inode.insert(detached.inode, data);
    }
    // Open every retained handle before removing the private backing names.
    for path in temporary_objects.into_values() {
        fs::remove_file(path)?;
    }
    for (id, count) in state.lookups {
        prepared.inodes.by_inode[&id]
            .lookups
            .store(count, Ordering::Release);
    }
    // Restore all tracked aliases, not merely each inode's canonical path. Guest
    // cached dentries need no new lookup before a sidecar-backed chmod/chown.
    for alias in state.aliases {
        let path = super::path_from_components(fs, &alias.components)?;
        fs.safe_metadata(&path)?;
        let data = prepared.inodes.by_inode[&alias.inode].clone();
        if fs.owned_identity(&path)? != data.identity {
            return Err(invalid_state(
                "owned alias no longer names its captured inode",
            ));
        }
        prepared.inodes.by_path.insert(path, data);
    }
    Ok(prepared)
}

fn validate(
    fs: &PassthroughFs,
    state: &OwnedState,
    snapshot: &OwnedDirectorySnapshot,
) -> io::Result<()> {
    let detached_ids = state
        .detached
        .iter()
        .map(|inode| inode.inode)
        .collect::<BTreeSet<_>>();
    validate_quota(fs, &state.linked)?;
    validate_shape(
        &state.linked,
        fs.cfg.readonly,
        fs.cfg.inject_init,
        &detached_ids,
    )?;
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
            || detached.guest[2] & 0o170000 != 0o100000
            || detached.guest[3] != 0
            || !matches!(snapshot.object(detached.object)?.kind, ObjectKind::File(_))
        {
            return Err(invalid_state("invalid owned Windows detached inode"));
        }
        for handle in &detached.handles {
            if handle.inode != detached.inode
                || handle.handle == 0
                || handle.handle >= state.linked.next_handle
                || !handles.insert(handle.handle)
                || handle.flags & 3 == 3
                || (fs.cfg.readonly && handle.flags & 3 != 0)
            {
                return Err(invalid_state("invalid owned Windows detached handle"));
            }
        }
    }
    if state.lookups.keys().copied().collect::<BTreeSet<_>>() != inodes {
        return Err(invalid_state(
            "owned Windows lookup inventory differs from inode state",
        ));
    }
    let linked_ids = state
        .linked
        .inodes
        .iter()
        .map(|inode| inode.inode)
        .collect::<BTreeSet<_>>();
    let mut aliases = BTreeMap::new();
    for alias in &state.aliases {
        super::validate_components(&alias.components)?;
        if !linked_ids.contains(&alias.inode)
            || aliases.insert(&alias.components, alias.inode).is_some()
        {
            return Err(invalid_state("invalid owned alias inventory"));
        }
    }
    for inode in &state.linked.inodes {
        if aliases.get(&inode.components) != Some(&inode.inode) {
            return Err(invalid_state(
                "owned canonical inode path is absent from aliases",
            ));
        }
    }
    Ok(())
}

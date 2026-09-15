//! Durable passthrough filesystem state and destination-local handle reconstruction.

#[path = "owned_mobility.rs"]
mod owned;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{self, Read},
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::fs::MetadataExt,
    },
    sync::{Arc, Mutex, RwLock, atomic::Ordering},
};

#[cfg(target_os = "linux")]
use std::collections::HashSet;
#[cfg(target_os = "macos")]
use std::os::fd::OwnedFd;
#[cfg(target_os = "macos")]
use std::{
    ffi::{CStr, CString, OsStr},
    os::unix::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{DirSnapshot, PassthroughDirEntry, PassthroughDirHandle, PassthroughFs, inode};
use crate::backends::{
    mobility,
    passthroughfs::quota::QuotaState,
    shared::{
        handle_table::HandleData,
        inode_table::{InodeAltKey, InodeData, MultikeyBTreeMap},
        platform,
    },
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const KIND: &[u8; 8] = b"MSBPTUNX";
const EXTERNAL_KIND: &[u8; 8] = b"MSBPTEX1";
const MAX_PATH_DEPTH: usize = 256;
const MAX_COMPONENT_BYTES: usize = 255;
const GUEST_O_CREAT: u32 = 0x40;
const GUEST_O_EXCL: u32 = 0x80;
const GUEST_O_TRUNC: u32 = 0x200;

// libc's mode_t constants are u16 on macOS and u32 on Linux, while persisted
// file kinds use u32 on both. Normalize once without changing the wire format.
#[allow(clippy::unnecessary_cast)]
const FILE_TYPE_MASK: u32 = libc::S_IFMT as u32;
#[allow(clippy::unnecessary_cast)]
const REGULAR_FILE: u32 = libc::S_IFREG as u32;
#[allow(clippy::unnecessary_cast)]
const SYMBOLIC_LINK: u32 = libc::S_IFLNK as u32;
#[allow(clippy::unnecessary_cast)]
const DIRECTORY: u32 = libc::S_IFDIR as u32;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Deserialize, Serialize)]
struct PassthroughState {
    next_inode: u64,
    next_handle: u64,
    writeback: bool,
    quota: Option<QuotaState>,
    inodes: Vec<InodeState>,
    files: Vec<FileHandleState>,
    dirs: Vec<DirHandleState>,
}

#[derive(Deserialize, Serialize)]
struct ExternalState {
    state: PassthroughState,
    identities: BTreeMap<u64, ObjectIdentity>,
    invalid_inodes: BTreeSet<u64>,
}

#[derive(Deserialize, Serialize, PartialEq, Eq)]
struct ObjectIdentity {
    device: u64,
    inode: u64,
    kind: u32,
    permissions: u32,
    owner: (u32, u32),
    size: u64,
    modified_seconds: i64,
    modified_nanos: i64,
    changed_seconds: i64,
    changed_nanos: i64,
    content: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
struct InodeState {
    inode: u64,
    components: Vec<Vec<u8>>,
    refcount: u64,
}

#[derive(Deserialize, Serialize)]
struct FileHandleState {
    handle: u64,
    inode: u64,
    flags: u32,
}

#[derive(Deserialize, Serialize)]
struct DirHandleState {
    handle: u64,
    inode: u64,
    flags: u32,
    entries: Option<Vec<DirEntryState>>,
}

#[derive(Deserialize, Serialize)]
struct DirEntryState {
    inode: u64,
    name: Vec<u8>,
    offset: u64,
    file_type: u32,
}

pub(super) struct PreparedState {
    invalid_inodes: BTreeSet<u64>,
    next_inode: u64,
    next_handle: u64,
    writeback: bool,
    quota: Option<QuotaState>,
    inodes: MultikeyBTreeMap<u64, InodeAltKey, Arc<InodeData>>,
    files: BTreeMap<u64, Arc<HandleData>>,
    dirs: BTreeMap<u64, Arc<PassthroughDirHandle>>,
}

//--------------------------------------------------------------------------------------------------
// Functions: Public operations
//--------------------------------------------------------------------------------------------------

pub(super) fn capture(fs: &PassthroughFs) -> io::Result<Vec<u8>> {
    if fs.cfg.owned_checkpoint.is_some() {
        return owned::capture(fs);
    }
    let inode_states = capture_inodes(fs, &BTreeSet::new())?;
    let inode_ids = inode_states
        .iter()
        .map(|state| state.inode)
        .collect::<BTreeSet<_>>();

    let files = fs
        .handles
        .read()
        .unwrap()
        .iter()
        .map(|(handle, data)| FileHandleState {
            handle: *handle,
            inode: data.inode,
            flags: data.flags,
        })
        .collect::<Vec<_>>();
    let dirs = fs
        .dir_handles
        .read()
        .unwrap()
        .iter()
        .map(|(handle, data)| {
            let entries = data.snapshot.lock().unwrap().as_ref().map(|snapshot| {
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
            });
            DirHandleState {
                handle: *handle,
                inode: data.inode,
                flags: data.flags,
                entries,
            }
        })
        .collect::<Vec<_>>();

    if files
        .iter()
        .any(|handle| !inode_ids.contains(&handle.inode))
        || dirs.iter().any(|handle| !inode_ids.contains(&handle.inode))
    {
        return Err(invalid_state(
            "passthrough handle references an uncaptured inode",
        ));
    }

    let state = PassthroughState {
        next_inode: fs.next_inode.load(Ordering::Acquire),
        next_handle: fs.next_handle.load(Ordering::Acquire),
        writeback: fs.writeback.load(Ordering::Acquire),
        quota: fs.quota.as_ref().map(|quota| quota.capture_state()),
        inodes: inode_states,
        files,
        dirs,
    };
    if fs.cfg.external_checkpoint.is_none() {
        return mobility::encode(KIND, &state);
    }
    if state.writeback {
        return Err(invalid_state(
            "external checkpoint cannot retain negotiated writeback cache",
        ));
    }
    let identities = state
        .inodes
        .iter()
        .map(|saved| {
            let identity = object_identity(fs, saved)?;
            let inodes = fs.inodes.read().unwrap();
            let tracked = inodes
                .get(&saved.inode)
                .ok_or_else(|| invalid_state("captured inode disappeared"))?;
            if (identity.device, identity.inode) != (tracked.dev, tracked.ino) {
                return Err(invalid_state(
                    "external pathname no longer names the guest's captured object",
                ));
            }
            Ok((saved.inode, identity))
        })
        .collect::<io::Result<BTreeMap<_, _>>>()?;
    mobility::encode(
        EXTERNAL_KIND,
        &ExternalState {
            state,
            identities,
            invalid_inodes: fs.invalid_inodes.read().unwrap().clone(),
        },
    )
}

pub(super) fn prepare(fs: &PassthroughFs, bytes: &[u8]) -> io::Result<PreparedState> {
    if fs.cfg.owned_checkpoint.is_some() {
        return owned::prepare(fs, bytes);
    }
    if let Some(options) = &fs.cfg.external_checkpoint {
        let mut external: ExternalState = mobility::decode(EXTERNAL_KIND, bytes)?;
        validate_external_shape(&external)?;
        validate_semantics(fs, &external.state, external.invalid_inodes.contains(&1))?;
        let mut invalid = external.invalid_inodes;
        // Reconstruct parents first. A missing parent invalidates its descendants even if
        // an unrelated replacement happens to expose the same leaf names.
        external
            .state
            .inodes
            .sort_by_key(|saved| saved.components.len());
        let mut invalid_paths = Vec::<Vec<Vec<u8>>>::new();
        let mut verified = BTreeMap::new();
        for saved in &external.state.inodes {
            let identity = &external.identities[&saved.inode];
            let current = object_identity(fs, saved);
            let valid = !invalid_paths
                .iter()
                .any(|path| saved.components.starts_with(path))
                && current
                    .as_ref()
                    .is_ok_and(|current| same_object(identity, current, options.remapped));
            if !valid {
                if !options.relaxed {
                    return Err(invalid_state(format!(
                        "external object {} is missing, replaced, or changed",
                        saved.inode
                    )));
                }
                invalid.insert(saved.inode);
                invalid_paths.push(saved.components.clone());
            } else {
                verified.insert(saved.inode, current.expect("valid identity"));
            }
        }
        external
            .state
            .inodes
            .retain(|saved| !invalid.contains(&saved.inode));
        external
            .state
            .files
            .retain(|saved| !invalid.contains(&saved.inode));
        external
            .state
            .dirs
            .retain(|saved| !invalid.contains(&saved.inode));
        let mut prepared = rebuild(fs, external.state, Some(&verified))?;
        prepared.invalid_inodes = invalid;
        return Ok(prepared);
    }
    let state: PassthroughState = mobility::decode(KIND, bytes)?;
    validate_semantics(fs, &state, false)?;
    rebuild(fs, state, None)
}

pub(super) fn restore(fs: &PassthroughFs, bytes: &[u8]) -> io::Result<()> {
    let prepared = prepare(fs, bytes)?;
    if let (Some(quota), Some(state)) = (&fs.quota, &prepared.quota) {
        quota.restore_state(state)?;
    }

    *fs.inodes.write().unwrap() = prepared.inodes;
    *fs.handles.write().unwrap() = prepared.files;
    *fs.dir_handles.write().unwrap() = prepared.dirs;
    fs.next_inode.store(prepared.next_inode, Ordering::Release);
    fs.next_handle
        .store(prepared.next_handle, Ordering::Release);
    fs.writeback.store(prepared.writeback, Ordering::Release);
    if let Some(options) = &fs.cfg.external_checkpoint {
        *options.invalid_inodes.lock().unwrap() = prepared.invalid_inodes.iter().copied().collect();
    }
    *fs.invalid_inodes.write().unwrap() = prepared.invalid_inodes;
    Ok(())
}

/// Validate an external payload without opening any destination path.
pub(super) fn validate_unavailable(bytes: &[u8]) -> io::Result<()> {
    let external: ExternalState = mobility::decode(EXTERNAL_KIND, bytes)?;
    validate_external_shape(&external)?;
    validate_shape(&external.state, false, external.invalid_inodes.contains(&1))
}

pub(super) fn prepare_single_file_state(
    bytes: &[u8],
    source: &std::ffi::CStr,
    destination: &std::ffi::CStr,
) -> io::Result<(
    Vec<u8>,
    crate::backends::passthroughfs::ExternalSingleFileIndex,
)> {
    let mut external: ExternalState = mobility::decode(EXTERNAL_KIND, bytes)?;
    validate_external_shape(&external)?;
    validate_shape(&external.state, false, external.invalid_inodes.contains(&1))?;
    if !external.state.dirs.is_empty() {
        return Err(invalid_state(
            "single-file state contains a real directory handle",
        ));
    }
    validate_components(&[destination.to_bytes().to_vec()])?;
    for inode in &mut external.state.inodes {
        if inode.inode == 1 {
            continue;
        }
        if inode.components != [source.to_bytes().to_vec()]
            || external.identities[&inode.inode].kind != REGULAR_FILE
        {
            return Err(invalid_state(
                "single-file state references a sibling or non-file object",
            ));
        }
        inode.components = vec![destination.to_bytes().to_vec()];
    }
    if external.state.files.iter().any(|handle| handle.inode == 1) {
        return Err(invalid_state(
            "single-file state opens the real parent directory",
        ));
    }
    let index = crate::backends::passthroughfs::ExternalSingleFileIndex {
        inodes: external
            .state
            .inodes
            .iter()
            .map(|inode| inode.inode)
            .collect(),
        files: external
            .state
            .files
            .iter()
            .map(|handle| (handle.handle, handle.inode))
            .collect(),
        invalid_inodes: external.invalid_inodes.clone(),
    };
    Ok((mobility::encode(EXTERNAL_KIND, &external)?, index))
}

fn validate_external_shape(external: &ExternalState) -> io::Result<()> {
    if external.state.writeback
        || external.identities.len() != external.state.inodes.len()
        || external
            .state
            .inodes
            .iter()
            .any(|saved| !external.identities.contains_key(&saved.inode))
        || external.invalid_inodes.iter().any(|inode| {
            *inode == 0
                || *inode == 2
                || *inode >= external.state.next_inode
                || external.identities.contains_key(inode)
        })
        || external
            .identities
            .values()
            .any(|identity| match identity.kind {
                kind if kind == REGULAR_FILE || kind == SYMBOLIC_LINK => {
                    identity.content.len() != 32
                }
                kind if kind == DIRECTORY => !identity.content.is_empty(),
                _ => true,
            })
        || (external.invalid_inodes.contains(&1) && !external.state.inodes.is_empty())
    {
        return Err(invalid_state(
            "invalid external filesystem identity manifest",
        ));
    }
    Ok(())
}

fn same_object(saved: &ObjectIdentity, current: &ObjectIdentity, remapped: bool) -> bool {
    saved.kind == current.kind
        && (remapped || (saved.device == current.device && saved.inode == current.inode))
        && (remapped || (saved.permissions == current.permissions && saved.owner == current.owner))
        // Directory contents remain external and mutable. Existing directory iterators
        // keep their captured sequence, while new lookups see the current namespace.
        && (saved.kind == DIRECTORY
            || (saved.size == current.size && saved.content == current.content
                && (remapped || (saved.modified_seconds == current.modified_seconds
                    && saved.modified_nanos == current.modified_nanos))))
}

fn object_identity(fs: &PassthroughFs, saved: &InodeState) -> io::Result<ObjectIdentity> {
    let raw = open_inode_components(fs, &saved.components)?;
    let pinned = unsafe { File::from_raw_fd(raw) };
    let before = pinned.metadata()?;
    let kind = before.mode() & FILE_TYPE_MASK;
    let mut content = Vec::new();
    if kind == REGULAR_FILE {
        let fd = open_components(fs, &saved.components, libc::O_RDONLY | libc::O_NOFOLLOW)?;
        let mut readable = unsafe { File::from_raw_fd(fd) };
        let metadata = readable.metadata()?;
        if (metadata.dev(), metadata.ino()) != (before.dev(), before.ino()) {
            return Err(invalid_state(
                "external object changed while reopening for capture",
            ));
        }
        let mut hash = Sha256::new();
        let mut buffer = [0_u8; 128 * 1024];
        loop {
            let count = readable.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hash.update(&buffer[..count]);
        }
        content = hash.finalize().to_vec();
    } else if kind == SYMBOLIC_LINK {
        let (name, parent) = saved
            .components
            .split_last()
            .ok_or_else(|| invalid_state("symlink root"))?;
        let parent_fd = open_components(fs, parent, directory_open_flags())?;
        let parent = unsafe { File::from_raw_fd(parent_fd) };
        let name = std::ffi::CString::new(name.as_slice())
            .map_err(|_| invalid_state("invalid symlink name"))?;
        let mut target = vec![0_u8; 64 * 1024];
        let count = unsafe {
            libc::readlinkat(
                parent.as_raw_fd(),
                name.as_ptr(),
                target.as_mut_ptr().cast(),
                target.len(),
            )
        };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        if count as usize == target.len() {
            return Err(invalid_state("external symlink target too long"));
        }
        target.truncate(count as usize);
        content = Sha256::digest(target).to_vec();
    } else if kind != DIRECTORY {
        return Err(invalid_state(
            "external special objects are not checkpointable",
        ));
    }
    let after = pinned.metadata()?;
    if (
        before.dev(),
        before.ino(),
        before.len(),
        before.mtime(),
        before.mtime_nsec(),
        before.ctime(),
        before.ctime_nsec(),
    ) != (
        after.dev(),
        after.ino(),
        after.len(),
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
    ) {
        return Err(invalid_state(
            "external object changed while recording its identity",
        ));
    }
    Ok(ObjectIdentity {
        device: before.dev(),
        inode: before.ino(),
        kind,
        permissions: before.mode() & 0o7777,
        owner: (before.uid(), before.gid()),
        size: before.len(),
        modified_seconds: before.mtime(),
        modified_nanos: before.mtime_nsec(),
        changed_seconds: before.ctime(),
        changed_nanos: before.ctime_nsec(),
        content,
    })
}

//--------------------------------------------------------------------------------------------------
// Functions: Capture
//--------------------------------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn capture_inodes(fs: &PassthroughFs, excluded: &BTreeSet<u64>) -> io::Result<Vec<InodeState>> {
    let inodes = fs.inodes.read().unwrap();
    let mut states = Vec::new();
    for (inode_id, data) in inodes.iter() {
        if excluded.contains(inode_id) {
            continue;
        }
        if data.retained_fd.lock().unwrap().is_some() {
            return Err(invalid_state(
                "open-unlinked passthrough objects are not checkpointable",
            ));
        }
        let components = if *inode_id == 1 {
            Vec::new()
        } else {
            inode::build_anchor_components_locked(&inodes, *inode_id, &mut HashSet::new())?
        };
        states.push(InodeState {
            inode: *inode_id,
            components,
            refcount: data.refcount.load(Ordering::Acquire),
        });
    }
    Ok(states)
}

#[cfg(target_os = "macos")]
fn capture_inodes(fs: &PassthroughFs, excluded: &BTreeSet<u64>) -> io::Result<Vec<InodeState>> {
    let root_path = fd_path(fs.root_fd.as_raw_fd())?;
    let tracked = fs
        .inodes
        .read()
        .unwrap()
        .iter()
        .map(|(inode, data)| (*inode, Arc::clone(data)))
        .collect::<Vec<_>>();
    let mut states = Vec::with_capacity(tracked.len());
    for (inode_id, data) in tracked {
        if excluded.contains(&inode_id) {
            continue;
        }
        if data.unlinked_fd.load(Ordering::Acquire) >= 0 {
            return Err(invalid_state(
                "open-unlinked passthrough objects are not checkpointable",
            ));
        }
        let components = if inode_id == 1 {
            Vec::new()
        } else {
            let fd = open_macos_inode_for_path(fs, inode_id)?;
            let path = fd_path(fd.as_raw_fd())?;
            relative_components(&root_path, &path)?
        };
        states.push(InodeState {
            inode: inode_id,
            components,
            refcount: data.refcount.load(Ordering::Acquire),
        });
    }
    Ok(states)
}

//--------------------------------------------------------------------------------------------------
// Functions: Validation and reconstruction
//--------------------------------------------------------------------------------------------------

fn validate_semantics(
    fs: &PassthroughFs,
    state: &PassthroughState,
    invalid_root: bool,
) -> io::Result<()> {
    if state.quota.is_some() != fs.quota.is_some() {
        return Err(invalid_state("passthrough quota configuration differs"));
    }
    if state.writeback && !fs.cfg.writeback {
        return Err(invalid_state(
            "passthrough writeback cache is disabled at the destination",
        ));
    }
    if let (Some(quota), Some(quota_state)) = (&fs.quota, &state.quota) {
        quota.validate_state(quota_state)?;
    }

    validate_shape(state, fs.cfg.readonly(), invalid_root)
}

fn validate_shape(state: &PassthroughState, readonly: bool, invalid_root: bool) -> io::Result<()> {
    let mut inode_ids = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut root_count = 0;
    let mut max_inode = 2;
    for inode in &state.inodes {
        validate_components(&inode.components)?;
        if inode.inode == 0
            || inode.inode == 2
            || !inode_ids.insert(inode.inode)
            || !paths.insert(inode.components.clone())
        {
            return Err(invalid_state("duplicate or reserved passthrough inode"));
        }
        if inode.inode == 1 {
            root_count += 1;
            if !inode.components.is_empty() {
                return Err(invalid_state("passthrough root path is not empty"));
            }
        } else if inode.components.is_empty() {
            return Err(invalid_state(
                "non-root passthrough inode has an empty path",
            ));
        }
        max_inode = max_inode.max(inode.inode);
    }
    if root_count != usize::from(!invalid_root) || state.next_inode <= max_inode {
        return Err(invalid_state("invalid passthrough root or next inode"));
    }

    let mut handles = BTreeSet::new();
    let mut max_handle = 0;
    for handle in &state.files {
        if handle.handle == 0
            || !handles.insert(handle.handle)
            || !inode_ids.contains(&handle.inode)
            || handle.flags & 0b11 == 0b11
            || (readonly && handle.flags & 0b11 != 0)
        {
            return Err(invalid_state("invalid passthrough file handle"));
        }
        max_handle = max_handle.max(handle.handle);
    }
    for handle in &state.dirs {
        if handle.handle == 0
            || !handles.insert(handle.handle)
            || !inode_ids.contains(&handle.inode)
            || handle.flags & 0b11 == 0b11
        {
            return Err(invalid_state("invalid passthrough directory handle"));
        }
        if let Some(entries) = &handle.entries {
            let mut previous = 0;
            for entry in entries {
                if entry.offset == 0
                    || entry.offset <= previous
                    || entry.name.is_empty()
                    || entry.name.len() > MAX_COMPONENT_BYTES
                    || entry.name.contains(&0)
                    || entry.name.contains(&b'/')
                {
                    return Err(invalid_state("invalid passthrough directory snapshot"));
                }
                previous = entry.offset;
            }
        }
        max_handle = max_handle.max(handle.handle);
    }
    if state.next_handle <= max_handle {
        return Err(invalid_state("invalid passthrough next handle"));
    }
    Ok(())
}

fn rebuild(
    fs: &PassthroughFs,
    mut state: PassthroughState,
    verified: Option<&BTreeMap<u64, ObjectIdentity>>,
) -> io::Result<PreparedState> {
    state.inodes.sort_by(|left, right| {
        left.components
            .len()
            .cmp(&right.components.len())
            .then(left.inode.cmp(&right.inode))
    });
    let path_ids = state
        .inodes
        .iter()
        .map(|inode| (inode.components.clone(), inode.inode))
        .collect::<BTreeMap<_, _>>();
    let inode_paths = state
        .inodes
        .iter()
        .map(|inode| (inode.inode, inode.components.clone()))
        .collect::<BTreeMap<_, _>>();

    let mut inodes = MultikeyBTreeMap::new();
    for saved in &state.inodes {
        let fd = open_inode_components(fs, &saved.components)?;
        let pinned = unsafe { File::from_raw_fd(fd) };
        verify_reopened(&pinned, saved.inode, verified)?;
        let (alt_key, data) =
            inode_data_from_fd(fs, &inodes, saved, &path_ids, pinned.as_raw_fd())?;
        if inodes.get_alt(&alt_key).is_some() {
            return Err(invalid_state(
                "multiple guest inodes resolve to one destination object",
            ));
        }
        inodes.insert(saved.inode, alt_key, data);
    }

    let mut files = BTreeMap::new();
    for saved in &state.files {
        let components = inode_paths
            .get(&saved.inode)
            .ok_or_else(|| invalid_state("file handle inode is missing"))?;
        let mut flags = restored_open_flags(saved.flags, state.writeback);
        flags |= libc::O_NOFOLLOW;
        let fd = open_components(fs, components, flags)?;
        let file = unsafe { File::from_raw_fd(fd) };
        verify_reopened(&file, saved.inode, verified)?;
        files.insert(
            saved.handle,
            Arc::new(HandleData {
                inode: saved.inode,
                flags: saved.flags,
                file: RwLock::new(file),
            }),
        );
    }

    let mut dirs = BTreeMap::new();
    for saved in &state.dirs {
        let components = inode_paths
            .get(&saved.inode)
            .ok_or_else(|| invalid_state("directory handle inode is missing"))?;
        let fd = open_components(fs, components, directory_open_flags())?;
        let file = unsafe { File::from_raw_fd(fd) };
        verify_reopened(&file, saved.inode, verified)?;
        let snapshot = saved.entries.as_ref().map(|entries| DirSnapshot {
            entries: entries
                .iter()
                .map(|entry| PassthroughDirEntry {
                    inode: entry.inode,
                    name: entry.name.clone(),
                    offset: entry.offset,
                    file_type: entry.file_type,
                })
                .collect(),
        });
        dirs.insert(
            saved.handle,
            Arc::new(PassthroughDirHandle {
                inode: saved.inode,
                flags: saved.flags,
                file: RwLock::new(file),
                snapshot: Mutex::new(snapshot),
            }),
        );
    }

    Ok(PreparedState {
        invalid_inodes: BTreeSet::new(),
        next_inode: state.next_inode,
        next_handle: state.next_handle,
        writeback: state.writeback,
        quota: state.quota,
        inodes,
        files,
        dirs,
    })
}

fn verify_reopened(
    file: &File,
    inode: u64,
    verified: Option<&BTreeMap<u64, ObjectIdentity>>,
) -> io::Result<()> {
    let Some(verified) = verified else {
        return Ok(());
    };
    let expected = verified
        .get(&inode)
        .ok_or_else(|| invalid_state("reopened external inode was not verified"))?;
    let current = file.metadata()?;
    // Compare the destination-local identity even for a cross-host remap. A second
    // pathname open must not swap a validated object for an unvalidated replacement.
    if current.dev() != expected.device
        || current.ino() != expected.inode
        || current.mode() & FILE_TYPE_MASK != expected.kind
        || current.mode() & 0o7777 != expected.permissions
        || (current.uid(), current.gid()) != expected.owner
        || current.len() != expected.size
        || current.mtime() != expected.modified_seconds
        || current.mtime_nsec() != expected.modified_nanos
        || current.ctime() != expected.changed_seconds
        || current.ctime_nsec() != expected.changed_nanos
    {
        return Err(invalid_state(
            "external object changed while rebuilding captured handles",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn inode_data_from_fd(
    _fs: &PassthroughFs,
    _inodes: &MultikeyBTreeMap<u64, InodeAltKey, Arc<InodeData>>,
    saved: &InodeState,
    path_ids: &BTreeMap<Vec<Vec<u8>>, u64>,
    fd: RawFd,
) -> io::Result<(InodeAltKey, Arc<InodeData>)> {
    let mut stx: libc::statx = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::statx(
            fd,
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW | libc::AT_STATX_SYNC_AS_STAT,
            libc::STATX_BASIC_STATS | libc::STATX_MNT_ID,
            &mut stx,
        )
    };
    if result < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }
    let stat = platform::statx_to_stat64(&stx);
    let alt_key = InodeAltKey::new(stat.st_ino, stat.st_dev, stx.stx_mnt_id);
    let (anchor_parent, anchor_name, aliases) = if saved.inode == 1 {
        (0, Vec::new(), BTreeSet::new())
    } else {
        let mut parent_path = saved.components.clone();
        let name = parent_path.pop().expect("non-root path validated above");
        let parent = *path_ids
            .get(&parent_path)
            .ok_or_else(|| invalid_state("passthrough inode parent was not captured"))?;
        let alias = crate::backends::shared::inode_table::NamespaceAlias::new(parent, &name);
        (parent, name, BTreeSet::from([alias]))
    };
    let anchor_children = path_ids
        .keys()
        .filter(|components| {
            !components.is_empty() && components[..components.len() - 1] == saved.components[..]
        })
        .count() as u64;
    Ok((
        alt_key,
        Arc::new(InodeData {
            inode: saved.inode,
            ino: stat.st_ino,
            dev: stat.st_dev,
            refcount: std::sync::atomic::AtomicU64::new(saved.refcount),
            mnt_id: stx.stx_mnt_id,
            anchor_parent: std::sync::atomic::AtomicU64::new(anchor_parent),
            anchor_name: RwLock::new(anchor_name),
            aliases: RwLock::new(aliases),
            anchor_children: std::sync::atomic::AtomicU64::new(anchor_children),
            retained_fd: Mutex::new(None),
        }),
    ))
}

#[cfg(target_os = "macos")]
fn inode_data_from_fd(
    _fs: &PassthroughFs,
    _inodes: &MultikeyBTreeMap<u64, InodeAltKey, Arc<InodeData>>,
    saved: &InodeState,
    _path_ids: &BTreeMap<Vec<Vec<u8>>, u64>,
    fd: RawFd,
) -> io::Result<(InodeAltKey, Arc<InodeData>)> {
    let stat = platform::fstat(fd)?;
    let ino = platform::stat_ino(&stat);
    let dev = platform::stat_dev(&stat);
    Ok((
        InodeAltKey::new(ino, dev),
        Arc::new(InodeData {
            inode: saved.inode,
            ino,
            dev,
            refcount: std::sync::atomic::AtomicU64::new(saved.refcount),
            unlinked_fd: std::sync::atomic::AtomicI64::new(-1),
        }),
    ))
}

//--------------------------------------------------------------------------------------------------
// Functions: Paths and flags
//--------------------------------------------------------------------------------------------------

fn validate_components(components: &[Vec<u8>]) -> io::Result<()> {
    if components.len() > MAX_PATH_DEPTH {
        return Err(invalid_state("passthrough path is too deep"));
    }
    for component in components {
        if component.is_empty()
            || component.len() > MAX_COMPONENT_BYTES
            || component == b"."
            || component == b".."
            || component.contains(&0)
            || component.contains(&b'/')
        {
            return Err(invalid_state("invalid passthrough path component"));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_components(fs: &PassthroughFs, components: &[Vec<u8>], flags: i32) -> io::Result<RawFd> {
    inode::secure_open_path_linux(fs, components, flags)
}

#[cfg(target_os = "macos")]
fn open_components(fs: &PassthroughFs, components: &[Vec<u8>], flags: i32) -> io::Result<RawFd> {
    let mut current = unsafe { libc::fcntl(fs.root_fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if current < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }
    for (index, component) in components.iter().enumerate() {
        let name = CString::new(component.as_slice()).map_err(|_| invalid_state("invalid path"))?;
        let last = index + 1 == components.len();
        let open_flags = if last {
            // O_SYMLINK itself opens the link object. Combining it with
            // O_NOFOLLOW is rejected by macOS, while every parent component
            // remains opened O_DIRECTORY|O_NOFOLLOW beneath the root fd.
            let nofollow = if flags & libc::O_SYMLINK != 0 {
                0
            } else {
                libc::O_NOFOLLOW
            };
            flags | libc::O_CLOEXEC | nofollow
        } else {
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW
        };
        let next = unsafe { libc::openat(current, name.as_ptr(), open_flags) };
        unsafe { libc::close(current) };
        if next < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
        current = next;
    }
    Ok(current)
}

#[cfg(target_os = "linux")]
fn open_inode_components(fs: &PassthroughFs, components: &[Vec<u8>]) -> io::Result<RawFd> {
    open_components(fs, components, libc::O_PATH | libc::O_NOFOLLOW)
}

#[cfg(target_os = "macos")]
fn open_inode_components(fs: &PassthroughFs, components: &[Vec<u8>]) -> io::Result<RawFd> {
    open_components(fs, components, libc::O_RDONLY)
        .or_else(|_| open_components(fs, components, libc::O_SYMLINK))
}

fn directory_open_flags() -> i32 {
    libc::O_RDONLY | libc::O_DIRECTORY
}

fn restored_open_flags(guest_flags: u32, writeback: bool) -> i32 {
    // Creation flags describe how the source handle was established. Replaying
    // them could mutate the destination object, so reopen the existing path.
    let safe = guest_flags & !(GUEST_O_CREAT | GUEST_O_EXCL | GUEST_O_TRUNC);
    let mut flags = inode::translate_open_flags(safe as i32);
    if writeback {
        // Match do_open: writeback may issue reads through a guest O_WRONLY
        // handle, and append races with the client's cached write position.
        if flags & libc::O_WRONLY != 0 {
            flags = (flags & !libc::O_WRONLY) | libc::O_RDWR;
        }
        flags &= !libc::O_APPEND;
    }
    flags
}

#[cfg(target_os = "macos")]
fn fd_path(fd: RawFd) -> io::Result<PathBuf> {
    let mut bytes = vec![0u8; libc::PATH_MAX as usize];
    if unsafe { libc::fcntl(fd, libc::F_GETPATH, bytes.as_mut_ptr()) } < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }
    let path = CStr::from_bytes_until_nul(&bytes)
        .map_err(|_| invalid_state("unterminated F_GETPATH result"))?;
    Ok(PathBuf::from(OsStr::from_bytes(path.to_bytes())))
}

#[cfg(target_os = "macos")]
fn open_macos_inode_for_path(fs: &PassthroughFs, inode_id: u64) -> io::Result<OwnedFd> {
    let (dev, ino) = {
        let inodes = fs.inodes.read().unwrap();
        let data = inodes.get(&inode_id).ok_or_else(platform::ebadf)?;
        (data.dev, data.ino)
    };
    let mut failures = Vec::new();
    for flags in [
        libc::O_RDONLY,
        libc::O_RDONLY | libc::O_DIRECTORY,
        libc::O_SYMLINK,
    ] {
        let opened = if flags == libc::O_SYMLINK {
            // Open the link object, never its target. Darwin's no-follow flags can
            // conflict with O_SYMLINK; this trusted /.vol identity path has no
            // guest-provided components (as in inode's metadata-stat reopen).
            let path = inode::vol_path(dev, ino);
            let fd = unsafe { libc::open(path.as_ptr(), flags | libc::O_CLOEXEC) };
            if fd < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(fd)
            }
        } else {
            inode::open_inode_fd(fs, inode_id, flags)
        };
        match opened {
            Ok(fd) => {
                // Own the descriptor before any fallible identity/path checks.
                let fd = unsafe { OwnedFd::from_raw_fd(fd) };
                let stat = platform::fstat(fd.as_raw_fd())?;
                if stat.st_dev as u64 != dev || stat.st_ino != ino {
                    return Err(invalid_state("reopened passthrough inode identity changed"));
                }
                return Ok(fd);
            }
            Err(error) => failures.push(format!("flags {flags:#x}: {error}")),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "cannot reopen tracked passthrough inode {inode_id} ({dev}:{ino}): {}",
            failures.join("; ")
        ),
    ))
}

#[cfg(target_os = "macos")]
fn relative_components(root: &Path, path: &Path) -> io::Result<Vec<Vec<u8>>> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| invalid_state("tracked passthrough inode escaped the mount root"))?;
    let mut components = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(name) => components.push(name.as_bytes().to_vec()),
            _ => return Err(invalid_state("invalid tracked passthrough path")),
        }
    }
    validate_components(&components)?;
    Ok(components)
}

fn invalid_state(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{ffi::CString, io::Read, os::fd::AsRawFd};

    use super::*;
    use crate::{Context, DynFileSystem, FsOptions, backends::passthroughfs::StatVirtualization};

    fn backend(root: &std::path::Path) -> PassthroughFs {
        PassthroughFs::new(super::super::PassthroughConfig {
            root_dir: root.to_path_buf(),
            inject_init: false,
            stat_virtualization: StatVirtualization::Off,
            ..Default::default()
        })
        .unwrap()
    }

    fn context() -> Context {
        Context {
            uid: 0,
            gid: 0,
            pid: 0,
        }
    }

    fn external_backend(root: &std::path::Path, relaxed: bool, remapped: bool) -> PassthroughFs {
        PassthroughFs::new(super::super::PassthroughConfig {
            root_dir: root.to_path_buf(),
            inject_init: false,
            stat_virtualization: StatVirtualization::Off,
            external_checkpoint: Some(crate::ExternalCheckpointOptions {
                relaxed,
                remapped,
                ..Default::default()
            }),
            ..Default::default()
        })
        .unwrap()
    }

    #[test]
    fn external_state_restores_open_handles_without_copying_host_data() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("data"), b"external").unwrap();
        let source = external_backend(root.path(), false, false);
        source.init(FsOptions::empty()).unwrap();
        let entry = source.lookup(context(), 1, c"data").unwrap();
        let handle = source
            .open(context(), entry.inode, false, 2)
            .unwrap()
            .0
            .unwrap();
        let encoded = capture(&source).unwrap();
        let destination = external_backend(root.path(), false, false);
        restore(&destination, &encoded).unwrap();
        assert_eq!(destination.request_error(entry.inode), None);
        let restored = destination.handles.read().unwrap()[&handle].clone();
        assert_eq!(
            restored.file.read().unwrap().metadata().unwrap().ino(),
            std::fs::metadata(root.path().join("data")).unwrap().ino()
        );
        assert_eq!(capture(&destination).unwrap(), encoded);
    }

    #[test]
    fn external_changed_file_strict_rejects_relaxed_tombstones_old_inode() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("data");
        std::fs::write(&path, b"old").unwrap();
        let source = external_backend(root.path(), false, false);
        source.init(FsOptions::empty()).unwrap();
        let entry = source.lookup(context(), 1, c"data").unwrap();
        let old_handle = source
            .open(context(), entry.inode, false, 2)
            .unwrap()
            .0
            .unwrap();
        let encoded = capture(&source).unwrap();
        std::fs::write(&path, b"new host bytes").unwrap();
        assert!(prepare(&external_backend(root.path(), false, false), &encoded).is_err());
        let relaxed = external_backend(root.path(), true, false);
        restore(&relaxed, &encoded).unwrap();
        assert_eq!(relaxed.request_error(entry.inode), Some(116));
        assert!(!relaxed.handles.read().unwrap().contains_key(&old_handle));
        assert_eq!(
            *relaxed
                .cfg
                .external_checkpoint
                .as_ref()
                .unwrap()
                .invalid_inodes
                .lock()
                .unwrap(),
            vec![entry.inode]
        );
        let fresh = relaxed.lookup(context(), 1, c"data").unwrap();
        assert_ne!(fresh.inode, entry.inode);
        assert_eq!(relaxed.request_error(fresh.inode), None);
        assert_eq!(std::fs::read(&path).unwrap(), b"new host bytes");
        let recaptured = capture(&relaxed).unwrap();
        validate_unavailable(&recaptured).unwrap();
    }

    #[test]
    fn external_replacement_before_capture_is_not_fingerprinted_as_old_handle() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("data");
        std::fs::write(&path, b"old").unwrap();
        let source = external_backend(root.path(), false, false);
        source.init(FsOptions::empty()).unwrap();
        let entry = source.lookup(context(), 1, c"data").unwrap();
        source.open(context(), entry.inode, false, 0).unwrap();
        // Atomic replacement unlinks the object still held by the guest's FD.
        let replacement = root.path().join("replacement");
        std::fs::write(&replacement, b"replacement").unwrap();
        std::fs::rename(&replacement, &path).unwrap();
        assert!(capture(&source).is_err());
    }

    #[test]
    fn external_explicit_remap_requires_matching_referenced_content() {
        let source_root = tempfile::tempdir().unwrap();
        let destination_root = tempfile::tempdir().unwrap();
        std::fs::write(source_root.path().join("data"), b"same content").unwrap();
        std::fs::write(destination_root.path().join("data"), b"same content").unwrap();
        let source = external_backend(source_root.path(), false, false);
        source.init(FsOptions::empty()).unwrap();
        source.lookup(context(), 1, c"data").unwrap();
        let encoded = capture(&source).unwrap();
        assert!(
            prepare(
                &external_backend(destination_root.path(), false, false),
                &encoded
            )
            .is_err()
        );
        restore(
            &external_backend(destination_root.path(), false, true),
            &encoded,
        )
        .unwrap();
        std::fs::write(destination_root.path().join("data"), b"wrong content").unwrap();
        assert!(
            prepare(
                &external_backend(destination_root.path(), false, true),
                &encoded
            )
            .is_err()
        );
    }

    #[test]
    fn external_relaxed_policy_never_accepts_malformed_identity_state() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("data"), b"data").unwrap();
        let source = external_backend(root.path(), false, false);
        source.init(FsOptions::empty()).unwrap();
        let entry = source.lookup(context(), 1, c"data").unwrap();
        let mut state: ExternalState =
            mobility::decode(EXTERNAL_KIND, &capture(&source).unwrap()).unwrap();
        state
            .identities
            .get_mut(&entry.inode)
            .unwrap()
            .content
            .clear();
        let malformed = mobility::encode(EXTERNAL_KIND, &state).unwrap();
        assert!(prepare(&external_backend(root.path(), true, false), &malformed).is_err());
        assert!(
            crate::UnavailableFs::default()
                .validate_state(&malformed)
                .is_err()
        );
    }

    #[test]
    fn external_rebuild_rechecks_validated_destination_object() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("data");
        std::fs::write(&path, b"old").unwrap();
        let source = external_backend(root.path(), false, false);
        source.init(FsOptions::empty()).unwrap();
        source.lookup(context(), 1, c"data").unwrap();
        let state: ExternalState =
            mobility::decode(EXTERNAL_KIND, &capture(&source).unwrap()).unwrap();
        std::fs::rename(&path, root.path().join("old")).unwrap();
        std::fs::write(&path, b"old").unwrap();
        assert!(rebuild(&source, state.state, Some(&state.identities)).is_err());
    }

    #[test]
    fn external_strict_rejects_permission_changes_without_changing_bytes() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("data");
        std::fs::write(&path, b"same bytes").unwrap();
        let source = external_backend(root.path(), false, false);
        source.init(FsOptions::empty()).unwrap();
        source.lookup(context(), 1, c"data").unwrap();
        let state = capture(&source).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(prepare(&external_backend(root.path(), false, false), &state).is_err());
    }

    #[test]
    fn external_symlink_identity_does_not_follow_outside_targets() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("secret");
        std::fs::write(&target, b"not part of the export").unwrap();
        std::os::unix::fs::symlink(&target, root.path().join("link")).unwrap();
        let source = external_backend(root.path(), false, false);
        source.init(FsOptions::empty()).unwrap();
        let entry = source.lookup(context(), 1, c"link").unwrap();
        let state = capture(&source).unwrap();
        std::fs::write(&target, b"outside host changed").unwrap();
        let destination = external_backend(root.path(), false, false);
        restore(&destination, &state).unwrap();
        assert_eq!(
            destination.readlink(context(), entry.inode).unwrap(),
            std::os::unix::ffi::OsStrExt::as_bytes(target.as_os_str())
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"outside host changed");
    }

    #[test]
    fn external_guest_rename_preserves_handle_identity_but_unlink_refuses_capture() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("data"), b"identity").unwrap();
        let source = external_backend(root.path(), false, false);
        source.init(FsOptions::empty()).unwrap();
        let entry = source.lookup(context(), 1, c"data").unwrap();
        let handle = source
            .open(context(), entry.inode, false, 0)
            .unwrap()
            .0
            .unwrap();
        source
            .rename(context(), 1, c"data", 1, c"renamed", 0)
            .unwrap();
        let state = capture(&source).unwrap();
        let destination = external_backend(root.path(), false, false);
        restore(&destination, &state).unwrap();
        assert_eq!(
            destination.handles.read().unwrap()[&handle].inode,
            entry.inode
        );
        source.unlink(context(), 1, c"renamed").unwrap();
        assert!(capture(&source).is_err());
    }

    #[test]
    fn state_round_trip_reopens_handles_and_preserves_directory_cookies() {
        let source_root = tempfile::tempdir().unwrap();
        let destination_root = tempfile::tempdir().unwrap();
        std::fs::write(source_root.path().join("data"), b"mobility").unwrap();
        std::fs::write(destination_root.path().join("data"), b"mobility").unwrap();

        let source = backend(source_root.path());
        source.init(FsOptions::empty()).unwrap();
        let name = CString::new("data").unwrap();
        let entry = source.lookup(context(), 1, &name).unwrap();
        let file_handle = source
            .open(context(), entry.inode, false, 0)
            .unwrap()
            .0
            .unwrap();
        let dir_handle = source.opendir(context(), 1, 0).unwrap().0.unwrap();
        let before = source
            .readdir(context(), 1, dir_handle, u32::MAX, 0)
            .unwrap();
        let encoded = capture(&source).unwrap();

        let destination = backend(destination_root.path());
        restore(&destination, &encoded).unwrap();
        assert_eq!(capture(&destination).unwrap(), encoded);
        let after = destination
            .readdir(context(), 1, dir_handle, u32::MAX, 0)
            .unwrap();
        assert_eq!(
            before
                .iter()
                .map(|entry| (entry.ino, entry.offset, entry.name.to_vec()))
                .collect::<Vec<_>>(),
            after
                .iter()
                .map(|entry| (entry.ino, entry.offset, entry.name.to_vec()))
                .collect::<Vec<_>>()
        );

        let handle = destination.handles.read().unwrap()[&file_handle].clone();
        let mut bytes = Vec::new();
        handle
            .file
            .read()
            .unwrap()
            .try_clone()
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, b"mobility");
    }

    #[test]
    fn missing_destination_object_rejects_without_mutation() {
        let source_root = tempfile::tempdir().unwrap();
        std::fs::write(source_root.path().join("data"), b"mobility").unwrap();
        let source = backend(source_root.path());
        source.init(FsOptions::empty()).unwrap();
        source
            .lookup(context(), 1, &CString::new("data").unwrap())
            .unwrap();
        let encoded = capture(&source).unwrap();

        let destination_root = tempfile::tempdir().unwrap();
        let destination = backend(destination_root.path());
        assert!(prepare(&destination, &encoded).is_err());
        assert_eq!(destination.inodes.read().unwrap().iter().count(), 0);
        assert!(destination.handles.read().unwrap().is_empty());
        assert!(destination.dir_handles.read().unwrap().is_empty());
        assert_eq!(destination.next_inode.load(Ordering::Acquire), 3);
        assert_eq!(destination.next_handle.load(Ordering::Acquire), 1);
    }

    #[test]
    fn capture_preserves_symlink_objects_without_following_their_targets() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("nested")).unwrap();
        std::fs::write(root.path().join("nested/file"), b"inside").unwrap();
        std::fs::write(outside.path().join("file"), b"outside").unwrap();
        let targets = [
            ("relative", std::path::PathBuf::from("file")),
            ("dangling", std::path::PathBuf::from("missing")),
            ("external", outside.path().join("file")),
        ];
        for (name, target) in &targets {
            std::os::unix::fs::symlink(target, root.path().join("nested").join(name)).unwrap();
        }
        let source = backend(root.path());
        source.init(FsOptions::empty()).unwrap();
        let nested = source
            .lookup(context(), 1, &CString::new("nested").unwrap())
            .unwrap();
        let links = targets
            .iter()
            .map(|(name, _)| {
                source
                    .lookup(context(), nested.inode, &CString::new(*name).unwrap())
                    .unwrap()
                    .inode
            })
            .collect::<Vec<_>>();
        let encoded = capture(&source).unwrap();
        let destination = backend(root.path());
        restore(&destination, &encoded).unwrap();
        assert_eq!(capture(&destination).unwrap(), encoded);
        for (inode, (_, target)) in links.iter().zip(&targets) {
            use std::os::unix::ffi::OsStrExt;

            assert_eq!(
                destination.readlink(context(), *inode).unwrap(),
                target.as_os_str().as_bytes()
            );
        }
        assert_eq!(
            std::fs::read(outside.path().join("file")).unwrap(),
            b"outside"
        );
    }

    #[test]
    fn nested_symlink_writeback_quota_and_invalid_restore_round_trip() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("nested")).unwrap();
        std::fs::write(root.path().join("nested/file"), b"mobility").unwrap();
        std::os::unix::fs::symlink("file", root.path().join("nested/link")).unwrap();
        let make = |writeback| {
            PassthroughFs::new(super::super::PassthroughConfig {
                root_dir: root.path().to_path_buf(),
                inject_init: false,
                stat_virtualization: StatVirtualization::Off,
                writeback,
                quota_bytes: Some(1024),
                ..Default::default()
            })
            .unwrap()
        };

        let source = make(true);
        source.init(FsOptions::WRITEBACK_CACHE).unwrap();
        let nested = source
            .lookup(context(), 1, &CString::new("nested").unwrap())
            .unwrap();
        let file = source
            .lookup(context(), nested.inode, &CString::new("file").unwrap())
            .unwrap();
        source
            .lookup(context(), nested.inode, &CString::new("link").unwrap())
            .unwrap();
        let handle = source
            .open(
                context(),
                file.inode,
                false,
                (libc::O_WRONLY | libc::O_APPEND) as u32,
            )
            .unwrap()
            .0
            .unwrap();
        source.quota.as_ref().unwrap().charge(17).unwrap();
        let encoded = capture(&source).unwrap();

        let destination = make(true);
        destination.validate_state(&encoded).unwrap();
        destination.restore_state(&encoded).unwrap();
        assert_eq!(destination.quota.as_ref().unwrap().used(), 17);
        let restored = destination.handles.read().unwrap();
        let fd = restored[&handle].file.read().unwrap().as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert_eq!(flags & libc::O_ACCMODE, libc::O_RDWR);
        assert_eq!(flags & libc::O_APPEND, 0);
        drop(restored);

        let before = capture(&destination).unwrap();
        let mut corrupt: PassthroughState = mobility::decode(KIND, &before).unwrap();
        corrupt.next_handle = 0;
        let corrupt = mobility::encode(KIND, &corrupt).unwrap();
        assert!(destination.restore_state(&corrupt).is_err());
        assert_eq!(capture(&destination).unwrap(), before);

        assert!(make(false).validate_state(&encoded).is_err());
    }
}

//! Durable Windows passthrough state and destination-local handle reconstruction.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    io,
    os::windows::ffi::{OsStrExt, OsStringExt},
    path::{Component, PathBuf},
    sync::{Arc, Mutex, RwLock, atomic::Ordering},
};

use serde::{Deserialize, Serialize};

use super::{
    DirHandle, DirSnapshotEntry, HandleData, InodeData, InodeTable, LINUX_O_ACCMODE, PassthroughFs,
    host_error, inode::VirtualMetadata, is_reserved_name, open_options_from_flags,
    reject_reparse_metadata,
};
use crate::backends::{mobility, passthroughfs::quota::QuotaState};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const KIND: &[u8; 8] = b"MSBPTWIN";
const MAX_PATH_DEPTH: usize = 256;
const MAX_COMPONENT_UNITS: usize = 255;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Deserialize, Serialize)]
struct PassthroughState {
    next_inode: u64,
    next_handle: u64,
    quota: Option<QuotaState>,
    inodes: Vec<InodeState>,
    files: Vec<FileHandleState>,
    dirs: Vec<DirHandleState>,
}

#[derive(Deserialize, Serialize)]
struct InodeState {
    inode: u64,
    components: Vec<Vec<u16>>,
    uid: u32,
    gid: u32,
    mode: Option<u32>,
    rdev: u64,
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
    next_inode: u64,
    next_handle: u64,
    quota: Option<QuotaState>,
    inodes: InodeTable,
    files: BTreeMap<u64, Arc<HandleData>>,
    dirs: BTreeMap<u64, Arc<DirHandle>>,
}

//--------------------------------------------------------------------------------------------------
// Functions: Public operations
//--------------------------------------------------------------------------------------------------

pub(super) fn capture(fs: &PassthroughFs) -> io::Result<Vec<u8>> {
    let inodes = fs.inodes.read().unwrap();
    let inode_states = inodes
        .by_inode
        .iter()
        .map(|(inode, data)| {
            let relative = data
                .path
                .strip_prefix(&fs.root)
                .map_err(|_| invalid_state("tracked inode escaped passthrough root"))?;
            let components = relative
                .components()
                .map(|component| match component {
                    Component::Normal(name) => Ok(name.encode_wide().collect()),
                    _ => Err(invalid_state("invalid tracked Windows path")),
                })
                .collect::<io::Result<Vec<_>>>()?;
            let meta = data.virtual_meta.read().unwrap();
            Ok(InodeState {
                inode: *inode,
                components,
                uid: meta.uid,
                gid: meta.gid,
                mode: meta.mode,
                rdev: meta.rdev,
            })
        })
        .collect::<io::Result<Vec<_>>>()?;
    drop(inodes);

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
        .map(|(handle, data)| DirHandleState {
            handle: *handle,
            inode: data.inode,
            flags: data.flags,
            entries: data.snapshot.lock().unwrap().as_ref().map(|entries| {
                entries
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
        .collect::<Vec<_>>();

    let inode_ids = inode_states
        .iter()
        .map(|state| state.inode)
        .collect::<BTreeSet<_>>();
    if files
        .iter()
        .any(|handle| !inode_ids.contains(&handle.inode))
        || dirs.iter().any(|handle| !inode_ids.contains(&handle.inode))
    {
        return Err(invalid_state(
            "passthrough handle references an uncaptured inode",
        ));
    }

    mobility::encode(
        KIND,
        &PassthroughState {
            next_inode: fs.next_inode.load(Ordering::Acquire),
            next_handle: fs.next_handle.load(Ordering::Acquire),
            quota: fs.quota.as_ref().map(|quota| quota.capture_state()),
            inodes: inode_states,
            files,
            dirs,
        },
    )
}

pub(super) fn prepare(fs: &PassthroughFs, bytes: &[u8]) -> io::Result<PreparedState> {
    let state: PassthroughState = mobility::decode(KIND, bytes)?;
    validate_semantics(fs, &state)?;
    rebuild(fs, state)
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
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Validation and reconstruction
//--------------------------------------------------------------------------------------------------

fn validate_semantics(fs: &PassthroughFs, state: &PassthroughState) -> io::Result<()> {
    if state.quota.is_some() != fs.quota.is_some() {
        return Err(invalid_state("passthrough quota configuration differs"));
    }
    if let (Some(quota), Some(saved)) = (&fs.quota, &state.quota) {
        quota.validate_state(saved)?;
    }
    let mut inode_ids = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut roots = 0;
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
            roots += 1;
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
    if roots != 1 || state.next_inode <= max_inode {
        return Err(invalid_state("invalid passthrough root or next inode"));
    }

    let mut handles = BTreeSet::new();
    let mut max_handle = 0;
    for handle in &state.files {
        if handle.handle == 0
            || !handles.insert(handle.handle)
            || !inode_ids.contains(&handle.inode)
            || handle.flags & LINUX_O_ACCMODE as u32 == LINUX_O_ACCMODE as u32
            || (fs.cfg.readonly && handle.flags & LINUX_O_ACCMODE as u32 != 0)
        {
            return Err(invalid_state("invalid passthrough file handle"));
        }
        max_handle = max_handle.max(handle.handle);
    }
    for handle in &state.dirs {
        if handle.handle == 0
            || !handles.insert(handle.handle)
            || !inode_ids.contains(&handle.inode)
            || handle.flags & LINUX_O_ACCMODE as u32 == LINUX_O_ACCMODE as u32
        {
            return Err(invalid_state("invalid passthrough directory handle"));
        }
        if let Some(entries) = &handle.entries {
            let mut previous = 0;
            for entry in entries {
                let synthetic_init = fs.cfg.inject_init
                    && entry.inode == super::INIT_INODE
                    && entry.name == super::INIT_NAME;
                if entry.offset == 0
                    || entry.offset <= previous
                    || (!inode_ids.contains(&entry.inode) && !synthetic_init)
                    || entry.name.is_empty()
                    || entry.name.len() > 255
                    || entry.name.contains(&0)
                    || entry.name.contains(&b'/')
                    || entry.name.contains(&b'\\')
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

fn rebuild(fs: &PassthroughFs, state: PassthroughState) -> io::Result<PreparedState> {
    let mut inodes = InodeTable::default();
    let mut inode_paths = BTreeMap::new();
    for saved in &state.inodes {
        let path = path_from_components(fs, &saved.components)?;
        fs.safe_metadata(&path)?;
        let data = Arc::new(InodeData {
            inode: saved.inode,
            path: path.clone(),
            virtual_meta: RwLock::new(VirtualMetadata {
                uid: saved.uid,
                gid: saved.gid,
                mode: saved.mode,
                rdev: saved.rdev,
            }),
        });
        inodes.by_inode.insert(saved.inode, Arc::clone(&data));
        inodes.by_path.insert(path.clone(), data);
        inode_paths.insert(saved.inode, path);
    }

    let mut files = BTreeMap::new();
    for saved in &state.files {
        let path = inode_paths
            .get(&saved.inode)
            .ok_or_else(|| invalid_state("file handle inode is missing"))?;
        let flags = saved.flags
            & !((super::LINUX_O_CREAT | super::LINUX_O_EXCL | super::LINUX_O_TRUNC) as u32);
        let file = open_options_from_flags(flags, false)?
            .open(path)
            .map_err(host_error)?;
        reject_reparse_metadata(&file.metadata().map_err(host_error)?)?;
        files.insert(
            saved.handle,
            Arc::new(HandleData {
                inode: saved.inode,
                flags: saved.flags,
                file: Mutex::new(file),
            }),
        );
    }

    let mut dirs = BTreeMap::new();
    for saved in &state.dirs {
        let path = inode_paths
            .get(&saved.inode)
            .ok_or_else(|| invalid_state("directory handle inode is missing"))?;
        if !fs.safe_metadata(path)?.file_type().is_dir() {
            return Err(invalid_state(
                "restored directory handle is not a directory",
            ));
        }
        let snapshot = saved.entries.as_ref().map(|entries| {
            entries
                .iter()
                .map(|entry| DirSnapshotEntry {
                    inode: entry.inode,
                    name: entry.name.clone(),
                    offset: entry.offset,
                    file_type: entry.file_type,
                })
                .collect()
        });
        dirs.insert(
            saved.handle,
            Arc::new(DirHandle {
                inode: saved.inode,
                flags: saved.flags,
                snapshot: Mutex::new(snapshot),
            }),
        );
    }

    Ok(PreparedState {
        next_inode: state.next_inode,
        next_handle: state.next_handle,
        quota: state.quota,
        inodes,
        files,
        dirs,
    })
}

fn validate_components(components: &[Vec<u16>]) -> io::Result<()> {
    if components.len() > MAX_PATH_DEPTH {
        return Err(invalid_state("passthrough path is too deep"));
    }
    for component in components {
        if component.is_empty() || component.len() > MAX_COMPONENT_UNITS {
            return Err(invalid_state("invalid passthrough path component"));
        }
        let name = OsString::from_wide(component);
        let Some(name) = name.to_str() else {
            return Err(invalid_state("passthrough path is not valid Unicode"));
        };
        if name == "." || name == ".." || name.contains(['\0', '/', '\\']) || is_reserved_name(name)
        {
            return Err(invalid_state("invalid passthrough path component"));
        }
    }
    Ok(())
}

fn path_from_components(fs: &PassthroughFs, components: &[Vec<u16>]) -> io::Result<PathBuf> {
    let mut path = fs.root.clone();
    for component in components {
        path.push(OsString::from_wide(component));
    }
    Ok(path)
}

fn invalid_state(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

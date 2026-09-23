//! Durable Windows passthrough state and destination-local handle reconstruction.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::File,
    io::{self, Read},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::{Component, PathBuf},
    sync::{Arc, Mutex, RwLock, atomic::Ordering},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_BASIC_INFO, FileBasicInfo, GetFileInformationByHandle,
    GetFileInformationByHandleEx,
};

use super::{
    DirHandle, DirSnapshotEntry, HandleData, InodeData, InodeTable, LINUX_O_ACCMODE, PassthroughFs,
    host_error, inode::VirtualMetadata, is_reserved_name, open_options_from_flags,
    reject_reparse_metadata,
};
use crate::backends::{mobility, passthroughfs::quota::QuotaState};

#[path = "owned_mobility.rs"]
mod owned;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const KIND: &[u8; 8] = b"MSBPTWIN";
const EXTERNAL_KIND: &[u8; 8] = b"MSBPTWX1";
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
struct ExternalState {
    state: PassthroughState,
    identities: BTreeMap<u64, ObjectIdentity>,
    invalid_inodes: BTreeSet<u64>,
}

#[derive(Deserialize, Serialize, PartialEq, Eq)]
struct ObjectIdentity {
    volume: u32,
    file_id: u64,
    directory: bool,
    size: u64,
    modified: u64,
    changed: i64,
    content: Vec<u8>,
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
    invalid_inodes: BTreeSet<u64>,
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

fn capture_linked(fs: &PassthroughFs, excluded: &BTreeSet<u64>) -> io::Result<PassthroughState> {
    let inodes = fs.inodes.read().unwrap();
    let inode_states = inodes
        .by_inode
        .iter()
        .filter(|(inode, _)| !excluded.contains(inode))
        .map(|(inode, data)| {
            let path = data.path();
            let relative = path
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
        .filter(|(_, data)| !excluded.contains(&data.inode))
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

    let state = PassthroughState {
        next_inode: fs.next_inode.load(Ordering::Acquire),
        next_handle: fs.next_handle.load(Ordering::Acquire),
        quota: fs.quota.as_ref().map(|quota| quota.capture_state()),
        inodes: inode_states,
        files,
        dirs,
    };
    Ok(state)
}

pub(super) fn capture(fs: &PassthroughFs) -> io::Result<Vec<u8>> {
    if fs.cfg.owned_checkpoint.is_some() {
        return owned::capture(fs);
    }
    let state = capture_linked(fs, &BTreeSet::new())?;
    if fs.cfg.external_checkpoint.is_none() {
        return mobility::encode(KIND, &state);
    }
    if fs
        .invalid_inodes
        .read()
        .unwrap()
        .contains(&super::ROOT_INODE)
    {
        return Err(invalid_state(
            "unavailable external root cannot establish a new checkpoint",
        ));
    }
    let identities = state
        .inodes
        .iter()
        .map(|saved| {
            let identity = object_identity(fs, saved)?;
            // A guest-open file may still refer to a removed/replaced host object.
            // Never snapshot its path replacement as if it were that live handle.
            for handle in fs
                .handles
                .read()
                .unwrap()
                .values()
                .filter(|handle| handle.inode == saved.inode)
            {
                let file = handle.file.lock().unwrap();
                if file_identity(&file)? != (identity.volume, identity.file_id) {
                    return Err(invalid_state(
                        "external open handle no longer matches its captured path",
                    ));
                }
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
        validate_quota(fs, &external.state)?;
        validate_shape(
            &external.state,
            fs.cfg.readonly,
            fs.cfg.inject_init,
            &external.invalid_inodes,
        )?;
        let mut invalid = external.invalid_inodes;
        let mut observed = BTreeMap::new();
        // Descendants cannot regain validity through a replaced parent directory.
        external
            .state
            .inodes
            .sort_by_key(|saved| saved.components.len());
        let mut invalid_paths = Vec::<Vec<Vec<u16>>>::new();
        for saved in &external.state.inodes {
            let identity = &external.identities[&saved.inode];
            let current = if invalid_paths
                .iter()
                .any(|path| saved.components.starts_with(path))
            {
                None
            } else {
                object_identity(fs, saved)
                    .ok()
                    .filter(|current| same_object(identity, current, options.remapped))
            };
            let valid = current.is_some();
            if let Some(current) = current {
                observed.insert(saved.inode, current);
            }
            if !valid {
                if !options.relaxed {
                    return Err(invalid_state(format!(
                        "external object {} is missing, replaced, or changed",
                        saved.inode
                    )));
                }
                invalid.insert(saved.inode);
                invalid_paths.push(saved.components.clone());
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
        let mut prepared = rebuild(fs, external.state, Some(&observed))?;
        prepared.invalid_inodes = invalid;
        return Ok(prepared);
    }
    let state: PassthroughState = mobility::decode(KIND, bytes)?;
    validate_semantics(fs, &state)?;
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
    if let Some(options) = &fs.cfg.external_checkpoint {
        *options.invalid_inodes.lock().unwrap() = prepared.invalid_inodes.iter().copied().collect();
    }
    *fs.invalid_inodes.write().unwrap() = prepared.invalid_inodes;
    Ok(())
}

/// Validate a missing export's payload without opening any host paths.
pub(super) fn validate_unavailable(bytes: &[u8]) -> io::Result<()> {
    let external: ExternalState = mobility::decode(EXTERNAL_KIND, bytes)?;
    validate_external_shape(&external)?;
    validate_shape(&external.state, false, false, &external.invalid_inodes)
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
    validate_shape(&external.state, false, false, &external.invalid_inodes)?;
    let source = source
        .to_str()
        .map_err(|_| invalid_state("source filename is not UTF-8"))?
        .encode_utf16()
        .collect::<Vec<_>>();
    let destination = destination
        .to_str()
        .map_err(|_| invalid_state("destination filename is not UTF-8"))?
        .encode_utf16()
        .collect::<Vec<_>>();
    validate_components(std::slice::from_ref(&destination))?;
    if !external.state.dirs.is_empty()
        || external
            .state
            .files
            .iter()
            .any(|handle| handle.inode == super::ROOT_INODE)
    {
        return Err(invalid_state("single-file state opens a real directory"));
    }
    for inode in &mut external.state.inodes {
        if inode.inode == super::ROOT_INODE {
            continue;
        }
        if inode.components != [source.clone()]
            || external.identities[&inode.inode].directory
            || inode
                .mode
                .is_some_and(|mode| mode & super::S_IFMT != super::S_IFREG)
        {
            return Err(invalid_state(
                "single-file state references a sibling or non-file object",
            ));
        }
        inode.components = vec![destination.clone()];
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

//--------------------------------------------------------------------------------------------------
// Functions: Validation and reconstruction
//--------------------------------------------------------------------------------------------------

fn validate_external_shape(external: &ExternalState) -> io::Result<()> {
    if external.identities.len() != external.state.inodes.len()
        || external
            .state
            .inodes
            .iter()
            .any(|saved| !external.identities.contains_key(&saved.inode))
        || external.identities.values().any(|identity| {
            if identity.directory {
                !identity.content.is_empty()
            } else {
                identity.content.len() != 32
            }
        })
        || external.invalid_inodes.iter().any(|inode| {
            *inode == 0
                || *inode == super::INIT_INODE
                || *inode >= external.state.next_inode
                || external.identities.contains_key(inode)
        })
    {
        return Err(invalid_state(
            "invalid external filesystem identity manifest",
        ));
    }
    Ok(())
}

fn same_object(saved: &ObjectIdentity, current: &ObjectIdentity, remapped: bool) -> bool {
    saved.directory == current.directory
        && (remapped || (saved.volume == current.volume && saved.file_id == current.file_id))
        // New directory lookups intentionally observe the current external namespace;
        // captured directory iterators retain their saved sequence.
        && (saved.directory || (saved.size == current.size && saved.content == current.content
            && (remapped || saved.modified == current.modified)))
}

fn object_identity(fs: &PassthroughFs, saved: &InodeState) -> io::Result<ObjectIdentity> {
    let path = path_from_components(fs, &saved.components)?;
    let metadata = fs.safe_metadata(&path)?;
    let mut file = open_identity_file(&path)?;
    let before = file.metadata().map_err(host_error)?;
    reject_reparse_metadata(&before)?;
    if before.is_dir() != metadata.is_dir() || (!before.is_dir() && !before.is_file()) {
        return Err(invalid_state(
            "external object changed type or is not checkpointable",
        ));
    }
    let (volume, file_id) = file_identity(&file)?;
    let changed = file_change_time(&file)?;
    let mut content = Vec::new();
    if before.is_file() {
        // Guest symlinks are regular backing files containing the target on Windows;
        // native reparse points are never followed or admitted.
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 128 * 1024];
        loop {
            let count = file.read(&mut buffer).map_err(host_error)?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
        }
        content = digest.finalize().to_vec();
    }
    let after = file.metadata().map_err(host_error)?;
    if before.file_size() != after.file_size()
        || before.last_write_time() != after.last_write_time()
        || before.creation_time() != after.creation_time()
        || file_identity(&file)? != (volume, file_id)
        || file_change_time(&file)? != changed
    {
        return Err(invalid_state(
            "external object changed while recording its identity",
        ));
    }
    Ok(ObjectIdentity {
        volume,
        file_id,
        directory: before.is_dir(),
        size: before.file_size(),
        modified: before.last_write_time(),
        changed,
        content,
    })
}

fn open_identity_file(path: &std::path::Path) -> io::Result<File> {
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(super::FILE_FLAG_OPEN_REPARSE_POINT | super::FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .map_err(host_error)
}

fn validate_reopened_file(file: &File, expected: &ObjectIdentity) -> io::Result<()> {
    let metadata = file.metadata().map_err(host_error)?;
    reject_reparse_metadata(&metadata)?;
    if file_identity(file)? != (expected.volume, expected.file_id)
        || metadata.is_dir() != expected.directory
        || metadata.file_size() != expected.size
        || metadata.last_write_time() != expected.modified
        || file_change_time(file)? != expected.changed
    {
        return Err(invalid_state(
            "external object changed while reconstructing destination handles",
        ));
    }
    Ok(())
}

fn file_change_time(file: &File) -> io::Result<i64> {
    let mut info = FILE_BASIC_INFO::default();
    // Like file_identity, this borrows a live handle and fills the exact ABI struct.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileBasicInfo,
            (&mut info as *mut FILE_BASIC_INFO).cast(),
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(host_error(io::Error::last_os_error()));
    }
    Ok(info.ChangeTime)
}

pub(super) fn file_identity(file: &File) -> io::Result<(u32, u64)> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // The borrowed File keeps the handle live for the entire query; the API fills
    // only this initialized information struct and never takes ownership.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(host_error(io::Error::last_os_error()));
    }
    Ok((
        info.dwVolumeSerialNumber,
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    ))
}

fn validate_semantics(fs: &PassthroughFs, state: &PassthroughState) -> io::Result<()> {
    validate_quota(fs, state)?;
    validate_shape(state, fs.cfg.readonly, fs.cfg.inject_init, &BTreeSet::new())
}

fn validate_quota(fs: &PassthroughFs, state: &PassthroughState) -> io::Result<()> {
    if state.quota.is_some() != fs.quota.is_some() {
        return Err(invalid_state("passthrough quota configuration differs"));
    }
    if let (Some(quota), Some(saved)) = (&fs.quota, &state.quota) {
        quota.validate_state(saved)?;
    }
    Ok(())
}

fn validate_shape(
    state: &PassthroughState,
    readonly: bool,
    inject_init: bool,
    invalid: &BTreeSet<u64>,
) -> io::Result<()> {
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
    let invalid_root = invalid.contains(&super::ROOT_INODE);
    if roots + usize::from(invalid_root) != 1
        || state.next_inode <= max_inode
        || (invalid_root && !state.inodes.is_empty())
    {
        return Err(invalid_state("invalid passthrough root or next inode"));
    }

    let mut handles = BTreeSet::new();
    let mut max_handle = 0;
    for handle in &state.files {
        if handle.handle == 0
            || !handles.insert(handle.handle)
            || !inode_ids.contains(&handle.inode)
            || handle.flags & LINUX_O_ACCMODE as u32 == LINUX_O_ACCMODE as u32
            || (readonly && handle.flags & LINUX_O_ACCMODE as u32 != 0)
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
                let synthetic_init = inject_init
                    && entry.inode == super::INIT_INODE
                    && entry.name == super::INIT_NAME;
                if entry.offset == 0
                    || entry.offset <= previous
                    || (!inode_ids.contains(&entry.inode)
                        && !invalid.contains(&entry.inode)
                        && !synthetic_init)
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

fn rebuild(
    fs: &PassthroughFs,
    state: PassthroughState,
    expected: Option<&BTreeMap<u64, ObjectIdentity>>,
) -> io::Result<PreparedState> {
    let mut inodes = InodeTable::default();
    let mut inode_paths = BTreeMap::new();
    for saved in &state.inodes {
        let path = path_from_components(fs, &saved.components)?;
        fs.safe_metadata(&path)?;
        if let Some(expected) = expected {
            validate_reopened_file(&open_identity_file(&path)?, &expected[&saved.inode])?;
        }
        let data = Arc::new(InodeData {
            inode: saved.inode,
            path: RwLock::new(path.clone()),
            identity: fs.owned_identity(&path)?,
            virtual_meta: RwLock::new(VirtualMetadata {
                uid: saved.uid,
                gid: saved.gid,
                mode: saved.mode,
                rdev: saved.rdev,
            }),
            retained: Mutex::new(None),
            retained_stat: Mutex::new(None),
            lookups: std::sync::atomic::AtomicU64::new(0),
        });
        if let Some(identity) = data.identity
            && inodes.by_identity.insert(identity, data.clone()).is_some()
        {
            return Err(invalid_state(
                "owned aliases have conflicting logical inode ids",
            ));
        }
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
        if let Some(expected) = expected {
            validate_reopened_file(&file, &expected[&saved.inode])?;
        }
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
        invalid_inodes: BTreeSet::new(),
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
        if name == "."
            || name == ".."
            || name.contains(['\0', '/', '\\', ':'])
            || is_reserved_name(name)
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

fn invalid_state(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

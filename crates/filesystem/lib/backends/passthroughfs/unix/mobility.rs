//! Durable passthrough filesystem state and destination-local handle reconstruction.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io,
    os::fd::{AsRawFd, FromRawFd, RawFd},
    sync::{Arc, Mutex, RwLock, atomic::Ordering},
};

#[cfg(target_os = "linux")]
use std::collections::HashSet;
#[cfg(target_os = "macos")]
use std::{
    ffi::{CStr, CString, OsStr},
    os::unix::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};

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
const MAX_PATH_DEPTH: usize = 256;
const MAX_COMPONENT_BYTES: usize = 255;
const GUEST_O_CREAT: u32 = 0x40;
const GUEST_O_EXCL: u32 = 0x80;
const GUEST_O_TRUNC: u32 = 0x200;

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
    let inode_states = capture_inodes(fs)?;
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

    mobility::encode(
        KIND,
        &PassthroughState {
            next_inode: fs.next_inode.load(Ordering::Acquire),
            next_handle: fs.next_handle.load(Ordering::Acquire),
            writeback: fs.writeback.load(Ordering::Acquire),
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
    fs.writeback.store(prepared.writeback, Ordering::Release);
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Capture
//--------------------------------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn capture_inodes(fs: &PassthroughFs) -> io::Result<Vec<InodeState>> {
    let inodes = fs.inodes.read().unwrap();
    let mut states = Vec::new();
    for (inode_id, data) in inodes.iter() {
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
fn capture_inodes(fs: &PassthroughFs) -> io::Result<Vec<InodeState>> {
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
        if data.unlinked_fd.load(Ordering::Acquire) >= 0 {
            return Err(invalid_state(
                "open-unlinked passthrough objects are not checkpointable",
            ));
        }
        let components = if inode_id == 1 {
            Vec::new()
        } else {
            let fd = open_macos_inode_for_path(fs, inode_id)?;
            let path = fd_path(fd)?;
            unsafe { libc::close(fd) };
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

fn validate_semantics(fs: &PassthroughFs, state: &PassthroughState) -> io::Result<()> {
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
    if root_count != 1 || state.next_inode <= max_inode {
        return Err(invalid_state("invalid passthrough root or next inode"));
    }

    let mut handles = BTreeSet::new();
    let mut max_handle = 0;
    for handle in &state.files {
        if handle.handle == 0
            || !handles.insert(handle.handle)
            || !inode_ids.contains(&handle.inode)
            || handle.flags & 0b11 == 0b11
            || (fs.cfg.readonly() && handle.flags & 0b11 != 0)
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

fn rebuild(fs: &PassthroughFs, mut state: PassthroughState) -> io::Result<PreparedState> {
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
        let (alt_key, data) = inode_data_from_fd(fs, &inodes, saved, &path_ids, fd)?;
        unsafe { libc::close(fd) };
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
        files.insert(
            saved.handle,
            Arc::new(HandleData {
                inode: saved.inode,
                flags: saved.flags,
                file: RwLock::new(unsafe { File::from_raw_fd(fd) }),
            }),
        );
    }

    let mut dirs = BTreeMap::new();
    for saved in &state.dirs {
        let components = inode_paths
            .get(&saved.inode)
            .ok_or_else(|| invalid_state("directory handle inode is missing"))?;
        let fd = open_components(fs, components, directory_open_flags())?;
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
                file: RwLock::new(unsafe { File::from_raw_fd(fd) }),
                snapshot: Mutex::new(snapshot),
            }),
        );
    }

    Ok(PreparedState {
        next_inode: state.next_inode,
        next_handle: state.next_handle,
        writeback: state.writeback,
        quota: state.quota,
        inodes,
        files,
        dirs,
    })
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
fn open_macos_inode_for_path(fs: &PassthroughFs, inode_id: u64) -> io::Result<RawFd> {
    for flags in [
        libc::O_RDONLY,
        libc::O_RDONLY | libc::O_DIRECTORY,
        libc::O_SYMLINK,
    ] {
        if let Ok(fd) = inode::open_inode_fd(fs, inode_id, flags) {
            return Ok(fd);
        }
    }
    Err(invalid_state("cannot reopen tracked passthrough inode"))
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

fn invalid_state(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
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

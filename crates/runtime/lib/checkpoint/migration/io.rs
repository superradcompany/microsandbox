//! Bounded no-follow acquisition and independent durable capture.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};
use std::time::UNIX_EPOCH;

use cap_primitives::fs as cap_fs;
use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

pub(super) const MAX_METADATA: u64 = 1024 * 1024;
pub(super) const MAX_ENTRIES: usize = 16384;
pub(super) const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024 * 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Identity {
    pub object: String,
    pub length: u64,
    pub links: u64,
    pub modified: (u64, u32),
    pub changed: Option<(i64, i64)>,
}

/// Per-acquisition canonical directory names. Never shared across operations or writer leases.
#[derive(Default)]
pub(super) struct EntryCache {
    names: BTreeMap<String, BTreeSet<OsString>>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn directory(path: &Path) -> Result<File, String> {
    let absolute = std::path::absolute(path).map_err(|_| "cannot resolve storage directory")?;
    let parent = absolute.parent().ok_or("storage directory has no parent")?;
    let name = absolute
        .file_name()
        .ok_or("storage directory has no name")?;
    let parent = cap_fs::open_ambient_dir(parent, cap_primitives::ambient_authority())
        .map_err(|_| "cannot open storage parent")?;
    let file = cap_fs::open_dir_nofollow(&parent, Path::new(name))
        .map_err(|_| "storage directory is missing or linked")?;
    reject_link(
        &file
            .metadata()
            .map_err(|_| "cannot inspect storage directory")?,
    )?;
    // cap-primitives deliberately returns O_PATH on Linux. Reopen this pinned inode through
    // openat(".") before permission changes or fsync; those operations reject O_PATH handles.
    #[cfg(target_os = "linux")]
    let file = {
        use std::os::fd::{AsRawFd, FromRawFd};
        let fd = unsafe {
            libc::openat(
                file.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err("cannot retain readable storage directory".into());
        }
        unsafe { File::from_raw_fd(fd) }
    };
    Ok(file)
}

pub(super) fn subdirectory(root: &File, relative: &Path) -> Result<File, String> {
    let mut cursor = root.try_clone().map_err(|_| "cannot retain directory")?;
    for component in relative.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err("invalid storage directory component".into());
        }
        cursor = cap_fs::open_dir_nofollow(&cursor, Path::new(component.as_os_str()))
            .map_err(|_| "storage directory is missing or linked")?;
        reject_link(
            &cursor
                .metadata()
                .map_err(|_| "cannot inspect storage directory")?,
        )?;
    }
    Ok(cursor)
}

pub(super) fn open(root: &File, relative: &Path) -> Result<File, String> {
    let parts: Vec<_> = relative.components().collect();
    if parts.is_empty()
        || parts.len() > 12
        || parts.iter().any(|p| !matches!(p, Component::Normal(_)))
    {
        return Err("storage source has invalid path components".into());
    }
    let mut parent = root
        .try_clone()
        .map_err(|_| "cannot retain storage directory")?;
    for part in &parts[..parts.len() - 1] {
        parent = cap_fs::open_dir_nofollow(&parent, Path::new(part.as_os_str()))
            .map_err(|_| "storage source traverses a missing or linked directory")?;
        reject_link(
            &parent
                .metadata()
                .map_err(|_| "cannot inspect source directory")?,
        )?;
    }
    let mut options = cap_fs::OpenOptions::new();
    options.read(true);
    options._cap_fs_ext_follow(cap_fs::FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use cap_fs::OpenOptionsExt;
        // Read-only discovery must not deny another process's writes. Execution separately
        // reopens these exact pinned objects with deny-write sharing in WriterGuard.
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    }
    let file = cap_fs::open(
        &parent,
        Path::new(parts.last().unwrap().as_os_str()),
        &options,
    )
    .map_err(|_| "storage source is unavailable or linked")?;
    let metadata = file
        .metadata()
        .map_err(|_| "cannot inspect storage source")?;
    reject_link(&metadata)?;
    if !metadata.is_file() {
        return Err("storage source must be a regular file".into());
    }
    Ok(file)
}

pub(super) fn exact(path: &Path) -> Result<File, String> {
    let parent = path.parent().ok_or("source binding has no parent")?;
    let name = path.file_name().ok_or("source binding has no filename")?;
    open(&directory(parent)?, Path::new(name))
}

pub(super) fn bytes(root: &File, path: &Path) -> Result<Option<Vec<u8>>, String> {
    // Absence is distinguished before open only to support missing journals; a replacement
    // still passes through descriptor-relative no-follow acquisition and bounded reads.
    match cap_fs::stat(root, path, cap_fs::FollowSymlinks::No) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("cannot inspect legacy metadata".into()),
        Ok(_) => {}
    }
    let mut file = open(root, path)?;
    if file
        .metadata()
        .map_err(|_| "cannot inspect legacy metadata")?
        .len()
        > MAX_METADATA
    {
        return Err("legacy metadata exceeds its size bound".into());
    }
    if identity(&file)?.links != 1 {
        return Err("legacy journal has hardlink aliases".into());
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_METADATA + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read legacy metadata")?;
    if bytes.len() as u64 > MAX_METADATA {
        return Err("legacy metadata exceeds its size bound".into());
    }
    Ok(Some(bytes))
}

pub(super) fn identity(file: &File) -> Result<Identity, String> {
    let metadata = file
        .metadata()
        .map_err(|_| "cannot inspect pinned storage")?;
    reject_link(&metadata)?;
    #[cfg(unix)]
    let (object, links) = {
        use std::os::unix::fs::MetadataExt;
        (
            format!("{}:{}", metadata.dev(), metadata.ino()),
            metadata.nlink(),
        )
    };
    #[cfg(windows)]
    let (object, links) = {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, &mut info) } == 0 {
            return Err("cannot establish Windows source identity".into());
        }
        (
            format!(
                "{}:{}:{}",
                info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow
            ),
            u64::from(info.nNumberOfLinks),
        )
    };
    let time = metadata
        .modified()
        .map_err(|_| "cannot inspect source modification time")?
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "source modification time is unsupported")?;
    #[cfg(unix)]
    let changed = {
        use std::os::unix::fs::MetadataExt;
        Some((metadata.ctime(), metadata.ctime_nsec()))
    };
    #[cfg(windows)]
    let changed = {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_BASIC_INFO, FileBasicInfo, GetFileInformationByHandleEx,
        };
        let mut info: FILE_BASIC_INFO = unsafe { std::mem::zeroed() };
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle() as _,
                FileBasicInfo,
                (&mut info as *mut FILE_BASIC_INFO).cast(),
                std::mem::size_of::<FILE_BASIC_INFO>() as u32,
            )
        } == 0
        {
            return Err("cannot establish Windows source change time".into());
        }
        // LastWriteTime can be restored by ordinary file APIs. ChangeTime also records the
        // replacement and timestamp edits, so a same-size write cannot reuse a frozen plan.
        Some((info.ChangeTime, 0))
    };
    Ok(Identity {
        object,
        length: metadata.len(),
        links,
        modified: (time.as_secs(), time.subsec_nanos()),
        changed,
    })
}

/// Count actual directory entries rather than user path spellings. Kernel FD path reporting can
/// preserve caller casing on APFS, so even a "normalized" pathname is insufficient evidence.
pub(super) fn entry_identity(
    file: &File,
    path: &Path,
    cache: &mut EntryCache,
) -> Result<String, String> {
    let parent = directory(path.parent().ok_or("disk alias has no parent")?)?;
    let parent_id = identity(&parent)?.object;
    if !cache.names.contains_key(&parent_id) {
        let mut names = BTreeSet::new();
        for entry in
            cap_fs::read_base_dir(&parent).map_err(|_| "cannot enumerate alias directory")?
        {
            if names.len() >= MAX_ENTRIES {
                return Err("alias directory exceeds its entry bound".into());
            }
            names.insert(
                entry
                    .map_err(|_| "cannot read alias directory entry")?
                    .file_name(),
            );
        }
        cache.names.insert(parent_id.clone(), names);
    }
    let names = &cache.names[&parent_id];
    let requested = path.file_name().ok_or("disk alias has no filename")?;
    let actual = if names.contains(requested) {
        requested.to_os_string()
    } else {
        // A case/Unicode/short-name alias may still resolve to this inode. Choose its stored
        // name only when this directory contains exactly one link to that inode. Ambiguity
        // fails closed instead of crediting a second spelling as a second hardlink.
        let object = identity(file)?.object;
        let mut found = None;
        for name in names {
            if let Ok(candidate) = open(&parent, Path::new(name))
                && identity(&candidate)?.object == object
            {
                if found.is_some() {
                    return Err("noncanonical alias is ambiguous between directory entries".into());
                }
                found = Some(name.clone());
            }
        }
        found.ok_or("disk alias directory entry changed")?
    };
    #[cfg(unix)]
    let name = {
        use std::os::unix::ffi::OsStrExt;
        hex::encode(actual.as_bytes())
    };
    #[cfg(windows)]
    let name = {
        use std::os::windows::ffi::OsStrExt;
        hex::encode(
            actual
                .encode_wide()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
    };
    Ok(format!("{parent_id}/{name}"))
}

pub(super) fn reject_link(metadata: &fs::Metadata) -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err("storage cannot use reparse points".into());
        }
    }
    if metadata.file_type().is_symlink() {
        return Err("storage cannot use symlinks".into());
    }
    Ok(())
}

pub(super) fn private_directory(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => return verify_private_directory(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("cannot inspect private capture directory".into()),
    }
    let parent = path.parent().ok_or("private directory has no parent")?;
    directory(parent)?;
    let staging = tempfile::Builder::new()
        .prefix(".storage-directory-")
        .tempdir_in(parent)
        .map_err(|error| format!("create private capture directory: {error}"))?;
    // Harden before publishing the name or placing any disk bytes inside it. On Windows
    // MoveFileExW(WRITE_THROUGH) persists this namespace publication; directory FlushFileBuffers
    // is not a supported substitute and requires different access rights from an inspection FD.
    harden_created(staging.path(), true)?;
    publish(staging.path(), path)?;
    verify_private_directory(path)
}

pub(super) fn publish(source: &Path, destination: &Path) -> Result<(), String> {
    super::super::replace_file(source, destination)
        .map_err(|error| format!("publish migration storage: {error}"))?;
    #[cfg(unix)]
    sync(
        destination
            .parent()
            .ok_or("published storage has no parent")?,
    )?;
    // Windows replace_file uses MOVEFILE_WRITE_THROUGH. Every new directory/file is
    // published through this operation after its writable contents have been flushed.
    Ok(())
}

pub(super) fn harden_created(path: &Path, directory: bool) -> Result<(), String> {
    #[cfg(unix)]
    let file = if directory {
        self::directory(path)?
    } else {
        exact(path)?
    };
    #[cfg(windows)]
    let file = {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        let file = fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES | 0x0002_0000 | 0x0004_0000)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(
                FILE_FLAG_OPEN_REPARSE_POINT
                    | if directory {
                        FILE_FLAG_BACKUP_SEMANTICS
                    } else {
                        0
                    },
            )
            .open(path)
            .map_err(|_| "cannot open new storage security descriptor")?;
        reject_link(&file.metadata().map_err(|_| "cannot inspect new storage")?)?;
        file
    };
    microsandbox_utils::private_file::harden(&file, directory)
        .map_err(|error| format!("protect new storage permissions: {error}"))
}

pub(super) fn verify_private_directory(path: &Path) -> Result<(), String> {
    microsandbox_utils::private_file::verify(&directory(path)?)
        .map_err(|error| format!("migration storage permissions are not private: {error}"))
}

#[cfg(unix)]
pub(super) fn sync(path: &Path) -> Result<(), String> {
    directory(path)?
        .sync_all()
        .map_err(|error| format!("flush storage directory: {error}"))?;
    Ok(())
}

pub(super) fn capture(source: &File, destination: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        let parent = destination.parent().ok_or("capture has no parent")?;
        verify_private_directory(parent)?;
        let staging = tempfile::NamedTempFile::new_in(parent)
            .map_err(|error| format!("create private capture: {error}"))?;
        harden_created(staging.path(), false)?;
        microsandbox_utils::copy::copy_file_handles(source, staging.as_file())
            .map_err(|error| format!("capture pinned storage: {error}"))?;
        // copy_file_handles flushes the writable handle. Close it before the write-through
        // rename; a read-only inspection pin must never be used for FlushFileBuffers.
        let (file, temporary) = staging.keep().map_err(|error| error.to_string())?;
        drop(file);
        publish(&temporary, destination)
    }
    #[cfg(unix)]
    capture_unix(source, destination)
}

#[cfg(unix)]
fn capture_unix(source: &File, destination: &Path) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;
        use std::os::fd::AsRawFd;
        use std::os::unix::ffi::OsStrExt;
        let parent = directory(destination.parent().ok_or("capture has no parent")?)?;
        let name = CString::new(
            destination
                .file_name()
                .ok_or("capture has no name")?
                .as_bytes(),
        )
        .map_err(|_| "invalid capture name")?;
        if unsafe { libc::fclonefileat(source.as_raw_fd(), parent.as_raw_fd(), name.as_ptr(), 0) }
            == 0
        {
            let target = open(&parent, Path::new(destination.file_name().unwrap()))?;
            microsandbox_utils::private_file::harden(&target, false)
                .map_err(|error| format!("protect cloned storage: {error}"))?;
            target
                .sync_all()
                .map_err(|error| format!("flush cloned storage: {error}"))?;
            return sync(destination.parent().unwrap());
        }
        let error = std::io::Error::last_os_error();
        if !matches!(
            error.raw_os_error(),
            Some(libc::ENOTSUP | libc::EXDEV | libc::EINVAL | libc::ENOSYS)
        ) {
            return Err(format!("clone pinned storage: {error}"));
        }
    }
    let mut options = fs::OpenOptions::new();
    options.create_new(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let target = options
        .open(destination)
        .map_err(|error| format!("create private capture: {error}"))?;
    microsandbox_utils::copy::copy_file_handles(source, &target)
        .map_err(|error| format!("capture pinned storage: {error}"))?;
    sync(destination.parent().unwrap())
}

/// Read only the fixed header and bounded backing basename; never follow embedded paths.
pub(super) fn header(file: &File, qcow: bool) -> Result<(u64, Option<String>), String> {
    if !qcow {
        return Ok((
            file.metadata()
                .map_err(|_| "cannot inspect raw disk")?
                .len(),
            None,
        ));
    }
    let mut file = file.try_clone().map_err(|_| "cannot retain qcow header")?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| "cannot seek qcow header")?;
    let mut fixed = [0u8; 104];
    file.read_exact(&mut fixed)
        .map_err(|_| "truncated qcow header")?;
    let version = u32::from_be_bytes(fixed[4..8].try_into().unwrap());
    let bits = u32::from_be_bytes(fixed[20..24].try_into().unwrap());
    if &fixed[..4] != b"QFI\xfb" || !matches!(version, 2 | 3) || !(9..=21).contains(&bits) {
        return Err("unsupported qcow header".into());
    }
    if version == 3 && u64::from_be_bytes(fixed[72..80].try_into().unwrap()) & !1 != 0 {
        return Err("unsupported qcow incompatible features".into());
    }
    // Bound parser allocation before the image library sees untrusted tables. Historical
    // producers use ordinary unencrypted QCOW2 without internal snapshots or external data.
    let container = file
        .metadata()
        .map_err(|_| "cannot inspect qcow container")?
        .len();
    let cluster = 1u64 << bits;
    let l1_entries = u32::from_be_bytes(fixed[36..40].try_into().unwrap()) as u64;
    let l1_offset = u64::from_be_bytes(fixed[40..48].try_into().unwrap());
    let refcount_offset = u64::from_be_bytes(fixed[48..56].try_into().unwrap());
    let refcount_clusters = u32::from_be_bytes(fixed[56..60].try_into().unwrap()) as u64;
    let l1_bytes = l1_entries
        .checked_mul(8)
        .ok_or("qcow table size overflow")?;
    let refcount_bytes = refcount_clusters
        .checked_mul(cluster)
        .ok_or("qcow table size overflow")?;
    if l1_bytes > 8 * 1024 * 1024
        || refcount_bytes > 8 * 1024 * 1024
        || l1_offset
            .checked_add(l1_bytes)
            .is_none_or(|end| end > container)
        || refcount_offset
            .checked_add(refcount_bytes)
            .is_none_or(|end| end > container)
        || u32::from_be_bytes(fixed[32..36].try_into().unwrap()) != 0
        || u32::from_be_bytes(fixed[60..64].try_into().unwrap()) != 0
        || (version == 3
            && (u32::from_be_bytes(fixed[96..100].try_into().unwrap()) != 4
                || !(104..=cluster as u32)
                    .contains(&u32::from_be_bytes(fixed[100..104].try_into().unwrap()))))
    {
        return Err("qcow metadata exceeds the supported bounded producer format".into());
    }
    let size = u64::from_be_bytes(fixed[24..32].try_into().unwrap());
    let offset = u64::from_be_bytes(fixed[8..16].try_into().unwrap());
    let length = u32::from_be_bytes(fixed[16..20].try_into().unwrap()) as u64;
    if length == 0 && offset == 0 {
        return Ok((size, None));
    }
    if length == 0
        || length > 1023
        || offset < 72
        || offset
            .checked_add(length)
            .is_none_or(|end| end > (1u64 << bits))
    {
        return Err("invalid qcow dependency header".into());
    }
    let mut name = vec![0; length as usize];
    file.seek(SeekFrom::Start(offset))
        .and_then(|_| file.read_exact(&mut name))
        .map_err(|_| "truncated qcow dependency")?;
    let name = String::from_utf8(name).map_err(|_| "non-portable qcow dependency")?;
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\', ':', '\0']) {
        return Err("qcow dependency is not a portable basename".into());
    }
    Ok((size, Some(name)))
}

pub(super) fn relative(path: &Path, root: &Path) -> Result<PathBuf, String> {
    let path = path
        .strip_prefix(root)
        .map_err(|_| "legacy selection escapes its disk resource")?;
    if path
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err("legacy selection has invalid path components".into());
    }
    Ok(path.into())
}

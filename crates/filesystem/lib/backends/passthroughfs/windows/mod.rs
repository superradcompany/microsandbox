//! Windows passthrough filesystem backend.
//!
//! This backend is owned by microsandbox and is used instead of libkrun's
//! platform passthrough implementation. It exposes a host directory through
//! virtio-fs while keeping guest metadata private and rejecting Windows path
//! features that could escape the mount root.

use std::collections::BTreeMap;
use std::ffi::{CStr, OsString};
use std::fs::{File, FileTimes, OpenOptions as StdOpenOptions};
use std::io::{self, Read, Write};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::agentd::AGENTD_BYTES;
use crate::{
    Context, DirEntry, DynFileSystem, Entry, Extensions, FsOptions, GetxattrReply, ListxattrReply,
    OpenOptions, SetattrValid, ZeroCopyReader, ZeroCopyWriter, stat64, statvfs64,
};

mod builder;
mod create_ops;
mod dir_ops;
mod file_ops;
mod inode;
mod metadata;
mod ops;
mod remove_ops;
mod stat_store;

use inode::{DirHandle, HandleData, InodeData, InodeTable};

pub use builder::{HostPermissions, PassthroughConfig, StatVirtualization};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const ROOT_INODE: u64 = 1;
const INIT_INODE: u64 = 2;
const INIT_HANDLE: u64 = 0;
const INIT_NAME: &[u8] = b"init.krun";
const FALLBACK_METADATA_DIR_NAME: &str = ".msb_override_stat";
const METADATA_ROOT_NAME: &str = "__root";
const METADATA_STAT_NAME: &str = "stat.bin";
const ADS_STREAM_NAME: &str = "msb.override_stat";

const DT_UNKNOWN: u32 = 0;
const DT_FIFO: u32 = 1;
const DT_CHR: u32 = 2;
const DT_DIR: u32 = 4;
const DT_BLK: u32 = 6;
const DT_REG: u32 = 8;
const DT_LNK: u32 = 10;
const DT_SOCK: u32 = 12;

const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;
const S_IFIFO: u32 = 0o010000;
const S_IFCHR: u32 = 0o020000;
const S_IFBLK: u32 = 0o060000;
const S_IFSOCK: u32 = 0o140000;
const S_ISUID: u32 = 0o4000;
const S_ISGID: u32 = 0o2000;

const LINUX_EPERM: i32 = 1;
const LINUX_ENOENT: i32 = 2;
const LINUX_EIO: i32 = 5;
const LINUX_EBADF: i32 = 9;
const LINUX_EACCES: i32 = 13;
const LINUX_EBUSY: i32 = 16;
const LINUX_EEXIST: i32 = 17;
const LINUX_EXDEV: i32 = 18;
const LINUX_ENOTDIR: i32 = 20;
const LINUX_EISDIR: i32 = 21;
const LINUX_EINVAL: i32 = 22;
#[cfg(test)]
const LINUX_ENOSPC: i32 = 28;
const LINUX_EROFS: i32 = 30;
const LINUX_ENOTEMPTY: i32 = 39;
const LINUX_ELOOP: i32 = 40;
const LINUX_ENODATA: i32 = 61;
const LINUX_EOPNOTSUPP: i32 = 95;

const LINUX_O_ACCMODE: i32 = 0o3;
const LINUX_O_WRONLY: i32 = 0o1;
const LINUX_O_RDWR: i32 = 0o2;
const LINUX_O_CREAT: i32 = 0o100;
const LINUX_O_EXCL: i32 = 0o200;
const LINUX_O_TRUNC: i32 = 0o1000;
const LINUX_O_APPEND: i32 = 0o2000;

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const LINUX_O_DIRECTORY: i32 = 0x4000;
#[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
const LINUX_O_DIRECTORY: i32 = 0x10000;

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const LINUX_O_DIRECT: i32 = 0x10000;
#[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
const LINUX_O_DIRECT: i32 = 0x4000;

const LINUX_ACCESS_W_OK: u32 = 0o2;
const LINUX_ACCESS_X_OK: u32 = 0o1;
const LINUX_ACCESS_R_OK: u32 = 0o4;

const RENAME_NOREPLACE: u32 = 1;
const RENAME_EXCHANGE: u32 = 2;
const RENAME_WHITEOUT: u32 = 4;

const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_PATH_NOT_FOUND: i32 = 3;
const ERROR_ACCESS_DENIED: i32 = 5;
const ERROR_NOT_SAME_DEVICE: i32 = 17;
const ERROR_SHARING_VIOLATION: i32 = 32;
const ERROR_FILE_EXISTS: i32 = 80;
const ERROR_INVALID_NAME: i32 = 123;
const ERROR_DIR_NOT_EMPTY: i32 = 145;
const ERROR_ALREADY_EXISTS: i32 = 183;
const ERROR_PRIVILEGE_NOT_HELD: i32 = 1314;

const WINDOWS_TICKS_PER_SECOND: u64 = 10_000_000;
const WINDOWS_TO_UNIX_EPOCH_SECONDS: u64 = 11_644_473_600;
const OVERRIDE_VERSION: u8 = 1;
const OVERRIDE_SIZE: usize = std::mem::size_of::<OverrideStat>();

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Windows passthrough filesystem backend.
pub struct PassthroughFs {
    cfg: PassthroughConfig,
    root: PathBuf,
    inodes: RwLock<InodeTable>,
    next_inode: AtomicU64,
    handles: RwLock<BTreeMap<u64, Arc<HandleData>>>,
    dir_handles: RwLock<BTreeMap<u64, Arc<DirHandle>>>,
    next_handle: AtomicU64,
    init_file: Option<Mutex<File>>,
    stat_store: Option<StatStore>,
    quota: Option<super::quota::DirQuota>,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct OverrideStat {
    version: u8,
    _pad: [u8; 3],
    uid: u32,
    gid: u32,
    mode: u32,
    rdev: u32,
}

#[derive(Clone, Debug)]
struct StatStore {
    root: PathBuf,
    backend: StatStoreBackend,
}

#[derive(Clone, Debug)]
enum StatStoreBackend {
    AlternateDataStream,
    Sidecar { dir: PathBuf },
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PassthroughFs {
    /// Charge the quota for growing from `old_len` to `new_end` bytes.
    pub(super) fn quota_charge_growth(&self, old_len: u64, new_end: u64) -> io::Result<()> {
        if let Some(quota) = &self.quota {
            quota.charge(new_end.saturating_sub(old_len))?;
        }
        Ok(())
    }

    /// Charge the quota for growing an open file to `new_end` bytes.
    ///
    /// Used on create-like paths where the file was just created and the
    /// handle metadata is enough to determine growth before bytes are written.
    pub(super) fn quota_charge_file_to(&self, file: &File, new_end: u64) -> io::Result<()> {
        self.quota_charge_growth(super::quota::file_size(file), new_end)
    }

    /// Capture the quota baseline now if it has not been captured yet.
    ///
    /// The first write-intent operation pays the one-time directory walk so
    /// pre-existing host files become baseline instead of guest growth.
    pub(super) fn quota_ensure_baseline(&self) {
        if let Some(quota) = &self.quota {
            quota.ensure_baseline();
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn validate_component(name: &CStr) -> io::Result<&str> {
    let component = name.to_str().map_err(|_| linux_error(LINUX_EINVAL))?;
    if component.is_empty()
        || component == "."
        || component == ".."
        || component.contains('/')
        || component.contains('\\')
        || component.contains(':')
        || is_reserved_name(component)
    {
        return Err(linux_error(LINUX_EPERM));
    }

    Ok(component)
}

fn is_reserved_name(component: &str) -> bool {
    component.eq_ignore_ascii_case(FALLBACK_METADATA_DIR_NAME)
}

fn ensure_lexically_under_root(root: &Path, path: &Path) -> io::Result<()> {
    if path.starts_with(root) {
        Ok(())
    } else {
        Err(linux_error(LINUX_EACCES))
    }
}

fn safe_metadata_under_root(root: &Path, path: &Path) -> io::Result<std::fs::Metadata> {
    ensure_lexically_under_root(root, path)?;
    let relative = path
        .strip_prefix(root)
        .map_err(|_| linux_error(LINUX_EACCES))?;
    let mut cursor = root.to_path_buf();
    reject_reparse_metadata(&std::fs::symlink_metadata(&cursor).map_err(host_error)?)?;

    for component in relative.components() {
        match component {
            Component::Normal(part) => {
                if part.to_str().is_some_and(is_reserved_name) {
                    return Err(linux_error(LINUX_EPERM));
                }
                cursor.push(part);
                let metadata = std::fs::symlink_metadata(&cursor).map_err(host_error)?;
                reject_reparse_metadata(&metadata)?;
            }
            Component::CurDir => {}
            _ => return Err(linux_error(LINUX_EACCES)),
        }
    }

    std::fs::symlink_metadata(path).map_err(host_error)
}

fn reject_reparse_metadata(metadata: &std::fs::Metadata) -> io::Result<()> {
    if metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        Err(linux_error(LINUX_ELOOP))
    } else {
        Ok(())
    }
}

fn open_options_from_flags(flags: u32, create: bool) -> io::Result<StdOpenOptions> {
    let flags = flags as i32;
    if flags & LINUX_O_DIRECT != 0 {
        return Err(linux_error(LINUX_EOPNOTSUPP));
    }
    if !create && flags & (LINUX_O_CREAT | LINUX_O_EXCL) != 0 {
        return Err(linux_error(LINUX_EINVAL));
    }
    if flags & LINUX_O_DIRECTORY != 0 {
        return Err(linux_error(LINUX_EISDIR));
    }

    let accmode = flags & LINUX_O_ACCMODE;
    let mut options = StdOpenOptions::new();
    match accmode {
        0 => {
            options.read(true);
        }
        LINUX_O_WRONLY => {
            options.write(true);
        }
        LINUX_O_RDWR => {
            options.read(true).write(true);
        }
        _ => return Err(linux_error(LINUX_EINVAL)),
    }

    if flags & LINUX_O_APPEND != 0 {
        options.append(true);
    }
    if flags & LINUX_O_TRUNC != 0 {
        if accmode == 0 {
            return Err(linux_error(LINUX_EACCES));
        }
        options.truncate(true);
    }
    if create {
        if flags & LINUX_O_EXCL != 0 {
            options.create_new(true);
        } else {
            options.create(true);
        }
    }
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS);

    Ok(options)
}

fn open_flags_readable(flags: u32) -> bool {
    let accmode = flags as i32 & LINUX_O_ACCMODE;
    accmode == 0 || accmode == LINUX_O_RDWR
}

fn open_flags_writable(flags: u32) -> bool {
    let accmode = flags as i32 & LINUX_O_ACCMODE;
    accmode == LINUX_O_WRONLY || accmode == LINUX_O_RDWR || flags as i32 & LINUX_O_APPEND != 0
}

fn open_flags_write(flags: u32) -> bool {
    open_flags_writable(flags) || flags as i32 & (LINUX_O_TRUNC | LINUX_O_CREAT) != 0
}

fn stat_from_metadata(metadata: &std::fs::Metadata, data: &InodeData) -> stat64 {
    let mut st = host_stat_from_metadata(metadata, data.inode);
    let virtual_meta = data.virtual_meta.read().unwrap();
    st.st_uid = virtual_meta.uid;
    st.st_gid = virtual_meta.gid;
    st.st_mode = virtual_meta
        .mode
        .unwrap_or_else(|| mode_from_metadata(metadata));
    st.st_rdev = virtual_meta.rdev;
    st
}

fn host_stat_from_metadata(metadata: &std::fs::Metadata, inode: u64) -> stat64 {
    let (atime, atime_nsec) = filetime_to_unix(metadata.last_access_time());
    let (mtime, mtime_nsec) = filetime_to_unix(metadata.last_write_time());
    let (ctime, ctime_nsec) = filetime_to_unix(metadata.creation_time());

    stat64 {
        st_ino: inode,
        st_size: metadata.file_size() as i64,
        st_blocks: blocks_for_size(metadata.file_size()),
        st_atime: atime,
        st_mtime: mtime,
        st_ctime: ctime,
        st_atime_nsec: atime_nsec,
        st_mtime_nsec: mtime_nsec,
        st_ctime_nsec: ctime_nsec,
        st_mode: mode_from_metadata(metadata),
        st_nlink: 1,
        st_uid: 0,
        st_gid: 0,
        st_rdev: 0,
        st_blksize: 4096,
    }
}

fn apply_override_stat(st: &mut stat64, override_stat: OverrideStat) {
    st.st_uid = override_stat.uid;
    st.st_gid = override_stat.gid;
    st.st_mode = override_stat.mode;
    st.st_rdev = u64::from(override_stat.rdev);
}

fn check_access(ctx: Context, st: &stat64, mask: u32) -> io::Result<()> {
    if mask == 0 {
        return Ok(());
    }

    let mode = st.st_mode;
    if ctx.uid == 0 {
        if mask & LINUX_ACCESS_X_OK != 0 && mode & 0o111 == 0 {
            return Err(linux_error(LINUX_EACCES));
        }
        return Ok(());
    }

    let bits = if st.st_uid == ctx.uid {
        (mode >> 6) & 0o7
    } else if st.st_gid == ctx.gid {
        (mode >> 3) & 0o7
    } else {
        mode & 0o7
    };

    if mask & LINUX_ACCESS_R_OK != 0 && bits & 0o4 == 0 {
        return Err(linux_error(LINUX_EACCES));
    }
    if mask & LINUX_ACCESS_W_OK != 0 && bits & 0o2 == 0 {
        return Err(linux_error(LINUX_EACCES));
    }
    if mask & LINUX_ACCESS_X_OK != 0 && bits & 0o1 == 0 {
        return Err(linux_error(LINUX_EACCES));
    }

    Ok(())
}

fn build_file_times(attr: stat64, valid: SetattrValid) -> io::Result<FileTimes> {
    let mut times = FileTimes::new();
    if valid.contains(SetattrValid::ATIME_NOW) {
        times = times.set_accessed(SystemTime::now());
    } else if valid.contains(SetattrValid::ATIME) {
        times = times.set_accessed(system_time_from_unix(attr.st_atime, attr.st_atime_nsec)?);
    }

    if valid.contains(SetattrValid::MTIME_NOW) {
        times = times.set_modified(SystemTime::now());
    } else if valid.contains(SetattrValid::MTIME) {
        times = times.set_modified(system_time_from_unix(attr.st_mtime, attr.st_mtime_nsec)?);
    }

    Ok(times)
}

fn system_time_from_unix(seconds: i64, nanos: i64) -> io::Result<SystemTime> {
    if seconds < 0 || !(0..1_000_000_000).contains(&nanos) {
        return Err(linux_error(LINUX_EINVAL));
    }

    Ok(UNIX_EPOCH + Duration::new(seconds as u64, nanos as u32))
}

fn apply_host_permissions(path: &Path, mode: u32) -> io::Result<()> {
    let mut permissions = std::fs::metadata(path).map_err(host_error)?.permissions();
    permissions.set_readonly(mode & 0o222 == 0);
    std::fs::set_permissions(path, permissions).map_err(host_error)
}

fn mirror_eligible_type(file_type: u32) -> bool {
    file_type == S_IFREG || file_type == S_IFDIR
}

fn read_override_stream(path: &Path) -> io::Result<OverrideStat> {
    let mut file = StdOpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .map_err(host_error)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(host_error)?;
    OverrideStat::from_bytes(&bytes)
}

fn write_override_stream(path: &Path, override_stat: OverrideStat) -> io::Result<()> {
    let mut file = StdOpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .map_err(host_error)?;
    file.write_all(&override_stat.as_bytes())
        .map_err(host_error)?;
    file.sync_data().map_err(host_error)
}

fn read_override_sidecar_file(path: &Path) -> io::Result<OverrideStat> {
    let bytes = std::fs::read(path).map_err(host_error)?;
    OverrideStat::from_bytes(&bytes)
}

fn write_override_sidecar_file(path: &Path, override_stat: OverrideStat) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| linux_error(LINUX_EINVAL))?;
    std::fs::create_dir_all(parent).map_err(host_error)?;

    let mut temp = parent.to_path_buf();
    temp.push(format!("{}.tmp-{}", METADATA_STAT_NAME, unique_suffix()));
    {
        let mut file = StdOpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&temp)
            .map_err(host_error)?;
        file.write_all(&override_stat.as_bytes())
            .map_err(host_error)?;
        file.sync_data().map_err(host_error)?;
    }

    if path.exists() {
        std::fs::remove_file(path).map_err(host_error)?;
    }

    if let Err(error) = std::fs::rename(&temp, path) {
        let _ = std::fs::remove_file(&temp);
        return Err(host_error(error));
    }

    Ok(())
}

fn ads_override_path(path: &Path) -> PathBuf {
    let mut encoded: Vec<u16> = path.as_os_str().encode_wide().collect();
    encoded.push(b':' as u16);
    encoded.extend(ADS_STREAM_NAME.encode_utf16());
    PathBuf::from(OsString::from_wide(&encoded))
}

fn encode_metadata_component(component: &std::ffi::OsStr) -> String {
    let mut encoded = String::new();
    for unit in component.encode_wide() {
        encoded.push(hex_digit(((unit >> 12) & 0xf) as u8));
        encoded.push(hex_digit(((unit >> 8) & 0xf) as u8));
        encoded.push(hex_digit(((unit >> 4) & 0xf) as u8));
        encoded.push(hex_digit((unit & 0xf) as u8));
    }
    encoded
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        _ => (b'a' + value - 10) as char,
    }
}

fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("{}-{nanos}", std::process::id())
}

fn init_entry(entry_timeout: Duration, attr_timeout: Duration) -> Entry {
    Entry {
        inode: INIT_INODE,
        generation: 0,
        attr: init_stat(),
        attr_flags: 0,
        attr_timeout,
        entry_timeout,
    }
}

fn init_stat() -> stat64 {
    stat64 {
        st_ino: INIT_INODE,
        st_size: AGENTD_BYTES.len() as i64,
        st_blocks: blocks_for_size(AGENTD_BYTES.len() as u64),
        st_mode: S_IFREG | 0o755,
        st_nlink: 1,
        st_uid: 0,
        st_gid: 0,
        st_blksize: 4096,
        ..Default::default()
    }
}

fn mode_from_metadata(metadata: &std::fs::Metadata) -> u32 {
    let type_bits = if metadata.file_type().is_dir() {
        S_IFDIR
    } else if metadata.file_type().is_file() {
        S_IFREG
    } else {
        0
    };

    // NTFS has no Unix execute bit, so synthesize a default mode for files
    // that have no virtual override yet. Default to executable (matching
    // libkrun's own Windows fs passthrough and WSL DrvFs's no-metadata
    // behavior) so binaries on a bind mount or bind rootfs can run: without
    // this, every host file is exposed as 0o666 and the guest cannot exec
    // anything before it has a chance to chmod it. Precise per-file modes
    // still come from the virtual stat store once the guest sets them.
    let perms = if metadata.file_attributes() & FILE_ATTRIBUTE_READONLY != 0 {
        0o555
    } else {
        0o777
    };
    type_bits | perms
}

fn dirent_type_from_mode(mode: u32) -> u32 {
    match mode & S_IFMT {
        S_IFIFO => DT_FIFO,
        S_IFCHR => DT_CHR,
        S_IFDIR => DT_DIR,
        S_IFBLK => DT_BLK,
        S_IFREG => DT_REG,
        S_IFLNK => DT_LNK,
        S_IFSOCK => DT_SOCK,
        _ => DT_UNKNOWN,
    }
}

fn blocks_for_size(size: u64) -> i64 {
    size.div_ceil(512).try_into().unwrap_or(i64::MAX)
}

fn filetime_to_unix(filetime: u64) -> (i64, i64) {
    let seconds = filetime / WINDOWS_TICKS_PER_SECOND;
    if seconds < WINDOWS_TO_UNIX_EPOCH_SECONDS {
        return (0, 0);
    }

    let unix_seconds = seconds - WINDOWS_TO_UNIX_EPOCH_SECONDS;
    let nanos = (filetime % WINDOWS_TICKS_PER_SECOND) * 100;
    (
        unix_seconds.try_into().unwrap_or(i64::MAX),
        nanos.try_into().unwrap_or(i64::MAX),
    )
}

fn leak_name(name: &[u8]) -> &'static [u8] {
    Box::leak(name.to_vec().into_boxed_slice())
}

fn host_error(error: io::Error) -> io::Error {
    let errno = match error.raw_os_error() {
        Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) => LINUX_ENOENT,
        Some(ERROR_ACCESS_DENIED | ERROR_PRIVILEGE_NOT_HELD) => LINUX_EACCES,
        Some(ERROR_ALREADY_EXISTS | ERROR_FILE_EXISTS) => LINUX_EEXIST,
        Some(ERROR_DIR_NOT_EMPTY) => LINUX_ENOTEMPTY,
        Some(ERROR_SHARING_VIOLATION) => LINUX_EBUSY,
        Some(ERROR_INVALID_NAME) => LINUX_EINVAL,
        Some(ERROR_NOT_SAME_DEVICE) => LINUX_EXDEV,
        _ => match error.kind() {
            io::ErrorKind::NotFound => LINUX_ENOENT,
            io::ErrorKind::PermissionDenied => LINUX_EACCES,
            io::ErrorKind::AlreadyExists => LINUX_EEXIST,
            io::ErrorKind::InvalidInput => LINUX_EINVAL,
            io::ErrorKind::Unsupported => LINUX_EOPNOTSUPP,
            _ => LINUX_EIO,
        },
    };

    linux_error(errno)
}

fn linux_error(errno: i32) -> io::Error {
    io::Error::from_raw_os_error(errno)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests;

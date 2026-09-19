//! Unix metadata and pinned-file operations for owned directory generations.

use std::{
    ffi::{CString, OsString},
    fs::{self, File, OpenOptions},
    io,
    os::{
        fd::AsRawFd,
        unix::{
            ffi::{OsStrExt, OsStringExt},
            fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::Path,
};

use serde::{Deserialize, Serialize};

use super::invalid;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const MAX_XATTR_BYTES: usize = 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(super) type FileIdentity = (u64, u64);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct ObjectMetadata {
    mode: u32,
    accessed: (i64, i64),
    modified: (i64, i64),
    xattrs: Vec<(Vec<u8>, Vec<u8>)>,
    symlink: bool,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn open_nofollow(path: &Path, directory: bool) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(
            libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | if directory {
                    libc::O_DIRECTORY
                } else {
                    libc::O_NONBLOCK
                },
        )
        .open(path)
}

pub(super) fn file_identity(_file: &File, metadata: &fs::Metadata) -> io::Result<FileIdentity> {
    Ok((metadata.dev(), metadata.ino()))
}

pub(super) fn symlink_identity(metadata: &fs::Metadata) -> io::Result<FileIdentity> {
    // The caller used lstat, so this identifies the link itself rather than its target.
    Ok((metadata.dev(), metadata.ino()))
}

pub(super) fn stamp(file: &File) -> io::Result<(u64, u64, u64, i64, i64, i64, i64)> {
    let metadata = file.metadata()?;
    Ok((
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    ))
}

pub(super) fn path_bytes(path: &Path) -> io::Result<Vec<u8>> {
    Ok(path.as_os_str().as_bytes().to_vec())
}

pub(super) fn component(bytes: &[u8]) -> io::Result<OsString> {
    Ok(OsString::from_vec(bytes.to_vec()))
}

pub(super) fn skip_entry(_name: &std::ffi::OsStr) -> bool {
    false
}

pub(super) fn symlink(target: &[u8], destination: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(OsString::from_vec(target.to_vec()), destination)
}

pub(super) fn hardlink(source: &Path, destination: &Path) -> io::Result<()> {
    let source = CString::new(source.as_os_str().as_bytes()).map_err(invalid)?;
    let destination = CString::new(destination.as_os_str().as_bytes()).map_err(invalid)?;
    // Explicit flags=0 preserves a symlink inode. Never follow a target that may name
    // an unrelated guest path or lie outside this privately constructed namespace.
    if unsafe {
        libc::linkat(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            0,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn file_metadata(
    file: &File,
    _root: &Path,
    _path: Option<&Path>,
) -> io::Result<ObjectMetadata> {
    let metadata = file.metadata()?;
    let xattrs = read_xattrs(file.as_raw_fd(), None)?;
    // Virtual special files are ordinary host files with an override type. Existing live
    // passthrough checkpoints do not reconstruct special sessions, so refuse them explicitly.
    if let Some((_, bytes)) = xattrs
        .iter()
        .find(|(name, _)| name == b"user.msb.override_stat")
    {
        if bytes.len() != 20 || bytes[0] != 1 {
            return Err(invalid("invalid guest metadata overlay"));
        }
        let mode = u32::from_ne_bytes(bytes[12..16].try_into().unwrap()) & 0o170000;
        if !matches!(mode, 0o100000 | 0o040000 | 0o120000) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "owned checkpoint cannot capture virtual special objects",
            ));
        }
    }
    Ok(metadata_value(&metadata, xattrs, false))
}

pub(super) fn path_metadata(
    _root: &Path,
    path: &Path,
    symlink: bool,
) -> io::Result<ObjectMetadata> {
    let metadata = fs::symlink_metadata(path)?;
    let path = CString::new(path.as_os_str().as_bytes()).map_err(invalid)?;
    Ok(metadata_value(
        &metadata,
        read_xattrs(-1, Some(&path))?,
        symlink,
    ))
}

fn metadata_value(
    metadata: &fs::Metadata,
    xattrs: Vec<(Vec<u8>, Vec<u8>)>,
    symlink: bool,
) -> ObjectMetadata {
    ObjectMetadata {
        mode: metadata.mode() & 0o777,
        accessed: (metadata.atime(), metadata.atime_nsec()),
        modified: (metadata.mtime(), metadata.mtime_nsec()),
        xattrs,
        symlink,
    }
}

pub(super) fn validate_alias_metadata(_: &ObjectMetadata, _: &ObjectMetadata) -> io::Result<()> {
    // Unix xattrs are inode-scoped, so aliases cannot have divergent guest overlays.
    Ok(())
}

pub(super) fn validate_metadata(metadata: &ObjectMetadata) -> io::Result<()> {
    if metadata.mode & !0o777 != 0
        || !(0..1_000_000_000).contains(&metadata.accessed.1)
        || !(0..1_000_000_000).contains(&metadata.modified.1)
    {
        return Err(invalid("invalid owned metadata"));
    }
    let mut names = std::collections::BTreeSet::new();
    for (name, value) in &metadata.xattrs {
        if name.is_empty()
            || name.contains(&0)
            || name.len() > 255
            || !portable_xattr(name)
            || value.len() > MAX_XATTR_BYTES
            || !names.insert(name)
        {
            return Err(invalid("unsupported or invalid owned xattr"));
        }
        if name == b"user.msb.override_stat" {
            if value.len() != 20 || value[0] != 1 {
                return Err(invalid("invalid owned guest metadata overlay"));
            }
            let mode = u32::from_ne_bytes(value[12..16].try_into().unwrap()) & 0o170000;
            if !matches!(mode, 0o100000 | 0o040000 | 0o120000) {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "owned checkpoint cannot restore virtual special objects",
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn apply_metadata(
    _root: &Path,
    path: &Path,
    metadata: &ObjectMetadata,
) -> io::Result<()> {
    validate_metadata(metadata)?;
    if fs::symlink_metadata(path)?.is_symlink() != metadata.symlink {
        return Err(invalid(
            "owned metadata object kind differs from destination",
        ));
    }
    let cpath = CString::new(path.as_os_str().as_bytes()).map_err(invalid)?;
    if !metadata.symlink {
        // Imported metadata must never remove the service's access or set host privilege bits.
        let is_directory = fs::symlink_metadata(path)?.is_dir();
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(metadata.mode | if is_directory { 0o700 } else { 0o600 }),
        )?;
    }
    for (name, bytes) in &metadata.xattrs {
        let name = CString::new(name.as_slice()).map_err(invalid)?;
        #[cfg(target_os = "linux")]
        let result = unsafe {
            libc::lsetxattr(
                cpath.as_ptr(),
                name.as_ptr(),
                bytes.as_ptr().cast(),
                bytes.len(),
                0,
            )
        };
        #[cfg(target_os = "macos")]
        let result = unsafe {
            libc::setxattr(
                cpath.as_ptr(),
                name.as_ptr(),
                bytes.as_ptr().cast(),
                bytes.len(),
                0,
                libc::XATTR_NOFOLLOW,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let times = [
        libc::timespec {
            tv_sec: metadata.accessed.0 as _,
            tv_nsec: metadata.accessed.1 as _,
        },
        libc::timespec {
            tv_sec: metadata.modified.0 as _,
            tv_nsec: metadata.modified.1 as _,
        },
    ];
    if unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            cpath.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn set_guest_metadata(
    metadata: &mut ObjectMetadata,
    uid: u32,
    gid: u32,
    mode: u32,
    rdev: u32,
) -> io::Result<()> {
    if metadata.symlink {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "cannot attach portable guest metadata to a host symlink",
        ));
    }
    let mut bytes = vec![1, 0, 0, 0];
    for value in [uid, gid, mode, rdev] {
        bytes.extend_from_slice(&value.to_ne_bytes());
    }
    metadata
        .xattrs
        .retain(|(name, _)| name != b"user.msb.override_stat");
    metadata
        .xattrs
        .push((b"user.msb.override_stat".to_vec(), bytes));
    metadata.xattrs.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(())
}

pub(super) fn copy_detached(source: &File, destination: &Path) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        let path = CString::new(destination.as_os_str().as_bytes()).map_err(invalid)?;
        if unsafe { libc::fclonefileat(source.as_raw_fd(), libc::AT_FDCWD, path.as_ptr(), 0) } == 0
        {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if !matches!(
            error.raw_os_error(),
            Some(libc::ENOTSUP | libc::EXDEV | libc::EINVAL | libc::ENOSYS)
        ) {
            return Err(error);
        }
    }
    let destination = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)?;
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::ioctl(destination.as_raw_fd(), libc::FICLONE, source.as_raw_fd()) } == 0 {
            return destination.sync_all();
        }
        let error = io::Error::last_os_error();
        if !matches!(
            error.raw_os_error(),
            Some(libc::EOPNOTSUPP | libc::EXDEV | libc::EINVAL | libc::ENOTTY | libc::ENOSYS)
        ) {
            return Err(error);
        }
    }
    let length = source.metadata()?.len();
    destination.set_len(length)?;
    // Positional reads leave the source's open-file offset untouched. Skipping zero chunks
    // preserves holes even when the platform cannot reflink an unlinked source descriptor.
    let mut buffer = vec![0; 1024 * 1024];
    let mut offset = 0;
    while offset < length {
        let size = buffer.len().min((length - offset) as usize);
        source.read_exact_at(&mut buffer[..size], offset)?;
        for (index, chunk) in buffer[..size].chunks(4096).enumerate() {
            if chunk.iter().any(|byte| *byte != 0) {
                destination.write_all_at(chunk, offset + (index * 4096) as u64)?;
            }
        }
        offset += size as u64;
    }
    destination.sync_all()
}

pub(super) fn clear_payload_metadata(path: &Path) -> io::Result<()> {
    let file = open_nofollow(path, false)?;
    for (name, _) in read_xattrs(file.as_raw_fd(), None)? {
        let name = CString::new(name).map_err(invalid)?;
        #[cfg(target_os = "linux")]
        let result = unsafe { libc::fremovexattr(file.as_raw_fd(), name.as_ptr()) };
        #[cfg(target_os = "macos")]
        let result = unsafe { libc::fremovexattr(file.as_raw_fd(), name.as_ptr(), 0) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

fn read_xattrs(fd: i32, path: Option<&CString>) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let list = |buffer: *mut libc::c_char, size| {
        #[cfg(target_os = "linux")]
        unsafe {
            match path {
                Some(path) => libc::llistxattr(path.as_ptr(), buffer, size),
                None => libc::flistxattr(fd, buffer, size),
            }
        }
        #[cfg(target_os = "macos")]
        unsafe {
            match path {
                Some(path) => libc::listxattr(path.as_ptr(), buffer, size, libc::XATTR_NOFOLLOW),
                None => libc::flistxattr(fd, buffer, size, 0),
            }
        }
    };
    let count = list(std::ptr::null_mut(), 0);
    if count < 0 {
        let error = io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(libc::ENOTSUP)) {
            return Ok(Vec::new());
        }
        return Err(error);
    }
    if count as usize > MAX_XATTR_BYTES {
        return Err(invalid("owned xattr list is too large"));
    }
    let mut names = vec![0; count as usize];
    if count != 0 && list(names.as_mut_ptr().cast(), names.len()) != count {
        return Err(invalid("owned xattrs changed while capturing"));
    }
    let mut output = Vec::new();
    for name in names
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
    {
        // Host security labels and platform services do not belong to guest-owned metadata.
        // Refuse unknown namespaces rather than silently losing guest-requested attributes.
        #[cfg(target_os = "macos")]
        if matches!(
            name,
            b"com.apple.provenance" | b"com.apple.quarantine" | b"com.apple.macl"
        ) {
            continue;
        }
        if !portable_xattr(name) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "owned checkpoint cannot transport host security xattr {}",
                    String::from_utf8_lossy(name)
                ),
            ));
        }
        let c_name = CString::new(name).map_err(invalid)?;
        let get = |buffer: *mut libc::c_void, size| {
            #[cfg(target_os = "linux")]
            unsafe {
                match path {
                    Some(path) => libc::lgetxattr(path.as_ptr(), c_name.as_ptr(), buffer, size),
                    None => libc::fgetxattr(fd, c_name.as_ptr(), buffer, size),
                }
            }
            #[cfg(target_os = "macos")]
            unsafe {
                match path {
                    Some(path) => libc::getxattr(
                        path.as_ptr(),
                        c_name.as_ptr(),
                        buffer,
                        size,
                        0,
                        libc::XATTR_NOFOLLOW,
                    ),
                    None => libc::fgetxattr(fd, c_name.as_ptr(), buffer, size, 0, 0),
                }
            }
        };
        let size = get(std::ptr::null_mut(), 0);
        if size < 0 {
            return Err(io::Error::last_os_error());
        }
        if size as usize > MAX_XATTR_BYTES {
            return Err(invalid("owned xattr value is too large"));
        }
        let mut value = vec![0; size as usize];
        if get(value.as_mut_ptr().cast(), value.len()) != size {
            return Err(invalid("owned xattr changed while capturing"));
        }
        output.push((name.to_vec(), value));
    }
    output.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(output)
}

fn portable_xattr(name: &[u8]) -> bool {
    #[cfg(target_os = "linux")]
    {
        name.starts_with(b"user.")
    }
    #[cfg(target_os = "macos")]
    {
        !matches!(
            name,
            b"com.apple.provenance" | b"com.apple.quarantine" | b"com.apple.macl"
        )
    }
}

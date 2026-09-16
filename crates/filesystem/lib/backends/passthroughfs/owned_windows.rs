//! Windows owned generations use pinned handles and the backend's virtual metadata store.

use std::{
    ffi::{OsStr, OsString},
    fs::{File, FileTimes, Metadata, OpenOptions},
    io,
    os::windows::{
        fs::{FileExt, MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use windows_sys::Win32::{
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_BASIC_INFO, FileBasicInfo, GetFileInformationByHandle,
        GetFileInformationByHandleEx,
    },
    System::IO::DeviceIoControl,
};

use super::super::windows;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const OPEN_NOFOLLOW: u32 = 0x0020_0000 | 0x0200_0000;
const REPARSE_POINT: u32 = 0x400;
const FSCTL_SET_SPARSE: u32 = 0x0009_00c4;
const FSCTL_DUPLICATE_EXTENTS_TO_FILE: u32 = 0x0009_8344;
const CLONE_ALIGNMENT: u64 = 64 * 1024;
const MAX_CLONE_BYTES: u64 = 1024 * 1024 * 1024;
const WINDOWS_UNIX_EPOCH: u64 = 116_444_736_000_000_000;
const FILE_READ_WRITE_ATTRIBUTES: u32 = 0x80 | 0x100;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(super) type FileIdentity = (u64, u64);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct ObjectMetadata {
    accessed: u64,
    modified: u64,
    readonly: bool,
    // Guest uid/gid/mode/rdev, never host Windows ACLs.
    guest: Option<[u32; 4]>,
}

// The documented DUPLICATE_EXTENTS_DATA ABI; keeping the source HANDLE here avoids
// reopening its removed/replaced path when ReFS can share immutable storage blocks.
#[repr(C)]
struct DuplicateExtents {
    file_handle: windows_sys::Win32::Foundation::HANDLE,
    source_offset: i64,
    target_offset: i64,
    bytes: i64,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn open_nofollow(path: &Path, directory: bool) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(OPEN_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if metadata.file_attributes() & REPARSE_POINT != 0 || metadata.is_dir() != directory {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "owned generation encountered a reparse point or changed object type",
        ));
    }
    Ok(file)
}

pub(super) fn file_identity(file: &File, _: &Metadata) -> io::Result<FileIdentity> {
    let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let info = unsafe { info.assume_init() };
    Ok((
        u64::from(info.dwVolumeSerialNumber),
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    ))
}

pub(super) fn symlink_identity(_: &Metadata) -> io::Result<FileIdentity> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native Windows reparse points cannot appear in an owned generation",
    ))
}

pub(super) fn hardlink(source: &Path, destination: &Path) -> io::Result<()> {
    // Guest symlinks are ordinary host files with virtual type metadata on Windows.
    std::fs::hard_link(source, destination)
}

pub(super) fn stamp(file: &File) -> io::Result<(FileIdentity, u64, i64, i64)> {
    let mut basic = std::mem::MaybeUninit::<FILE_BASIC_INFO>::zeroed();
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileBasicInfo,
            basic.as_mut_ptr().cast(),
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let basic = unsafe { basic.assume_init() };
    let metadata = file.metadata()?;
    Ok((
        file_identity(file, &metadata)?,
        metadata.len(),
        basic.LastWriteTime,
        basic.ChangeTime,
    ))
}

pub(super) fn path_bytes(path: &Path) -> io::Result<Vec<u8>> {
    path.to_str()
        .map(|name| name.as_bytes().to_vec())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "owned Windows path is not UTF-8",
            )
        })
}

pub(super) fn component(bytes: &[u8]) -> io::Result<OsString> {
    windows::owned_component(
        std::str::from_utf8(bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
    )
}

pub(super) fn skip_entry(name: &OsStr) -> bool {
    name.to_str()
        .is_some_and(|name| name.eq_ignore_ascii_case(".msb_override_stat"))
}

pub(super) fn symlink(_: &[u8], _: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native Windows reparse points cannot appear in an owned generation",
    ))
}

pub(super) fn file_metadata(
    file: &File,
    root: &Path,
    path: Option<&Path>,
) -> io::Result<ObjectMetadata> {
    let host = file.metadata()?;
    let meta = ObjectMetadata {
        accessed: host.last_access_time(),
        modified: host.last_write_time(),
        readonly: host.permissions().readonly(),
        guest: path
            .map(|path| windows::capture_owned_metadata(root, path))
            .transpose()?
            .flatten(),
    };
    validate_metadata(&meta)?;
    Ok(meta)
}

pub(super) fn path_metadata(
    root: &Path,
    path: &Path,
    is_symlink: bool,
) -> io::Result<ObjectMetadata> {
    if is_symlink {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "owned Windows native symlinks are unsupported",
        ));
    }
    file_metadata(
        &open_nofollow(path, std::fs::symlink_metadata(path)?.is_dir())?,
        root,
        Some(path),
    )
}

pub(super) fn validate_metadata(meta: &ObjectMetadata) -> io::Result<()> {
    if let Some([_, _, mode, rdev]) = meta.guest
        && (!matches!(mode & 0o170000, 0o100000 | 0o040000 | 0o120000) || rdev != 0)
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "owned Windows generation contains unsupported guest special-file metadata",
        ));
    }
    windows_time(meta.accessed)?;
    windows_time(meta.modified)?;
    Ok(())
}

pub(super) fn set_guest_metadata(
    meta: &mut ObjectMetadata,
    uid: u32,
    gid: u32,
    mode: u32,
    rdev: u32,
) -> io::Result<()> {
    meta.guest = Some([uid, gid, mode, rdev]);
    validate_metadata(meta)
}

pub(super) fn validate_alias_metadata(
    first: &ObjectMetadata,
    alias: &ObjectMetadata,
) -> io::Result<()> {
    if first.guest != alias.guest {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "owned hardlink aliases have inconsistent guest metadata",
        ));
    }
    Ok(())
}

// Windows readonly is a DOS attribute, not Unix permissions.
#[allow(clippy::permissions_set_readonly_false)]
pub(super) fn apply_metadata(root: &Path, path: &Path, meta: &ObjectMetadata) -> io::Result<()> {
    validate_metadata(meta)?;
    let file = OpenOptions::new()
        // Attribute-only access still works when another alias already restored readonly.
        // Never request permission to write data or modify the host security descriptor.
        .access_mode(FILE_READ_WRITE_ATTRIBUTES)
        .custom_flags(OPEN_NOFOLLOW)
        .open(path)?;
    let mut permissions = file.metadata()?.permissions();
    if permissions.readonly() {
        // A previous alias can have applied the shared readonly attribute already.
        // Temporarily lift that data attribute while restoring its metadata stream.
        permissions.set_readonly(false);
        file.set_permissions(permissions.clone())?;
    }
    if let Some(guest) = meta.guest {
        windows::restore_owned_metadata(root, path, guest)?;
    }
    file.set_times(
        FileTimes::new()
            .set_accessed(windows_time(meta.accessed)?)
            .set_modified(windows_time(meta.modified)?),
    )?;
    permissions.set_readonly(meta.readonly);
    file.set_permissions(permissions)
}

pub(super) fn clear_payload_metadata(path: &Path) -> io::Result<()> {
    windows::clear_owned_payload_metadata(path)
}

pub(super) fn copy_detached(source: &File, destination: &Path) -> io::Result<()> {
    let target = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(destination)?;
    let mut returned = 0;
    // Windows requires a sparse attribute before seeking across zero ranges preserves allocation.
    if unsafe {
        DeviceIoControl(
            target.as_raw_handle(),
            FSCTL_SET_SPARSE,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let size = source.metadata()?.len();
    target.set_len(size)?;
    let mut buffer = vec![0u8; 64 * 1024];
    let mut offset = clone_prefix(source, &target, size);
    while offset < size {
        let count = source.seek_read(
            &mut buffer[..((size - offset).min(64 * 1024) as usize)],
            offset,
        )?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "owned file changed during capture",
            ));
        }
        for (index, chunk) in buffer[..count].chunks(4096).enumerate() {
            if chunk.iter().all(|byte| *byte == 0) {
                continue;
            }
            let mut written = 0;
            while written < chunk.len() {
                let bytes = target
                    .seek_write(&chunk[written..], offset + (index * 4096 + written) as u64)?;
                if bytes == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "owned sparse copy made no progress",
                    ));
                }
                written += bytes;
            }
        }
        offset += count as u64;
    }
    target.sync_all()
}

fn clone_prefix(source: &File, target: &File, size: u64) -> u64 {
    let aligned = size / CLONE_ALIGNMENT * CLONE_ALIGNMENT;
    let mut offset = 0;
    while offset < aligned {
        let bytes = (aligned - offset).min(MAX_CLONE_BYTES);
        let (Ok(signed_offset), Ok(signed_bytes)) = (i64::try_from(offset), i64::try_from(bytes))
        else {
            break;
        };
        let request = DuplicateExtents {
            file_handle: source.as_raw_handle(),
            source_offset: signed_offset,
            target_offset: signed_offset,
            bytes: signed_bytes,
        };
        let mut returned = 0;
        let ok = unsafe {
            DeviceIoControl(
                target.as_raw_handle(),
                FSCTL_DUPLICATE_EXTENTS_TO_FILE,
                (&request as *const DuplicateExtents).cast(),
                std::mem::size_of::<DuplicateExtents>() as u32,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            // NTFS, cross-volume copies, unsupported integrity settings, and other
            // refusals take the byte-preserving sparse fallback from this offset.
            break;
        }
        offset += bytes;
    }
    offset
}

fn windows_time(ticks: u64) -> io::Result<SystemTime> {
    let delta = Duration::from_nanos(
        ticks
            .abs_diff(WINDOWS_UNIX_EPOCH)
            .checked_mul(100)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "owned Windows timestamp out of range",
                )
            })?,
    );
    (if ticks >= WINDOWS_UNIX_EPOCH {
        UNIX_EPOCH.checked_add(delta)
    } else {
        UNIX_EPOCH.checked_sub(delta)
    })
    .ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "owned Windows timestamp out of range",
        )
    })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::backends::passthroughfs::owned::OwnedDirectorySnapshot;
    use crate::{Context, DynFileSystem};

    #[test]
    fn owned_windows_namespace_is_private_and_preserves_guest_symlinks() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::create_dir(source.join("nested")).unwrap();
        let data = source.join("nested/data");
        fs::write(&data, b"initial").unwrap();
        fs::hard_link(&data, source.join("alias")).unwrap();
        windows::restore_owned_metadata(&source, &data, [42, 43, 0o100640, 0]).unwrap();

        // Windows guest symlinks are regular host files with a virtual S_IFLNK type.
        // They must not require Developer Mode or creating any native reparse point.
        let link = source.join("link");
        fs::write(&link, b"nested/data").unwrap();
        windows::restore_owned_metadata(&source, &link, [44, 45, 0o120777, 0]).unwrap();
        let generation = temporary.path().join("generation");
        let snapshot = OwnedDirectorySnapshot::capture(&source, &generation).unwrap();
        fs::remove_dir_all(&source).unwrap();
        let child = temporary.path().join("child");
        let sibling = temporary.path().join("sibling");
        snapshot.materialize(&generation, &child).unwrap();
        snapshot.materialize(&generation, &sibling).unwrap();
        let identity = |path: &Path| {
            let file = open_nofollow(path, false).unwrap();
            file_identity(&file, &file.metadata().unwrap()).unwrap()
        };
        assert_eq!(
            identity(&child.join("alias")),
            identity(&child.join("nested/data"))
        );
        assert_ne!(
            identity(&child.join("alias")),
            identity(&sibling.join("alias"))
        );
        fs::write(child.join("alias"), b"child").unwrap();
        assert_eq!(fs::read(child.join("nested/data")).unwrap(), b"child");
        assert_eq!(fs::read(sibling.join("alias")).unwrap(), b"initial");
        let backend = windows::PassthroughFs::new(windows::PassthroughConfig {
            root_dir: child.clone(),
            inject_init: false,
            ..Default::default()
        })
        .unwrap();
        let ctx = Context {
            uid: 0,
            gid: 0,
            pid: 0,
        };
        let entry = backend.lookup(ctx, 1, c"link").unwrap();
        assert_eq!(backend.readlink(ctx, entry.inode).unwrap(), b"nested/data");
        let (stat, _) = backend.getattr(ctx, entry.inode, None).unwrap();
        assert_eq!((stat.st_uid, stat.st_gid, stat.st_mode), (44, 45, 0o120777));
        assert!(fs::symlink_metadata(child.join("link")).unwrap().is_file());
    }

    #[test]
    fn owned_windows_sparse_copy_uses_pinned_source_without_changing_position() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&source)
            .unwrap();
        file.set_len(8 * 1024 * 1024).unwrap();
        file.seek_write(b"tail", 8 * 1024 * 1024 - 4).unwrap();
        let destination = temporary.path().join("destination");
        copy_detached(&file, &destination).unwrap();
        let output = open_nofollow(&destination, false).unwrap();
        assert_eq!(output.metadata().unwrap().len(), 8 * 1024 * 1024);
        assert_ne!(output.metadata().unwrap().file_attributes() & 0x200, 0);
        let mut tail = [0; 4];
        output.seek_read(&mut tail, 8 * 1024 * 1024 - 4).unwrap();
        assert_eq!(&tail, b"tail");
        let mut beginning = [1; 4];
        output.seek_read(&mut beginning, 0).unwrap();
        assert_eq!(beginning, [0; 4]);
    }

    #[test]
    fn owned_windows_metadata_can_be_reapplied_to_readonly_aliases() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("file");
        fs::write(&path, b"readonly").unwrap();
        let file = open_nofollow(&path, false).unwrap();
        let mut meta = file_metadata(&file, temporary.path(), Some(&path)).unwrap();
        meta.readonly = true;
        set_guest_metadata(&mut meta, 42, 43, 0o100400, 0).unwrap();
        apply_metadata(temporary.path(), &path, &meta).unwrap();
        apply_metadata(temporary.path(), &path, &meta).unwrap();
        assert!(fs::metadata(&path).unwrap().permissions().readonly());
        assert_eq!(
            windows::capture_owned_metadata(temporary.path(), &path).unwrap(),
            Some([42, 43, 0o100400, 0])
        );
        clear_payload_metadata(&path).unwrap();
    }
}

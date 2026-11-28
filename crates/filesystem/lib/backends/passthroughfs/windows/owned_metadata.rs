//! Conversion between owned-generation metadata and the Windows ADS/sidecar stat store.

use std::os::windows::{
    fs::FileExt,
    io::{AsRawHandle, FromRawHandle},
};

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_IF, FILE_OPEN_REPARSE_POINT,
    FILE_SYNCHRONOUS_IO_NONALERT, NTCREATEFILE_CREATE_DISPOSITION, NtCreateFile,
};
use windows_sys::Win32::Foundation::{
    ERROR_DELETE_PENDING, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError,
    STATUS_DELETE_PENDING, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, ExtendedFileIdType, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_ID_DESCRIPTOR, FILE_ID_DESCRIPTOR_0, FILE_ID_INFO,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FileIdInfo,
    GetFileInformationByHandle, GetFileInformationByHandleEx, OpenFileById,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use super::*;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// `IO_STATUS_BLOCK.Information` after NtCreateFile created the file.
const FILE_CREATED: usize = 2;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PassthroughFs {
    /// Report the host link count, including zero for an unlinked retained file.
    pub(super) fn stat_link_count(&self, mut stat: stat64, data: &InodeData) -> io::Result<stat64> {
        let file = if let Some(file) = data.retained.lock().unwrap().as_ref() {
            file.try_clone().map_err(host_error)?
        } else {
            StdOpenOptions::new()
                .access_mode(FILE_READ_ATTRIBUTES)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
                .open(data.path())
                .map_err(host_error)?
        };
        let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) } == 0 {
            return Err(host_error(io::Error::last_os_error()));
        }
        stat.st_nlink = unsafe { info.assume_init() }.nNumberOfLinks.into();
        Ok(stat)
    }

    /// Retain the inode-scoped metadata stream alongside an unlinked file,
    /// and return it with the metadata it holds. The stream is opened
    /// relative to `file`, which the caller has checked holds the inode's
    /// object, never by path: a host rename-over of the name would otherwise
    /// read, or create, the replacing file's stream. A file without a stream
    /// gets one holding `initial`.
    ///
    /// Returns `None` when the store does not follow the file, or when the
    /// file has no name left, so its metadata can only be kept in memory.
    pub(super) fn pin_owned_stat(
        &self,
        file: &File,
        initial: OverrideStat,
    ) -> io::Result<Option<(File, OverrideStat)>> {
        if !self.stat_follows_file() {
            return Ok(None);
        }

        // A handle opened through a name the host has since replaced can no
        // longer open the file's streams (they report delete pending), so
        // they are opened through a handle reopened by file ID, which no name
        // holds. Where that reopen is not available, such as a share without
        // open by ID, the checked handle itself is used; it then reports
        // delete pending only if the host replaced its name.
        let reopened = reopen_by_id(file).ok();
        let file = reopened.as_ref().unwrap_or(file);
        let access = if self.cfg.readonly {
            FILE_GENERIC_READ
        } else {
            FILE_GENERIC_READ | FILE_GENERIC_WRITE
        };
        match open_override_stream_at(file, access, FILE_OPEN) {
            Ok((stream, _)) => {
                let stat = read_stat_file(&stream)?;
                return Ok(Some((stream, stat)));
            }
            // The file has no name left: its metadata stays in memory.
            Err(error) if is_delete_pending(&error) => return Ok(None),
            Err(error) if error.kind() != io::ErrorKind::NotFound => {
                return Err(host_error(error));
            }
            Err(_) => {}
        }

        let (stream, created) = match open_override_stream_at(
            file,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            FILE_OPEN_IF,
        ) {
            Ok(opened) => opened,
            Err(error) if is_delete_pending(&error) => return Ok(None),
            Err(error) => return Err(host_error(error)),
        };
        let stat = if created {
            write_stat_file(&stream, initial)?;
            stream.sync_data().map_err(host_error)?;
            initial
        } else {
            read_stat_file(&stream)?
        };
        if self.cfg.readonly {
            return match open_override_stream_at(file, FILE_GENERIC_READ, FILE_OPEN) {
                Ok((stream, _)) => Ok(Some((stream, stat))),
                Err(error) if is_delete_pending(&error) => Ok(None),
                Err(error) => Err(host_error(error)),
            };
        }

        Ok(Some((stream, stat)))
    }

    /// Sidecar paths are not inode-scoped like ADS. Tracked hardlink aliases
    /// therefore receive the same virtual metadata explicitly.
    pub(super) fn propagate_sidecar_stat(
        &self,
        data: &InodeData,
        stat: OverrideStat,
    ) -> io::Result<()> {
        if !self
            .stat_store
            .as_ref()
            .is_some_and(|store| matches!(store.backend, StatStoreBackend::Sidecar { .. }))
        {
            return Ok(());
        }
        // Hardlink aliases share the logical inode. The path key, not the canonical path
        // stored in InodeData, selects each sidecar record. Never hold the table lock
        // during host metadata I/O.
        let aliases = self
            .inodes
            .read()
            .unwrap()
            .by_path
            .iter()
            .filter(|(_, alias)| alias.inode == data.inode)
            .map(|(path, alias)| (path.clone(), alias.clone()))
            .collect::<Vec<_>>();
        for (path, alias) in aliases {
            *alias.virtual_meta.write().unwrap() = inode::VirtualMetadata {
                uid: stat.uid,
                gid: stat.gid,
                mode: Some(stat.mode),
                rdev: u64::from(stat.rdev),
            };
            self.stat_store
                .as_ref()
                .expect("sidecar checked")
                .write(&path, stat.uid, stat.gid, stat.mode, stat.rdev)?;
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn read_retained_stat(data: &InodeData) -> io::Result<Option<OverrideStat>> {
    let retained = data.retained_stat.lock().unwrap();
    let Some(file) = retained.as_ref() else {
        return Ok(None);
    };

    read_stat_file(file).map(Some)
}

pub(super) fn write_retained_stat(data: &InodeData, stat: OverrideStat) -> io::Result<bool> {
    let retained = data.retained_stat.lock().unwrap();
    let Some(file) = retained.as_ref() else {
        return Ok(false);
    };

    write_stat_file(file, stat)?;
    Ok(true)
}

pub(in crate::backends::passthroughfs) fn owned_component(name: &str) -> io::Result<OsString> {
    // Win32 aliases trailing dots/spaces and device basenames, even with an extension.
    // Refuse them in imported inventories instead of materializing a different namespace.
    let basename = name.split('.').next().unwrap_or_default();
    let upper = basename.to_ascii_uppercase();
    let numbered_device = upper
        .strip_prefix("COM")
        .or_else(|| upper.strip_prefix("LPT"))
        .is_some_and(|suffix| {
            matches!(
                suffix,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        });
    if name.ends_with(['.', ' '])
        || name
            .chars()
            .any(|ch| ch.is_control() || "<>\"|?*".contains(ch))
        || matches!(
            upper.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        )
        || numbered_device
    {
        return Err(linux_error(LINUX_EINVAL));
    }
    let name = std::ffi::CString::new(name).map_err(|_| linux_error(LINUX_EINVAL))?;
    validate_component(&name).map(OsString::from)
}

pub(in crate::backends::passthroughfs) fn capture_owned_metadata(
    root: &Path,
    path: &Path,
) -> io::Result<Option<[u32; 4]>> {
    // Capture must not probe or mutate the source namespace or root streams.
    let ads = StatStore {
        root: root.to_path_buf(),
        backend: StatStoreBackend::AlternateDataStream,
    };
    let stored = if stat_store::volume_supports_named_streams(root)? {
        match ads.read(path)? {
            Some(value) => Some(value),
            None => StatStore::sidecar(root).read(path)?,
        }
    } else {
        StatStore::sidecar(root).read(path)?
    };
    Ok(stored.map(|stat| [stat.uid, stat.gid, stat.mode, stat.rdev]))
}

pub(in crate::backends::passthroughfs) fn restore_owned_metadata(
    root: &Path,
    path: &Path,
    guest: [u32; 4],
) -> io::Result<()> {
    let ads = StatStore {
        root: root.to_path_buf(),
        backend: StatStoreBackend::AlternateDataStream,
    };
    let [uid, gid, mode, rdev] = guest;
    if stat_store::volume_supports_named_streams(root)? {
        ads.write(path, uid, gid, mode, rdev)
    } else {
        StatStore::sidecar(root).write(path, uid, gid, mode, rdev)
    }
}

// Windows readonly is a DOS attribute, not Unix permissions.
#[allow(clippy::permissions_set_readonly_false)]
pub(in crate::backends::passthroughfs) fn clear_owned_payload_metadata(
    path: &Path,
) -> io::Result<()> {
    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_readonly(false);
    std::fs::set_permissions(path, permissions)?;
    if stat_store::volume_supports_named_streams(path)? {
        match std::fs::remove_file(ads_override_path(path)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn read_stat_file(file: &File) -> io::Result<OverrideStat> {
    let mut bytes = [0; OVERRIDE_SIZE];
    if file.metadata().map_err(host_error)?.len() != OVERRIDE_SIZE as u64 {
        return Err(linux_error(LINUX_EIO));
    }

    let mut offset = 0;
    while offset < bytes.len() {
        let read = file
            .seek_read(&mut bytes[offset..], offset as u64)
            .map_err(host_error)?;
        if read == 0 {
            return Err(linux_error(LINUX_EIO));
        }
        offset += read;
    }
    OverrideStat::from_bytes(&bytes)
}

fn write_stat_file(file: &File, stat: OverrideStat) -> io::Result<()> {
    let bytes = stat.as_bytes();
    let mut offset = 0;
    while offset < bytes.len() {
        let written = file
            .seek_write(&bytes[offset..], offset as u64)
            .map_err(host_error)?;
        if written == 0 {
            return Err(linux_error(LINUX_EIO));
        }
        offset += written;
    }
    Ok(())
}

/// Open the metadata stream of the file `file` holds, relative to that
/// handle. Also returns whether the open created the stream. Errors are the
/// host's, not yet mapped to Linux.
fn open_override_stream_at(
    file: &File,
    access: u32,
    disposition: NTCREATEFILE_CREATE_DISPOSITION,
) -> io::Result<(File, bool)> {
    let mut name: Vec<u16> = format!(":{ADS_STREAM_NAME}").encode_utf16().collect();
    // The name is a short constant, so its length in bytes fits.
    let name_bytes = (name.len() * 2) as u16;
    let name = UNICODE_STRING {
        Length: name_bytes,
        MaximumLength: name_bytes,
        Buffer: name.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: file.as_raw_handle(),
        ObjectName: &name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut handle = std::ptr::null_mut();
    let mut status_block = IO_STATUS_BLOCK::default();

    // SAFETY: every pointer refers to a live local for the duration of the
    // synchronous call, and `file` keeps the root handle open until it returns.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access,
            &attributes,
            &mut status_block,
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            disposition,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
            std::ptr::null(),
            0,
        )
    };
    if status == STATUS_DELETE_PENDING {
        return Err(io::Error::from_raw_os_error(ERROR_DELETE_PENDING as i32));
    }
    if status < 0 {
        // SAFETY: RtlNtStatusToDosError only maps the status code.
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(io::Error::from_raw_os_error(code as i32));
    }

    // SAFETY: NtCreateFile succeeded, so handle is a new handle we now own.
    let stream = unsafe { File::from_raw_handle(handle) };
    Ok((stream, status_block.Information == FILE_CREATED))
}

/// Reopen the file `file` holds by its file ID. Unlike `file`, the new handle
/// was not opened through a name, so the host replacing that name leaves it
/// usable. Fails once the file has no name left, and where the filesystem
/// cannot open files by ID.
fn reopen_by_id(file: &File) -> io::Result<File> {
    let mut info = FILE_ID_INFO::default();
    // SAFETY: file owns a live handle and info is a FILE_ID_INFO of the size passed.
    let read = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            (&mut info as *mut FILE_ID_INFO).cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    };
    if read == 0 {
        return Err(io::Error::last_os_error());
    }

    let id = FILE_ID_DESCRIPTOR {
        dwSize: std::mem::size_of::<FILE_ID_DESCRIPTOR>() as u32,
        Type: ExtendedFileIdType,
        Anonymous: FILE_ID_DESCRIPTOR_0 {
            ExtendedFileId: info.FileId,
        },
    };
    // SAFETY: file is a live handle on the volume that holds the file, and id
    // is a complete descriptor; the call only reads both.
    let handle = unsafe {
        OpenFileById(
            file.as_raw_handle(),
            &id,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: OpenFileById succeeded, so handle is a new handle we now own.
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn is_delete_pending(error: &io::Error) -> bool {
    error.raw_os_error() == Some(ERROR_DELETE_PENDING as i32)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backends::passthroughfs::owned::OwnedDirectorySnapshot;

    #[test]
    fn owned_components_reject_win32_aliases_and_hidden_metadata() {
        for name in [
            "CON",
            "nul.txt",
            "COM1",
            "Lpt9.log",
            "COM¹",
            "CONIN$",
            "file.",
            "file ",
            "one:stream",
            "a\\b",
            ".msb_override_stat",
            "bad?name",
            "a\n",
        ] {
            assert!(owned_component(name).is_err(), "accepted {name:?}");
        }
        for name in ["data", "file.txt", "COM10", "unicode-λ"] {
            assert!(owned_component(name).is_ok(), "rejected {name:?}");
        }
    }

    #[test]
    fn owned_capture_consumes_sidecar_without_exposing_it_as_guest_data() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source");
        std::fs::create_dir(&source).unwrap();
        let path = source.join("file");
        std::fs::write(&path, b"contents").unwrap();
        StatStore::sidecar(&source)
            .write(&path, 10, 20, S_IFREG | 0o640, 0)
            .unwrap();
        let generation = temporary.path().join("generation");
        let snapshot = OwnedDirectorySnapshot::capture(&source, &generation).unwrap();
        // Only file contents are captured: the metadata stream/sidecar is in the descriptor.
        assert_eq!(snapshot.payloads().len(), 1);
        let destination = temporary.path().join("destination");
        snapshot.materialize(&generation, &destination).unwrap();
        assert_eq!(
            capture_owned_metadata(&destination, &destination.join("file")).unwrap(),
            Some([10, 20, S_IFREG | 0o640, 0])
        );
    }

    #[test]
    fn owned_hardlink_guest_metadata_is_shared_for_ads_and_sidecar() {
        for sidecar in [false, true] {
            let temporary = tempfile::tempdir().unwrap();
            let root = temporary.path().join("source");
            std::fs::create_dir(&root).unwrap();
            let checkpoint = crate::OwnedDirectoryCheckpoint::default();
            let mut backend = PassthroughFs::new(PassthroughConfig {
                root_dir: root.clone(),
                inject_init: false,
                owned_checkpoint: Some(checkpoint.clone()),
                ..Default::default()
            })
            .unwrap();
            if sidecar {
                // Exercise the non-ADS backend without requiring a separately mounted FAT volume.
                backend.stat_store = Some(StatStore::sidecar(&backend.root));
            }
            backend.init(FsOptions::empty()).unwrap();
            let ctx = Context {
                uid: 0,
                gid: 0,
                pid: 0,
            };
            let (entry, _, _) = backend
                .create(
                    ctx,
                    ROOT_INODE,
                    c"file",
                    S_IFREG | 0o644,
                    false,
                    (LINUX_O_CREAT | LINUX_O_RDWR) as u32,
                    0,
                    Extensions::default(),
                )
                .unwrap();
            let alias = backend
                .link(ctx, entry.inode, ROOT_INODE, c"alias")
                .unwrap();
            assert_eq!(
                entry.inode, alias.inode,
                "hardlinks must share the guest inode"
            );
            assert_eq!(alias.attr.st_nlink, 2);
            backend
                .setattr(
                    ctx,
                    entry.inode,
                    stat64 {
                        st_uid: 123,
                        st_gid: 234,
                        st_mode: 0o640,
                        ..Default::default()
                    },
                    None,
                    SetattrValid::UID | SetattrValid::GID | SetattrValid::MODE,
                )
                .unwrap();
            let stat = backend.getattr(ctx, alias.inode, None).unwrap().0;
            assert_eq!(
                (stat.st_uid, stat.st_gid, stat.st_mode),
                (123, 234, S_IFREG | 0o640)
            );
            if sidecar {
                for name in ["file", "alias"] {
                    let stored = backend
                        .stat_store
                        .as_ref()
                        .unwrap()
                        .read(&backend.root.join(name))
                        .unwrap()
                        .unwrap();
                    let values = [stored.uid, stored.gid, stored.mode];
                    assert_eq!(values, [123, 234, S_IFREG | 0o640]);
                }
            }
            backend.unlink(ctx, ROOT_INODE, c"file").unwrap();
            assert_eq!(
                backend.getattr(ctx, entry.inode, None).unwrap().0.st_nlink,
                1
            );
            backend
                .setattr(
                    ctx,
                    alias.inode,
                    stat64 {
                        st_uid: 345,
                        ..Default::default()
                    },
                    None,
                    SetattrValid::UID,
                )
                .unwrap();
            assert_eq!(
                backend.getattr(ctx, entry.inode, None).unwrap().0.st_uid,
                345
            );
            let generation = temporary.path().join("generation");
            checkpoint.prepare_capture(&generation).unwrap();
            let state = backend.capture_state().unwrap();
            let snapshot = checkpoint.finish_capture().unwrap();
            drop(backend);
            std::fs::remove_dir_all(&root).unwrap();
            let child = temporary.path().join("child");
            snapshot.materialize(&generation, &child).unwrap();
            let restored = crate::OwnedDirectoryCheckpoint::default();
            restored.set_restore(&generation).unwrap();
            let backend = PassthroughFs::new(PassthroughConfig {
                root_dir: child,
                inject_init: false,
                owned_checkpoint: Some(restored),
                ..Default::default()
            })
            .unwrap();
            backend.restore_state(&state).unwrap();
            let found = backend.lookup(ctx, ROOT_INODE, c"alias").unwrap();
            assert_eq!(found.inode, entry.inode);
            assert_eq!(found.attr.st_uid, 345);
        }
    }

    #[test]
    fn owned_capture_refuses_preexisting_inconsistent_sidecar_hardlinks() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("source");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("first"), b"data").unwrap();
        std::fs::hard_link(root.join("first"), root.join("second")).unwrap();
        let store = StatStore::sidecar(&root);
        store
            .write(&root.join("first"), 1, 2, S_IFREG | 0o640, 0)
            .unwrap();
        store
            .write(&root.join("second"), 3, 4, S_IFREG | 0o640, 0)
            .unwrap();
        let generation = temporary.path().join("generation");
        let error = OwnedDirectorySnapshot::capture(&root, &generation).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(
            !generation.exists(),
            "unpublished payload generation must be cleaned up"
        );
    }

    #[test]
    fn owned_restore_recovers_sidecar_aliases_before_any_new_lookup() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("source");
        std::fs::create_dir(&root).unwrap();
        let checkpoint = crate::OwnedDirectoryCheckpoint::default();
        let mut source = PassthroughFs::new(PassthroughConfig {
            root_dir: root,
            inject_init: false,
            owned_checkpoint: Some(checkpoint.clone()),
            ..Default::default()
        })
        .unwrap();
        source.stat_store = Some(StatStore::sidecar(&source.root));
        source.init(FsOptions::empty()).unwrap();
        let ctx = Context {
            uid: 0,
            gid: 0,
            pid: 0,
        };
        let (entry, _, _) = source
            .create(
                ctx,
                ROOT_INODE,
                c"first",
                S_IFREG | 0o644,
                false,
                (LINUX_O_CREAT | LINUX_O_RDWR) as u32,
                0,
                Extensions::default(),
            )
            .unwrap();
        let alias = source
            .link(ctx, entry.inode, ROOT_INODE, c"second")
            .unwrap();
        assert_eq!(entry.inode, alias.inode);
        let generation = temporary.path().join("generation");
        checkpoint.prepare_capture(&generation).unwrap();
        let state = source.capture_state().unwrap();
        let snapshot = checkpoint.finish_capture().unwrap();
        let child = temporary.path().join("child");
        snapshot.materialize(&generation, &child).unwrap();
        // Simulate a destination volume using sidecars, including its already materialized
        // per-path metadata. NTFS CI can exercise the fallback without mounting another disk.
        // Both names share an ADS: preserve it before clearing either alias.
        let [uid, gid, mode, rdev] = capture_owned_metadata(&child, &child.join("first"))
            .unwrap()
            .unwrap();
        for name in ["first", "second"] {
            let path = child.join(name);
            StatStore::sidecar(&child)
                .write(&path, uid, gid, mode, rdev)
                .unwrap();
            clear_owned_payload_metadata(&path).unwrap();
        }
        let restored_checkpoint = crate::OwnedDirectoryCheckpoint::default();
        restored_checkpoint.set_restore(&generation).unwrap();
        let mut restored = PassthroughFs::new(PassthroughConfig {
            root_dir: child,
            inject_init: false,
            owned_checkpoint: Some(restored_checkpoint.clone()),
            ..Default::default()
        })
        .unwrap();
        restored.stat_store = Some(StatStore::sidecar(&restored.root));
        restored.restore_state(&state).unwrap();
        // The guest still has its old dentries and inode ID, so no lookup precedes mutation.
        restored
            .setattr(
                ctx,
                entry.inode,
                stat64 {
                    st_uid: 789,
                    ..Default::default()
                },
                None,
                SetattrValid::UID,
            )
            .unwrap();
        for name in ["first", "second"] {
            let stored = restored
                .stat_store
                .as_ref()
                .unwrap()
                .read(&restored.root.join(name))
                .unwrap()
                .unwrap();
            let uid = stored.uid;
            assert_eq!(uid, 789);
        }
        restored_checkpoint
            .prepare_capture(&temporary.path().join("recapture"))
            .unwrap();
        restored.capture_state().unwrap();
        restored_checkpoint.finish_capture().unwrap();
    }

    #[test]
    fn owned_encoded_symlink_aliases_preserve_full_fuse_identity() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("source");
        std::fs::create_dir(&root).unwrap();
        let checkpoint = crate::OwnedDirectoryCheckpoint::default();
        let source = PassthroughFs::new(PassthroughConfig {
            root_dir: root.clone(),
            inject_init: false,
            owned_checkpoint: Some(checkpoint.clone()),
            ..Default::default()
        })
        .unwrap();
        source.init(FsOptions::empty()).unwrap();
        let ctx = Context {
            uid: 0,
            gid: 0,
            pid: 0,
        };
        let link = source
            .symlink(
                ctx,
                c"/absent-owned-test-target",
                ROOT_INODE,
                c"link",
                Extensions::default(),
            )
            .unwrap();
        let alias = source.link(ctx, link.inode, ROOT_INODE, c"alias").unwrap();
        assert_eq!(link.inode, alias.inode);
        assert_eq!(alias.attr.st_nlink, 2);
        let generation = temporary.path().join("generation");
        checkpoint.prepare_capture(&generation).unwrap();
        let state = source.capture_state().unwrap();
        let snapshot = checkpoint.finish_capture().unwrap();
        drop(source);
        std::fs::remove_dir_all(&root).unwrap();
        let child = temporary.path().join("child");
        snapshot.materialize(&generation, &child).unwrap();
        let restored_checkpoint = crate::OwnedDirectoryCheckpoint::default();
        restored_checkpoint.set_restore(&generation).unwrap();
        let restored = PassthroughFs::new(PassthroughConfig {
            root_dir: child,
            inject_init: false,
            owned_checkpoint: Some(restored_checkpoint.clone()),
            ..Default::default()
        })
        .unwrap();
        restored.restore_state(&state).unwrap();
        for name in [c"link", c"alias"] {
            let entry = restored.lookup(ctx, ROOT_INODE, name).unwrap();
            assert_eq!(entry.inode, link.inode);
            assert_eq!(entry.attr.st_nlink, 2);
            assert_eq!(entry.attr.st_mode & S_IFMT, S_IFLNK);
        }
        restored.unlink(ctx, ROOT_INODE, c"link").unwrap();
        let remaining = restored.lookup(ctx, ROOT_INODE, c"alias").unwrap();
        assert_eq!(remaining.inode, link.inode);
        assert_eq!(remaining.attr.st_nlink, 1);
        assert_eq!(
            restored.readlink(ctx, link.inode).unwrap(),
            b"/absent-owned-test-target"
        );
        restored_checkpoint
            .prepare_capture(&temporary.path().join("recapture"))
            .unwrap();
        restored.capture_state().unwrap();
        restored_checkpoint.finish_capture().unwrap();
    }
}

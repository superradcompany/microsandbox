//! Conversion between owned-generation metadata and the Windows ADS/sidecar stat store.

use super::*;

use std::os::windows::{fs::FileExt, io::AsRawHandle};

use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PassthroughFs {
    /// Report the actual link count for owned files, including zero for an unlinked pin.
    pub(super) fn owned_stat_link_count(
        &self,
        mut stat: stat64,
        data: &InodeData,
    ) -> io::Result<stat64> {
        if self.cfg.owned_checkpoint.is_none() {
            return Ok(stat);
        }
        let file = if let Some(file) = data.retained.lock().unwrap().as_ref() {
            file.try_clone().map_err(host_error)?
        } else {
            StdOpenOptions::new()
                .access_mode(0x80)
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

    /// Retain the inode-scoped metadata stream alongside an owned unlinked file.
    /// The caller has either validated the live path or just privately materialized it.
    pub(super) fn pin_owned_stat(
        &self,
        path: &Path,
        current: OverrideStat,
    ) -> io::Result<Option<File>> {
        if !self
            .stat_store
            .as_ref()
            .is_some_and(|store| matches!(store.backend, StatStoreBackend::AlternateDataStream))
        {
            return Ok(None);
        }
        let path = ads_override_path(path);
        match read_override_stream(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                write_override_stream(&path, current)?
            }
            Err(error) => return Err(error),
        }
        StdOpenOptions::new()
            .read(true)
            .write(!self.cfg.readonly)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
            .map(Some)
            .map_err(host_error)
    }

    /// Sidecar paths are not inode-scoped like ADS. Owned guest-created hardlink aliases
    /// therefore receive the same virtual metadata explicitly, without changing bind mounts.
    pub(super) fn propagate_owned_sidecar_stat(
        &self,
        data: &InodeData,
        stat: OverrideStat,
    ) -> io::Result<()> {
        if self.cfg.owned_checkpoint.is_none()
            || !self
                .stat_store
                .as_ref()
                .is_some_and(|store| matches!(store.backend, StatStoreBackend::Sidecar { .. }))
        {
            return Ok(());
        }
        // Owned aliases share the logical inode. The path key, not the canonical path
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
    OverrideStat::from_bytes(&bytes).map(Some)
}

pub(super) fn write_retained_stat(data: &InodeData, stat: OverrideStat) -> io::Result<bool> {
    let retained = data.retained_stat.lock().unwrap();
    let Some(file) = retained.as_ref() else {
        return Ok(false);
    };
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
        for name in ["first", "second"] {
            let path = child.join(name);
            let [uid, gid, mode, rdev] = capture_owned_metadata(&child, &path).unwrap().unwrap();
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

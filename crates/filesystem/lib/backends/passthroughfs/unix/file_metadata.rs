//! Pinned file/directory metadata for the private runtime share, including guest overrides.

use std::{fs::File, io, os::fd::AsRawFd};

use super::PassthroughFs;
use crate::{
    backends::shared::{platform, stat_override},
    stat64,
};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PassthroughFs {
    /// Read pinned runtime backing using the runtime share's strict stat virtualization.
    ///
    /// This is not the metadata policy for arbitrary bind mounts: the runtime share has
    /// no bind-identity mapping. Both the host object and its guest-visible type must be
    /// regular files or directories of matching types. Unknown/corrupt overrides fail
    /// rather than falling back to host mode.
    pub fn runtime_backing_stat(file: &File) -> io::Result<stat64> {
        let fd = file.as_raw_fd();
        let host = platform::fstat(fd)?;
        let kind = backing_kind(platform::mode_u32(host.st_mode))?;
        let guest = stat_override::patched_stat(fd, host, true, true, None)?;
        if backing_kind(platform::mode_u32(guest.st_mode))? != kind {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "runtime backing type changed by virtual metadata",
            ));
        }
        Ok(guest)
    }

    /// Seed exact guest permissions on newly staged regular-file/directory backing.
    ///
    /// The host file keeps its private owner-access permissions. Guest mode/ownership
    /// live in the same persistent overlay used by the mounted runtime filesystem.
    /// Callers must own an unpublished file; this does not authorize changing a live guest.
    pub fn set_runtime_backing_permissions(
        file: &File,
        uid: u32,
        gid: u32,
        permissions: u16,
    ) -> io::Result<()> {
        if permissions > 0o777 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "runtime file permissions contain unsupported bits",
            ));
        }
        let kind = backing_kind(platform::mode_u32(
            platform::fstat(file.as_raw_fd())?.st_mode,
        ))?;
        stat_override::set_override(file.as_raw_fd(), uid, gid, kind | u32::from(permissions), 0)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn backing_kind(mode: u32) -> io::Result<u32> {
    let kind = mode & platform::MODE_TYPE_MASK;
    if kind != platform::MODE_REG && kind != platform::MODE_DIR {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "runtime backing is not a regular file or directory",
        ));
    }
    Ok(kind)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use super::*;
    use crate::{Context, DynFileSystem, FsOptions, PassthroughConfig};

    #[test]
    fn guest_metadata_preserves_zero_mode_without_removing_host_access() {
        let file = tempfile::tempfile().unwrap();
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .unwrap();
        PassthroughFs::set_runtime_backing_permissions(&file, 123, 456, 0).unwrap();
        let guest = PassthroughFs::runtime_backing_stat(&file).unwrap();
        assert_eq!((guest.st_uid, guest.st_gid), (123, 456));
        assert_eq!(platform::mode_u32(guest.st_mode) & 0o7777, 0);
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn guest_virtual_type_cannot_disguise_regular_host_storage_as_a_script() {
        let file = tempfile::tempfile().unwrap();
        stat_override::set_override(file.as_raw_fd(), 0, 0, platform::MODE_CHR | 0o600, 0).unwrap();
        assert!(PassthroughFs::runtime_backing_stat(&file).is_err());
        assert!(PassthroughFs::set_runtime_backing_permissions(&file, 0, 0, 0o4755).is_err());
    }

    #[test]
    fn directory_virtual_permissions_are_preserved() {
        let root = tempfile::tempdir().unwrap();
        let file = File::open(root.path()).unwrap();
        PassthroughFs::set_runtime_backing_permissions(&file, 123, 456, 0o710).unwrap();
        let guest = PassthroughFs::runtime_backing_stat(&file).unwrap();
        assert_eq!(
            platform::mode_u32(guest.st_mode),
            platform::MODE_DIR | 0o710
        );
        assert_eq!((guest.st_uid, guest.st_gid), (123, 456));
    }

    #[test]
    fn seeded_metadata_matches_the_mounted_runtime_filesystem_view() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("script");
        fs::write(&path, b"body").unwrap();
        let file = File::open(&path).unwrap();
        PassthroughFs::set_runtime_backing_permissions(&file, 123, 456, 0o640).unwrap();
        let backend = PassthroughFs::new(PassthroughConfig {
            root_dir: root.path().to_owned(),
            inject_init: false,
            ..Default::default()
        })
        .unwrap();
        backend.init(FsOptions::empty()).unwrap();
        let context = Context {
            uid: 0,
            gid: 0,
            pid: 0,
        };
        let entry = backend.lookup(context, 1, c"script").unwrap();
        let (stat, _) = backend.getattr(context, entry.inode, None).unwrap();
        assert_eq!((stat.st_uid, stat.st_gid), (123, 456));
        assert_eq!(platform::mode_u32(stat.st_mode) & 0o7777, 0o640);
        assert_eq!(stat.st_size, 4);
    }
}

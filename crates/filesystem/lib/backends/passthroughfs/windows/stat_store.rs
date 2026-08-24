//! Windows stat-virtualization store for the passthrough backend.

use super::*;
use windows_sys::Win32::Storage::FileSystem::{GetVolumeInformationW, GetVolumePathNameW};
use windows_sys::Win32::System::SystemServices::FILE_NAMED_STREAMS;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl StatStore {
    pub(super) fn new(
        root: &Path,
        policy: StatVirtualization,
        readonly: bool,
    ) -> io::Result<Option<Self>> {
        if matches!(policy, StatVirtualization::Off) {
            return Ok(None);
        }

        let ads_store = Self::ads(root);
        let ads_probe = if readonly {
            ads_store.probe_read()
        } else {
            ads_store.probe()
        };
        match ads_probe {
            Ok(()) => return Ok(Some(ads_store)),
            Err(error) if matches!(policy, StatVirtualization::Strict) => return Err(error),
            Err(error) => {
                tracing::debug!(?error, "windows passthrough ADS stat store unavailable");
            }
        }

        let sidecar_store = Self::sidecar(root);
        let sidecar_probe = if readonly {
            sidecar_store.probe_read()
        } else {
            sidecar_store.probe()
        };
        match sidecar_probe {
            Ok(()) => Ok(Some(sidecar_store)),
            Err(error) => {
                tracing::debug!(?error, "windows passthrough sidecar stat store unavailable");
                Ok(None)
            }
        }
    }

    fn ads(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            backend: StatStoreBackend::AlternateDataStream,
        }
    }

    pub(super) fn sidecar(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            backend: StatStoreBackend::Sidecar {
                dir: root.join(FALLBACK_METADATA_DIR_NAME),
            },
        }
    }

    pub(super) fn probe(&self) -> io::Result<()> {
        match &self.backend {
            StatStoreBackend::AlternateDataStream => self.probe_ads(),
            StatStoreBackend::Sidecar { dir } => self.probe_sidecar(dir),
        }
    }

    /// Verify that an existing metadata store can be consumed without
    /// creating, replacing, or deleting anything beneath a read-only mount.
    fn probe_read(&self) -> io::Result<()> {
        match &self.backend {
            StatStoreBackend::AlternateDataStream => self.probe_ads_read(),
            StatStoreBackend::Sidecar { dir } => self.probe_sidecar_read(dir),
        }
    }

    fn probe_ads(&self) -> io::Result<()> {
        // Never probe through `msb.override_stat`: that is the persistent
        // metadata stream for the mount root and may already contain a guest
        // chown/chmod override that must survive remounting.
        let probe_path = ads_probe_path(&self.root);
        let probe = OverrideStat::new(0, 0, S_IFDIR | 0o700, 0);
        write_override_stream(&probe_path, probe)?;
        let validation = read_override_stream(&probe_path).and_then(|read_back| {
            if read_back.version == OVERRIDE_VERSION {
                Ok(())
            } else {
                Err(linux_error(LINUX_EIO))
            }
        });
        match std::fs::remove_file(&probe_path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(host_error(error)),
        }
        validation?;
        Ok(())
    }

    /// Verify that a read-only mount can consume ADS metadata without creating
    /// or deleting a stream on the host directory.
    fn probe_ads_read(&self) -> io::Result<()> {
        if !volume_supports_named_streams(&self.root)? {
            return Err(linux_error(LINUX_EOPNOTSUPP));
        }

        let probe_path = ads_override_path(&self.root);
        match StdOpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(&probe_path)
        {
            Ok(_) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(host_error(error)),
        }
    }

    fn probe_sidecar_read(&self, dir: &Path) -> io::Result<()> {
        // A missing sidecar is a valid empty store. If it exists, opening its
        // directory verifies read access without leaving a probe artifact.
        match std::fs::read_dir(dir) {
            Ok(_) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(host_error(error)),
        }
    }

    fn probe_sidecar(&self, dir: &Path) -> io::Result<()> {
        std::fs::create_dir_all(dir).map_err(host_error)?;
        let probe_dir = dir.join(".probe");
        std::fs::create_dir_all(&probe_dir).map_err(host_error)?;
        let probe_file = probe_dir.join(METADATA_STAT_NAME);
        let probe = OverrideStat::new(0, 0, S_IFREG | 0o600, 0);
        write_override_sidecar_file(&probe_file, probe)?;
        let read_back = read_override_sidecar_file(&probe_file)?;
        if read_back.version != OVERRIDE_VERSION {
            return Err(linux_error(LINUX_EIO));
        }
        let _ = std::fs::remove_dir_all(&probe_dir);
        Ok(())
    }

    pub(super) fn read(&self, path: &Path) -> io::Result<Option<OverrideStat>> {
        let override_path = self.override_file_path(path)?;
        let result = match self.backend {
            StatStoreBackend::AlternateDataStream => read_override_stream(&override_path),
            StatStoreBackend::Sidecar { .. } => read_override_sidecar_file(&override_path),
        };
        match result {
            Ok(override_stat) => Ok(Some(override_stat)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub(super) fn write(
        &self,
        path: &Path,
        uid: u32,
        gid: u32,
        mode: u32,
        rdev: u32,
    ) -> io::Result<()> {
        let override_path = self.override_file_path(path)?;
        match self.backend {
            StatStoreBackend::AlternateDataStream => {
                write_override_stream(&override_path, OverrideStat::new(uid, gid, mode, rdev))
            }
            StatStoreBackend::Sidecar { .. } => {
                let parent = override_path
                    .parent()
                    .ok_or_else(|| linux_error(LINUX_EINVAL))?;
                std::fs::create_dir_all(parent).map_err(host_error)?;
                write_override_sidecar_file(&override_path, OverrideStat::new(uid, gid, mode, rdev))
            }
        }
    }

    pub(super) fn remove(&self, path: &Path) -> io::Result<()> {
        match self.backend {
            StatStoreBackend::AlternateDataStream => Ok(()),
            StatStoreBackend::Sidecar { .. } => {
                let container = self.override_container_path(path)?;
                match std::fs::remove_dir_all(container) {
                    Ok(()) => Ok(()),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                    Err(error) => Err(host_error(error)),
                }
            }
        }
    }

    pub(super) fn rename(&self, old_path: &Path, new_path: &Path) -> io::Result<()> {
        if matches!(self.backend, StatStoreBackend::AlternateDataStream) {
            return Ok(());
        }

        let old_container = self.override_container_path(old_path)?;
        let new_container = self.override_container_path(new_path)?;
        if let Err(error) = std::fs::remove_dir_all(&new_container)
            && error.kind() != io::ErrorKind::NotFound
        {
            return Err(host_error(error));
        }

        if !old_container.exists() {
            return Ok(());
        }

        let new_parent = new_container
            .parent()
            .ok_or_else(|| linux_error(LINUX_EINVAL))?;
        std::fs::create_dir_all(new_parent).map_err(host_error)?;
        std::fs::rename(old_container, new_container).map_err(host_error)
    }

    pub(super) fn override_file_path(&self, path: &Path) -> io::Result<PathBuf> {
        ensure_lexically_under_root(&self.root, path)?;
        match self.backend {
            StatStoreBackend::AlternateDataStream => Ok(ads_override_path(path)),
            StatStoreBackend::Sidecar { .. } => {
                Ok(self.override_container_path(path)?.join(METADATA_STAT_NAME))
            }
        }
    }

    fn override_container_path(&self, path: &Path) -> io::Result<PathBuf> {
        let StatStoreBackend::Sidecar { dir } = &self.backend else {
            return Err(linux_error(LINUX_EINVAL));
        };
        ensure_lexically_under_root(&self.root, path)?;
        let relative = path
            .strip_prefix(&self.root)
            .map_err(|_| linux_error(LINUX_EACCES))?;
        let mut encoded = dir.clone();

        if relative.as_os_str().is_empty() {
            encoded.push(METADATA_ROOT_NAME);
            return Ok(encoded);
        }

        for component in relative.components() {
            match component {
                Component::Normal(part) => encoded.push(encode_metadata_component(part)),
                Component::CurDir => {}
                _ => return Err(linux_error(LINUX_EACCES)),
            }
        }

        Ok(encoded)
    }
}

impl OverrideStat {
    pub(super) fn new(uid: u32, gid: u32, mode: u32, rdev: u32) -> Self {
        Self {
            version: OVERRIDE_VERSION,
            _pad: [0; 3],
            uid,
            gid,
            mode,
            rdev,
        }
    }

    pub(super) fn from_bytes(buf: &[u8]) -> io::Result<Self> {
        if buf.len() != OVERRIDE_SIZE {
            return Err(linux_error(LINUX_EIO));
        }
        let override_stat =
            unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const OverrideStat) };
        if override_stat.version != OVERRIDE_VERSION {
            return Err(linux_error(LINUX_EIO));
        }
        Ok(override_stat)
    }

    pub(super) fn as_bytes(&self) -> [u8; OVERRIDE_SIZE] {
        let mut buf = [0u8; OVERRIDE_SIZE];
        unsafe {
            std::ptr::copy_nonoverlapping(
                self as *const OverrideStat as *const u8,
                buf.as_mut_ptr(),
                OVERRIDE_SIZE,
            );
        }
        buf
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Query the backing volume instead of creating a probe ADS on a read-only mount.
fn volume_supports_named_streams(path: &Path) -> io::Result<bool> {
    let path_wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut volume_path = [0u16; 32_768];
    let found = unsafe {
        GetVolumePathNameW(
            path_wide.as_ptr(),
            volume_path.as_mut_ptr(),
            volume_path.len() as u32,
        )
    };
    if found == 0 {
        return Err(host_error(io::Error::last_os_error()));
    }

    let mut flags = 0u32;
    let queried = unsafe {
        GetVolumeInformationW(
            volume_path.as_ptr(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut flags,
            std::ptr::null_mut(),
            0,
        )
    };
    if queried == 0 {
        return Err(host_error(io::Error::last_os_error()));
    }

    Ok(flags & FILE_NAMED_STREAMS != 0)
}

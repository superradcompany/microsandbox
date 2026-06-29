//! Windows stat-virtualization store for the passthrough backend.

use super::*;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl StatStore {
    pub(super) fn new(root: &Path, policy: StatVirtualization) -> io::Result<Option<Self>> {
        if matches!(policy, StatVirtualization::Off) {
            return Ok(None);
        }

        let ads_store = Self::ads(root);
        match ads_store.probe() {
            Ok(()) => return Ok(Some(ads_store)),
            Err(error) if matches!(policy, StatVirtualization::Strict) => return Err(error),
            Err(error) => {
                tracing::debug!(?error, "windows passthrough ADS stat store unavailable");
            }
        }

        let sidecar_store = Self::sidecar(root);
        match sidecar_store.probe() {
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

    fn probe_ads(&self) -> io::Result<()> {
        let probe_path = ads_override_path(&self.root);
        let probe = OverrideStat::new(0, 0, S_IFDIR | 0o700, 0);
        write_override_stream(&probe_path, probe)?;
        let read_back = read_override_stream(&probe_path)?;
        if read_back.version != OVERRIDE_VERSION {
            return Err(linux_error(LINUX_EIO));
        }
        match std::fs::remove_file(&probe_path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(host_error(error)),
        }
        Ok(())
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

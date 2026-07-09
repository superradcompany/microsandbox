//! Host-side filesystem operations on a named volume.
//!
//! Unlike [`SandboxFsOps`](crate::sandbox::fs::SandboxFsOps) which goes through the
//! agent protocol, [`VolumeFs`] reads + writes a volume's bytes directly. For
//! the local backend that is `tokio::fs` against `volumes_dir/<name>/`; for
//! cloud (Phase 6) it routes through msb-cloud HTTP. Today every cloud op
//! returns [`crate::MicrosandboxError::Unsupported`].
//!
//! `VolumeFs` is a single type per D6.4 — no public variants. It borrows the
//! parent volume's `Arc<dyn Backend>` + name and dispatches through the
//! [`VolumeBackend`](crate::backend::VolumeBackend) trait.

use std::sync::Arc;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::backend::Backend;
use crate::{
    MicrosandboxResult,
    sandbox::fs::{FsEntry, FsMetadata},
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Chunk size for streaming volume reads (64 KiB).
const STREAM_CHUNK_SIZE: usize = 64 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Filesystem operations on a volume.
///
/// Borrows the parent volume's `Arc<dyn Backend>` + name and dispatches every
/// op through the [`VolumeBackend`](crate::backend::VolumeBackend) trait.
/// Local routes to `tokio::fs`; cloud returns `Unsupported` until Phase 6.
pub struct VolumeFs<'a> {
    backend: Arc<dyn Backend>,
    name: &'a str,
}

/// A streaming reader for file data from a volume's host-side directory.
///
/// **Local backend only** — opened from a host path. Cloud streaming flows
/// through `VolumeFs::read_stream` will land alongside the cloud HTTP routes
/// in Phase 6.
pub struct VolumeFsReadStream {
    file: tokio::fs::File,
    buf: Vec<u8>,
}

impl VolumeFsReadStream {
    /// Construct from an already-opened file. Local impl only.
    pub(crate) fn from_file(file: tokio::fs::File) -> Self {
        Self {
            file,
            buf: vec![0u8; STREAM_CHUNK_SIZE],
        }
    }
}

/// A streaming writer for file data to a volume's host-side directory.
///
/// **Local backend only** — opened against a host path. Cloud streaming will
/// land alongside the cloud HTTP routes in Phase 6.
pub struct VolumeFsWriteSink {
    file: tokio::fs::File,
}

impl VolumeFsWriteSink {
    /// Construct from an already-opened file. Local impl only.
    pub(crate) fn from_file(file: tokio::fs::File) -> Self {
        Self { file }
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: VolumeFs
//--------------------------------------------------------------------------------------------------

impl<'a> VolumeFs<'a> {
    /// Construct a volume FS handle for the named volume.
    ///
    /// Called by [`Volume::fs`](super::Volume::fs) and
    /// [`VolumeHandle::fs`](super::VolumeHandle::fs) — those are the public
    /// entry points; this constructor itself is crate-private.
    pub(crate) fn new(backend: Arc<dyn Backend>, name: &'a str) -> Self {
        Self { backend, name }
    }

    /// Public constructor for FFI shims that don't hold a [`Volume`](super::Volume) /
    /// [`VolumeHandle`](super::VolumeHandle) directly.
    ///
    /// Most callers should use [`Volume::fs`](super::Volume::fs) /
    /// [`VolumeHandle::fs`](super::VolumeHandle::fs); this is here for the
    /// language bindings that re-assemble a `VolumeFs` per FFI call.
    pub fn with_backend(backend: Arc<dyn Backend>, name: &'a str) -> Self {
        Self { backend, name }
    }

    //----------------------------------------------------------------------------------------------
    // Read Operations
    //----------------------------------------------------------------------------------------------

    /// Read an entire file into memory as raw bytes.
    pub async fn read(&self, path: &str) -> MicrosandboxResult<Bytes> {
        self.backend.volumes().fs_read(self.name, path).await
    }

    /// Read an entire file into memory as a UTF-8 string.
    pub async fn read_to_string(&self, path: &str) -> MicrosandboxResult<String> {
        self.backend
            .volumes()
            .fs_read_to_string(self.name, path)
            .await
    }

    /// Read a file with streaming. Returns a [`VolumeFsReadStream`] that
    /// yields chunks of bytes.
    ///
    /// Routes through the [`VolumeBackend`](crate::backend::VolumeBackend)
    /// trait — cloud routes return [`crate::MicrosandboxError::Unsupported`]
    /// until cloud volumes ship.
    pub async fn read_stream(&self, path: &str) -> MicrosandboxResult<VolumeFsReadStream> {
        self.backend.volumes().fs_read_stream(self.name, path).await
    }

    //----------------------------------------------------------------------------------------------
    // Write Operations
    //----------------------------------------------------------------------------------------------

    /// Write data to a file, creating parent directories as needed.
    /// Overwrites if the file already exists.
    pub async fn write(&self, path: &str, data: impl AsRef<[u8]>) -> MicrosandboxResult<()> {
        let bytes = data.as_ref().to_vec();
        self.backend
            .volumes()
            .fs_write(self.name, path, bytes)
            .await
    }

    /// Write to a file with streaming. Returns a [`VolumeFsWriteSink`] that
    /// accepts chunks of bytes. Creates parent directories as needed.
    ///
    /// Routes through the [`VolumeBackend`](crate::backend::VolumeBackend)
    /// trait — cloud routes return [`crate::MicrosandboxError::Unsupported`]
    /// until cloud volumes ship.
    pub async fn write_stream(&self, path: &str) -> MicrosandboxResult<VolumeFsWriteSink> {
        self.backend
            .volumes()
            .fs_write_stream(self.name, path)
            .await
    }

    //----------------------------------------------------------------------------------------------
    // Directory + File Operations
    //----------------------------------------------------------------------------------------------

    /// List the immediate children of a directory (non-recursive).
    /// Each entry includes the path, kind, size, permissions, and modification time.
    pub async fn list(&self, path: &str) -> MicrosandboxResult<Vec<FsEntry>> {
        self.backend.volumes().fs_list(self.name, path).await
    }

    /// Create a directory (and parents).
    pub async fn mkdir(&self, path: &str) -> MicrosandboxResult<()> {
        self.backend.volumes().fs_mkdir(self.name, path).await
    }

    /// Remove a directory recursively.
    pub async fn remove_dir(&self, path: &str) -> MicrosandboxResult<()> {
        self.backend
            .volumes()
            .fs_remove(self.name, path, true)
            .await
    }

    /// Delete a single file. Use [`remove_dir`](Self::remove_dir) for directories.
    pub async fn remove(&self, path: &str) -> MicrosandboxResult<()> {
        self.backend
            .volumes()
            .fs_remove(self.name, path, false)
            .await
    }

    /// Copy a file within the volume.
    pub async fn copy(&self, from: &str, to: &str) -> MicrosandboxResult<()> {
        self.backend.volumes().fs_copy(self.name, from, to).await
    }

    /// Rename/move a file or directory.
    pub async fn rename(&self, from: &str, to: &str) -> MicrosandboxResult<()> {
        self.backend.volumes().fs_rename(self.name, from, to).await
    }

    //----------------------------------------------------------------------------------------------
    // Metadata
    //----------------------------------------------------------------------------------------------

    /// Get file/directory metadata.
    pub async fn stat(&self, path: &str) -> MicrosandboxResult<FsMetadata> {
        self.backend.volumes().fs_stat(self.name, path).await
    }

    /// Check whether a file or directory exists at the given path.
    /// Returns `false` (not an error) if the path is absent.
    pub async fn exists(&self, path: &str) -> MicrosandboxResult<bool> {
        self.backend.volumes().fs_exists(self.name, path).await
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: VolumeFsReadStream
//--------------------------------------------------------------------------------------------------

impl VolumeFsReadStream {
    /// Receive the next chunk of file data.
    ///
    /// Returns `None` at EOF.
    pub async fn recv(&mut self) -> MicrosandboxResult<Option<Bytes>> {
        let n = self.file.read(&mut self.buf).await?;
        if n == 0 {
            Ok(None)
        } else {
            Ok(Some(Bytes::copy_from_slice(&self.buf[..n])))
        }
    }

    /// Read the remaining file data into a single `Bytes` buffer.
    pub async fn collect(mut self) -> MicrosandboxResult<Bytes> {
        let mut data = Vec::new();
        let mut buf = vec![0u8; STREAM_CHUNK_SIZE];
        loop {
            let n = self.file.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            data.extend_from_slice(&buf[..n]);
        }
        Ok(Bytes::from(data))
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: VolumeFsWriteSink
//--------------------------------------------------------------------------------------------------

impl VolumeFsWriteSink {
    /// Write a chunk of data to the file.
    pub async fn write(&mut self, data: impl AsRef<[u8]>) -> MicrosandboxResult<()> {
        self.file.write_all(data.as_ref()).await?;
        Ok(())
    }

    /// Flush and close the file.
    pub async fn close(mut self) -> MicrosandboxResult<()> {
        self.file.flush().await?;
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Module: local (free fn impls called by LocalBackend's VolumeBackend impl)
//--------------------------------------------------------------------------------------------------

pub(crate) mod local {
    //! Local FS ops keyed by `(volume_name, rel_path)`.
    //!
    //! Lives in a sub-module so the `LocalBackend` trait impl in
    //! `backend/volume.rs` can call into one place. Each function takes
    //! the `&LocalBackend` whose `volumes_dir` it should resolve against,
    //! so `with_backend` scoping and explicit `LocalBackend::builder()`
    //! constructions correctly route to the right host directory.

    use std::path::{Path, PathBuf};

    use bytes::Bytes;

    use crate::{
        MicrosandboxError, MicrosandboxResult,
        backend::LocalBackend,
        sandbox::fs::{FsEntry, FsEntryKind, FsMetadata},
    };

    use super::{VolumeFsReadStream, VolumeFsWriteSink};

    /// Resolve a relative path against the volume root, preventing path traversal.
    pub(crate) fn resolve_relative(root: &Path, path: &str) -> MicrosandboxResult<PathBuf> {
        // Strip leading slash for joining.
        let clean = path.strip_prefix('/').unwrap_or(path);

        let joined = root.join(clean);

        // Canonicalize what exists, then check prefix. If the path doesn't exist
        // yet (for writes), canonicalize the parent and verify.
        let canonical = if joined.exists() {
            joined
                .canonicalize()
                .map_err(|e| MicrosandboxError::SandboxFsOps(format!("resolve path: {e}")))?
        } else {
            // Find the deepest existing ancestor.
            let mut ancestor = joined.as_path();
            loop {
                if let Some(parent) = ancestor.parent() {
                    if parent.exists() {
                        let canon_parent = parent.canonicalize().map_err(|e| {
                            MicrosandboxError::SandboxFsOps(format!("resolve parent: {e}"))
                        })?;
                        // Reconstruct with remaining components.
                        let remainder = joined.strip_prefix(parent).unwrap_or(Path::new(""));
                        break canon_parent.join(remainder);
                    }
                    ancestor = parent;
                } else {
                    break joined.clone();
                }
            }
        };

        // Ensure the root itself is canonicalized for comparison.
        let canon_root = if root.exists() {
            root.canonicalize()
                .map_err(|e| MicrosandboxError::SandboxFsOps(format!("resolve root: {e}")))?
        } else {
            root.to_path_buf()
        };

        if !canonical.starts_with(&canon_root) {
            return Err(MicrosandboxError::SandboxFsOps(
                "path traversal outside volume root".into(),
            ));
        }

        Ok(canonical)
    }

    /// Volume root directory on the host for the named volume.
    fn volume_root(local: &LocalBackend, name: &str) -> PathBuf {
        local.volume_path(name)
    }

    /// Resolve `(volume_name, path)` to a canonical host path.
    fn resolve(local: &LocalBackend, name: &str, path: &str) -> MicrosandboxResult<PathBuf> {
        resolve_relative(&volume_root(local, name), path)
    }

    /// Normalize a volume-relative path to `/`-separated absolute form
    /// (`""`/`"/"` → `"/"`, `"a//./b/../c"` → `"/a/c"`). Purely textual —
    /// volume paths are platform-independent and must not route through
    /// host `Path` APIs, whose separator semantics differ on Windows.
    fn normalize_slash_path(path: &str) -> String {
        let mut parts: Vec<&str> = Vec::new();
        for seg in path.split('/') {
            match seg {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                seg => parts.push(seg),
            }
        }
        if parts.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", parts.join("/"))
        }
    }

    pub(crate) async fn read(
        local: &LocalBackend,
        name: &str,
        path: &str,
    ) -> MicrosandboxResult<Bytes> {
        let full = resolve(local, name, path)?;
        let data = tokio::fs::read(&full).await?;
        Ok(Bytes::from(data))
    }

    pub(crate) async fn read_to_string(
        local: &LocalBackend,
        name: &str,
        path: &str,
    ) -> MicrosandboxResult<String> {
        let full = resolve(local, name, path)?;
        let data = tokio::fs::read_to_string(&full).await?;
        Ok(data)
    }

    pub(crate) async fn write(
        local: &LocalBackend,
        name: &str,
        path: &str,
        data: &[u8],
    ) -> MicrosandboxResult<()> {
        let full = resolve(local, name, path)?;
        if let Some(parent) = full.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(&full, data).await?;
        Ok(())
    }

    pub(crate) async fn list(
        local: &LocalBackend,
        name: &str,
        path: &str,
    ) -> MicrosandboxResult<Vec<FsEntry>> {
        let root = volume_root(local, name);
        let full = resolve_relative(&root, path)?;
        // Present entries as the request path joined with '/'. Deriving them from
        // host paths instead (strip_prefix + display) breaks on Windows: `display()`
        // renders host separators, and canonicalization adds a `\\?\` verbatim
        // prefix that defeats the strip against the un-canonicalized root.
        let base = normalize_slash_path(path);
        let mut dir = tokio::fs::read_dir(&full).await?;
        let mut entries = Vec::new();

        while let Some(entry) = dir.next_entry().await? {
            let entry_name = entry.file_name();
            let entry_path = if base == "/" {
                format!("/{}", entry_name.to_string_lossy())
            } else {
                format!("{base}/{}", entry_name.to_string_lossy())
            };

            match entry.metadata().await {
                Ok(meta) => {
                    entries.push(metadata_to_entry(&entry_path, &meta));
                }
                Err(_) => {
                    entries.push(FsEntry {
                        path: entry_path,
                        kind: FsEntryKind::Other,
                        size: 0,
                        mode: 0,
                        uid: 0,
                        gid: 0,
                        accessed: None,
                        modified: None,
                    });
                }
            }
        }

        Ok(entries)
    }

    pub(crate) async fn mkdir(
        local: &LocalBackend,
        name: &str,
        path: &str,
    ) -> MicrosandboxResult<()> {
        let full = resolve(local, name, path)?;
        tokio::fs::create_dir_all(&full).await?;
        Ok(())
    }

    pub(crate) async fn remove(
        local: &LocalBackend,
        name: &str,
        path: &str,
        recursive: bool,
    ) -> MicrosandboxResult<()> {
        let root = volume_root(local, name);
        let full = resolve_relative(&root, path)?;
        if recursive {
            ensure_not_volume_root(&root, &full, "remove_dir")?;
            tokio::fs::remove_dir_all(&full).await?;
        } else {
            tokio::fs::remove_file(&full).await?;
        }
        Ok(())
    }

    pub(crate) async fn copy(
        local: &LocalBackend,
        name: &str,
        from: &str,
        to: &str,
    ) -> MicrosandboxResult<()> {
        let src = resolve(local, name, from)?;
        let dst = resolve(local, name, to)?;

        if let Some(parent) = dst.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        tokio::fs::copy(&src, &dst).await?;
        Ok(())
    }

    pub(crate) async fn rename(
        local: &LocalBackend,
        name: &str,
        from: &str,
        to: &str,
    ) -> MicrosandboxResult<()> {
        let src = resolve(local, name, from)?;
        let dst = resolve(local, name, to)?;

        if let Some(parent) = dst.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        tokio::fs::rename(&src, &dst).await?;
        Ok(())
    }

    pub(crate) async fn stat(
        local: &LocalBackend,
        name: &str,
        path: &str,
    ) -> MicrosandboxResult<FsMetadata> {
        let full = resolve(local, name, path)?;
        let meta = tokio::fs::symlink_metadata(&full).await?;
        Ok(std_metadata_to_fs(&meta))
    }

    pub(crate) async fn exists(
        local: &LocalBackend,
        name: &str,
        path: &str,
    ) -> MicrosandboxResult<bool> {
        let full = resolve(local, name, path)?;
        Ok(tokio::fs::try_exists(&full).await.unwrap_or(false))
    }

    pub(crate) async fn read_stream(
        local: &LocalBackend,
        name: &str,
        path: &str,
    ) -> MicrosandboxResult<VolumeFsReadStream> {
        let full = resolve(local, name, path)?;
        let file = tokio::fs::File::open(&full).await?;
        Ok(VolumeFsReadStream::from_file(file))
    }

    pub(crate) async fn write_stream(
        local: &LocalBackend,
        name: &str,
        path: &str,
    ) -> MicrosandboxResult<VolumeFsWriteSink> {
        let full = resolve(local, name, path)?;
        if let Some(parent) = full.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let file = tokio::fs::File::create(&full).await?;
        Ok(VolumeFsWriteSink::from_file(file))
    }

    //----------------------------------------------------------------------------------------------
    // Functions: helpers
    //----------------------------------------------------------------------------------------------

    fn ensure_not_volume_root(root: &Path, path: &Path, operation: &str) -> MicrosandboxResult<()> {
        let canon_root = if root.exists() {
            root.canonicalize()
                .map_err(|e| MicrosandboxError::SandboxFsOps(format!("resolve root: {e}")))?
        } else {
            root.to_path_buf()
        };

        if path == canon_root {
            return Err(MicrosandboxError::SandboxFsOps(format!(
                "{operation} cannot target the volume root"
            )));
        }

        Ok(())
    }

    fn std_kind(meta: &std::fs::Metadata) -> FsEntryKind {
        if meta.is_file() {
            FsEntryKind::File
        } else if meta.is_dir() {
            FsEntryKind::Directory
        } else if meta.is_symlink() {
            FsEntryKind::Symlink
        } else {
            FsEntryKind::Other
        }
    }

    fn std_modified(meta: &std::fs::Metadata) -> Option<chrono::DateTime<chrono::Utc>> {
        meta.modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| chrono::DateTime::from_timestamp(d.as_secs() as i64, 0).unwrap_or_default())
    }

    fn std_accessed(meta: &std::fs::Metadata) -> Option<chrono::DateTime<chrono::Utc>> {
        meta.accessed()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| chrono::DateTime::from_timestamp(d.as_secs() as i64, 0).unwrap_or_default())
    }

    fn metadata_to_entry(path: &str, meta: &std::fs::Metadata) -> FsEntry {
        FsEntry {
            path: path.to_string(),
            kind: std_kind(meta),
            size: meta.len(),
            mode: metadata_mode(meta),
            uid: metadata_uid(meta),
            gid: metadata_gid(meta),
            accessed: std_accessed(meta),
            modified: std_modified(meta),
        }
    }

    fn std_created(meta: &std::fs::Metadata) -> Option<chrono::DateTime<chrono::Utc>> {
        meta.created()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| chrono::DateTime::from_timestamp(d.as_secs() as i64, 0).unwrap_or_default())
    }

    fn std_metadata_to_fs(meta: &std::fs::Metadata) -> FsMetadata {
        FsMetadata {
            kind: std_kind(meta),
            size: meta.len(),
            mode: metadata_mode(meta),
            uid: metadata_uid(meta),
            gid: metadata_gid(meta),
            readonly: meta.permissions().readonly(),
            accessed: std_accessed(meta),
            modified: std_modified(meta),
            created: std_created(meta),
        }
    }

    #[cfg(unix)]
    fn metadata_mode(meta: &std::fs::Metadata) -> u32 {
        use std::os::unix::fs::MetadataExt;

        meta.mode()
    }

    #[cfg(unix)]
    fn metadata_uid(meta: &std::fs::Metadata) -> u32 {
        use std::os::unix::fs::MetadataExt;

        meta.uid()
    }

    #[cfg(unix)]
    fn metadata_gid(meta: &std::fs::Metadata) -> u32 {
        use std::os::unix::fs::MetadataExt;

        meta.gid()
    }

    #[cfg(windows)]
    fn metadata_mode(meta: &std::fs::Metadata) -> u32 {
        match (meta.is_dir(), meta.permissions().readonly()) {
            (true, true) => 0o555,
            (true, false) => 0o755,
            (false, true) => 0o444,
            (false, false) => 0o644,
        }
    }

    #[cfg(windows)]
    fn metadata_uid(_meta: &std::fs::Metadata) -> u32 {
        0
    }

    #[cfg(windows)]
    fn metadata_gid(_meta: &std::fs::Metadata) -> u32 {
        0
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::LocalBackend;

    #[tokio::test]
    async fn remove_dir_rejects_slash_volume_root() {
        let (_temp, backend) = local_backend().await;
        local::write(&backend, "vol", "nested/file.txt", b"data")
            .await
            .unwrap();
        let root = backend.volume_path("vol");

        let err = local::remove(&backend, "vol", "/", true).await.unwrap_err();

        assert!(
            err.to_string().contains("volume root"),
            "unexpected error: {err}"
        );
        assert!(root.is_dir());
        assert!(root.join("nested/file.txt").is_file());
    }

    #[tokio::test]
    async fn remove_dir_rejects_empty_volume_root() {
        let (_temp, backend) = local_backend().await;
        local::write(&backend, "vol", "nested/file.txt", b"data")
            .await
            .unwrap();
        let root = backend.volume_path("vol");

        let err = local::remove(&backend, "vol", "", true).await.unwrap_err();

        assert!(
            err.to_string().contains("volume root"),
            "unexpected error: {err}"
        );
        assert!(root.is_dir());
        assert!(root.join("nested/file.txt").is_file());
    }

    #[tokio::test]
    async fn list_returns_slash_paths_anchored_at_request() {
        let (_temp, backend) = local_backend().await;
        local::write(&backend, "vol", "nested/inner/file.txt", b"data")
            .await
            .unwrap();

        let root_entries = local::list(&backend, "vol", "/").await.unwrap();
        assert_eq!(root_entries.len(), 1);
        assert_eq!(root_entries[0].path, "/nested");

        let nested = local::list(&backend, "vol", "/nested").await.unwrap();
        assert_eq!(nested.len(), 1);
        assert_eq!(nested[0].path, "/nested/inner");

        // Trailing slash and missing leading slash normalize to the same form.
        let inner = local::list(&backend, "vol", "nested/inner/").await.unwrap();
        assert_eq!(inner.len(), 1);
        assert_eq!(inner[0].path, "/nested/inner/file.txt");
    }

    #[tokio::test]
    async fn remove_dir_removes_child_directory() {
        let (_temp, backend) = local_backend().await;
        local::write(&backend, "vol", "nested/file.txt", b"data")
            .await
            .unwrap();
        let root = backend.volume_path("vol");

        local::remove(&backend, "vol", "nested", true)
            .await
            .unwrap();

        assert!(root.is_dir());
        assert!(!root.join("nested").exists());
    }

    async fn local_backend() -> (tempfile::TempDir, LocalBackend) {
        let temp = tempfile::tempdir().unwrap();
        let backend = LocalBackend::builder()
            .home(temp.path())
            .build()
            .await
            .unwrap();
        tokio::fs::create_dir_all(backend.volume_path("vol"))
            .await
            .unwrap();

        (temp, backend)
    }
}

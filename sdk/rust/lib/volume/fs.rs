//! Host-side filesystem operations on a named volume.
//!
//! Unlike [`SandboxFsOps`](crate::sandbox::fs::SandboxFsOps) which goes through the
//! agent protocol, [`VolumeFs`] reads + writes a volume's bytes directly. For
//! the local backend that is capability-scoped access to `volumes_dir/<name>/`; for
//! cloud it routes through msb-cloud HTTP.
//!
//! `VolumeFs` is a single type per D6.4 — no public variants. It borrows the
//! parent volume's `Arc<dyn Backend>` + name and dispatches through the
//! [`VolumeBackend`](crate::backend::VolumeBackend) trait.

use std::sync::Arc;

#[cfg(feature = "cloud")]
use std::pin::Pin;

use bytes::Bytes;
#[cfg(feature = "cloud")]
use futures::{Stream, StreamExt};
#[cfg(feature = "local")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "cloud")]
use tokio::sync::mpsc;
#[cfg(feature = "cloud")]
use tokio::task::JoinHandle;

use crate::backend::Backend;
use crate::{
    MicrosandboxResult,
    sandbox::fs::{FsEntry, FsMetadata},
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Chunk size for streaming volume reads (64 KiB).
#[cfg(feature = "local")]
const STREAM_CHUNK_SIZE: usize = 64 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Filesystem operations on a volume.
///
/// Borrows the parent volume's `Arc<dyn Backend>` + name and dispatches every
/// op through the [`VolumeBackend`](crate::backend::VolumeBackend) trait.
/// Local operations stay beneath an open volume directory; cloud operations use the authenticated volume API.
pub struct VolumeFs<'a> {
    backend: Arc<dyn Backend>,
    name: &'a str,
}

/// A streaming reader for local files or Cloud HTTP response bodies.
pub struct VolumeFsReadStream {
    inner: VolumeFsReadStreamInner,
}

enum VolumeFsReadStreamInner {
    #[cfg(feature = "local")]
    Local { file: tokio::fs::File, buf: Vec<u8> },
    #[cfg(feature = "cloud")]
    Cloud(Pin<Box<dyn Stream<Item = MicrosandboxResult<Bytes>> + Send>>),
}

impl VolumeFsReadStream {
    /// Construct from an already-opened file. Local impl only.
    #[cfg(feature = "local")]
    pub(crate) fn from_file(file: tokio::fs::File) -> Self {
        Self {
            inner: VolumeFsReadStreamInner::Local {
                file,
                buf: vec![0u8; STREAM_CHUNK_SIZE],
            },
        }
    }

    /// Construct from a cloud HTTP response stream.
    #[cfg(feature = "cloud")]
    pub(crate) fn from_stream(
        stream: Pin<Box<dyn Stream<Item = MicrosandboxResult<Bytes>> + Send>>,
    ) -> Self {
        Self {
            inner: VolumeFsReadStreamInner::Cloud(stream),
        }
    }
}

/// A streaming writer for local files or Cloud HTTP request bodies.
pub struct VolumeFsWriteSink {
    inner: VolumeFsWriteSinkInner,
}

enum VolumeFsWriteSinkInner {
    #[cfg(feature = "local")]
    Local(tokio::fs::File),
    #[cfg(feature = "cloud")]
    Cloud {
        tx: mpsc::Sender<Bytes>,
        completion: JoinHandle<MicrosandboxResult<()>>,
    },
}

impl VolumeFsWriteSink {
    /// Construct from an already-opened file. Local impl only.
    #[cfg(feature = "local")]
    pub(crate) fn from_file(file: tokio::fs::File) -> Self {
        Self {
            inner: VolumeFsWriteSinkInner::Local(file),
        }
    }

    /// Construct from a channel-backed cloud upload.
    #[cfg(feature = "cloud")]
    pub(crate) fn from_channel(
        tx: mpsc::Sender<Bytes>,
        completion: JoinHandle<MicrosandboxResult<()>>,
    ) -> Self {
        Self {
            inner: VolumeFsWriteSinkInner::Cloud { tx, completion },
        }
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
    /// trait for both local and Cloud volumes.
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
    /// trait for both local and Cloud volumes.
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
        // With neither backend enabled the private enum has no constructors. Match the value,
        // not its reference: references are considered inhabited even for an empty enum.
        #[cfg(not(any(feature = "local", feature = "cloud")))]
        match self.inner {}
        #[cfg(any(feature = "local", feature = "cloud"))]
        match &mut self.inner {
            #[cfg(feature = "local")]
            VolumeFsReadStreamInner::Local { file, buf } => {
                let n = file.read(buf).await?;
                if n == 0 {
                    Ok(None)
                } else {
                    Ok(Some(Bytes::copy_from_slice(&buf[..n])))
                }
            }
            #[cfg(feature = "cloud")]
            VolumeFsReadStreamInner::Cloud(stream) => stream.next().await.transpose(),
        }
    }

    /// Read the remaining file data into a single `Bytes` buffer.
    pub async fn collect(mut self) -> MicrosandboxResult<Bytes> {
        let mut data = Vec::new();
        while let Some(chunk) = self.recv().await? {
            data.extend_from_slice(&chunk);
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
        #[cfg(not(any(feature = "local", feature = "cloud")))]
        {
            let _ = data;
            match self.inner {}
        }
        #[cfg(any(feature = "local", feature = "cloud"))]
        match &mut self.inner {
            #[cfg(feature = "local")]
            VolumeFsWriteSinkInner::Local(file) => {
                file.write_all(data.as_ref()).await?;
                Ok(())
            }
            #[cfg(feature = "cloud")]
            VolumeFsWriteSinkInner::Cloud { tx, .. } => tx
                .send(Bytes::copy_from_slice(data.as_ref()))
                .await
                .map_err(|_| crate::MicrosandboxError::Custom("cloud upload closed".into())),
        }
    }

    /// Flush and close the file.
    pub async fn close(self) -> MicrosandboxResult<()> {
        match self.inner {
            #[cfg(feature = "local")]
            VolumeFsWriteSinkInner::Local(mut file) => {
                file.flush().await?;
                Ok(())
            }
            #[cfg(feature = "cloud")]
            VolumeFsWriteSinkInner::Cloud { tx, completion } => {
                drop(tx);
                completion.await.map_err(|error| {
                    crate::MicrosandboxError::Custom(format!("cloud upload task failed: {error}"))
                })?
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Module: local (free fn impls called by LocalBackend's VolumeBackend impl)
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "local")]
#[path = "fs_root.rs"]
mod rooted;

/// Internal capability adapter shared with native SDK bindings.
#[cfg(feature = "local")]
#[doc(hidden)]
pub use rooted::RootedVolumeFs;

#[cfg(feature = "local")]
pub(crate) mod local {
    //! Local FS ops keyed by `(volume_name, rel_path)`.
    //!
    //! Lives in a sub-module so the `LocalBackend` trait impl in
    //! `backend/volume.rs` can call into one place. Each function takes
    //! the `&LocalBackend` whose `volumes_dir` it should resolve against,
    //! so `with_backend` scoping and explicit `LocalBackend::builder()`
    //! constructions correctly route to the right host directory.

    use std::path::Path;

    use bytes::Bytes;
    use cap_std::fs::Metadata;

    use crate::{
        MicrosandboxError, MicrosandboxResult,
        backend::LocalBackend,
        sandbox::fs::{FsEntry, FsEntryKind, FsMetadata},
    };

    use super::{VolumeFsReadStream, VolumeFsWriteSink, rooted::RootedVolumeFs};

    // Run directory-relative filesystem calls off the async executor. Every operation
    // opens its root once and keeps that capability through resolution and use.
    async fn with_root<T: Send + 'static>(
        local: &LocalBackend,
        name: &str,
        operation: impl FnOnce(RootedVolumeFs) -> MicrosandboxResult<T> + Send + 'static,
    ) -> MicrosandboxResult<T> {
        crate::volume::validate_volume_name(name)?;
        let root_path = local.volume_path(name);
        tokio::task::spawn_blocking(move || operation(RootedVolumeFs::open(&root_path)?))
            .await
            .map_err(|error| {
                MicrosandboxError::SandboxFsOps(format!("volume filesystem task failed: {error}"))
            })?
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
        let path = path.to_owned();
        with_root(local, name, move |root| {
            Ok(Bytes::from(root.dir.read(root.resolve(&path)?)?))
        })
        .await
    }

    pub(crate) async fn read_to_string(
        local: &LocalBackend,
        name: &str,
        path: &str,
    ) -> MicrosandboxResult<String> {
        let path = path.to_owned();
        with_root(local, name, move |root| {
            Ok(root.dir.read_to_string(root.resolve(&path)?)?)
        })
        .await
    }

    pub(crate) async fn write(
        local: &LocalBackend,
        name: &str,
        path: &str,
        data: &[u8],
    ) -> MicrosandboxResult<()> {
        let path = path.to_owned();
        let data = data.to_vec();
        with_root(local, name, move |root| {
            let path = root.resolve(&path)?;
            root.ensure_parent(&path)?;
            root.dir.write(path, data)?;
            Ok(())
        })
        .await
    }

    pub(crate) async fn list(
        local: &LocalBackend,
        name: &str,
        path: &str,
    ) -> MicrosandboxResult<Vec<FsEntry>> {
        let path = path.to_owned();
        with_root(local, name, move |root| {
            // Keep the public slash-separated spelling separate from host path handling.
            let base = normalize_slash_path(&path);
            let dir = root.dir.read_dir(root.resolve(&path)?)?;
            let mut entries = Vec::new();
            for entry in dir {
                let entry = entry?;
                let entry_name = entry.file_name();
                let entry_path = if base == "/" {
                    format!("/{}", entry_name.to_string_lossy())
                } else {
                    format!("{base}/{}", entry_name.to_string_lossy())
                };
                match entry.metadata() {
                    Ok(meta) => entries.push(metadata_to_entry(&entry_path, &meta)),
                    Err(_) => entries.push(FsEntry {
                        path: entry_path,
                        kind: FsEntryKind::Other,
                        size: 0,
                        mode: 0,
                        uid: 0,
                        gid: 0,
                        accessed: None,
                        modified: None,
                    }),
                }
            }
            Ok(entries)
        })
        .await
    }

    pub(crate) async fn mkdir(
        local: &LocalBackend,
        name: &str,
        path: &str,
    ) -> MicrosandboxResult<()> {
        let path = path.to_owned();
        with_root(local, name, move |root| {
            root.dir.create_dir_all(root.resolve(&path)?)?;
            Ok(())
        })
        .await
    }

    pub(crate) async fn remove(
        local: &LocalBackend,
        name: &str,
        path: &str,
        recursive: bool,
    ) -> MicrosandboxResult<()> {
        let path = path.to_owned();
        with_root(local, name, move |root| {
            let path = root.resolve_entry(&path)?;
            ensure_not_volume_root(&path, if recursive { "remove_dir" } else { "remove" })?;
            if recursive {
                root.remove_dir_all(&path)?;
            } else {
                root.dir.remove_file(path)?;
            }
            Ok(())
        })
        .await
    }

    pub(crate) async fn copy(
        local: &LocalBackend,
        name: &str,
        from: &str,
        to: &str,
    ) -> MicrosandboxResult<()> {
        let from = from.to_owned();
        let to = to.to_owned();
        with_root(local, name, move |root| {
            let source = root.resolve(&from)?;
            let destination = root.resolve(&to)?;
            root.ensure_parent(&destination)?;
            root.dir.copy(source, &root.dir, destination)?;
            Ok(())
        })
        .await
    }

    pub(crate) async fn rename(
        local: &LocalBackend,
        name: &str,
        from: &str,
        to: &str,
    ) -> MicrosandboxResult<()> {
        let from = from.to_owned();
        let to = to.to_owned();
        with_root(local, name, move |root| {
            let source = root.resolve_entry(&from)?;
            let destination = root.resolve_entry(&to)?;
            ensure_not_volume_root(&source, "rename")?;
            ensure_not_volume_root(&destination, "rename")?;
            root.ensure_parent(&destination)?;
            root.dir.rename(source, &root.dir, destination)?;
            Ok(())
        })
        .await
    }

    pub(crate) async fn stat(
        local: &LocalBackend,
        name: &str,
        path: &str,
    ) -> MicrosandboxResult<FsMetadata> {
        let path = path.to_owned();
        with_root(local, name, move |root| {
            Ok(std_metadata_to_fs(
                &root.dir.symlink_metadata(root.resolve_entry(&path)?)?,
            ))
        })
        .await
    }

    pub(crate) async fn exists(
        local: &LocalBackend,
        name: &str,
        path: &str,
    ) -> MicrosandboxResult<bool> {
        let path = path.to_owned();
        with_root(local, name, move |root| {
            // Only absence is false: confinement and permission failures remain errors.
            Ok(root.dir.try_exists(root.resolve(&path)?)?)
        })
        .await
    }

    pub(crate) async fn read_stream(
        local: &LocalBackend,
        name: &str,
        path: &str,
    ) -> MicrosandboxResult<VolumeFsReadStream> {
        let path = path.to_owned();
        let file = with_root(local, name, move |root| {
            Ok(root.dir.open(root.resolve(&path)?)?.into_std())
        })
        .await?;
        Ok(VolumeFsReadStream::from_file(tokio::fs::File::from_std(
            file,
        )))
    }

    pub(crate) async fn write_stream(
        local: &LocalBackend,
        name: &str,
        path: &str,
    ) -> MicrosandboxResult<VolumeFsWriteSink> {
        let path = path.to_owned();
        let file = with_root(local, name, move |root| {
            let path = root.resolve(&path)?;
            root.ensure_parent(&path)?;
            Ok(root.dir.create(path)?.into_std())
        })
        .await?;
        Ok(VolumeFsWriteSink::from_file(tokio::fs::File::from_std(
            file,
        )))
    }

    fn ensure_not_volume_root(path: &Path, operation: &str) -> MicrosandboxResult<()> {
        // A missing suffix can retain `..` to preserve OS semantics. Check its
        // textual destination too, before a write creates those missing parents.
        let mut depth = 0usize;
        for component in path.components() {
            match component {
                std::path::Component::Normal(_) => depth += 1,
                std::path::Component::ParentDir => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
        if depth == 0 {
            return Err(MicrosandboxError::SandboxFsOps(format!(
                "{operation} cannot target the volume root"
            )));
        }
        Ok(())
    }

    fn std_kind(meta: &Metadata) -> FsEntryKind {
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

    fn std_modified(meta: &Metadata) -> Option<chrono::DateTime<chrono::Utc>> {
        meta.modified()
            .ok()
            .and_then(|t| t.into_std().duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| chrono::DateTime::from_timestamp(d.as_secs() as i64, 0).unwrap_or_default())
    }

    fn std_accessed(meta: &Metadata) -> Option<chrono::DateTime<chrono::Utc>> {
        meta.accessed()
            .ok()
            .and_then(|t| t.into_std().duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| chrono::DateTime::from_timestamp(d.as_secs() as i64, 0).unwrap_or_default())
    }

    fn metadata_to_entry(path: &str, meta: &Metadata) -> FsEntry {
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

    fn std_created(meta: &Metadata) -> Option<chrono::DateTime<chrono::Utc>> {
        meta.created()
            .ok()
            .and_then(|t| t.into_std().duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| chrono::DateTime::from_timestamp(d.as_secs() as i64, 0).unwrap_or_default())
    }

    fn std_metadata_to_fs(meta: &Metadata) -> FsMetadata {
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
    fn metadata_mode(meta: &Metadata) -> u32 {
        use cap_std::fs::MetadataExt;

        meta.mode()
    }

    #[cfg(unix)]
    fn metadata_uid(meta: &Metadata) -> u32 {
        use cap_std::fs::MetadataExt;

        meta.uid()
    }

    #[cfg(unix)]
    fn metadata_gid(meta: &Metadata) -> u32 {
        use cap_std::fs::MetadataExt;

        meta.gid()
    }

    #[cfg(windows)]
    fn metadata_mode(meta: &Metadata) -> u32 {
        match (meta.is_dir(), meta.permissions().readonly()) {
            (true, true) => 0o555,
            (true, false) => 0o755,
            (false, true) => 0o444,
            (false, false) => 0o644,
        }
    }

    #[cfg(windows)]
    fn metadata_uid(_meta: &Metadata) -> u32 {
        0
    }

    #[cfg(windows)]
    fn metadata_gid(_meta: &Metadata) -> u32 {
        0
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, feature = "local"))]
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

    #[tokio::test]
    async fn all_operations_reject_missing_suffix_traversal() {
        let (temp, backend) = local_backend().await;
        let outside = temp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("sentinel"), b"outside").unwrap();
        local::write(&backend, "vol", "source", b"inside")
            .await
            .unwrap();
        for path in ["../outside/sentinel", "missing/../../../outside/sentinel"] {
            assert!(local::read(&backend, "vol", path).await.is_err());
            assert!(local::read_to_string(&backend, "vol", path).await.is_err());
            assert!(local::read_stream(&backend, "vol", path).await.is_err());
            assert!(
                local::write(&backend, "vol", path, b"changed")
                    .await
                    .is_err()
            );
            assert!(local::write_stream(&backend, "vol", path).await.is_err());
            assert!(local::list(&backend, "vol", path).await.is_err());
            assert!(local::mkdir(&backend, "vol", path).await.is_err());
            assert!(local::stat(&backend, "vol", path).await.is_err());
            assert!(local::exists(&backend, "vol", path).await.is_err());
            assert!(local::remove(&backend, "vol", path, false).await.is_err());
            assert!(local::remove(&backend, "vol", path, true).await.is_err());
            assert!(
                local::copy(&backend, "vol", path, "destination")
                    .await
                    .is_err()
            );
            assert!(local::copy(&backend, "vol", "source", path).await.is_err());
            assert!(
                local::rename(&backend, "vol", path, "destination")
                    .await
                    .is_err()
            );
            assert!(
                local::rename(&backend, "vol", "source", path)
                    .await
                    .is_err()
            );
        }
        assert_eq!(std::fs::read(outside.join("sentinel")).unwrap(), b"outside");
        assert_eq!(
            local::read(&backend, "vol", "source").await.unwrap(),
            b"inside"[..]
        );
        assert!(!backend.volume_path("vol").join("missing").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn missing_parent_components_keep_os_lookup_semantics() {
        let (_temp, backend) = local_backend().await;
        local::write(&backend, "vol", "file", b"inside")
            .await
            .unwrap();
        assert!(
            local::read(&backend, "vol", "missing/../file")
                .await
                .is_err()
        );
        assert!(!backend.volume_path("vol").join("missing").exists());
        local::write(&backend, "vol", "missing/../file", b"updated")
            .await
            .unwrap();
        assert!(backend.volume_path("vol").join("missing").is_dir());
        assert_eq!(
            local::read(&backend, "vol", "file").await.unwrap(),
            b"updated"[..]
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn missing_parent_components_keep_windows_lookup_semantics() {
        let (_temp, backend) = local_backend().await;
        local::write(&backend, "vol", "file", b"inside")
            .await
            .unwrap();
        // Win32 normalizes this spelling before opening it; unlike Unix, the
        // canceled component need not exist. Preserve the platform's API behavior.
        let expected = std::fs::read(backend.volume_path("vol").join("missing/../file")).unwrap();
        assert_eq!(
            local::read(&backend, "vol", "missing/../file")
                .await
                .unwrap(),
            expected
        );
        local::write(&backend, "vol", "missing/../file", b"updated")
            .await
            .unwrap();
        assert_eq!(
            local::read(&backend, "vol", "file").await.unwrap(),
            b"updated"[..]
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn list_reports_links_without_reading_external_target_metadata() {
        use std::os::unix::fs::symlink;

        let (temp, backend) = local_backend().await;
        let outside = temp.path().join("outside");
        std::fs::write(&outside, vec![0u8; 8192]).unwrap();
        let link = backend.volume_path("vol").join("link");
        symlink(&outside, &link).unwrap();
        let entries = local::list(&backend, "vol", "/").await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, crate::sandbox::fs::FsEntryKind::Symlink);
        assert_eq!(
            entries[0].size,
            std::fs::symlink_metadata(link).unwrap().len()
        );
        assert_ne!(entries[0].size, 8192);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlinks_cannot_read_or_mutate_external_targets() {
        use std::os::unix::fs::symlink;

        let (temp, backend) = local_backend().await;
        let outside = temp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("sentinel"), b"outside").unwrap();
        let root = backend.volume_path("vol");
        symlink(&outside, root.join("link")).unwrap();
        symlink(outside.join("missing"), root.join("dangling")).unwrap();
        local::write(&backend, "vol", "source", b"inside")
            .await
            .unwrap();

        for path in ["link/sentinel", "link/new/child", "dangling/child"] {
            assert!(local::read(&backend, "vol", path).await.is_err());
            assert!(local::read_to_string(&backend, "vol", path).await.is_err());
            assert!(local::read_stream(&backend, "vol", path).await.is_err());
            assert!(
                local::write(&backend, "vol", path, b"changed")
                    .await
                    .is_err()
            );
            assert!(local::write_stream(&backend, "vol", path).await.is_err());
            assert!(local::list(&backend, "vol", path).await.is_err());
            assert!(local::mkdir(&backend, "vol", path).await.is_err());
            assert!(local::stat(&backend, "vol", path).await.is_err());
            assert!(local::exists(&backend, "vol", path).await.is_err());
            assert!(local::remove(&backend, "vol", path, false).await.is_err());
            assert!(local::remove(&backend, "vol", path, true).await.is_err());
            assert!(
                local::copy(&backend, "vol", path, "destination")
                    .await
                    .is_err()
            );
            assert!(local::copy(&backend, "vol", "source", path).await.is_err());
            assert!(
                local::rename(&backend, "vol", path, "destination")
                    .await
                    .is_err()
            );
            assert!(
                local::rename(&backend, "vol", "source", path)
                    .await
                    .is_err()
            );
        }
        assert_eq!(std::fs::read(outside.join("sentinel")).unwrap(), b"outside");
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 1);
        assert!(!root.join("destination").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn in_volume_links_and_parent_components_keep_their_meaning() {
        use std::os::unix::fs::symlink;

        let (_temp, backend) = local_backend().await;
        let root = backend.volume_path("vol");
        local::write(&backend, "vol", "/nested/deeper/file", b"inside")
            .await
            .unwrap();
        local::write(&backend, "vol", "/nested/peer", b"peer")
            .await
            .unwrap();
        symlink("nested/deeper", root.join("relative")).unwrap();
        symlink(root.join("nested/deeper"), root.join("absolute")).unwrap();
        symlink("nested/missing", root.join("dangling-inside")).unwrap();
        for path in [
            "relative/../peer",
            "absolute/../peer",
            "/nested/deeper/../peer",
        ] {
            assert_eq!(
                local::read(&backend, "vol", path).await.unwrap(),
                b"peer"[..]
            );
        }
        local::write(&backend, "vol", "dangling-inside", b"created")
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(root.join("nested/missing")).unwrap(),
            b"created"
        );
        assert!(!local::exists(&backend, "vol", "missing").await.unwrap());
        assert_eq!(
            local::stat(&backend, "vol", "absolute/file")
                .await
                .unwrap()
                .size,
            6
        );
        local::copy(&backend, "vol", "absolute/file", "copied/new/file")
            .await
            .unwrap();
        local::rename(&backend, "vol", "copied/new/file", "renamed/new/file")
            .await
            .unwrap();
        assert_eq!(
            local::read(&backend, "vol", "renamed/new/file")
                .await
                .unwrap(),
            b"inside"[..]
        );
        local::remove(&backend, "vol", "renamed", true)
            .await
            .unwrap();
        assert!(!root.join("renamed").exists());
        // Entry operations preserve the link itself, including a missing target.
        symlink("nested/missing-target", root.join("final-link")).unwrap();
        assert_eq!(
            local::stat(&backend, "vol", "final-link")
                .await
                .unwrap()
                .kind,
            crate::sandbox::fs::FsEntryKind::Symlink
        );
        local::rename(&backend, "vol", "final-link", "moved-link")
            .await
            .unwrap();
        assert!(
            root.join("moved-link")
                .symlink_metadata()
                .unwrap()
                .is_symlink()
        );
        local::remove(&backend, "vol", "moved-link", false)
            .await
            .unwrap();
        assert!(root.join("moved-link").symlink_metadata().is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn streams_keep_opened_file_after_parent_is_replaced() {
        use std::os::unix::fs::symlink;

        let (temp, backend) = local_backend().await;
        let root = backend.volume_path("vol");
        let outside = temp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("read"), b"outside").unwrap();
        std::fs::write(outside.join("write"), b"outside").unwrap();
        local::write(&backend, "vol", "nested/read", b"inside")
            .await
            .unwrap();
        let reader = local::read_stream(&backend, "vol", "nested/read")
            .await
            .unwrap();
        let mut writer = local::write_stream(&backend, "vol", "nested/write")
            .await
            .unwrap();
        std::fs::rename(root.join("nested"), root.join("moved")).unwrap();
        symlink(&outside, root.join("nested")).unwrap();
        assert_eq!(reader.collect().await.unwrap(), b"inside"[..]);
        writer.write(b"new inside").await.unwrap();
        writer.close().await.unwrap();
        assert_eq!(
            std::fs::read(root.join("moved/write")).unwrap(),
            b"new inside"
        );
        assert_eq!(std::fs::read(outside.join("write")).unwrap(), b"outside");
    }

    #[tokio::test]
    async fn invalid_volume_names_cannot_choose_a_different_root() {
        let (_temp, backend) = local_backend().await;
        for name in ["..", ".", "../vol", "/tmp"] {
            assert!(local::write(&backend, name, "file", b"data").await.is_err());
            assert!(local::read(&backend, name, "file").await.is_err());
        }
    }

    #[tokio::test]
    async fn rename_and_recursive_remove_cannot_target_root_aliases() {
        let (_temp, backend) = local_backend().await;
        local::write(&backend, "vol", "nested/file", b"data")
            .await
            .unwrap();
        let paths = ["", "/", ".", "nested/..", "missing/.."];
        for path in paths {
            assert!(local::remove(&backend, "vol", path, true).await.is_err());
            assert!(local::rename(&backend, "vol", path, "moved").await.is_err());
            assert!(
                local::rename(&backend, "vol", "nested", path)
                    .await
                    .is_err()
            );
        }
        assert_eq!(
            local::read(&backend, "vol", "nested/file").await.unwrap(),
            b"data"[..]
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn relocated_roots_and_alternate_internal_links_remain_usable() {
        use std::os::unix::fs::symlink;
        let (temp, backend) = local_backend().await;
        let root = backend.volume_path("vol");
        let moved = temp.path().join("relocated");
        std::fs::rename(&root, &moved).unwrap();
        symlink(&moved, &root).unwrap();
        let alias = temp.path().join("shortcut");
        symlink(&moved, &alias).unwrap();
        symlink(alias.join("report"), moved.join("report-link")).unwrap();
        local::write(&backend, "vol", "report-link", b"inside")
            .await
            .unwrap();
        assert_eq!(
            local::read(&backend, "vol", "report-link").await.unwrap(),
            b"inside"[..]
        );
        symlink(".", moved.join("root-link")).unwrap();
        local::rename(&backend, "vol", "root-link", "renamed-link")
            .await
            .unwrap();
        local::remove(&backend, "vol", "renamed-link", false)
            .await
            .unwrap();
        assert_eq!(std::fs::read(moved.join("report")).unwrap(), b"inside");
    }

    async fn local_backend() -> (tempfile::TempDir, LocalBackend) {
        let temp = tempfile::tempdir().unwrap();
        let backend = LocalBackend::builder()
            .config_path(temp.path().join("config.json"))
            .managed_config_path(temp.path().join("managed.json"))
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

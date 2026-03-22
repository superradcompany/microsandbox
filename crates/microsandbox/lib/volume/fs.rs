//! Direct host-side filesystem operations on a named volume.
//!
//! Unlike [`SandboxFs`](crate::sandbox::fs::SandboxFs) which operates through the
//! agent protocol, [`VolumeFs`] operates directly on the host-side volume
//! directory using `tokio::fs`.

use std::path::{Path, PathBuf};

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    MicrosandboxError, MicrosandboxResult,
    sandbox::fs::{FsEntry, FsEntryKind, FsMetadata},
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Filesystem operations on a volume's host-side directory.
pub struct VolumeFs<'a> {
    root: VolumeRoot<'a>,
}

/// Internal path storage — borrowed from a `Volume` or owned from a `VolumeHandle`.
enum VolumeRoot<'a> {
    Borrowed(&'a Path),
    Owned(PathBuf),
}

/// Chunk size for streaming volume reads (64 KiB).
const STREAM_CHUNK_SIZE: usize = 64 * 1024;

/// A streaming reader for file data from a volume's host-side directory.
pub struct VolumeFsReadStream {
    file: tokio::fs::File,
    buf: Vec<u8>,
}

/// A streaming writer for file data to a volume's host-side directory.
pub struct VolumeFsWriteSink {
    file: tokio::fs::File,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<'a> VolumeFs<'a> {
    /// Create a volume filesystem handle from a borrowed path.
    pub(crate) fn from_path_ref(path: &'a Path) -> Self {
        Self {
            root: VolumeRoot::Borrowed(path),
        }
    }

    /// Create a volume filesystem handle from an owned path.
    pub(crate) fn from_path(path: PathBuf) -> Self {
        Self {
            root: VolumeRoot::Owned(path),
        }
    }

    /// Get the root path of the volume.
    fn root_path(&self) -> &Path {
        match &self.root {
            VolumeRoot::Borrowed(p) => p,
            VolumeRoot::Owned(p) => p,
        }
    }

    //----------------------------------------------------------------------------------------------
    // Read Operations
    //----------------------------------------------------------------------------------------------

    /// Read an entire file into memory as raw bytes.
    pub async fn read(&self, path: &str) -> MicrosandboxResult<Bytes> {
        let full = self.resolve(path)?;
        let data = tokio::fs::read(&full).await?;
        Ok(Bytes::from(data))
    }

    /// Read an entire file into memory as a UTF-8 string.
    pub async fn read_to_string(&self, path: &str) -> MicrosandboxResult<String> {
        let full = self.resolve(path)?;
        let data = tokio::fs::read_to_string(&full).await?;
        Ok(data)
    }

    /// Read a file with streaming. Returns a [`VolumeFsReadStream`] that
    /// yields chunks of bytes.
    pub async fn read_stream(&self, path: &str) -> MicrosandboxResult<VolumeFsReadStream> {
        let full = self.resolve(path)?;
        let file = tokio::fs::File::open(&full).await?;
        Ok(VolumeFsReadStream {
            file,
            buf: vec![0u8; STREAM_CHUNK_SIZE],
        })
    }

    //----------------------------------------------------------------------------------------------
    // Write Operations
    //----------------------------------------------------------------------------------------------

    /// Write data to a file, creating parent directories as needed.
    /// Overwrites if the file already exists.
    pub async fn write(&self, path: &str, data: impl AsRef<[u8]>) -> MicrosandboxResult<()> {
        let full = self.resolve(path)?;

        // Ensure parent directory exists.
        if let Some(parent) = full.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        tokio::fs::write(&full, data.as_ref()).await?;
        Ok(())
    }

    /// Write to a file with streaming. Returns a [`VolumeFsWriteSink`] that
    /// accepts chunks of bytes. Creates parent directories as needed.
    pub async fn write_stream(&self, path: &str) -> MicrosandboxResult<VolumeFsWriteSink> {
        let full = self.resolve(path)?;

        if let Some(parent) = full.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let file = tokio::fs::File::create(&full).await?;
        Ok(VolumeFsWriteSink { file })
    }

    //----------------------------------------------------------------------------------------------
    // Directory Operations
    //----------------------------------------------------------------------------------------------

    /// List the immediate children of a directory (non-recursive).
    /// Each entry includes the path, kind, size, permissions, and modification time.
    pub async fn list(&self, path: &str) -> MicrosandboxResult<Vec<FsEntry>> {
        let full = self.resolve(path)?;
        let mut dir = tokio::fs::read_dir(&full).await?;
        let mut entries = Vec::new();

        while let Some(entry) = dir.next_entry().await? {
            let entry_path = entry.path();
            let rel_path = entry_path
                .strip_prefix(self.root_path())
                .unwrap_or(&entry_path);

            match entry.metadata().await {
                Ok(meta) => {
                    entries.push(metadata_to_entry(
                        &format!("/{}", rel_path.display()),
                        &meta,
                    ));
                }
                Err(_) => {
                    entries.push(FsEntry {
                        path: format!("/{}", rel_path.display()),
                        kind: FsEntryKind::Other,
                        size: 0,
                        mode: 0,
                        modified: None,
                    });
                }
            }
        }

        Ok(entries)
    }

    /// Create a directory (and parents).
    pub async fn mkdir(&self, path: &str) -> MicrosandboxResult<()> {
        let full = self.resolve(path)?;
        tokio::fs::create_dir_all(&full).await?;
        Ok(())
    }

    /// Remove a directory recursively.
    pub async fn remove_dir(&self, path: &str) -> MicrosandboxResult<()> {
        let full = self.resolve(path)?;
        tokio::fs::remove_dir_all(&full).await?;
        Ok(())
    }

    //----------------------------------------------------------------------------------------------
    // File Operations
    //----------------------------------------------------------------------------------------------

    /// Delete a single file. Use [`remove_dir`](Self::remove_dir) for directories.
    pub async fn remove(&self, path: &str) -> MicrosandboxResult<()> {
        let full = self.resolve(path)?;
        tokio::fs::remove_file(&full).await?;
        Ok(())
    }

    /// Copy a file within the volume.
    pub async fn copy(&self, from: &str, to: &str) -> MicrosandboxResult<()> {
        let src = self.resolve(from)?;
        let dst = self.resolve(to)?;

        if let Some(parent) = dst.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        tokio::fs::copy(&src, &dst).await?;
        Ok(())
    }

    /// Rename/move a file or directory.
    pub async fn rename(&self, from: &str, to: &str) -> MicrosandboxResult<()> {
        let src = self.resolve(from)?;
        let dst = self.resolve(to)?;

        if let Some(parent) = dst.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        tokio::fs::rename(&src, &dst).await?;
        Ok(())
    }

    //----------------------------------------------------------------------------------------------
    // Metadata
    //----------------------------------------------------------------------------------------------

    /// Get file/directory metadata.
    pub async fn stat(&self, path: &str) -> MicrosandboxResult<FsMetadata> {
        let full = self.resolve(path)?;
        let meta = tokio::fs::symlink_metadata(&full).await?;
        Ok(std_metadata_to_fs(&meta))
    }

    /// Check whether a file or directory exists at the given path.
    /// Returns `false` (not an error) if the path is absent.
    pub async fn exists(&self, path: &str) -> MicrosandboxResult<bool> {
        let full = self.resolve(path)?;
        Ok(tokio::fs::try_exists(&full).await.unwrap_or(false))
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Helpers
//--------------------------------------------------------------------------------------------------

impl VolumeFs<'_> {
    /// Resolve a relative path against the volume root, preventing path traversal.
    fn resolve(&self, path: &str) -> MicrosandboxResult<PathBuf> {
        let root = self.root_path();

        // Strip leading slash for joining.
        let clean = path.strip_prefix('/').unwrap_or(path);

        let joined = root.join(clean);

        // Canonicalize what exists, then check prefix. If the path doesn't exist
        // yet (for writes), canonicalize the parent and verify.
        let canonical = if joined.exists() {
            joined
                .canonicalize()
                .map_err(|e| MicrosandboxError::SandboxFs(format!("resolve path: {e}")))?
        } else {
            // Find the deepest existing ancestor.
            let mut ancestor = joined.as_path();
            loop {
                if let Some(parent) = ancestor.parent() {
                    if parent.exists() {
                        let canon_parent = parent.canonicalize().map_err(|e| {
                            MicrosandboxError::SandboxFs(format!("resolve parent: {e}"))
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
                .map_err(|e| MicrosandboxError::SandboxFs(format!("resolve root: {e}")))?
        } else {
            root.to_path_buf()
        };

        if !canonical.starts_with(&canon_root) {
            return Err(MicrosandboxError::SandboxFs(
                "path traversal outside volume root".into(),
            ));
        }

        Ok(canonical)
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
// Functions
//--------------------------------------------------------------------------------------------------

/// Determine the `FsEntryKind` from `std::fs::Metadata`.
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

/// Extract the modification time from `std::fs::Metadata`.
fn std_modified(meta: &std::fs::Metadata) -> Option<chrono::DateTime<chrono::Utc>> {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| chrono::DateTime::from_timestamp(d.as_secs() as i64, 0).unwrap_or_default())
}

/// Convert `std::fs::Metadata` to an `FsEntry`.
fn metadata_to_entry(path: &str, meta: &std::fs::Metadata) -> FsEntry {
    use std::os::unix::fs::MetadataExt;

    FsEntry {
        path: path.to_string(),
        kind: std_kind(meta),
        size: meta.len(),
        mode: meta.mode(),
        modified: std_modified(meta),
    }
}

/// Extract the creation time from `std::fs::Metadata`.
fn std_created(meta: &std::fs::Metadata) -> Option<chrono::DateTime<chrono::Utc>> {
    meta.created()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| chrono::DateTime::from_timestamp(d.as_secs() as i64, 0).unwrap_or_default())
}

/// Convert `std::fs::Metadata` to `FsMetadata`.
fn std_metadata_to_fs(meta: &std::fs::Metadata) -> FsMetadata {
    use std::os::unix::fs::MetadataExt;

    FsMetadata {
        kind: std_kind(meta),
        size: meta.len(),
        mode: meta.mode(),
        readonly: meta.permissions().readonly(),
        modified: std_modified(meta),
        created: std_created(meta),
    }
}

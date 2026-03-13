//! Direct host-side filesystem operations on a named volume.
//!
//! Unlike [`SandboxFs`](crate::sandbox::fs::SandboxFs) which operates through the
//! agent protocol, [`VolumeFs`] operates directly on the host-side volume
//! directory using `tokio::fs`.

use std::path::{Path, PathBuf};

use bytes::Bytes;

use crate::{
    MicrosandboxError, MicrosandboxResult,
    sandbox::fs::{FsEntry, FsEntryKind, FsMetadata},
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Filesystem operations on a volume's host-side directory.
pub struct VolumeFs<'a> {
    volume: &'a super::Volume,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<'a> VolumeFs<'a> {
    /// Create a new volume filesystem handle.
    pub(crate) fn new(volume: &'a super::Volume) -> Self {
        Self { volume }
    }

    //----------------------------------------------------------------------------------------------
    // Read Operations
    //----------------------------------------------------------------------------------------------

    /// Read a file to bytes.
    pub async fn read(&self, path: &str) -> MicrosandboxResult<Bytes> {
        let full = self.resolve(path)?;
        let data = tokio::fs::read(&full).await?;
        Ok(Bytes::from(data))
    }

    /// Read a file to string.
    pub async fn read_to_string(&self, path: &str) -> MicrosandboxResult<String> {
        let full = self.resolve(path)?;
        let data = tokio::fs::read_to_string(&full).await?;
        Ok(data)
    }

    //----------------------------------------------------------------------------------------------
    // Write Operations
    //----------------------------------------------------------------------------------------------

    /// Write bytes to a file.
    pub async fn write(&self, path: &str, data: impl AsRef<[u8]>) -> MicrosandboxResult<()> {
        let full = self.resolve(path)?;

        // Ensure parent directory exists.
        if let Some(parent) = full.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        tokio::fs::write(&full, data.as_ref()).await?;
        Ok(())
    }

    //----------------------------------------------------------------------------------------------
    // Directory Operations
    //----------------------------------------------------------------------------------------------

    /// List directory contents.
    pub async fn list(&self, path: &str) -> MicrosandboxResult<Vec<FsEntry>> {
        let full = self.resolve(path)?;
        let mut dir = tokio::fs::read_dir(&full).await?;
        let mut entries = Vec::new();

        while let Some(entry) = dir.next_entry().await? {
            let entry_path = entry.path();
            let rel_path = entry_path
                .strip_prefix(self.volume.path())
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

    /// Remove a file.
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

    /// Check if a path exists.
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
        let root = self.volume.path();

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

/// Convert `std::fs::Metadata` to `FsMetadata`.
fn std_metadata_to_fs(meta: &std::fs::Metadata) -> FsMetadata {
    use std::os::unix::fs::MetadataExt;

    FsMetadata {
        kind: std_kind(meta),
        size: meta.len(),
        mode: meta.mode(),
        readonly: meta.permissions().readonly(),
        modified: std_modified(meta),
    }
}

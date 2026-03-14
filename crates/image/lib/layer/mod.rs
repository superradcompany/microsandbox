//! Layer download, extraction, and management.

pub(crate) mod extraction;
pub(crate) mod index;

use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::fd::AsRawFd,
    path::{Path, PathBuf},
};

use oci_client::client::{BlobResponse, SizedStream};
use sha2::{Digest as Sha2Digest, Sha256};

use crate::{
    digest::Digest,
    error::{ImageError, ImageResult},
    store::{self, GlobalCache},
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Xattr key for stat virtualization.
pub(crate) const OVERRIDE_XATTR_KEY: &str = "user.containers.override_stat";

/// File type mask.
pub(crate) const S_IFMT: u32 = libc::S_IFMT as u32;

/// Symlink file type bits.
pub(crate) const S_IFLNK: u32 = libc::S_IFLNK as u32;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A single OCI layer handle with download/extraction state.
pub(crate) struct Layer {
    /// Compressed layer digest (from manifest).
    pub digest: Digest,
    /// Cached paths derived from the global cache.
    tar_path: PathBuf,
    extracted_dir: PathBuf,
    extracting_dir: PathBuf,
    index_path: PathBuf,
    lock_path: PathBuf,
    download_lock_path: PathBuf,
    part_path: PathBuf,
}

enum DownloadStart {
    Fresh,
    Resume(u64),
    Complete,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Layer {
    /// Create a new layer handle.
    pub fn new(digest: Digest, cache: &GlobalCache) -> Self {
        Self {
            tar_path: cache.tar_path(&digest),
            extracted_dir: cache.extracted_dir(&digest),
            extracting_dir: cache.extracting_dir(&digest),
            index_path: cache.index_path(&digest),
            lock_path: cache.lock_path(&digest),
            download_lock_path: cache.download_lock_path(&digest),
            part_path: cache.part_path(&digest),
            digest,
        }
    }

    /// Path to the extracted layer directory.
    pub fn extracted_dir(&self) -> PathBuf {
        self.extracted_dir.clone()
    }

    /// Check if this layer is already fully extracted.
    pub fn is_extracted(&self) -> bool {
        self.extracted_dir.join(store::COMPLETE_MARKER).exists()
    }

    /// Download the layer blob to the cache.
    ///
    /// Uses cross-process `flock()` to prevent races. Supports resumption
    /// via partial `.part` files.
    pub async fn download(
        &self,
        client: &oci_client::Client,
        image_ref: &oci_client::Reference,
        expected_size: Option<u64>,
        force: bool,
        progress: Option<&crate::progress::PullProgressSender>,
        layer_index: usize,
    ) -> ImageResult<()> {
        let tar_path = &self.tar_path;
        let part_path = &self.part_path;

        // Acquire cross-process download lock.
        let lock_file = open_lock_file(&self.download_lock_path)?;
        flock_exclusive(&lock_file)?;
        let _guard = scopeguard::guard(lock_file, |f| {
            let _ = flock_unlock(&f);
        });

        if force {
            remove_file_if_exists(tar_path)?;
            remove_file_if_exists(part_path)?;
        }

        // Re-check after lock — another process may have completed the download.
        if tar_path.exists() {
            if let Some(expected) = expected_size {
                if let Ok(meta) = std::fs::metadata(tar_path)
                    && meta.len() == expected
                {
                    return Ok(());
                }
            } else if let Ok(meta) = std::fs::metadata(tar_path)
                && meta.len() > 0
            {
                return Ok(());
            }
        }

        // Stream the blob to a .part file.
        let digest_display = self.digest.to_string();
        let digest_str: std::sync::Arc<str> = digest_display.as_str().into();
        let expected_hex = self.digest.hex();

        let download_start = determine_download_start(part_path, expected_size, expected_hex)?;
        if matches!(download_start, DownloadStart::Complete) {
            std::fs::rename(part_path, tar_path).map_err(|e| ImageError::Cache {
                path: tar_path.clone(),
                source: e,
            })?;

            if let Some(p) = progress {
                p.send(crate::progress::PullProgress::LayerDownloadComplete {
                    layer_index,
                    digest: digest_str,
                    downloaded_bytes: expected_size.unwrap_or(0),
                });
            }

            return Ok(());
        }

        let (mut stream, mut file, mut downloaded): (SizedStream, File, u64) = match download_start
        {
            DownloadStart::Fresh => {
                let stream = client
                    .pull_blob_stream(image_ref, digest_display.as_str())
                    .await?;
                let file = OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .write(true)
                    .open(part_path)
                    .map_err(|e| ImageError::Cache {
                        path: part_path.clone(),
                        source: e,
                    })?;
                (stream, file, 0)
            }
            DownloadStart::Resume(offset) => {
                let blob = client
                    .pull_blob_stream_partial(image_ref, digest_display.as_str(), offset, None)
                    .await?;

                match blob {
                    BlobResponse::Partial(stream) => {
                        let file = OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(part_path)
                            .map_err(|e| ImageError::Cache {
                                path: part_path.clone(),
                                source: e,
                            })?;
                        (stream, file, offset)
                    }
                    BlobResponse::Full(stream) => {
                        let file = OpenOptions::new()
                            .create(true)
                            .truncate(true)
                            .write(true)
                            .open(part_path)
                            .map_err(|e| ImageError::Cache {
                                path: part_path.clone(),
                                source: e,
                            })?;
                        (stream, file, 0)
                    }
                }
            }
            DownloadStart::Complete => unreachable!(),
        };

        use futures::StreamExt;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            file.write_all(&chunk).map_err(|e| ImageError::Cache {
                path: part_path.clone(),
                source: e,
            })?;
            downloaded += chunk.len() as u64;

            if let Some(p) = progress {
                p.send(crate::progress::PullProgress::LayerDownloadProgress {
                    layer_index,
                    digest: digest_str.clone(),
                    downloaded_bytes: downloaded,
                    total_bytes: expected_size,
                });
            }
        }
        file.flush().map_err(|e| ImageError::Cache {
            path: part_path.clone(),
            source: e,
        })?;
        drop(file);

        // Verify hash.
        let actual_hash = compute_sha256_file(part_path)?;
        if actual_hash != expected_hex {
            let _ = std::fs::remove_file(part_path);
            return Err(ImageError::DigestMismatch {
                digest: digest_display,
                expected: expected_hex.to_string(),
                actual: actual_hash,
            });
        }

        // Atomic rename .part -> final.
        std::fs::rename(part_path, tar_path).map_err(|e| ImageError::Cache {
            path: tar_path.clone(),
            source: e,
        })?;

        if let Some(p) = progress {
            p.send(crate::progress::PullProgress::LayerDownloadComplete {
                layer_index,
                digest: digest_str,
                downloaded_bytes: downloaded,
            });
        }

        Ok(())
    }

    /// Extract this layer (decompress + untar).
    ///
    /// Uses cross-process `flock()` to prevent concurrent extraction.
    pub async fn extract(
        &self,
        parent_extracted_dirs: &[PathBuf],
        progress: Option<&crate::progress::PullProgressSender>,
        layer_index: usize,
        media_type: Option<&str>,
        diff_id: &str,
    ) -> ImageResult<()> {
        // Cross-process lock.
        let lock_file = open_lock_file(&self.lock_path)?;
        flock_exclusive(&lock_file)?;
        let _flock_guard = scopeguard::guard(lock_file, |f| {
            let _ = flock_unlock(&f);
        });

        // Re-check after lock.
        if self.is_extracted() {
            return Ok(());
        }

        let diff_id_arc: std::sync::Arc<str> = diff_id.into();

        if let Some(p) = progress {
            p.send(crate::progress::PullProgress::LayerExtractStarted {
                layer_index,
                diff_id: diff_id_arc.clone(),
            });
        }

        let extracting_dir = &self.extracting_dir;
        let extracted_dir = &self.extracted_dir;

        // Clean up any previous incomplete extraction.
        let _ = std::fs::remove_dir_all(extracting_dir);
        std::fs::create_dir_all(extracting_dir).map_err(|e| ImageError::Cache {
            path: extracting_dir.clone(),
            source: e,
        })?;

        // Run the extraction pipeline.
        match extraction::extract_layer(
            &self.tar_path,
            extracting_dir,
            parent_extracted_dirs,
            media_type,
        )
        .await
        {
            Ok(()) => {}
            Err(e) => {
                let _ = std::fs::remove_dir_all(extracting_dir);
                return Err(e);
            }
        }

        // Write .complete marker.
        let marker_path = extracting_dir.join(store::COMPLETE_MARKER);
        std::fs::write(&marker_path, b"").map_err(|e| ImageError::Cache {
            path: marker_path,
            source: e,
        })?;

        // Atomic rename.
        // Remove target if it exists (incomplete from a crash).
        let _ = std::fs::remove_dir_all(extracted_dir);
        std::fs::rename(extracting_dir, extracted_dir).map_err(|e| ImageError::Cache {
            path: extracted_dir.clone(),
            source: e,
        })?;

        if let Some(p) = progress {
            p.send(crate::progress::PullProgress::LayerExtractComplete {
                layer_index,
                diff_id: diff_id_arc,
            });
        }

        Ok(())
    }

    /// Generate the binary sidecar index for this layer's extracted tree.
    pub async fn build_index(&self) -> ImageResult<()> {
        index::build_sidecar_index(&self.extracted_dir, &self.index_path).await
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Open or create a lock file.
fn open_lock_file(path: &Path) -> ImageResult<File> {
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)
        .map_err(|e| ImageError::Cache {
            path: path.to_path_buf(),
            source: e,
        })
}

/// Acquire an exclusive `flock()`.
fn flock_exclusive(file: &File) -> ImageResult<()> {
    let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if ret != 0 {
        return Err(ImageError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

/// Release a `flock()`.
fn flock_unlock(file: &File) -> ImageResult<()> {
    let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    if ret != 0 {
        return Err(ImageError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

/// Compute the SHA-256 hex digest of a file.
fn compute_sha256_file(path: &Path) -> ImageResult<String> {
    let mut file = File::open(path).map_err(|e| ImageError::Cache {
        path: path.to_path_buf(),
        source: e,
    })?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(|e| ImageError::Cache {
            path: path.to_path_buf(),
            source: e,
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn remove_file_if_exists(path: &Path) -> ImageResult<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(ImageError::Cache {
            path: path.to_path_buf(),
            source: err,
        }),
    }
}

fn determine_download_start(
    part_path: &Path,
    expected_size: Option<u64>,
    expected_hex: &str,
) -> ImageResult<DownloadStart> {
    let part_size = match std::fs::metadata(part_path) {
        Ok(meta) => meta.len(),
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(DownloadStart::Fresh),
        Err(err) => {
            return Err(ImageError::Cache {
                path: part_path.to_path_buf(),
                source: err,
            });
        }
    };

    if part_size == 0 {
        return Ok(DownloadStart::Fresh);
    }

    if let Some(expected) = expected_size {
        if part_size > expected {
            let _ = std::fs::remove_file(part_path);
            return Ok(DownloadStart::Fresh);
        }

        if part_size == expected {
            let actual_hash = compute_sha256_file(part_path)?;
            if actual_hash == expected_hex {
                return Ok(DownloadStart::Complete);
            }

            let _ = std::fs::remove_file(part_path);
            return Ok(DownloadStart::Fresh);
        }
    }

    Ok(DownloadStart::Resume(part_size))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::{DownloadStart, determine_download_start, remove_file_if_exists};

    #[test]
    fn test_determine_download_start_returns_fresh_when_part_missing() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("layer.part");

        let start = determine_download_start(&path, Some(10), "deadbeef").unwrap();

        assert!(matches!(start, DownloadStart::Fresh));
    }

    #[test]
    fn test_determine_download_start_resumes_partial_file() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("layer.part");
        std::fs::write(&path, b"hello").unwrap();

        let start = determine_download_start(&path, Some(10), "deadbeef").unwrap();

        assert!(matches!(start, DownloadStart::Resume(5)));
    }

    #[test]
    fn test_determine_download_start_resets_oversized_part_file() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("layer.part");
        std::fs::write(&path, b"hello world").unwrap();

        let start = determine_download_start(&path, Some(5), "deadbeef").unwrap();

        assert!(matches!(start, DownloadStart::Fresh));
        assert!(!path.exists());
    }

    #[test]
    fn test_determine_download_start_marks_complete_when_hash_matches() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("layer.part");
        std::fs::write(&path, b"hello").unwrap();
        let digest = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

        let start = determine_download_start(&path, Some(5), digest).unwrap();

        assert!(matches!(start, DownloadStart::Complete));
    }

    #[test]
    fn test_determine_download_start_restarts_when_full_part_hash_mismatches() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("layer.part");
        std::fs::write(&path, b"hello").unwrap();

        let start = determine_download_start(&path, Some(5), "deadbeef").unwrap();

        assert!(matches!(start, DownloadStart::Fresh));
        assert!(!path.exists());
    }

    #[test]
    fn test_remove_file_if_exists_deletes_existing_file() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("layer.tar.gz");
        std::fs::write(&path, b"cached").unwrap();

        remove_file_if_exists(&path).unwrap();

        assert!(!path.exists());
    }

    #[test]
    fn test_remove_file_if_exists_ignores_missing_file() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("missing.tar.gz");

        remove_file_if_exists(&path).unwrap();

        assert!(!path.exists());
    }
}

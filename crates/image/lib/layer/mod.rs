//! Layer download and blob-cache management.

use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::Instant,
};

use oci_client::client::{BlobResponse, SizedStream};
use sha2::{Digest as Sha2Digest, Sha256};

use crate::{
    digest::Digest,
    error::{ImageError, ImageResult},
    lock::{flock_exclusive_by_fd, flock_unlock, open_lock_file},
    store::GlobalCache,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Minimum byte delta between per-layer download progress updates.
const DOWNLOAD_PROGRESS_EMIT_BYTES: u64 = 256 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A single OCI layer handle with download state.
pub(crate) struct Layer {
    /// Compressed layer digest (from manifest).
    pub digest: Digest,
    /// Cached paths derived from the global cache.
    tar_path: PathBuf,
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
            download_lock_path: cache.download_lock_path(&digest),
            part_path: cache.part_path(&digest),
            digest,
        }
    }

    /// Path to the compressed tarball.
    pub fn tar_path_ref(&self) -> PathBuf {
        self.tar_path.clone()
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
        let started_at = Instant::now();
        let tar_path = &self.tar_path;
        let part_path = &self.part_path;

        // Acquire cross-process download lock (non-blocking on async executor).
        let lock_file = open_lock_file(&self.download_lock_path)?;
        {
            use std::os::unix::io::AsRawFd;
            let fd = lock_file.as_raw_fd();
            tokio::task::spawn_blocking(move || flock_exclusive_by_fd(fd))
                .await
                .map_err(|e| ImageError::Io(std::io::Error::other(e)))??;
        }
        let _guard = scopeguard::guard(lock_file, |f| {
            let _ = flock_unlock(&f);
        });

        if force {
            remove_file_if_exists(tar_path)?;
            remove_file_if_exists(part_path)?;
        }

        let digest_display = self.digest.to_string();
        let digest_str: std::sync::Arc<str> = digest_display.as_str().into();

        // Re-check after lock — another process may have completed the download.
        if tar_path.exists() {
            let already_complete = if let Some(expected) = expected_size {
                matches!(std::fs::metadata(tar_path), Ok(meta) if meta.len() == expected)
            } else {
                matches!(std::fs::metadata(tar_path), Ok(meta) if meta.len() > 0)
            };

            if already_complete {
                if let Some(p) = progress {
                    p.send(crate::progress::PullProgress::LayerDownloadComplete {
                        layer_index,
                        digest: digest_str,
                        downloaded_bytes: expected_size.unwrap_or(0),
                    });
                }
                tracing::debug!(
                    layer_index,
                    digest = %digest_display,
                    elapsed_ms = started_at.elapsed().as_millis(),
                    "layer download reused cached tarball"
                );
                return Ok(());
            }
        }

        // Stream the blob to a .part file.
        let expected_hex = self.digest.hex();

        // Run download-start determination (may hash a large .part file) off the executor.
        let part_path_for_start = part_path.clone();
        let expected_hex_owned = expected_hex.to_string();
        let download_start = tokio::task::spawn_blocking(move || {
            determine_download_start(&part_path_for_start, expected_size, &expected_hex_owned)
        })
        .await
        .map_err(|e| ImageError::Io(io::Error::other(e)))??;
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

            tracing::debug!(
                layer_index,
                digest = %digest_display,
                elapsed_ms = started_at.elapsed().as_millis(),
                "layer download resumed from completed part file"
            );

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
        let mut last_progress_bytes = downloaded;

        // Compute SHA-256 incrementally during download — avoids re-reading
        // the entire blob from disk for post-download verification.
        // For resumed downloads, we must hash the existing bytes first.
        let mut hasher = Sha256::new();
        if downloaded > 0 {
            // Hash the existing portion of the .part file before appending.
            let mut existing = File::open(part_path).map_err(|e| ImageError::Cache {
                path: part_path.clone(),
                source: e,
            })?;
            let mut buf = [0u8; 65536];
            loop {
                let n = existing.read(&mut buf).map_err(|e| ImageError::Cache {
                    path: part_path.clone(),
                    source: e,
                })?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
        }

        use futures::StreamExt;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            hasher.update(&chunk);
            file.write_all(&chunk).map_err(|e| ImageError::Cache {
                path: part_path.clone(),
                source: e,
            })?;
            downloaded += chunk.len() as u64;

            let should_emit_progress = downloaded.saturating_sub(last_progress_bytes)
                >= DOWNLOAD_PROGRESS_EMIT_BYTES
                || expected_size.is_some_and(|total| downloaded >= total);

            if should_emit_progress {
                if let Some(p) = progress {
                    p.send(crate::progress::PullProgress::LayerDownloadProgress {
                        layer_index,
                        digest: digest_str.clone(),
                        downloaded_bytes: downloaded,
                        total_bytes: expected_size,
                    });
                }
                last_progress_bytes = downloaded;
            }
        }
        file.flush().map_err(|e| ImageError::Cache {
            path: part_path.clone(),
            source: e,
        })?;
        drop(file);

        // Verify compressed digest from the incremental hash.
        let actual_hash = hex::encode(hasher.finalize());
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

        tracing::debug!(
            layer_index,
            digest = %digest_display,
            downloaded_bytes = downloaded,
            elapsed_ms = started_at.elapsed().as_millis(),
            "layer download completed"
        );

        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

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

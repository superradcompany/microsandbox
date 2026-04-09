//! Layer download, extraction, and management.

pub(crate) mod extraction;
pub(crate) mod index;

use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use oci_client::client::{BlobResponse, SizedStream};
use sha2::{Digest as Sha2Digest, Sha256};

use crate::{
    digest::Digest,
    error::{ImageError, ImageResult},
    lock::{flock_exclusive_async, flock_unlock, open_lock_file},
    store::{self, GlobalCache},
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Xattr key for stat virtualization.
pub(crate) const OVERRIDE_XATTR_KEY: &str = "user.containers.override_stat";

/// File type mask.
#[cfg(target_os = "linux")]
pub(crate) const S_IFMT: u32 = libc::S_IFMT;
#[cfg(target_os = "macos")]
pub(crate) const S_IFMT: u32 = libc::S_IFMT as u32;

/// Symlink file type bits.
#[cfg(target_os = "linux")]
pub(crate) const S_IFLNK: u32 = libc::S_IFLNK;
#[cfg(target_os = "macos")]
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
    implicit_dirs_path: PathBuf,
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
            implicit_dirs_path: cache.implicit_dirs_path(&digest),
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
        let lock_file = flock_exclusive_async(open_lock_file(&self.download_lock_path)?).await?;
        let download_lock_path = self.download_lock_path.clone();
        let _guard = scopeguard::guard(lock_file, |f| {
            let _ = flock_unlock(&f);
            drop(f);
            let _ = std::fs::remove_file(&download_lock_path);
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
                return Ok(());
            }
        }

        // Stream the blob to a .part file.
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
        let actual_hash = compute_sha256_file_async(part_path.to_path_buf()).await?;
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
    /// Returns an `ExtractionResult` containing the list of implicitly-created
    /// directories that may need xattr fixup from lower layers.
    pub async fn extract(
        &self,
        progress: Option<&crate::progress::PullProgressSender>,
        layer_index: usize,
        media_type: Option<&str>,
        diff_id: &str,
        force: bool,
    ) -> ImageResult<extraction::ExtractionResult> {
        // Cross-process lock.
        let lock_file = flock_exclusive_async(open_lock_file(&self.lock_path)?).await?;
        let lock_path = self.lock_path.clone();
        let _flock_guard = scopeguard::guard(lock_file, |f| {
            let _ = flock_unlock(&f);
            drop(f);
            let _ = std::fs::remove_file(&lock_path);
        });

        // Re-check after lock.
        if self.is_extracted() && !force {
            return Ok(extraction::ExtractionResult {
                implicit_dirs: read_pending_implicit_dirs(&self.implicit_dirs_path)?,
            });
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

        if force {
            let _ = std::fs::remove_dir_all(extracted_dir);
            remove_file_if_exists(&self.implicit_dirs_path)?;
        }

        // Clean up any previous incomplete extraction.
        let _ = std::fs::remove_dir_all(extracting_dir);
        remove_file_if_exists(&self.implicit_dirs_path)?;
        std::fs::create_dir_all(extracting_dir).map_err(|e| ImageError::Cache {
            path: extracting_dir.clone(),
            source: e,
        })?;

        // Run the extraction pipeline.
        let result = match extraction::extract_layer(
            &self.tar_path,
            extracting_dir,
            media_type,
            progress,
            layer_index,
        )
        .await
        {
            Ok(result) => result,
            Err(e) => {
                let _ = std::fs::remove_dir_all(extracting_dir);
                return Err(e);
            }
        };

        write_pending_implicit_dirs(&self.implicit_dirs_path, &result.implicit_dirs)?;

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

        Ok(result)
    }

    /// Generate the binary sidecar index for this layer's extracted tree.
    pub async fn build_index(&self) -> ImageResult<()> {
        index::build_sidecar_index(&self.extracted_dir, &self.index_path).await
    }

    /// Load any pending implicit directories that still need fixup.
    pub fn pending_implicit_dirs(&self) -> ImageResult<Vec<PathBuf>> {
        read_pending_implicit_dirs(&self.implicit_dirs_path)
    }

    /// Clear the pending implicit directory marker after fixup completes.
    pub fn clear_pending_implicit_dirs(&self) -> ImageResult<()> {
        remove_file_if_exists(&self.implicit_dirs_path)?;
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

async fn compute_sha256_file_async(path: PathBuf) -> ImageResult<String> {
    tokio::task::spawn_blocking(move || compute_sha256_file(&path))
        .await
        .map_err(|error| ImageError::Io(io::Error::other(format!("hash task failed: {error}"))))?
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

fn write_pending_implicit_dirs(path: &Path, implicit_dirs: &[PathBuf]) -> ImageResult<()> {
    use std::os::unix::ffi::OsStrExt;

    if implicit_dirs.is_empty() {
        remove_file_if_exists(path)?;
        return Ok(());
    }

    let mut data = Vec::new();
    for entry in implicit_dirs {
        let bytes = entry.as_os_str().as_bytes();
        let len = u32::try_from(bytes.len()).map_err(|_| ImageError::Cache {
            path: path.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::InvalidData,
                format!("implicit dir path too long: {}", entry.display()),
            ),
        })?;
        data.extend_from_slice(&len.to_le_bytes());
        data.extend_from_slice(bytes);
    }

    std::fs::write(path, data).map_err(|e| ImageError::Cache {
        path: path.to_path_buf(),
        source: e,
    })
}

fn read_pending_implicit_dirs(path: &Path) -> ImageResult<Vec<PathBuf>> {
    use std::os::unix::ffi::OsStringExt;

    let data = match std::fs::read(path) {
        Ok(data) => data,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(ImageError::Cache {
                path: path.to_path_buf(),
                source: err,
            });
        }
    };

    let mut offset = 0usize;
    let mut paths = Vec::new();
    while offset < data.len() {
        let len_end = offset + 4;
        if len_end > data.len() {
            return Err(ImageError::Cache {
                path: path.to_path_buf(),
                source: io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated implicit dirs sidecar",
                ),
            });
        }
        let len = u32::from_le_bytes(data[offset..len_end].try_into().unwrap()) as usize;
        offset = len_end;
        let path_end = offset + len;
        if path_end > data.len() {
            return Err(ImageError::Cache {
                path: path.to_path_buf(),
                source: io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid implicit dirs sidecar entry length",
                ),
            });
        }
        paths.push(PathBuf::from(std::ffi::OsString::from_vec(
            data[offset..path_end].to_vec(),
        )));
        offset = path_end;
    }

    Ok(paths)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt, path::PathBuf};

    use tempfile::tempdir;

    use crate::{
        digest::Digest,
        store::{COMPLETE_MARKER, GlobalCache},
    };

    use super::{
        DownloadStart, Layer, determine_download_start, read_pending_implicit_dirs,
        remove_file_if_exists, write_pending_implicit_dirs,
    };

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

    #[test]
    fn test_extract_reads_pending_implicit_dirs_from_existing_layer() {
        let temp = tempdir().unwrap();
        let cache = GlobalCache::new(temp.path()).unwrap();
        let digest: Digest =
            "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                .parse()
                .unwrap();
        let layer = Layer::new(digest.clone(), &cache);

        let extracted_dir = cache.extracted_dir(&digest);
        let implicit_dirs_path = cache.implicit_dirs_path(&digest);
        std::fs::create_dir_all(&extracted_dir).unwrap();
        std::fs::write(extracted_dir.join(COMPLETE_MARKER), b"").unwrap();
        write_pending_implicit_dirs(
            &implicit_dirs_path,
            &[PathBuf::from("usr"), PathBuf::from("usr/local/bin")],
        )
        .unwrap();

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime
            .block_on(layer.extract(
                None,
                0,
                Some("application/vnd.oci.image.layer.v1.tar"),
                "sha256:deadbeef",
                false,
            ))
            .unwrap();

        assert_eq!(
            result.implicit_dirs,
            vec![PathBuf::from("usr"), PathBuf::from("usr/local/bin")]
        );
    }

    #[test]
    fn test_clear_pending_implicit_dirs_removes_marker() {
        let temp = tempdir().unwrap();
        let cache = GlobalCache::new(temp.path()).unwrap();
        let digest: Digest =
            "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                .parse()
                .unwrap();
        let layer = Layer::new(digest.clone(), &cache);

        let extracted_dir = cache.extracted_dir(&digest);
        let implicit_dirs_path = cache.implicit_dirs_path(&digest);
        std::fs::create_dir_all(&extracted_dir).unwrap();
        write_pending_implicit_dirs(&implicit_dirs_path, &[PathBuf::from("usr")]).unwrap();

        layer.clear_pending_implicit_dirs().unwrap();

        assert!(!implicit_dirs_path.exists());
    }

    #[test]
    fn test_pending_implicit_dirs_round_trip_raw_bytes() {
        let temp = tempdir().unwrap();
        let sidecar_path = temp.path().join("layer.implicit_dirs");
        let raw_path = PathBuf::from(OsString::from_vec(vec![
            b'u', b's', b'r', b'/', b'b', b'i', b'n', b'/', 0xff, b'\n', b'x',
        ]));

        write_pending_implicit_dirs(&sidecar_path, std::slice::from_ref(&raw_path)).unwrap();
        let round_tripped = read_pending_implicit_dirs(&sidecar_path).unwrap();

        assert_eq!(round_tripped, vec![raw_path]);
    }
}

//! Snapshot content verification.

use std::fs::File;
use std::io;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use microsandbox_image::snapshot::{SPARSE_SHA256_V1, UpperIntegrity};
use microsandbox_utils::extent::ExtentMap;
use sha2::{Digest as _, Sha256};
use tokio::io::AsyncReadExt;

use crate::{MicrosandboxError, MicrosandboxResult};

use super::Snapshot;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Result of explicit snapshot verification.
#[derive(Debug, Clone)]
pub struct SnapshotVerifyReport {
    /// Snapshot manifest digest.
    pub digest: String,
    /// Artifact directory.
    pub path: PathBuf,
    /// Upper-layer content verification result.
    pub upper: UpperVerifyStatus,
}

/// Upper-layer content verification result.
#[derive(Debug, Clone)]
pub enum UpperVerifyStatus {
    /// No content integrity descriptor was recorded in the manifest.
    NotRecorded,
    /// Recorded content integrity matched the computed digest.
    Verified {
        /// Digest algorithm.
        algorithm: String,
        /// Matching digest.
        digest: String,
    },
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) async fn verify_snapshot(snap: &Snapshot) -> MicrosandboxResult<SnapshotVerifyReport> {
    let Some(expected) = snap.manifest().upper.integrity.as_ref() else {
        return Ok(SnapshotVerifyReport {
            digest: snap.digest().to_string(),
            path: snap.path().to_path_buf(),
            upper: UpperVerifyStatus::NotRecorded,
        });
    };

    let upper_path = snap.path().join(&snap.manifest().upper.file);
    let actual = match expected.algorithm.as_str() {
        "sha256" => sha256_file(&upper_path).await?,
        SPARSE_SHA256_V1 => compute_sparse_integrity(&upper_path).await?.digest,
        algorithm => {
            return Err(MicrosandboxError::SnapshotIntegrity(format!(
                "unsupported upper integrity algorithm: {algorithm}"
            )));
        }
    };

    if actual != expected.digest {
        return Err(MicrosandboxError::SnapshotIntegrity(format!(
            "upper digest mismatch: manifest={}, file={}",
            expected.digest, actual
        )));
    }

    Ok(SnapshotVerifyReport {
        digest: snap.digest().to_string(),
        path: snap.path().to_path_buf(),
        upper: UpperVerifyStatus::Verified {
            algorithm: expected.algorithm.clone(),
            digest: actual,
        },
    })
}

pub(super) async fn compute_sparse_integrity(path: &Path) -> MicrosandboxResult<UpperIntegrity> {
    let path = path.to_path_buf();
    let computed = tokio::task::spawn_blocking(move || sparse_integrity_blocking(&path))
        .await
        .map_err(|e| MicrosandboxError::Custom(format!("snapshot integrity task: {e}")))??;
    Ok(computed)
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

async fn sha256_file(path: &Path) -> MicrosandboxResult<String> {
    let mut f = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

/// Hash the file's logical content — data extents plus synthesized zeros for holes — in O(data) wherever [`ExtentMap`] can enumerate the allocation map, with a full sequential
/// read as the fallback.
fn sparse_integrity_blocking(path: &Path) -> io::Result<UpperIntegrity> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();

    let mut hasher = Sha256::new();
    hasher.update(b"msb-sparse-sha256-v1\0");
    hasher.update(len.to_le_bytes());

    match ExtentMap::scan_file(&file)? {
        Some(map) => {
            let mut off: u64 = 0;
            for (start, extent_len) in &map.extents {
                if *start > off {
                    hash_zeroes(start - off, &mut hasher);
                }
                hash_extent(&mut file, *start, *extent_len, &mut hasher)?;
                off = start + extent_len;
            }
            if off < len {
                hash_zeroes(len - off, &mut hasher);
            }
        }
        None => {
            // The scan may have moved the cursor before reporting
            // "can't enumerate"; rewind for the sequential read.
            file.seek(SeekFrom::Start(0))?;
            let mut buf = vec![0u8; 1024 * 1024];
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
        }
    }

    let digest = format!("sha256:{}", hex::encode(hasher.finalize()));
    Ok(UpperIntegrity {
        algorithm: SPARSE_SHA256_V1.into(),
        digest,
    })
}

fn hash_extent(file: &mut File, off: u64, len: u64, hasher: &mut Sha256) -> io::Result<()> {
    const BUF_SIZE: usize = 1024 * 1024;
    let mut buf = vec![0u8; BUF_SIZE];
    let mut hashed = 0u64;

    file.seek(SeekFrom::Start(off))?;
    while hashed < len {
        let to_read = (len - hashed).min(BUF_SIZE as u64) as usize;
        let n = file.read(&mut buf[..to_read])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected EOF mid-extent",
            ));
        }
        hasher.update(&buf[..n]);
        hashed += n as u64;
    }

    Ok(())
}

fn hash_zeroes(mut len: u64, hasher: &mut Sha256) {
    static ZEROES: [u8; 1024 * 1024] = [0; 1024 * 1024];

    while len > 0 {
        let chunk = len.min(ZEROES.len() as u64) as usize;
        hasher.update(&ZEROES[..chunk]);
        len -= chunk as u64;
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::{Seek, SeekFrom, Write};

    use super::*;

    #[test]
    fn sparse_integrity_is_stable_and_detects_data_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("upper.ext4");
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.set_len(64 * 1024 * 1024).unwrap();
        file.seek(SeekFrom::Start(8 * 1024 * 1024)).unwrap();
        file.write_all(b"hello").unwrap();
        drop(file);

        let first = match sparse_integrity_blocking(&path) {
            Ok(integrity) => integrity,
            Err(e) if e.raw_os_error() == Some(libc::EINVAL) => return,
            Err(e) => panic!("sparse integrity failed: {e}"),
        };
        let second = sparse_integrity_blocking(&path).unwrap();
        assert_eq!(first.algorithm, SPARSE_SHA256_V1);
        assert_eq!(first.digest, second.digest);

        let mut file = OpenOptions::new().write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(8 * 1024 * 1024)).unwrap();
        file.write_all(b"HELLO").unwrap();
        drop(file);

        let changed = sparse_integrity_blocking(&path).unwrap();
        assert_ne!(first.digest, changed.digest);
    }
}

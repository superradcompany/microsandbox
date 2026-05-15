//! Snapshot content verification.

use std::fs::File;
use std::io;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use microsandbox_image::snapshot::{SPARSE_SHA256_V1, UpperIntegrity};
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

fn sparse_integrity_blocking(path: &Path) -> io::Result<UpperIntegrity> {
    let file = File::open(path)?;
    let len = file.metadata()?.len();
    let fd = file.as_raw_fd();

    let mut hasher = Sha256::new();
    hasher.update(b"msb-sparse-sha256-v1\0");
    hasher.update(len.to_le_bytes());

    let mut off: i64 = 0;
    while (off as u64) < len {
        let data_start = unsafe { libc::lseek(fd, off, libc::SEEK_DATA) };
        if data_start < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENXIO) {
                break;
            }
            return Err(err);
        }

        let data_end = unsafe { libc::lseek(fd, data_start, libc::SEEK_HOLE) };
        if data_end < 0 {
            return Err(io::Error::last_os_error());
        }

        let data_start = data_start as u64;
        let data_end = (data_end as u64).min(len);
        if data_end <= data_start {
            break;
        }

        let extent_len = data_end - data_start;
        hasher.update(b"D");
        hasher.update(data_start.to_le_bytes());
        hasher.update(extent_len.to_le_bytes());
        hash_extent(fd, data_start, extent_len, &mut hasher)?;

        off = data_end as i64;
    }

    let digest = format!("sha256:{}", hex::encode(hasher.finalize()));
    Ok(UpperIntegrity {
        algorithm: SPARSE_SHA256_V1.into(),
        digest,
    })
}

fn hash_extent(fd: i32, off: u64, len: u64, hasher: &mut Sha256) -> io::Result<()> {
    const BUF_SIZE: usize = 1024 * 1024;
    let mut buf = vec![0u8; BUF_SIZE];
    let mut hashed = 0u64;

    while hashed < len {
        let to_read = (len - hashed).min(BUF_SIZE as u64) as usize;
        let read_off = (off + hashed) as i64;
        let n =
            unsafe { libc::pread(fd, buf.as_mut_ptr() as *mut libc::c_void, to_read, read_off) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected EOF mid-extent",
            ));
        }
        let n = n as usize;
        hasher.update(&buf[..n]);
        hashed += n as u64;
    }

    Ok(())
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

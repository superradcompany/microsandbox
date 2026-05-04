//! Sparse-aware fast copy with reflink fallback.
//!
//! Two-tier strategy that preserves sparseness on every supported
//! platform:
//!
//! 1. **Reflink** (zero-copy COW). Tries `clonefile(2)` on macOS and
//!    `ioctl(FICLONE)` on Linux via `reflink-copy`. Succeeds instantly
//!    on APFS, btrfs, XFS (with `reflink=1`), and bcachefs. Returns
//!    `EOPNOTSUPP` (or similar) on ext4 and other non-COW filesystems.
//!
//! 2. **Sparse-aware copy**. POSIX `SEEK_DATA` / `SEEK_HOLE` walk of
//!    the source's allocation map, with `copy_file_range(2)` on Linux
//!    for in-kernel zero-copy of data extents. The destination is
//!    `ftruncate`d to the source size up front so unallocated regions
//!    stay holes.
//!
//! Never falls back to a naive byte-for-byte copy — that would
//! densify a 4 GiB sparse file with a few MB of data into 4 GiB on
//! disk, which is the exact failure mode this module exists to
//! prevent.
//!
//! See `planning/microsandbox/implementation/snapshots.md` for the
//! full design and tradeoffs.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Copy `src` to `dst`, preserving sparseness. Returns the apparent
/// size of the destination in bytes.
///
/// Tries reflink first (zero-copy COW); on filesystems without reflink
/// support, walks the source's allocation map and copies only its
/// data extents into a `ftruncate`-established sparse destination.
///
/// **Blocking.** Callers in async contexts should wrap in
/// `tokio::task::spawn_blocking`.
pub fn fast_copy(src: &Path, dst: &Path) -> io::Result<u64> {
    // Stat the source up front. This makes the missing-source error
    // kind platform-consistent (`NotFound` everywhere); without it,
    // reflink-copy on Linux surfaces `InvalidInput` with no errno
    // for a non-existent path, which our `is_reflink_unsupported`
    // check can't recognize as a fall-through.
    let src_len = std::fs::metadata(src)?.len();

    // Tier 1: reflink. Errors on unsupported FSes; we fall through to
    // Tier 2. We do NOT use `reflink_or_copy`, which densifies on
    // fallback via `std::fs::copy`.
    match reflink_copy::reflink(src, dst) {
        Ok(()) => return Ok(src_len),
        Err(e) if is_reflink_unsupported(&e) => {
            // fall through to sparse copy
        }
        Err(e) => return Err(e),
    }

    sparse_copy(src, dst)
}

/// Sparse-aware copy via `SEEK_DATA`/`SEEK_HOLE` and per-extent copy.
///
/// Public for callers that want to skip the reflink attempt — e.g.
/// when they already know the destination filesystem doesn't support
/// reflinks, or for tests that want to exercise the fallback path.
pub fn sparse_copy(src: &Path, dst: &Path) -> io::Result<u64> {
    let src_file = File::open(src)?;
    let len = src_file.metadata()?.len();

    let dst_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(dst)?;
    // Establish destination as a fully-sparse hole of `len` bytes;
    // only data extents will materialize into allocated blocks below.
    dst_file.set_len(len)?;

    let src_fd = src_file.as_raw_fd();
    let dst_fd = dst_file.as_raw_fd();

    let mut off: i64 = 0;
    while (off as u64) < len {
        // Find next data extent.
        let data_start = unsafe { libc::lseek(src_fd, off, libc::SEEK_DATA) };
        if data_start < 0 {
            let err = io::Error::last_os_error();
            // ENXIO: no more data past this offset → done.
            if err.raw_os_error() == Some(libc::ENXIO) {
                break;
            }
            return Err(err);
        }
        // Find the end of that extent (start of next hole, or EOF).
        let data_end = unsafe { libc::lseek(src_fd, data_start, libc::SEEK_HOLE) };
        if data_end < 0 {
            return Err(io::Error::last_os_error());
        }
        let data_end = (data_end as u64).min(len);
        let data_start = data_start as u64;
        if data_end <= data_start {
            break;
        }

        copy_extent(src_fd, dst_fd, data_start, data_end - data_start)?;
        off = data_end as i64;
    }

    dst_file.sync_all()?;
    Ok(len)
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Reflink can fail with several different errnos depending on the
/// filesystem and platform. Treat them all as "fall through to Tier 2"
/// rather than propagating to the caller.
///
/// On Linux `ENOTSUP == EOPNOTSUPP`, so a single arm covers both;
/// macOS / BSDs assign them distinct values and need both arms.
fn is_reflink_unsupported(e: &io::Error) -> bool {
    let Some(code) = e.raw_os_error() else {
        return false;
    };

    #[cfg(target_os = "linux")]
    let aliases: &[i32] = &[libc::ENOTSUP, libc::EXDEV, libc::EINVAL];
    #[cfg(not(target_os = "linux"))]
    let aliases: &[i32] = &[libc::ENOTSUP, libc::EOPNOTSUPP, libc::EXDEV, libc::EINVAL];

    aliases.contains(&code)
}

#[cfg(target_os = "linux")]
fn copy_extent(src_fd: RawFd, dst_fd: RawFd, off: u64, len: u64) -> io::Result<()> {
    let mut src_off = off as i64;
    let mut dst_off = off as i64;
    let mut remaining = len;

    while remaining > 0 {
        let chunk = remaining.min(usize::MAX as u64 / 2) as usize;
        let n =
            unsafe { libc::copy_file_range(src_fd, &mut src_off, dst_fd, &mut dst_off, chunk, 0) };
        if n < 0 {
            let err = io::Error::last_os_error();
            // copy_file_range may not be supported on every kernel/FS
            // combination (notably across-FS prior to 5.3, or older
            // kernels). Fall back to pread/pwrite for the remainder of
            // this extent.
            if matches!(
                err.raw_os_error(),
                Some(libc::ENOSYS)
                    | Some(libc::EXDEV)
                    | Some(libc::EINVAL)
                    | Some(libc::EOPNOTSUPP)
            ) {
                let consumed = len - remaining;
                return read_write_extent(src_fd, dst_fd, off + consumed, remaining);
            }
            return Err(err);
        }
        if n == 0 {
            // EOF — should not happen for a valid extent, but guard.
            break;
        }
        remaining -= n as u64;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn copy_extent(src_fd: RawFd, dst_fd: RawFd, off: u64, len: u64) -> io::Result<()> {
    read_write_extent(src_fd, dst_fd, off, len)
}

/// Copy `len` bytes from `src_fd` at `off` to `dst_fd` at `off` using
/// `pread`/`pwrite`. Universal fallback for `copy_extent` on platforms
/// or filesystems where `copy_file_range` doesn't apply.
fn read_write_extent(src_fd: RawFd, dst_fd: RawFd, off: u64, len: u64) -> io::Result<()> {
    const BUF_SIZE: usize = 64 * 1024;
    let mut buf = [0u8; BUF_SIZE];
    let mut copied: u64 = 0;

    while copied < len {
        let to_read = (len - copied).min(BUF_SIZE as u64) as usize;
        let read_off = (off + copied) as i64;
        let n = unsafe {
            libc::pread(
                src_fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                to_read,
                read_off,
            )
        };
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

        let mut written: usize = 0;
        while written < n {
            let w_off = (off + copied + written as u64) as i64;
            let w = unsafe {
                libc::pwrite(
                    dst_fd,
                    buf[written..n].as_ptr() as *const libc::c_void,
                    n - written,
                    w_off,
                )
            };
            if w < 0 {
                return Err(io::Error::last_os_error());
            }
            if w == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "pwrite returned 0",
                ));
            }
            written += w as usize;
        }
        copied += n as u64;
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    /// Build a sparse source file: total apparent size `len`, with
    /// 64 KiB of data written at each of the given offsets.
    fn make_sparse(path: &Path, len: u64, data_offsets: &[u64]) -> io::Result<()> {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        f.set_len(len)?;
        for &off in data_offsets {
            let buf = vec![0xAB_u8; 64 * 1024];
            let fd = f.as_raw_fd();
            let n = unsafe { libc::pwrite(fd, buf.as_ptr() as *const _, buf.len(), off as i64) };
            assert!(n > 0, "pwrite failed: {}", io::Error::last_os_error());
        }
        f.sync_all()?;
        Ok(())
    }

    #[test]
    fn round_trip_small() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src.bin");
        let dst = dir.path().join("dst.bin");

        std::fs::write(&src, b"hello world").unwrap();
        let n = fast_copy(&src, &dst).unwrap();
        assert_eq!(n, 11);
        assert_eq!(std::fs::read(&dst).unwrap(), b"hello world");
    }

    #[test]
    fn sparse_copy_preserves_holes_and_data() {
        // 16 MiB sparse file with 4 data extents at known offsets.
        // Use sparse_copy directly to exercise Tier 2 regardless of
        // the test-host filesystem.
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src.bin");
        let dst = dir.path().join("dst.bin");

        let len: u64 = 16 * 1024 * 1024;
        let offsets = [0u64, 4 * 1024 * 1024, 8 * 1024 * 1024, 12 * 1024 * 1024];
        make_sparse(&src, len, &offsets).unwrap();

        let n = sparse_copy(&src, &dst).unwrap();
        assert_eq!(n, len);

        // Apparent size matches.
        let dst_meta = std::fs::metadata(&dst).unwrap();
        assert_eq!(dst_meta.len(), len);

        // Each data extent's bytes round-trip.
        let mut buf = [0u8; 64 * 1024];
        let dst_file = File::open(&dst).unwrap();
        for &off in &offsets {
            let n = unsafe {
                libc::pread(
                    dst_file.as_raw_fd(),
                    buf.as_mut_ptr() as *mut _,
                    buf.len(),
                    off as i64,
                )
            };
            assert_eq!(n as usize, buf.len());
            assert!(buf.iter().all(|&b| b == 0xAB));
        }

        // Sparseness preservation: only meaningful if the source
        // itself is sparse on this filesystem. Some test hosts (FAT,
        // certain APFS configurations under tempfile mounts) don't
        // produce a sparse source from `ftruncate + pwrite` — in that
        // case sparseness is unachievable and we just confirm the
        // destination didn't blow up beyond the source's footprint.
        let src_bytes_on_disk = std::fs::metadata(&src).unwrap().blocks() * 512;
        let dst_bytes_on_disk = dst_meta.blocks() * 512;
        if src_bytes_on_disk < len / 2 {
            // Source IS sparse. Destination must also be sparse —
            // this is the load-bearing regression test for the whole
            // module.
            assert!(
                dst_bytes_on_disk < len / 2,
                "source is sparse ({src_bytes_on_disk} bytes on disk) but destination densified to {dst_bytes_on_disk} bytes for an apparent size of {len}",
            );
            assert!(
                dst_bytes_on_disk <= src_bytes_on_disk * 4 + 1024 * 1024,
                "destination allocated significantly more than source: src={src_bytes_on_disk} dst={dst_bytes_on_disk}",
            );
        } else {
            eprintln!(
                "filesystem did not sparsify the source (src_bytes_on_disk={src_bytes_on_disk}, apparent={len}); sparseness preservation not exercised in this run",
            );
            // Without source sparseness we can't exceed source's
            // footprint by much — guard against gross regressions.
            assert!(
                dst_bytes_on_disk <= src_bytes_on_disk + 1024 * 1024,
                "destination grew beyond source footprint: src={src_bytes_on_disk} dst={dst_bytes_on_disk}",
            );
        }
    }

    #[test]
    fn fast_copy_matches_source_size() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src.bin");
        let dst = dir.path().join("dst.bin");

        let len: u64 = 4 * 1024 * 1024;
        make_sparse(&src, len, &[0, 2 * 1024 * 1024]).unwrap();

        let n = fast_copy(&src, &dst).unwrap();
        assert_eq!(n, len);
        assert_eq!(std::fs::metadata(&dst).unwrap().len(), len);
    }

    #[test]
    fn missing_source_errors() {
        let dir = tempfile::tempdir().unwrap();
        let err = fast_copy(&dir.path().join("nope.bin"), &dir.path().join("dst.bin")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }
}

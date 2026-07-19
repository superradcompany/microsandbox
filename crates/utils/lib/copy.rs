//! Sparse-aware fast copy with reflink fallback.
//!
//! Two-tier strategy that preserves sparseness on every supported
//! platform:
//!
//! 1. **Reflink** (zero-copy COW). Uses `clonefile(2)` on macOS,
//!    `ioctl(FICLONE)` on Linux, and `FSCTL_DUPLICATE_EXTENTS_TO_FILE`
//!    on block-refcounting Windows volumes. Succeeds as a metadata
//!    operation on APFS, btrfs, reflink-enabled XFS, bcachefs, and
//!    supported ReFS/Dev Drive volumes.
//!
//! 2. **Sparse-aware copy**. POSIX `SEEK_DATA` / `SEEK_HOLE` walks the
//!    source allocation map and transfers data extents through explicit
//!    reads and writes. The destination is `ftruncate`d to the source
//!    size up front so unallocated regions stay holes. Linux deliberately
//!    avoids `copy_file_range(2)` because reflink-capable filesystems may
//!    implement it as a COW clone, violating the explicit copy contract.
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
#[cfg(windows)]
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
use std::path::Path;
#[cfg(windows)]
use std::ptr;

#[cfg(windows)]
use crate::extent::mark_sparse;
#[cfg(windows)]
use windows_sys::Win32::Foundation::HANDLE;
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::GetVolumeInformationByHandleW;
#[cfg(windows)]
use windows_sys::Win32::System::IO::DeviceIoControl;
#[cfg(windows)]
use windows_sys::Win32::System::Ioctl::{
    DUPLICATE_EXTENTS_DATA, FSCTL_DUPLICATE_EXTENTS_TO_FILE, FSCTL_GET_INTEGRITY_INFORMATION,
    FSCTL_GET_INTEGRITY_INFORMATION_BUFFER, FSCTL_SET_INTEGRITY_INFORMATION,
    FSCTL_SET_INTEGRITY_INFORMATION_BUFFER,
};
#[cfg(windows)]
use windows_sys::Win32::System::SystemServices::FILE_SUPPORTS_BLOCK_REFCOUNTING;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// ReFS supports 4 KiB and 64 KiB clusters. Aligning to the larger unit is valid on both.
#[cfg(windows)]
const WINDOWS_CLONE_ALIGNMENT: u64 = 64 * 1024;

/// Windows requires each duplicate-extents request to be strictly smaller than 4 GiB.
#[cfg(windows)]
const WINDOWS_MAX_CLONE_CHUNK: u64 =
    (u32::MAX as u64 / WINDOWS_CLONE_ALIGNMENT) * WINDOWS_CLONE_ALIGNMENT;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Strategy that successfully created a destination in [`fast_copy_with_strategy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastCopyStrategy {
    /// The destination shares source extents through filesystem copy-on-write.
    Reflink,
    /// The destination is an independent sparse-aware copy.
    SparseCopy,
}

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
    fast_copy_with_strategy(src, dst).map(|(len, _)| len)
}

/// Copy `src` to `dst` using the fastest safe strategy and report which strategy resolved.
pub fn fast_copy_with_strategy(src: &Path, dst: &Path) -> io::Result<(u64, FastCopyStrategy)> {
    // Stat the source up front. This makes the missing-source error
    // kind platform-consistent (`NotFound` everywhere); without it,
    // reflink-copy on Linux surfaces `InvalidInput` with no errno
    // for a non-existent path, which our `is_reflink_unsupported`
    // check can't recognize as a fall-through.
    let src_len = std::fs::metadata(src)?.len();

    // Tier 1: reflink. Errors on unsupported FSes; we fall through to
    // Tier 2. We do NOT use `reflink_or_copy`, which densifies on
    // fallback via `std::fs::copy`.
    match reflink_impl(src, dst) {
        Ok(()) => return Ok((src_len, FastCopyStrategy::Reflink)),
        Err(e) if is_reflink_unsupported(&e) => {
            // fall through to sparse copy
        }
        Err(e) => return Err(e),
    }

    sparse_copy(src, dst).map(|len| (len, FastCopyStrategy::SparseCopy))
}

/// Require a filesystem copy-on-write clone with no fallback.
pub fn reflink(src: &Path, dst: &Path) -> io::Result<u64> {
    let src_len = std::fs::metadata(src)?.len();
    reflink_impl(src, dst)?;
    Ok(src_len)
}

/// Sparse-aware copy via `SEEK_DATA`/`SEEK_HOLE` and per-extent copy.
///
/// Public for callers that want to skip the reflink attempt — e.g.
/// when they already know the destination filesystem doesn't support
/// reflinks, or for tests that want to exercise the fallback path.
pub fn sparse_copy(src: &Path, dst: &Path) -> io::Result<u64> {
    sparse_copy_impl(src, dst)
}

#[cfg(unix)]
fn sparse_copy_impl(src: &Path, dst: &Path) -> io::Result<u64> {
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

/// Use the platform's native copy-on-write file-clone primitive.
#[cfg(unix)]
fn reflink_impl(src: &Path, dst: &Path) -> io::Result<()> {
    reflink_copy::reflink(src, dst)
}

/// Clone a file on a block-refcounting Windows volume without relying on the dependency's
/// explicitly experimental Windows implementation.
#[cfg(windows)]
fn reflink_impl(src: &Path, dst: &Path) -> io::Result<()> {
    let mut src_file = File::open(src)?;
    let mut dst_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(dst)?;

    let result = reflink_windows_files(&mut src_file, &mut dst_file);
    // Windows cannot unlink an open file. Close both handles before cleaning up a partial clone.
    drop(dst_file);
    drop(src_file);
    if result.is_err() {
        let _ = std::fs::remove_file(dst);
    }
    result
}

#[cfg(not(any(unix, windows)))]
fn reflink_impl(_src: &Path, _dst: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "filesystem reflinks are unsupported on this platform",
    ))
}

#[cfg(windows)]
fn sparse_copy_impl(src: &Path, dst: &Path) -> io::Result<u64> {
    const BUF_SIZE: usize = 1024 * 1024;

    let mut src_file = File::open(src)?;
    let len = src_file.metadata()?.len();

    let mut dst_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(dst)?;
    dst_file.set_len(len)?;
    mark_sparse(&dst_file)?;

    let mut offset = 0u64;
    let mut buf = vec![0u8; BUF_SIZE];
    loop {
        let n = src_file.read(&mut buf)?;
        if n == 0 {
            break;
        }

        write_nonzero_runs(&mut dst_file, offset, &buf[..n])?;
        offset += n as u64;
    }

    dst_file.sync_all()?;
    Ok(len)
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

#[cfg(windows)]
fn reflink_windows_files(src: &mut File, dst: &mut File) -> io::Result<()> {
    let src_volume = windows_volume_identity(src)?;
    let dst_volume = windows_volume_identity(dst)?;
    if src_volume.0 != dst_volume.0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows block cloning requires source and destination on the same volume",
        ));
    }
    if src_volume.1 & FILE_SUPPORTS_BLOCK_REFCOUNTING == 0
        || dst_volume.1 & FILE_SUPPORTS_BLOCK_REFCOUNTING == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "destination volume does not advertise block-refcounting support",
        ));
    }

    // Flat roots and snapshots are intentionally sparse. Marking the destination before setting
    // its length satisfies ReFS's sparse-source rule without allocating zero-backed clusters.
    mark_sparse(dst)?;
    match_windows_integrity(src, dst)?;

    let len = src.metadata()?.len();
    dst.set_len(len)?;
    let clone_len = len / WINDOWS_CLONE_ALIGNMENT * WINDOWS_CLONE_ALIGNMENT;
    let mut offset = 0u64;
    while offset < clone_len {
        let chunk = (clone_len - offset).min(WINDOWS_MAX_CLONE_CHUNK);
        duplicate_windows_extents(src, dst, offset, chunk)?;
        offset += chunk;
    }

    // Block-clone ranges must end on a ReFS cluster boundary. Preserve exact bytes by copying the
    // final sub-64-KiB tail; flat ext4 artifacts are aligned and therefore never take this path.
    if clone_len < len {
        copy_windows_tail(src, dst, clone_len, len - clone_len)?;
    }
    Ok(())
}

#[cfg(windows)]
fn windows_volume_identity(file: &File) -> io::Result<(u32, u32)> {
    let mut serial = 0u32;
    let mut flags = 0u32;
    let ok = unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle() as HANDLE,
            ptr::null_mut(),
            0,
            &mut serial,
            ptr::null_mut(),
            &mut flags,
            ptr::null_mut(),
            0,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((serial, flags))
}

#[cfg(windows)]
fn match_windows_integrity(src: &File, dst: &File) -> io::Result<()> {
    let Some(src_info) = get_windows_integrity(src)? else {
        // Client Dev Drive builds may not expose the integrity-stream control. The clone ioctl
        // remains authoritative and will reject incompatible source/destination settings.
        return Ok(());
    };
    let Some(dst_info) = get_windows_integrity(dst)? else {
        return Ok(());
    };
    if src_info.ChecksumAlgorithm == dst_info.ChecksumAlgorithm && src_info.Flags == dst_info.Flags
    {
        return Ok(());
    }

    let info = FSCTL_SET_INTEGRITY_INFORMATION_BUFFER {
        ChecksumAlgorithm: src_info.ChecksumAlgorithm,
        Reserved: 0,
        Flags: src_info.Flags,
    };
    let mut returned = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            dst.as_raw_handle() as HANDLE,
            FSCTL_SET_INTEGRITY_INFORMATION,
            &info as *const _ as *const _,
            size_of::<FSCTL_SET_INTEGRITY_INFORMATION_BUFFER>() as u32,
            ptr::null_mut(),
            0,
            &mut returned,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
fn get_windows_integrity(
    file: &File,
) -> io::Result<Option<FSCTL_GET_INTEGRITY_INFORMATION_BUFFER>> {
    let mut info = FSCTL_GET_INTEGRITY_INFORMATION_BUFFER::default();
    let mut returned = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle() as HANDLE,
            FSCTL_GET_INTEGRITY_INFORMATION,
            ptr::null(),
            0,
            &mut info as *mut _ as *mut _,
            size_of::<FSCTL_GET_INTEGRITY_INFORMATION_BUFFER>() as u32,
            &mut returned,
            ptr::null_mut(),
        )
    };
    if ok != 0 {
        return Ok(Some(info));
    }

    let error = io::Error::last_os_error();
    if is_reflink_unsupported(&error) {
        Ok(None)
    } else {
        Err(error)
    }
}

#[cfg(windows)]
fn duplicate_windows_extents(src: &File, dst: &File, offset: u64, len: u64) -> io::Result<()> {
    debug_assert!(len > 0);
    debug_assert_eq!(offset % WINDOWS_CLONE_ALIGNMENT, 0);
    debug_assert_eq!(len % WINDOWS_CLONE_ALIGNMENT, 0);
    debug_assert!(len < 4 * 1024 * 1024 * 1024);

    let request = DUPLICATE_EXTENTS_DATA {
        FileHandle: src.as_raw_handle() as HANDLE,
        SourceFileOffset: offset as i64,
        TargetFileOffset: offset as i64,
        ByteCount: len as i64,
    };
    let mut returned = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            dst.as_raw_handle() as HANDLE,
            FSCTL_DUPLICATE_EXTENTS_TO_FILE,
            &request as *const _ as *const _,
            size_of::<DUPLICATE_EXTENTS_DATA>() as u32,
            ptr::null_mut(),
            0,
            &mut returned,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
fn copy_windows_tail(src: &mut File, dst: &mut File, offset: u64, len: u64) -> io::Result<()> {
    src.seek(SeekFrom::Start(offset))?;
    dst.seek(SeekFrom::Start(offset))?;
    let copied = io::copy(&mut src.take(len), dst)?;
    if copied != len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("Windows reflink tail copied {copied} of {len} bytes"),
        ));
    }
    Ok(())
}

/// Reflink can fail with several different errnos depending on the
/// filesystem and platform. Treat them all as "fall through to Tier 2"
/// rather than propagating to the caller.
///
/// On Linux `ENOTSUP == EOPNOTSUPP`, so a single arm covers both;
/// macOS / BSDs assign them distinct values and need both arms.
fn is_reflink_unsupported(e: &io::Error) -> bool {
    if matches!(e.kind(), io::ErrorKind::Unsupported) {
        return true;
    }

    let Some(code) = e.raw_os_error() else {
        return false;
    };

    #[cfg(target_os = "linux")]
    let aliases: &[i32] = &[libc::ENOTSUP, libc::EXDEV, libc::EINVAL];
    #[cfg(all(unix, not(target_os = "linux")))]
    let aliases: &[i32] = &[libc::ENOTSUP, libc::EOPNOTSUPP, libc::EXDEV, libc::EINVAL];
    #[cfg(windows)]
    let aliases: &[i32] = &[
        1,   // ERROR_INVALID_FUNCTION
        17,  // ERROR_NOT_SAME_DEVICE
        50,  // ERROR_NOT_SUPPORTED
        87,  // ERROR_INVALID_PARAMETER
        124, // ERROR_INVALID_LEVEL
        775, // ERROR_NOT_CAPABLE
    ];

    #[cfg(windows)]
    {
        let win32_code = (code as u32 & 0xffff) as i32;
        aliases.contains(&code) || aliases.contains(&win32_code)
    }

    #[cfg(unix)]
    aliases.contains(&code)
}

#[cfg(unix)]
fn copy_extent(src_fd: RawFd, dst_fd: RawFd, off: u64, len: u64) -> io::Result<()> {
    // Do not substitute copy_file_range here. Linux permits the filesystem to satisfy that API
    // with shared COW extents, which makes explicit clone=copy indistinguishable from reflink on
    // XFS and btrfs. Reads and writes preserve the cross-platform independent-copy contract.
    read_write_extent(src_fd, dst_fd, off, len)
}

/// Copy `len` bytes from `src_fd` at `off` to `dst_fd` at `off` using
/// `pread`/`pwrite` without asking the filesystem to share extents.
#[cfg(unix)]
fn read_write_extent(src_fd: RawFd, dst_fd: RawFd, off: u64, len: u64) -> io::Result<()> {
    const BUF_SIZE: usize = 1024 * 1024;
    // Keep the larger transfer buffer off the comparatively small worker-thread stack.
    let mut buf = vec![0u8; BUF_SIZE];
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

#[cfg(windows)]
fn write_nonzero_runs(dst: &mut File, base_offset: u64, bytes: &[u8]) -> io::Result<()> {
    let mut cursor = 0;
    while cursor < bytes.len() {
        while cursor < bytes.len() && bytes[cursor] == 0 {
            cursor += 1;
        }
        if cursor == bytes.len() {
            break;
        }

        let start = cursor;
        while cursor < bytes.len() && bytes[cursor] != 0 {
            cursor += 1;
        }

        dst.seek(SeekFrom::Start(base_offset + start as u64))?;
        dst.write_all(&bytes[start..cursor])?;
    }

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom, Write};
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;

    /// Build a sparse source file: total apparent size `len`, with
    /// 64 KiB of data written at each of the given offsets.
    fn make_sparse(path: &Path, len: u64, data_offsets: &[u64]) -> io::Result<()> {
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        f.set_len(len)?;
        for &off in data_offsets {
            let buf = vec![0xAB_u8; 64 * 1024];
            f.seek(SeekFrom::Start(off))?;
            f.write_all(&buf)?;
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
        let mut dst_file = File::open(&dst).unwrap();
        for &off in &offsets {
            dst_file.seek(SeekFrom::Start(off)).unwrap();
            dst_file.read_exact(&mut buf).unwrap();
            assert!(buf.iter().all(|&b| b == 0xAB));
        }

        // Sparseness preservation: only meaningful if the source
        // itself is sparse on this filesystem. Some test hosts (FAT,
        // certain APFS configurations under tempfile mounts) don't
        // produce a sparse source from `ftruncate + pwrite` — in that
        // case sparseness is unachievable and we just confirm the
        // destination didn't blow up beyond the source's footprint.
        #[cfg(unix)]
        {
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
    }

    #[test]
    fn sparse_copy_is_independent_after_source_and_destination_writes() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src.bin");
        let dst = dir.path().join("dst.bin");
        let len = 4 * 1024 * 1024;
        make_sparse(&src, len, &[0, 2 * 1024 * 1024]).unwrap();

        sparse_copy(&src, &dst).unwrap();
        let original_dst = std::fs::read(&dst).unwrap();

        std::fs::write(&src, vec![0xCD; len as usize]).unwrap();
        assert_eq!(std::fs::read(&dst).unwrap(), original_dst);

        std::fs::write(&dst, vec![0xEF; len as usize]).unwrap();
        assert!(
            std::fs::read(&src)
                .unwrap()
                .iter()
                .all(|byte| *byte == 0xCD)
        );
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

    #[test]
    fn strict_reflink_preserves_isolation_or_fails_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src.bin");
        let dst = dir.path().join("dst.bin");
        std::fs::write(&src, vec![0xAB; 128 * 1024]).unwrap();

        match reflink(&src, &dst) {
            Ok(len) => {
                assert_eq!(len, 128 * 1024);
                assert_eq!(std::fs::read(&dst).unwrap(), std::fs::read(&src).unwrap());
                std::fs::write(&dst, vec![0xCD; 128 * 1024]).unwrap();
                assert!(
                    std::fs::read(&src)
                        .unwrap()
                        .iter()
                        .all(|byte| *byte == 0xAB)
                );
            }
            Err(error) if is_reflink_unsupported(&error) => {
                assert!(
                    !dst.exists(),
                    "an unsupported strict reflink must not leave a partial destination"
                );
            }
            Err(error) => panic!("strict reflink failed unexpectedly: {error}"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn recognizes_windows_reflink_capability_errors() {
        for code in [1, 17, 50, 87, 124, 775] {
            assert!(is_reflink_unsupported(&io::Error::from_raw_os_error(code)));
        }
        assert!(!is_reflink_unsupported(&io::Error::from_raw_os_error(5)));
    }
}

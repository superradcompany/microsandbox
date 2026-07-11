//! Filesystem allocation-map scanning.
//!
//! Answers one question — "which byte ranges of this file are actually allocated?" — with the same `(offset, length)` shape on every supported platform: `SEEK_DATA`/`SEEK_HOLE` on
//! unix, `FSCTL_QUERY_ALLOCATED_RANGES` on Windows. Consumers (sparse snapshot export, integrity verification, capture) never branch on OS; only the scan backend does.
//!
//! Also home to the hole-restoration primitives that the scan's consumers need on platforms where "just don't write the hole" is not enough: NTFS only keeps unwritten ranges
//! unallocated on files flagged sparse ([`mark_sparse`]), and APFS densifies files on any write, so holes must be punched explicitly ([`punch_hole_aligned`]).

use std::fs::File;
use std::io;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
#[cfg(windows)]
use std::ptr;

#[cfg(windows)]
use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, HANDLE};
#[cfg(windows)]
use windows_sys::Win32::System::IO::DeviceIoControl;
#[cfg(windows)]
use windows_sys::Win32::System::Ioctl::{
    FILE_ALLOCATED_RANGE_BUFFER, FSCTL_QUERY_ALLOCATED_RANGES, FSCTL_SET_SPARSE,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Allocation map of a file: logical length plus sorted, non-overlapping, byte-granular data extents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtentMap {
    /// Logical (apparent) file size in bytes.
    pub len: u64,
    /// Sorted `(offset, length)` allocated ranges. Everything outside them reads as zeros.
    pub extents: Vec<(u64, u64)>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ExtentMap {
    /// Scan `path`'s allocation map.
    ///
    /// Returns `Ok(None)` when the filesystem cannot enumerate extents (no `SEEK_DATA` / allocated-ranges support); callers should then treat the file as fully dense. A dense file
    /// on a capable filesystem scans as `Some` with a single `(0, len)` extent.
    ///
    /// **Blocking.** Callers in async contexts should wrap in `tokio::task::spawn_blocking`.
    pub fn scan(path: &Path) -> io::Result<Option<ExtentMap>> {
        let file = File::open(path)?;
        Self::scan_file(&file)
    }

    /// [`ExtentMap::scan`] over an already-open file.
    pub fn scan_file(file: &File) -> io::Result<Option<ExtentMap>> {
        let len = file.metadata()?.len();
        if len == 0 {
            return Ok(Some(ExtentMap {
                len,
                extents: Vec::new(),
            }));
        }
        scan_impl(file, len)
    }

    /// Sum of extent lengths — the bytes a sparse-aware reader must actually move.
    pub fn data_bytes(&self) -> u64 {
        self.extents.iter().map(|(_, len)| len).sum()
    }

    /// True when some of the logical range is unallocated.
    pub fn has_holes(&self) -> bool {
        self.data_bytes() < self.len
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Flag `file` as sparse so NTFS keeps unwritten ranges unallocated. No-op semantics on filesystems where files are implicitly hole-capable is handled by the unix definition
/// below.
#[cfg(windows)]
pub fn mark_sparse(file: &File) -> io::Result<()> {
    let mut bytes_returned = 0;
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle() as HANDLE,
            FSCTL_SET_SPARSE,
            ptr::null(),
            0,
            ptr::null_mut(),
            0,
            &mut bytes_returned,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Unix files are hole-capable without any flag; kept so callers can mark destinations unconditionally.
#[cfg(unix)]
pub fn mark_sparse(_file: &File) -> io::Result<()> {
    Ok(())
}

/// Punch a hole over as much of `[offset, offset + len)` as the filesystem's allocation block size allows, shrinking the range inward to block alignment. Ranges smaller than one
/// block are left allocated. Needed on APFS, which densifies a file on any write — unwritten ranges do not stay holes the way they do on ext4/XFS.
#[cfg(target_os = "macos")]
pub fn punch_hole_aligned(file: &File, offset: u64, len: u64) -> io::Result<()> {
    let block = allocation_block_size(file)?;
    let start = offset.div_ceil(block).saturating_mul(block);
    let end = (offset.saturating_add(len) / block).saturating_mul(block);
    if end <= start {
        return Ok(());
    }
    let args = libc::fpunchhole_t {
        fp_flags: 0,
        reserved: 0,
        fp_offset: start as libc::off_t,
        fp_length: (end - start) as libc::off_t,
    };
    let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_PUNCHHOLE, &args) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Hole punching is unnecessary outside macOS: on ext4/XFS/btrfs (and on NTFS files flagged via [`mark_sparse`]) ranges that are never written stay unallocated.
#[cfg(not(target_os = "macos"))]
pub fn punch_hole_aligned(_file: &File, _offset: u64, _len: u64) -> io::Result<()> {
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

#[cfg(unix)]
fn scan_impl(file: &File, len: u64) -> io::Result<Option<ExtentMap>> {
    let fd = file.as_raw_fd();

    let mut extents: Vec<(u64, u64)> = Vec::new();
    let mut off: i64 = 0;
    while (off as u64) < len {
        let data_start = unsafe { libc::lseek(fd, off, libc::SEEK_DATA) };
        if data_start < 0 {
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                // No more data past this offset: trailing hole.
                Some(libc::ENXIO) => break,
                // Filesystem doesn't implement the seek flags — report "can't enumerate" rather than failing the caller. ENOTSUP and EOPNOTSUPP are distinct on macOS / BSDs.
                Some(libc::EINVAL) | Some(libc::ENOTSUP) => return Ok(None),
                #[cfg(not(target_os = "linux"))]
                Some(libc::EOPNOTSUPP) => return Ok(None),
                _ => return Err(err),
            }
        }
        let data_end = unsafe { libc::lseek(fd, data_start, libc::SEEK_HOLE) };
        if data_end < 0 {
            return Err(io::Error::last_os_error());
        }
        let data_end = (data_end as u64).min(len);
        let data_start = data_start as u64;
        if data_end <= data_start {
            break;
        }
        extents.push((data_start, data_end - data_start));
        off = data_end as i64;
    }

    Ok(Some(ExtentMap { len, extents }))
}

#[cfg(windows)]
fn scan_impl(file: &File, len: u64) -> io::Result<Option<ExtentMap>> {
    // Query in batches; ERROR_MORE_DATA means the output buffer filled and the walk continues from the end of the last returned range.
    const BATCH: usize = 64;

    let handle = file.as_raw_handle() as HANDLE;
    let mut extents: Vec<(u64, u64)> = Vec::new();
    let mut next_offset: u64 = 0;

    while next_offset < len {
        let query = FILE_ALLOCATED_RANGE_BUFFER {
            FileOffset: next_offset as i64,
            Length: (len - next_offset) as i64,
        };
        let mut out = [FILE_ALLOCATED_RANGE_BUFFER {
            FileOffset: 0,
            Length: 0,
        }; BATCH];
        let mut bytes_returned: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                FSCTL_QUERY_ALLOCATED_RANGES,
                &query as *const _ as *const _,
                size_of::<FILE_ALLOCATED_RANGE_BUFFER>() as u32,
                out.as_mut_ptr() as *mut _,
                (size_of::<FILE_ALLOCATED_RANGE_BUFFER>() * BATCH) as u32,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };
        let more = if ok == 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(ERROR_MORE_DATA as i32) {
                true
            } else {
                // Filesystem without allocated-range support (FAT, network shares): report "can't enumerate".
                return Ok(None);
            }
        } else {
            false
        };

        let count = bytes_returned as usize / size_of::<FILE_ALLOCATED_RANGE_BUFFER>();
        if count == 0 {
            break;
        }
        for range in &out[..count] {
            let start = range.FileOffset as u64;
            let end = (start + range.Length as u64).min(len);
            if end > start {
                extents.push((start, end - start));
            }
        }
        let (last_off, last_len) = extents[extents.len() - 1];
        next_offset = last_off + last_len;
        if !more {
            break;
        }
    }

    Ok(Some(ExtentMap { len, extents }))
}

/// Fundamental allocation block size of the filesystem hosting `file`.
#[cfg(target_os = "macos")]
fn allocation_block_size(file: &File) -> io::Result<u64> {
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstatfs(file.as_raw_fd(), &mut stat) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((stat.f_bsize as u64).max(512))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::{Seek, SeekFrom, Write};

    use super::*;

    #[test]
    fn dense_file_scans_as_single_extent_or_unsupported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dense.bin");
        std::fs::write(&path, vec![0xAB; 8192]).unwrap();

        match ExtentMap::scan(&path).unwrap() {
            None => {} // FS can't enumerate; callers treat as dense
            Some(map) => {
                assert_eq!(map.len, 8192);
                assert_eq!(map.data_bytes(), 8192);
                assert!(!map.has_holes());
            }
        }
    }

    #[test]
    fn empty_file_scans_as_empty_map() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.bin");
        std::fs::write(&path, b"").unwrap();

        let map = ExtentMap::scan(&path).unwrap().unwrap();
        assert_eq!(map.len, 0);
        assert!(map.extents.is_empty());
        assert!(!map.has_holes());
    }

    #[test]
    fn sparse_file_scan_covers_all_data() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sparse.bin");
        let len: u64 = 8 * 1024 * 1024;
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        // Mark before extending so NTFS keeps the gap a hole.
        mark_sparse(&f).unwrap();
        f.set_len(len).unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
        f.write_all(&[0x11; 4096]).unwrap();
        f.seek(SeekFrom::Start(4 * 1024 * 1024)).unwrap();
        f.write_all(&[0x22; 4096]).unwrap();
        f.sync_all().unwrap();
        punch_hole_aligned(&f, 4096, 4 * 1024 * 1024 - 4096).unwrap();
        punch_hole_aligned(&f, 4 * 1024 * 1024 + 4096, len - (4 * 1024 * 1024 + 4096)).unwrap();
        drop(f);

        let Some(map) = ExtentMap::scan(&path).unwrap() else {
            eprintln!("filesystem can't enumerate extents; scan not exercised");
            return;
        };
        assert_eq!(map.len, len);
        // Extents must cover both data ranges (a densifying FS may report more than the written bytes, never less).
        let covers = |target: u64| {
            map.extents
                .iter()
                .any(|(off, l)| *off <= target && target < off + l)
        };
        assert!(covers(0), "extent map misses data at 0: {:?}", map.extents);
        assert!(
            covers(4 * 1024 * 1024),
            "extent map misses data at 4 MiB: {:?}",
            map.extents
        );
    }
}

//! Direct local RAM generations. The source's live mappings are never replaced.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

#[cfg(feature = "runner")]
use std::{
    fs::OpenOptions,
    io::{Seek, SeekFrom, Write},
};

#[cfg(feature = "runner")]
use msb_krun::{GuestMemoryRange, MemoryCaptureSink};
use serde::{Deserialize, Serialize};

use super::memory_cache::open_pinned;
use super::{CachedMemoryRegion, MemoryCache};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Complete local memory geometry; this is not a portable memory manifest.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalMemory {
    /// Immutable backend-owned file, independent of the source sandbox directory.
    pub path: PathBuf,
    /// Native mapping geometry in guest-physical order.
    pub regions: Vec<CachedMemoryRegion>,
    /// Retained memory generation used only for incremental capture continuity.
    pub generation: u64,
    /// Memory topology to which the generation belongs.
    pub topology: u64,
}

#[cfg(feature = "runner")]
pub(crate) struct LocalMemoryPin {
    pub(crate) memory: LocalMemory,
    pub(crate) _file: File,
}

#[cfg(feature = "runner")]
pub(super) struct LocalMemoryCapture {
    staging: tempfile::TempDir,
    file: File,
    path: PathBuf,
    regions: Vec<CachedMemoryRegion>,
    length: u64,
    incremental: bool,
    page_size: u64,
    pub(super) reflink: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LocalMemory {
    /// Reserve publication-to-pin ownership before asking the source to capture RAM.
    /// Stable lock inodes are never unlinked, so eviction cannot race a replacement lock.
    pub fn reserve(root: &Path, id: &str) -> io::Result<File> {
        if id.is_empty()
            || id.len() > 128
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        {
            return Err(io::Error::other("invalid local generation identity"));
        }
        let cache = MemoryCache::open_namespace(root.into(), "branches")?;
        let path = cache
            .root
            .join(format!("{id}-{}.handoff-lock", cache.page_size));
        let file = microsandbox_utils::process_lock::open_lock_file(&path)?;
        microsandbox_utils::process_lock::lock_exclusive(&file)?;
        Ok(file)
    }

    /// Reclaim only after pending handoff, retained-baseline and VM pins have been released.
    pub fn evict(&self) -> io::Result<bool> {
        let handoff = microsandbox_utils::process_lock::open_lock_file(
            &self.path.with_extension("handoff-lock"),
        )?;
        if !microsandbox_utils::process_lock::try_lock_exclusive(&handoff)? {
            return Ok(false);
        }
        super::memory_cache::evict_unpinned(&self.path)
    }

    /// Acquire independent backing ownership before launching or mapping a child.
    pub fn pin(&self) -> io::Result<File> {
        let mut file_end = 0;
        let mut guest_end = 0;
        for region in &self.regions {
            if region.length == 0
                || region.file_offset != file_end
                || region.guest_address < guest_end
            {
                return Err(io::Error::other("invalid local memory geometry"));
            }
            file_end = region
                .file_offset
                .checked_add(region.length)
                .ok_or_else(|| io::Error::other("memory size overflow"))?;
            guest_end = region
                .guest_address
                .checked_add(region.length)
                .ok_or_else(|| io::Error::other("guest range overflow"))?;
        }
        if file_end == 0 {
            return Err(io::Error::other("empty local memory"));
        }
        open_pinned(&self.path, file_end)?
            .ok_or_else(|| io::Error::other("local memory backing is missing"))
    }
}

#[cfg(feature = "runner")]
impl LocalMemoryCapture {
    pub(super) fn new(
        root: &Path,
        id: &str,
        baseline: Option<&LocalMemoryPin>,
    ) -> io::Result<Self> {
        let cache = MemoryCache::open_namespace(root.into(), "branches")?;
        let staging = tempfile::Builder::new()
            .prefix(".capture-")
            .tempdir_in(&cache.root)?;
        let temporary = staging.path().join("memory");
        let mut reflink = false;
        if let Some(base) = baseline {
            // This is a process-local handoff, not durable snapshot publication. On
            // non-reflink filesystems the ordinary copy helper flushes the entire RAM
            // backing, unnecessarily extending the source pause by seconds.
            let (_, strategy) =
                microsandbox_utils::copy::fast_copy_without_sync(&base.memory.path, &temporary)?;
            reflink = strategy == microsandbox_utils::copy::FastCopyStrategy::Reflink;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))?;
            }
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&temporary)?;
        let length = file.metadata()?.len();
        Ok(Self {
            staging,
            file,
            length,
            reflink,
            path: cache.root.join(format!("{id}-{}.ram", cache.page_size)),
            regions: baseline
                .map(|base| base.memory.regions.clone())
                .unwrap_or_default(),
            incremental: baseline.is_some(),
            page_size: cache.page_size,
        })
    }

    fn offset(&mut self, range: GuestMemoryRange) -> io::Result<u64> {
        let end = range
            .start()
            .checked_add(range.length())
            .ok_or_else(|| io::Error::other("range overflow"))?;
        if self.incremental {
            let region = self
                .regions
                .iter()
                .find(|region| {
                    range.start() >= region.guest_address
                        && end <= region.guest_address + region.length
                })
                .ok_or_else(|| io::Error::other("delta falls outside retained memory topology"))?;
            return Ok(region.file_offset + range.start() - region.guest_address);
        }
        let offset = self.length;
        if let Some(last) = self.regions.last_mut() {
            let previous_end = last.guest_address + last.length;
            if range.start() < previous_end {
                return Err(io::Error::other("unordered full memory capture"));
            }
            if range.start() == previous_end {
                last.length += range.length();
            } else {
                self.regions.push(CachedMemoryRegion {
                    guest_address: range.start(),
                    length: range.length(),
                    file_offset: offset,
                });
            }
        } else {
            self.regions.push(CachedMemoryRegion {
                guest_address: range.start(),
                length: range.length(),
                file_offset: offset,
            });
        }
        self.length = self
            .length
            .checked_add(range.length())
            .ok_or_else(|| io::Error::other("memory file overflow"))?;
        Ok(offset)
    }

    pub(super) fn finish(self, generation: u64, topology: u64) -> io::Result<LocalMemoryPin> {
        for region in &self.regions {
            if !region.guest_address.is_multiple_of(self.page_size)
                || !region.length.is_multiple_of(self.page_size)
                || !region.file_offset.is_multiple_of(self.page_size)
            {
                return Err(io::Error::other(
                    "local memory geometry is not native-page aligned",
                ));
            }
        }
        self.file.set_len(self.length)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            self.file
                .set_permissions(std::fs::Permissions::from_mode(0o400))?;
        }
        // Local branching promises process-independent ownership, not crash recovery. Closing
        // the writer and publishing the completed inode suffices; no RAM-sized fsync/hash pass.
        drop(self.file);
        let memory = LocalMemory {
            path: self.path,
            regions: self.regions,
            generation,
            topology,
        };
        let file = open_pinned(&self.staging.path().join("memory"), self.length)?
            .ok_or_else(|| io::Error::other("capture staging disappeared"))?;
        std::fs::hard_link(self.staging.path().join("memory"), &memory.path)?;
        Ok(LocalMemoryPin {
            memory,
            _file: file,
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "runner")]
impl MemoryCaptureSink for LocalMemoryCapture {
    fn write_bytes(&mut self, range: GuestMemoryRange, bytes: &[u8]) -> io::Result<()> {
        if range.length() != bytes.len() as u64 {
            return Err(io::Error::other("capture length mismatch"));
        }
        let offset = self.offset(range)?;
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(bytes)
    }

    fn write_zero(&mut self, range: GuestMemoryRange) -> io::Result<()> {
        let offset = self.offset(range)?;
        if self.incremental {
            // A zero/discard delta must replace old bytes, not leave stale private content.
            self.file.seek(SeekFrom::Start(offset))?;
            let zeroes = [0u8; 65536];
            let mut remaining = range.length();
            while remaining != 0 {
                let count = remaining.min(zeroes.len() as u64) as usize;
                self.file.write_all(&zeroes[..count])?;
                remaining -= count as u64;
            }
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, feature = "runner"))]
mod tests {
    use std::io::Read;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn range(start: u64, length: u64) -> GuestMemoryRange {
        GuestMemoryRange::new(start, length).unwrap()
    }

    #[test]
    fn direct_generation_is_sparse_complete_and_independently_pinned() {
        let dir = tempfile::tempdir().unwrap();
        let page = MemoryCache::open(dir.path()).unwrap().page_size;
        let mut sink = LocalMemoryCapture::new(dir.path(), "first", None).unwrap();
        sink.write_bytes(range(0, page), &vec![7; page as usize])
            .unwrap();
        sink.write_zero(range(page, page)).unwrap();
        sink.write_bytes(range(4 * page, page), &vec![9; page as usize])
            .unwrap();
        let captured = sink.finish(1, 1).unwrap();
        assert_eq!(captured.memory.regions.len(), 2);
        assert_eq!(captured.memory.regions[1].file_offset, 2 * page);
        #[cfg(unix)]
        assert_eq!(
            captured._file.metadata().unwrap().permissions().mode() & 0o777,
            0o400
        );
        let mut child = captured.memory.pin().unwrap();
        std::fs::remove_file(&captured.memory.path).unwrap();
        drop(captured);
        let mut bytes = Vec::new();
        child.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes.len(), (3 * page) as usize);
        assert!(
            bytes[page as usize..(2 * page) as usize]
                .iter()
                .all(|byte| *byte == 0)
        );
    }

    #[test]
    fn incremental_zero_and_write_do_not_mutate_the_baseline() {
        let dir = tempfile::tempdir().unwrap();
        let page = MemoryCache::open(dir.path()).unwrap().page_size;
        let mut full = LocalMemoryCapture::new(dir.path(), "base", None).unwrap();
        full.write_bytes(range(0, 2 * page), &vec![7; (2 * page) as usize])
            .unwrap();
        let base = full.finish(1, 1).unwrap();
        let mut delta = LocalMemoryCapture::new(dir.path(), "delta", Some(&base)).unwrap();
        delta.write_zero(range(0, page)).unwrap();
        delta
            .write_bytes(range(page, page), &vec![9; page as usize])
            .unwrap();
        let child = delta.finish(2, 1).unwrap();
        assert!(
            std::fs::read(&base.memory.path)
                .unwrap()
                .iter()
                .all(|b| *b == 7)
        );
        let bytes = std::fs::read(&child.memory.path).unwrap();
        assert!(bytes[..page as usize].iter().all(|b| *b == 0));
        assert!(bytes[page as usize..].iter().all(|b| *b == 9));
    }

    #[test]
    fn capture_rejects_overlap_unaligned_geometry_and_identity_collision() {
        let dir = tempfile::tempdir().unwrap();
        let page = MemoryCache::open(dir.path()).unwrap().page_size;
        let mut sink = LocalMemoryCapture::new(dir.path(), "same", None).unwrap();
        sink.write_zero(range(0, page)).unwrap();
        assert!(sink.write_zero(range(0, page)).is_err());
        let _pin = sink.finish(1, 1).unwrap();
        let mut collision = LocalMemoryCapture::new(dir.path(), "same", None).unwrap();
        collision.write_zero(range(0, page)).unwrap();
        assert!(collision.finish(2, 1).is_err());
        let mut unaligned = LocalMemoryCapture::new(dir.path(), "unaligned", None).unwrap();
        unaligned.write_zero(range(0, 4096)).unwrap();
        if page > 4096 {
            assert!(unaligned.finish(3, 1).is_err());
        }
    }

    #[test]
    fn pending_handoff_survives_source_pin_loss_and_eviction() {
        let dir = tempfile::tempdir().unwrap();
        let page = MemoryCache::open(dir.path()).unwrap().page_size;
        let reservation = LocalMemory::reserve(dir.path(), "handoff").unwrap();
        let mut sink = LocalMemoryCapture::new(dir.path(), "handoff", None).unwrap();
        sink.write_zero(range(0, page)).unwrap();
        let source = sink.finish(1, 1).unwrap();
        let memory = source.memory.clone();
        drop(source); // source exits before the SDK receives the response
        assert!(!memory.evict().unwrap());
        let child = memory.pin().unwrap();
        drop(reservation);
        assert!(!memory.evict().unwrap());
        drop(child);
        assert!(memory.evict().unwrap());
        assert!(memory.pin().is_err());
    }
}

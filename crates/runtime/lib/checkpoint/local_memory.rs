//! Direct local RAM generations. The source's live mappings are never replaced.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
#[cfg(feature = "runner")]
use std::time::Instant;

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

/// Pending local handoff ownership. The original backend lock remains held even when a
/// Linux RAM-side reservation is available, so either storage strategy has the same lifetime.
pub struct LocalMemoryReservation {
    _backend: File,
    #[cfg(target_os = "linux")]
    _ram: Option<File>,
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
    capacity: Option<u64>,
    baseline: Option<(u64, u64)>,
    pub(super) reflink: bool,
    pub(super) baseline_bytes: u64,
    pub(super) prepare_us: u128,
    pub(super) ram_backed: bool,
    #[cfg(target_os = "linux")]
    ram_publication: Option<super::local_memory_ram::RamPublication>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LocalMemory {
    /// Reserve publication-to-pin ownership before asking the source to capture RAM.
    /// Stable lock inodes are never unlinked, so eviction cannot race a replacement lock.
    pub fn reserve(root: &Path, id: &str) -> io::Result<LocalMemoryReservation> {
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
        Ok(LocalMemoryReservation {
            _backend: file,
            #[cfg(target_os = "linux")]
            _ram: super::local_memory_ram::reserve(root, id, cache.page_size),
        })
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
impl LocalMemoryPin {
    /// Exact capture geometry includes kernel/device mappings and reserved hotplug ranges,
    /// not just the user-facing guest RAM size. The retained immutable file is authoritative.
    pub(crate) fn capacity(&self) -> io::Result<u64> {
        let length = self
            .memory
            .regions
            .iter()
            .try_fold(0u64, |length, region| {
                if region.length == 0 || region.file_offset != length {
                    return Err(io::Error::other("invalid retained memory geometry"));
                }
                length
                    .checked_add(region.length)
                    .ok_or_else(|| io::Error::other("retained memory size overflow"))
            })?;
        if length == 0 || self._file.metadata()?.len() != length {
            return Err(io::Error::other(
                "retained memory size differs from geometry",
            ));
        }
        Ok(length)
    }
}

#[cfg(feature = "runner")]
impl LocalMemoryCapture {
    #[cfg(test)]
    pub(super) fn new(
        root: &Path,
        id: &str,
        baseline: Option<&LocalMemoryPin>,
    ) -> io::Result<Self> {
        Self::prepare(
            root,
            id,
            baseline,
            baseline.map(LocalMemoryPin::capacity).transpose()?,
        )
    }

    /// Prepare immutable baseline bytes while the source can still run. The caller must
    /// revalidate the baseline token after quiescing before using this sink for a delta.
    /// Unknown capture geometry retains ordinary disk backing; it must never be guessed from
    /// guest-visible RAM sizing to admit a bounded tmpfs allocation.
    pub(super) fn prepare(
        root: &Path,
        id: &str,
        baseline: Option<&LocalMemoryPin>,
        capacity: Option<u64>,
    ) -> io::Result<Self> {
        let started = Instant::now();
        if capacity == Some(0) {
            return Err(io::Error::other("local memory capacity is empty"));
        }
        if let (Some(base), Some(capacity)) = (baseline, capacity)
            && base._file.metadata()?.len() > capacity
        {
            return Err(io::Error::other("local baseline exceeds memory capacity"));
        }
        let cache = MemoryCache::open_namespace(root.into(), "branches")?;
        #[cfg(target_os = "linux")]
        let ram = match capacity {
            Some(capacity) => {
                super::local_memory_ram::prepare(root, &cache.root, id, cache.page_size, capacity)
            }
            None => None,
        };
        #[cfg(target_os = "linux")]
        let (staging, path, ram_publication) = if let Some(ram) = ram {
            (ram.staging, ram.path, Some(ram.publication))
        } else {
            (
                tempfile::Builder::new()
                    .prefix(".capture-")
                    .tempdir_in(&cache.root)?,
                cache.root.join(format!("{id}-{}.ram", cache.page_size)),
                None,
            )
        };
        #[cfg(not(target_os = "linux"))]
        let (staging, path) = (
            tempfile::Builder::new()
                .prefix(".capture-")
                .tempdir_in(&cache.root)?,
            cache.root.join(format!("{id}-{}.ram", cache.page_size)),
        );
        let temporary = staging.path().join("memory");
        let mut reflink = false;
        let mut baseline_bytes = 0;
        if let Some(base) = baseline {
            let metadata = base._file.metadata()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                baseline_bytes = metadata.blocks().saturating_mul(512);
            }
            #[cfg(not(unix))]
            {
                baseline_bytes = metadata.len();
            }
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
        // A cancelled initiating SDK can release its handoff guard while capture is still
        // running. The source keeps the staging inode pinned until a readonly successor owns
        // it, so cooperative RAM reclamation cannot race an in-progress write/publication.
        #[cfg(target_os = "linux")]
        microsandbox_utils::process_lock::lock_shared(&file)?;
        Ok(Self {
            staging,
            file,
            length,
            reflink,
            path,
            regions: baseline
                .map(|base| base.memory.regions.clone())
                .unwrap_or_default(),
            incremental: baseline.is_some(),
            page_size: cache.page_size,
            capacity,
            baseline: baseline.map(|base| (base.memory.generation, base.memory.topology)),
            baseline_bytes,
            prepare_us: started.elapsed().as_micros(),
            #[cfg(target_os = "linux")]
            ram_backed: ram_publication.is_some(),
            #[cfg(not(target_os = "linux"))]
            ram_backed: false,
            #[cfg(target_os = "linux")]
            ram_publication,
        })
    }

    pub(super) fn baseline(&self) -> Option<(u64, u64)> {
        self.baseline
    }

    /// A same-topology non-beneficial delta requires a complete image. Discard prepared bytes
    /// without touching the old generation or resuming a paused user VM. For changed/unknown
    /// topology, the caller must replace this sink with unknown-capacity disk preparation.
    pub(super) fn reset_to_full(&mut self) -> io::Result<()> {
        self.file.set_len(0)?;
        self.regions.clear();
        self.length = 0;
        self.incremental = false;
        self.reflink = false;
        self.baseline = None;
        Ok(())
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
        let length = self
            .length
            .checked_add(range.length())
            .filter(|length| self.capacity.is_none_or(|capacity| *length <= capacity))
            .ok_or_else(|| io::Error::other("capture exceeds reserved memory capacity"))?;
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
        self.length = length;
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
        #[cfg(target_os = "linux")]
        let file = open_pinned(&self.staging.path().join("memory"), self.length)?
            .ok_or_else(|| io::Error::other("capture staging disappeared"))?;
        drop(self.file);
        let memory = LocalMemory {
            path: self.path,
            regions: self.regions,
            generation,
            topology,
        };
        #[cfg(not(target_os = "linux"))]
        let file = open_pinned(&self.staging.path().join("memory"), self.length)?
            .ok_or_else(|| io::Error::other("capture staging disappeared"))?;
        #[cfg(target_os = "linux")]
        if let Some(publication) = &self.ram_publication {
            publication.publish(self.staging.path(), &memory.path)?;
        } else {
            std::fs::hard_link(self.staging.path().join("memory"), &memory.path)?;
        }
        #[cfg(not(target_os = "linux"))]
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

    #[test]
    fn prepared_delta_can_fall_back_to_full_without_old_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let page = MemoryCache::open(dir.path()).unwrap().page_size;
        let mut full =
            LocalMemoryCapture::prepare(dir.path(), "base", None, Some(2 * page)).unwrap();
        full.write_bytes(range(0, 2 * page), &vec![7; (2 * page) as usize])
            .unwrap();
        let base = full.finish(7, 9).unwrap();
        let mut prepared =
            LocalMemoryCapture::prepare(dir.path(), "next", Some(&base), Some(2 * page)).unwrap();
        assert_eq!(prepared.baseline(), Some((7, 9)));
        prepared.reset_to_full().unwrap();
        assert_eq!(prepared.baseline(), None);
        prepared.write_zero(range(0, page)).unwrap();
        prepared
            .write_bytes(range(page, page), &vec![3; page as usize])
            .unwrap();
        let child = prepared.finish(8, 9).unwrap();
        let bytes = std::fs::read(&child.memory.path).unwrap();
        assert!(bytes[..page as usize].iter().all(|byte| *byte == 0));
        assert!(bytes[page as usize..].iter().all(|byte| *byte == 3));
        assert!(
            std::fs::read(&base.memory.path)
                .unwrap()
                .iter()
                .all(|byte| *byte == 7)
        );
    }

    #[test]
    fn capture_cannot_outgrow_its_prepared_capacity() {
        let dir = tempfile::tempdir().unwrap();
        let page = MemoryCache::open(dir.path()).unwrap().page_size;
        assert!(LocalMemoryCapture::prepare(dir.path(), "zero", None, Some(0)).is_err());
        let mut full = LocalMemoryCapture::prepare(dir.path(), "small", None, Some(page)).unwrap();
        assert!(full.write_zero(range(0, 2 * page)).is_err());
        // Rejection precedes geometry mutation, so a correctly sized full cut still works.
        full.write_zero(range(0, page)).unwrap();
        let base = full.finish(1, 1).unwrap();
        assert!(
            LocalMemoryCapture::prepare(dir.path(), "too-small", Some(&base), Some(page / 2))
                .is_err()
        );
    }

    #[test]
    fn unknown_geometry_keeps_disk_backing_and_records_actual_capacity() {
        let dir = tempfile::tempdir().unwrap();
        let page = MemoryCache::open(dir.path()).unwrap().page_size;
        let _reservation = LocalMemory::reserve(dir.path(), "geometry").unwrap();
        let mut full = LocalMemoryCapture::prepare(dir.path(), "geometry", None, None).unwrap();
        assert!(!full.ram_backed);
        // The capture contains boot RAM, a separate firmware range and reserved hotplug RAM.
        // Its file length is their sum, not guest-visible RAM or the highest physical address.
        full.write_bytes(range(0, 2 * page), &vec![7; (2 * page) as usize])
            .unwrap();
        full.write_zero(range(4 * page, page)).unwrap();
        full.write_zero(range(8 * page, 3 * page)).unwrap();
        let mut retained = full.finish(1, 1).unwrap();
        assert_eq!(retained.capacity().unwrap(), 6 * page);
        retained.memory.regions[1].file_offset += page;
        assert!(retained.capacity().is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn changed_topology_replaces_bounded_ram_sink_with_unknown_disk_sink() {
        let dir = tempfile::tempdir().unwrap();
        let page = MemoryCache::open(dir.path()).unwrap().page_size;
        let mut full = LocalMemoryCapture::prepare(dir.path(), "base", None, None).unwrap();
        full.write_bytes(range(0, page), &vec![7; page as usize])
            .unwrap();
        let base = full.finish(1, 1).unwrap();
        let _reservation = LocalMemory::reserve(dir.path(), "changed").unwrap();
        let prepared = LocalMemoryCapture::prepare(
            dir.path(),
            "changed",
            Some(&base),
            Some(base.capacity().unwrap()),
        )
        .unwrap();
        assert!(prepared.ram_backed);
        // The coordinator observes a different paused topology and drops, rather than grows,
        // the reserved tmpfs capture. No unknown-size generation can exceed a RAM admission.
        drop(prepared);
        let mut replacement =
            LocalMemoryCapture::prepare(dir.path(), "changed", None, None).unwrap();
        assert!(!replacement.ram_backed);
        replacement.write_zero(range(0, 3 * page)).unwrap();
        let changed = replacement.finish(2, 2).unwrap();
        assert_eq!(changed.capacity().unwrap(), 3 * page);
        assert_eq!(
            std::fs::read(&base.memory.path).unwrap(),
            vec![7; page as usize]
        );
    }

    #[test]
    fn local_memory_handoff_keeps_its_existing_serialized_shape() {
        let dir = tempfile::tempdir().unwrap();
        let page = MemoryCache::open(dir.path()).unwrap().page_size;
        let mut capture =
            LocalMemoryCapture::prepare(dir.path(), "shape", None, Some(page)).unwrap();
        capture.write_zero(range(0, page)).unwrap();
        let captured = capture.finish(1, 2).unwrap();
        let value = serde_json::to_value(&captured.memory).unwrap();
        let mut keys = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        keys.sort_unstable();
        assert_eq!(keys, ["generation", "path", "regions", "topology"]);
        let decoded: LocalMemory = serde_json::from_value(value).unwrap();
        assert_eq!(decoded.path, captured.memory.path);
        assert_eq!(decoded.generation, 1);
        assert_eq!(decoded.topology, 2);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ram_storage_requires_dual_reservation_and_keeps_pending_handoff_alive() {
        let dir = tempfile::tempdir().unwrap();
        let page = MemoryCache::open(dir.path()).unwrap().page_size;
        let unreserved =
            LocalMemoryCapture::prepare(dir.path(), "unreserved", None, Some(page)).unwrap();
        assert!(!unreserved.ram_backed);
        let reservation = LocalMemory::reserve(dir.path(), "reserved").unwrap();
        assert!(reservation._ram.is_some());
        let mut capture =
            LocalMemoryCapture::prepare(dir.path(), "reserved", None, Some(page)).unwrap();
        assert!(capture.ram_backed);
        capture
            .write_bytes(range(0, page), &vec![7; page as usize])
            .unwrap();
        let source = capture.finish(1, 1).unwrap();
        let memory = source.memory.clone();
        let ram_lock = std::fs::metadata(memory.path.with_extension("handoff-lock")).unwrap();
        let reserved_lock = reservation._ram.as_ref().unwrap().metadata().unwrap();
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            (ram_lock.dev(), ram_lock.ino()),
            (reserved_lock.dev(), reserved_lock.ino())
        );
        drop(source);
        assert!(!memory.evict().unwrap());
        let child = memory.pin().unwrap();
        drop(reservation);
        assert!(!memory.evict().unwrap());
        drop(child);
        assert!(memory.evict().unwrap());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cancelled_handoff_does_not_reclaim_a_generation_still_being_written() {
        let dir = tempfile::tempdir().unwrap();
        let page = MemoryCache::open(dir.path()).unwrap().page_size;
        let reservation = LocalMemory::reserve(dir.path(), "writing").unwrap();
        let mut capture =
            LocalMemoryCapture::prepare(dir.path(), "writing", None, Some(page)).unwrap();
        assert!(capture.ram_backed);
        drop(reservation);
        // A new capture triggers reclamation after the cancelled caller releases its guard.
        let next = LocalMemory::reserve(dir.path(), "next").unwrap();
        let _other = LocalMemoryCapture::prepare(dir.path(), "next", None, Some(page)).unwrap();
        capture
            .write_bytes(range(0, page), &vec![9; page as usize])
            .unwrap();
        let captured = capture.finish(1, 1).unwrap();
        assert_eq!(
            std::fs::read(&captured.memory.path).unwrap(),
            vec![9; page as usize]
        );
        drop(next);
    }
}

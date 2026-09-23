//! Immutable local realizations of complete portable memory manifests.
//!
//! The cache is trusted host storage, not a second portable snapshot format. Publication is
//! atomic; readers retain read-only handles, so removing a snapshot never invalidates live RAM.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use microsandbox_image::checkpoint::{
    CheckpointObjectReadTiming, MemoryExtentContent, MemoryManifest, ObjectId,
};

use super::object_pipeline::{ObjectPipelineTiming, consume_verified_objects};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One native-aligned, contiguous guest address span in a flat cache file.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CachedMemoryRegion {
    /// Start of the guest physical span.
    pub guest_address: u64,
    /// Length of the span in bytes.
    pub length: u64,
    /// Byte offset in the immutable cache file.
    pub file_offset: u64,
}

/// An opened realization pinned against cooperative eviction until the handle is dropped.
pub struct CachedMemory {
    path: PathBuf,
    identity: ObjectId,
    /// Read-only backing ownership. Transfer this handle to the VMM, not merely its pathname.
    pub file: File,
    /// Exact guest coverage, with address holes omitted from physical storage.
    pub regions: Vec<CachedMemoryRegion>,
    /// Whether existing verified bytes were reused without rereading portable objects.
    pub cache_hit: bool,
    /// Whether this construction cloned its baseline using a filesystem reflink.
    pub reflink: bool,
    /// Time spent resolving or constructing this backing, in microseconds.
    pub prepare_us: u128,
}

/// Host-local, immutable memory cache. No entry is ever modified in place.
pub struct MemoryCache {
    pub(super) root: PathBuf,
    pub(super) page_size: u64,
    progress: Option<crate::startup_progress::StartupProgressCallback>,
}

type ObjectSlices = BTreeMap<ObjectId, Vec<(u64, u64, u64)>>;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl MemoryCache {
    /// Open a dedicated cache directory using this host's native mapping alignment.
    pub fn open(root: impl Into<PathBuf>) -> io::Result<Self> {
        Self::open_namespace(root.into(), "snapshots")
    }

    pub(super) fn open_namespace(root: PathBuf, namespace: &str) -> io::Result<Self> {
        #[cfg(unix)]
        {
            let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
            if page_size <= 0 {
                return Err(io::Error::last_os_error());
            }
            std::fs::create_dir_all(&root)?;
            // Cache contents are guest RAM, not public image data. Restrict traversal even
            // when the caller's umask permits other local users to read ordinary cache files.
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
            let root = root.join(namespace);
            std::fs::create_dir_all(&root)?;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
            Ok(Self {
                root,
                page_size: page_size as u64,
                progress: None,
            })
        }
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
            let mut info: SYSTEM_INFO = unsafe { std::mem::zeroed() };
            unsafe {
                GetSystemInfo(&mut info);
            }
            std::fs::create_dir_all(&root)?;
            restrict_cache_directory(&root)?;
            let root = root.join(namespace);
            std::fs::create_dir_all(&root)?;
            restrict_cache_directory(&root)?;
            Ok(Self {
                root,
                page_size: u64::from(info.dwPageSize),
                progress: None,
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (root, namespace);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "private memory cache is not qualified on this backend",
            ))
        }
    }

    /// Attach the nonblocking runtime telemetry producer.
    #[cfg(any(feature = "runner", test))]
    pub(crate) fn with_progress(
        mut self,
        progress: crate::startup_progress::StartupProgressCallback,
    ) -> Self {
        self.progress = Some(progress);
        self
    }

    fn report(&self, phase: crate::startup_progress::StartupPhase) {
        if let Some(progress) = &self.progress {
            progress(crate::startup_progress::StartupProgress::phase(phase));
        }
    }

    /// Resolve a complete memory image, verifying portable objects only on a cache miss.
    ///
    /// `read_object` must return identity-verified bytes. It is called once per distinct packed
    /// object, not once per extent. The complete canonical manifest identity names the cache;
    /// neither an unverified partial delta nor a mutable file may be published under that name.
    pub fn materialize(
        &self,
        manifest: &MemoryManifest,
        identity: &ObjectId,
        read_object: impl FnMut(&ObjectId) -> io::Result<Vec<u8>>,
    ) -> io::Result<CachedMemory> {
        self.materialize_with_baseline(manifest, identity, None, read_object)
    }

    /// Prepare a durable restore backing with bounded parallel verification and reusable buffers.
    /// Readers must enforce the 32 MiB portable memory-object bound and return verified bytes.
    pub fn materialize_parallel(
        &self,
        manifest: &MemoryManifest,
        identity: &ObjectId,
        read_object: impl Fn(&ObjectId, &mut Vec<u8>) -> io::Result<CheckpointObjectReadTiming> + Sync,
    ) -> io::Result<CachedMemory> {
        self.materialize_with_baseline_inner(manifest, identity, None, |objects, staging| {
            let total_bytes = objects.values().flatten().map(|slice| slice.2).sum();
            let mut completed_bytes = 0;
            let timings = consume_verified_objects(objects, read_object, |slices, bytes| {
                let written: u64 = slices.iter().map(|slice| slice.2).sum();
                write_object_slices(staging, slices, bytes)?;
                completed_bytes += written;
                if let Some(progress) = &self.progress {
                    progress(crate::startup_progress::StartupProgress {
                        phase: crate::startup_progress::StartupPhase::PreparingMemoryBacking,
                        completed_bytes,
                        total_bytes: Some(total_bytes),
                    });
                }
                Ok(())
            })?;
            tracing::info!(
                target: "microsandbox_checkpoint_timing",
                operation = "memory_cache_objects",
                object_io_worker_us = timings.read_us,
                object_hash_worker_us = timings.hash_us,
                object_write_us = timings.consume_us,
                object_pipeline_us = timings.elapsed_us,
                object_bytes = timings.object_bytes,
                "parallel memory cache object timing"
            );
            Ok(timings)
        })
    }

    /// Reuse a pinned complete baseline before overlaying immutable changed object slices.
    /// The source VM is never read or remapped here; both inputs are completed captures.
    pub fn materialize_with_baseline(
        &self,
        manifest: &MemoryManifest,
        identity: &ObjectId,
        baseline: Option<(&MemoryManifest, &CachedMemory)>,
        mut read_object: impl FnMut(&ObjectId) -> io::Result<Vec<u8>>,
    ) -> io::Result<CachedMemory> {
        self.materialize_with_baseline_inner(manifest, identity, baseline, |objects, staging| {
            let started = Instant::now();
            let mut timings = ObjectPipelineTiming::default();
            for (id, slices) in objects {
                let reading = Instant::now();
                let bytes = read_object(&id)?;
                timings.read_us += reading.elapsed().as_micros();
                timings.object_bytes += bytes.len() as u64;
                let writing = Instant::now();
                write_object_slices(staging, slices, &bytes)?;
                timings.consume_us += writing.elapsed().as_micros();
            }
            timings.elapsed_us = started.elapsed().as_micros();
            Ok(timings)
        })
    }

    fn materialize_with_baseline_inner(
        &self,
        manifest: &MemoryManifest,
        identity: &ObjectId,
        baseline: Option<(&MemoryManifest, &CachedMemory)>,
        consume_objects: impl FnOnce(ObjectSlices, &mut File) -> io::Result<ObjectPipelineTiming>,
    ) -> io::Result<CachedMemory> {
        let started = Instant::now();
        let canonical = manifest.to_canonical_bytes().map_err(io::Error::other)?;
        if ObjectId::from_bytes(&canonical).map_err(io::Error::other)? != *identity {
            return Err(invalid(
                "memory cache identity does not match its complete manifest",
            ));
        }
        let regions = memory_regions(manifest, self.page_size)?;
        let length = regions
            .last()
            .and_then(|r| r.file_offset.checked_add(r.length))
            .ok_or_else(|| invalid("empty or overflowing memory topology"))?;
        let path = self.entry_path(identity);
        if let Some(file) = open_pinned(&path, length)? {
            self.report(crate::startup_progress::StartupPhase::ReusingMemoryBacking);
            return Ok(CachedMemory {
                path,
                identity: identity.clone(),
                file,
                regions,
                cache_hit: true,
                reflink: false,
                prepare_us: started.elapsed().as_micros(),
            });
        }

        // Stable per-identity lock inodes serialize cache misses across processes, without
        // placing warm hits or unrelated snapshots behind a global cache lock. Never unlink a
        // build lock: waiters must not acquire different inodes for the same identity.
        let build_lock =
            microsandbox_utils::process_lock::open_lock_file(&path.with_extension("build-lock"))?;
        if !microsandbox_utils::process_lock::try_lock_exclusive(&build_lock)? {
            self.report(crate::startup_progress::StartupPhase::WaitingForMemoryBacking);
            microsandbox_utils::process_lock::lock_exclusive(&build_lock)?;
        }
        if let Some(file) = open_pinned(&path, length)? {
            self.report(crate::startup_progress::StartupPhase::ReusingMemoryBacking);
            return Ok(CachedMemory {
                path,
                identity: identity.clone(),
                file,
                regions,
                cache_hit: true,
                reflink: false,
                prepare_us: started.elapsed().as_micros(),
            });
        }

        self.report(crate::startup_progress::StartupPhase::PreparingMemoryBacking);
        let staging_dir = tempfile::Builder::new()
            .prefix(".memory-")
            .tempdir_in(&self.root)?;
        let staging_path = staging_dir.path().join("memory");
        let baseline = baseline.filter(|(_, cached)| cached.regions == regions);
        if let Some((previous, cached)) = baseline {
            let bytes = previous.to_canonical_bytes().map_err(io::Error::other)?;
            if ObjectId::from_bytes(&bytes).map_err(io::Error::other)? != cached.identity {
                return Err(invalid("cache baseline does not match its pinned manifest"));
            }
        }
        let mut reflink = false;
        if let Some((_, cached)) = baseline {
            let (_, strategy) =
                microsandbox_utils::copy::fast_copy_with_strategy(&cached.path, &staging_path)?;
            reflink = strategy == microsandbox_utils::copy::FastCopyStrategy::Reflink;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&staging_path, std::fs::Permissions::from_mode(0o600))?;
            }
        }
        let mut staging = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&staging_path)?;
        // A fresh sparse file supplies all zero extents without allocating or writing RAM-sized
        // buffers. Only immutable nonzero object slices are copied into it.
        staging.set_len(length)?;
        let previous = baseline.map(|(manifest, _)| {
            manifest
                .extents
                .iter()
                .map(|extent| (extent.start, extent))
                .collect::<BTreeMap<_, _>>()
        });
        let mut objects = BTreeMap::<ObjectId, Vec<(u64, u64, u64)>>::new();
        let mut region_index = 0;
        for extent in &manifest.extents {
            while extent.start >= regions[region_index].guest_address + regions[region_index].length
            {
                region_index += 1;
            }
            if previous.as_ref().and_then(|map| map.get(&extent.start)) == Some(&extent) {
                continue;
            }
            let region = &regions[region_index];
            let offset = region.file_offset + (extent.start - region.guest_address);
            if let MemoryExtentContent::Object(content) = &extent.content {
                objects.entry(content.object.clone()).or_default().push((
                    offset,
                    content.object_offset,
                    extent.length,
                ));
            } else if baseline.is_some() {
                // A newly zero range must overwrite the cloned bytes, never resurrect them.
                // Bound the temporary allocation independently of guest RAM size.
                staging.seek(SeekFrom::Start(offset))?;
                let zeros = [0u8; 64 * 1024];
                let mut remaining = extent.length;
                while remaining > 0 {
                    let count = remaining.min(zeros.len() as u64) as usize;
                    staging.write_all(&zeros[..count])?;
                    remaining -= count as u64;
                }
            }
        }
        let objects = consume_objects(objects, &mut staging)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            staging.set_permissions(std::fs::Permissions::from_mode(0o400))?;
        }
        let syncing = Instant::now();
        self.report(crate::startup_progress::StartupPhase::SyncingMemoryBacking);
        staging.sync_all()?;
        let file_sync_us = syncing.elapsed().as_micros();
        // Windows readers deliberately deny write sharing. Close the completed writer before
        // publishing/opening its immutable view; keeping it open would cause a sharing violation.
        drop(staging);
        let mut directory_sync_us = 0;
        let file = publish_pinned_entry(&staging_path, &path, length, || {
            let syncing = Instant::now();
            #[cfg(unix)]
            File::open(&self.root)?.sync_all()?;
            directory_sync_us = syncing.elapsed().as_micros();
            Ok(())
        })?;
        tracing::info!(
            target: "microsandbox_checkpoint_timing",
            operation = "memory_cache_materialize",
            total_us = started.elapsed().as_micros(),
            object_pipeline_us = objects.elapsed_us,
            object_write_us = objects.consume_us,
            object_bytes = objects.object_bytes,
            file_sync_us,
            directory_sync_us,
            "memory cache construction timing"
        );
        Ok(CachedMemory {
            path,
            identity: identity.clone(),
            file,
            regions,
            cache_hit: false,
            reflink,
            prepare_us: started.elapsed().as_micros(),
        })
    }

    /// Remove an unpinned immutable entry. `false` means absent or still owned by a VM.
    ///
    /// Never truncate or hole-punch a live entry. POSIX open-handle lifetime also protects a
    /// reader that opened the inode immediately before an eviction acquired its exclusive lock.
    pub fn evict(&self, identity: &ObjectId) -> io::Result<bool> {
        let path = self.entry_path(identity);
        evict_unpinned(&path)
    }

    fn entry_path(&self, identity: &ObjectId) -> PathBuf {
        // Geometry lives in the identity-bearing manifest. Native alignment is local realization
        // policy, so a cache prepared on a different page-size host must not collide with it.
        self.root.join(format!(
            "{}-{}.ram",
            identity.as_str().replace(':', "-"),
            self.page_size
        ))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Pin the completed inode before exposing its name to cooperative eviction. An older builder
/// may win publication without taking our build lock; pin its winner or retry if it was evicted.
fn publish_pinned_entry(
    staging: &Path,
    path: &Path,
    length: u64,
    after_publication: impl FnOnce() -> io::Result<()>,
) -> io::Result<File> {
    let staged = open_pinned(staging, length)?
        .ok_or_else(|| io::Error::other("completed memory staging disappeared"))?;
    let file = loop {
        match std::fs::hard_link(staging, path) {
            Ok(()) => break staged,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                if let Some(winner) = open_pinned(path, length)? {
                    break winner;
                }
            }
            Err(error) => return Err(error),
        }
    };
    // The pin also spans the directory durability barrier, which can take arbitrarily long.
    after_publication()?;
    Ok(file)
}

fn write_object_slices(
    staging: &mut File,
    slices: Vec<(u64, u64, u64)>,
    bytes: &[u8],
) -> io::Result<()> {
    for (target, offset, count) in slices {
        let start =
            usize::try_from(offset).map_err(|_| invalid("memory object offset overflows"))?;
        let count =
            usize::try_from(count).map_err(|_| invalid("memory object length overflows"))?;
        let end = start
            .checked_add(count)
            .ok_or_else(|| invalid("memory object slice overflows"))?;
        let bytes = bytes
            .get(start..end)
            .ok_or_else(|| invalid("memory object slice exceeds verified bytes"))?;
        staging.seek(SeekFrom::Start(target))?;
        staging.write_all(bytes)?;
    }
    Ok(())
}

fn memory_regions(
    manifest: &MemoryManifest,
    page_size: u64,
) -> io::Result<Vec<CachedMemoryRegion>> {
    let mut regions: Vec<CachedMemoryRegion> = Vec::new();
    let mut file_length = 0u64;
    for extent in &manifest.extents {
        if let Some(last) = regions.last_mut()
            && last.guest_address.checked_add(last.length) == Some(extent.start)
        {
            last.length = last
                .length
                .checked_add(extent.length)
                .ok_or_else(|| invalid("memory topology overflows"))?;
        } else {
            regions.push(CachedMemoryRegion {
                guest_address: extent.start,
                length: extent.length,
                file_offset: file_length,
            });
        }
        file_length = file_length
            .checked_add(extent.length)
            .ok_or_else(|| invalid("memory cache size overflows"))?;
    }
    for region in &regions {
        if !region.guest_address.is_multiple_of(page_size)
            || !region.length.is_multiple_of(page_size)
            || !region.file_offset.is_multiple_of(page_size)
        {
            return Err(invalid(
                "guest memory topology is not aligned for private mappings on this host",
            ));
        }
    }
    Ok(regions)
}

/// Both cache namespaces use the same inode/lock checks and never mutate mapped RAM.
pub(super) fn evict_unpinned(path: &Path) -> io::Result<bool> {
    let file = match open_readonly(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if !microsandbox_utils::process_lock::try_lock_exclusive(&file)? {
        return Ok(false);
    }
    // A competing evictor can have removed this same inode while we waited to acquire it.
    // Do not unlink a new realization published at the old name in the meantime.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = file.metadata()?;
        let current = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        if (opened.dev(), opened.ino()) != (current.dev(), current.ino()) {
            return Ok(false);
        }
    }
    #[cfg(windows)]
    {
        let current = match open_readonly(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        if windows_file_identity(&file)? != windows_file_identity(&current)? {
            return Ok(false);
        }
    }
    std::fs::remove_file(path)?;
    Ok(true)
}

fn open_readonly(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_DELETE, FILE_SHARE_READ};
        options.share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE);
    }
    options.open(path)
}

pub(super) fn open_pinned(path: &Path, length: u64) -> io::Result<Option<File>> {
    let file = match open_readonly(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != length {
        return Err(invalid(
            "memory cache entry has invalid type or length; evict and rebuild it",
        ));
    }
    microsandbox_utils::process_lock::lock_shared(&file)?;
    Ok(Some(file))
}

#[cfg(windows)]
fn windows_file_identity(file: &File) -> io::Result<(u32, u32, u32)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((
        info.dwVolumeSerialNumber,
        info.nFileIndexHigh,
        info.nFileIndexLow,
    ))
}

/// Guest RAM must not inherit broad read permissions from a custom cache parent.
#[cfg(windows)]
fn restrict_cache_directory(path: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, SetFileSecurityW,
    };
    // OWNER RIGHTS follows the actual owner; SYSTEM is retained for OS maintenance. Children
    // inherit these ACEs. This is local-user confidentiality, not an adversarial-host boundary.
    let sddl: Vec<u16> = "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)\0"
        .encode_utf16()
        .collect();
    let mut descriptor = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let success = unsafe {
        SetFileSecurityW(
            path.as_ptr(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        )
    };
    let result = if success == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    };
    unsafe {
        LocalFree(descriptor);
    }
    result
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use microsandbox_image::checkpoint::{ContentRef, MemoryCaptureMode, MemoryExtent};
    #[cfg(unix)]
    use std::os::unix::fs::FileExt;
    #[cfg(windows)]
    trait ReadAt {
        fn read_exact_at(&self, bytes: &mut [u8], offset: u64) -> io::Result<()>;
    }
    #[cfg(windows)]
    impl ReadAt for File {
        fn read_exact_at(&self, bytes: &mut [u8], offset: u64) -> io::Result<()> {
            use std::io::Read;
            let mut file = self.try_clone()?;
            file.seek(SeekFrom::Start(offset))?;
            file.read_exact(bytes)
        }
    }

    fn fixture(page: u64) -> (MemoryManifest, ObjectId, Vec<u8>) {
        let bytes = vec![0x5a; page as usize];
        let object = ObjectId::from_bytes(&bytes).unwrap();
        let manifest = MemoryManifest {
            schema: "microsandbox.memory/1".into(),
            architecture: std::env::consts::ARCH.into(),
            guest_page_size: 4096,
            topology_generation: 1,
            generation: 1,
            capture_mode: MemoryCaptureMode::Full,
            pause_generation: 1,
            extents: vec![
                MemoryExtent {
                    start: 0,
                    length: page,
                    content: MemoryExtentContent::Object(ContentRef {
                        object: object.clone(),
                        object_offset: 0,
                    }),
                },
                MemoryExtent {
                    start: page,
                    length: page,
                    content: MemoryExtentContent::Zero,
                },
                MemoryExtent {
                    start: page * 4,
                    length: page,
                    content: MemoryExtentContent::Object(ContentRef {
                        object,
                        object_offset: 0,
                    }),
                },
            ],
        };
        let id = ObjectId::from_bytes(&manifest.to_canonical_bytes().unwrap()).unwrap();
        (manifest, id, bytes)
    }

    #[test]
    fn publication_already_owns_a_pin_before_the_directory_barrier() {
        let directory = tempfile::tempdir().unwrap();
        let staging = directory.path().join("staged");
        let published = directory.path().join("published");
        std::fs::write(&staging, b"complete memory").unwrap();
        let file = publish_pinned_entry(&staging, &published, 15, || {
            // This is the old publication-to-pin window. Run eviction on another thread so the
            // test exercises independent lock ownership even on process-oriented platforms.
            assert!(!std::thread::scope(|scope| {
                scope
                    .spawn(|| evict_unpinned(&published).unwrap())
                    .join()
                    .unwrap()
            }));
            Ok(())
        })
        .unwrap();
        assert!(!evict_unpinned(&published).unwrap());
        drop(file);
        assert!(evict_unpinned(&published).unwrap());
    }

    #[test]
    fn publication_pins_an_existing_winner_without_replacing_its_inode() {
        let directory = tempfile::tempdir().unwrap();
        let staging = directory.path().join("staged");
        let published = directory.path().join("published");
        std::fs::write(&staging, b"candidate").unwrap();
        std::fs::write(&published, b"thewinner").unwrap();
        let file = publish_pinned_entry(&staging, &published, 9, || {
            assert!(!evict_unpinned(&published).unwrap());
            Ok(())
        })
        .unwrap();
        assert_eq!(std::fs::read(&published).unwrap(), b"thewinner");
        drop(file);
        assert!(evict_unpinned(&published).unwrap());
    }

    #[test]
    fn materialize_once_reuse_pinned_bytes_and_evict_after_last_owner() {
        let directory = tempfile::tempdir().unwrap();
        let cache = MemoryCache::open(directory.path()).unwrap();
        let (manifest, id, bytes) = fixture(cache.page_size);
        let mut reads = 0;
        let first = cache
            .materialize(&manifest, &id, |_| {
                reads += 1;
                Ok(bytes.clone())
            })
            .unwrap();
        assert_eq!(reads, 1);
        assert!(!first.cache_hit);
        assert_eq!(first.regions.len(), 2);
        assert_eq!(first.file.metadata().unwrap().len(), cache.page_size * 3);
        let mut zero = vec![1; cache.page_size as usize];
        first
            .file
            .read_exact_at(&mut zero, cache.page_size)
            .unwrap();
        assert!(zero.iter().all(|byte| *byte == 0));
        let second = cache
            .materialize(&manifest, &id, |_| {
                panic!("warm cache reread a portable object")
            })
            .unwrap();
        assert!(second.cache_hit);
        assert!(!cache.evict(&id).unwrap());
        drop(first);
        assert!(!cache.evict(&id).unwrap());
        drop(second);
        assert!(cache.evict(&id).unwrap());
        assert!(!cache.evict(&id).unwrap());
    }

    #[test]
    fn parallel_materialization_preserves_holes_zeroes_and_warm_pins() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let directory = tempfile::tempdir().unwrap();
        let cache = MemoryCache::open(directory.path()).unwrap();
        let (manifest, id, bytes) = fixture(cache.page_size);
        let reads = AtomicUsize::new(0);
        let first = cache
            .materialize_parallel(&manifest, &id, |_, buffer| {
                reads.fetch_add(1, Ordering::Relaxed);
                buffer.resize(bytes.len(), 0);
                buffer.copy_from_slice(&bytes);
                Ok(CheckpointObjectReadTiming::default())
            })
            .unwrap();
        assert_eq!(reads.load(Ordering::Relaxed), 1);
        let mut actual = vec![0xff; cache.page_size as usize * 3];
        first.file.read_exact_at(&mut actual, 0).unwrap();
        assert_eq!(&actual[..bytes.len()], bytes);
        assert!(
            actual[bytes.len()..bytes.len() * 2]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert_eq!(&actual[bytes.len() * 2..], bytes);
        let second = cache
            .materialize_parallel(&manifest, &id, |_, _| panic!("warm restore reread objects"))
            .unwrap();
        assert!(second.cache_hit);
        assert!(!cache.evict(&id).unwrap());
        drop(first);
        assert!(!cache.evict(&id).unwrap());
        drop(second);
        assert!(cache.evict(&id).unwrap());
    }

    #[test]
    fn preparation_progress_counts_written_slices_and_reports_warm_reuse() {
        use crate::startup_progress::StartupPhase;
        let directory = tempfile::tempdir().unwrap();
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let observed = events.clone();
        let cache =
            MemoryCache::open(directory.path())
                .unwrap()
                .with_progress(std::sync::Arc::new(move |event| {
                    observed.lock().unwrap().push(event);
                }));
        let (manifest, id, bytes) = fixture(cache.page_size);
        let first = cache
            .materialize_parallel(&manifest, &id, |_, buffer| {
                buffer.extend_from_slice(&bytes);
                Ok(CheckpointObjectReadTiming::default())
            })
            .unwrap();
        let recorded = events.lock().unwrap().clone();
        let bytes_event = recorded
            .iter()
            .find(|event| event.total_bytes.is_some())
            .unwrap();
        // This fixture writes the same verified object into two guest slices. Count each
        // destination once, excluding the intervening zero page, not each object read.
        assert_eq!(bytes_event.completed_bytes, 2 * bytes.len() as u64);
        assert_eq!(bytes_event.total_bytes, Some(2 * bytes.len() as u64));
        assert_eq!(
            recorded.last().unwrap().phase,
            StartupPhase::SyncingMemoryBacking
        );
        let _second = cache
            .materialize_parallel(&manifest, &id, |_, _| panic!("warm read"))
            .unwrap();
        assert_eq!(
            events.lock().unwrap().last().unwrap().phase,
            StartupPhase::ReusingMemoryBacking
        );
        drop(first);
    }

    #[test]
    fn failed_parallel_read_or_slice_never_publishes_a_cache_entry() {
        let directory = tempfile::tempdir().unwrap();
        let cache = MemoryCache::open(directory.path()).unwrap();
        let (manifest, id, _) = fixture(cache.page_size);
        assert!(
            cache
                .materialize_parallel(&manifest, &id, |_, _| {
                    Err(io::Error::other("injected verification failure"))
                })
                .is_err()
        );
        assert_eq!(payload_count(directory.path()), 0);
        assert!(
            cache
                .materialize_parallel(&manifest, &id, |_, buffer| {
                    buffer.resize(1, 0);
                    Ok(CheckpointObjectReadTiming::default())
                })
                .is_err()
        );
        assert_eq!(payload_count(directory.path()), 0);
    }

    #[test]
    fn descendant_reuses_unchanged_objects_and_clears_new_zero_ranges() {
        let directory = tempfile::tempdir().unwrap();
        let cache = MemoryCache::open(directory.path()).unwrap();
        let (manifest, id, bytes) = fixture(cache.page_size);
        let baseline = cache
            .materialize(&manifest, &id, |_| Ok(bytes.clone()))
            .unwrap();
        let mut descendant = manifest.clone();
        descendant.generation += 1;
        descendant.extents[0].content = MemoryExtentContent::Zero;
        let changed = vec![0x7c; cache.page_size as usize];
        let changed_id = ObjectId::from_bytes(&changed).unwrap();
        descendant.extents[1].content = MemoryExtentContent::Object(ContentRef {
            object: changed_id.clone(),
            object_offset: 0,
        });
        let descendant_id =
            ObjectId::from_bytes(&descendant.to_canonical_bytes().unwrap()).unwrap();
        let mut reads = 0;
        let child = cache
            .materialize_with_baseline(
                &descendant,
                &descendant_id,
                Some((&manifest, &baseline)),
                |id| {
                    assert_eq!(id, &changed_id, "unchanged object was reread");
                    reads += 1;
                    Ok(changed.clone())
                },
            )
            .unwrap();
        assert_eq!(reads, 1);
        let mut result = vec![0; cache.page_size as usize * 3];
        child.file.read_exact_at(&mut result, 0).unwrap();
        assert!(
            result[..cache.page_size as usize]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert_eq!(
            &result[cache.page_size as usize..cache.page_size as usize * 2],
            &changed
        );
        assert_eq!(&result[cache.page_size as usize * 2..], &bytes);
        baseline
            .file
            .read_exact_at(&mut result[..cache.page_size as usize], 0)
            .unwrap();
        assert_eq!(
            &result[..cache.page_size as usize],
            &bytes,
            "baseline was mutated"
        );
        assert!(!cache.evict(&id).unwrap());
    }

    #[test]
    fn reject_a_manifest_paired_with_the_wrong_baseline() {
        let directory = tempfile::tempdir().unwrap();
        let cache = MemoryCache::open(directory.path()).unwrap();
        let (manifest, id, bytes) = fixture(cache.page_size);
        let baseline = cache
            .materialize(&manifest, &id, |_| Ok(bytes.clone()))
            .unwrap();
        let mut wrong = manifest.clone();
        wrong.generation += 1;
        let target = ObjectId::from_bytes(&wrong.to_canonical_bytes().unwrap()).unwrap();
        assert!(
            cache
                .materialize_with_baseline(&wrong, &target, Some((&wrong, &baseline)), |_| panic!(
                    "must reject before reads"
                ))
                .is_err()
        );
        assert_eq!(payload_count(directory.path()), 1);
    }

    #[test]
    fn failed_materialization_does_not_publish_or_leave_staging() {
        let directory = tempfile::tempdir().unwrap();
        let cache = MemoryCache::open(directory.path()).unwrap();
        let (manifest, id, _) = fixture(cache.page_size);
        let failure = cache.materialize(&manifest, &id, |_| {
            Err(io::Error::other("injected object read failure"))
        });
        assert!(failure.is_err());
        assert_eq!(payload_count(directory.path()), 0);
        assert!(cache.materialize(&manifest, &id, |_| Ok(vec![])).is_err());
        assert_eq!(payload_count(directory.path()), 0);
    }

    #[test]
    fn reject_wrong_manifest_identity_and_host_alignment() {
        let directory = tempfile::tempdir().unwrap();
        let cache = MemoryCache::open(directory.path()).unwrap();
        let (mut manifest, id, _) = fixture(cache.page_size);
        manifest.generation += 1;
        assert!(
            cache
                .materialize(&manifest, &id, |_| panic!(
                    "identity rejection must precede reads"
                ))
                .is_err()
        );
        let (mut manifest, _, _) = fixture(4096);
        manifest.extents.truncate(1);
        assert!(memory_regions(&manifest, 16384).is_err());
    }

    fn payload_count(root: &Path) -> usize {
        // Build-lock inodes intentionally survive failed builders. Only RAM or staging entries
        // count as payloads; removing lock files would permit two independent flock owners.
        std::fs::read_dir(root.join("snapshots"))
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .path()
                    .extension()
                    .and_then(|ext| ext.to_str())
                    != Some("build-lock")
            })
            .count()
    }

    #[test]
    fn concurrent_builders_publish_one_immutable_inode() {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        let directory = tempfile::tempdir().unwrap();
        let cache = MemoryCache::open(directory.path()).unwrap();
        let (manifest, id, bytes) = fixture(cache.page_size);
        let barrier = std::sync::Barrier::new(2);
        let reads = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|scope| {
            let run = || {
                barrier.wait();
                cache
                    .materialize(&manifest, &id, |_| {
                        reads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        Ok(bytes.clone())
                    })
                    .unwrap()
            };
            let first = scope.spawn(run);
            let second = scope.spawn(run);
            let first = first.join().unwrap();
            let second = second.join().unwrap();
            #[cfg(unix)]
            assert_eq!(
                first.file.metadata().unwrap().ino(),
                second.file.metadata().unwrap().ino()
            );
            #[cfg(windows)]
            assert_eq!(
                windows_file_identity(&first.file).unwrap(),
                windows_file_identity(&second.file).unwrap()
            );
        });
        assert_eq!(reads.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(
            std::fs::read_dir(directory.path().join("snapshots"))
                .unwrap()
                .count(),
            2
        );
    }

    #[test]
    fn unlinked_backing_survives_without_snapshot_paths() {
        let directory = tempfile::tempdir().unwrap();
        let cache = MemoryCache::open(directory.path()).unwrap();
        let (manifest, id, bytes) = fixture(cache.page_size);
        let memory = cache
            .materialize(&manifest, &id, |_| Ok(bytes.clone()))
            .unwrap();
        std::fs::remove_file(cache.entry_path(&id)).unwrap();
        let mut actual = vec![0; bytes.len()];
        memory
            .file
            .read_exact_at(&mut actual, cache.page_size * 2)
            .unwrap();
        assert_eq!(actual, bytes);
    }
}

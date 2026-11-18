//! Cooperative, process-held leases for installed storage entries.
//!
//! Locks name directory entries, not content digests: two installed copies have independent
//! lifetimes. The stable lock inode lives beside the entry, outside any removable payload.
//!
//! # Choosing a lease
//!
//! - [`StorageLease::shared`] and [`StorageLease::shared_async`] pin an entry while a caller
//!   reads it or publishes its files and catalog references. Multiple readers may coexist.
//! - [`StorageLease::try_exclusive`] claims an entry for deletion only when no reader holds
//!   it. Prune skips busy entries rather than waiting for downloads or sandbox creation.
//! - [`StorageLease::exclusive`] and [`StorageLease::exclusive_async`] wait for exclusive
//!   access to a short publication critical section. Use a separate publication key when
//!   the operation already holds a lifetime pin; upgrading that pin would deadlock.
//! - [`StorageLease::descriptor`] locks an existing immutable descriptor directly and checks
//!   its identity after admission. It does not create a sidecar or use the shared pool.
//!
//! # Identity and ownership
//!
//! [`StorageLease::key`] resolves the parent directory but leaves the entry name unresolved.
//! Parent aliases therefore coordinate on the same key without following a payload symlink.
//! Ordinary leases lock `.msb-leases/<hash-of-entry-name>.lock` in that parent. These lock files
//! remain in place: removing one could let two processes lock different inodes for one key.
//!
//! The OS lock coordinates participating processes. Within one process, `SharedLeasePool`
//! maps each key to a weak `SharedLeaseEntry`. Readers reuse one `Arc<LeaseFile>` per key, so many
//! concurrent operations do not each consume another descriptor for the same artifact.
//! Every returned reader lease owns the file and keeps its pool entry alive. Clones extend that
//! ownership; the last file owner closes the descriptor and releases the OS lock.
//!
//! # Reader acquisition
//!
//! `SharedLeaseEntry::admit` chooses one of three outcomes:
//!
//! - `Held`: reuse the existing descriptor.
//! - `Acquire`: reserve the vacant slot with a `SharedLeaseAcquisition` token.
//! - `Wait`: another acquisition or an exclusive writer must finish first.
//!
//! The slot progresses from `Vacant` to `Acquiring` to `Held`. `Held` contains a weak file
//! reference; after the last reader drops, the next admission treats it as vacant. Dropping
//! an unpublished acquisition token resets the slot and wakes both kinds of waiter.
//!
//! Synchronous callers wait on a condition variable and acquire OS locks in blocking work.
//! A sync acquirer owns the slot while blocking in the OS lock; async readers of that key
//! await its publication. Call the sync API only from threads allowed to block.
//! Async callers wait on a watch channel and perform nonblocking OS lock attempts in
//! `spawn_blocking`. One per-entry async gate serializes reader retries; warm reuse bypasses
//! the gate. Reservation, OS lock attempt, and publication all happen inside the worker.
//! A failed attempt releases its token before the async caller sleeps. Neither a queued
//! worker nor an async task waiting to resume holds an acquisition reservation.
//! Cancellation leaves an in-flight attempt owned by its worker until it finishes.
//! Local descriptor release wakes retrying readers and writers immediately. Timers remain
//! as a fallback for lock holders in other processes, which cannot send local notifications.
//!
//! # Exclusive writers
//!
//! `SharedLeaseWriter` registers writer interest before a blocking acquisition and retains it for the
//! exclusive lease's lifetime. New readers of that key wait while existing readers finish;
//! otherwise they could continually extend the pooled file's lifetime. Async writers also
//! share a per-key gate to serialize their retry loops. Writer interest is local to this
//! process: readers in other processes are governed by the OS lock, without a global
//! fairness guarantee. Nonblocking deletion claims register interest only after success.
//! Do not reacquire a shared key while holding it if that key admits waiting writers:
//! reuse the existing lease instead. Metadata reads retain their already-held entry lease
//! when admitting dependencies, rather than acquiring that entry again.
//!
//! # Cache lock ordering
//!
//! For [`crate::GlobalCache`] artifacts, deletion must use [`StorageLease::try_exclusive`],
//! never a waiting exclusive lease. Waiting exclusive leases are only for separate publication
//! keys. Metadata readers hold a shared publication gate while admitting dependencies; publishers
//! pin those dependencies before waiting for the exclusive publication gate. A waiting exclusive
//! lease on a dependency would block new readers and complete a deadlock cycle between them.
//!
//! # Registry cleanup and lock scope
//!
//! Pool entries and their file references are weak, so the registry itself never pins an
//! artifact or an open descriptor. Occasional sweeps remove unused entries. An atomic entry
//! count avoids scanning the map on every acquisition; `SharedLeaseSweep` restores the next
//! sweep threshold on completion or cancellation so an interrupted sweep can retry.
//!
//! Entry lookup and each entry's state mutex cover short bookkeeping operations. Occasional
//! inline registry sweeps scan all entries using individual bucket locks. These amortized
//! O(N) sweeps are separate from OS locking and never hold a bucket during filesystem I/O.
//! State mutexes are released before filesystem I/O, OS lock waits, and async sleeps. Different artifact
//! keys remain independent. This protocol protects only callers that participate in it;
//! it does not prevent arbitrary writes or deletion by legacy processes.

use std::fmt;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use microsandbox_utils::process_lock;
use sha2::{Digest, Sha256};

use crate::async_gate::jittered_delay;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const LEASE_RETRY_INITIAL_DELAY: Duration = Duration::from_millis(2);
const LEASE_RETRY_MAX_DELAY: Duration = Duration::from_millis(100);
const INITIAL_POOL_SWEEP_SIZE: usize = 1_024;

static SHARED_LEASE_POOL: OnceLock<SharedLeasePool> = OnceLock::new();

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A shared reader/publisher lease or an exclusive deletion lease.
///
/// Clones retain the same OS lock until the last clone is dropped. Legacy processes which do
/// not participate in this protocol are not protected by it.
#[derive(Clone)]
pub struct StorageLease {
    /// Owns the OS lock; declared first so it closes before writer interest is released.
    _file: Arc<LeaseFile>,
    /// Keeps the reader's registry entry available for other operations to reuse.
    _shared_entry: Option<Arc<SharedLeaseEntry>>,
    /// Keeps new local readers waiting until the last exclusive lease clone drops.
    _writer: Option<Arc<SharedLeaseWriter>>,
}

/// Shared ownership of an OS descriptor, with notification after its final owner closes it.
struct LeaseFile {
    /// Taken on drop so notifications cannot precede OS lock release.
    file: Option<File>,
    /// Reader descriptors wake exclusive waiters when the last reader finishes.
    released: Option<tokio::sync::watch::Sender<u64>>,
}

/// Process-wide lookup of per-key reader state, without owning live leases.
struct SharedLeasePool {
    /// Weak entries allow idle keys to be reclaimed without retaining descriptors.
    entries: scc::HashMap<PathBuf, Weak<SharedLeaseEntry>>,
    /// Updated on insertion and removal instead of calling the map's O(N) `len`.
    entry_count: AtomicUsize,
    /// Entry count that triggers cleanup; `usize::MAX` reserves an in-progress sweep.
    next_sweep_size: AtomicUsize,
}

/// Reader acquisition and writer admission state for one canonical entry key.
struct SharedLeaseEntry {
    /// Protects admission decisions only, never filesystem work or async waits.
    state: Mutex<SharedLeaseEntryState>,
    /// Wakes synchronous callers after acquisition or writer admission changes.
    changed: Condvar,
    /// Wakes async callers without occupying an executor or blocking-pool thread.
    generation: tokio::sync::watch::Sender<u64>,
    /// Wakes OS lock pollers only after a local descriptor has been released.
    released: tokio::sync::watch::Sender<u64>,
    /// Serializes async reader retries without delaying warm descriptor reuse.
    reader_gate: tokio::sync::Mutex<()>,
    /// Serializes async writer retries using the same per-key entry.
    writer_gate: tokio::sync::Mutex<()>,
}

/// State examined together so reader reuse cannot bypass a registered writer.
struct SharedLeaseEntryState {
    /// Current pooled reader descriptor or the reservation to acquire one.
    lease: SharedLeaseState,
    /// Registered exclusive operations, including those already holding their lock.
    writers_waiting: usize,
}

/// Lifecycle of the shared descriptor for a single entry.
enum SharedLeaseState {
    /// No caller has reserved or published a shared descriptor.
    Vacant,
    /// One acquisition token owns the right to publish the next descriptor.
    Acquiring,
    /// Readers own this file; an expired weak reference is treated as vacant.
    Held(Weak<LeaseFile>),
}

/// Decision returned by reader admission before performing any filesystem work.
enum SharedLeaseAdmission {
    /// Reuse a descriptor already locked by another local reader.
    Held(Arc<LeaseFile>),
    /// Acquire the OS lock and publish it through this reservation.
    Acquire(SharedLeaseAcquisition),
    /// Wait for the current acquirer or registered writers to finish.
    Wait,
}

/// Result of one worker-owned nonblocking reader attempt.
enum SharedLeaseAttempt {
    /// The worker reused or published a protected descriptor.
    Held(StorageLease),
    /// A local acquisition or writer must signal an admission change.
    Wait,
    /// The OS lock was busy; the async retry leader should back off.
    Retry,
}

/// Exclusive right to populate a shared slot; drop rolls back an unpublished attempt.
struct SharedLeaseAcquisition {
    entry: Arc<SharedLeaseEntry>,
    /// Cleared after publication so dropping the token does not reset held state.
    active: bool,
}

/// Writer interest that pauses new readers and wakes them when the interest ends.
///
/// An `Arc` retains this registration across exclusive lease clones.
struct SharedLeaseWriter {
    entry: Arc<SharedLeaseEntry>,
}

/// Restores sweep scheduling even if an async cleanup future is cancelled.
struct SharedLeaseSweep<'a> {
    pool: &'a SharedLeasePool,
    /// Only a complete sweep earns the larger interval before the next cleanup.
    completed: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SharedLeasePool {
    /// Process-wide registry; entries coordinate independently by artifact key.
    fn global() -> &'static Self {
        SHARED_LEASE_POOL.get_or_init(Self::new)
    }

    fn new() -> Self {
        Self {
            entries: scc::HashMap::new(),
            entry_count: AtomicUsize::new(0),
            next_sweep_size: AtomicUsize::new(INITIAL_POOL_SWEEP_SIZE),
        }
    }

    fn entry(&self, key: &Path) -> Arc<SharedLeaseEntry> {
        let mut slot = match self.entries.entry_sync(key.to_path_buf()) {
            scc::hash_map::Entry::Occupied(slot) => slot,
            scc::hash_map::Entry::Vacant(slot) => {
                self.entry_count.fetch_add(1, Ordering::Relaxed);
                slot.insert_entry(Weak::new())
            }
        };
        let entry = if let Some(entry) = slot.get().upgrade() {
            entry
        } else {
            let entry = Arc::new(SharedLeaseEntry::new());
            *slot.get_mut() = Arc::downgrade(&entry);
            entry
        };
        drop(slot);
        self.sweep_if_needed();
        entry
    }

    async fn entry_async(&self, key: &Path) -> Arc<SharedLeaseEntry> {
        let mut slot = match self.entries.entry_async(key.to_path_buf()).await {
            scc::hash_map::Entry::Occupied(slot) => slot,
            scc::hash_map::Entry::Vacant(slot) => {
                self.entry_count.fetch_add(1, Ordering::Relaxed);
                slot.insert_entry(Weak::new())
            }
        };
        let entry = if let Some(entry) = slot.get().upgrade() {
            entry
        } else {
            let entry = Arc::new(SharedLeaseEntry::new());
            *slot.get_mut() = Arc::downgrade(&entry);
            entry
        };
        drop(slot);
        self.sweep_if_needed_async().await;
        entry
    }

    /// Reserve the next cleanup once its threshold is reached.
    fn begin_sweep(&self) -> Option<SharedLeaseSweep<'_>> {
        let next_sweep_size = self.next_sweep_size.load(Ordering::Relaxed);
        if self.entry_count.load(Ordering::Relaxed) < next_sweep_size
            || self
                .next_sweep_size
                .compare_exchange(
                    next_sweep_size,
                    usize::MAX,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_err()
        {
            return None;
        }
        Some(SharedLeaseSweep {
            pool: self,
            completed: false,
        })
    }

    /// Back off after success, or allow the next acquisition to retry interrupted cleanup.
    fn finish_sweep(&self, completed: bool) {
        let entry_count = self.entry_count.load(Ordering::Relaxed);
        let next_sweep_size = if completed {
            entry_count.saturating_mul(2).max(INITIAL_POOL_SWEEP_SIZE)
        } else {
            entry_count.max(1)
        };
        self.next_sweep_size
            .store(next_sweep_size, Ordering::Relaxed);
    }

    fn sweep_if_needed(&self) {
        let Some(mut sweep) = self.begin_sweep() else {
            return;
        };
        self.entries.retain_sync(|_, entry| {
            let retained = entry.strong_count() > 0;
            if !retained {
                self.entry_count.fetch_sub(1, Ordering::Relaxed);
            }
            retained
        });
        sweep.completed = true;
    }

    async fn sweep_if_needed_async(&self) {
        let Some(mut sweep) = self.begin_sweep() else {
            return;
        };
        self.entries
            .retain_async(|_, entry| {
                let retained = entry.strong_count() > 0;
                if !retained {
                    self.entry_count.fetch_sub(1, Ordering::Relaxed);
                }
                retained
            })
            .await;
        sweep.completed = true;
    }
}

impl SharedLeaseEntry {
    fn new() -> Self {
        let (generation, _) = tokio::sync::watch::channel(0);
        let (released, _) = tokio::sync::watch::channel(0);
        Self {
            state: Mutex::new(SharedLeaseEntryState {
                lease: SharedLeaseState::Vacant,
                writers_waiting: 0,
            }),
            changed: Condvar::new(),
            generation,
            released,
            reader_gate: tokio::sync::Mutex::new(()),
            writer_gate: tokio::sync::Mutex::new(()),
        }
    }

    /// Reuse a warm descriptor without entering the async retry queue.
    fn reuse(&self) -> Option<Arc<LeaseFile>> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.writers_waiting > 0 {
            return None;
        }

        match &state.lease {
            SharedLeaseState::Held(file) => file.upgrade(),
            SharedLeaseState::Vacant | SharedLeaseState::Acquiring => None,
        }
    }

    /// Reuse or reserve the shared descriptor unless an exclusive writer has priority.
    fn admit(self: &Arc<Self>) -> SharedLeaseAdmission {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.writers_waiting > 0 {
            return SharedLeaseAdmission::Wait;
        }
        if let SharedLeaseState::Held(file) = &state.lease
            && let Some(file) = file.upgrade()
        {
            return SharedLeaseAdmission::Held(file);
        }
        if matches!(&state.lease, SharedLeaseState::Acquiring) {
            return SharedLeaseAdmission::Wait;
        }

        state.lease = SharedLeaseState::Acquiring;
        SharedLeaseAdmission::Acquire(SharedLeaseAcquisition {
            entry: Arc::clone(self),
            active: true,
        })
    }

    /// Signal both waiter families; each rechecks admission rather than trusting the signal.
    fn notify_waiters(&self) {
        self.changed.notify_all();
        self.generation.send_modify(|generation| *generation += 1);
    }

    /// Return an unsuccessful or cancelled attempt's slot to the next reader.
    fn abandon_acquisition(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if matches!(&state.lease, SharedLeaseState::Acquiring) {
            state.lease = SharedLeaseState::Vacant;
        }
        drop(state);
        self.notify_waiters();
    }
}

impl SharedLeaseAcquisition {
    /// Publish an already locked file and transfer its ownership to the returned lease.
    fn publish(mut self, file: File) -> StorageLease {
        let file = Arc::new(LeaseFile {
            file: Some(file),
            released: Some(self.entry.released.clone()),
        });
        {
            let mut state = self
                .entry
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.lease = SharedLeaseState::Held(Arc::downgrade(&file));
        }
        self.active = false;
        self.entry.notify_waiters();
        StorageLease {
            _file: file,
            _shared_entry: Some(Arc::clone(&self.entry)),
            _writer: None,
        }
    }
}

impl SharedLeaseWriter {
    /// Register interest before waiting for an OS lock, preventing new reader reuse.
    fn new(entry: Arc<SharedLeaseEntry>) -> Self {
        {
            let mut state = entry
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.writers_waiting += 1;
        }
        entry.notify_waiters();
        Self { entry }
    }
}

impl StorageLease {
    /// Pin an existing immutable descriptor without writing beside it. Its identity is
    /// checked after locking, so a waiter cannot accidentally admit a retired generation.
    pub fn descriptor(path: &Path, exclusive: bool) -> io::Result<Option<Self>> {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let file = options.open(path)?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::other(
                "snapshot descriptor is not a regular file",
            ));
        }
        if !process_lock::lock_descriptor(&file, exclusive, exclusive)? {
            return Ok(None);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let admitted = file.metadata()?;
            let current = std::fs::symlink_metadata(path)?;
            if !current.file_type().is_file()
                || (admitted.dev(), admitted.ino()) != (current.dev(), current.ino())
            {
                return Err(io::Error::other("snapshot changed during admission"));
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Storage::FileSystem::{
                BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
            };
            fn identity(file: &File) -> io::Result<(u32, u32, u32)> {
                let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
                if unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) }
                    == 0
                {
                    return Err(io::Error::last_os_error());
                }
                let info = unsafe { info.assume_init() };
                Ok((
                    info.dwVolumeSerialNumber,
                    info.nFileIndexHigh,
                    info.nFileIndexLow,
                ))
            }
            if !std::fs::symlink_metadata(path)?.file_type().is_file()
                || identity(&file)? != identity(&File::open(path)?)?
            {
                return Err(io::Error::other("snapshot changed during admission"));
            }
        }
        Ok(Some(Self {
            _file: Arc::new(LeaseFile {
                file: Some(file),
                released: None,
            }),
            _shared_entry: None,
            _writer: None,
        }))
    }

    /// Canonical coordination key, without resolving the removable entry itself.
    pub fn key(path: &Path) -> io::Result<PathBuf> {
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::other("storage entry has no filename"))?;
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("storage entry has no parent"))?;
        Ok(parent.canonicalize()?.join(name))
    }

    /// Serialize a short publication critical section. Never upgrade a shared lease on
    /// the same key: publication gates and lifetime pins use distinct keys.
    pub fn exclusive(path: &Path) -> io::Result<Self> {
        let key = Self::key(path)?;
        let writer = Arc::new(SharedLeaseWriter::new(
            SharedLeasePool::global().entry(&key),
        ));
        let file = Self::open_lock_file(&key)?;
        process_lock::lock_exclusive(&file)?;
        Ok(Self {
            _file: Arc::new(LeaseFile {
                file: Some(file),
                released: None,
            }),
            _shared_entry: None,
            _writer: Some(writer),
        })
    }

    /// Protect an entry before reading it or publishing files and their catalog references.
    /// Call from blocking work; a deletion already in progress may briefly delay this call.
    pub fn shared(path: &Path) -> io::Result<Self> {
        let key = Self::key(path)?;
        Self::shared_keyed(&key)
    }

    /// Protect an entry whose coordination key was already canonicalized.
    pub(crate) fn shared_keyed(key: &Path) -> io::Result<Self> {
        let entry = SharedLeasePool::global().entry(key);
        loop {
            match entry.admit() {
                SharedLeaseAdmission::Held(file) => {
                    return Ok(Self::from_shared(file, Arc::clone(&entry)));
                }
                SharedLeaseAdmission::Acquire(acquisition) => {
                    let file = match Self::open_lock_file(key).and_then(|file| {
                        process_lock::lock_shared(&file)?;
                        Ok(file)
                    }) {
                        Ok(file) => file,
                        Err(error) => {
                            drop(acquisition);
                            return Err(error);
                        }
                    };
                    return Ok(acquisition.publish(file));
                }
                SharedLeaseAdmission::Wait => {
                    let mut state = entry
                        .state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    while state.writers_waiting > 0
                        || matches!(&state.lease, SharedLeaseState::Acquiring)
                    {
                        state = entry
                            .changed
                            .wait(state)
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                    }
                }
            }
        }
    }

    /// Acquire reader protection without blocking the async executor.
    pub async fn shared_async(path: PathBuf) -> io::Result<Self> {
        let key = tokio::task::spawn_blocking(move || Self::key(&path))
            .await
            .map_err(io::Error::other)??;
        Self::shared_async_keyed(key).await
    }

    /// Asynchronously protect an entry whose coordination key was already canonicalized.
    pub(crate) async fn shared_async_keyed(key: PathBuf) -> io::Result<Self> {
        let entry = SharedLeasePool::global().entry_async(&key).await;
        if let Some(file) = entry.reuse() {
            return Ok(Self::from_shared(file, entry));
        }

        let _reader = entry.reader_gate.lock().await;
        let mut generation = entry.generation.subscribe();
        let mut released = entry.released.subscribe();
        let mut delay = LEASE_RETRY_INITIAL_DELAY;
        let started = Instant::now();
        let mut warned = false;
        let mut attempt_count = 0;

        loop {
            released.borrow_and_update();
            if let Some(file) = entry.reuse() {
                return Ok(Self::from_shared(file, Arc::clone(&entry)));
            }

            let attempt_path = key.clone();
            let attempt_entry = Arc::clone(&entry);
            let attempt = tokio::task::spawn_blocking(move || match attempt_entry.admit() {
                SharedLeaseAdmission::Held(file) => Ok(SharedLeaseAttempt::Held(
                    Self::from_shared(file, attempt_entry),
                )),
                SharedLeaseAdmission::Wait => Ok(SharedLeaseAttempt::Wait),
                SharedLeaseAdmission::Acquire(acquisition) => {
                    let file = Self::open_lock_file(&attempt_path)?;
                    if process_lock::try_lock_shared(&file)? {
                        return Ok(SharedLeaseAttempt::Held(acquisition.publish(file)));
                    }

                    drop(file);
                    drop(acquisition);
                    Ok::<_, io::Error>(SharedLeaseAttempt::Retry)
                }
            })
            .await
            .map_err(io::Error::other)??;

            match attempt {
                SharedLeaseAttempt::Held(lease) => return Ok(lease),
                SharedLeaseAttempt::Wait => {
                    generation.changed().await.map_err(io::Error::other)?;
                }
                SharedLeaseAttempt::Retry => {
                    if !warned && started.elapsed() >= Duration::from_secs(5) {
                        tracing::warn!(path = %key.display(), "still waiting for storage lease");
                        warned = true;
                    }
                    tokio::select! {
                        changed = released.changed() => { changed.map_err(io::Error::other)?; }
                        _ = tokio::time::sleep(jittered_delay(&key, delay, attempt_count)) => {}
                    }
                    delay = delay.saturating_mul(2).min(LEASE_RETRY_MAX_DELAY);
                    attempt_count += 1;
                }
            }
        }
    }

    /// Acquire exclusive publication protection without blocking the async executor.
    pub async fn exclusive_async(path: PathBuf) -> io::Result<Self> {
        Self::acquire_exclusive_async(path).await
    }

    async fn acquire_exclusive_async(path: PathBuf) -> io::Result<Self> {
        let key = tokio::task::spawn_blocking(move || Self::key(&path))
            .await
            .map_err(io::Error::other)??;
        let entry = SharedLeasePool::global().entry_async(&key).await;
        let writer = Arc::new(SharedLeaseWriter::new(Arc::clone(&entry)));
        let _waiter = entry.writer_gate.lock().await;
        let mut released = entry.released.subscribe();
        let mut delay = LEASE_RETRY_INITIAL_DELAY;
        let started = Instant::now();
        let mut warned = false;
        let mut attempt_count = 0;

        loop {
            released.borrow_and_update();
            let attempt_path = key.clone();
            let lease =
                tokio::task::spawn_blocking(move || Self::try_exclusive_keyed(&attempt_path))
                    .await
                    .map_err(io::Error::other)??;
            if let Some(mut lease) = lease {
                lease._writer = Some(Arc::clone(&writer));
                return Ok(lease);
            }

            if !warned && started.elapsed() >= Duration::from_secs(5) {
                tracing::warn!(path = %key.display(), "still waiting for storage lease");
                warned = true;
            }
            tokio::select! {
                changed = released.changed() => { changed.map_err(io::Error::other)?; }
                _ = tokio::time::sleep(jittered_delay(&key, delay, attempt_count)) => {}
            }
            delay = delay.saturating_mul(2).min(LEASE_RETRY_MAX_DELAY);
            attempt_count += 1;
        }
    }

    /// Try to exclude readers and publishers. Deleters never wait for other entry leases,
    /// so taking multiple leases cannot deadlock with dependency discovery by readers.
    pub fn try_exclusive(path: &Path) -> io::Result<Option<Self>> {
        let key = Self::key(path)?;
        let lease = Self::try_exclusive_keyed(&key)?;
        Ok(lease.map(|mut lease| {
            lease._writer = Some(Arc::new(SharedLeaseWriter::new(
                SharedLeasePool::global().entry(&key),
            )));
            lease
        }))
    }

    fn try_exclusive_keyed(key: &Path) -> io::Result<Option<Self>> {
        let file = Self::open_lock_file(key)?;
        Ok(process_lock::try_lock_exclusive(&file)?.then(|| Self {
            _file: Arc::new(LeaseFile {
                file: Some(file),
                released: None,
            }),
            _shared_entry: None,
            _writer: None,
        }))
    }

    /// Open the stable sidecar lock for an entry without following its payload symlink.
    fn open_lock_file(path: &Path) -> io::Result<File> {
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::other("storage entry has no filename"))?;
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("storage entry has no parent"))?;
        // Resolve aliases of the parent before choosing a lock. Never follow an entry symlink:
        // callers validate the payload only after acquiring protection for this exact name.
        let parent = parent.canonicalize()?;
        let directory = parent.join(".msb-leases");
        match std::fs::create_dir(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        if !std::fs::symlink_metadata(&directory)?.file_type().is_dir() {
            return Err(io::Error::other(
                "storage lease directory is not a real directory",
            ));
        }
        let key = format!(
            "{}.lock",
            hex::encode(Sha256::digest(name.as_encoded_bytes()))
        );
        let file = process_lock::open_lock_file(&directory.join(key))?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::other("storage lease is not a regular file"));
        }
        Ok(file)
    }

    fn from_shared(file: Arc<LeaseFile>, entry: Arc<SharedLeaseEntry>) -> Self {
        Self {
            _file: file,
            _shared_entry: Some(entry),
            _writer: None,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for LeaseFile {
    fn drop(&mut self) {
        drop(self.file.take());
        if let Some(released) = &self.released {
            released.send_modify(|generation| *generation = generation.wrapping_add(1));
        }
    }
}

impl Drop for SharedLeaseAcquisition {
    fn drop(&mut self) {
        if self.active {
            self.entry.abandon_acquisition();
        }
    }
}

impl Drop for SharedLeaseWriter {
    fn drop(&mut self) {
        let mut state = self
            .entry
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.writers_waiting -= 1;
        drop(state);
        self.entry
            .released
            .send_modify(|generation| *generation = generation.wrapping_add(1));
        self.entry.notify_waiters();
    }
}

impl Drop for SharedLeaseSweep<'_> {
    fn drop(&mut self) {
        self.pool.finish_sweep(self.completed);
    }
}

impl fmt::Debug for StorageLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StorageLease")
            .finish_non_exhaustive()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Compare the exact file identities of two regular entries without following entry symlinks.
/// Used by deletion recovery to distinguish the admitted file from a later replacement.
pub fn same_file(left: &Path, right: &Path) -> io::Result<bool> {
    for path in [left, right] {
        if !std::fs::symlink_metadata(path)?.file_type().is_file() {
            return Err(io::Error::other(
                "storage recovery entry is not a regular file",
            ));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let left = std::fs::metadata(left)?;
        let right = std::fs::metadata(right)?;
        Ok((left.dev(), left.ino()) == (right.dev(), right.ino()))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        fn identity(path: &Path) -> io::Result<(u32, u32, u32)> {
            let file = File::open(path)?;
            let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
            // SAFETY: the file retains a live handle and the API initializes info on success.
            if unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let info = unsafe { info.assume_init() };
            Ok((
                info.dwVolumeSerialNumber,
                info.nFileIndexHigh,
                info.nFileIndexLow,
            ))
        }
        Ok(identity(left)? == identity(right)?)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;

    #[tokio::test]
    async fn last_reader_release_wakes_writer_without_advancing_retry_time() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("resource");
        let reader = StorageLease::shared(&path).unwrap();
        let last_reader = reader.clone();
        let waiter = tokio::spawn(async move { StorageLease::exclusive_async(path).await });
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(!waiter.is_finished());

        drop(reader);
        // Give the writer a retry opportunity while another reader still owns the file.
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(
            !waiter.is_finished(),
            "a remaining reader must still pin the entry"
        );
        tokio::time::pause();
        drop(last_reader);
        let deadline = Instant::now() + Duration::from_secs(1);
        while !waiter.is_finished() && Instant::now() < deadline {
            tokio::task::yield_now().await;
        }

        assert!(
            waiter.is_finished(),
            "last-reader release must wake the writer immediately"
        );
        drop(waiter.await.unwrap().unwrap());
    }

    #[test]
    fn descriptor_pins_allow_reads_and_exclude_retirement() {
        let directory = tempfile::tempdir().unwrap();
        let descriptor = directory.path().join("snapshot.json");
        std::fs::write(&descriptor, b"descriptor").unwrap();
        let reader = StorageLease::descriptor(&descriptor, false)
            .unwrap()
            .unwrap();
        let clone = reader.clone();
        assert_eq!(std::fs::read(&descriptor).unwrap(), b"descriptor");
        assert!(
            StorageLease::descriptor(&descriptor, true)
                .unwrap()
                .is_none()
        );
        drop(reader);
        assert!(
            StorageLease::descriptor(&descriptor, true)
                .unwrap()
                .is_none()
        );
        drop(clone);
        let deadline = Instant::now() + Duration::from_secs(2);
        let deletion = loop {
            if let Some(lease) = StorageLease::descriptor(&descriptor, true).unwrap() {
                break lease;
            }
            // Parallel tests may fork while this descriptor is live. The child retains
            // the flock briefly until exec closes its inherited descriptor.
            assert!(Instant::now() < deadline, "descriptor remained busy");
            std::thread::sleep(Duration::from_millis(1));
        };
        // Windows must reserve a marker beyond the JSON bytes, not a mandatory lock
        // over bytes that the deleting operation still needs to inspect.
        assert_eq!(std::fs::read(&descriptor).unwrap(), b"descriptor");
        drop(deletion);
    }

    #[test]
    fn readers_exclude_deletion_but_not_unrelated_entries() {
        let directory = tempfile::tempdir().unwrap();
        let a = directory.path().join("a");
        let b = directory.path().join("b");
        let reader = StorageLease::shared(&a).unwrap();
        let clone = reader.clone();
        assert!(StorageLease::try_exclusive(&a).unwrap().is_none());
        assert!(StorageLease::try_exclusive(&b).unwrap().is_some());
        drop(reader);
        assert!(StorageLease::try_exclusive(&a).unwrap().is_none());
        drop(clone);
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if StorageLease::try_exclusive(&a).unwrap().is_some() {
                break;
            }
            // A concurrent fork can retain the last descriptor until exec closes it.
            assert!(Instant::now() < deadline, "reader lease remained busy");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn replacing_payload_does_not_replace_its_lock() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("snapshot");
        std::fs::create_dir(&path).unwrap();
        let lease = StorageLease::try_exclusive(&path).unwrap().unwrap();
        std::fs::remove_dir(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(StorageLease::try_exclusive(&path).unwrap().is_none());
        drop(lease);
        assert!(StorageLease::try_exclusive(&path).unwrap().is_some());
    }

    #[test]
    fn sync_reader_progresses_while_async_reader_retries() {
        const CHILD: &str = "MSB_TEST_SYNC_ASYNC_LEASE_LIVENESS";
        if std::env::var_os(CHILD).is_none() {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "storage_lease::tests::sync_reader_progresses_while_async_reader_retries",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            let status = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break status;
                }
                if Instant::now() >= deadline {
                    child.kill().unwrap();
                    child.wait().unwrap();
                    panic!("sync reader remained stuck behind an async retry");
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            assert!(status.success(), "lease liveness child failed");
            return;
        }

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("resource");
        let key = StorageLease::key(&path).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .max_blocking_threads(1)
            .enable_time()
            .build()
            .unwrap();

        runtime.block_on(async {
            let (release, blocked) = std::sync::mpsc::channel();
            let blocker = tokio::task::spawn_blocking(move || blocked.recv().unwrap());
            let async_reader =
                tokio::spawn(async move { StorageLease::shared_async_keyed(key).await.unwrap() });
            tokio::time::sleep(Duration::from_millis(20)).await;

            let releaser = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(50));
                release.send(()).unwrap();
            });

            // The async attempt is queued. A sync caller must not depend on the
            // runtime resuming that attempt to publish or release its reservation.
            let sync_reader = StorageLease::shared(&path).unwrap();
            releaser.join().unwrap();
            blocker.await.unwrap();
            let async_reader = tokio::time::timeout(Duration::from_secs(1), async_reader)
                .await
                .expect("async reader should reuse the acquired lease")
                .unwrap();
            drop((sync_reader, async_reader));
        });
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn waiting_writer_stops_new_readers() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("resource");
        let initial_reader = StorageLease::shared(&path).unwrap();
        let entry = SharedLeasePool::global().entry(&StorageLease::key(&path).unwrap());
        let writer_path = path.clone();
        let writer =
            tokio::spawn(async move { StorageLease::exclusive_async(writer_path).await.unwrap() });
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let waiting = entry
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .writers_waiting;
            if waiting > 0 {
                break;
            }
            assert!(Instant::now() < deadline, "writer did not start waiting");
            tokio::task::yield_now().await;
        }

        let (sender, receiver) = std::sync::mpsc::channel();
        let reader_path = path.clone();
        let reader = std::thread::spawn(move || {
            sender
                .send(StorageLease::shared(&reader_path).unwrap())
                .unwrap();
        });
        assert!(receiver.recv_timeout(Duration::from_millis(50)).is_err());

        drop(initial_reader);
        let writer = tokio::time::timeout(Duration::from_secs(1), writer)
            .await
            .expect("writer should acquire after existing readers finish")
            .unwrap();
        assert!(receiver.recv_timeout(Duration::from_millis(50)).is_err());

        drop(writer);
        let next_reader = receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("reader should resume after the writer finishes");
        reader.join().unwrap();
        drop(next_reader);
    }

    #[test]
    fn process_exit_releases_reader_lease() {
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("resource");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "storage_lease::tests::child_reader",
                "--ignored",
                "--nocapture",
            ])
            .env("MSB_TEST_STORAGE_LEASE", &path)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let output = child.stdout.take().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                if line.unwrap().contains("LEASE_READY") {
                    sender.send(()).unwrap();
                    break;
                }
            }
        });
        let ready = receiver.recv_timeout(std::time::Duration::from_secs(15));
        if ready.is_err() {
            let _ = child.kill();
        }
        ready.unwrap();
        assert!(StorageLease::try_exclusive(&path).unwrap().is_none());
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(StorageLease::try_exclusive(&path).unwrap().is_some());
    }

    #[test]
    #[ignore = "subprocess helper, exercised by process_exit_releases_reader_lease"]
    fn child_reader() {
        use std::io::Write;
        let path = PathBuf::from(std::env::var_os("MSB_TEST_STORAGE_LEASE").unwrap());
        let _lease = StorageLease::shared(&path).unwrap();
        println!("LEASE_READY");
        std::io::stdout().flush().unwrap();
        loop {
            std::thread::park();
        }
    }
}

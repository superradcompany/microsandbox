//! POSIX shared-memory registry: open/create, slot reservation, sample writes,
//! and snapshot reads.
//!
//! All cross-process synchronization happens through atomics inside the
//! mapped region. The seqlock pattern protects per-sample bytes against
//! torn reads without requiring a kernel mutex.

use std::ffi::CString;
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU16, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use chrono::{DateTime, TimeZone, Utc};

use crate::layout::{
    DEFAULT_CAPACITY, HEADER_SIZE, HEADER_STATE_INITIALIZING, HEADER_STATE_READY,
    HEADER_STATE_UNINIT, Header, NAME_BYTES, REGISTRY_MAGIC, REGISTRY_VERSION, SLOT_ACTIVE,
    SLOT_FREE, SLOT_RESERVED, SLOT_SIZE, SLOT_STALE, Slot, registry_size,
};
use crate::snapshot::LiveMetric;
use crate::{MetricsError, MetricsResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const INIT_WAIT_TIMEOUT: Duration = Duration::from_secs(5);
const INIT_POLL_INTERVAL: Duration = Duration::from_millis(5);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Caller-supplied data used to reserve a slot.
#[derive(Clone, Debug)]
pub struct ReserveSlot<'a> {
    /// Catalog sandbox id.
    pub sandbox_id: i32,
    /// Sandbox name. Truncated to fit the slot.
    pub name: &'a str,
    /// Configured guest memory limit in bytes.
    pub memory_limit_bytes: u64,
}

/// Caller-supplied data used to transition a reservation to active.
#[derive(Clone, Debug)]
pub struct ActivateSlot {
    /// Slot index returned by [`MetricsRegistry::reserve`].
    pub slot: u32,
    /// Generation returned by [`MetricsRegistry::reserve`].
    pub generation: u64,
    /// Catalog run id of the running sandbox.
    pub run_id: i32,
    /// PID of the runtime process.
    pub pid: i32,
    /// Wall-clock time at which the sandbox started.
    pub started_at: DateTime<Utc>,
}

/// Mode passed to [`MetricsRegistry::release`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseMode {
    /// Mark the slot stale so its last sample stays visible until reuse.
    Stale,
    /// Mark the slot immediately free.
    Free,
}

/// Sample bytes to write into a slot.
#[derive(Clone, Copy, Debug)]
pub struct SampleWrite {
    /// Wall-clock time the sample was captured.
    pub sampled_at: DateTime<Utc>,
    /// CPU usage as a percentage across all host CPUs.
    pub cpu_percent: f32,
    /// Resident memory in bytes.
    pub memory_bytes: u64,
    /// Cumulative disk bytes read.
    pub disk_read_bytes: u64,
    /// Cumulative disk bytes written.
    pub disk_write_bytes: u64,
    /// Cumulative network bytes received.
    pub net_rx_bytes: u64,
    /// Cumulative network bytes transmitted.
    pub net_tx_bytes: u64,
}

/// Shared-memory registry.
///
/// Cloneable handle (`Arc`-backed). Dropping the last clone unmaps the region
/// but never `shm_unlink`s — the registry outlives every process.
#[derive(Clone)]
pub struct MetricsRegistry {
    inner: Arc<RegistryInner>,
}

/// Reservation token returned by [`MetricsRegistry::reserve`].
#[derive(Clone, Copy, Debug)]
pub struct SlotReservation {
    /// Slot index assigned to the reservation.
    pub slot: u32,
    /// Generation stamp paired with this allocation. Carries through every
    /// subsequent state transition to prevent stale writers from corrupting
    /// a reused slot.
    pub generation: u64,
}

/// Per-slot writer handle held by the runtime process.
#[derive(Clone)]
pub struct MetricsSlotWriter {
    registry: MetricsRegistry,
    slot: u32,
    generation: u64,
}

struct RegistryInner {
    // Kept alive so a future explicit `unlink` API has the resolved name.
    // Currently only used for the open path; suppress the dead-code warning.
    #[allow(dead_code)]
    name: CString,
    ptr: NonNull<u8>,
    capacity: u32,
    map_len: usize,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

// Safety: the pointer aliases the same shared-memory region across all
// clones, and every read/write goes through atomics or the seqlock helpers.
unsafe impl Send for RegistryInner {}
unsafe impl Sync for RegistryInner {}

impl Drop for RegistryInner {
    fn drop(&mut self) {
        // Unmap only — do not `shm_unlink`. The segment outlives this
        // process and is shared by sibling sandboxes.
        unsafe {
            libc::munmap(self.ptr.as_ptr().cast(), self.map_len);
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl MetricsRegistry {
    /// Open the registry by name, creating it if it does not exist.
    pub fn open_or_create(name: &str, capacity: u32) -> MetricsResult<Self> {
        if capacity == 0 {
            return Err(MetricsError::Custom(
                "registry capacity must be non-zero".into(),
            ));
        }
        let cname = CString::new(name)
            .map_err(|_| MetricsError::Custom("registry name contains NUL byte".into()))?;
        let map_len = registry_size(capacity);

        // Loop to recover from stuck-`INITIALIZING` segments: if a prior
        // creator was SIGKILL'd mid-init, `try_open_existing` will unlink
        // the segment and return `None`, after which we attempt creation.
        // Bound the loop so a pathological environment cannot spin forever.
        const MAX_ATTEMPTS: u32 = 4;
        for _ in 0..MAX_ATTEMPTS {
            if let Some(reg) = try_open_existing(&cname, capacity, map_len)? {
                return Ok(reg);
            }
            match create_and_init(&cname, capacity, map_len) {
                Ok(reg) => return Ok(reg),
                Err(MetricsError::AlreadyExists) => continue,
                Err(other) => return Err(other),
            }
        }
        Err(MetricsError::Custom(
            "failed to open or create metrics registry after multiple attempts".into(),
        ))
    }

    /// Open an existing registry. Errors if it has not yet been created.
    pub fn open(name: &str) -> MetricsResult<Self> {
        let cname = CString::new(name)
            .map_err(|_| MetricsError::Custom("registry name contains NUL byte".into()))?;

        // Two-pass: first map with the header-only length to discover the
        // capacity, then remap with the full length.
        let header_only_len = HEADER_SIZE;
        let fd = unsafe { libc::shm_open(cname.as_ptr(), libc::O_RDWR, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                header_only_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        // Closing the fd is fine: the mapping stays alive.
        unsafe { libc::close(fd) };
        if ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error().into());
        }
        let header = unsafe { &*(ptr as *const Header) };
        let ready_result = wait_for_ready(header);
        let capacity = match ready_result {
            Ok(()) => match validate_header(header, None) {
                Ok(()) => header.capacity,
                Err(err) => {
                    unsafe { libc::munmap(ptr, header_only_len) };
                    return Err(err);
                }
            },
            Err(WaitForReadyError::Stuck) => {
                unsafe { libc::munmap(ptr, header_only_len) };
                return Err(MetricsError::Custom(
                    "metrics registry is still initializing".into(),
                ));
            }
            Err(WaitForReadyError::Invalid(state)) => {
                unsafe { libc::munmap(ptr, header_only_len) };
                return Err(MetricsError::Custom(format!(
                    "invalid registry header state: {state}"
                )));
            }
        };
        unsafe {
            libc::munmap(ptr, header_only_len);
        }

        let map_len = registry_size(capacity);
        let reg = try_open_existing(&cname, capacity, map_len)?
            .ok_or_else(|| MetricsError::Custom("registry disappeared during open".into()))?;
        Ok(reg)
    }

    /// Reserve a slot for an upcoming sandbox spawn.
    pub fn reserve(&self, spec: ReserveSlot<'_>) -> MetricsResult<SlotReservation> {
        let capacity = self.inner.capacity;
        // Scan slots once for a Free entry; fall back to a second pass that
        // also reclaims Stale entries. Two passes keep Stale samples visible
        // when there is spare capacity.
        for pass in 0..2 {
            for idx in 0..capacity {
                let slot = self.slot(idx);
                let current = slot.state.load(Ordering::Acquire);
                let claimable = matches!((pass, current), (_, SLOT_FREE) | (1, SLOT_STALE));
                if !claimable {
                    continue;
                }
                if slot
                    .state
                    .compare_exchange(current, SLOT_RESERVED, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    let generation = self.next_generation();
                    write_reservation_fields(slot, &spec, generation);
                    return Ok(SlotReservation {
                        slot: idx,
                        generation,
                    });
                }
            }
        }
        Err(MetricsError::Full)
    }

    /// Promote a reservation to an active writer.
    pub fn activate_writer(&self, spec: ActivateSlot) -> MetricsResult<MetricsSlotWriter> {
        let slot = self.try_slot(spec.slot)?;
        let observed = slot.generation.load(Ordering::Acquire);
        if observed != spec.generation {
            return Err(MetricsError::GenerationMismatch {
                expected: spec.generation,
                actual: observed,
            });
        }

        // Seq starts even; bump odd, write metadata, bump even again. We
        // write inside the seqlock window so a reader that observes Active
        // sees a coherent run_id/pid/started_at snapshot.
        let begin = begin_write(slot);
        // Re-check generation under the seqlock so a stale activator cannot
        // resurrect a slot that was reused while we were preparing.
        let observed_inside = slot.generation.load(Ordering::Acquire);
        if observed_inside != spec.generation {
            end_write(slot, begin);
            return Err(MetricsError::GenerationMismatch {
                expected: spec.generation,
                actual: observed_inside,
            });
        }
        slot.run_id.store(spec.run_id, Ordering::Relaxed);
        slot.pid.store(spec.pid, Ordering::Relaxed);
        slot.started_at_unix_ms
            .store(spec.started_at.timestamp_millis(), Ordering::Relaxed);
        end_write(slot, begin);

        // Atomic Reserved → Active transition. Reject if anything moved the
        // slot out of Reserved (an external release, a stale activator, or a
        // reaper) between our generation check and now.
        slot.state
            .compare_exchange(
                SLOT_RESERVED,
                SLOT_ACTIVE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|actual| {
                MetricsError::Custom(format!(
                    "cannot activate slot {}: state moved out of Reserved ({actual})",
                    spec.slot
                ))
            })?;

        Ok(MetricsSlotWriter {
            registry: self.clone(),
            slot: spec.slot,
            generation: spec.generation,
        })
    }

    /// Release a slot. Used both by the runtime exit observer and the host
    /// reaper. Generation-checked so a stale caller cannot clear a reused slot.
    ///
    /// The release does three things, in order:
    ///
    /// 1. Wait briefly for any in-flight writer to finish its seqlock cycle.
    ///    If `seq` stays odd past the spin budget, the writer is presumed
    ///    dead (e.g. SIGKILL'd mid-write); force `seq` back to even so the
    ///    next `reserve` does not call `begin_write` on an odd `seq` —
    ///    that would corrupt the seqlock and make the slot unreadable.
    /// 2. Bump the slot's generation. Any stranded writer that re-enters
    ///    `write_sample` (or that already passed the outer generation
    ///    check but has not yet committed) will see the new generation in
    ///    its inner re-check and abort the cycle.
    /// 3. Publish the new state. Readers observing `Free`/`Stale` either
    ///    skip the slot or see a coherent terminal sample.
    pub fn release(&self, slot_idx: u32, generation: u64, mode: ReleaseMode) -> MetricsResult<()> {
        let slot = self.try_slot(slot_idx)?;
        let observed = slot.generation.load(Ordering::Acquire);
        if observed != generation {
            return Err(MetricsError::GenerationMismatch {
                expected: generation,
                actual: observed,
            });
        }

        quiesce_seq(slot);

        // Invalidate any writer that might still be holding `self.generation`
        // — its inner re-check will now see a different value and bail.
        let new_gen = self
            .header()
            .global_generation
            .fetch_add(1, Ordering::AcqRel)
            + 1;
        slot.generation.store(new_gen, Ordering::Release);

        let new_state = match mode {
            ReleaseMode::Stale => SLOT_STALE,
            ReleaseMode::Free => SLOT_FREE,
        };
        slot.state.store(new_state, Ordering::Release);
        Ok(())
    }

    /// Snapshot every active or stale slot.
    pub fn snapshot(&self) -> MetricsResult<Vec<LiveMetric>> {
        let mut out = Vec::new();
        for idx in 0..self.inner.capacity {
            if let Some(metric) = self.read_slot(idx) {
                out.push(metric);
            }
        }
        Ok(out)
    }

    /// Lookup the active or stale slot for a sandbox id, if any.
    pub fn get_by_sandbox_id(&self, sandbox_id: i32) -> MetricsResult<Option<LiveMetric>> {
        for idx in 0..self.inner.capacity {
            let slot = self.slot(idx);
            let state = slot.state.load(Ordering::Acquire);
            if state != SLOT_ACTIVE && state != SLOT_STALE {
                continue;
            }
            if slot.sandbox_id.load(Ordering::Acquire) != sandbox_id {
                continue;
            }
            // Re-verify identity from the coherent snapshot: the slot could
            // have been released and reused for a different sandbox between
            // the outer filter and the seqlock-protected read.
            if let Some(metric) = self.read_slot(idx)
                && metric.sandbox_id == sandbox_id
            {
                return Ok(Some(metric));
            }
        }
        Ok(None)
    }

    /// Lookup the active slot for a run id, if any.
    pub fn get_by_run_id(&self, run_id: i32) -> MetricsResult<Option<LiveMetric>> {
        for idx in 0..self.inner.capacity {
            let slot = self.slot(idx);
            let state = slot.state.load(Ordering::Acquire);
            if state != SLOT_ACTIVE && state != SLOT_STALE {
                continue;
            }
            if slot.run_id.load(Ordering::Acquire) != run_id {
                continue;
            }
            if let Some(metric) = self.read_slot(idx)
                && metric.run_id == run_id
            {
                return Ok(Some(metric));
            }
        }
        Ok(None)
    }

    /// Number of slots in this registry.
    pub fn capacity(&self) -> u32 {
        self.inner.capacity
    }

    /// Release the slot owned by the given catalog identity, if any.
    ///
    /// Matches by run id first (most precise), falling back to sandbox id
    /// when `run_id` is `None`. Returns the slot index that was released, or
    /// `None` if no matching slot was found. The current slot generation is
    /// looked up internally — callers do not have to track it across
    /// catalog reads.
    pub fn release_by_identity(
        &self,
        sandbox_id: i32,
        run_id: Option<i32>,
        mode: ReleaseMode,
    ) -> MetricsResult<Option<u32>> {
        for idx in 0..self.inner.capacity {
            let slot = self.slot(idx);
            let state = slot.state.load(Ordering::Acquire);
            if state != SLOT_ACTIVE && state != SLOT_STALE && state != SLOT_RESERVED {
                continue;
            }
            let matches = match run_id {
                Some(rid) => slot.run_id.load(Ordering::Acquire) == rid,
                None => slot.sandbox_id.load(Ordering::Acquire) == sandbox_id,
            };
            if !matches {
                continue;
            }
            let generation = slot.generation.load(Ordering::Acquire);
            self.release(idx, generation, mode)?;
            return Ok(Some(idx));
        }
        Ok(None)
    }

    fn next_generation(&self) -> u64 {
        let header = self.header();
        // Generations start at 1 so the value `0` always means "unset".
        header.global_generation.fetch_add(1, Ordering::AcqRel) + 1
    }

    fn header(&self) -> &Header {
        unsafe { &*(self.inner.ptr.as_ptr() as *const Header) }
    }

    fn slot(&self, idx: u32) -> &Slot {
        debug_assert!(idx < self.inner.capacity);
        let base = self.inner.ptr.as_ptr();
        let offset = HEADER_SIZE + (idx as usize) * SLOT_SIZE;
        unsafe { &*(base.add(offset) as *const Slot) }
    }

    fn try_slot(&self, idx: u32) -> MetricsResult<&Slot> {
        if idx >= self.inner.capacity {
            return Err(MetricsError::Custom(format!(
                "slot index {idx} out of range (capacity={})",
                self.inner.capacity
            )));
        }
        Ok(self.slot(idx))
    }

    fn read_slot(&self, idx: u32) -> Option<LiveMetric> {
        let slot = self.slot(idx);
        // Try many times to obtain a coherent snapshot. A tight-loop writer
        // can complete a full cycle in <100 ns, so we need a generous budget
        // before giving up. 4096 attempts is still cheap (<1 ms in the worst
        // case) and effectively unbounded in practice.
        for _ in 0..4096 {
            let state = slot.state.load(Ordering::Acquire);
            if state != SLOT_ACTIVE && state != SLOT_STALE {
                return None;
            }
            // Capture generation before reading fields so we can confirm the
            // slot's identity stayed stable across the entire read.
            let gen_before = slot.generation.load(Ordering::Acquire);

            let s1 = slot.seq.load(Ordering::Acquire);
            if s1 & 1 == 1 {
                std::hint::spin_loop();
                continue;
            }

            let sandbox_id = slot.sandbox_id.load(Ordering::Relaxed);
            let run_id = slot.run_id.load(Ordering::Relaxed);
            let pid = slot.pid.load(Ordering::Relaxed);
            let started_at_ms = slot.started_at_unix_ms.load(Ordering::Relaxed);
            let sampled_at_ms = slot.sampled_at_unix_ms.load(Ordering::Relaxed);
            let memory_limit = slot.memory_limit_bytes.load(Ordering::Relaxed);
            let cpu_bits = slot.cpu_percent_bits.load(Ordering::Relaxed);
            let memory = slot.memory_bytes.load(Ordering::Relaxed);
            let disk_r = slot.disk_read_bytes.load(Ordering::Relaxed);
            let disk_w = slot.disk_write_bytes.load(Ordering::Relaxed);
            let net_rx = slot.net_rx_bytes.load(Ordering::Relaxed);
            let net_tx = slot.net_tx_bytes.load(Ordering::Relaxed);
            let name = read_name(slot);

            let s2 = slot.seq.load(Ordering::Acquire);
            // Reject torn reads (s1 != s2), reads that landed mid-write
            // (s2 odd), reads where the slot was reused under us
            // (generation changed), or reads where state moved out of
            // {Active, Stale} between the initial state check and now.
            let gen_after = slot.generation.load(Ordering::Acquire);
            let state_after = slot.state.load(Ordering::Acquire);
            let state_stable = state_after == SLOT_ACTIVE || state_after == SLOT_STALE;
            if s1 != s2 || s2 & 1 == 1 || gen_before != gen_after || !state_stable {
                std::hint::spin_loop();
                continue;
            }

            // Skip slots whose owner has activated but not yet written a
            // first sample — `sampled_at_unix_ms` is 0 from reservation
            // zeroing, which would surface as a 1970-stamped metric.
            if sampled_at_ms <= 0 {
                return None;
            }

            let timestamp = ms_to_datetime(sampled_at_ms);
            let started_at = ms_to_datetime(started_at_ms);
            let uptime = timestamp
                .signed_duration_since(started_at)
                .to_std()
                .unwrap_or_default();

            return Some(LiveMetric {
                sandbox_id,
                run_id,
                pid,
                name,
                timestamp,
                uptime,
                cpu_percent: f32::from_bits(cpu_bits),
                memory_bytes: memory,
                memory_limit_bytes: memory_limit,
                disk_read_bytes: disk_r,
                disk_write_bytes: disk_w,
                net_rx_bytes: net_rx,
                net_tx_bytes: net_tx,
            });
        }
        None
    }
}

impl MetricsSlotWriter {
    /// Write a new sample into the owned slot.
    ///
    /// Returns [`MetricsError::GenerationMismatch`] if the slot was reclaimed
    /// out from under this writer. Callers (the sampler) should stop on
    /// mismatch instead of forcing the write.
    pub fn write_sample(&self, sample: SampleWrite) -> MetricsResult<()> {
        let slot = self.registry.try_slot(self.slot)?;
        let observed = slot.generation.load(Ordering::Acquire);
        if observed != self.generation {
            return Err(MetricsError::GenerationMismatch {
                expected: self.generation,
                actual: observed,
            });
        }

        let begin = begin_write(slot);

        // Re-check generation while inside the seqlock window. Between the
        // outer load and `begin_write`, an external caller can release the
        // slot and a new reservation can claim it, bumping `generation`. If
        // that happened, our stores would corrupt the new owner's freshly
        // initialized fields. Close the seqlock without writing.
        let observed_inside = slot.generation.load(Ordering::Acquire);
        if observed_inside != self.generation {
            end_write(slot, begin);
            return Err(MetricsError::GenerationMismatch {
                expected: self.generation,
                actual: observed_inside,
            });
        }

        slot.sampled_at_unix_ms
            .store(sample.sampled_at.timestamp_millis(), Ordering::Relaxed);
        slot.cpu_percent_bits
            .store(sample.cpu_percent.to_bits(), Ordering::Relaxed);
        slot.memory_bytes
            .store(sample.memory_bytes, Ordering::Relaxed);
        slot.disk_read_bytes
            .store(sample.disk_read_bytes, Ordering::Relaxed);
        slot.disk_write_bytes
            .store(sample.disk_write_bytes, Ordering::Relaxed);
        slot.net_rx_bytes
            .store(sample.net_rx_bytes, Ordering::Relaxed);
        slot.net_tx_bytes
            .store(sample.net_tx_bytes, Ordering::Relaxed);
        end_write(slot, begin);
        Ok(())
    }

    /// Slot index owned by this writer.
    pub fn slot(&self) -> u32 {
        self.slot
    }

    /// Generation paired with this writer's slot reservation.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Convenience method for releasing the owned slot.
    pub fn release(self, mode: ReleaseMode) -> MetricsResult<()> {
        self.registry.release(self.slot, self.generation, mode)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Default capacity used by the host launcher when creating a registry.
pub const fn default_capacity() -> u32 {
    DEFAULT_CAPACITY
}

fn try_open_existing(
    name: &std::ffi::CStr,
    expected_capacity: u32,
    map_len: usize,
) -> MetricsResult<Option<MetricsRegistry>> {
    let fd = unsafe { libc::shm_open(name.as_ptr(), libc::O_RDWR, 0) };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(err.into());
    }

    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            map_len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    unsafe { libc::close(fd) };
    if ptr == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error().into());
    }

    let header_ref = unsafe { &*(ptr as *const Header) };
    match wait_for_ready(header_ref) {
        Ok(()) => {}
        Err(WaitForReadyError::Stuck) => {
            // The creator was killed mid-init. Unlink the dead segment so
            // the caller can create a fresh one; return `None` to indicate
            // "no usable registry exists".
            unsafe {
                libc::munmap(ptr, map_len);
                libc::shm_unlink(name.as_ptr());
            }
            tracing::warn!(
                shm = %name.to_string_lossy(),
                "metrics registry stuck in initialization; unlinked for recreate"
            );
            return Ok(None);
        }
        Err(WaitForReadyError::Invalid(state)) => {
            unsafe { libc::munmap(ptr, map_len) };
            return Err(MetricsError::Custom(format!(
                "invalid registry header state: {state}"
            )));
        }
    }
    if let Err(e) = validate_header(header_ref, Some(expected_capacity)) {
        unsafe { libc::munmap(ptr, map_len) };
        return Err(e);
    }

    let inner = RegistryInner {
        name: name.to_owned(),
        ptr: NonNull::new(ptr as *mut u8).expect("mmap returned non-null"),
        capacity: header_ref.capacity,
        map_len,
    };
    Ok(Some(MetricsRegistry {
        inner: Arc::new(inner),
    }))
}

fn create_and_init(
    name: &std::ffi::CStr,
    capacity: u32,
    map_len: usize,
) -> MetricsResult<MetricsRegistry> {
    let fd = unsafe {
        libc::shm_open(
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )
    };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(libc::EEXIST) => Err(MetricsError::AlreadyExists),
            _ => Err(err.into()),
        };
    }

    if unsafe { libc::ftruncate(fd, map_len as libc::off_t) } != 0 {
        let e = std::io::Error::last_os_error();
        unsafe {
            libc::close(fd);
            libc::shm_unlink(name.as_ptr());
        }
        return Err(e.into());
    }

    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            map_len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    unsafe { libc::close(fd) };
    if ptr == libc::MAP_FAILED {
        let e = std::io::Error::last_os_error();
        unsafe {
            libc::shm_unlink(name.as_ptr());
        }
        return Err(e.into());
    }

    // Initialize header and slots while the state is still UNINIT/INITIALIZING.
    let header = unsafe { &mut *(ptr as *mut Header) };
    // SAFETY: just-truncated memory is zero-filled. We're the exclusive
    // initializer thanks to O_EXCL.
    header
        .state
        .store(HEADER_STATE_INITIALIZING, Ordering::Release);
    header.magic = REGISTRY_MAGIC;
    header.version = REGISTRY_VERSION;
    header.header_len = HEADER_SIZE as u32;
    header.slot_len = SLOT_SIZE as u32;
    header.capacity = capacity;
    header.created_at_unix_ms = chrono::Utc::now().timestamp_millis();
    header.global_generation.store(0, Ordering::Release);
    // Slots are already zero-filled by ftruncate; SLOT_FREE == 0 and
    // seq == 0 (even), so they are already in a valid initial state.
    header.state.store(HEADER_STATE_READY, Ordering::Release);

    let inner = RegistryInner {
        name: name.to_owned(),
        ptr: NonNull::new(ptr as *mut u8).expect("mmap returned non-null"),
        capacity,
        map_len,
    };
    Ok(MetricsRegistry {
        inner: Arc::new(inner),
    })
}

/// Outcome of `wait_for_ready`. `Stuck` lets the caller unlink and retry.
enum WaitForReadyError {
    /// The header was still `UNINIT`/`INITIALIZING` when the wait expired.
    /// The creator likely crashed mid-init; the segment must be unlinked
    /// before any further progress.
    Stuck,
    /// The header carried an unrecognised state value.
    Invalid(u32),
}

fn wait_for_ready(header: &Header) -> Result<(), WaitForReadyError> {
    let deadline = Instant::now() + INIT_WAIT_TIMEOUT;
    loop {
        let state = header.state.load(Ordering::Acquire);
        if state == HEADER_STATE_READY {
            return Ok(());
        }
        if state != HEADER_STATE_UNINIT && state != HEADER_STATE_INITIALIZING {
            return Err(WaitForReadyError::Invalid(state));
        }
        if Instant::now() >= deadline {
            return Err(WaitForReadyError::Stuck);
        }
        std::thread::sleep(INIT_POLL_INTERVAL);
    }
}

fn validate_header(header: &Header, expected_capacity: Option<u32>) -> MetricsResult<()> {
    if header.magic != REGISTRY_MAGIC {
        return Err(MetricsError::Custom(format!(
            "invalid registry magic: 0x{:x}",
            header.magic
        )));
    }
    if header.version != REGISTRY_VERSION {
        return Err(MetricsError::Custom(format!(
            "incompatible registry version: {}",
            header.version
        )));
    }
    if header.header_len as usize != HEADER_SIZE {
        return Err(MetricsError::Custom(format!(
            "unexpected header length: {}",
            header.header_len
        )));
    }
    if header.slot_len as usize != SLOT_SIZE {
        return Err(MetricsError::Custom(format!(
            "unexpected slot length: {}",
            header.slot_len
        )));
    }
    if let Some(expected) = expected_capacity
        && header.capacity != expected
    {
        return Err(MetricsError::Custom(format!(
            "registry capacity mismatch: opened={}, expected={expected}",
            header.capacity
        )));
    }
    Ok(())
}

fn write_reservation_fields(slot: &Slot, spec: &ReserveSlot<'_>, generation: u64) {
    // Reset the per-sample fields first so a reader seeing the slot before
    // activation doesn't observe stale counters from a prior owner.
    let begin = begin_write(slot);
    slot.sandbox_id.store(spec.sandbox_id, Ordering::Relaxed);
    slot.run_id.store(0, Ordering::Relaxed);
    slot.pid.store(0, Ordering::Relaxed);
    slot.started_at_unix_ms.store(0, Ordering::Relaxed);
    slot.sampled_at_unix_ms.store(0, Ordering::Relaxed);
    slot.memory_limit_bytes
        .store(spec.memory_limit_bytes, Ordering::Relaxed);
    slot.cpu_percent_bits.store(0, Ordering::Relaxed);
    slot.memory_bytes.store(0, Ordering::Relaxed);
    slot.disk_read_bytes.store(0, Ordering::Relaxed);
    slot.disk_write_bytes.store(0, Ordering::Relaxed);
    slot.net_rx_bytes.store(0, Ordering::Relaxed);
    slot.net_tx_bytes.store(0, Ordering::Relaxed);
    write_name(slot, spec.name);
    end_write(slot, begin);

    // Publishing the generation last makes the activator's compare succeed
    // only after every reservation byte is visible.
    slot.generation.store(generation, Ordering::Release);
}

fn write_name(slot: &Slot, name: &str) {
    let bytes = name.as_bytes();
    let len = bytes.len().min(NAME_BYTES);
    for (i, byte) in bytes.iter().take(len).enumerate() {
        slot.name_bytes[i].store(*byte, Ordering::Relaxed);
    }
    for i in len..NAME_BYTES {
        slot.name_bytes[i].store(0, Ordering::Relaxed);
    }
    slot.name_len.store(len as u16, Ordering::Relaxed);
}

fn read_name(slot: &Slot) -> String {
    let len = (slot.name_len.load(Ordering::Relaxed) as usize).min(NAME_BYTES);
    let mut bytes = Vec::with_capacity(len);
    for i in 0..len {
        bytes.push(slot.name_bytes[i].load(Ordering::Relaxed));
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn begin_write(slot: &Slot) -> u64 {
    let prev = slot.seq.fetch_add(1, Ordering::AcqRel);
    debug_assert!(prev & 1 == 0, "seqlock was already odd before write");
    prev + 1
}

fn end_write(slot: &Slot, begin: u64) {
    let prev = slot.seq.fetch_add(1, Ordering::AcqRel);
    debug_assert_eq!(prev, begin, "seqlock end did not pair with begin");
}

/// Wait for any in-flight writer to leave the seqlock window before
/// surrendering the slot. If `seq` stays odd past the spin budget, the
/// writer is presumed dead (SIGKILL mid-write) and we force `seq` to even
/// so the next reservation can `begin_write` without observing odd parity.
///
/// The spin budget is generous: a legitimate `write_sample` cycle stores
/// ~8 atomics, well under a microsecond. 4096 spin iterations gives the
/// writer roughly two orders of magnitude of headroom on modern hardware
/// before we decide the writer is dead.
fn quiesce_seq(slot: &Slot) {
    const MAX_SPINS: u32 = 4096;
    let mut spins = 0u32;
    loop {
        let s = slot.seq.load(Ordering::Acquire);
        if s & 1 == 0 {
            return;
        }
        if spins >= MAX_SPINS {
            // Writer assumed dead. Force seq even via CAS so a concurrent
            // writer racing the same recovery cannot leave seq odd again.
            // The CAS may fail if the writer just completed; the loop
            // re-reads and exits cleanly in that case.
            let _ = slot.seq.compare_exchange(
                s,
                s.wrapping_add(1),
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            continue;
        }
        spins += 1;
        std::hint::spin_loop();
    }
}

fn ms_to_datetime(ms: i64) -> DateTime<Utc> {
    if ms <= 0 {
        return DateTime::<Utc>::UNIX_EPOCH;
    }
    Utc.timestamp_millis_opt(ms)
        .single()
        .unwrap_or_else(|| Utc.timestamp_opt(0, 0).unwrap())
}

// `AtomicU8`, `AtomicU16`, and `AtomicU64` are referenced to keep the
// reservation/write helpers self-contained.
fn _assert_atomic_traits() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<AtomicU8>();
    assert_send_sync::<AtomicU16>();
    assert_send_sync::<AtomicU64>();
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Barrier;
    use std::thread;

    use super::*;

    fn unique_name(tag: &str) -> String {
        // macOS shm_open names are capped at ~31 bytes; keep the test name
        // short enough to fit while remaining unique per test invocation.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("/msb-mtt-{tag}-{}", nanos & 0xffff_ffff)
    }

    fn cleanup(name: &str) {
        let cname = CString::new(name).unwrap();
        unsafe {
            libc::shm_unlink(cname.as_ptr());
        }
    }

    #[test]
    fn reserve_activate_write_and_snapshot_roundtrip() {
        let name = unique_name("rt");
        let reg = MetricsRegistry::open_or_create(&name, 16).unwrap();

        let res = reg
            .reserve(ReserveSlot {
                sandbox_id: 7,
                name: "alpine",
                memory_limit_bytes: 256 * 1024 * 1024,
            })
            .unwrap();
        let started_at = Utc::now() - chrono::Duration::seconds(2);
        let writer = reg
            .activate_writer(ActivateSlot {
                slot: res.slot,
                generation: res.generation,
                run_id: 99,
                pid: 4242,
                started_at,
            })
            .unwrap();

        let sample = SampleWrite {
            sampled_at: Utc::now(),
            cpu_percent: 12.5,
            memory_bytes: 1024 * 1024,
            disk_read_bytes: 4096,
            disk_write_bytes: 8192,
            net_rx_bytes: 100,
            net_tx_bytes: 200,
        };
        writer.write_sample(sample).unwrap();

        let snap = reg.snapshot().unwrap();
        assert_eq!(snap.len(), 1);
        let item = &snap[0];
        assert_eq!(item.sandbox_id, 7);
        assert_eq!(item.run_id, 99);
        assert_eq!(item.pid, 4242);
        assert_eq!(item.name, "alpine");
        assert!((item.cpu_percent - 12.5).abs() < 1e-6);
        assert_eq!(item.memory_bytes, 1024 * 1024);
        assert_eq!(item.memory_limit_bytes, 256 * 1024 * 1024);
        assert_eq!(item.disk_read_bytes, 4096);
        assert_eq!(item.disk_write_bytes, 8192);
        assert_eq!(item.net_rx_bytes, 100);
        assert_eq!(item.net_tx_bytes, 200);

        // Lookup by sandbox + run id.
        assert_eq!(
            reg.get_by_sandbox_id(7).unwrap().map(|m| m.run_id),
            Some(99)
        );
        assert_eq!(
            reg.get_by_run_id(99).unwrap().map(|m| m.sandbox_id),
            Some(7)
        );

        writer.release(ReleaseMode::Free).unwrap();
        assert!(reg.snapshot().unwrap().is_empty());
        cleanup(&name);
    }

    #[test]
    fn coherent_reads_under_writer_pressure() {
        let name = unique_name("coh");
        let reg = MetricsRegistry::open_or_create(&name, 8).unwrap();

        let res = reg
            .reserve(ReserveSlot {
                sandbox_id: 1,
                name: "x",
                memory_limit_bytes: 1,
            })
            .unwrap();
        let writer = reg
            .activate_writer(ActivateSlot {
                slot: res.slot,
                generation: res.generation,
                run_id: 1,
                pid: 1,
                started_at: Utc::now(),
            })
            .unwrap();

        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_w = Arc::clone(&stop);
        let writer_clone = writer.clone();
        let writer_thread = thread::spawn(move || {
            let mut counter: u64 = 0;
            while !stop_w.load(Ordering::Relaxed) {
                counter = counter.wrapping_add(1);
                let sample = SampleWrite {
                    sampled_at: Utc::now(),
                    cpu_percent: (counter % 100) as f32,
                    memory_bytes: counter,
                    disk_read_bytes: counter,
                    disk_write_bytes: counter,
                    net_rx_bytes: counter,
                    net_tx_bytes: counter,
                };
                writer_clone.write_sample(sample).unwrap();
                // Yield occasionally so the reader has a quiescent window;
                // production writers sample at ~1 Hz, not in a tight loop.
                std::thread::yield_now();
            }
        });

        // Coherence check: any snapshot we manage to read must have all five
        // counter fields equal. The seqlock retries internally; on extreme
        // contention we may briefly observe `None`, which is acceptable.
        let mut successful_reads = 0;
        for _ in 0..10_000 {
            let snap = reg.snapshot().unwrap();
            if let Some(item) = snap.first() {
                assert_eq!(item.memory_bytes, item.disk_read_bytes);
                assert_eq!(item.memory_bytes, item.disk_write_bytes);
                assert_eq!(item.memory_bytes, item.net_rx_bytes);
                assert_eq!(item.memory_bytes, item.net_tx_bytes);
                successful_reads += 1;
            }
        }
        stop.store(true, Ordering::Relaxed);
        writer_thread.join().unwrap();

        assert!(
            successful_reads > 100,
            "expected non-trivial number of successful reads under contention, got {successful_reads}"
        );
        cleanup(&name);
    }

    #[test]
    fn concurrent_reservations_do_not_collide() {
        let name = unique_name("res");
        let reg = MetricsRegistry::open_or_create(&name, 64).unwrap();

        const WORKERS: usize = 8;
        const PER_WORKER: usize = 6;
        let barrier = Arc::new(Barrier::new(WORKERS));
        let mut handles = Vec::new();
        for w in 0..WORKERS {
            let reg = reg.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                let mut claimed = Vec::new();
                for n in 0..PER_WORKER {
                    let res = reg
                        .reserve(ReserveSlot {
                            sandbox_id: (w * PER_WORKER + n) as i32 + 1,
                            name: "concur",
                            memory_limit_bytes: 1,
                        })
                        .unwrap();
                    claimed.push((res.slot, res.generation));
                }
                claimed
            }));
        }

        let mut all = Vec::new();
        for h in handles {
            all.extend(h.join().unwrap());
        }
        assert_eq!(all.len(), WORKERS * PER_WORKER);
        let mut slot_indices: Vec<u32> = all.iter().map(|(s, _)| *s).collect();
        slot_indices.sort();
        slot_indices.dedup();
        assert_eq!(slot_indices.len(), WORKERS * PER_WORKER);
        cleanup(&name);
    }

    #[test]
    fn generation_mismatch_blocks_stale_writes() {
        let name = unique_name("gen");
        // Capacity 1 forces the second reservation to reuse the stale slot.
        let reg = MetricsRegistry::open_or_create(&name, 1).unwrap();
        let res = reg
            .reserve(ReserveSlot {
                sandbox_id: 1,
                name: "x",
                memory_limit_bytes: 1,
            })
            .unwrap();
        let writer = reg
            .activate_writer(ActivateSlot {
                slot: res.slot,
                generation: res.generation,
                run_id: 1,
                pid: 1,
                started_at: Utc::now(),
            })
            .unwrap();
        // Stale-release the slot, then reuse it for a different sandbox.
        writer.clone().release(ReleaseMode::Stale).unwrap();
        let res2 = reg
            .reserve(ReserveSlot {
                sandbox_id: 2,
                name: "y",
                memory_limit_bytes: 1,
            })
            .unwrap();
        assert_eq!(res2.slot, res.slot);
        assert_ne!(res2.generation, res.generation);

        let err = writer
            .write_sample(SampleWrite {
                sampled_at: Utc::now(),
                cpu_percent: 0.0,
                memory_bytes: 0,
                disk_read_bytes: 0,
                disk_write_bytes: 0,
                net_rx_bytes: 0,
                net_tx_bytes: 0,
            })
            .unwrap_err();
        assert!(matches!(err, MetricsError::GenerationMismatch { .. }));
        cleanup(&name);
    }

    #[test]
    fn full_registry_returns_full_error() {
        let name = unique_name("full");
        let reg = MetricsRegistry::open_or_create(&name, 2).unwrap();
        let _ = reg
            .reserve(ReserveSlot {
                sandbox_id: 1,
                name: "a",
                memory_limit_bytes: 1,
            })
            .unwrap();
        let _ = reg
            .reserve(ReserveSlot {
                sandbox_id: 2,
                name: "b",
                memory_limit_bytes: 1,
            })
            .unwrap();
        let err = reg
            .reserve(ReserveSlot {
                sandbox_id: 3,
                name: "c",
                memory_limit_bytes: 1,
            })
            .unwrap_err();
        assert!(matches!(err, MetricsError::Full));
        cleanup(&name);
    }

    #[test]
    fn activated_but_unsampled_slot_is_not_visible() {
        // Until a sampler writes its first sample, readers should not see a
        // freshly-activated slot — otherwise consumers observe a 1970-stamped
        // metric for a sandbox that hasn't reported yet.
        let name = unique_name("pre");
        let reg = MetricsRegistry::open_or_create(&name, 2).unwrap();
        let res = reg
            .reserve(ReserveSlot {
                sandbox_id: 1,
                name: "x",
                memory_limit_bytes: 1,
            })
            .unwrap();
        let _writer = reg
            .activate_writer(ActivateSlot {
                slot: res.slot,
                generation: res.generation,
                run_id: 1,
                pid: 1,
                started_at: Utc::now(),
            })
            .unwrap();
        assert!(reg.snapshot().unwrap().is_empty());
        assert!(reg.get_by_sandbox_id(1).unwrap().is_none());
        assert!(reg.get_by_run_id(1).unwrap().is_none());
        cleanup(&name);
    }

    #[test]
    fn write_sample_inner_generation_recheck_rejects_stale_writer() {
        // Force a release+reserve race between the outer generation check
        // and the seqlock window: do the release+reserve manually, then call
        // write_sample on the original writer and confirm it errors out.
        let name = unique_name("igen");
        let reg = MetricsRegistry::open_or_create(&name, 1).unwrap();
        let res = reg
            .reserve(ReserveSlot {
                sandbox_id: 1,
                name: "x",
                memory_limit_bytes: 1,
            })
            .unwrap();
        let writer = reg
            .activate_writer(ActivateSlot {
                slot: res.slot,
                generation: res.generation,
                run_id: 10,
                pid: 100,
                started_at: Utc::now(),
            })
            .unwrap();
        // Stale-release and re-reserve the slot for a different sandbox.
        reg.release(res.slot, res.generation, ReleaseMode::Stale)
            .unwrap();
        let res2 = reg
            .reserve(ReserveSlot {
                sandbox_id: 2,
                name: "y",
                memory_limit_bytes: 1,
            })
            .unwrap();
        assert_eq!(res2.slot, res.slot);
        assert_ne!(res2.generation, res.generation);
        // The original writer must refuse to write a sample.
        let err = writer
            .write_sample(SampleWrite {
                sampled_at: Utc::now(),
                cpu_percent: 0.0,
                memory_bytes: 999_999,
                disk_read_bytes: 0,
                disk_write_bytes: 0,
                net_rx_bytes: 0,
                net_tx_bytes: 0,
            })
            .unwrap_err();
        assert!(matches!(err, MetricsError::GenerationMismatch { .. }));
        cleanup(&name);
    }

    #[test]
    fn release_recovers_from_writer_killed_mid_seqlock() {
        // Simulate a writer SIGKILL'd between `begin_write` and `end_write`:
        // seq is left odd. The next `release` must (a) restore even parity
        // so a subsequent `begin_write` does not see odd seq and corrupt
        // the seqlock, and (b) bump generation so any stranded writer that
        // re-enters `write_sample` fails the inner re-check.
        let name = unique_name("sigk");
        let reg = MetricsRegistry::open_or_create(&name, 2).unwrap();
        let res = reg
            .reserve(ReserveSlot {
                sandbox_id: 1,
                name: "x",
                memory_limit_bytes: 1,
            })
            .unwrap();
        let writer = reg
            .activate_writer(ActivateSlot {
                slot: res.slot,
                generation: res.generation,
                run_id: 10,
                pid: 100,
                started_at: Utc::now(),
            })
            .unwrap();
        writer
            .write_sample(SampleWrite {
                sampled_at: Utc::now(),
                cpu_percent: 0.0,
                memory_bytes: 1,
                disk_read_bytes: 0,
                disk_write_bytes: 0,
                net_rx_bytes: 0,
                net_tx_bytes: 0,
            })
            .unwrap();

        // Inject the SIGKILL-mid-write state: bump seq once to leave it odd.
        let slot_ref = reg.slot(res.slot);
        let prev = slot_ref.seq.fetch_add(1, Ordering::AcqRel);
        assert_eq!(prev & 1, 0, "seq should have been even before injection");
        assert_eq!(
            slot_ref.seq.load(Ordering::Acquire) & 1,
            1,
            "seq is now odd, simulating a writer killed mid-write"
        );

        // Reaper-style release: this must restore even parity and bump
        // generation.
        let gen_before_release = slot_ref.generation.load(Ordering::Acquire);
        reg.release(res.slot, gen_before_release, ReleaseMode::Free)
            .unwrap();
        assert_eq!(
            slot_ref.seq.load(Ordering::Acquire) & 1,
            0,
            "release must leave seq even so the next begin_write is valid"
        );
        let gen_after_release = slot_ref.generation.load(Ordering::Acquire);
        assert_ne!(
            gen_after_release, gen_before_release,
            "release must bump generation to invalidate any stranded writer"
        );

        // The stranded writer must now fail on its next write_sample. In
        // debug, this also verifies that the next reserve does not panic
        // on `begin_write`'s seq-parity assert.
        let err = writer
            .write_sample(SampleWrite {
                sampled_at: Utc::now(),
                cpu_percent: 0.0,
                memory_bytes: 999,
                disk_read_bytes: 0,
                disk_write_bytes: 0,
                net_rx_bytes: 0,
                net_tx_bytes: 0,
            })
            .unwrap_err();
        assert!(matches!(err, MetricsError::GenerationMismatch { .. }));

        // The slot must be cleanly reusable: a fresh reserve+activate+sample
        // cycle should succeed without panicking and without a stuck seqlock.
        let res2 = reg
            .reserve(ReserveSlot {
                sandbox_id: 2,
                name: "y",
                memory_limit_bytes: 1,
            })
            .unwrap();
        assert_eq!(res2.slot, res.slot);
        let writer2 = reg
            .activate_writer(ActivateSlot {
                slot: res2.slot,
                generation: res2.generation,
                run_id: 20,
                pid: 200,
                started_at: Utc::now(),
            })
            .unwrap();
        writer2
            .write_sample(SampleWrite {
                sampled_at: Utc::now(),
                cpu_percent: 1.0,
                memory_bytes: 42,
                disk_read_bytes: 0,
                disk_write_bytes: 0,
                net_rx_bytes: 0,
                net_tx_bytes: 0,
            })
            .unwrap();
        let live = reg
            .get_by_sandbox_id(2)
            .unwrap()
            .expect("recovered slot must produce a coherent live sample");
        assert_eq!(live.run_id, 20);
        assert_eq!(live.memory_bytes, 42);
        cleanup(&name);
    }

    #[test]
    fn reopen_existing_registry_reuses_slots() {
        let name = unique_name("reopen");
        let reg = MetricsRegistry::open_or_create(&name, 4).unwrap();
        let res = reg
            .reserve(ReserveSlot {
                sandbox_id: 11,
                name: "alpine",
                memory_limit_bytes: 1,
            })
            .unwrap();
        let writer = reg
            .activate_writer(ActivateSlot {
                slot: res.slot,
                generation: res.generation,
                run_id: 22,
                pid: 33,
                started_at: Utc::now(),
            })
            .unwrap();
        // Write a sample so the slot is visible to readers (readers skip
        // freshly-activated slots whose `sampled_at_unix_ms` is still 0).
        writer
            .write_sample(SampleWrite {
                sampled_at: Utc::now(),
                cpu_percent: 1.0,
                memory_bytes: 0,
                disk_read_bytes: 0,
                disk_write_bytes: 0,
                net_rx_bytes: 0,
                net_tx_bytes: 0,
            })
            .unwrap();

        let reopened = MetricsRegistry::open(&name).unwrap();
        let found = reopened
            .get_by_sandbox_id(11)
            .unwrap()
            .expect("slot is visible after reopen");
        assert_eq!(found.run_id, 22);
        assert_eq!(found.name, "alpine");
        cleanup(&name);
    }
}

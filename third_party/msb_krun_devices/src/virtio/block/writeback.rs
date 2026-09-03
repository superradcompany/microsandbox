// Copyright 2026 The Microsandbox Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
#[cfg(target_os = "linux")]
use std::fs::File;
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use crossbeam_channel::{bounded, Receiver, Sender, TryRecvError};
use log::warn;

use super::WritebackLimit;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Smallest supported per-device hard writeback budget.
pub(crate) const MINIMUM_WRITEBACK_BUDGET_BYTES: u64 = 128 * 1024 * 1024;

const MINIMUM_RETIREMENT_BYTES: u64 = 32 * 1024 * 1024;
/// Maximum exact disjoint ranges retained in one generation before it is submitted early.
///
/// This bounds both controller metadata and the number of `sync_file_range` calls in one job
/// independently of the caller-supplied hard byte budget. At 4 KiB per page, 8192 extents cover
/// a 32 MiB minimally fragmented retirement while limiting one job's range vector to roughly
/// 128 KiB.
const MAX_EXTENTS_PER_GENERATION: usize = 8192;
const MAX_QUEUED_GENERATIONS: usize = 64;
const WORKER_THREAD_NAME: &str = "virtio-blk-writeback";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirtyRange {
    start: u64,
    end: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ExtentSet {
    bytes: u64,
    ranges: Vec<DirtyRange>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GenerationStatus {
    InFlight,
    Failed,
}

#[derive(Debug)]
struct SharedHealth {
    healthy: AtomicBool,
}

#[derive(Debug)]
struct Generation {
    id: u64,
    extents: ExtentSet,
    status: GenerationStatus,
}

#[derive(Debug)]
struct WritebackJob {
    generation: u64,
    ranges: Vec<DirtyRange>,
}

#[derive(Debug)]
struct WritebackCompletion {
    generation: u64,
    result: Result<(), WritebackFailure>,
}

#[derive(Clone, Debug)]
struct WritebackFailure {
    error: Arc<io::Error>,
}

#[derive(Clone, Debug)]
struct LatchedError {
    kind: io::ErrorKind,
    raw_os_error: Option<i32>,
    message: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingReservation {
    id: u64,
    offset: u64,
    length: u64,
    range: DirtyRange,
}

/// A single write admitted by the writeback budget.
///
/// The token is deliberately owned and does not borrow the controller, so callers can release
/// interior mutability before performing the backing-file mutation.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct WritebackReservation {
    id: u64,
    offset: u64,
    length: u64,
}

/// What the backing mutation did after a [`WritebackReservation`] was issued.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WritebackOutcome {
    /// The mutation succeeded and dirtied exactly this prefix of the reservation.
    Written(u64),
    /// The mutation failed and may have dirtied any part of the reservation.
    Failed,
}

trait WritebackBackend: Send + Sync + 'static {
    fn start_writeback(&self, ranges: &[DirtyRange]) -> io::Result<()>;
    fn wait_writeback(&self, ranges: &[DirtyRange]) -> io::Result<()>;
}

#[cfg(target_os = "linux")]
struct SyncFileRangeBackend {
    file: Arc<File>,
}

/// Immutable inputs used to create a fresh controller when a block device is reactivated.
#[cfg(target_os = "linux")]
#[derive(Clone)]
pub(crate) struct BufferedWritebackConfig {
    file: Arc<File>,
    limit: WritebackLimit,
    page_size: u64,
    health: Arc<SharedHealth>,
}

/// Bounds buffered dirty data and moves range writeback off the virtio block worker.
///
/// The configured value is the single hard budget. Credits represent unique page-aligned extents
/// and are released only after the background worker completes exact range writeback. Hot rewrites
/// remain inside their already-reserved finite window; retirement starts only when a new unique page
/// cannot fit or metadata fragmentation reaches its explicit bound. Guest `FLUSH` remains governed
/// by the existing full backing-image sync, including the data-retrieval metadata required by the
/// host filesystem.
pub(crate) struct BufferedWritebackController {
    limit: WritebackLimit,
    page_size: u64,
    tracked: ExtentSet,
    current_generation: u64,
    current_extents: ExtentSet,
    submitted: VecDeque<Generation>,
    next_reservation: u64,
    pending: Option<PendingReservation>,
    latched_error: Option<LatchedError>,
    health: Arc<SharedHealth>,
    job_sender: Sender<WritebackJob>,
    completion_receiver: Receiver<WritebackCompletion>,
    shutdown_sender: Sender<()>,
    worker: Option<JoinHandle<()>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DirtyRange {
    fn for_write(offset: u64, length: u64, page_size: u64) -> io::Result<Option<Self>> {
        if length == 0 {
            return Ok(None);
        }

        let end = offset.checked_add(length).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "writeback range overflow")
        })?;
        let start = offset - offset % page_size;
        let end = align_up(end, page_size).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "writeback page-aligned range overflow",
            )
        })?;
        Ok(Some(Self { start, end }))
    }

    fn len(self) -> u64 {
        self.end - self.start
    }

    fn intersection_len(self, other: Self) -> u64 {
        self.end
            .min(other.end)
            .saturating_sub(self.start.max(other.start))
    }
}

impl ExtentSet {
    fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    fn additional_bytes(&self, range: DirtyRange) -> u64 {
        let first = self
            .ranges
            .partition_point(|existing| existing.end <= range.start);
        let covered = self.ranges[first..]
            .iter()
            .take_while(|existing| existing.start < range.end)
            .map(|existing| existing.intersection_len(range))
            .sum::<u64>();
        range.len() - covered
    }

    fn extent_count_after_insert(&self, mut range: DirtyRange) -> usize {
        let first = self
            .ranges
            .partition_point(|existing| existing.end < range.start);
        let mut last = first;

        while let Some(existing) = self.ranges.get(last).copied() {
            if existing.start > range.end {
                break;
            }
            range.end = range.end.max(existing.end);
            last += 1;
        }

        self.ranges.len() - (last - first) + 1
    }

    fn insert(&mut self, mut range: DirtyRange) -> u64 {
        let first = self
            .ranges
            .partition_point(|existing| existing.end < range.start);
        let mut last = first;
        let mut removed_bytes = 0;

        while let Some(existing) = self.ranges.get(last).copied() {
            if existing.start > range.end {
                break;
            }
            range.start = range.start.min(existing.start);
            range.end = range.end.max(existing.end);
            removed_bytes += existing.len();
            last += 1;
        }

        let added_bytes = range.len() - removed_bytes;
        self.ranges.splice(first..last, [range]);
        self.bytes += added_bytes;
        added_bytes
    }

    fn remove(&mut self, range: DirtyRange) -> u64 {
        let first = self
            .ranges
            .partition_point(|existing| existing.end <= range.start);
        let mut last = first;
        let mut removed_bytes = 0;
        let mut replacements = Vec::with_capacity(2);

        while let Some(existing) = self.ranges.get(last).copied() {
            if existing.start >= range.end {
                break;
            }

            removed_bytes += existing.intersection_len(range);
            if existing.start < range.start {
                replacements.push(DirtyRange {
                    start: existing.start,
                    end: range.start,
                });
            }
            if existing.end > range.end {
                replacements.push(DirtyRange {
                    start: range.end,
                    end: existing.end,
                });
            }
            last += 1;
        }

        self.ranges.splice(first..last, replacements);
        self.bytes -= removed_bytes;
        removed_bytes
    }
}

impl SharedHealth {
    fn new() -> Self {
        Self {
            healthy: AtomicBool::new(true),
        }
    }

    fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
    }

    fn mark_permanent_failure(&self) {
        self.healthy.store(false, Ordering::Release);
    }

    fn mark_full_sync_success(&self) -> bool {
        // A later success on the same file description does not prove that bytes associated with
        // an earlier reported writeback error were recovered; errseq_t has already advanced.
        self.is_healthy()
    }
}

impl LatchedError {
    fn capture(error: &io::Error) -> Self {
        Self {
            kind: error.kind(),
            raw_os_error: error.raw_os_error(),
            message: error.to_string(),
        }
    }

    fn to_io_error(&self) -> io::Error {
        match self.raw_os_error {
            Some(code) => io::Error::new(self.kind, format!("{} (os error {code})", self.message)),
            None => io::Error::new(self.kind, self.message.clone()),
        }
    }
}

impl WritebackReservation {
    /// Number of bytes the caller may pass to the backing mutation.
    pub(crate) fn len(&self) -> u64 {
        self.length
    }
}

#[cfg(target_os = "linux")]
impl SyncFileRangeBackend {
    fn sync_ranges(&self, ranges: &[DirtyRange], flags: u32) -> io::Result<()> {
        for range in ranges {
            let offset = libc::off64_t::try_from(range.start).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "writeback range offset exceeds sync_file_range limits",
                )
            })?;
            let length = libc::off64_t::try_from(range.len()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "writeback range length exceeds sync_file_range limits",
                )
            })?;

            // Safe: the backend owns a live descriptor for the exact backing inode. Ranges are
            // validated, page-aligned integers and the flags are Linux-defined constants.
            let result =
                unsafe { libc::sync_file_range(self.file.as_raw_fd(), offset, length, flags) };
            if result != 0 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl WritebackBackend for SyncFileRangeBackend {
    fn start_writeback(&self, ranges: &[DirtyRange]) -> io::Result<()> {
        self.sync_ranges(ranges, libc::SYNC_FILE_RANGE_WRITE)
    }

    fn wait_writeback(&self, ranges: &[DirtyRange]) -> io::Result<()> {
        // The earlier WRITE kick submitted the generation's dirty pages. WAIT_AFTER proves that
        // their page-cache writeback completed before their credit is reused, but deliberately
        // does not make this internal containment batch a durability boundary. The Imago backing
        // file was opened separately through /proc/self/fd, so advancing this descriptor's errseq
        // cursor cannot consume an error that the guest-visible full sync still needs to report.
        self.sync_ranges(ranges, libc::SYNC_FILE_RANGE_WAIT_AFTER)
    }
}

#[cfg(target_os = "linux")]
impl BufferedWritebackConfig {
    pub(crate) fn new(file: Arc<File>, limit: WritebackLimit) -> io::Result<Self> {
        let page_size = host_page_size()?;
        validate_policy(limit.maximum_bytes(), page_size)?;
        Ok(Self {
            file,
            limit,
            page_size,
            health: Arc::new(SharedHealth::new()),
        })
    }

    pub(crate) fn controller(&self) -> io::Result<BufferedWritebackController> {
        if !self.health.is_healthy() {
            return Err(io::Error::other(
                "buffered writeback is permanently failed for this backing file",
            ));
        }

        BufferedWritebackController::spawn_with_health(
            Arc::new(SyncFileRangeBackend {
                file: Arc::clone(&self.file),
            }),
            self.limit.clone(),
            self.page_size,
            Arc::clone(&self.health),
        )
    }

    /// Records a successful guest-visible full backing-file sync.
    ///
    /// Returns `false` when a permanent range-kick or controller failure must remain latched.
    pub(crate) fn record_full_sync_success(&self) -> bool {
        self.health.mark_full_sync_success()
    }

    /// Keeps future activations failed closed after a guest-visible full sync fails.
    pub(crate) fn record_full_sync_failure(&self, error: &io::Error) {
        warn!("Buffered block backing-file sync failed permanently: {error}");
        self.health.mark_permanent_failure();
    }
}

impl BufferedWritebackController {
    #[cfg(test)]
    fn spawn(
        backend: Arc<dyn WritebackBackend>,
        hard_budget_bytes: u64,
        page_size: u64,
    ) -> io::Result<Self> {
        Self::spawn_with_health(
            backend,
            WritebackLimit::new(hard_budget_bytes),
            page_size,
            Arc::new(SharedHealth::new()),
        )
    }

    fn spawn_with_health(
        backend: Arc<dyn WritebackBackend>,
        limit: WritebackLimit,
        page_size: u64,
        health: Arc<SharedHealth>,
    ) -> io::Result<Self> {
        let hard_budget_bytes = limit.maximum_bytes();
        validate_policy(hard_budget_bytes, page_size)?;
        let queue_capacity = queue_capacity(hard_budget_bytes);
        let (job_sender, job_receiver) = bounded(queue_capacity);
        let (completion_sender, completion_receiver) = bounded(queue_capacity + 1);
        let (shutdown_sender, shutdown_receiver) = bounded(1);
        let worker = thread::Builder::new()
            .name(WORKER_THREAD_NAME.to_string())
            .spawn(move || {
                run_worker(backend, job_receiver, completion_sender, shutdown_receiver)
            })?;

        Ok(Self {
            limit,
            page_size,
            tracked: ExtentSet::default(),
            current_generation: 0,
            current_extents: ExtentSet::default(),
            submitted: VecDeque::new(),
            next_reservation: 0,
            pending: None,
            latched_error: None,
            health,
            job_sender,
            completion_receiver,
            shutdown_sender,
            worker: Some(worker),
        })
    }

    /// Reserves budget for a prefix of a buffered backing mutation.
    pub(crate) fn plan_write(
        &mut self,
        offset: u64,
        requested_bytes: u64,
    ) -> io::Result<WritebackReservation> {
        if requested_bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot reserve an empty buffered write",
            ));
        }
        offset.checked_add(requested_bytes).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "buffered write range overflow")
        })?;
        if self.pending.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "a buffered write reservation is already pending",
            ));
        }

        loop {
            self.reap_completions_while_latching();
            self.check_error()?;

            let active_budget_bytes = self.active_budget_bytes();
            if self.tracked.bytes > active_budget_bytes {
                // A live decrease cannot revoke bytes already mutated. Retire the current
                // generation and stop admitting even hot rewrites until completed writeback has
                // brought this controller beneath its new target.
                if !self.current_extents.is_empty() {
                    if let Err(error) = self.submit_current_generation() {
                        self.latch_error(&error);
                        return Err(self
                            .latched_error
                            .as_ref()
                            .expect("submission failure must latch an error")
                            .to_io_error());
                    }
                    continue;
                }
                if self.has_in_flight_generations() {
                    self.wait_for_completion()?;
                    continue;
                }
            }

            if let Some((length, range)) =
                self.plannable_prefix(offset, requested_bytes, active_budget_bytes)?
            {
                let id = self.next_reservation;
                self.next_reservation = self
                    .next_reservation
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other("writeback reservation id exhausted"))?;
                self.pending = Some(PendingReservation {
                    id,
                    offset,
                    length,
                    range,
                });
                return Ok(WritebackReservation { id, offset, length });
            }

            if !self.current_extents.is_empty() {
                if let Err(error) = self.submit_current_generation() {
                    self.latch_error(&error);
                    return Err(self
                        .latched_error
                        .as_ref()
                        .expect("submission failure must latch an error")
                        .to_io_error());
                }
                continue;
            }
            if !self.has_in_flight_generations() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "writeback budget cannot admit one page",
                ));
            }
            self.wait_for_completion()?;
        }
    }

    /// Finalizes a reservation after the backing mutation returns.
    pub(crate) fn finish_write(
        &mut self,
        reservation: WritebackReservation,
        outcome: WritebackOutcome,
    ) -> io::Result<()> {
        let pending = self.pending.take().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffered write reservation is not pending",
            )
        })?;
        if pending.id != reservation.id
            || pending.offset != reservation.offset
            || pending.length != reservation.length
        {
            self.pending = Some(pending);
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffered write reservation does not match the pending plan",
            ));
        }

        let committed_length = match outcome {
            WritebackOutcome::Written(length) if length <= pending.length => length,
            WritebackOutcome::Written(_) => {
                self.pending = Some(pending);
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "buffered write exceeded its reservation",
                ));
            }
            WritebackOutcome::Failed => pending.length,
        };

        self.reap_completions_while_latching();
        if committed_length != 0 {
            let range = if committed_length == pending.length {
                pending.range
            } else {
                DirtyRange::for_write(pending.offset, committed_length, self.page_size)?
                    .expect("non-empty committed write must have a range")
            };
            if let Err(error) = self.commit_range(range) {
                self.latch_error(&error);
            }
        }

        self.check_error()
    }

    /// Makes the background worker idle before the guest-visible full sync.
    pub(crate) fn quiesce(&mut self) -> io::Result<()> {
        if self.pending.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "cannot quiesce with a buffered write reservation pending",
            ));
        }

        self.reap_completions_while_latching();
        if !self.current_extents.is_empty() {
            if let Err(error) = self.submit_current_generation() {
                self.latch_error(&error);
            }
        }
        while self.has_in_flight_generations() {
            if let Err(error) = self.wait_for_completion_while_latching() {
                self.mark_in_flight_failed();
                debug_assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
            }
        }
        self.check_error()
    }

    /// Resets accounting after the existing full backing-image sync succeeds.
    pub(crate) fn reset_after_flush(&mut self) -> bool {
        if self.pending.is_some() || self.has_in_flight_generations() {
            let error = io::Error::other(
                "cannot reset writeback accounting before the controller is quiescent",
            );
            self.latch_error(&error);
            return false;
        }
        self.tracked = ExtentSet::default();
        self.current_extents = ExtentSet::default();
        self.submitted.clear();
        if self.latched_error.is_some() {
            false
        } else {
            self.health.mark_full_sync_success()
        }
    }

    fn plannable_prefix(
        &self,
        offset: u64,
        requested_bytes: u64,
        active_budget_bytes: u64,
    ) -> io::Result<Option<(u64, DirtyRange)>> {
        let first_page = DirtyRange::for_write(offset, 1, self.page_size)?
            .expect("non-empty requested write must have a range");
        if self.current_extents.extent_count_after_insert(first_page) > MAX_EXTENTS_PER_GENERATION {
            // Extending a range from a fixed start can only merge more existing extents. Refuse
            // the first new disjoint page so the caller submits this underfilled generation.
            return Ok(None);
        }

        let capped_length = requested_bytes.min(active_budget_bytes);
        let mut low = 0;
        let mut high = capped_length;

        while low < high {
            let candidate = low + (high - low).div_ceil(2);
            let range = DirtyRange::for_write(offset, candidate, self.page_size)?
                .expect("positive candidate must have a range");
            let fits_generation = self
                .current_extents
                .bytes
                .checked_add(self.current_extents.additional_bytes(range))
                .is_some_and(|bytes| bytes <= active_budget_bytes);
            let fits_hard = self
                .tracked
                .bytes
                .checked_add(self.tracked.additional_bytes(range))
                .is_some_and(|bytes| bytes <= active_budget_bytes);
            if fits_generation && fits_hard {
                low = candidate;
            } else {
                high = candidate - 1;
            }
        }

        if low == 0 {
            Ok(None)
        } else {
            let range = DirtyRange::for_write(offset, low, self.page_size)?
                .expect("positive planned write must have a range");
            Ok(Some((low, range)))
        }
    }

    fn commit_range(&mut self, range: DirtyRange) -> io::Result<()> {
        let projected_generation = self
            .current_extents
            .bytes
            .checked_add(self.current_extents.additional_bytes(range));
        let projected_hard = self
            .tracked
            .bytes
            .checked_add(self.tracked.additional_bytes(range));
        if projected_generation.is_none_or(|bytes| bytes > self.limit.maximum_bytes())
            || projected_hard.is_none_or(|bytes| bytes > self.limit.maximum_bytes())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "completed buffered write exceeded its reservation",
            ));
        }

        // Keep submitted extents immutable and bounded. Completion subtracts all newer ownership
        // before releasing credits, so an older job can never release a rewritten page.
        self.current_extents.insert(range);
        self.tracked.insert(range);
        Ok(())
    }

    fn submit_current_generation(&mut self) -> io::Result<()> {
        if self.current_extents.is_empty() {
            return Ok(());
        }

        let next_generation = self
            .current_generation
            .checked_add(1)
            .ok_or_else(|| io::Error::other("writeback generation id exhausted"))?;
        let job = WritebackJob {
            generation: self.current_generation,
            ranges: self.current_extents.ranges.clone(),
        };
        self.job_sender.send(job).map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "writeback worker stopped accepting jobs",
            )
        })?;

        self.submitted.push_back(Generation {
            id: self.current_generation,
            extents: std::mem::take(&mut self.current_extents),
            status: GenerationStatus::InFlight,
        });
        self.current_generation = next_generation;
        Ok(())
    }

    fn reap_completions(&mut self) -> io::Result<()> {
        loop {
            match self.completion_receiver.try_recv() {
                Ok(completion) => self.apply_completion(completion)?,
                Err(TryRecvError::Empty) => return Ok(()),
                Err(TryRecvError::Disconnected) if self.has_in_flight_generations() => {
                    let error = io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "writeback worker completion channel disconnected",
                    );
                    self.latch_error(&error);
                    return Err(error);
                }
                Err(TryRecvError::Disconnected) => return Ok(()),
            }
        }
    }

    fn reap_completions_while_latching(&mut self) {
        let _ = self.reap_completions();
    }

    fn wait_for_completion(&mut self) -> io::Result<()> {
        let completion = match self.completion_receiver.recv() {
            Ok(completion) => completion,
            Err(_) => {
                let error = io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "writeback worker completion channel disconnected",
                );
                self.latch_error(&error);
                return Err(error);
            }
        };
        // Receiving any completion is forward progress. A range error is already latched by
        // apply_completion, but quiesce must continue waiting for the remaining queued jobs.
        let _ = self.apply_completion(completion);
        Ok(())
    }

    fn wait_for_completion_while_latching(&mut self) -> io::Result<()> {
        self.wait_for_completion()
    }

    fn apply_completion(&mut self, completion: WritebackCompletion) -> io::Result<()> {
        let Some(position) = self
            .submitted
            .iter()
            .position(|generation| generation.id == completion.generation)
        else {
            let error = io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "writeback worker completed unknown generation {}",
                    completion.generation
                ),
            );
            self.latch_error(&error);
            return Err(error);
        };
        if self.submitted[position].status != GenerationStatus::InFlight {
            let error = io::Error::new(
                io::ErrorKind::InvalidData,
                "writeback worker completed a generation more than once",
            );
            self.latch_error(&error);
            return Err(error);
        }

        match completion.result {
            Ok(()) => {
                let generation = self
                    .submitted
                    .remove(position)
                    .expect("located generation must still exist");
                let mut releasable = generation.extents;
                for newer_generation in &self.submitted {
                    for range in &newer_generation.extents.ranges {
                        releasable.remove(*range);
                    }
                }
                for range in &self.current_extents.ranges {
                    releasable.remove(*range);
                }
                for range in releasable.ranges {
                    self.tracked.remove(range);
                }
                Ok(())
            }
            Err(failure) => {
                self.submitted[position].status = GenerationStatus::Failed;
                let error = failure.error;
                let error = io::Error::new(
                    error.kind(),
                    format!(
                        "writeback generation {} failed: {error}",
                        completion.generation
                    ),
                );
                self.latch_error(&error);
                Err(error)
            }
        }
    }

    fn has_in_flight_generations(&self) -> bool {
        self.submitted
            .iter()
            .any(|generation| generation.status == GenerationStatus::InFlight)
    }

    fn mark_in_flight_failed(&mut self) {
        for generation in &mut self.submitted {
            if generation.status == GenerationStatus::InFlight {
                generation.status = GenerationStatus::Failed;
            }
        }
    }

    fn latch_error(&mut self, error: &io::Error) {
        // The config retains this state after the controller is dropped, so reset/reactivation
        // cannot erase a reported writeback error after its errseq_t cursor has advanced.
        self.health.mark_permanent_failure();
        if self.latched_error.is_none() {
            warn!("Buffered block writeback failed closed: {error}");
            self.latched_error = Some(LatchedError::capture(error));
        }
    }

    fn check_error(&self) -> io::Result<()> {
        match &self.latched_error {
            Some(error) => Err(error.to_io_error()),
            None if !self.health.is_healthy() => Err(io::Error::other(
                "buffered writeback is permanently failed for this backing file",
            )),
            None => Ok(()),
        }
    }

    fn active_budget_bytes(&self) -> u64 {
        // An extremely oversubscribed host still leaves every controller one page of progress.
        // The configured maximum is page-aligned by validation, so this cannot exceed it.
        self.limit.target_bytes().max(self.page_size)
    }
}

impl Drop for BufferedWritebackController {
    fn drop(&mut self) {
        if let Err(error) = self.quiesce() {
            warn!("Buffered block writeback did not quiesce during drop: {error}");
        }
        let _ = self.shutdown_sender.try_send(());
        if let Some(worker) = self.worker.take() {
            if worker.join().is_err() {
                warn!("Buffered block writeback worker panicked");
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn align_down(value: u64, alignment: u64) -> u64 {
    value - value % alignment
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    value
        .checked_add(alignment - 1)
        .map(|rounded| align_down(rounded, alignment))
}

#[cfg(target_os = "linux")]
fn host_page_size() -> io::Result<u64> {
    // Safe: sysconf has no pointer arguments or caller-owned memory requirements.
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(page_size as u64)
    }
}

fn validate_policy(hard_budget_bytes: u64, page_size: u64) -> io::Result<()> {
    if !page_size.is_power_of_two() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "writeback page size must be a non-zero power of two",
        ));
    }
    if page_size > MINIMUM_WRITEBACK_BUDGET_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "writeback page size exceeds the minimum hard budget",
        ));
    }
    if hard_budget_bytes < MINIMUM_WRITEBACK_BUDGET_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "writeback hard budget must be at least {MINIMUM_WRITEBACK_BUDGET_BYTES} bytes"
            ),
        ));
    }
    Ok(())
}

fn queue_capacity(hard_budget_bytes: u64) -> usize {
    let generations = hard_budget_bytes.div_ceil(MINIMUM_RETIREMENT_BYTES);
    usize::try_from(generations)
        .unwrap_or(MAX_QUEUED_GENERATIONS)
        .clamp(1, MAX_QUEUED_GENERATIONS)
}

fn run_worker(
    backend: Arc<dyn WritebackBackend>,
    job_receiver: Receiver<WritebackJob>,
    completion_sender: Sender<WritebackCompletion>,
    shutdown_receiver: Receiver<()>,
) {
    // The completion channel is one slot larger than the job channel. Limit one coalesced group to
    // that same size so the worker can always publish every result without deadlocking against a
    // producer blocked on the bounded job queue.
    let max_jobs_per_group = job_receiver
        .capacity()
        .unwrap_or(MAX_QUEUED_GENERATIONS)
        .saturating_add(1);

    loop {
        let first_job = crossbeam_channel::select_biased! {
            recv(shutdown_receiver) -> _ => return,
            recv(job_receiver) -> job => {
                let Ok(job) = job else {
                    return;
                };
                job
            }
        };

        let mut jobs = Vec::with_capacity(max_jobs_per_group);
        let mut next_job = first_job;
        let mut first_error = None;
        let mut jobs_disconnected = false;

        loop {
            if let Err(error) = backend.start_writeback(&next_job.ranges) {
                first_error.get_or_insert((next_job.generation, "start", error));
            }
            jobs.push(next_job);

            if jobs.len() == max_jobs_per_group {
                break;
            }
            match job_receiver.try_recv() {
                Ok(job) => next_job = job,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    jobs_disconnected = true;
                    break;
                }
            }
        }

        // Kick every queued generation before waiting so the host block layer can keep multiple
        // ranges in flight. Completion waits return containment credit only after the associated
        // page-cache writeback has finished; durability metadata remains the responsibility of the
        // existing guest-visible full sync.
        for job in &jobs {
            if let Err(error) = backend.wait_writeback(&job.ranges) {
                first_error.get_or_insert((job.generation, "completion", error));
            }
        }
        let group_failure = first_error.map(|(generation, operation, error)| {
            warn!("Range writeback {operation} for generation {generation} failed closed: {error}");
            WritebackFailure {
                error: Arc::new(error),
            }
        });

        for job in jobs {
            let completion = WritebackCompletion {
                generation: job.generation,
                result: match &group_failure {
                    None => Ok(()),
                    Some(failure) => Err(failure.clone()),
                },
            };
            crossbeam_channel::select_biased! {
                recv(shutdown_receiver) -> _ => return,
                send(completion_sender, completion) -> result => {
                    if result.is_err() {
                        return;
                    }
                }
            }
        }

        if jobs_disconnected {
            return;
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::FileExt;
    use std::sync::{Condvar, Mutex};
    use std::time::Duration;

    #[cfg(target_os = "linux")]
    use utils::tempfile::TempFile;

    use super::*;

    const TEST_PAGE_SIZE: u64 = 4096;

    #[derive(Default)]
    struct FakeBackend {
        start_calls: Mutex<Vec<Vec<DirtyRange>>>,
        wait_calls: Mutex<Vec<Vec<DirtyRange>>>,
        wait_failures: Mutex<VecDeque<io::ErrorKind>>,
    }

    impl WritebackBackend for FakeBackend {
        fn start_writeback(&self, ranges: &[DirtyRange]) -> io::Result<()> {
            self.start_calls.lock().unwrap().push(ranges.to_vec());
            Ok(())
        }

        fn wait_writeback(&self, ranges: &[DirtyRange]) -> io::Result<()> {
            self.wait_calls.lock().unwrap().push(ranges.to_vec());
            match self.wait_failures.lock().unwrap().pop_front() {
                Some(kind) => Err(io::Error::new(kind, "injected completion-wait failure")),
                None => Ok(()),
            }
        }
    }

    impl FakeBackend {
        fn fail_next_wait(&self, kind: io::ErrorKind) {
            self.wait_failures.lock().unwrap().push_back(kind);
        }

        fn wait_calls(&self) -> usize {
            self.wait_calls.lock().unwrap().len()
        }
    }

    #[derive(Default)]
    struct GatedBackend {
        changed: Condvar,
        state: Mutex<GatedState>,
    }

    #[derive(Default)]
    struct GatedState {
        calls: Vec<Vec<DirtyRange>>,
        permits: usize,
    }

    impl WritebackBackend for GatedBackend {
        fn start_writeback(&self, ranges: &[DirtyRange]) -> io::Result<()> {
            let mut state = self.state.lock().unwrap();
            state.calls.push(ranges.to_vec());
            self.changed.notify_all();
            while state.permits == 0 {
                state = self.changed.wait(state).unwrap();
            }
            state.permits -= 1;
            Ok(())
        }

        fn wait_writeback(&self, _ranges: &[DirtyRange]) -> io::Result<()> {
            Ok(())
        }
    }

    impl GatedBackend {
        fn allow(&self, jobs: usize) {
            let mut state = self.state.lock().unwrap();
            state.permits += jobs;
            self.changed.notify_all();
        }

        fn wait_for_calls(&self, calls: usize) {
            let mut state = self.state.lock().unwrap();
            while state.calls.len() < calls {
                let (new_state, timeout) = self
                    .changed
                    .wait_timeout(state, Duration::from_secs(5))
                    .unwrap();
                assert!(
                    !timeout.timed_out(),
                    "writeback worker did not receive a job"
                );
                state = new_state;
            }
        }

        fn calls(&self) -> Vec<Vec<DirtyRange>> {
            self.state.lock().unwrap().calls.clone()
        }
    }

    #[derive(Default)]
    struct CompletionGatedBackend {
        changed: Condvar,
        state: Mutex<CompletionGatedState>,
    }

    #[derive(Default)]
    struct CompletionGatedState {
        calls: Vec<Vec<DirtyRange>>,
        writeback_permits: usize,
        writeback_failures: VecDeque<io::ErrorKind>,
        wait_calls: usize,
        wait_permits: usize,
        wait_failures: VecDeque<io::ErrorKind>,
    }

    impl WritebackBackend for CompletionGatedBackend {
        fn start_writeback(&self, ranges: &[DirtyRange]) -> io::Result<()> {
            let mut state = self.state.lock().unwrap();
            state.calls.push(ranges.to_vec());
            self.changed.notify_all();
            while state.writeback_permits == 0 {
                state = self.changed.wait(state).unwrap();
            }
            state.writeback_permits -= 1;
            match state.writeback_failures.pop_front() {
                Some(kind) => Err(io::Error::new(kind, "injected writeback failure")),
                None => Ok(()),
            }
        }

        fn wait_writeback(&self, _ranges: &[DirtyRange]) -> io::Result<()> {
            let mut state = self.state.lock().unwrap();
            state.wait_calls += 1;
            self.changed.notify_all();
            while state.wait_permits == 0 {
                state = self.changed.wait(state).unwrap();
            }
            state.wait_permits -= 1;
            match state.wait_failures.pop_front() {
                Some(kind) => Err(io::Error::new(kind, "injected completion-wait failure")),
                None => Ok(()),
            }
        }
    }

    impl CompletionGatedBackend {
        fn allow_writebacks(&self, jobs: usize) {
            let mut state = self.state.lock().unwrap();
            state.writeback_permits += jobs;
            self.changed.notify_all();
        }

        fn allow_waits(&self, waits: usize) {
            let mut state = self.state.lock().unwrap();
            state.wait_permits += waits;
            self.changed.notify_all();
        }

        fn fail_next_wait(&self, kind: io::ErrorKind) {
            self.state.lock().unwrap().wait_failures.push_back(kind);
        }

        fn fail_next_writeback(&self, kind: io::ErrorKind) {
            self.state
                .lock()
                .unwrap()
                .writeback_failures
                .push_back(kind);
        }

        fn wait_for_writebacks(&self, calls: usize) {
            let mut state = self.state.lock().unwrap();
            while state.calls.len() < calls {
                let (new_state, timeout) = self
                    .changed
                    .wait_timeout(state, Duration::from_secs(5))
                    .unwrap();
                assert!(
                    !timeout.timed_out(),
                    "writeback worker did not process the expected ranges"
                );
                state = new_state;
            }
        }

        fn wait_for_waits(&self, calls: usize) {
            let mut state = self.state.lock().unwrap();
            while state.wait_calls < calls {
                let (new_state, timeout) = self
                    .changed
                    .wait_timeout(state, Duration::from_secs(5))
                    .unwrap();
                assert!(
                    !timeout.timed_out(),
                    "writeback worker did not reach the expected completion wait"
                );
                state = new_state;
            }
        }

        fn calls(&self) -> Vec<Vec<DirtyRange>> {
            self.state.lock().unwrap().calls.clone()
        }

        fn wait_calls(&self) -> usize {
            self.state.lock().unwrap().wait_calls
        }
    }

    struct PanicBackend;

    impl WritebackBackend for PanicBackend {
        fn start_writeback(&self, _ranges: &[DirtyRange]) -> io::Result<()> {
            panic!("injected writeback worker panic");
        }

        fn wait_writeback(&self, _ranges: &[DirtyRange]) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn queue_capacity_scales_with_the_finite_hard_window() {
        assert_eq!(queue_capacity(MINIMUM_WRITEBACK_BUDGET_BYTES), 4);
        assert_eq!(queue_capacity(512 * 1024 * 1024), 16);
        assert_eq!(queue_capacity(8 * 1024 * 1024 * 1024), 64);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_backend_starts_and_waits_for_regular_file_writeback() {
        let backing = TempFile::new().unwrap();
        backing.as_file().set_len(TEST_PAGE_SIZE * 2).unwrap();
        backing
            .as_file()
            .write_all_at(&vec![0xa5; TEST_PAGE_SIZE as usize], 0)
            .unwrap();

        let backend = SyncFileRangeBackend {
            file: Arc::new(backing.as_file().try_clone().unwrap()),
        };
        backend
            .start_writeback(&[DirtyRange {
                start: 0,
                end: TEST_PAGE_SIZE,
            }])
            .unwrap();
        backend
            .wait_writeback(&[DirtyRange {
                start: 0,
                end: TEST_PAGE_SIZE,
            }])
            .unwrap();
    }

    #[test]
    fn extent_set_preserves_holes_and_unique_bytes() {
        let mut set = ExtentSet::default();
        set.insert(DirtyRange {
            start: 0,
            end: 4096,
        });
        set.insert(DirtyRange {
            start: 8192,
            end: 12288,
        });
        set.insert(DirtyRange {
            start: 0,
            end: 4096,
        });

        assert_eq!(set.bytes, 8192);
        assert_eq!(set.ranges.len(), 2);
    }

    #[test]
    fn extent_removal_splits_without_collapsing_the_gap() {
        let mut set = ExtentSet::default();
        set.insert(DirtyRange {
            start: 0,
            end: 16384,
        });
        assert_eq!(
            set.remove(DirtyRange {
                start: 4096,
                end: 12288
            }),
            8192
        );
        assert_eq!(
            set.ranges,
            vec![
                DirtyRange {
                    start: 0,
                    end: 4096
                },
                DirtyRange {
                    start: 12288,
                    end: 16384
                },
            ]
        );
    }

    #[test]
    fn extent_set_matches_a_page_bitmap_under_mixed_updates() {
        const PAGE_COUNT: usize = 31;

        let mut set = ExtentSet::default();
        let mut pages = [false; PAGE_COUNT];
        let mut seed = 0x1234_5678_u64;

        for _ in 0..1000 {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let start = (seed as usize) % PAGE_COUNT;
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let end = (start + 1 + (seed as usize % (PAGE_COUNT - start))).min(PAGE_COUNT);
            let range = DirtyRange {
                start: start as u64 * TEST_PAGE_SIZE,
                end: end as u64 * TEST_PAGE_SIZE,
            };

            if seed & 1 == 0 {
                set.insert(range);
                pages[start..end].fill(true);
            } else {
                set.remove(range);
                pages[start..end].fill(false);
            }

            let expected_bytes =
                pages.iter().filter(|dirty| **dirty).count() as u64 * TEST_PAGE_SIZE;
            assert_eq!(set.bytes, expected_bytes);
            assert_eq!(set.ranges, bitmap_ranges(&pages));
            assert!(set.ranges.len() as u64 <= set.bytes / TEST_PAGE_SIZE);
        }
    }

    #[test]
    fn planner_caps_a_large_request_at_the_hard_budget() {
        let backend = Arc::new(FakeBackend::default());
        let mut controller = BufferedWritebackController::spawn(
            backend,
            MINIMUM_WRITEBACK_BUDGET_BYTES,
            TEST_PAGE_SIZE,
        )
        .unwrap();
        let reservation = controller
            .plan_write(0, MINIMUM_WRITEBACK_BUDGET_BYTES)
            .unwrap();
        assert_eq!(reservation.len(), MINIMUM_WRITEBACK_BUDGET_BYTES);
        controller
            .finish_write(
                reservation,
                WritebackOutcome::Written(MINIMUM_WRITEBACK_BUDGET_BYTES),
            )
            .unwrap();
    }

    #[test]
    fn planner_accounts_for_page_alignment_at_the_hard_edge() {
        let backend = Arc::new(FakeBackend::default());
        let mut controller = BufferedWritebackController::spawn(
            backend,
            MINIMUM_WRITEBACK_BUDGET_BYTES,
            TEST_PAGE_SIZE,
        )
        .unwrap();
        let reservation = controller
            .plan_write(512, MINIMUM_WRITEBACK_BUDGET_BYTES)
            .unwrap();
        assert_eq!(reservation.len(), MINIMUM_WRITEBACK_BUDGET_BYTES - 512);
        controller
            .finish_write(
                reservation,
                WritebackOutcome::Written(MINIMUM_WRITEBACK_BUDGET_BYTES - 512),
            )
            .unwrap();
        assert_eq!(controller.tracked.bytes, MINIMUM_WRITEBACK_BUDGET_BYTES);
    }

    #[test]
    fn hard_pressure_starts_retirement_but_hot_rewrites_do_not() {
        let backend = Arc::new(FakeBackend::default());
        let mut controller = BufferedWritebackController::spawn(
            backend.clone(),
            MINIMUM_WRITEBACK_BUDGET_BYTES,
            TEST_PAGE_SIZE,
        )
        .unwrap();

        let initial = controller
            .plan_write(0, MINIMUM_WRITEBACK_BUDGET_BYTES)
            .unwrap();
        controller
            .finish_write(
                initial,
                WritebackOutcome::Written(MINIMUM_WRITEBACK_BUDGET_BYTES),
            )
            .unwrap();
        assert!(backend.start_calls.lock().unwrap().is_empty());

        let rewrite = controller.plan_write(0, TEST_PAGE_SIZE).unwrap();
        controller
            .finish_write(rewrite, WritebackOutcome::Written(TEST_PAGE_SIZE))
            .unwrap();
        assert!(backend.start_calls.lock().unwrap().is_empty());
        assert_eq!(controller.tracked.bytes, MINIMUM_WRITEBACK_BUDGET_BYTES);

        let next = controller
            .plan_write(MINIMUM_WRITEBACK_BUDGET_BYTES, TEST_PAGE_SIZE)
            .unwrap();
        controller
            .finish_write(next, WritebackOutcome::Written(TEST_PAGE_SIZE))
            .unwrap();
        controller.quiesce().unwrap();

        assert_eq!(backend.start_calls.lock().unwrap().len(), 2);
        assert_eq!(controller.tracked.bytes, 0);
    }

    #[test]
    fn live_target_caps_new_reservations_and_can_grow_again() {
        let backend = Arc::new(FakeBackend::default());
        let limit = WritebackLimit::new(MINIMUM_WRITEBACK_BUDGET_BYTES);
        limit.set_target_bytes(TEST_PAGE_SIZE * 2).unwrap();
        let mut controller = BufferedWritebackController::spawn_with_health(
            backend,
            limit.clone(),
            TEST_PAGE_SIZE,
            Arc::new(SharedHealth::new()),
        )
        .unwrap();

        let reservation = controller
            .plan_write(0, MINIMUM_WRITEBACK_BUDGET_BYTES)
            .unwrap();
        assert_eq!(reservation.len(), TEST_PAGE_SIZE * 2);
        controller
            .finish_write(reservation, WritebackOutcome::Written(TEST_PAGE_SIZE * 2))
            .unwrap();

        limit.set_target_bytes(TEST_PAGE_SIZE * 3).unwrap();
        let reservation = controller
            .plan_write(TEST_PAGE_SIZE * 2, TEST_PAGE_SIZE * 4)
            .unwrap();
        assert_eq!(reservation.len(), TEST_PAGE_SIZE);
        controller
            .finish_write(reservation, WritebackOutcome::Written(TEST_PAGE_SIZE))
            .unwrap();
    }

    #[test]
    fn live_shrink_retires_existing_bytes_before_admitting_hot_rewrite() {
        let backend = Arc::new(FakeBackend::default());
        let limit = WritebackLimit::new(MINIMUM_WRITEBACK_BUDGET_BYTES);
        let mut controller = BufferedWritebackController::spawn_with_health(
            backend.clone(),
            limit.clone(),
            TEST_PAGE_SIZE,
            Arc::new(SharedHealth::new()),
        )
        .unwrap();

        let reservation = controller.plan_write(0, TEST_PAGE_SIZE * 3).unwrap();
        controller
            .finish_write(reservation, WritebackOutcome::Written(TEST_PAGE_SIZE * 3))
            .unwrap();
        limit.set_target_bytes(TEST_PAGE_SIZE).unwrap();

        let rewrite = controller.plan_write(0, TEST_PAGE_SIZE).unwrap();
        assert_eq!(backend.start_calls.lock().unwrap().len(), 1);
        assert!(controller.tracked.bytes <= TEST_PAGE_SIZE);
        controller
            .finish_write(rewrite, WritebackOutcome::Written(TEST_PAGE_SIZE))
            .unwrap();
    }

    #[test]
    fn live_shrink_does_not_invalidate_an_existing_reservation() {
        let backend = Arc::new(FakeBackend::default());
        let limit = WritebackLimit::new(MINIMUM_WRITEBACK_BUDGET_BYTES);
        let mut controller = BufferedWritebackController::spawn_with_health(
            backend,
            limit.clone(),
            TEST_PAGE_SIZE,
            Arc::new(SharedHealth::new()),
        )
        .unwrap();

        let reservation = controller.plan_write(0, TEST_PAGE_SIZE * 2).unwrap();
        limit.set_target_bytes(TEST_PAGE_SIZE).unwrap();
        controller
            .finish_write(reservation, WritebackOutcome::Written(TEST_PAGE_SIZE * 2))
            .unwrap();
        assert_eq!(controller.tracked.bytes, TEST_PAGE_SIZE * 2);
    }

    #[test]
    fn planner_allows_only_one_pending_reservation() {
        let backend = Arc::new(FakeBackend::default());
        let mut controller = BufferedWritebackController::spawn(
            backend,
            MINIMUM_WRITEBACK_BUDGET_BYTES,
            TEST_PAGE_SIZE,
        )
        .unwrap();
        let reservation = controller.plan_write(0, 512).unwrap();
        assert_eq!(
            controller.plan_write(512, 512).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        controller
            .finish_write(reservation, WritebackOutcome::Failed)
            .unwrap();
    }

    #[test]
    fn planner_submits_underfilled_generation_at_extent_limit() {
        let backend = Arc::new(GatedBackend::default());
        let mut controller = BufferedWritebackController::spawn(
            backend.clone(),
            MINIMUM_WRITEBACK_BUDGET_BYTES * 2,
            TEST_PAGE_SIZE,
        )
        .unwrap();

        // Populate a maximally fragmented generation without allocating or dirtying a large file.
        for page in 0..MAX_EXTENTS_PER_GENERATION as u64 {
            let range = DirtyRange {
                start: page * TEST_PAGE_SIZE * 2,
                end: page * TEST_PAGE_SIZE * 2 + TEST_PAGE_SIZE,
            };
            controller.current_extents.insert(range);
            controller.tracked.insert(range);
        }
        assert!(controller.current_extents.bytes < controller.limit.maximum_bytes());

        let next_offset = MAX_EXTENTS_PER_GENERATION as u64 * TEST_PAGE_SIZE * 2;
        let reservation = controller.plan_write(next_offset, 512).unwrap();
        backend.wait_for_calls(1);
        controller
            .finish_write(reservation, WritebackOutcome::Written(512))
            .unwrap();

        backend.allow(2);
        controller.quiesce().unwrap();
        let calls = backend.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].len(), MAX_EXTENTS_PER_GENERATION);
        assert_eq!(calls[1].len(), 1);
    }

    #[test]
    fn failed_mutation_conservatively_commits_the_full_reservation() {
        let backend = Arc::new(FakeBackend::default());
        let mut controller = BufferedWritebackController::spawn(
            backend,
            MINIMUM_WRITEBACK_BUDGET_BYTES,
            TEST_PAGE_SIZE,
        )
        .unwrap();
        let reservation = controller.plan_write(512, 512).unwrap();
        controller
            .finish_write(reservation, WritebackOutcome::Failed)
            .unwrap();
        assert_eq!(controller.tracked.bytes, TEST_PAGE_SIZE);
    }

    #[test]
    fn successful_partial_write_commits_only_the_actual_prefix() {
        let backend = Arc::new(FakeBackend::default());
        let mut controller = BufferedWritebackController::spawn(
            backend,
            MINIMUM_WRITEBACK_BUDGET_BYTES,
            TEST_PAGE_SIZE,
        )
        .unwrap();
        let reservation = controller.plan_write(0, 8192).unwrap();
        controller
            .finish_write(reservation, WritebackOutcome::Written(4096))
            .unwrap();
        assert_eq!(controller.tracked.bytes, 4096);
    }

    #[test]
    fn quiesce_sends_exact_disjoint_ranges() {
        let backend = Arc::new(FakeBackend::default());
        let mut controller = BufferedWritebackController::spawn(
            backend.clone(),
            MINIMUM_WRITEBACK_BUDGET_BYTES,
            TEST_PAGE_SIZE,
        )
        .unwrap();
        for offset in [0, 8192] {
            let reservation = controller.plan_write(offset, 512).unwrap();
            controller
                .finish_write(reservation, WritebackOutcome::Written(512))
                .unwrap();
        }
        controller.quiesce().unwrap();

        assert_eq!(
            backend.start_calls.lock().unwrap().as_slice(),
            &[vec![
                DirtyRange {
                    start: 0,
                    end: 4096
                },
                DirtyRange {
                    start: 8192,
                    end: 12288
                },
            ]]
        );
        assert_eq!(controller.tracked.bytes, 0);
        assert_eq!(backend.wait_calls(), 1);
    }

    #[test]
    fn queued_generations_wait_for_each_range_before_releasing_credit() {
        let backend = Arc::new(CompletionGatedBackend::default());
        let mut controller = BufferedWritebackController::spawn(
            backend.clone(),
            MINIMUM_WRITEBACK_BUDGET_BYTES,
            TEST_PAGE_SIZE,
        )
        .unwrap();

        submit_small_generation(&mut controller, 0);
        backend.wait_for_writebacks(1);
        submit_small_generation(&mut controller, TEST_PAGE_SIZE * 2);

        backend.allow_writebacks(2);
        backend.wait_for_writebacks(2);
        backend.wait_for_waits(1);

        assert_eq!(backend.wait_calls(), 1);
        assert_eq!(backend.calls().len(), 2);
        assert_eq!(controller.tracked.bytes, TEST_PAGE_SIZE * 2);
        assert!(controller
            .submitted
            .iter()
            .all(|generation| generation.status == GenerationStatus::InFlight));
        assert_eq!(
            controller.completion_receiver.try_recv().unwrap_err(),
            TryRecvError::Empty
        );

        backend.allow_waits(2);
        controller.quiesce().unwrap();
        assert_eq!(backend.wait_calls(), 2);
        assert_eq!(controller.tracked.bytes, 0);
        assert!(controller.submitted.is_empty());
        assert!(controller.health.is_healthy());
    }

    #[test]
    fn completion_failure_fails_every_coalesced_generation() {
        let backend = Arc::new(CompletionGatedBackend::default());
        backend.fail_next_wait(io::ErrorKind::Other);
        let mut controller = BufferedWritebackController::spawn(
            backend.clone(),
            MINIMUM_WRITEBACK_BUDGET_BYTES,
            TEST_PAGE_SIZE,
        )
        .unwrap();

        submit_small_generation(&mut controller, 0);
        backend.wait_for_writebacks(1);
        submit_small_generation(&mut controller, TEST_PAGE_SIZE * 2);

        backend.allow_writebacks(2);
        backend.wait_for_writebacks(2);
        backend.wait_for_waits(1);
        backend.allow_waits(2);

        assert_eq!(
            controller.quiesce().unwrap_err().kind(),
            io::ErrorKind::Other
        );
        assert_eq!(controller.tracked.bytes, TEST_PAGE_SIZE * 2);
        assert_eq!(controller.submitted.len(), 2);
        assert!(controller
            .submitted
            .iter()
            .all(|generation| generation.status == GenerationStatus::Failed));
        assert!(controller.latched_error.is_some());
        assert!(!controller.health.is_healthy());
    }

    #[test]
    fn successful_completion_wait_does_not_hide_a_range_kick_failure() {
        let backend = Arc::new(CompletionGatedBackend::default());
        backend.fail_next_writeback(io::ErrorKind::Other);
        let mut controller = BufferedWritebackController::spawn(
            backend.clone(),
            MINIMUM_WRITEBACK_BUDGET_BYTES,
            TEST_PAGE_SIZE,
        )
        .unwrap();

        submit_small_generation(&mut controller, 0);
        backend.wait_for_writebacks(1);
        submit_small_generation(&mut controller, TEST_PAGE_SIZE * 2);

        backend.allow_writebacks(2);
        backend.wait_for_writebacks(2);
        backend.wait_for_waits(1);
        assert_eq!(controller.tracked.bytes, TEST_PAGE_SIZE * 2);
        assert_eq!(
            controller.completion_receiver.try_recv().unwrap_err(),
            TryRecvError::Empty
        );
        backend.allow_waits(2);

        assert_eq!(
            controller.quiesce().unwrap_err().kind(),
            io::ErrorKind::Other
        );

        assert_eq!(backend.wait_calls(), 2);
        assert_eq!(controller.tracked.bytes, TEST_PAGE_SIZE * 2);
        assert_eq!(controller.submitted.len(), 2);
        assert!(controller
            .submitted
            .iter()
            .all(|generation| generation.status == GenerationStatus::Failed));
        assert!(controller.latched_error.is_some());
        assert!(!controller.health.is_healthy());

        // A later full sync cannot prove a failed range-kick path safe.
        assert!(!controller.reset_after_flush());
        assert!(controller.latched_error.is_some());
        assert!(!controller.health.is_healthy());
    }

    #[test]
    fn newer_generation_keeps_rewritten_page_charged() {
        let backend = Arc::new(GatedBackend::default());
        let mut controller = BufferedWritebackController::spawn(
            backend.clone(),
            MINIMUM_WRITEBACK_BUDGET_BYTES,
            TEST_PAGE_SIZE,
        )
        .unwrap();

        let first = controller.plan_write(0, MINIMUM_RETIREMENT_BYTES).unwrap();
        controller
            .finish_write(first, WritebackOutcome::Written(MINIMUM_RETIREMENT_BYTES))
            .unwrap();
        controller.submit_current_generation().unwrap();
        backend.wait_for_calls(1);

        let rewrite = controller.plan_write(0, TEST_PAGE_SIZE).unwrap();
        controller
            .finish_write(rewrite, WritebackOutcome::Written(TEST_PAGE_SIZE))
            .unwrap();
        assert_eq!(controller.tracked.bytes, MINIMUM_RETIREMENT_BYTES);
        assert_eq!(
            controller.submitted[0].extents.bytes,
            MINIMUM_RETIREMENT_BYTES
        );
        assert_eq!(controller.current_extents.bytes, TEST_PAGE_SIZE);

        backend.allow(2);
        controller.quiesce().unwrap();
        assert_eq!(controller.tracked.bytes, 0);
        assert_eq!(
            backend.calls(),
            vec![
                vec![DirtyRange {
                    start: 0,
                    end: MINIMUM_RETIREMENT_BYTES,
                }],
                vec![DirtyRange {
                    start: 0,
                    end: TEST_PAGE_SIZE,
                }],
            ]
        );
    }

    #[test]
    fn worker_error_latches_without_releasing_credits() {
        let backend = Arc::new(FakeBackend::default());
        backend.fail_next_wait(io::ErrorKind::Other);
        let mut controller = BufferedWritebackController::spawn(
            backend,
            MINIMUM_WRITEBACK_BUDGET_BYTES,
            TEST_PAGE_SIZE,
        )
        .unwrap();
        let reservation = controller.plan_write(0, 512).unwrap();
        controller
            .finish_write(reservation, WritebackOutcome::Written(512))
            .unwrap();

        assert_eq!(
            controller.quiesce().unwrap_err().kind(),
            io::ErrorKind::Other
        );
        assert_eq!(controller.tracked.bytes, TEST_PAGE_SIZE);
        assert!(controller.latched_error.is_some());
        assert_eq!(
            controller
                .plan_write(TEST_PAGE_SIZE, 512)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Other
        );

        // A later sync cannot prove that bytes behind an already-reported completion error survived.
        assert!(!controller.reset_after_flush());
        assert_eq!(controller.tracked.bytes, 0);
        assert!(controller.latched_error.is_some());
        assert!(!controller.health.is_healthy());
    }

    #[test]
    fn unsupported_backend_error_survives_full_sync_reset() {
        let backend = Arc::new(FakeBackend::default());
        backend.fail_next_wait(io::ErrorKind::Unsupported);
        let mut controller = BufferedWritebackController::spawn(
            backend,
            MINIMUM_WRITEBACK_BUDGET_BYTES,
            TEST_PAGE_SIZE,
        )
        .unwrap();
        let reservation = controller.plan_write(0, 512).unwrap();
        controller
            .finish_write(reservation, WritebackOutcome::Written(512))
            .unwrap();

        assert_eq!(
            controller.quiesce().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert!(controller.latched_error.is_some());

        assert!(!controller.reset_after_flush());
        assert!(controller.latched_error.is_some());
        assert_eq!(
            controller
                .plan_write(TEST_PAGE_SIZE, 512)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn full_sync_reset_does_not_revive_a_dead_worker() {
        let mut controller = BufferedWritebackController::spawn(
            Arc::new(PanicBackend),
            MINIMUM_WRITEBACK_BUDGET_BYTES,
            TEST_PAGE_SIZE,
        )
        .unwrap();
        let reservation = controller.plan_write(0, 512).unwrap();
        controller
            .finish_write(reservation, WritebackOutcome::Written(512))
            .unwrap();

        assert_eq!(
            controller.quiesce().unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert!(controller.latched_error.is_some());

        assert!(!controller.reset_after_flush());
        assert_eq!(controller.tracked.bytes, 0);
        assert!(controller.latched_error.is_some());
        assert_eq!(
            controller
                .plan_write(TEST_PAGE_SIZE, 512)
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    #[test]
    fn reset_after_flush_does_not_clear_a_reported_writeback_error() {
        let backend = Arc::new(FakeBackend::default());
        let mut controller = BufferedWritebackController::spawn(
            backend,
            MINIMUM_WRITEBACK_BUDGET_BYTES,
            TEST_PAGE_SIZE,
        )
        .unwrap();
        controller.latched_error = Some(LatchedError::capture(&io::Error::other("failed")));
        controller.health.mark_permanent_failure();
        assert!(!controller.reset_after_flush());
        assert!(controller.latched_error.is_some());
    }

    #[test]
    fn shared_full_sync_failure_stops_the_live_controller() {
        let backend = Arc::new(FakeBackend::default());
        let mut controller = BufferedWritebackController::spawn(
            backend,
            MINIMUM_WRITEBACK_BUDGET_BYTES,
            TEST_PAGE_SIZE,
        )
        .unwrap();

        controller.health.mark_permanent_failure();
        assert_eq!(
            controller.plan_write(0, 512).unwrap_err().kind(),
            io::ErrorKind::Other
        );
        assert!(!controller.reset_after_flush());
    }

    #[test]
    fn reset_before_quiesce_fails_permanently_without_clearing_reservation() {
        let backend = Arc::new(FakeBackend::default());
        let mut controller = BufferedWritebackController::spawn(
            backend,
            MINIMUM_WRITEBACK_BUDGET_BYTES,
            TEST_PAGE_SIZE,
        )
        .unwrap();
        let reservation = controller.plan_write(0, 512).unwrap();

        assert!(!controller.reset_after_flush());
        assert!(controller.pending.is_some());
        assert!(controller.latched_error.is_some());
        assert!(controller
            .finish_write(reservation, WritebackOutcome::Written(0))
            .is_err());
    }

    fn submit_small_generation(controller: &mut BufferedWritebackController, offset: u64) {
        let reservation = controller.plan_write(offset, 512).unwrap();
        controller
            .finish_write(reservation, WritebackOutcome::Written(512))
            .unwrap();
        controller.submit_current_generation().unwrap();
    }

    fn bitmap_ranges(pages: &[bool]) -> Vec<DirtyRange> {
        let mut ranges = Vec::new();
        let mut page = 0;
        while page < pages.len() {
            if !pages[page] {
                page += 1;
                continue;
            }

            let start = page;
            while page < pages.len() && pages[page] {
                page += 1;
            }
            ranges.push(DirtyRange {
                start: start as u64 * TEST_PAGE_SIZE,
                end: page as u64 * TEST_PAGE_SIZE,
            });
        }
        ranges
    }
}

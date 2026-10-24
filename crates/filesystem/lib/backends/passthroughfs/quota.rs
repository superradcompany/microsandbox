//! Incremental guest-growth accounting for new passthrough mounts.
//!
//! Only logical byte ranges added by guest mutations consume the budget. Host
//! data is exempt, including host growth between guest operations. Reservations
//! precede I/O and are settled from the resulting file size, even on errors.
//! Each charged inode has one ledger, shared by hard links and open handles.
//! Old snapshots retain their original aggregate accounting in `quota_legacy`.

use std::{
    collections::BTreeMap,
    fs::File,
    io,
    path::PathBuf,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

use serde::{Deserialize, Serialize};

use super::quota_legacy::{LegacyQuota, LegacyQuotaState};
use crate::statvfs64;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A per-mount budget for logical bytes added by the guest.
pub(crate) struct DirQuota {
    limit: u64,
    root: PathBuf,
    legacy: RwLock<Option<LegacyQuota>>,
    used: AtomicU64,
    files: Mutex<BTreeMap<u64, Arc<Mutex<FileCharge>>>>,
}

/// Original schema-one fields stay byte-for-byte compatible. The ledger is
/// carried separately by the schema-two snapshot envelope, never appended to
/// an old bincode struct (which would shift every subsequent field).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct QuotaState {
    pub baseline: Option<u64>,
    pub used: u64,
    #[serde(skip)]
    pub files: Option<Vec<FileChargeState>>,
}

/// Durable charges keyed by the filesystem's stable guest inode identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct FileChargeState {
    pub inode: u64,
    pub ranges: Vec<(u64, u64)>,
}

struct FileCharge {
    ranges: Vec<(u64, u64)>,
}

/// Some Linux allocation operations shift bytes without rewriting them.
pub(crate) enum QuotaChange {
    Growth,
    #[cfg(target_os = "linux")]
    Insert {
        offset: u64,
        length: u64,
    },
    #[cfg(target_os = "linux")]
    Collapse {
        offset: u64,
        length: u64,
    },
}

/// Backend operations keep charged identities alive without keeping another
/// host file descriptor for every charged file. Metadata checks reopen only
/// these identities; they never enumerate a mount directory.
pub(crate) trait QuotaInodes {
    fn pin(&self, inode: u64) -> io::Result<()>;
    fn unpin(&self, inode: u64);
    fn live(&self, inode: u64) -> bool;
    fn observe(&self, inode: u64) -> io::Result<(u64, u64)>;
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DirQuota {
    pub(crate) fn new(root: PathBuf, limit: u64) -> Self {
        Self {
            limit,
            root,
            legacy: RwLock::new(None),
            used: AtomicU64::new(0),
            files: Mutex::new(BTreeMap::new()),
        }
    }

    pub(crate) fn limit(&self) -> u64 {
        self.limit
    }

    /// New mounts expose the guest budget directly, without a host-tree baseline.
    pub(crate) fn baseline(&self) -> u64 {
        self.legacy
            .read()
            .unwrap()
            .as_ref()
            .map_or(0, LegacyQuota::baseline)
    }

    pub(crate) fn ensure_baseline(&self) {
        if let Some(legacy) = self.legacy.read().unwrap().as_ref() {
            legacy.ensure_baseline();
        }
    }

    pub(crate) fn used(&self) -> u64 {
        self.legacy.read().unwrap().as_ref().map_or_else(
            || self.used.load(Ordering::Acquire).min(self.limit),
            LegacyQuota::used,
        )
    }

    pub(crate) fn incremental(&self) -> bool {
        self.legacy.read().unwrap().is_none()
    }

    pub(crate) fn contains(&self, inode: u64) -> bool {
        self.files.lock().unwrap().contains_key(&inode)
    }

    /// Serialize mutations to one inode, while independent files share only the
    /// short atomic budget reservation. A failed/short write cannot drain quota.
    pub(crate) fn mutate<T>(
        &self,
        fs: &impl QuotaInodes,
        inode: u64,
        file: &File,
        end: impl FnOnce(u64) -> u64,
        operation: impl FnOnce(u64) -> io::Result<T>,
    ) -> io::Result<T> {
        self.mutate_with_change(fs, inode, file, end, QuotaChange::Growth, operation)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn mutate_with_change<T>(
        &self,
        fs: &impl QuotaInodes,
        inode: u64,
        file: &File,
        end: impl FnOnce(u64) -> u64,
        change: QuotaChange,
        operation: impl FnOnce(u64) -> io::Result<T>,
    ) -> io::Result<T> {
        let legacy = self.legacy.read().unwrap();
        if let Some(legacy) = legacy.as_ref() {
            legacy.ensure_baseline();
            let before = file.metadata()?.len();
            legacy.charge(end(before).saturating_sub(before))?;
            return operation(before);
        }
        let entry = {
            let mut files = self.files.lock().unwrap();
            if let Some(entry) = files.get(&inode) {
                entry.clone()
            } else {
                fs.pin(inode)?;
                let entry = Arc::new(Mutex::new(FileCharge { ranges: Vec::new() }));
                files.insert(inode, entry.clone());
                entry
            }
        };
        let result = (|| {
            let mut charge = entry.lock().unwrap();
            let before = file.metadata()?.len();
            self.trim(&mut charge, before);
            let end = end(before).max(before);
            let reserved = end - before;
            if !self.reserve(reserved) {
                // try_lock in reconciliation avoids waiting on this entry or
                // another writer that is itself waiting for quota space.
                self.reconcile(fs);
                if !self.reserve(reserved) {
                    return Err(enospc());
                }
            }
            let result = operation(before);
            // Metadata failure must not give away space that may have been
            // written. Retain the reservation until a later observation.
            let after = file.metadata().map(|m| m.len());
            let actual = after.as_ref().copied().unwrap_or(end).min(end);
            let growth = actual.saturating_sub(before);
            self.used.fetch_sub(reserved - growth, Ordering::AcqRel);
            match change {
                #[cfg(target_os = "linux")]
                QuotaChange::Insert { offset, length } if result.is_ok() && growth == length => {
                    charge.insert(offset, length);
                }
                #[cfg(target_os = "linux")]
                QuotaChange::Collapse { offset, length } if result.is_ok() => {
                    let old = charge.bytes();
                    charge.collapse(offset, length);
                    self.used.fetch_sub(old - charge.bytes(), Ordering::AcqRel);
                }
                _ => {
                    if growth != 0 {
                        charge.add(before, before + growth);
                    }
                }
            }
            if let Ok(after) = after {
                self.trim(&mut charge, after);
            }
            result
        })();
        drop(entry);
        self.prune(fs, inode);
        result
    }

    /// Reconcile only recorded charges. Host changes that occur entirely between
    /// observations cannot be attributed exactly; unseen regrowth remains exempt
    /// and existing charges stay conservative until a shrink/removal is observed.
    pub(crate) fn reconcile(&self, fs: &impl QuotaInodes) {
        let inodes = self
            .files
            .lock()
            .unwrap()
            .keys()
            .copied()
            .collect::<Vec<_>>();
        for inode in inodes {
            self.reconcile_inode(fs, inode);
        }
    }

    /// Guest release/forget only touches its own ledger entry.
    pub(crate) fn reconcile_inode(&self, fs: &impl QuotaInodes, inode: u64) {
        let entry = self.files.lock().unwrap().get(&inode).cloned();
        let Some(entry) = entry else {
            return;
        };
        if let Ok(mut charge) = entry.try_lock() {
            match fs.observe(inode) {
                Ok((size, links)) => {
                    let size = if links == 0 && !fs.live(inode) {
                        0
                    } else {
                        size
                    };
                    self.trim(&mut charge, size);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound && !fs.live(inode) => {
                    self.trim(&mut charge, 0)
                }
                Err(_) => {} // An unreadable object is not evidence of reclaimed space.
            }
        }
        drop(entry);
        self.prune(fs, inode);
    }

    fn reserve(&self, bytes: u64) -> bool {
        #[allow(deprecated)]
        self.used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|next| *next <= self.limit)
            })
            .is_ok()
    }

    fn trim(&self, charge: &mut FileCharge, size: u64) {
        let before = charge.bytes();
        for range in &mut charge.ranges {
            range.1 = range.1.min(size);
        }
        charge.ranges.retain(|&(start, end)| start < end);
        self.used
            .fetch_sub(before - charge.bytes(), Ordering::AcqRel);
    }

    fn prune(&self, fs: &impl QuotaInodes, inode: u64) {
        let mut files = self.files.lock().unwrap();
        let remove = files.get(&inode).is_some_and(|entry| {
            Arc::strong_count(entry) == 1 && entry.lock().unwrap().ranges.is_empty()
        });
        if remove {
            files.remove(&inode);
        }
        drop(files);
        if remove {
            fs.unpin(inode);
        }
    }

    /// Capture runs with filesystem requests quiesced by the snapshot barrier.
    pub(crate) fn capture_state(&self) -> QuotaState {
        if let Some(legacy) = self.legacy.read().unwrap().as_ref() {
            let state = legacy.capture_state();
            return QuotaState {
                baseline: state.baseline,
                used: state.used,
                files: None,
            };
        }
        let files = self
            .files
            .lock()
            .unwrap()
            .iter()
            .map(|(&inode, entry)| FileChargeState {
                inode,
                ranges: entry.lock().unwrap().ranges.clone(),
            })
            .collect();
        QuotaState {
            baseline: None,
            used: self.used.load(Ordering::Acquire),
            files: Some(files),
        }
    }

    pub(crate) fn validate_state(&self, state: &QuotaState) -> io::Result<()> {
        state.validate()?;
        if state.used > self.limit {
            return Err(invalid("restored quota usage exceeds configured limit"));
        }
        if state.files.is_none()
            && let Some(legacy) = self.legacy.read().unwrap().as_ref()
        {
            legacy.validate_state(&LegacyQuotaState {
                baseline: state.baseline,
                used: state.used,
            })?;
        }
        Ok(())
    }

    /// Old aggregate states explicitly select legacy mode, as their guest bytes
    /// cannot be assigned to individual files without changing their meaning.
    pub(crate) fn restore_state(&self, state: &QuotaState) -> io::Result<()> {
        self.validate_state(state)?;
        if let Some(files) = &state.files {
            *self.files.lock().unwrap() = files
                .iter()
                .map(|file| {
                    (
                        file.inode,
                        Arc::new(Mutex::new(FileCharge {
                            ranges: file.ranges.clone(),
                        })),
                    )
                })
                .collect();
            self.used.store(state.used, Ordering::Release);
            *self.legacy.write().unwrap() = None;
        } else {
            let legacy = LegacyQuota::new(self.root.clone(), self.limit);
            legacy.restore_state(&LegacyQuotaState {
                baseline: state.baseline,
                used: state.used,
            })?;
            *self.legacy.write().unwrap() = Some(legacy);
            self.files.lock().unwrap().clear();
        }
        Ok(())
    }
}

impl FileCharge {
    #[cfg(target_os = "linux")]
    fn insert(&mut self, offset: u64, length: u64) {
        let mut ranges = Vec::new();
        for &(start, end) in &self.ranges {
            if start < offset {
                ranges.push((start, end.min(offset)));
            }
            if end > offset {
                ranges.push((start.max(offset) + length, end + length));
            }
        }
        ranges.push((offset, offset + length));
        self.replace_ranges(ranges);
    }

    #[cfg(target_os = "linux")]
    fn collapse(&mut self, offset: u64, length: u64) {
        let mut ranges = Vec::new();
        for &(start, end) in &self.ranges {
            if start < offset {
                ranges.push((start, end.min(offset)));
            }
            if end > offset + length {
                ranges.push((start.max(offset + length) - length, end - length));
            }
        }
        self.replace_ranges(ranges);
    }

    #[cfg(target_os = "linux")]
    fn replace_ranges(&mut self, mut ranges: Vec<(u64, u64)>) {
        ranges.sort_unstable();
        self.ranges.clear();
        for (start, end) in ranges {
            self.add(start, end);
        }
    }

    fn bytes(&self) -> u64 {
        self.ranges.iter().map(|&(start, end)| end - start).sum()
    }

    fn add(&mut self, start: u64, end: u64) {
        if let Some(last) = self.ranges.last_mut()
            && last.1 == start
        {
            last.1 = end;
        } else {
            self.ranges.push((start, end));
        }
    }
}

impl QuotaState {
    pub(crate) fn validate(&self) -> io::Result<()> {
        if let Some(files) = &self.files {
            if self.baseline.is_some() {
                return Err(invalid("incremental quota has a legacy baseline"));
            }
            let mut previous_inode = 0;
            let mut used = 0u64;
            for file in files {
                if file.inode <= previous_inode || file.ranges.is_empty() {
                    return Err(invalid("invalid quota inode ledger"));
                }
                previous_inode = file.inode;
                let mut previous_end = None;
                for &(start, end) in &file.ranges {
                    if start >= end || previous_end.is_some_and(|previous| previous >= start) {
                        return Err(invalid("invalid quota charge ranges"));
                    }
                    previous_end = Some(end);
                    used = used
                        .checked_add(end - start)
                        .ok_or_else(|| invalid("quota charge overflow"))?;
                }
            }
            if used != self.used {
                return Err(invalid("quota ledger does not match usage"));
            }
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn enospc() -> io::Error {
    io::Error::from_raw_os_error(28)
}

/// Report the remaining guest budget in filesystem block units. New mounts
/// use zero baseline; legacy restored snapshots retain their original total.
pub(crate) fn quota_statvfs(baseline: u64, limit: u64, used: u64) -> statvfs64 {
    let bsize = 4096u64;
    let total = baseline.saturating_add(limit);
    let free = limit.saturating_sub(used);
    let mut st: statvfs64 = unsafe { std::mem::zeroed() };

    #[cfg(target_os = "linux")]
    {
        st.f_bsize = bsize;
        st.f_frsize = bsize;
        st.f_blocks = total / bsize;
        st.f_bfree = free / bsize;
        st.f_bavail = free / bsize;
        st.f_namemax = 255;
    }

    #[cfg(target_os = "macos")]
    {
        st.f_bsize = bsize;
        st.f_frsize = bsize;
        st.f_blocks = (total / bsize) as _;
        st.f_bfree = (free / bsize) as _;
        st.f_bavail = (free / bsize) as _;
        st.f_namemax = 255;
    }

    #[cfg(windows)]
    {
        st.f_bsize = bsize;
        st.f_frsize = bsize;
        st.f_blocks = total / bsize;
        st.f_bfree = free / bsize;
        st.f_bavail = free / bsize;
        st.f_namemax = 255;
    }

    st
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    struct TestInodes {
        files: BTreeMap<u64, File>,
        live: AtomicBool,
        pins: AtomicU64,
    }

    impl QuotaInodes for TestInodes {
        fn pin(&self, _: u64) -> io::Result<()> {
            self.pins.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        fn unpin(&self, _: u64) {
            self.pins.fetch_sub(1, Ordering::Relaxed);
        }
        fn live(&self, _: u64) -> bool {
            self.live.load(Ordering::Relaxed)
        }
        fn observe(&self, inode: u64) -> io::Result<(u64, u64)> {
            Ok((self.files[&inode].metadata()?.len(), 1))
        }
    }

    fn setup(limit: u64) -> (DirQuota, TestInodes) {
        // The quota root deliberately does not exist: incremental operations
        // must depend only on the file being mutated, never a directory walk.
        (
            DirQuota::new(PathBuf::from("/nonexistent-quota-root"), limit),
            TestInodes {
                files: [
                    (3, tempfile::tempfile().unwrap()),
                    (4, tempfile::tempfile().unwrap()),
                ]
                .into(),
                live: AtomicBool::new(false),
                pins: AtomicU64::new(0),
            },
        )
    }

    #[test]
    fn short_and_failed_writes_settle_actual_growth() {
        let (quota, fs) = setup(100);
        let file = &fs.files[&3];
        quota
            .mutate(&fs, 3, file, |_| 100, |_| file.set_len(40))
            .unwrap();
        assert_eq!(quota.used(), 40);
        let result: io::Result<()> = quota.mutate(
            &fs,
            3,
            file,
            |_| 100,
            |_| Err(io::Error::other("write failed")),
        );
        assert!(result.is_err());
        assert_eq!(quota.used(), 40);
        let result: io::Result<()> = quota.mutate(
            &fs,
            3,
            file,
            |_| 100,
            |_| {
                file.set_len(60)?;
                Err(io::Error::other("partially written"))
            },
        );
        assert!(result.is_err());
        assert_eq!(quota.used(), 60);
        quota
            .mutate(&fs, 3, file, |_| 0, |_| file.set_len(0))
            .unwrap();
        assert_eq!(quota.used(), 0);
        assert_eq!(fs.pins.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn host_growth_is_exempt_and_shrinks_remove_only_guest_ranges() {
        let (quota, fs) = setup(100);
        let file = &fs.files[&3];
        file.set_len(1000).unwrap();
        quota
            .mutate(&fs, 3, file, |_| 1040, |_| file.set_len(1040))
            .unwrap();
        file.set_len(2000).unwrap(); // Host adds an uncharged gap.
        quota
            .mutate(&fs, 3, file, |_| 2060, |_| file.set_len(2060))
            .unwrap();
        assert_eq!(quota.used(), 100);
        file.set_len(2020).unwrap();
        quota.reconcile(&fs);
        assert_eq!(quota.used(), 60);
        file.set_len(1030).unwrap();
        quota.reconcile(&fs);
        assert_eq!(quota.used(), 30);
        assert_eq!(quota.baseline(), 0);
        assert_eq!(quota.capture_state().baseline, None);
    }

    #[test]
    fn quota_pressure_reclaims_observed_host_shrink_only() {
        let (quota, fs) = setup(100);
        let first = &fs.files[&3];
        let second = &fs.files[&4];
        quota
            .mutate(&fs, 3, first, |_| 100, |_| first.set_len(100))
            .unwrap();
        assert_eq!(
            quota
                .mutate(&fs, 4, second, |_| 1, |_| second.set_len(1))
                .unwrap_err()
                .raw_os_error(),
            Some(28)
        );
        first.set_len(25).unwrap();
        quota
            .mutate(&fs, 4, second, |_| 75, |_| second.set_len(75))
            .unwrap();
        assert_eq!(quota.used(), 100);
    }

    #[test]
    fn concurrent_files_cannot_overreserve_mount_budget() {
        let (quota, fs) = setup(100);
        let barrier = std::sync::Barrier::new(2);
        let successes = std::thread::scope(|scope| {
            let runs: Vec<_> = [3, 4]
                .into_iter()
                .map(|inode| {
                    let quota = &quota;
                    let fs = &fs;
                    let barrier = &barrier;
                    scope.spawn(move || {
                        barrier.wait();
                        quota
                            .mutate(
                                fs,
                                inode,
                                &fs.files[&inode],
                                |_| 100,
                                |_| fs.files[&inode].set_len(100),
                            )
                            .is_ok()
                    })
                })
                .collect();
            runs.into_iter()
                .map(|run| usize::from(run.join().unwrap()))
                .sum::<usize>()
        });
        assert_eq!(successes, 1);
        assert_eq!(quota.used(), 100);
    }

    #[test]
    fn malformed_ledgers_are_rejected_without_mutation() {
        let (quota, _) = setup(100);
        let before = quota.capture_state();
        for files in [
            vec![FileChargeState {
                inode: 3,
                ranges: vec![(0, 20), (10, 30)],
            }],
            vec![FileChargeState {
                inode: 3,
                ranges: vec![(10, 10)],
            }],
            vec![
                FileChargeState {
                    inode: 3,
                    ranges: vec![(0, 10)],
                },
                FileChargeState {
                    inode: 3,
                    ranges: vec![(10, 20)],
                },
            ],
        ] {
            assert!(
                quota
                    .restore_state(&QuotaState {
                        baseline: None,
                        used: 20,
                        files: Some(files)
                    })
                    .is_err()
            );
            assert_eq!(quota.capture_state(), before);
        }
    }
    #[test]
    fn concurrent_appends_to_one_inode_share_a_ledger() {
        let (quota, fs) = setup(100);
        std::thread::scope(|scope| {
            for _ in 0..2 {
                scope.spawn(|| {
                    quota
                        .mutate(
                            &fs,
                            3,
                            &fs.files[&3],
                            |before| before + 50,
                            |before| fs.files[&3].set_len(before + 50),
                        )
                        .unwrap();
                });
            }
        });
        assert_eq!(fs.files[&3].metadata().unwrap().len(), 100);
        assert_eq!(quota.used(), 100);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn insert_and_collapse_preserve_guest_ownership_across_host_ranges() {
        let (quota, fs) = setup(100);
        let file = &fs.files[&3];
        file.set_len(100).unwrap();
        quota
            .mutate(&fs, 3, file, |_| 120, |_| file.set_len(120))
            .unwrap();
        quota
            .mutate_with_change(
                &fs,
                3,
                file,
                |before| before + 10,
                QuotaChange::Insert {
                    offset: 50,
                    length: 10,
                },
                |before| file.set_len(before + 10),
            )
            .unwrap();
        assert_eq!(
            quota.capture_state().files.unwrap()[0].ranges,
            vec![(50, 60), (110, 130)]
        );
        assert_eq!(quota.used(), 30);
        quota
            .mutate_with_change(
                &fs,
                3,
                file,
                |before| before,
                QuotaChange::Collapse {
                    offset: 40,
                    length: 80,
                },
                |before| file.set_len(before - 80),
            )
            .unwrap();
        assert_eq!(
            quota.capture_state().files.unwrap()[0].ranges,
            vec![(40, 50)]
        );
        assert_eq!(quota.used(), 10);
    }
}

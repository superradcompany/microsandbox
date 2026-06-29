//! Directory byte-budget quota for the passthrough filesystem.
//!
//! A passthrough mount shares a host directory directly, so without a budget a
//! guest can write unbounded data straight onto the host disk. [`DirQuota`]
//! bounds the *guest-attributable* growth of one mount's subtree.
//!
//! ## Accounting model
//!
//! `used` is an optimistic running estimate of the subtree's logical size,
//! charged on growth (write / fallocate / truncate-extend / copy). It is
//! deliberately **never decremented** on the unlink / rename / truncate-shrink
//! paths — that would mean fstat-before-remove bookkeeping on every mutation.
//! Instead, when an optimistic charge would cross `limit`, the budget walks the
//! root to recompute the ground-truth size and corrects `used`. The walk is
//! ground truth at the only moment it matters (the limit boundary), so the hot
//! path stays cheap while a churning workload (e.g. a heartbeat file rewritten
//! every second) converges on its true size instead of monotonically draining
//! the budget.
//!
//! Accounting is **logical** (`st_size`, not allocated blocks): a sparse file is
//! charged at its apparent size. That is conservative for a fill-prevention
//! quota — it bounds what the guest could later fill.
//!
//! ## Delta semantics
//!
//! The budget bounds *guest additions beyond what already existed when the
//! guest first writes*, not the absolute subtree size. That baseline — the
//! host-written control-plane files for `/.msb`, or a pre-existing host
//! directory for a bind mount — never counts against the guest. So
//! `quota = 1 GiB` on a directory that already holds 5 GiB means "the guest may
//! add up to 1 GiB," not "instantly full."
//!
//! ## Lazy baseline
//!
//! The baseline is **not** walked at mount — that would put a directory walk on
//! the VM-setup path, costly for a heavy bind mount. It is computed once, on the
//! first guest write-access ([`DirQuota::ensure_baseline`], called from the
//! `open`/`create`/`setattr` handlers). Those ops necessarily precede the first
//! `write`/`fallocate`/truncate-extend, so the baseline always reflects the
//! pre-guest-write state — the snapshot just happens at first touch instead of
//! at boot. A read-only workload never triggers it.

use std::{
    io,
    path::{Path, PathBuf},
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

#[cfg(windows)]
use std::fs::File;
#[cfg(unix)]
use std::os::fd::RawFd;

#[cfg(unix)]
use crate::backends::shared::platform;
use crate::statvfs64;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A delta-charged byte budget for one passthrough mount subtree.
pub(crate) struct DirQuota {
    /// Hard ceiling in bytes for guest additions. Growth past this returns `ENOSPC`.
    limit: u64,

    /// Host directory whose subtree is bounded.
    root: PathBuf,

    /// Subtree size at first guest write-access. Never counts against the
    /// guest. Computed lazily so a heavy directory is not walked at boot.
    baseline: OnceLock<u64>,

    /// Optimistic running estimate of guest-added bytes beyond the baseline.
    used: AtomicU64,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DirQuota {
    /// Create a budget of `limit` guest-addable bytes over the subtree at `root`.
    ///
    /// Does not walk the directory — the baseline is captured lazily on the
    /// first guest write-access (see [`Self::ensure_baseline`]).
    pub(crate) fn new(root: PathBuf, limit: u64) -> Self {
        Self {
            limit,
            root,
            baseline: OnceLock::new(),
            used: AtomicU64::new(0),
        }
    }

    /// The configured ceiling in bytes for guest additions.
    pub(crate) fn limit(&self) -> u64 {
        self.limit
    }

    /// Bytes present at the moment the baseline was first captured (never
    /// charged to the guest). Computes the baseline if it has not been yet.
    pub(crate) fn baseline(&self) -> u64 {
        *self.baseline.get_or_init(|| subtree_size(&self.root))
    }

    /// Capture the baseline now if it has not been captured yet.
    ///
    /// Called from the write-gating FUSE handlers (`open` with write intent,
    /// `create`, `setattr`-truncate) so the baseline is snapshotted *before* the
    /// guest's first mutation. Idempotent and cheap after the first call.
    pub(crate) fn ensure_baseline(&self) {
        let _ = self.baseline();
    }

    /// Current best estimate of bytes used, clamped to the ceiling for display.
    pub(crate) fn used(&self) -> u64 {
        self.used.load(Ordering::Relaxed).min(self.limit)
    }

    /// Charge `growth` bytes of pending subtree growth.
    ///
    /// Returns `ENOSPC` if the growth would exceed the limit even after a
    /// ground-truth recount. The pending write has not happened yet, so the
    /// recount measures the subtree *without* this growth and the decision is
    /// made against `real + growth`.
    pub(crate) fn charge(&self, growth: u64) -> io::Result<()> {
        if growth == 0 {
            return Ok(());
        }

        let prev = self.used.fetch_add(growth, Ordering::Relaxed);
        if prev.saturating_add(growth) <= self.limit {
            return Ok(());
        }

        // The optimistic estimate crossed the ceiling. It may be stale (deletes
        // and overwrites are not tracked incrementally), so fall back to ground
        // truth — guest additions beyond the baseline — before refusing.
        let real = subtree_size(&self.root).saturating_sub(self.baseline());
        if real.saturating_add(growth) <= self.limit {
            self.used
                .store(real.saturating_add(growth), Ordering::Relaxed);
            Ok(())
        } else {
            self.used.store(real, Ordering::Relaxed);
            Err(enospc())
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Logical size of an open file by fd, or 0 if it cannot be stat'd.
#[cfg(unix)]
pub(crate) fn fd_size(fd: RawFd) -> u64 {
    platform::fstat(fd)
        .map(|st| st.st_size.max(0) as u64)
        .unwrap_or(0)
}

/// Logical size of an open file handle, or 0 if it cannot be stat'd.
#[cfg(windows)]
pub(crate) fn file_size(file: &File) -> u64 {
    file.metadata().map(|metadata| metadata.len()).unwrap_or(0)
}

/// Linux `ENOSPC` error for the guest FUSE ABI.
fn enospc() -> io::Error {
    #[cfg(unix)]
    {
        platform::enospc()
    }
    #[cfg(windows)]
    {
        io::Error::from_raw_os_error(28)
    }
}

/// Sum the logical size of every regular file beneath `root`.
///
/// Best-effort: unreadable directories and entries are skipped. Symlinks are
/// not followed, so the walk stays within the mount subtree.
fn subtree_size(root: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                stack.push(entry.path());
            } else if file_type.is_file() {
                let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
                total = total.saturating_add(len);
            }
        }
    }
    total
}

/// Build a `statvfs64` reply that reports the quota as the filesystem size.
///
/// Makes guest `df` reflect the mount's real constraint instead of the host
/// filesystem's much larger figures. Includes the baseline so that `df`'s
/// derived *used* (total − free) tracks what `du` reports, while *available*
/// stays the remaining guest budget:
///
/// - total     = `baseline + limit`
/// - available = `limit - used`
/// - used (df) = total − available = `baseline + used`
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

    #[test]
    fn charge_allows_up_to_limit() {
        let dir = tempfile::tempdir().unwrap();
        let q = DirQuota::new(dir.path().to_path_buf(), 1024);
        assert!(q.charge(512).is_ok());
        assert!(q.charge(512).is_ok());
        assert_eq!(q.used(), 1024);
    }

    #[test]
    fn charge_past_limit_is_enospc_when_real_growth_exceeds_limit() {
        let dir = tempfile::tempdir().unwrap();
        let q = DirQuota::new(dir.path().to_path_buf(), 1024);
        // The handlers force the baseline before the first guest write; mirror
        // that here so the about-to-be-written file is charged, not baselined.
        q.ensure_baseline();
        // Guest writes a real 1 KiB file (charge succeeds, then the write lands).
        assert!(q.charge(1024).is_ok());
        std::fs::write(dir.path().join("a"), vec![0u8; 1024]).unwrap();
        // A second 1 KiB write crosses the ceiling; the recount finds the real
        // 1 KiB already on disk and refuses the new growth.
        let err = q.charge(1024).unwrap_err();
        assert_eq!(err.raw_os_error(), enospc().raw_os_error());
    }

    #[test]
    fn baseline_files_are_not_charged() {
        let dir = tempfile::tempdir().unwrap();
        // A pre-existing 4 KiB file forms the baseline.
        std::fs::write(dir.path().join("preexisting"), vec![0u8; 4096]).unwrap();
        let q = DirQuota::new(dir.path().to_path_buf(), 1024);
        q.ensure_baseline();
        assert_eq!(q.baseline(), 4096);
        // The guest may still add up to the full quota beyond the baseline.
        assert!(q.charge(1024).is_ok());
    }

    #[test]
    fn baseline_is_captured_lazily_not_at_construction() {
        let dir = tempfile::tempdir().unwrap();
        let q = DirQuota::new(dir.path().to_path_buf(), 1024);
        // A file appearing after construction but before first access (e.g. a
        // host-written control file) counts as baseline, not guest usage.
        std::fs::write(dir.path().join("late"), vec![0u8; 800]).unwrap();
        q.ensure_baseline();
        assert_eq!(q.baseline(), 800);
    }

    #[test]
    fn recount_reclaims_drift_from_untracked_deletes() {
        let dir = tempfile::tempdir().unwrap();
        let q = DirQuota::new(dir.path().to_path_buf(), 1024);
        // Simulate a churning writer: the optimistic counter drifts up to the
        // ceiling even though nothing is actually on disk.
        assert!(q.charge(1024).is_ok());
        // Next charge crosses the ceiling, triggers a recount, finds an empty
        // subtree, and succeeds — the budget did not get permanently stuck.
        assert!(q.charge(512).is_ok());
        assert_eq!(q.used(), 512);
    }

    #[test]
    fn zero_growth_is_free() {
        let dir = tempfile::tempdir().unwrap();
        let q = DirQuota::new(dir.path().to_path_buf(), 0);
        assert!(q.charge(0).is_ok());
    }
}

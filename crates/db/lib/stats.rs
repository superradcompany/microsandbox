//! Lightweight counters for database health.
//!
//! Hosts running many sandboxes can exhaust the database connection pools;
//! these counters let host processes export how often pool acquisition
//! timed out or writes had to retry on `SQLITE_BUSY`, without pulling a
//! metrics framework into this crate.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

/// Shared counters recorded by the connection wrappers and retry loop.
///
/// `Clone` is cheap: clones share the same `Arc`-backed counters, so a
/// snapshot taken from any clone reflects the whole connection's history.
#[derive(Debug, Clone, Default)]
pub struct DbStats(Arc<Counters>);

#[derive(Debug, Default)]
struct Counters {
    pool_timeouts: AtomicU64,
    busy_retries: AtomicU64,
    retries_exhausted: AtomicU64,
}

/// Point-in-time copy of [`DbStats`] counters, for export by host processes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DbStatsSnapshot {
    /// Operations that failed because pool acquisition timed out.
    pub pool_timeouts: u64,
    /// Individual retries performed after `SQLITE_BUSY` / `BUSY_SNAPSHOT`.
    pub busy_retries: u64,
    /// Operations that gave up after exhausting all busy retries.
    pub retries_exhausted: u64,
}

impl DbStats {
    /// Create a fresh set of zeroed counters.
    pub fn new() -> Self {
        Self::default()
    }

    /// Copy the current counter values.
    pub fn snapshot(&self) -> DbStatsSnapshot {
        DbStatsSnapshot {
            pool_timeouts: self.0.pool_timeouts.load(Ordering::Relaxed),
            busy_retries: self.0.busy_retries.load(Ordering::Relaxed),
            retries_exhausted: self.0.retries_exhausted.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn record_pool_timeout(&self) {
        self.0.pool_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_busy_retry(&self) {
        self.0.busy_retries.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_retries_exhausted(&self) {
        self.0.retries_exhausted.fetch_add(1, Ordering::Relaxed);
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clones_share_counters() {
        let stats = DbStats::new();
        let clone = stats.clone();

        stats.record_pool_timeout();
        clone.record_busy_retry();

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.pool_timeouts, 1);
        assert_eq!(snapshot.busy_retries, 1);
        assert_eq!(snapshot.retries_exhausted, 0);
    }
}

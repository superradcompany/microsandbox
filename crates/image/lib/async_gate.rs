//! In-process coordination for asynchronously polled file locks.
//!
//! A concurrent weak index shares one gate per canonical path without a global map mutex.
//! Bucket guards cover lookup and publication only, never file locking or async waits.
//! Sync callers may wait for a bucket; async callers use cooperative map operations.
//! An atomic count schedules occasional sweeps without scanning the map on every lookup.

use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use tokio::sync::{Mutex as AsyncMutex, MutexGuard, watch};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const INITIAL_SWEEP_SIZE: usize = 1_024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Weak registry of per-path async gates.
pub(crate) struct AsyncGateRegistry {
    /// Weak entries never retain an idle gate.
    entries: scc::HashMap<PathBuf, Weak<AsyncGate>>,
    /// Updated under bucket guards instead of calling the map's O(N) `len`.
    entry_count: AtomicUsize,
    /// Entry count triggering cleanup; `usize::MAX` reserves an in-progress sweep.
    next_sweep_size: AtomicUsize,
}

/// Per-key retry coordination and release notifications for local lock holders.
pub(crate) struct AsyncGate {
    /// Admits one async OS lock poller at a time.
    mutex: AsyncMutex<()>,
    /// Retains notifications that arrive between a lock probe and its retry wait.
    pub(crate) generation: watch::Sender<u64>,
}

/// Re-arms cleanup after completion or cancellation of an async sweep.
struct AsyncGateSweep<'a> {
    registry: &'a AsyncGateRegistry,
    /// Only a completed sweep earns a larger interval before the next cleanup.
    completed: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl AsyncGateRegistry {
    /// Create an empty registry.
    pub(crate) fn new() -> Self {
        Self {
            entries: scc::HashMap::new(),
            entry_count: AtomicUsize::new(0),
            next_sweep_size: AtomicUsize::new(INITIAL_SWEEP_SIZE),
        }
    }

    /// Reuse an async waiter gate for a key canonicalized by the caller.
    /// This registry does not resolve aliases or relative paths itself.
    pub(crate) fn gate(&self, path: &Path) -> Arc<AsyncGate> {
        let mut slot = match self.entries.entry_sync(path.to_path_buf()) {
            scc::hash_map::Entry::Occupied(slot) => slot,
            scc::hash_map::Entry::Vacant(slot) => {
                self.entry_count.fetch_add(1, Ordering::Relaxed);
                slot.insert_entry(Weak::new())
            }
        };
        let gate = if let Some(gate) = slot.get().upgrade() {
            gate
        } else {
            let gate = Arc::new(AsyncGate::new());
            *slot.get_mut() = Arc::downgrade(&gate);
            gate
        };
        drop(slot);
        self.sweep_if_needed();
        gate
    }

    /// Look up a gate without blocking the executor on a contended map bucket.
    pub(crate) async fn gate_async(&self, path: &Path) -> Arc<AsyncGate> {
        let mut slot = match self.entries.entry_async(path.to_path_buf()).await {
            scc::hash_map::Entry::Occupied(slot) => slot,
            scc::hash_map::Entry::Vacant(slot) => {
                self.entry_count.fetch_add(1, Ordering::Relaxed);
                slot.insert_entry(Weak::new())
            }
        };
        let gate = if let Some(gate) = slot.get().upgrade() {
            gate
        } else {
            let gate = Arc::new(AsyncGate::new());
            *slot.get_mut() = Arc::downgrade(&gate);
            gate
        };
        drop(slot);
        self.sweep_if_needed_async().await;
        gate
    }

    /// Reserve one sweep without serializing lookups behind it.
    fn begin_sweep(&self) -> Option<AsyncGateSweep<'_>> {
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

        Some(AsyncGateSweep {
            registry: self,
            completed: false,
        })
    }

    fn sweep_if_needed(&self) {
        let Some(mut sweep) = self.begin_sweep() else {
            return;
        };
        self.entries.retain_sync(|_, gate| {
            let retained = gate.strong_count() > 0;
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
            .retain_async(|_, gate| {
                let retained = gate.strong_count() > 0;
                if !retained {
                    self.entry_count.fetch_sub(1, Ordering::Relaxed);
                }
                retained
            })
            .await;
        sweep.completed = true;
    }
}

impl AsyncGate {
    fn new() -> Self {
        let (generation, _) = watch::channel(0);
        Self {
            mutex: AsyncMutex::new(()),
            generation,
        }
    }

    /// Wait for ownership of the retry loop without blocking the executor.
    pub(crate) async fn lock(&self) -> MutexGuard<'_, ()> {
        self.mutex.lock().await
    }

    /// Wake a local poller after its holder has released the OS lock.
    pub(crate) fn notify_release(&self) {
        self.generation
            .send_modify(|generation| *generation = generation.wrapping_add(1));
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for AsyncGateSweep<'_> {
    fn drop(&mut self) {
        let entry_count = self.registry.entry_count.load(Ordering::Relaxed);
        let next_sweep_size = if self.completed {
            entry_count.saturating_mul(2).max(INITIAL_SWEEP_SIZE)
        } else {
            entry_count.max(1)
        };
        self.registry
            .next_sweep_size
            .store(next_sweep_size, Ordering::Relaxed);
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Add process- and attempt-specific jitter to an exponential retry delay.
pub(crate) fn jittered_delay(path: &Path, delay: Duration, attempt: u64) -> Duration {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    attempt.hash(&mut hasher);
    let jitter_ceiling = delay.as_millis().saturating_div(2).max(1) as u64;
    delay.saturating_add(Duration::from_millis(1 + hasher.finish() % jitter_ceiling))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_delays_add_bounded_nonzero_jitter() {
        for delay in [
            Duration::ZERO,
            Duration::from_millis(2),
            Duration::from_millis(100),
        ] {
            for attempt in 0..100 {
                let actual = jittered_delay(Path::new("artifact.lock"), delay, attempt);

                assert!(actual > delay);
                assert!(actual <= delay + Duration::from_millis(50));
            }
        }
    }

    #[tokio::test]
    async fn cleanup_preserves_live_gates_and_bounds_idle_entries() {
        for asynchronous in [false, true] {
            let registry = AsyncGateRegistry::new();
            let key = Path::new("active.lock");
            let gate = registry.gate(key);
            let held = gate.mutex.try_lock().unwrap();
            for index in 0..INITIAL_SWEEP_SIZE * 2 {
                let path = PathBuf::from(format!("{index}.lock"));
                let idle = if asynchronous {
                    registry.gate_async(&path).await
                } else {
                    registry.gate(&path)
                };
                drop(idle);
            }

            let same_gate = registry.gate_async(key).await;
            assert!(same_gate.mutex.try_lock().is_err());
            assert!(registry.entries.len() <= INITIAL_SWEEP_SIZE);

            drop(held);
            assert!(same_gate.mutex.try_lock().is_ok());
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_sync_and_async_lookups_share_one_gate() {
        let registry = Arc::new(AsyncGateRegistry::new());
        let start = Arc::new(tokio::sync::Barrier::new(16));
        let mut tasks = Vec::new();
        for index in 0..16 {
            let registry = Arc::clone(&registry);
            let start = Arc::clone(&start);
            tasks.push(tokio::spawn(async move {
                start.wait().await;
                let path = Path::new("shared.lock");
                if index % 2 == 0 {
                    registry.gate_async(path).await
                } else {
                    tokio::task::spawn_blocking(move || registry.gate(path))
                        .await
                        .unwrap()
                }
            }));
        }

        let mut gates = Vec::new();
        for task in tasks {
            gates.push(task.await.unwrap());
        }

        let first = &gates[0];
        for gate in &gates[1..] {
            assert!(Arc::ptr_eq(first, gate));
        }
    }
}

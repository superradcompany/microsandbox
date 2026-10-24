//! Cross-process file locking helpers.
//!
//! Used by the download and materialization pipelines to coordinate
//! concurrent access to shared cache artifacts.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use crate::async_gate::{AsyncGate, AsyncGateRegistry, jittered_delay};
use crate::error::{ImageError, ImageResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const LOCK_RETRY_INITIAL_DELAY: Duration = Duration::from_millis(2);
const LOCK_RETRY_MAX_DELAY: Duration = Duration::from_millis(100);

static ASYNC_LOCK_GATES: OnceLock<AsyncGateRegistry> = OnceLock::new();

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// RAII guard for an exclusively locked cache artifact.
#[must_use = "the cache artifact lock is released when the guard is dropped"]
pub(crate) struct CacheLockGuard {
    /// Taken on drop so the descriptor closes before local waiters are notified.
    file: Option<File>,
    /// Retains the same-key release channel while the OS lock is held.
    gate: Arc<AsyncGate>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CacheLockGuard {
    /// Open a cache lock file and hold exclusive access until the returned guard drops.
    ///
    /// This may block while another process holds the lock. Async callers should use
    /// [`Self::acquire_async`] or call this from `tokio::task::spawn_blocking`.
    pub(crate) fn acquire(path: &Path) -> ImageResult<Self> {
        let key = Self::canonical_lock_path(path)?;
        let gate = ASYNC_LOCK_GATES
            .get_or_init(AsyncGateRegistry::new)
            .gate(&key);
        let file = Self::open_lock_file(&key)?;
        microsandbox_utils::process_lock::lock_exclusive(&file).map_err(ImageError::Io)?;

        Ok(Self {
            file: Some(file),
            gate,
        })
    }

    /// Acquire an exclusive cache lock without parking an async blocking worker.
    pub(crate) async fn acquire_async(path: &Path) -> ImageResult<Self> {
        let path = path.to_path_buf();
        let path = tokio::task::spawn_blocking(move || Self::canonical_lock_path(&path))
            .await
            .map_err(|error| ImageError::Io(io::Error::other(error)))??;
        let gate = ASYNC_LOCK_GATES
            .get_or_init(AsyncGateRegistry::new)
            .gate_async(&path)
            .await;
        let _waiter = gate.lock().await;
        let mut generation = gate.generation.subscribe();
        let mut delay = LOCK_RETRY_INITIAL_DELAY;
        let started = Instant::now();
        let mut warned = false;
        let mut attempt = 0;

        loop {
            generation.borrow_and_update();
            let attempt_path = path.clone();
            let attempt_gate = Arc::clone(&gate);
            let guard = tokio::task::spawn_blocking(move || {
                let file = Self::open_lock_file(&attempt_path)?;
                Ok::<_, ImageError>(
                    microsandbox_utils::process_lock::try_lock_exclusive(&file)?.then(|| Self {
                        file: Some(file),
                        gate: attempt_gate,
                    }),
                )
            })
            .await
            .map_err(|error| ImageError::Io(io::Error::other(error)))??;
            if let Some(guard) = guard {
                return Ok(guard);
            }

            if !warned && started.elapsed() >= Duration::from_secs(5) {
                tracing::warn!(path = %path.display(), "still waiting for cache artifact lock");
                warned = true;
            }

            tokio::select! {
                changed = generation.changed() => {
                    changed.map_err(|error| ImageError::Io(io::Error::other(error)))?;
                }
                _ = tokio::time::sleep(jittered_delay(&path, delay, attempt)) => {}
            }
            delay = delay.saturating_mul(2).min(LOCK_RETRY_MAX_DELAY);
            attempt += 1;
        }
    }

    /// Open (or create) a zero-byte lock file for cross-process coordination.
    fn open_lock_file(path: &Path) -> ImageResult<File> {
        microsandbox_utils::process_lock::open_lock_file(path).map_err(|e| ImageError::Cache {
            path: path.to_path_buf(),
            source: e,
        })
    }

    fn canonical_lock_path(path: &Path) -> ImageResult<PathBuf> {
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::other("cache lock has no filename"))?;

        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("cache lock has no parent"))?;
        Ok(parent.canonicalize()?.join(name))
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for CacheLockGuard {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            let _ = microsandbox_utils::process_lock::unlock(&file);
            drop(file);
        }
        self.gate.notify_release();
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn local_release_wakes_waiter_without_advancing_retry_time() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("artifact.lock");
        let held = CacheLockGuard::acquire(&path).unwrap();
        let waiter_path = path.clone();
        let waiter = tokio::spawn(async move { CacheLockGuard::acquire_async(&waiter_path).await });
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(!waiter.is_finished());

        tokio::time::pause();
        drop(held);
        let deadline = Instant::now() + Duration::from_secs(1);
        while !waiter.is_finished() && Instant::now() < deadline {
            tokio::task::yield_now().await;
        }

        assert!(
            waiter.is_finished(),
            "local handoff must not wait for the retry timer"
        );
        drop(waiter.await.unwrap().unwrap());
    }

    #[test]
    fn async_wait_does_not_occupy_the_blocking_pool() {
        let directory = tempfile::tempdir().unwrap();
        let lock_path = directory.path().join("artifact.lock");
        let held_guard = CacheLockGuard::acquire(&lock_path).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .max_blocking_threads(1)
            .enable_time()
            .build()
            .unwrap();

        runtime.block_on(async move {
            let waiter_path = lock_path.clone();
            let waiter =
                tokio::spawn(async move { CacheLockGuard::acquire_async(&waiter_path).await });
            tokio::time::sleep(Duration::from_millis(20)).await;

            let marker =
                tokio::time::timeout(Duration::from_secs(1), tokio::task::spawn_blocking(|| 42))
                    .await
                    .expect("a lock waiter must not monopolize the only blocking thread")
                    .unwrap();
            assert_eq!(marker, 42);

            drop(held_guard);
            let guard = tokio::time::timeout(Duration::from_secs(1), waiter)
                .await
                .expect("the waiter should acquire the released lock")
                .unwrap()
                .unwrap();
            drop(guard);
            let probe = CacheLockGuard::open_lock_file(&lock_path).unwrap();
            assert!(
                microsandbox_utils::process_lock::try_lock_exclusive(&probe).unwrap(),
                "dropping the async guard should release its lock"
            );
        });
    }
}

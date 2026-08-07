//! Shared synchronization helpers for crate unit tests.

use std::sync::{Mutex, MutexGuard};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Serializes process-global environment mutation across SDK unit tests.
static ENV_LOCK: Mutex<()> = Mutex::new(());

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Lock process-global environment mutation for the duration of a unit test.
pub(crate) fn lock_env() -> MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner())
}

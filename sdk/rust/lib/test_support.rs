//! Isolated backend construction and synchronization helpers for crate unit tests.

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

/// Construct a cloud backend with explicitly empty config sources, independent of the host.
pub(crate) fn cloud_backend(
    url: impl Into<String>,
    api_key: impl Into<String>,
) -> crate::MicrosandboxResult<crate::CloudBackend> {
    crate::CloudBackend::builder()
        .url(url)
        .api_key(api_key)
        .config_sources(crate::config::layers::BackendConfig::new(
            Default::default(),
            Default::default(),
        ))
        .build()
}

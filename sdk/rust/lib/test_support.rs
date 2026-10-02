//! Fixture decoding, isolated backend construction, and synchronization for crate unit tests.

use std::sync::{Mutex, MutexGuard};

pub(crate) mod fixtures;
mod json;

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
#[cfg(feature = "cloud")]
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

/// Construct a local backend from explicit settings without reading machine configuration.
#[cfg(feature = "local")]
pub(crate) fn local_backend(config: crate::config::GlobalConfig) -> crate::LocalBackend {
    crate::LocalBackend::from_backend_config(
        crate::config::layers::BackendConfig::new(
            crate::config::GlobalConfigPatch::from_present_fields(config),
            Default::default(),
        ),
        crate::BackendSelectionSource::Programmatic,
        None,
    )
}

/// Build against user and managed config files inside a test's temporary home.
/// Runtime environment paths are still honored for live runtime fixtures.
#[cfg(feature = "local")]
pub(crate) fn local_backend_builder(
    home: impl AsRef<std::path::Path>,
) -> crate::backend::local::LocalBackendBuilder {
    let home = home.as_ref();
    crate::LocalBackend::builder()
        .config_path(home.join("config.json"))
        .managed_config_path(home.join("managed.json"))
        .home(home)
}

//! Observe explicit backend intent without constructing a backend for diagnostics.

use crate::MicrosandboxResult;
use crate::config::layers::BackendConfig;

use super::BackendInfo;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Immutable backend selection and settings, without touching the backend's database.
pub(crate) struct BackendInspection {
    pub(crate) info: BackendInfo,
    pub(crate) config: Option<BackendConfig>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// A scoped or already-selected backend takes precedence over ambient config. Never initialize
/// DEFAULT here: its normal local backend is allowed to initialize and migrate a catalog.
pub(crate) fn initialized_backend_config() -> MicrosandboxResult<Option<BackendInspection>> {
    if let Ok(scoped) = super::SCOPED_BACKEND.try_with(|backend| backend.clone()) {
        return capture(scoped.as_ref()).map(Some);
    }
    match super::DEFAULT.get() {
        Some(cell) => {
            let backend = cell
                .read()
                .expect("DEFAULT backend RwLock poisoned")
                .clone();
            capture(backend.as_ref()).map(Some)
        }
        None => Ok(None),
    }
}

fn capture(backend: &dyn super::Backend) -> MicrosandboxResult<BackendInspection> {
    Ok(BackendInspection {
        info: backend.info()?,
        config: BackendConfig::for_backend(backend).cloned(),
    })
}

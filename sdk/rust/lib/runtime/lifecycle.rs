//! Shared ownership of a sandbox runtime namespace.

use std::path::Path;
use std::time::Duration;

use microsandbox_runtime::ipc::SandboxLifecycleGuard;

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Wait until no runtime generation owns a sandbox's deterministic namespace.
pub(crate) async fn acquire_sandbox_lifecycle_guard(
    run_dir: &Path,
    name: &str,
    timeout: Duration,
) -> MicrosandboxResult<SandboxLifecycleGuard> {
    SandboxLifecycleGuard::acquire(run_dir, name, timeout)
        .await?
        .ok_or_else(|| {
            MicrosandboxError::SandboxStillRunning(format!(
                "sandbox {name:?} runtime still owns its lifecycle lock"
            ))
        })
}

//! Receiver-identity-bound diagnostics for external filesystem restoration.

#[cfg(feature = "local")]
use crate::backend::LocalBackend;
use crate::{MicrosandboxError, MicrosandboxResult};

use super::{ExternalMountWarning, Sandbox};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Read structured storage-health warnings from an explicitly relaxed full restore.
    /// An empty list means no external resource was degraded by that restore.
    pub async fn restore_warnings(&self) -> MicrosandboxResult<Vec<ExternalMountWarning>> {
        #[cfg(feature = "local")]
        if let Some(local) = self.backend.as_local() {
            // A stale receiver must never read diagnostics from a replacement run.
            let _transition = LocalBackend::acquire_sandbox_transition_guard(
                &local.config().run_dir(),
                &self.name,
            )
            .await?;
            self.refresh_handle().await?;
            let path = local
                .sandboxes_dir()
                .join(&self.name)
                .join("restore-mount-warnings.json");
            return match tokio::fs::read(path).await {
                Ok(bytes) => serde_json::from_slice(&bytes).map_err(MicrosandboxError::from),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
                Err(error) => Err(error.into()),
            };
        }
        Err(MicrosandboxError::InvalidConfig(
            "external mount restore diagnostics require the local backend".into(),
        ))
    }
}

//! Shared lifecycle ownership observations and non-consuming detach.

use crate::MicrosandboxResult;

use super::Sandbox;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Binding implementation hook for ownership-aware, awaited scope cleanup.
    ///
    /// Unlike explicit resource-wide stop, this cannot stop a replacement run.
    /// Once cleanup is admitted, concurrent detach does not cancel that shutdown.
    #[doc(hidden)]
    pub async fn shutdown_owned(&self) -> MicrosandboxResult<()> {
        #[cfg(feature = "local")]
        if self.owns_lifecycle()
            && let Some(local) = self.local()
            && let Some(run) = local.owned_run_id
            && let Some(backend) = self.backend.as_local()
        {
            backend
                .stop_owned_generation(&self.name, local.db_id, self.is_local_ephemeral(), run)
                .await?;
            if let Some(handle) = &local.handle {
                handle.lock().await.wait().await?;
            }
        }
        Ok(())
    }

    /// Whether this object shares automatic-shutdown responsibility for its local run.
    ///
    /// Clones share the same ownership group. Detaching any clone disarms that
    /// group; connecting independently or using a remote sandbox never acquires it.
    /// This describes cleanup authority, not whether the process is still running.
    pub fn owns_lifecycle(&self) -> bool {
        #[cfg(feature = "local")]
        {
            self.local().is_some_and(|local| {
                local
                    .cleanup
                    .as_ref()
                    .is_some_and(|cleanup| cleanup.is_armed())
            })
        }
        #[cfg(not(feature = "local"))]
        {
            false
        }
    }

    /// Relinquish automatic shutdown without consuming this sandbox or its clones.
    ///
    /// Repeating detach succeeds. Explicit lifecycle and guest operations remain
    /// available. An independent non-owner cannot disarm another object's owner.
    /// If disarming fails, the error is returned and cleanup remains armed.
    pub async fn detach(&self) -> MicrosandboxResult<()> {
        #[cfg(feature = "local")]
        if let Some(local) = self.local()
            && let Some(cleanup) = &local.cleanup
        {
            // Reap an already exited child when immediately available. A live
            // waiter owns this lock until exit and publishes completion itself.
            if let Some(handle) = &local.handle
                && let Ok(mut process) = handle.try_lock()
            {
                process.try_wait()?;
            }
            // Cleanup control is independent of the process wait lock, so a
            // pending wait never blocks detaching the shared group.
            cleanup.disarm()?;
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "local", unix))]
pub(super) mod tests;

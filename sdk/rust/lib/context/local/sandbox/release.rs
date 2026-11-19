//! Resource fences for replacement and recovery of an old runtime generation.

use std::fs::File;
use std::path::Path;

#[cfg(unix)]
use microsandbox_runtime::ipc::SandboxSocketPaths;

use super::{LocalContext, sandbox_entity};
use crate::sandbox::SandboxConfig;
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LocalContext {
    /// An active launcher owns the transition lock. Without one, an ambiguous
    /// recorded PID must fail preparation rather than leave the caller waiting forever.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) async fn validate_starting_observer(
        &self,
        name: &str,
        id: i32,
    ) -> MicrosandboxResult<()> {
        let run_dir = self.config().run_dir();
        let Some(_transition) =
            microsandbox_runtime::ipc::try_acquire_transition_guard(&run_dir, name)?
        else {
            return Ok(());
        };
        let pools = self.db().await?;
        let latest = Self::load_latest_run(pools.read(), id).await?;
        let lock = microsandbox_runtime::ipc::lifecycle_lock_path(&run_dir, name);
        if let super::runtime_identity::RecordedRuntime::Unverified { pid } =
            Self::recorded_runtime(pools.read(), latest.as_ref(), &lock).await?
        {
            return Err(MicrosandboxError::Runtime(format!(
                "cannot prepare sandbox {name:?}: recorded PID {pid} has unverified ownership"
            )));
        }
        Ok(())
    }

    /// Call with transition and lifecycle guards held. Keep the returned disk
    /// guards until terminal publication or deletion has completed.
    pub(crate) async fn released_sandbox_resources(
        &self,
        model: &sandbox_entity::Model,
    ) -> MicrosandboxResult<Vec<File>> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let latest = Self::load_latest_run(self.db().await?.read(), model.id).await?;
            let lock = microsandbox_runtime::ipc::lifecycle_lock_path(
                &self.config().run_dir(),
                &model.name,
            );
            match Self::recorded_runtime(self.db().await?.read(), latest.as_ref(), &lock).await? {
                super::runtime_identity::RecordedRuntime::Unverified { pid } => {
                    return Err(MicrosandboxError::Runtime(format!(
                        "cannot release sandbox {:?}: recorded PID {pid} has unverified ownership",
                        model.name
                    )));
                }
                super::runtime_identity::RecordedRuntime::Live(_) => {
                    return Err(MicrosandboxError::SandboxStillRunning(model.name.clone()));
                }
                _ => {}
            }
        }
        Self::released_runtime_disks(
            &self.config().run_dir(),
            &self.sandboxes_dir().join(&model.name),
            model,
        )
        .await
    }

    /// The caller retains transition and lifecycle ownership through mutation.
    /// Returned disk guards must outlive terminal publication or storage deletion.
    pub(super) async fn released_runtime_disks(
        run_dir: &Path,
        sandbox_dir: &Path,
        model: &sandbox_entity::Model,
    ) -> MicrosandboxResult<Vec<File>> {
        let uncertain = || {
            MicrosandboxError::SandboxStillRunning(format!(
                "cannot release sandbox {:?}: runtime endpoints or owned disks may still be in use",
                model.name
            ))
        };
        #[cfg(unix)]
        let sandboxes = sandbox_dir.parent().ok_or_else(uncertain)?;
        #[cfg(unix)]
        if SandboxSocketPaths::in_sandboxes_dir(run_dir, sandboxes, &model.name)
            .may_be_live()
            .await?
        {
            return Err(uncertain());
        }
        let _ = run_dir;
        let config: SandboxConfig = serde_json::from_str(&model.config)?;
        crate::runtime::owned_volumes::try_acquire_disk_guards(sandbox_dir, &config.spec.mounts)?
            .ok_or_else(uncertain)
    }
}

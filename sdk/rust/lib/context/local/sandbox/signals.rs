//! Signal the runtime selected under the sandbox transition guard.

use std::time::Duration;

use microsandbox_runtime::ipc::{
    SandboxSocketPaths, lifecycle_lock_path, try_acquire_lifecycle_guard,
};

use super::{LocalContext, process_exit::RuntimeExit, run_entity, sandbox_entity};
use crate::sandbox::{SandboxConfig, SandboxStatus};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LocalContext {
    /// Returns an exit observer only when the signal was delivered.
    pub(super) async fn signal_runtime(
        &self,
        model: &sandbox_entity::Model,
        pid: Option<i32>,
        signal: libc::c_int,
    ) -> MicrosandboxResult<Option<RuntimeExit>> {
        let name = &model.name;
        let run_dir = self.config().run_dir();
        let observer = match RuntimeExit::capture(pid, &lifecycle_lock_path(&run_dir, name)) {
            // A recycled PID may belong to another user. Authorize reconciliation
            // only through the independent ownership checks below.
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => None,
            result => result?,
        };
        if let Some(observer) = observer {
            if observer.send_signal(signal)? {
                return Ok(Some(observer));
            }
            // Darwin can observe a process already exiting after it closed its
            // identity descriptor. Wait only on that captured process.
            tokio::time::timeout(Duration::from_secs(5), async {
                while !observer.has_exited()? {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                Ok::<_, std::io::Error>(())
            })
            .await
            .map_err(|_| {
                MicrosandboxError::Runtime(format!("sandbox {name:?} runtime is still exiting"))
            })??;
        }

        // An absent identity descriptor alone does not prove the sandbox stopped.
        // Fence current and legacy runtimes before retiring this catalog generation.
        let uncertain = || {
            MicrosandboxError::Runtime(format!(
                "cannot prove runtime ownership for sandbox {name:?}"
            ))
        };
        let _owner = try_acquire_lifecycle_guard(&run_dir, name)?.ok_or_else(uncertain)?;
        let sandboxes = self.sandboxes_dir();
        if SandboxSocketPaths::in_sandboxes_dir(&run_dir, &sandboxes, name)
            .may_be_live()
            .await?
        {
            return Err(uncertain());
        }
        let config: SandboxConfig = serde_json::from_str(&model.config)?;
        let _disks = crate::runtime::owned_volumes::try_acquire_disk_guards(
            &sandboxes.join(name),
            &config.spec.mounts,
        )?
        .ok_or_else(uncertain)?;
        let pools = self.db().await?;
        let active = Self::load_active_run(pools.read(), model.id).await?;
        let (status, reason) = if signal == libc::SIGKILL {
            (
                SandboxStatus::Stopped,
                run_entity::TerminationReason::InternalError,
            )
        } else {
            Self::stale_runtime_terminal_state(model.status)
        };
        Self::mark_sandbox_runtime_stale(
            pools.write(),
            model.id,
            active.map(|run| run.id),
            status,
            reason,
        )
        .await?;
        Ok(None)
    }
}

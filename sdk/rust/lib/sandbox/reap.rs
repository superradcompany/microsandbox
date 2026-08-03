//! Identity-checked cleanup for Windows sandbox runtime processes.

use std::time::{Duration, Instant};

use microsandbox_db::entity::run as run_entity;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};

use crate::{MicrosandboxResult, runtime::reap};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// What [`reap_leaked_runtime_process`] established about the recorded run PID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LeakedReapVerdict {
    /// No live runtime process remains (already dead, or terminated here).
    NoProcess,

    /// A live process holds the PID but is provably not the runtime; it was left alone.
    RecycledPid,

    /// The live process could not be queried, so its ownership is unknown and it was left alone.
    Unverifiable,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Terminate a leftover VM process only when its identity matches the sandbox's latest run.
///
/// A stopped database row can still have a Windows VM process serving the sandbox's named pipes.
/// Checking the recorded start time and image before termination prevents a recycled PID from
/// causing an unrelated process to be killed.
pub(crate) async fn reap_leaked_runtime_process(
    local_backend: &crate::backend::LocalBackend,
    sandbox_id: i32,
    name: &str,
) -> MicrosandboxResult<LeakedReapVerdict> {
    let pools = local_backend.db().await?;
    let run = run_entity::Entity::find()
        .filter(run_entity::Column::SandboxId.eq(sandbox_id))
        .order_by_desc(run_entity::Column::Id)
        .one(pools.read())
        .await?;
    let Some(run) = run else {
        return Ok(LeakedReapVerdict::NoProcess);
    };
    let (Some(pid), Some(started_at)) = (run.pid, run.started_at) else {
        return Ok(LeakedReapVerdict::NoProcess);
    };
    let Ok(pid_u32) = u32::try_from(pid) else {
        return Ok(LeakedReapVerdict::NoProcess);
    };
    if !pid_is_alive(pid) {
        return Ok(LeakedReapVerdict::NoProcess);
    }

    let outcome =
        reap::terminate_runtime_process_checked(pid_u32, started_at.and_utc().timestamp_micros());
    match outcome {
        Ok(reap::ReapOutcome::AlreadyDead) => return Ok(LeakedReapVerdict::NoProcess),
        Ok(reap::ReapOutcome::IdentityMismatch) => {
            tracing::warn!(
                pid,
                sandbox = %name,
                "recorded runtime PID is now a different process (recycled); leaving it alone"
            );
            return Ok(LeakedReapVerdict::RecycledPid);
        }
        Ok(reap::ReapOutcome::Unverifiable) => {
            tracing::warn!(
                pid,
                sandbox = %name,
                "recorded runtime PID cannot be queried (likely recycled); leaving it alone"
            );
            return Ok(LeakedReapVerdict::Unverifiable);
        }
        Ok(reap::ReapOutcome::Terminated) => {
            tracing::warn!(pid, sandbox = %name, "terminated leftover sandbox VM process");
        }
        // Termination can fail while a verified process is already exiting. The liveness check
        // below is authoritative, so wait before deciding whether cleanup failed.
        Err(err) => {
            tracing::warn!(
                pid,
                sandbox = %name,
                error = %err,
                "failed to terminate leftover sandbox VM process; waiting for exit"
            );
        }
    }

    wait_for_pids_to_exit(&[pid], reap::REAP_EXIT_WAIT).await;
    if pid_is_alive(pid) {
        return Err(crate::MicrosandboxError::Runtime(format!(
            "sandbox process {pid} for '{name}' is still running after termination"
        )));
    }

    Ok(LeakedReapVerdict::NoProcess)
}

fn pid_is_alive(pid: i32) -> bool {
    microsandbox_utils::process::pid_is_alive(pid)
}

async fn wait_for_pids_to_exit(pids: &[i32], timeout: Duration) {
    let start = Instant::now();
    let poll_interval = Duration::from_millis(50);

    loop {
        if pids.iter().all(|pid| !pid_is_alive(*pid)) || start.elapsed() >= timeout {
            return;
        }

        tokio::time::sleep(poll_interval).await;
    }
}

//! Recover per-sandbox private writeback leases before removing a stopped sandbox.

use std::fs::File;
use std::io;
use std::path::Path;

use microsandbox_db::{
    DbReadConnection, DbWriteConnection,
    entity::{run, writeback_allocation},
};
use microsandbox_runtime::writeback_recovery::{is_valid_lease_name, recover_stale_allocation};
use microsandbox_utils::process_lock;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

use crate::{
    MicrosandboxError, MicrosandboxResult,
    context::LocalContext,
    host_file::{self, HostFileAccess, HostFileKind, HostFilePolicy},
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Recover and clear any remaining `writeback_allocation` rows backed by a
/// sandbox's private `sandboxes/<name>/runtime-leases/writeback` directory.
pub(super) async fn recover(
    local: &LocalContext,
    read: &DbReadConnection,
    write: &DbWriteConnection,
    name: &str,
    sandbox_id: i32,
) -> MicrosandboxResult<()> {
    // The caller holds transition and lifecycle ownership. No new runtime for
    // this sandbox can start until removal or recovery completes.
    let runs: Vec<i32> = run::Entity::find()
        .filter(run::Column::SandboxId.eq(sandbox_id))
        .all(read)
        .await?
        .into_iter()
        .map(|run| run.id)
        .collect();
    if runs.is_empty() {
        return Ok(());
    }

    let allocations = writeback_allocation::Entity::find()
        .filter(writeback_allocation::Column::RunId.is_in(runs))
        .all(read)
        .await?;
    if allocations.is_empty() {
        return Ok(());
    }

    let private_dir = local.private_writeback_lease_dir(name);
    let shared_dir = local.config().run_dir().join("writeback-leases");
    let policy = HostFilePolicy::strict_beneath(local.config().home());

    let leases = tokio::task::spawn_blocking(move || -> MicrosandboxResult<_> {
        let mut leases = Vec::with_capacity(allocations.len());
        for allocation in allocations {
            if !is_valid_lease_name(&allocation.id, &allocation.lease_name) {
                return Err(MicrosandboxError::Runtime(
                    "invalid private writeback lease identity".into(),
                ));
            }
            let lease = open_lease(&private_dir, &shared_dir, &allocation.lease_name, &policy)?;
            if !process_lock::try_lock_exclusive(&lease)? {
                return Err(MicrosandboxError::Runtime(format!(
                    "writeback lease {} is still held by a live runtime",
                    allocation.lease_name
                )));
            }
            recover_stale_allocation(&allocation)
                .map_err(|error| MicrosandboxError::Runtime(error.to_string()))?;
            leases.push((allocation, lease));
        }
        Ok(leases)
    })
    .await
    .map_err(|error| MicrosandboxError::Runtime(error.to_string()))??;

    for (allocation, _lease) in leases {
        // Keep each exact lease locked through deletion. An unavailable device,
        // live lock, or failed sync leaves reservation and recovery files intact.
        let removed = writeback_allocation::Entity::delete_many()
            .filter(writeback_allocation::Column::Id.eq(allocation.id))
            .filter(writeback_allocation::Column::RunId.eq(allocation.run_id))
            .filter(writeback_allocation::Column::LeaseName.eq(allocation.lease_name))
            .filter(writeback_allocation::Column::BootId.eq(allocation.boot_id))
            .filter(writeback_allocation::Column::BackingDevices.eq(allocation.backing_devices))
            .exec(write)
            .await?;
        if removed.rows_affected != 1 {
            return Err(MicrosandboxError::Runtime(
                "writeback reservation changed during removal; retaining recovery state".into(),
            ));
        }
    }

    Ok(())
}

/// Open a writeback lease file strictly (no symlinks), preferring the sandbox's
/// private lease directory and falling back to the shared directory for rows
/// created before `private_writeback_leases` was enabled.
fn open_lease(
    private_dir: &Path,
    shared_dir: &Path,
    lease_name: &str,
    policy: &HostFilePolicy,
) -> io::Result<File> {
    match host_file::open(
        &private_dir.join(lease_name),
        HostFileKind::Regular,
        HostFileAccess::ReadWrite,
        policy,
    ) {
        Ok(file) => Ok(file),
        Err(err) if err.kind() == io::ErrorKind::NotFound => host_file::open(
            &shared_dir.join(lease_name),
            HostFileKind::Regular,
            HostFileAccess::ReadWrite,
            policy,
        ),
        Err(err) => Err(err),
    }
}

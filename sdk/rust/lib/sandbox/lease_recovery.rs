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

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::os::unix::fs::MetadataExt;

    use chrono::Utc;
    use microsandbox_db::entity::{run, sandbox as sandbox_entity, writeback_allocation};
    use microsandbox_runtime::writeback_recovery::{current_boot_id, device_id};
    use microsandbox_utils::process_lock;
    use sea_orm::{ActiveModelTrait, EntityTrait, Set};

    use super::recover;
    use crate::context::LocalContext;
    use crate::sandbox::remove_local_persisted_sandbox;

    async fn insert_stopped_sandbox_run(local: &LocalContext, name: &str) -> (i32, i32) {
        let pools = local.db().await.unwrap();
        let sandbox_id = sandbox_entity::ActiveModel {
            name: Set(name.to_string()),
            config: Set("{}".to_string()),
            status: Set(sandbox_entity::SandboxStatus::Stopped),
            ephemeral: Set(false),
            ..Default::default()
        }
        .insert(pools.write())
        .await
        .unwrap()
        .id;
        let run_id = run::Entity::insert(run::ActiveModel {
            sandbox_id: Set(sandbox_id),
            status: Set(run::RunStatus::Terminated),
            started_at: Set(Some(Utc::now().naive_utc())),
            terminated_at: Set(Some(Utc::now().naive_utc())),
            ..Default::default()
        })
        .exec(pools.write())
        .await
        .unwrap()
        .last_insert_id;
        (sandbox_id, run_id)
    }

    async fn insert_allocation(
        local: &LocalContext,
        run_id: i32,
        id: &str,
        lease_name: &str,
        boot_id: &str,
        backing_devices: &str,
    ) {
        let pools = local.db().await.unwrap();
        let now = Utc::now().naive_utc();
        writeback_allocation::ActiveModel {
            id: Set(id.to_string()),
            run_id: Set(run_id),
            lease_name: Set(lease_name.to_string()),
            per_disk_limit_bytes: Set(128 * 1024 * 1024),
            disk_count: Set(1),
            reserved_bytes: Set(128 * 1024 * 1024),
            pool_bytes: Set(512 * 1024 * 1024),
            boot_id: Set(boot_id.to_string()),
            backing_devices: Set(backing_devices.to_string()),
            created_at: Set(now),
        }
        .insert(pools.write())
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn recover_clears_private_and_shared_fallback_leases_and_rejects_live_or_symlinked_locks()
    {
        let home = tempfile::tempdir().unwrap();
        let local = LocalContext::builder()
            .home(home.path())
            .private_writeback_leases(true)
            .build()
            .unwrap();
        let (sandbox_id, run_id) = insert_stopped_sandbox_run(&local, "wb-recover").await;
        let pools = local.db().await.unwrap();

        let private_dir = local.private_writeback_lease_dir("wb-recover");
        let shared_dir = local.config().run_dir().join("writeback-leases");
        fs::create_dir_all(&private_dir).unwrap();
        fs::create_dir_all(&shared_dir).unwrap();

        let dev = device_id(fs::metadata(home.path()).unwrap().dev());
        let dev_str = format!("{}:{}", dev.major, dev.minor);
        let boot_upper = current_boot_id().unwrap().to_ascii_uppercase();

        // 1. Live flock must block recovery and keep the DB row intact.
        let live_id = "0123456789abcdef0123456789abcdef";
        let live_name = format!("{live_id}.lock");
        let live_file = File::create(private_dir.join(&live_name)).unwrap();
        assert!(process_lock::try_lock_exclusive(&live_file).unwrap());
        insert_allocation(&local, run_id, live_id, &live_name, &boot_upper, &dev_str).await;

        let err = recover(
            &local,
            pools.read(),
            pools.write(),
            "wb-recover",
            sandbox_id,
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("still held by a live runtime"),
            "{err}"
        );
        assert_eq!(
            writeback_allocation::Entity::find()
                .all(pools.read())
                .await
                .unwrap()
                .len(),
            1
        );
        drop(live_file);

        // 2. Also add a prior-boot row in the shared fallback dir; both recover cleanly.
        let fallback_run_id = run::Entity::insert(run::ActiveModel {
            sandbox_id: Set(sandbox_id),
            status: Set(run::RunStatus::Terminated),
            started_at: Set(Some(Utc::now().naive_utc())),
            terminated_at: Set(Some(Utc::now().naive_utc())),
            ..Default::default()
        })
        .exec(pools.write())
        .await
        .unwrap()
        .last_insert_id;
        let fallback_id = "fedcba9876543210fedcba9876543210";
        let fallback_name = format!("{fallback_id}.lock");
        File::create(shared_dir.join(&fallback_name)).unwrap();
        insert_allocation(
            &local,
            fallback_run_id,
            fallback_id,
            &fallback_name,
            "00000000-0000-0000-0000-000000000000",
            "9999:9999",
        )
        .await;

        recover(
            &local,
            pools.read(),
            pools.write(),
            "wb-recover",
            sandbox_id,
        )
        .await
        .unwrap();
        assert!(
            writeback_allocation::Entity::find()
                .all(pools.read())
                .await
                .unwrap()
                .is_empty()
        );

        // 3. Symlinked lease file must be rejected and leave the row intact.
        let sym_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let sym_name = format!("{sym_id}.lock");
        let target = home.path().join("outside-lease");
        File::create(&target).unwrap();
        std::os::unix::fs::symlink(&target, private_dir.join(&sym_name)).unwrap();
        insert_allocation(
            &local,
            run_id,
            sym_id,
            &sym_name,
            "00000000-0000-0000-0000-000000000000",
            &dev_str,
        )
        .await;
        assert!(
            recover(
                &local,
                pools.read(),
                pools.write(),
                "wb-recover",
                sandbox_id
            )
            .await
            .is_err()
        );
        assert_eq!(
            writeback_allocation::Entity::find()
                .all(pools.read())
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn remove_sandbox_recovers_existing_private_leases_even_when_option_is_disabled() {
        let home = tempfile::tempdir().unwrap();
        let local = LocalContext::builder()
            .home(home.path())
            .private_writeback_leases(false)
            .build()
            .unwrap();
        let (sandbox_id, run_id) = insert_stopped_sandbox_run(&local, "wb-disabled-remove").await;
        let pools = local.db().await.unwrap();

        let private_dir = local.private_writeback_lease_dir("wb-disabled-remove");
        fs::create_dir_all(&private_dir).unwrap();
        let id = "11111111111111111111111111111111";
        let lease_name = format!("{id}.lock");
        File::create(private_dir.join(&lease_name)).unwrap();
        insert_allocation(
            &local,
            run_id,
            id,
            &lease_name,
            "00000000-0000-0000-0000-000000000000",
            "0:0",
        )
        .await;

        remove_local_persisted_sandbox(&local, "wb-disabled-remove", sandbox_id)
            .await
            .unwrap();

        assert!(
            writeback_allocation::Entity::find()
                .all(pools.read())
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            sandbox_entity::Entity::find_by_id(sandbox_id)
                .one(pools.read())
                .await
                .unwrap()
                .is_none()
        );
        assert!(!local.sandboxes_dir().join("wb-disabled-remove").exists());
    }
}

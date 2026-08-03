//! Crash-releasing dirty-credit reservations acquired once per VM boot.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use microsandbox_db::DbWriteConnection;
use microsandbox_db::entity::writeback_allocation;
use microsandbox_utils::process_lock;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};

use crate::{RuntimeError, RuntimeResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Process-held reservation from the host-global buffered-writeback pool.
pub(crate) struct WritebackAdmissionGuard {
    lease: Option<AllocationLease>,
}

struct AllocationLease {
    allocation_id: String,
    lease_path: PathBuf,
    file: File,
    released: AtomicBool,
}

struct StaleAllocation {
    id: String,
    lease_name: String,
    lease_path: PathBuf,
    file: File,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl WritebackAdmissionGuard {
    /// Removes catalog state and releases the process-held reservation.
    pub(crate) async fn release(&self, db: &DbWriteConnection) -> RuntimeResult<()> {
        if let Some(lease) = &self.lease {
            lease.release(db).await?;
        }
        Ok(())
    }
}

impl AllocationLease {
    async fn release(&self, db: &DbWriteConnection) -> RuntimeResult<()> {
        if self.released.load(Ordering::Acquire) {
            return Ok(());
        }

        writeback_allocation::Entity::delete_many()
            .filter(writeback_allocation::Column::Id.eq(self.allocation_id.clone()))
            .exec(db)
            .await?;
        process_lock::unlock(&self.file)?;
        self.released.store(true, Ordering::Release);
        if let Err(error) = std::fs::remove_file(&self.lease_path)
            && error.kind() != io::ErrorKind::NotFound
        {
            tracing::debug!(path = %self.lease_path.display(), %error, "remove writeback lease file");
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Reserves aggregate dirty credit for every eligible disk attached to one VM.
pub(crate) async fn acquire(
    db: &DbWriteConnection,
    run_id: i32,
    lease_dir: &Path,
    pool_bytes: Option<u64>,
    per_disk_limit_bytes: Option<u64>,
    disk_count: usize,
) -> RuntimeResult<WritebackAdmissionGuard> {
    let (Some(pool_bytes), Some(per_disk_limit_bytes)) = (pool_bytes, per_disk_limit_bytes) else {
        return Ok(WritebackAdmissionGuard { lease: None });
    };
    if disk_count == 0 {
        return Ok(WritebackAdmissionGuard { lease: None });
    }

    let requested_bytes = reservation_bytes(per_disk_limit_bytes, disk_count)?;
    if requested_bytes > pool_bytes {
        return Err(pool_exhausted_error(
            requested_bytes,
            0,
            pool_bytes,
            per_disk_limit_bytes,
            disk_count,
        ));
    }

    prepare_lease_dir(lease_dir)?;
    let allocation_id = format!("{:032x}", rand::random::<u128>());
    let lease_name = format!("{allocation_id}.lock");
    let lease_path = lease_dir.join(&lease_name);
    let file = process_lock::create_new_lock_file(&lease_path)?;
    process_lock::lock_exclusive(&file)?;

    let started = Instant::now();
    let allocations = match writeback_allocation::Entity::find().all(db).await {
        Ok(allocations) => allocations,
        Err(error) => {
            clean_unpublished_lease(&file, &lease_path);
            return Err(error.into());
        }
    };
    let stale = probe_stale_allocations(lease_dir, &allocations);

    let transaction_result = db
        .transaction(|transaction| {
            let stale = stale
                .iter()
                .map(|entry| (entry.id.clone(), entry.lease_name.clone()))
                .collect::<Vec<_>>();
            let allocation_id = allocation_id.clone();
            let lease_name = lease_name.clone();
            async move {
                for (id, expected_lease_name) in stale {
                    writeback_allocation::Entity::delete_many()
                        .filter(writeback_allocation::Column::Id.eq(id))
                        .filter(writeback_allocation::Column::LeaseName.eq(expected_lease_name))
                        .exec(&transaction)
                        .await?;
                }

                // The capacity check and insert share one retryable SQLite transaction. Concurrent
                // spawns that read the same snapshot cannot both commit: the loser retries and
                // observes the winner before deciding whether capacity remains.
                let active = writeback_allocation::Entity::find()
                    .all(&transaction)
                    .await?;
                let occupied_bytes = total_reserved_bytes(&active)?;
                let admitted_bytes =
                    occupied_bytes.checked_add(requested_bytes).ok_or_else(|| {
                        RuntimeError::Custom("writeback reservation total overflowed u64".into())
                    })?;
                if admitted_bytes > pool_bytes {
                    return Err(pool_exhausted_error(
                        requested_bytes,
                        occupied_bytes,
                        pool_bytes,
                        per_disk_limit_bytes,
                        disk_count,
                    ));
                }

                writeback_allocation::Entity::insert(writeback_allocation::ActiveModel {
                    id: Set(allocation_id.clone()),
                    run_id: Set(run_id),
                    lease_name: Set(lease_name.clone()),
                    per_disk_limit_bytes: Set(to_i64(
                        per_disk_limit_bytes,
                        "per-disk writeback limit",
                    )?),
                    disk_count: Set(i32::try_from(disk_count).map_err(|_| {
                        RuntimeError::Custom("writeback disk count exceeds i32".into())
                    })?),
                    reserved_bytes: Set(to_i64(requested_bytes, "writeback reservation")?),
                    pool_bytes: Set(to_i64(pool_bytes, "writeback pool")?),
                    created_at: Set(chrono::Utc::now().naive_utc()),
                })
                .exec(&transaction)
                .await?;

                Ok::<_, RuntimeError>((transaction, occupied_bytes))
            }
        })
        .await;

    match transaction_result {
        Ok(occupied_bytes) => {
            clean_stale_files(stale);
            tracing::debug!(
                pool_bytes,
                occupied_bytes,
                requested_bytes,
                per_disk_limit_bytes,
                disk_count,
                elapsed_us = started.elapsed().as_micros(),
                "writeback dirty credit admitted"
            );
            Ok(WritebackAdmissionGuard {
                lease: Some(AllocationLease {
                    allocation_id,
                    lease_path,
                    file,
                    released: AtomicBool::new(false),
                }),
            })
        }
        Err(error) => {
            clean_unpublished_lease(&file, &lease_path);
            Err(error)
        }
    }
}

fn reservation_bytes(per_disk_limit_bytes: u64, disk_count: usize) -> RuntimeResult<u64> {
    let disk_count = u64::try_from(disk_count)
        .map_err(|_| RuntimeError::Custom("writeback disk count exceeds u64".into()))?;
    per_disk_limit_bytes
        .checked_mul(disk_count)
        .ok_or_else(|| RuntimeError::Custom("writeback reservation overflowed u64".into()))
}

fn total_reserved_bytes(allocations: &[writeback_allocation::Model]) -> RuntimeResult<u64> {
    allocations.iter().try_fold(0_u64, |total, allocation| {
        let reserved = u64::try_from(allocation.reserved_bytes).map_err(|_| {
            RuntimeError::Custom(format!(
                "writeback allocation {} contains a negative reservation",
                allocation.id
            ))
        })?;
        total
            .checked_add(reserved)
            .ok_or_else(|| RuntimeError::Custom("writeback allocation total overflowed u64".into()))
    })
}

fn to_i64(value: u64, label: &str) -> RuntimeResult<i64> {
    i64::try_from(value).map_err(|_| RuntimeError::Custom(format!("{label} exceeds i64")))
}

fn pool_exhausted_error(
    requested_bytes: u64,
    occupied_bytes: u64,
    pool_bytes: u64,
    per_disk_limit_bytes: u64,
    disk_count: usize,
) -> RuntimeError {
    RuntimeError::Custom(format!(
        "host writeback pool exhausted: requested {requested_bytes} bytes for {disk_count} disk(s) at {per_disk_limit_bytes} bytes each, but {occupied_bytes} of {pool_bytes} bytes is already reserved"
    ))
}

fn probe_stale_allocations(
    lease_dir: &Path,
    allocations: &[writeback_allocation::Model],
) -> Vec<StaleAllocation> {
    let mut stale = Vec::new();
    for allocation in allocations {
        if !is_valid_lease_name(&allocation.id, &allocation.lease_name) {
            // Catalog contents are not trusted as paths. An invalid or unverifiable entry remains
            // charged, which fails closed instead of escaping the private lease directory.
            tracing::warn!(
                allocation_id = %allocation.id,
                lease_name = %allocation.lease_name,
                "writeback allocation has an invalid lease name; preserving reservation"
            );
            continue;
        }
        let lease_path = lease_dir.join(&allocation.lease_name);
        let Ok(file) = process_lock::open_existing_lock_file(&lease_path) else {
            // Missing lease files remain conservatively occupied. This avoids freeing credit when
            // the lease directory is unreadable or has been tampered with.
            continue;
        };
        match process_lock::try_lock_exclusive(&file) {
            Ok(true) => stale.push(StaleAllocation {
                id: allocation.id.clone(),
                lease_name: allocation.lease_name.clone(),
                lease_path,
                file,
            }),
            Ok(false) => {}
            Err(error) => tracing::warn!(
                allocation_id = %allocation.id,
                %error,
                "could not verify writeback allocation lease; preserving reservation"
            ),
        }
    }
    stale
}

fn clean_stale_files(stale: Vec<StaleAllocation>) {
    for entry in stale {
        let _ = process_lock::unlock(&entry.file);
        if let Err(error) = std::fs::remove_file(&entry.lease_path)
            && error.kind() != io::ErrorKind::NotFound
        {
            tracing::debug!(path = %entry.lease_path.display(), %error, "remove stale writeback lease");
        }
    }
}

fn clean_unpublished_lease(file: &File, lease_path: &Path) {
    let _ = process_lock::unlock(file);
    if let Err(error) = std::fs::remove_file(lease_path)
        && error.kind() != io::ErrorKind::NotFound
    {
        tracing::debug!(path = %lease_path.display(), %error, "remove unpublished writeback lease");
    }
}

fn prepare_lease_dir(path: &Path) -> RuntimeResult<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn is_valid_lease_name(allocation_id: &str, lease_name: &str) -> bool {
    allocation_id.len() == 32
        && allocation_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        && lease_name == format!("{allocation_id}.lock")
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use microsandbox_db::DbWriteConnection;
    use microsandbox_db::entity::{run, sandbox, writeback_allocation};
    use microsandbox_migration::{Migrator, MigratorTrait};
    use sea_orm::{ActiveModelTrait, EntityTrait, Set};
    use tempfile::TempDir;

    use super::{acquire, is_valid_lease_name, reservation_bytes};

    async fn test_db() -> (TempDir, DbWriteConnection, Vec<i32>) {
        let dir = tempfile::tempdir().unwrap();
        let db = DbWriteConnection::open(
            &dir.path().join("catalog.db"),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        Migrator::up(db.inner(), None).await.unwrap();

        let sandbox_id = sandbox::ActiveModel {
            name: Set("writeback-admission-test".into()),
            config: Set("{}".into()),
            status: Set(sandbox::SandboxStatus::Running),
            ephemeral: Set(false),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap()
        .id;
        let mut run_ids = Vec::new();
        for _ in 0..3 {
            run_ids.push(
                run::ActiveModel {
                    sandbox_id: Set(sandbox_id),
                    status: Set(run::RunStatus::Running),
                    ..Default::default()
                }
                .insert(&db)
                .await
                .unwrap()
                .id,
            );
        }
        (dir, db, run_ids)
    }

    #[test]
    fn reservation_multiplies_the_per_disk_limit() {
        assert_eq!(reservation_bytes(1280, 3).unwrap(), 3840);
        assert!(reservation_bytes(u64::MAX, 2).is_err());
    }

    #[test]
    fn lease_names_are_derived_from_canonical_allocation_ids() {
        let id = "0123456789abcdef0123456789abcdef";
        assert!(is_valid_lease_name(id, &format!("{id}.lock")));
        assert!(!is_valid_lease_name(id, "../outside.lock"));
        assert!(!is_valid_lease_name("short", "short.lock"));
        assert!(!is_valid_lease_name(
            "0123456789abcdef0123456789abcdeg",
            "0123456789abcdef0123456789abcdeg.lock"
        ));
    }

    #[tokio::test]
    async fn admission_rejects_overcommit_and_reuses_released_credit() {
        let (dir, db, run_ids) = test_db().await;
        let lease_dir = dir.path().join("leases");
        let per_disk = 512 * 1024 * 1024;
        let pool = 2 * per_disk;

        let first = acquire(&db, run_ids[0], &lease_dir, Some(pool), Some(per_disk), 1)
            .await
            .unwrap();
        let second = acquire(&db, run_ids[1], &lease_dir, Some(pool), Some(per_disk), 1)
            .await
            .unwrap();
        let error = match acquire(&db, run_ids[2], &lease_dir, Some(pool), Some(per_disk), 1).await
        {
            Ok(_) => panic!("third reservation unexpectedly exceeded the global pool"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("host writeback pool exhausted"));
        assert_eq!(
            writeback_allocation::Entity::find()
                .all(&db)
                .await
                .unwrap()
                .len(),
            2
        );

        first.release(&db).await.unwrap();
        let third = acquire(&db, run_ids[2], &lease_dir, Some(pool), Some(per_disk), 1)
            .await
            .unwrap();
        assert_eq!(
            writeback_allocation::Entity::find()
                .all(&db)
                .await
                .unwrap()
                .len(),
            2
        );

        second.release(&db).await.unwrap();
        third.release(&db).await.unwrap();
    }

    #[tokio::test]
    async fn disabled_admission_does_not_create_a_lease_or_catalog_row() {
        let (dir, db, run_ids) = test_db().await;
        let lease_dir = dir.path().join("leases");

        let guard = acquire(
            &db,
            run_ids[0],
            &lease_dir,
            None,
            Some(512 * 1024 * 1024),
            1,
        )
        .await
        .unwrap();

        assert!(!lease_dir.exists());
        assert!(
            writeback_allocation::Entity::find()
                .all(&db)
                .await
                .unwrap()
                .is_empty()
        );
        guard.release(&db).await.unwrap();
    }

    #[tokio::test]
    async fn admission_recovers_credit_after_owner_crash() {
        let (dir, db, run_ids) = test_db().await;
        let lease_dir = dir.path().join("leases");
        let limit = 512 * 1024 * 1024;

        let abandoned = acquire(&db, run_ids[0], &lease_dir, Some(limit), Some(limit), 1)
            .await
            .unwrap();
        drop(abandoned);

        let replacement = acquire(&db, run_ids[1], &lease_dir, Some(limit), Some(limit), 1)
            .await
            .unwrap();
        let rows = writeback_allocation::Entity::find().all(&db).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].run_id, run_ids[1]);

        replacement.release(&db).await.unwrap();
    }

    #[tokio::test]
    async fn concurrent_admission_cannot_overcommit_one_credit() {
        let (dir, first_db, run_ids) = test_db().await;
        let second_db = DbWriteConnection::open(
            &dir.path().join("catalog.db"),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        let lease_dir = dir.path().join("leases");
        let limit = 512 * 1024 * 1024;

        let (first, second) = tokio::join!(
            acquire(
                &first_db,
                run_ids[0],
                &lease_dir,
                Some(limit),
                Some(limit),
                1,
            ),
            acquire(
                &second_db,
                run_ids[1],
                &lease_dir,
                Some(limit),
                Some(limit),
                1,
            ),
        );

        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        assert_eq!(
            writeback_allocation::Entity::find()
                .all(&first_db)
                .await
                .unwrap()
                .len(),
            1
        );

        if let Ok(guard) = first {
            guard.release(&first_db).await.unwrap();
        }
        if let Ok(guard) = second {
            guard.release(&second_db).await.unwrap();
        }
    }
}

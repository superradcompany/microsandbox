//! SQLite-backed cooperative CPU allocation and process-held leases.

use std::collections::HashSet;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use microsandbox_db::DbWriteConnection;
use microsandbox_db::entity::{cpu_allocation, cpu_allocation_cpu};
use microsandbox_types::CpuPlacement;
use microsandbox_utils::process_lock;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};

use super::planner::{self, ResolvedPlacement};
use super::topology::{CpuTopology, LogicalCpuId};
use crate::{RuntimeError, RuntimeResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const MAX_ALLOCATION_ATTEMPTS: usize = 5;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(crate) struct AllocationLease {
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

impl AllocationLease {
    pub(crate) async fn release(&self, db: &DbWriteConnection) -> RuntimeResult<()> {
        if self.released.load(Ordering::Acquire) {
            return Ok(());
        }

        cpu_allocation::Entity::delete_many()
            .filter(cpu_allocation::Column::Id.eq(self.allocation_id.clone()))
            .exec(db)
            .await?;
        process_lock::unlock(&self.file)?;
        self.released.store(true, Ordering::Release);
        if let Err(error) = std::fs::remove_file(&self.lease_path)
            && error.kind() != io::ErrorKind::NotFound
        {
            tracing::debug!(path = %self.lease_path.display(), %error, "remove CPU lease file");
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) async fn acquire(
    db: &DbWriteConnection,
    run_id: i32,
    lease_dir: &Path,
    topology: &CpuTopology,
    requested: CpuPlacement,
    max_vcpus: u8,
) -> RuntimeResult<(AllocationLease, ResolvedPlacement, usize)> {
    prepare_lease_dir(lease_dir)?;
    let allocation_id = format!("{:032x}", rand::random::<u128>());
    let lease_name = format!("{allocation_id}.lock");
    let lease_path = lease_dir.join(&lease_name);
    let file = process_lock::create_new_lock_file(&lease_path)?;
    process_lock::lock_exclusive(&file)?;

    for attempt in 0..MAX_ALLOCATION_ATTEMPTS {
        let snapshot_started = Instant::now();
        let allocations = match cpu_allocation::Entity::find().all(db).await {
            Ok(allocations) => allocations,
            Err(error) => {
                clean_unpublished_lease(&file, &lease_path);
                return Err(error.into());
            }
        };
        let cpu_rows = match cpu_allocation_cpu::Entity::find().all(db).await {
            Ok(cpu_rows) => cpu_rows,
            Err(error) => {
                clean_unpublished_lease(&file, &lease_path);
                return Err(error.into());
            }
        };
        let stale = probe_stale_allocations(lease_dir, &allocations);
        let stale_ids: HashSet<_> = stale.iter().map(|entry| entry.id.as_str()).collect();
        let occupied = match cpu_rows
            .iter()
            .filter(|row| !stale_ids.contains(row.allocation_id.as_str()))
            .map(|row| {
                LogicalCpuId::from_catalog_key(row.logical_cpu).map_err(|error| {
                    RuntimeError::Custom(format!(
                        "CPU allocation {} contains invalid logical CPU {}: {error}",
                        row.allocation_id, row.logical_cpu
                    ))
                })
            })
            .collect::<RuntimeResult<HashSet<_>>>()
        {
            Ok(occupied) => occupied,
            Err(error) => {
                clean_unpublished_lease(&file, &lease_path);
                return Err(error);
            }
        };
        let resolved = match planner::plan(topology, &occupied, requested, max_vcpus) {
            Ok(resolved) => resolved,
            Err(error) => {
                clean_unpublished_lease(&file, &lease_path);
                return Err(error);
            }
        };

        let transaction_started = Instant::now();
        let insert_result = db
            .transaction(|transaction| {
                let stale = stale
                    .iter()
                    .map(|entry| (entry.id.clone(), entry.lease_name.clone()))
                    .collect::<Vec<_>>();
                let allocation_id = allocation_id.clone();
                let lease_name = lease_name.clone();
                let topology_fingerprint = topology.fingerprint.clone();
                let reservations = resolved.reservations.clone();
                async move {
                    for (id, expected_lease_name) in stale {
                        cpu_allocation::Entity::delete_many()
                            .filter(cpu_allocation::Column::Id.eq(id))
                            .filter(cpu_allocation::Column::LeaseName.eq(expected_lease_name))
                            .exec(&transaction)
                            .await?;
                    }

                    cpu_allocation::Entity::insert(cpu_allocation::ActiveModel {
                        id: Set(allocation_id.clone()),
                        run_id: Set(run_id),
                        requested_policy: Set(requested.to_string()),
                        resolved_policy: Set(resolved.resolved.to_string()),
                        enforcement: Set("thread-affinity".into()),
                        topology_fingerprint: Set(topology_fingerprint),
                        lease_name: Set(lease_name),
                        state: Set("active".into()),
                        created_at: Set(chrono::Utc::now().naive_utc()),
                    })
                    .exec(&transaction)
                    .await?;

                    for reservation in reservations {
                        cpu_allocation_cpu::Entity::insert(cpu_allocation_cpu::ActiveModel {
                            logical_cpu: Set(reservation.logical_cpu.catalog_key()),
                            allocation_id: Set(allocation_id.clone()),
                            vcpu_index: Set(reservation.vcpu_index.map(i32::from)),
                            role: Set(reservation.role.into()),
                        })
                        .exec(&transaction)
                        .await?;
                    }
                    Ok::<_, RuntimeError>((transaction, ()))
                }
            })
            .await;

        match insert_result {
            Ok(()) => {
                clean_stale_files(stale);
                tracing::debug!(
                    attempt,
                    snapshot_us = snapshot_started.elapsed().as_micros(),
                    transaction_us = transaction_started.elapsed().as_micros(),
                    "CPU allocation committed"
                );
                return Ok((
                    AllocationLease {
                        allocation_id,
                        lease_path,
                        file,
                        released: AtomicBool::new(false),
                    },
                    resolved,
                    attempt,
                ));
            }
            Err(error)
                if is_cpu_uniqueness_conflict(&error) && attempt + 1 < MAX_ALLOCATION_ATTEMPTS =>
            {
                tracing::debug!(attempt, "CPU allocation race lost; re-planning");
            }
            Err(error) => {
                clean_unpublished_lease(&file, &lease_path);
                return Err(error);
            }
        }
    }

    clean_unpublished_lease(&file, &lease_path);
    Err(RuntimeError::Custom(
        "CPU placement exceeded the bounded allocation retry budget".into(),
    ))
}

fn probe_stale_allocations(
    lease_dir: &Path,
    allocations: &[cpu_allocation::Model],
) -> Vec<StaleAllocation> {
    let mut stale = Vec::new();
    for allocation in allocations {
        if !is_valid_lease_name(&allocation.id, &allocation.lease_name) {
            // Catalog contents are not trusted as filesystem paths. Preserve an invalid row as
            // occupied instead of probing a path outside the private lease directory.
            tracing::warn!(
                allocation_id = %allocation.id,
                lease_name = %allocation.lease_name,
                "CPU allocation has an invalid lease name; preserving reservation"
            );
            continue;
        }
        let lease_path = lease_dir.join(&allocation.lease_name);
        let Ok(file) = process_lock::open_existing_lock_file(&lease_path) else {
            // Missing or unverifiable leases remain conservatively occupied.
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
                "could not verify CPU allocation lease; preserving reservation"
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
            tracing::debug!(path = %entry.lease_path.display(), %error, "remove stale CPU lease");
        }
    }
}

fn clean_unpublished_lease(file: &File, lease_path: &Path) {
    let _ = process_lock::unlock(file);
    if let Err(error) = std::fs::remove_file(lease_path)
        && error.kind() != io::ErrorKind::NotFound
    {
        tracing::debug!(path = %lease_path.display(), %error, "remove unpublished CPU lease");
    }
}

fn is_cpu_uniqueness_conflict(error: &RuntimeError) -> bool {
    matches!(
        error,
        RuntimeError::Database(db_error)
            if db_error.to_string().contains("cpu_allocation_cpu.logical_cpu")
                || db_error.to_string().contains("idx_cpu_allocation_cpu_vcpu")
    )
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
    use super::is_valid_lease_name;

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
}

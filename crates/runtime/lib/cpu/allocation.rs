//! SQLite-backed cooperative CPU allocation and process-held leases.

use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use microsandbox_db::DbWriteConnection;
use microsandbox_db::entity::{cpu_allocation, cpu_allocation_cpu, memory_allocation_node};
use microsandbox_utils::process_lock;
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};

use super::PlacementRequest;
use super::planner::{self, ResolvedPlacement};
use super::topology::{CpuTopology, LogicalCpuId};
use crate::{RuntimeError, RuntimeResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const PLANNER_LOCK_NAME: &str = "allocator.lock";
const PLANNER_LOCK_TIMEOUT: Duration = Duration::from_millis(250);
const PLANNER_LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(2);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(crate) struct AllocationLease {
    allocation_id: String,
    lease_path: PathBuf,
    file: File,
    released: AtomicBool,
    shared: bool,
}

/// Short-lived cross-process lock covering the allocation snapshot, plan, and catalog commit.
///
/// CPU load and NUMA memory capacity are aggregate promises that cannot be committed from a stale
/// snapshot. Holding this lock gives both resources one atomic admission boundary. The operating
/// system releases it if the planner process exits unexpectedly.
struct AllocationPlannerLock(File);

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
    pub(crate) async fn reconcile(
        &self,
        db: &DbWriteConnection,
        report: &msb_krun::PlacementReport,
    ) -> RuntimeResult<()> {
        if self.released.load(Ordering::Acquire) {
            return Ok(());
        }

        let allocation_id = self.allocation_id.clone();
        let vcpus = report.vcpus.clone();
        let memory = report.memory.clone();
        let shared = self.shared;
        db.transaction(|transaction| {
            let allocation_id = allocation_id.clone();
            let vcpus = vcpus.clone();
            let memory = memory.clone();
            async move {
                let rows = cpu_allocation_cpu::Entity::find()
                    .filter(cpu_allocation_cpu::Column::AllocationId.eq(allocation_id.clone()))
                    .all(&transaction)
                    .await?;
                if rows.len() != vcpus.len() {
                    return Err(RuntimeError::Custom(format!(
                        "placement report has {} vCPUs but allocation {} has {} planned rows",
                        vcpus.len(),
                        allocation_id,
                        rows.len()
                    )));
                }

                let mut pinned = 0usize;
                for result in &vcpus {
                    let (vcpu_index, reported_cpu) = match result {
                        msb_krun::VcpuPlacementResult::Pinned {
                            vcpu_index,
                            host_cpu,
                        } => (*vcpu_index, Some(*host_cpu)),
                        msb_krun::VcpuPlacementResult::Inherited {
                            vcpu_index,
                            requested_host_cpu,
                            ..
                        } => (*vcpu_index, *requested_host_cpu),
                    };
                    let row = rows
                        .iter()
                        .find(|row| row.vcpu_index == i32::from(vcpu_index))
                        .ok_or_else(|| {
                            RuntimeError::Custom(format!(
                                "placement report references unplanned vCPU {vcpu_index}"
                            ))
                        })?;
                    if let Some(host_cpu) = reported_cpu {
                        let reported_key =
                            ((i64::from(host_cpu.group)) << 16) | i64::from(host_cpu.index);
                        if row.logical_cpu != reported_key {
                            return Err(RuntimeError::Custom(format!(
                                "placement report maps vCPU {vcpu_index} to host CPU {reported_key}, expected {}",
                                row.logical_cpu
                            )));
                        }
                    }

                    match result {
                        msb_krun::VcpuPlacementResult::Pinned { .. } => {
                            pinned += 1;
                            cpu_allocation_cpu::Entity::update_many()
                                .col_expr(cpu_allocation_cpu::Column::Role, Expr::value("assigned"))
                                .filter(
                                    cpu_allocation_cpu::Column::AllocationId
                                        .eq(allocation_id.clone()),
                                )
                                .filter(
                                    cpu_allocation_cpu::Column::VcpuIndex
                                        .eq(i32::from(vcpu_index)),
                                )
                                .exec(&transaction)
                                .await?;
                        }
                        msb_krun::VcpuPlacementResult::Inherited { .. } => {
                            cpu_allocation_cpu::Entity::delete_many()
                                .filter(
                                    cpu_allocation_cpu::Column::AllocationId
                                        .eq(allocation_id.clone()),
                                )
                                .filter(
                                    cpu_allocation_cpu::Column::VcpuIndex
                                        .eq(i32::from(vcpu_index)),
                                )
                                .exec(&transaction)
                                .await?;
                        }
                    }
                }

                if !matches!(memory, msb_krun::MemoryPlacementResult::Applied) {
                    memory_allocation_node::Entity::delete_many()
                        .filter(
                            memory_allocation_node::Column::AllocationId.eq(allocation_id.clone()),
                        )
                        .exec(&transaction)
                        .await?;
                }

                let enforcement = match (pinned, vcpus.len(), shared) {
                    (0, _, _) => "inherited",
                    (count, total, false) if count == total => "thread-affinity-exclusive",
                    (count, total, true) if count == total => "thread-affinity-shared",
                    (_, _, false) => "thread-affinity-partial",
                    (_, _, true) => "thread-affinity-partial-shared",
                };
                cpu_allocation::Entity::update_many()
                    .col_expr(cpu_allocation::Column::Enforcement, Expr::value(enforcement))
                    .col_expr(cpu_allocation::Column::State, Expr::value("active"))
                    .filter(cpu_allocation::Column::Id.eq(allocation_id.clone()))
                    .exec(&transaction)
                    .await?;

                Ok::<_, RuntimeError>((transaction, ()))
            }
        })
        .await
    }

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
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for AllocationPlannerLock {
    fn drop(&mut self) {
        if let Err(error) = process_lock::unlock(&self.0) {
            tracing::warn!(%error, "release allocation planner lock");
        }
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
    request: PlacementRequest,
) -> RuntimeResult<(AllocationLease, ResolvedPlacement, usize)> {
    prepare_lease_dir(lease_dir)?;
    let planner_lock = process_lock::open_lock_file(&lease_dir.join(PLANNER_LOCK_NAME))?;
    lock_planner(&planner_lock).await?;
    let _planner_lock = AllocationPlannerLock(planner_lock);
    let allocation_id = format!("{:032x}", rand::random::<u128>());
    let lease_name = format!("{allocation_id}.lock");
    let lease_path = lease_dir.join(&lease_name);
    let file = process_lock::create_new_lock_file(&lease_path)?;
    process_lock::lock_exclusive(&file)?;

    let attempt = 0;
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
    let memory_rows = match memory_allocation_node::Entity::find().all(db).await {
        Ok(memory_rows) => memory_rows,
        Err(error) => {
            clean_unpublished_lease(&file, &lease_path);
            return Err(error.into());
        }
    };
    let stale = probe_stale_allocations(lease_dir, &allocations);
    let stale_ids: HashSet<_> = stale.iter().map(|entry| entry.id.as_str()).collect();
    let mut loads = BTreeMap::<LogicalCpuId, usize>::new();
    for row in cpu_rows
        .iter()
        .filter(|row| !stale_ids.contains(row.allocation_id.as_str()))
    {
        let logical_cpu = match LogicalCpuId::from_catalog_key(row.logical_cpu) {
            Ok(logical_cpu) => logical_cpu,
            Err(error) => {
                clean_unpublished_lease(&file, &lease_path);
                return Err(RuntimeError::Custom(format!(
                    "CPU allocation {} contains invalid logical CPU {}: {error}",
                    row.allocation_id, row.logical_cpu
                )));
            }
        };
        *loads.entry(logical_cpu).or_default() += 1;
    }
    let mut reserved_memory_mib = BTreeMap::<u32, u64>::new();
    for row in memory_rows
        .iter()
        .filter(|row| !stale_ids.contains(row.allocation_id.as_str()))
    {
        let host_node = u32::try_from(row.host_numa_node).map_err(|_| {
            RuntimeError::Custom(format!(
                "memory allocation {} contains invalid host NUMA node {}",
                row.allocation_id, row.host_numa_node
            ))
        })?;
        let max_mib = u64::try_from(row.max_mib).map_err(|_| {
            RuntimeError::Custom(format!(
                "memory allocation {} contains invalid maximum memory {}",
                row.allocation_id, row.max_mib
            ))
        })?;
        *reserved_memory_mib.entry(host_node).or_default() += max_mib;
    }
    let resolved = match planner::plan(topology, &loads, request, &reserved_memory_mib) {
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
            let memory_nodes = resolved
                .numa
                .as_ref()
                .map(|numa| numa.nodes.clone())
                .unwrap_or_default();
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
                    requested_policy: Set(request.policy.to_string()),
                    resolved_policy: Set(resolved.resolved.to_string()),
                    enforcement: Set("pending".into()),
                    topology_fingerprint: Set(topology_fingerprint),
                    lease_name: Set(lease_name),
                    state: Set("pending".into()),
                    created_at: Set(chrono::Utc::now().naive_utc()),
                })
                .exec(&transaction)
                .await?;

                for reservation in reservations {
                    cpu_allocation_cpu::Entity::insert(cpu_allocation_cpu::ActiveModel {
                        allocation_id: Set(allocation_id.clone()),
                        vcpu_index: Set(i32::from(reservation.vcpu_index.ok_or_else(|| {
                            RuntimeError::Custom(
                                "CPU assignment is missing its guest vCPU index".into(),
                            )
                        })?)),
                        logical_cpu: Set(reservation.logical_cpu.catalog_key()),
                        role: Set(reservation.role.into()),
                    })
                    .exec(&transaction)
                    .await?;
                }
                for node in memory_nodes {
                    memory_allocation_node::Entity::insert(memory_allocation_node::ActiveModel {
                        allocation_id: Set(allocation_id.clone()),
                        guest_numa_node: Set(i32::from(node.guest_node_id)),
                        host_numa_node: Set(i32::try_from(node.host_node_id).map_err(|_| {
                            RuntimeError::Custom(format!(
                                "host NUMA node {} exceeds the catalog range",
                                node.host_node_id
                            ))
                        })?),
                        boot_mib: Set(i64::from(node.boot_memory_mib)),
                        max_mib: Set(i64::from(node.max_memory_mib)),
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
            Ok((
                AllocationLease {
                    allocation_id,
                    lease_path,
                    file,
                    released: AtomicBool::new(false),
                    shared: resolved.shared,
                },
                resolved,
                attempt,
            ))
        }
        Err(error) => {
            clean_unpublished_lease(&file, &lease_path);
            Err(error)
        }
    }
}

async fn lock_planner(file: &File) -> RuntimeResult<()> {
    let started = Instant::now();
    loop {
        if process_lock::try_lock_exclusive(file)? {
            return Ok(());
        }
        if started.elapsed() >= PLANNER_LOCK_TIMEOUT {
            return Err(RuntimeError::Custom(format!(
                "CPU placement planner remained busy for {} ms",
                PLANNER_LOCK_TIMEOUT.as_millis()
            )));
        }
        tokio::time::sleep(PLANNER_LOCK_RETRY_INTERVAL).await;
    }
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
    use std::collections::BTreeMap;
    use std::time::{Duration, Instant};

    use microsandbox_db::DbWriteConnection;
    use microsandbox_db::entity::{
        cpu_allocation, cpu_allocation_cpu, memory_allocation_node, run, sandbox,
    };
    use microsandbox_migration::{Migrator, MigratorTrait};
    use microsandbox_types::{CpuPlacement, MemoryPlacement, NumaPlacement, PlacementProfile};
    use microsandbox_utils::process_lock;
    use sea_orm::{ActiveModelTrait, EntityTrait, Set};

    use super::{PlacementRequest, acquire, is_valid_lease_name, lock_planner};
    use crate::cpu::topology::{CpuTopology, HostNumaNode, LogicalCpu, LogicalCpuId};

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
    async fn planner_lock_wait_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allocator.lock");
        let held = process_lock::open_lock_file(&path).unwrap();
        process_lock::lock_exclusive(&held).unwrap();
        let contender = process_lock::open_lock_file(&path).unwrap();

        let started = Instant::now();
        let error = lock_planner(&contender).await.unwrap_err();

        assert!(error.to_string().contains("remained busy"));
        assert!(started.elapsed() < Duration::from_secs(1));
        process_lock::unlock(&held).unwrap();
    }

    #[tokio::test]
    async fn allocations_share_a_logical_cpu_after_exclusive_capacity_is_used() {
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
            name: Set("cpu-sharing-test".into()),
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
        for _ in 0..2 {
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
        let topology = CpuTopology {
            logical_cpus: vec![LogicalCpu {
                id: LogicalCpuId::new(0),
                package: 0,
                die: 0,
                core: 0,
                numa_node: 0,
                performance_class: 0,
            }],
            numa_nodes: vec![HostNumaNode {
                id: 0,
                package: 0,
                total_memory_mib: 16_384,
                available_memory_mib: 16_384,
                distances: BTreeMap::from([(0, 10)]),
            }],
            fingerprint: "single-logical-cpu".into(),
        };
        let request = PlacementRequest {
            policy: CpuPlacement::Auto,
            max_vcpus: 1,
            boot_memory_mib: 512,
            max_memory_mib: 512,
            profile: None,
        };

        let first = acquire(
            &db,
            run_ids[0],
            &dir.path().join("leases"),
            &topology,
            request,
        )
        .await
        .unwrap();
        let second = acquire(
            &db,
            run_ids[1],
            &dir.path().join("leases"),
            &topology,
            request,
        )
        .await
        .unwrap();

        let rows = cpu_allocation_cpu::Entity::find().all(&db).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|row| row.logical_cpu == 0));
        assert!(!first.1.shared);
        assert!(second.1.shared);

        first.0.release(&db).await.unwrap();
        second.0.release(&db).await.unwrap();
    }

    #[tokio::test]
    async fn placement_ack_keeps_successful_pins_and_releases_fallback_capacity() {
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
            name: Set("placement-ack-test".into()),
            config: Set("{}".into()),
            status: Set(sandbox::SandboxStatus::Running),
            ephemeral: Set(false),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap()
        .id;
        let run_id = run::ActiveModel {
            sandbox_id: Set(sandbox_id),
            status: Set(run::RunStatus::Running),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap()
        .id;
        let topology = CpuTopology {
            logical_cpus: vec![
                LogicalCpu {
                    id: LogicalCpuId::new(0),
                    package: 0,
                    die: 0,
                    core: 0,
                    numa_node: 0,
                    performance_class: 0,
                },
                LogicalCpu {
                    id: LogicalCpuId::new(1),
                    package: 0,
                    die: 0,
                    core: 1,
                    numa_node: 0,
                    performance_class: 0,
                },
            ],
            numa_nodes: vec![HostNumaNode {
                id: 0,
                package: 0,
                total_memory_mib: 16_384,
                available_memory_mib: 16_384,
                distances: BTreeMap::from([(0, 10)]),
            }],
            fingerprint: "placement-ack".into(),
        };
        let (lease, _, _) = acquire(
            &db,
            run_id,
            &dir.path().join("leases"),
            &topology,
            PlacementRequest {
                policy: CpuPlacement::Auto,
                max_vcpus: 2,
                boot_memory_mib: 512,
                max_memory_mib: 1024,
                profile: Some(PlacementProfile {
                    numa: NumaPlacement::PreferSingle,
                    memory: MemoryPlacement::FollowCpu,
                }),
            },
        )
        .await
        .unwrap();

        lease
            .reconcile(
                &db,
                &msb_krun::PlacementReport {
                    vcpus: vec![
                        msb_krun::VcpuPlacementResult::Pinned {
                            vcpu_index: 0,
                            host_cpu: msb_krun::HostCpuId::new(0),
                        },
                        msb_krun::VcpuPlacementResult::Inherited {
                            vcpu_index: 1,
                            requested_host_cpu: Some(msb_krun::HostCpuId::new(1)),
                            reason: Some("injected affinity rejection".into()),
                        },
                    ],
                    memory: msb_krun::MemoryPlacementResult::Fallback {
                        reason: "partial CPU placement".into(),
                    },
                },
            )
            .await
            .unwrap();

        let cpu_rows = cpu_allocation_cpu::Entity::find().all(&db).await.unwrap();
        assert_eq!(cpu_rows.len(), 1);
        assert_eq!(cpu_rows[0].vcpu_index, 0);
        assert_eq!(cpu_rows[0].role, "assigned");
        assert!(
            memory_allocation_node::Entity::find()
                .all(&db)
                .await
                .unwrap()
                .is_empty()
        );
        let allocation = cpu_allocation::Entity::find()
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(allocation.enforcement, "thread-affinity-partial");
        assert_eq!(allocation.state, "active");

        lease.release(&db).await.unwrap();
    }
}

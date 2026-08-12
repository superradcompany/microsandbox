//! Topology-aware cooperative host CPU placement.

mod allocation;
mod planner;
mod topology;

use std::path::Path;
use std::time::Instant;

use microsandbox_db::DbWriteConnection;
use microsandbox_types::{CpuPlacement, MemoryPlacement, NumaPlacement, PlacementProfile};

pub(crate) use self::topology::LogicalCpuId;
use crate::RuntimeResult;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Process-held placement reservation and resolved vCPU target map.
pub struct CpuPlacementGuard {
    lease: Option<allocation::AllocationLease>,
    resolved: Option<planner::ResolvedPlacement>,
}

/// Effective CPU and memory capacity requested from the host placement planner.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PlacementRequest {
    pub(crate) policy: CpuPlacement,
    pub(crate) max_vcpus: u8,
    pub(crate) boot_memory_mib: u32,
    pub(crate) max_memory_mib: u32,
    pub(crate) profile: Option<PlacementProfile>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CpuPlacementGuard {
    /// Returns the resolved host processor-group coordinate for every possible vCPU.
    pub(crate) fn vcpu_targets(&self) -> Option<&[LogicalCpuId]> {
        self.resolved
            .as_ref()
            .map(|resolved| resolved.vcpu_targets.as_slice())
    }

    /// Returns the policy selected by the planner.
    pub fn resolved_policy(&self) -> Option<CpuPlacement> {
        self.resolved.as_ref().map(|resolved| resolved.resolved)
    }

    /// Returns the concrete topology libkrun must realize for this allocation.
    pub(crate) fn numa_topology(&self) -> Option<msb_krun::NumaTopology> {
        let numa = self.resolved.as_ref()?.numa.as_ref()?;
        Some(msb_krun::NumaTopology {
            nodes: numa
                .nodes
                .iter()
                .map(|node| msb_krun::NumaNodeConfig {
                    guest_node_id: node.guest_node_id,
                    vcpu_indices: node.vcpu_indices.clone(),
                    memory_mib: node.boot_memory_mib as usize,
                    max_memory_mib: node.max_memory_mib as usize,
                    host_memory: match numa.memory {
                        MemoryPlacement::Inherit => msb_krun::HostMemoryPolicy::Inherit,
                        MemoryPlacement::FollowCpu => {
                            #[cfg(target_os = "linux")]
                            {
                                msb_krun::HostMemoryPolicy::Bind {
                                    host_nodes: vec![node.host_node_id],
                                }
                            }
                            #[cfg(target_os = "windows")]
                            {
                                msb_krun::HostMemoryPolicy::Preferred {
                                    host_node: node.host_node_id,
                                }
                            }
                            #[cfg(not(any(target_os = "linux", target_os = "windows")))]
                            {
                                msb_krun::HostMemoryPolicy::Inherit
                            }
                        }
                    },
                })
                .collect(),
            distances: numa
                .distances
                .iter()
                .map(|&(from, to, value)| msb_krun::NumaDistance { from, to, value })
                .collect(),
        })
    }

    /// Removes coordination state and releases the process-held lease.
    pub async fn release(&self, db: &DbWriteConnection) -> RuntimeResult<()> {
        if let Some(lease) = &self.lease {
            lease.release(db).await?;
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Resolves and reserves host placement for a sandbox run.
pub(crate) async fn acquire(
    db: &DbWriteConnection,
    run_id: i32,
    lease_dir: &Path,
    request: PlacementRequest,
) -> RuntimeResult<CpuPlacementGuard> {
    if request.policy == CpuPlacement::Inherit
        && request.profile.is_none_or(|profile| {
            matches!(profile.numa, NumaPlacement::Inherit)
                && matches!(profile.memory, MemoryPlacement::Inherit)
        })
    {
        return Ok(CpuPlacementGuard {
            lease: None,
            resolved: None,
        });
    }

    let started = Instant::now();
    let topology = topology::discover()?;
    let (lease, resolved, replans) =
        allocation::acquire(db, run_id, lease_dir, &topology, request).await?;
    tracing::info!(
        requested = %request.policy,
        resolved = %resolved.resolved,
        enforcement = "thread-affinity",
        max_vcpus = request.max_vcpus,
        replans,
        elapsed_us = started.elapsed().as_micros(),
        "CPU placement acquired"
    );

    Ok(CpuPlacementGuard {
        lease: Some(lease),
        resolved: Some(resolved),
    })
}

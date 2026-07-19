//! Topology-aware cooperative host CPU placement.

mod allocation;
mod planner;
mod topology;

use std::path::Path;
use std::time::Instant;

use microsandbox_db::DbWriteConnection;
use microsandbox_types::CpuPlacement;

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
pub async fn acquire(
    db: &DbWriteConnection,
    run_id: i32,
    lease_dir: &Path,
    requested: CpuPlacement,
    max_vcpus: u8,
) -> RuntimeResult<CpuPlacementGuard> {
    if requested == CpuPlacement::Inherit {
        return Ok(CpuPlacementGuard {
            lease: None,
            resolved: None,
        });
    }

    let started = Instant::now();
    let topology = topology::discover()?;
    let (lease, resolved, replans) =
        allocation::acquire(db, run_id, lease_dir, &topology, requested, max_vcpus).await?;
    tracing::info!(
        requested = %requested,
        resolved = %resolved.resolved,
        enforcement = "thread-affinity",
        max_vcpus,
        replans,
        elapsed_us = started.elapsed().as_micros(),
        "CPU placement acquired"
    );

    Ok(CpuPlacementGuard {
        lease: Some(lease),
        resolved: Some(resolved),
    })
}

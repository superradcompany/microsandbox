//! Native storage observations and ownership-aware runtime RAM pruning.

use std::sync::Arc;
use std::time::Duration;

use microsandbox::storage::{
    MemoryCacheEntry, MemoryCacheKind, MemoryCacheReport, MemoryCacheState, MemoryPruneOptions,
    Storage, StorageCategoryUsage, StorageItemUsage, StorageUsage,
};
use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::error::to_napi_error;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Aggregate storage usage. Unknown measurements remain nullable.
#[napi(object)]
pub struct StorageUsageJs {
    pub images: StorageCategoryUsageJs,
    pub snapshots: StorageCategoryUsageJs,
    pub sandboxes: StorageCategoryUsageJs,
    pub volumes: StorageCategoryUsageJs,
    pub branch_memory: StorageCategoryUsageJs,
    pub snapshot_memory: StorageCategoryUsageJs,
    pub notes: Vec<String>,
}

/// Counts and observed bytes in one managed storage category.
#[napi(object)]
pub struct StorageCategoryUsageJs {
    pub count: Option<f64>,
    pub in_use: Option<f64>,
    pub logical_bytes: Option<BigInt>,
    pub allocated_bytes: Option<BigInt>,
    pub reclaimable_logical_bytes: Option<BigInt>,
    pub items: Vec<StorageItemUsageJs>,
    pub notes: Vec<String>,
}

/// One object's storage usage and retention explanations.
#[napi(object)]
pub struct StorageItemUsageJs {
    pub name: String,
    pub path: String,
    pub logical_bytes: Option<BigInt>,
    pub allocated_bytes: Option<BigInt>,
    pub in_use: Option<bool>,
    pub reclaimable: Option<bool>,
    pub reasons: Vec<String>,
}

/// Per-file reclamation result, including ownership exclusions and errors.
#[napi(object)]
pub struct MemoryCacheEntryJs {
    pub path: String,
    pub kind: String,
    pub logical_bytes: Option<BigInt>,
    pub allocated_bytes: Option<BigInt>,
    pub state: String,
    pub error: Option<String>,
}

/// Runtime RAM pruning report; logical removal does not imply physical reclamation.
#[napi(object)]
pub struct MemoryCacheReportJs {
    pub dry_run: bool,
    pub entries: Vec<MemoryCacheEntryJs>,
    pub files_removed: f64,
    pub logical_bytes_removed: BigInt,
    pub physical_bytes_reclaimed: Option<BigInt>,
    pub truncated: bool,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Observe storage in the selected local backend without removing files.
#[napi(js_name = "storageUsage", ts_return_type = "Promise<StorageUsageJs>")]
pub fn storage_usage<'env>(env: &'env Env) -> Result<PromiseRaw<'env, StorageUsageJs>> {
    // Capture on the JS thread, before scheduling: callers may change the default
    // backend immediately after receiving the promise. Errors still reject that promise.
    let backend = resolve_local(microsandbox::Operation::StorageUsage);
    env.spawn_future(async move {
        let backend = backend?;
        let local = backend.as_local().expect("validated local backend");
        let report = Storage::usage_local(local).await.map_err(to_napi_error)?;
        usage_to_js(report)
    })
}

/// Inspect or remove unused published runtime RAM; never remove durable state or locks.
#[napi(
    js_name = "storagePrune",
    ts_return_type = "Promise<MemoryCacheReportJs>"
)]
pub fn storage_prune<'env>(
    env: &'env Env,
    dry_run: Option<bool>,
    older_than_seconds: Option<f64>,
) -> Result<PromiseRaw<'env, MemoryCacheReportJs>> {
    let backend = resolve_local(microsandbox::Operation::StoragePrune);
    let older_than = parse_age(older_than_seconds.unwrap_or(0.0));
    env.spawn_future(async move {
        let backend = backend?;
        let local = backend.as_local().expect("validated local backend");
        let options = MemoryPruneOptions {
            dry_run: dry_run.unwrap_or(false),
            older_than: older_than?,
            ..Default::default()
        };
        let report = Storage::prune_local(local, &options)
            .await
            .map_err(to_napi_error)?;
        prune_to_js(report)
    })
}

fn resolve_local(operation: microsandbox::Operation) -> Result<Arc<dyn microsandbox::Backend>> {
    // Keep this selected backend alive across the await; concurrent selection changes must
    // not redirect a scan or a deletion to a different configured runtime home.
    let backend = microsandbox::backend::default_backend();
    if backend.as_local().is_none() {
        return Err(to_napi_error(microsandbox::MicrosandboxError::local_only(
            operation,
        )));
    }
    Ok(backend)
}

fn parse_age(value: f64) -> Result<Duration> {
    if !value.is_finite()
        || value.fract() != 0.0
        || !(0.0..=MAX_SAFE_INTEGER as f64).contains(&value)
    {
        return Err(Error::from_reason(
            "olderThanSeconds must be a non-negative safe integer",
        ));
    }
    Ok(Duration::from_secs(value as u64))
}

/// Object counts use numbers, while arbitrary byte counts use lossless BigInts.
fn number(value: u64) -> Result<f64> {
    if value > MAX_SAFE_INTEGER {
        return Err(Error::from_reason(
            "storage count exceeds JavaScript's safe integer range; use the Rust SDK or CLI JSON for exact accounting",
        ));
    }
    Ok(value as f64)
}

fn optional_number(value: Option<u64>) -> Result<Option<f64>> {
    value.map(number).transpose()
}

fn usage_to_js(report: StorageUsage) -> Result<StorageUsageJs> {
    Ok(StorageUsageJs {
        images: category_to_js(report.images)?,
        snapshots: category_to_js(report.snapshots)?,
        sandboxes: category_to_js(report.sandboxes)?,
        volumes: category_to_js(report.volumes)?,
        branch_memory: category_to_js(report.branch_memory)?,
        snapshot_memory: category_to_js(report.snapshot_memory)?,
        notes: report.notes,
    })
}

fn category_to_js(category: StorageCategoryUsage) -> Result<StorageCategoryUsageJs> {
    Ok(StorageCategoryUsageJs {
        count: optional_number(category.count)?,
        in_use: optional_number(category.in_use)?,
        logical_bytes: category.logical_bytes.map(BigInt::from),
        allocated_bytes: category.allocated_bytes.map(BigInt::from),
        reclaimable_logical_bytes: category.reclaimable_logical_bytes.map(BigInt::from),
        items: category.items.into_iter().map(item_to_js).collect(),
        notes: category.notes,
    })
}

pub(crate) fn item_to_js(item: StorageItemUsage) -> StorageItemUsageJs {
    StorageItemUsageJs {
        name: item.name,
        path: item.path.to_string_lossy().into_owned(),
        logical_bytes: item.logical_bytes.map(BigInt::from),
        allocated_bytes: item.allocated_bytes.map(BigInt::from),
        in_use: item.in_use,
        reclaimable: item.reclaimable,
        reasons: item.reasons,
    }
}

fn prune_to_js(report: MemoryCacheReport) -> Result<MemoryCacheReportJs> {
    Ok(MemoryCacheReportJs {
        dry_run: report.dry_run,
        entries: report.entries.into_iter().map(entry_to_js).collect(),
        files_removed: number(report.files_removed)?,
        // Conversion after deletion must not discard the report for large sparse files.
        logical_bytes_removed: BigInt::from(report.logical_bytes_removed),
        physical_bytes_reclaimed: report.physical_bytes_reclaimed.map(BigInt::from),
        truncated: report.truncated,
    })
}

fn entry_to_js(entry: MemoryCacheEntry) -> MemoryCacheEntryJs {
    // Keep the state spellings identical to Rust/CLI JSON instead of exposing Debug names.
    let kind = match entry.kind {
        MemoryCacheKind::BranchMemory => "branch_memory",
        MemoryCacheKind::SnapshotMemory => "snapshot_memory",
    };
    let state = match entry.state {
        MemoryCacheState::Reclaimable => "reclaimable",
        MemoryCacheState::InUse => "in_use",
        MemoryCacheState::PendingHandoff => "pending_handoff",
        MemoryCacheState::TooYoung => "too_young",
        MemoryCacheState::MissingHandoffLock => "missing_handoff_lock",
        MemoryCacheState::Changed => "changed",
        MemoryCacheState::Removed => "removed",
        MemoryCacheState::Error => "error",
    };
    MemoryCacheEntryJs {
        path: entry.path.to_string_lossy().into_owned(),
        kind: kind.into(),
        logical_bytes: entry.logical_bytes.map(BigInt::from),
        allocated_bytes: entry.allocated_bytes.map(BigInt::from),
        state: state.into(),
        error: entry.error,
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_conversion_rejects_precision_loss_and_preserves_unknown() {
        assert_eq!(number(MAX_SAFE_INTEGER).unwrap(), MAX_SAFE_INTEGER as f64);
        assert!(number(MAX_SAFE_INTEGER + 1).is_err());
        assert!(number(u64::MAX).is_err());
        assert_eq!(optional_number(None).unwrap(), None);
        assert_eq!(optional_number(Some(0)).unwrap(), Some(0.0));
    }

    #[test]
    fn age_validation_rejects_fractional_negative_and_unsafe_values() {
        for value in [
            -1.0,
            1.5,
            f64::NAN,
            f64::INFINITY,
            MAX_SAFE_INTEGER as f64 + 1.0,
        ] {
            assert!(parse_age(value).is_err());
        }
        assert_eq!(parse_age(3600.0).unwrap(), Duration::from_secs(3600));
    }

    #[test]
    fn partial_failures_and_logical_accounting_survive_mapping() {
        let report = MemoryCacheReport {
            files_removed: 1,
            logical_bytes_removed: u64::MAX,
            entries: vec![MemoryCacheEntry {
                path: "/cache/failure.ram".into(),
                kind: MemoryCacheKind::BranchMemory,
                logical_bytes: None,
                allocated_bytes: None,
                state: MemoryCacheState::Error,
                error: Some("permission denied".into()),
            }],
            ..Default::default()
        };
        let mapped = prune_to_js(report).unwrap();
        assert_eq!(mapped.logical_bytes_removed, BigInt::from(u64::MAX));
        assert_eq!(mapped.physical_bytes_reclaimed, None);
        assert_eq!(mapped.entries[0].state, "error");
        assert_eq!(
            mapped.entries[0].error.as_deref(),
            Some("permission denied")
        );
    }
}

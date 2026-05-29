//! Internal `CollectFn` machinery: opens the named shm registry on every
//! tick and reads its active snapshot.
//!
//! The umbrella crate exposes a higher-level `MetricsReader` for ad-hoc
//! SDK reads; this module wraps `MetricsRegistry` directly so the
//! orchestrator stays decoupled from the umbrella.

use std::sync::Arc;

use futures::future::BoxFuture;
use microsandbox_metrics::{MetricsError, MetricsRegistry};

use crate::error::MetricsCollectorResult;
use crate::types::{MetricsCollection, SandboxMetricSnapshot};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A pluggable source of metrics collections for the run loop.
pub(crate) type CollectFn =
    Arc<dyn Fn() -> BoxFuture<'static, MetricsCollectorResult<MetricsCollection>> + Send + Sync>;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Build a `CollectFn` that opens the named shm registry on each tick and
/// reads its active snapshot. Returns an empty collection if the registry
/// hasn't been created yet (no sandboxes running).
pub(crate) fn registry_collect_fn(registry_name: String) -> CollectFn {
    Arc::new(move || {
        let name = registry_name.clone();
        Box::pin(async move {
            let collected_at = chrono::Utc::now();
            let sandboxes = match MetricsRegistry::open(&name) {
                Ok(registry) => registry
                    .active_snapshot()?
                    .into_iter()
                    .map(SandboxMetricSnapshot::from)
                    .collect(),
                Err(MetricsError::Io(ref e)) if e.raw_os_error() == Some(libc::ENOENT) => {
                    Vec::new()
                }
                Err(err) => return Err(err.into()),
            };
            Ok(MetricsCollection {
                collected_at,
                sandboxes,
            })
        })
    })
}

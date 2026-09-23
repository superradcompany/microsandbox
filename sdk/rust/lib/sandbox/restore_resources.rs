//! Operation-local resource authorization; never a persisted sandbox default.

use std::collections::BTreeSet;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub(crate) struct RestoreResources {
    /// Full restore requires captured external filesystems and additional disks unless waived.
    /// Kept operation-local: older SDK launches and direct branches retain their contract.
    pub require_complete: bool,
    /// Explicitly waive missing backing independently of object compatibility checks.
    pub allow_missing: bool,
    /// Guest paths whose captured disk contents may be materialized privately.
    pub captured: BTreeSet<String>,
    /// Explicit destination mappings take precedence over captured disk inheritance.
    pub mapped: BTreeSet<String>,
    /// Fill unspecified choices only from validated local source records.
    pub inherit: bool,
}

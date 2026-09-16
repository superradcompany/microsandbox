//! Operation-local resource authorization; never a persisted sandbox default.

use std::collections::BTreeSet;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub(crate) struct RestoreResources {
    /// Guest paths whose captured disk contents may be materialized privately.
    pub captured: BTreeSet<String>,
    /// Explicit destination mappings take precedence over captured disk inheritance.
    pub mapped: BTreeSet<String>,
    /// Fill unspecified choices only from validated local source records.
    pub inherit: bool,
}

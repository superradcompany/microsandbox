//! Constrained, crash-resumable import of legacy sandbox storage.

mod budget;
mod engine;
mod io;
mod namespace;
mod preview;
mod source;
mod types;
mod writer;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use engine::{MigrationPlan, inspect, plan, plan_selected};
pub use namespace::open_preview_cache_file;
pub use preview::{
    RecoveryPreview, capture_preview, plan_previewed, private_preview_parent, private_reader_home,
};
pub use source::{alias_sources, producer_role, selected_sources};
pub use types::{
    AliasSource, AuthorizedAlias, CandidateSummary, Inspection, MigrationBindings, MigrationStatus,
    OwnedDiskBinding, RecoverySelection,
};

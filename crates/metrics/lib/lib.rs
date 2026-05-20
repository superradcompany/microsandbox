//! Shared-memory live metrics registry for microsandbox.
//!
//! Replaces continuous `sandbox_metric` inserts into the catalog SQLite
//! database with a single POSIX shared-memory region. Every running sandbox
//! owns one fixed slot; readers scan the region to produce typed metrics
//! responses without per-sandbox RPC or per-sample writes.

#![warn(missing_docs)]

mod error;
mod layout;
mod registry;
mod snapshot;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use error::{MetricsError, MetricsResult};
pub use registry::{
    ActivateSlot, MetricsRegistry, MetricsSlotWriter, ReleaseMode, ReserveSlot, SampleWrite,
    SlotReservation, default_capacity,
};
pub use snapshot::LiveMetric;

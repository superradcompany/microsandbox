//! Host-global pressure coordination for bounded block writeback.

mod admission;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub(crate) use admission::{WritebackPressureGuard, acquire};

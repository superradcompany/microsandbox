//! Termination reason tracking for sandbox lifecycle.
//!
//! Re-exports [`TerminationReason`] from `microsandbox-db` where it is defined
//! alongside the microvm entity as a `DeriveActiveEnum`.

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use microsandbox_db::entity::microvm::TerminationReason;

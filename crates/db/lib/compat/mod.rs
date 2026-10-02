//! Compatibility for sandbox configurations persisted in the local SQLite database.

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub mod config;
/// Saved policies using the original secret contract.
pub mod v0_5_0;
/// Previous image, resource and mount representations.
pub mod v0_6_5;
/// Saved policies using the substitution contract.
pub mod v0_7_0;

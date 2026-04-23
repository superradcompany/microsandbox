//! Network policy model and rule matching.
//!
//! Policy types use first-match-wins semantics. Rules are evaluated in order
//! against packet headers. Domain-based rules rely on a DNS pin set to map
//! destination IPs back to domain names.

pub mod destination;
mod evaluator;
mod types;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use destination::*;
pub use evaluator::PolicyEvaluator;
pub use types::*;

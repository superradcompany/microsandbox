//! Network policy model and rule matching engine.
//!
//! Policy enforcement uses first-match-wins semantics. Rules are evaluated
//! in order against parsed packet headers. Domain-based rules rely on the
//! DNS pin set to map destination IPs back to domain names.

pub mod destination;
mod engine;
mod types;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use destination::*;
pub use engine::*;
pub use types::*;

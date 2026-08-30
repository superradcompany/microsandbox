//! Network policy model and rule matching.
//!
//! Policy types use first-match-wins semantics. Rules are evaluated in order
//! against packet headers. Domain-based rules rely on a resolved-hostname
//! index to map destination IPs back to domain names.

mod builder;
#[cfg(feature = "engine")]
pub use crate::engine::policy::destination;
mod name;
mod types;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "engine")]
pub use crate::engine::policy::destination::*;
pub use builder::{BuildError, NetworkPolicyBuilder, RuleBuilder, RuleDestinationBuilder};
pub use name::{DomainName, DomainNameError};
pub use types::*;

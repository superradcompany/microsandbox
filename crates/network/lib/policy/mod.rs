//! Network policy model and rule matching.
//!
//! Policy types use first-match-wins semantics. Rules are evaluated in order
//! against packet headers. Domain-based rules rely on a resolved-hostname
//! index to map destination IPs back to domain names.

mod builder;
pub mod cli;
pub mod destination;
mod name;
mod types;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use builder::{BuildError, ExplicitRuleBuilder, NetworkPolicyBuilder, RuleBuilder};
pub use cli::{RuleParseError, parse_rule_list, parse_rule_token};
pub use destination::*;
pub use name::{DomainName, DomainNameError};
pub use types::*;

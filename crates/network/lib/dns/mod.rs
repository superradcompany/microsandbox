//! DNS interception, resolution, and filtering.
//!
//! `msbnet` intercepts DNS queries (UDP/TCP port 53) destined for the sandbox
//! gateway, resolves them via host nameservers, applies domain and rebind
//! filters, records A/AAAA answers in the pin set, and synthesizes responses.

mod filter;
mod interceptor;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use filter::*;
pub use interceptor::*;

//! Placeholder-based secret injection for TLS-intercepted connections.
//!
//! Secrets use placeholder protection: the sandbox receives a placeholder
//! string (e.g. `$MSB_a8f3b2c1`), never the real value. The TLS proxy
//! substitutes the real value only when the request goes to an allowed host.

pub mod config;
pub mod handler;

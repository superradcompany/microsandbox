//! Small shared types and predicates used across the DNS module.
//!
//! Nothing here depends on the forwarder, proxies, or interceptor —
//! these are leaf modules that the rest of `dns/*` reads from:
//!
//! - [`config`] — [`config::NormalizedDnsConfig`], pre-processed
//!   operator input (lowercased block lists, `Duration` timeouts).
//! - [`filter`] — block-list matching and private-IP / rebind
//!   predicates used by [`super::forwarder::DnsForwarder`].
//! - [`ports`] — [`ports::DnsPortType`], the port-layer classification
//!   `stack.rs` uses to decide what to do with a TCP/UDP packet
//!   *before* it becomes a DNS query.
//! - [`transport`] — [`transport::Transport`], the vocabulary the
//!   proxies and forwarder use to identify which wire format a query
//!   arrived on.

pub(crate) mod config;
pub(crate) mod filter;
pub(crate) mod ports;
pub(crate) mod transport;

//! DNS interception via smoltcp UDP socket + async resolution.
//!
//! DNS queries (UDP port 53) flow through smoltcp to a bound UDP socket.
//! The poll loop reads queries, applies domain filters, resolves via the
//! host's DNS resolvers, and sends responses back through the smoltcp socket.

pub mod interceptor;
pub mod parse;

pub use parse::{NameserverSpec, ParseNameserverError, parse_nameserver};

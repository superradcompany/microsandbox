//! DNS interception via smoltcp UDP socket + async resolution.
//!
//! UDP/53 queries flow through smoltcp to a bound UDP socket; the poll
//! loop reads them and forwards via the `forwarder` task. TCP/53
//! connections are accepted as ordinary smoltcp TCP sockets, then
//! handed to the `tcp` proxy which frames RFC 1035 §4.2.2 messages
//! and routes them through the same shared forwarder. TCP/853
//! connections are handed to the `dot` proxy when TLS interception is
//! configured: it terminates the guest's TLS with a per-domain cert
//! from the intercept CA, parses the same length-prefixed DNS frames,
//! and routes them through the shared forwarder. All three transports
//! enforce the same block list + rebind protection.
//!
//! Alternative DNS-ish protocols on well-known ports (DoQ, mDNS,
//! LLMNR, NetBIOS-NS) are refused at the stack layer — see `ports`.
//! We don't intercept them because their wire formats are encrypted
//! (DoQ) or non-DNS (NetBIOS/mDNS/LLMNR multicast discovery), so the
//! operator-configured block list + rebind protection couldn't apply.
//! Refusal forces the guest's stub to fall back to plain DNS on port
//! 53, which we do see. DoT without a configured intercept CA is
//! refused the same way.

pub(crate) mod common;
pub mod interceptor;
pub mod nameserver;
pub(crate) mod proxies;

mod client;
pub(crate) mod forwarder;

pub use nameserver::{Nameserver, ParseNameserverError};

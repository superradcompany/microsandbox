//! Guest-facing DNS proxies, one per transport.
//!
//! Each submodule owns a per-task proxy that terminates a guest DNS
//! connection (or UDP query stream), parses the wire format, and hands
//! queries off to the shared [`super::forwarder::DnsForwarder`] which
//! applies the block list, rebind protection, and upstream routing.
//! Responses go back out on the same transport the guest used — UDP
//! stays UDP, TCP stays TCP, DoT stays DoT.
//!
//! - [`udp`] — UDP/53 query/response pump. Consumes `DnsQuery` records
//!   the interceptor pushed off the smoltcp UDP socket.
//! - [`tcp`] — TCP/53 per-connection proxy. Drains length-prefixed
//!   frames and dispatches them concurrently (RFC 7766 pipelining).
//! - [`dot`] — TCP/853 DoT per-connection proxy. Terminates TLS with a
//!   per-domain intercept cert, reuses the same length-prefix framing
//!   as [`tcp`] via the private [`framing`] helper.

pub(crate) mod dot;
pub(crate) mod tcp;
pub(crate) mod udp;

mod framing;

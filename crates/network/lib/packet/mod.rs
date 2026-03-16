//! Packet parsing for L2–L4 header inspection.
//!
//! Uses `etherparse` for all protocol parsing: Ethernet II, ARP, IPv4, IPv6,
//! TCP, UDP, ICMPv4, ICMPv6 (including NDP).

mod frame;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use frame::*;

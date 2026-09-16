//! Host networking implementation linked into the `msb` runtime.

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub(crate) mod addr;
pub mod dns;
pub mod icmp;
pub mod netstack;
pub mod network;
pub(crate) mod policy;
pub mod ports;
pub(crate) mod secrets;
pub mod tcp;
pub mod tls;
pub mod udp;

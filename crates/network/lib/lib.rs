//! `microsandbox-network` provides the smoltcp in-process networking engine
//! for sandbox network isolation and policy enforcement.

// New lints introduced in rustc 1.95 fire on existing code; addressing
// them is out of scope for the current change and tracked separately.
#![allow(
    clippy::useless_conversion,
    clippy::identity_op,
    clippy::unnecessary_cast,
    clippy::needless_update,
    clippy::manual_c_str_literals
)]

mod addr;

pub mod config;
pub mod dns;
pub mod icmp;
pub mod netstack;
pub mod network;
pub mod policy;
pub mod ports;
pub mod secrets;
pub mod tcp;
pub mod tls;
pub mod udp;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Static hostname the guest uses to reach the sandbox host.
///
/// The host-side DNS interceptor matches guest queries against this
/// name, and agentd writes the same name into `/etc/hosts`.
pub(crate) const HOST_ALIAS: &str = "host.microsandbox.internal";

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use config::builder;
pub use icmp::{error as icmp_error, relay as icmp_relay};
pub use netstack::{backend, device, poll as stack, shared};
pub use ports::publisher;
pub use tcp::{connection as conn, proxy};
pub use udp::{fragments as udp_fragments, relay as udp_relay};

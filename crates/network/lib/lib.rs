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

pub mod backend;
pub mod builder;
pub mod config;
pub mod conn;
pub mod device;
pub mod dns;
pub mod icmp_relay;
pub mod network;
pub mod policy;
pub mod proxy;
pub mod publisher;
pub mod secrets;
pub mod shared;
pub mod stack;
pub mod tls;
pub mod udp_relay;

/// Static hostname the guest uses to reach the sandbox host.
///
/// The host-side DNS interceptor matches guest queries against this
/// name, and agentd writes the same name into `/etc/hosts`.
pub(crate) const HOST_ALIAS: &str = "host.microsandbox.internal";

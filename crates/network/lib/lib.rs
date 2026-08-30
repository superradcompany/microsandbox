//! Network configuration models and the optional host networking engine.
//!
//! The model tree is always available for SDK-side configuration. The
//! `engine` feature adds packet processing, relays, DNS forwarding, policy
//! enforcement, TLS interception, and port publishing for the `msb` runtime.

// New lints introduced in rustc 1.95 fire on existing code; addressing
// them is out of scope for the current change and tracked separately.
#![allow(
    clippy::useless_conversion,
    clippy::identity_op,
    clippy::unnecessary_cast,
    clippy::needless_update,
    clippy::manual_c_str_literals
)]

#[cfg(feature = "engine")]
mod engine;
mod model;

#[cfg(feature = "engine")]
pub(crate) use engine::addr;
#[cfg(feature = "engine")]
pub use engine::{icmp, netstack, network, ports, tcp, udp};
pub use model::{config, dns, policy, secrets, tls};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Static hostname the guest uses to reach the sandbox host.
///
/// The host-side DNS interceptor matches guest queries against this
/// name, and agentd writes the same name into `/etc/hosts`.
#[cfg(feature = "engine")]
pub(crate) const HOST_ALIAS: &str = "host.microsandbox.internal";

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use config::builder;
#[cfg(feature = "engine")]
pub use icmp::{error as icmp_error, relay as icmp_relay};
#[cfg(feature = "engine")]
pub use netstack::{backend, device, poll as stack, shared};
#[cfg(feature = "engine")]
pub use ports::publisher;
#[cfg(feature = "engine")]
pub use tcp::{connection as conn, proxy};
#[cfg(feature = "engine")]
pub use udp::{fragments as udp_fragments, relay as udp_relay};

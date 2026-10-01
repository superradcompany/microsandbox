//! Backend-owned, identity-verified runtime control sessions.

#[cfg(all(test, unix))]
mod delivery_tests;
pub(super) mod identity;
#[cfg(all(test, unix))]
mod lifecycle_tests;
mod owner;
mod persistence;
mod registry;
mod session;
#[cfg(test)]
mod tests;

pub(super) use registry::ControlSessions;
pub(crate) use session::ControlSession;

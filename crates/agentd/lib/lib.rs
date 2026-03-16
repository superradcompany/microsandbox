//! `microsandbox-agentd` is the PID 1 init process and agent daemon
//! that runs inside the microVM guest.

#![warn(missing_docs)]

mod error;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub mod agent;
pub mod clock;
pub mod fs;
pub mod heartbeat;
pub mod init;
pub mod network;
pub mod serial;
pub mod session;

pub use error::*;

//! Contracts and host-side helpers used by clients that launch `msb`.

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub mod boot_error;
pub mod control;
pub mod ipc;
pub mod launch;
pub mod logging;
pub mod maintenance;
#[cfg(target_os = "linux")]
pub mod memory_handoff;
pub mod startup_progress;

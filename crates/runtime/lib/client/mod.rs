//! Contracts and host-side helpers used by clients that launch `msb`.

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub mod boot_error;
pub mod compat;
pub mod control;
#[cfg(windows)]
pub mod disk_lock_handoff;
pub mod ipc;
pub mod launch;
pub mod logging;
pub mod maintenance;
#[cfg(target_os = "linux")]
pub mod memory_handoff;
pub mod startup_progress;

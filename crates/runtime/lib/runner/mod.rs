//! VM runner implementation linked into the `msb` process.

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

#[cfg(windows)]
pub(crate) mod bootstrap_fs;
pub(crate) mod clock;
pub mod console;
pub(crate) mod control;
pub mod cpu;
pub(crate) mod exec_control;
pub mod exec_log;
pub mod heartbeat;
pub(crate) mod jobs;
pub(crate) mod logging;
pub mod metrics;
#[cfg(all(target_os = "linux", feature = "oci-runtime", feature = "net"))]
pub(crate) mod network_oci;
pub mod policy;
pub(crate) mod progress;
pub mod relay;
#[cfg_attr(feature = "oci-runtime", path = "startup_oci.rs")]
pub(crate) mod startup;
pub mod vm;
pub(crate) mod workload_control;
pub(crate) mod writeback;

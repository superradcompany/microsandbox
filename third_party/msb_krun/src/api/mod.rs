//! Native Rust API for libkrun.
//!
//! This module provides a builder-pattern API for creating and entering microVMs
//! using nested builders for organized configuration.
//!
//! # Example
//!
//! ```rust,no_run
//! use msb_krun::{VmBuilder, Result};
//!
//! fn main() -> Result<()> {
//!     // enter() hands process lifecycle to the VMM.
//!     // On normal guest exit, the process terminates directly.
//!     // It only returns on early setup errors.
//!     VmBuilder::new()
//!         .machine(|m| m.vcpus(4).memory_mib(2048))
//!         .fs(|fs| fs.root("/path/to/rootfs"))
//!         .exec(|e| e.path("/bin/myapp").args(["--flag"]).env("HOME", "/root"))
//!         .build()?
//!         .enter()?;
//!
//!     unreachable!()
//! }
//! ```

//--------------------------------------------------------------------------------------------------
// Modules
//--------------------------------------------------------------------------------------------------

pub mod builder;
pub mod builders;
pub mod error;
pub mod exit_handle;
pub mod metrics;
pub mod vm;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use builder::VmBuilder;
#[cfg(feature = "blk")]
pub use builders::DiskBuilder;
#[cfg(feature = "blk")]
pub use builders::DiskImageFormat;
#[cfg(not(target_os = "windows"))]
pub use builders::FsBuilder;
#[cfg(feature = "net")]
pub use builders::NetBuilder;
pub use builders::VsockBuilder;
#[cfg(feature = "blk")]
pub use builders::WritebackLimit;
pub use builders::{
    ConsoleBuilder, ConsolePortOptions, ExecBuilder, HostCpuId, HostMemoryPolicy, KernelBuilder,
    MachineBuilder, MemoryPlacementResult, NumaBuilder, NumaDistance, NumaNodeBuilder,
    NumaNodeConfig, NumaTopology, PlacementReport, VcpuPlacementResult,
};
pub use error::{BuildError, ConfigError, Error, Result, RuntimeError};
pub use exit_handle::ExitHandle;
pub use metrics::{
    BlockDeviceMetrics, BlockMetrics, CpuMetrics, FilesystemMetrics, MemoryMetrics, MetricsHandle,
    VmMetrics,
};
pub use vm::Vm;
#[cfg(not(feature = "tee"))]
pub use vm::{VmControl, VmCpuState, VmMemoryState};

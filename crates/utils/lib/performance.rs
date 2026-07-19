//! Development-only switches for cumulative performance experiments.
//!
//! These switches deliberately do not form part of the public sandbox API. They let benchmark
//! builds enable one optimization, a subsystem group, or the complete experimental stack while
//! production defaults remain unchanged.

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Comma-separated performance experiment selector inherited by sandbox subprocesses.
pub const PERF_EXPERIMENTS_ENV: &str = "MSB_PERF_EXPERIMENTS";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One independently selectable development performance experiment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PerfExperiment {
    /// Refresh guest-memory residency less frequently than ordinary metrics.
    MetricsResidency,
    /// End healthy shutdown waits after a verified guest durability acknowledgement.
    ShutdownReady,
    /// Reuse network packet buffers.
    NetworkBuffers,
    /// Coalesce network wake notifications.
    NetworkWakes,
    /// Enable negotiated checksum and segmentation offloads.
    NetworkOffload,
    /// Enable virtio-net multiqueue.
    NetworkMultiqueue,
    /// Batch host vCPU accounting updates.
    VcpuAccounting,
    /// Open managed flat root disks with direct I/O.
    FlatDirectIo,
    /// Parse each virtio-blk descriptor chain once.
    BlockDescriptors,
    /// Batch virtio-blk used-ring interrupts.
    BlockCompletions,
    /// Use data-only durability barriers where metadata durability is unnecessary.
    BlockFdatasync,
    /// Use bounded io_uring submission on supported Linux hosts.
    BlockIoUring,
    /// Enable virtio-blk multiqueue with ordered flush epochs.
    BlockMultiqueue,
    /// Merge OCI layer metadata before copying surviving file contents.
    ColdMaterialization,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PerfExperiment {
    /// Return the stable selector used in [`PERF_EXPERIMENTS_ENV`].
    pub const fn name(self) -> &'static str {
        match self {
            Self::MetricsResidency => "metrics-residency",
            Self::ShutdownReady => "shutdown-ready",
            Self::NetworkBuffers => "network-buffers",
            Self::NetworkWakes => "network-wakes",
            Self::NetworkOffload => "network-offload",
            Self::NetworkMultiqueue => "network-multiqueue",
            Self::VcpuAccounting => "vcpu-accounting",
            Self::FlatDirectIo => "flat-direct-io",
            Self::BlockDescriptors => "block-descriptors",
            Self::BlockCompletions => "block-completions",
            Self::BlockFdatasync => "block-fdatasync",
            Self::BlockIoUring => "block-io-uring",
            Self::BlockMultiqueue => "block-multiqueue",
            Self::ColdMaterialization => "cold-materialization",
        }
    }

    /// Return the subsystem selector that enables this experiment as a group.
    pub const fn group(self) -> &'static str {
        match self {
            Self::MetricsResidency => "metrics",
            Self::ShutdownReady => "shutdown",
            Self::NetworkBuffers
            | Self::NetworkWakes
            | Self::NetworkOffload
            | Self::NetworkMultiqueue => "network",
            Self::VcpuAccounting => "vcpu",
            Self::FlatDirectIo => "flat",
            Self::BlockDescriptors
            | Self::BlockCompletions
            | Self::BlockFdatasync
            | Self::BlockIoUring
            | Self::BlockMultiqueue => "block",
            Self::ColdMaterialization => "materialization",
        }
    }

    /// Return whether this experiment is enabled in the current process.
    pub fn enabled(self) -> bool {
        std::env::var(PERF_EXPERIMENTS_ENV)
            .ok()
            .is_some_and(|raw| self.enabled_in(&raw))
    }

    /// Return whether this experiment is selected by a raw comma-separated value.
    pub fn enabled_in(self, raw: &str) -> bool {
        raw.split(',').map(str::trim).any(|selector| {
            selector.eq_ignore_ascii_case("all")
                || selector.eq_ignore_ascii_case(self.group())
                || selector.eq_ignore_ascii_case(self.name())
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn individual_selector_enables_only_the_named_experiment() {
        assert!(PerfExperiment::NetworkBuffers.enabled_in("network-buffers"));
        assert!(!PerfExperiment::NetworkWakes.enabled_in("network-buffers"));
    }

    #[test]
    fn subsystem_and_all_selectors_expand_without_affecting_defaults() {
        assert!(PerfExperiment::BlockIoUring.enabled_in("block"));
        assert!(PerfExperiment::ShutdownReady.enabled_in("all"));
        assert!(!PerfExperiment::ShutdownReady.enabled_in(""));
    }
}

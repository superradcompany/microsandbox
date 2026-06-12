//! In-memory snapshot types produced by registry reads.

use std::time::Duration;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Coherent live sample read from a single registry slot.
///
/// Carries both identity (sandbox_id, run_id, pid, name) and the metric
/// fields in one struct, matching the on-disk slot layout. Consumers that
/// only want the metric values can convert to [`SandboxMetrics`] via
/// [`SandboxMetricSnapshot::from`].
#[derive(Clone, Debug)]
pub struct LiveMetric {
    /// Catalog sandbox id.
    pub sandbox_id: i32,
    /// Catalog run id.
    pub run_id: i32,
    /// PID of the runtime process that owns the slot.
    pub pid: i32,
    /// UTF-8 sandbox name stored inline in the slot.
    pub name: String,
    /// Wall-clock time at which the most recent sample was written.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Time elapsed between sandbox start and the sample timestamp.
    pub uptime: Duration,
    /// Guest vCPU usage as a percentage.
    pub cpu_percent: f32,
    /// Cumulative guest vCPU execution time across all vCPUs.
    pub vcpu_time_ns: u64,
    /// Guest-used memory in bytes.
    pub memory_bytes: u64,
    /// Guest-available memory in bytes when reported by the guest.
    pub memory_available_bytes: Option<u64>,
    /// Host-resident guest memory in bytes for capacity diagnostics.
    pub memory_host_resident_bytes: Option<u64>,
    /// Configured memory limit in bytes.
    pub memory_limit_bytes: u64,
    /// Cumulative guest logical storage bytes read.
    pub disk_read_bytes: u64,
    /// Cumulative guest logical storage bytes written.
    pub disk_write_bytes: u64,
    /// Cumulative guest-facing network bytes received.
    pub net_rx_bytes: u64,
    /// Cumulative guest-facing network bytes transmitted.
    pub net_tx_bytes: u64,
}

/// Point-in-time metrics for a running sandbox (no identity fields).
#[derive(Clone, Debug, PartialEq)]
pub struct SandboxMetrics {
    /// Guest vCPU usage as a percentage.
    pub cpu_percent: f32,
    /// Cumulative guest vCPU execution time across all vCPUs.
    pub vcpu_time_ns: u64,
    /// Guest-used memory in bytes.
    pub memory_bytes: u64,
    /// Guest-available memory in bytes when reported by the guest.
    pub memory_available_bytes: Option<u64>,
    /// Host-resident guest memory in bytes for capacity diagnostics.
    pub memory_host_resident_bytes: Option<u64>,
    /// Configured guest memory limit in bytes.
    pub memory_limit_bytes: u64,
    /// Cumulative guest logical storage bytes read.
    pub disk_read_bytes: u64,
    /// Cumulative guest logical storage bytes written.
    pub disk_write_bytes: u64,
    /// Cumulative network bytes delivered from the runtime to the guest.
    pub net_rx_bytes: u64,
    /// Cumulative network bytes transmitted from the guest into the runtime.
    pub net_tx_bytes: u64,
    /// Sandbox uptime at the moment the sample was taken.
    pub uptime: Duration,
    /// Timestamp of the sample.
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Metrics plus shared-memory identity metadata for one active sandbox slot.
#[derive(Clone, Debug, PartialEq)]
pub struct SandboxMetricSnapshot {
    /// Catalog sandbox id.
    pub sandbox_id: i32,
    /// Catalog run id.
    pub run_id: i32,
    /// Runtime process id that owns the metrics slot.
    pub pid: i32,
    /// Sandbox name.
    pub name: String,
    /// Resource metrics sample.
    pub metrics: SandboxMetrics,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl From<LiveMetric> for SandboxMetricSnapshot {
    fn from(live: LiveMetric) -> Self {
        Self {
            sandbox_id: live.sandbox_id,
            run_id: live.run_id,
            pid: live.pid,
            name: live.name,
            metrics: SandboxMetrics {
                cpu_percent: live.cpu_percent,
                vcpu_time_ns: live.vcpu_time_ns,
                memory_bytes: live.memory_bytes,
                memory_available_bytes: live.memory_available_bytes,
                memory_host_resident_bytes: live.memory_host_resident_bytes,
                memory_limit_bytes: live.memory_limit_bytes,
                disk_read_bytes: live.disk_read_bytes,
                disk_write_bytes: live.disk_write_bytes,
                net_rx_bytes: live.net_rx_bytes,
                net_tx_bytes: live.net_tx_bytes,
                uptime: live.uptime,
                timestamp: live.timestamp,
            },
        }
    }
}

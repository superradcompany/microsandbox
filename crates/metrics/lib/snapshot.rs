//! In-memory snapshot type produced by registry reads.

use std::time::Duration;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Coherent live sample read from a single registry slot.
#[derive(Clone, Debug)]
pub struct LiveMetric {
    /// Catalog sandbox id.
    pub sandbox_id: i32,
    /// Catalog run id.
    pub run_id: i32,
    /// PID of the runtime process that owns the slot.
    pub pid: i32,
    /// UTF-8 sandbox name (truncated to the slot capacity).
    pub name: String,
    /// Wall-clock time at which the most recent sample was written.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Time elapsed between sandbox start and the sample timestamp.
    pub uptime: Duration,
    /// CPU usage as a percentage across all host CPUs.
    pub cpu_percent: f32,
    /// Resident memory in bytes.
    pub memory_bytes: u64,
    /// Configured memory limit in bytes.
    pub memory_limit_bytes: u64,
    /// Cumulative disk bytes read.
    pub disk_read_bytes: u64,
    /// Cumulative disk bytes written.
    pub disk_write_bytes: u64,
    /// Cumulative network bytes received.
    pub net_rx_bytes: u64,
    /// Cumulative network bytes transmitted.
    pub net_tx_bytes: u64,
}

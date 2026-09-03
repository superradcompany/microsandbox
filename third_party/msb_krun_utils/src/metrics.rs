// Copyright 2026 Super Rad Company
// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

type HostResidentMemorySampler = dyn Fn() -> Option<u64> + Send + Sync + 'static;

/// Cloneable handle for point-in-time VM metrics.
#[derive(Clone, Debug, Default)]
pub struct MetricsHandle {
    state: Arc<MetricsState>,
}

/// Cloneable writer for VMM and device metrics.
#[derive(Clone, Debug, Default)]
pub struct MetricsWriter {
    state: Arc<MetricsState>,
}

/// Cloneable writer for one block device's metrics.
#[derive(Clone, Debug)]
pub struct BlockMetricsWriter {
    state: Arc<MetricsState>,
    device: Arc<BlockDeviceState>,
}

/// Point-in-time VM metrics.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VmMetrics {
    /// CPU metrics.
    pub cpu: CpuMetrics,
    /// Memory metrics.
    pub memory: MemoryMetrics,
    /// Block device metrics.
    pub block: BlockMetrics,
    /// Filesystem metrics.
    pub filesystem: FilesystemMetrics,
}

/// CPU metrics.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CpuMetrics {
    /// Cumulative guest vCPU execution time across all vCPUs when available.
    pub vcpu_time_ns: Option<u64>,
}

/// Memory metrics.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MemoryMetrics {
    /// Configured guest physical memory.
    pub total_bytes: u64,
    /// Guest-available memory when reported by virtio-balloon stats.
    pub available_bytes: Option<u64>,
    /// Derived guest-used memory when available.
    pub used_bytes: Option<u64>,
    /// Host-resident guest memory pages when the VMM can report them.
    pub host_resident_bytes: Option<u64>,
}

/// Aggregate block metrics.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BlockMetrics {
    /// Successful guest logical bytes read from block devices.
    pub read_bytes: u64,
    /// Successful guest logical bytes written to block devices.
    pub write_bytes: u64,
    /// Per-device block metrics.
    pub devices: Vec<BlockDeviceMetrics>,
}

/// Per-device block metrics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockDeviceMetrics {
    /// VMM block device id.
    pub id: String,
    /// Successful guest logical bytes read from this block device.
    pub read_bytes: u64,
    /// Successful guest logical bytes written to this block device.
    pub write_bytes: u64,
}

/// Filesystem metrics.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FilesystemMetrics {
    /// Guest-visible used bytes on the microsandbox OCI upper filesystem.
    pub upper_used_bytes: Option<u64>,
    /// Guest-visible bytes available to ordinary allocation on the microsandbox OCI upper filesystem.
    pub upper_free_bytes: Option<u64>,
    /// Unix milliseconds when the upper filesystem sample was received by the host.
    pub upper_sampled_at_unix_ms: Option<u64>,
}

struct MetricsState {
    vcpu_time_ns: AtomicU64,
    vcpu_time_valid: AtomicU64,
    memory_total_bytes: AtomicU64,
    memory_available_bytes: AtomicU64,
    memory_available_valid: AtomicU64,
    memory_host_resident_bytes: AtomicU64,
    memory_host_resident_valid: AtomicU64,
    memory_host_resident_sampler: Mutex<Option<Arc<HostResidentMemorySampler>>>,
    block_read_bytes: AtomicU64,
    block_write_bytes: AtomicU64,
    block_devices: Mutex<Vec<Arc<BlockDeviceState>>>,
    filesystem_upper_used_bytes: AtomicU64,
    filesystem_upper_used_valid: AtomicU64,
    filesystem_upper_free_bytes: AtomicU64,
    filesystem_upper_free_valid: AtomicU64,
    filesystem_upper_sampled_at_unix_ms: AtomicU64,
}

#[derive(Debug)]
struct BlockDeviceState {
    id: String,
    read_bytes: AtomicU64,
    write_bytes: AtomicU64,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl MetricsHandle {
    /// Return a coherent-enough snapshot of current VM metrics.
    ///
    /// Counters are monotonic atomics. Callers that need rates should compute
    /// deltas between snapshots.
    pub fn snapshot(&self) -> VmMetrics {
        self.snapshot_inner(true)
    }

    /// Return aggregate VM metrics without per-device block details.
    ///
    /// This avoids cloning the per-device vector for high-frequency samplers
    /// that only publish aggregate counters.
    pub fn aggregate_snapshot(&self) -> VmMetrics {
        self.snapshot_inner(false)
    }

    fn snapshot_inner(&self, include_block_devices: bool) -> VmMetrics {
        let total_bytes = self.state.memory_total_bytes.load(Ordering::Relaxed);
        let available_bytes = valid_value(
            &self.state.memory_available_valid,
            &self.state.memory_available_bytes,
        );
        let host_resident_bytes = self.host_resident_bytes();
        VmMetrics {
            cpu: CpuMetrics {
                vcpu_time_ns: valid_value(&self.state.vcpu_time_valid, &self.state.vcpu_time_ns),
            },
            memory: MemoryMetrics {
                total_bytes,
                available_bytes,
                used_bytes: available_bytes
                    .and_then(|available| total_bytes.checked_sub(available)),
                host_resident_bytes,
            },
            block: BlockMetrics {
                read_bytes: self.state.block_read_bytes.load(Ordering::Relaxed),
                write_bytes: self.state.block_write_bytes.load(Ordering::Relaxed),
                devices: if include_block_devices {
                    self.state
                        .block_devices
                        .lock()
                        .unwrap()
                        .iter()
                        .map(|device| BlockDeviceMetrics {
                            id: device.id.clone(),
                            read_bytes: device.read_bytes.load(Ordering::Relaxed),
                            write_bytes: device.write_bytes.load(Ordering::Relaxed),
                        })
                        .collect()
                } else {
                    Vec::new()
                },
            },
            filesystem: FilesystemMetrics {
                upper_used_bytes: valid_value(
                    &self.state.filesystem_upper_used_valid,
                    &self.state.filesystem_upper_used_bytes,
                ),
                upper_free_bytes: valid_value(
                    &self.state.filesystem_upper_free_valid,
                    &self.state.filesystem_upper_free_bytes,
                ),
                upper_sampled_at_unix_ms: valid_value(
                    &self.state.filesystem_upper_used_valid,
                    &self.state.filesystem_upper_sampled_at_unix_ms,
                ),
            },
        }
    }

    fn host_resident_bytes(&self) -> Option<u64> {
        let sampler = self
            .state
            .memory_host_resident_sampler
            .lock()
            .unwrap()
            .clone();
        if let Some(sampler) = sampler {
            match sampler() {
                Some(bytes) => {
                    self.state
                        .memory_host_resident_bytes
                        .store(bytes, Ordering::Relaxed);
                    self.state
                        .memory_host_resident_valid
                        .store(1, Ordering::Release);
                }
                None => {
                    self.state
                        .memory_host_resident_valid
                        .store(0, Ordering::Release);
                    return None;
                }
            }
        }

        valid_value(
            &self.state.memory_host_resident_valid,
            &self.state.memory_host_resident_bytes,
        )
    }
}

impl MetricsWriter {
    /// Return a public read handle for this metrics state.
    pub fn handle(&self) -> MetricsHandle {
        MetricsHandle {
            state: Arc::clone(&self.state),
        }
    }

    /// Set configured guest memory.
    pub fn set_memory_total_bytes(&self, bytes: u64) {
        self.state
            .memory_total_bytes
            .store(bytes, Ordering::Relaxed);
    }

    /// Set guest-available memory.
    pub fn set_memory_available_bytes(&self, bytes: u64) {
        self.state
            .memory_available_bytes
            .store(bytes, Ordering::Relaxed);
        self.state
            .memory_available_valid
            .store(1, Ordering::Release);
    }

    /// Set host-resident guest memory.
    pub fn set_memory_host_resident_bytes(&self, bytes: u64) {
        self.state
            .memory_host_resident_bytes
            .store(bytes, Ordering::Relaxed);
        self.state
            .memory_host_resident_valid
            .store(1, Ordering::Release);
    }

    /// Register a sampler that refreshes host-resident guest memory during snapshots.
    pub fn set_memory_host_resident_sampler<F>(&self, sampler: F)
    where
        F: Fn() -> Option<u64> + Send + Sync + 'static,
    {
        *self.state.memory_host_resident_sampler.lock().unwrap() = Some(Arc::new(sampler));
    }

    /// Set guest-visible OCI upper filesystem used/free bytes.
    pub fn set_upper_filesystem_bytes(&self, used_bytes: u64, free_bytes: u64) {
        self.state
            .filesystem_upper_used_bytes
            .store(used_bytes, Ordering::Relaxed);
        self.state
            .filesystem_upper_free_bytes
            .store(free_bytes, Ordering::Relaxed);
        self.state
            .filesystem_upper_sampled_at_unix_ms
            .store(unix_timestamp_ms(), Ordering::Relaxed);
        self.state
            .filesystem_upper_used_valid
            .store(1, Ordering::Release);
        self.state
            .filesystem_upper_free_valid
            .store(1, Ordering::Release);
    }

    /// Clear guest-visible OCI upper filesystem metrics.
    pub fn clear_upper_filesystem_bytes(&self) {
        self.state
            .filesystem_upper_used_valid
            .store(0, Ordering::Release);
        self.state
            .filesystem_upper_free_valid
            .store(0, Ordering::Release);
    }

    /// Add guest vCPU execution time.
    pub fn add_vcpu_time_ns(&self, ns: u64) {
        self.state.vcpu_time_ns.fetch_add(ns, Ordering::Relaxed);
        self.state.vcpu_time_valid.store(1, Ordering::Release);
    }

    /// Register one block device and return a device-scoped metrics writer.
    pub fn register_block_device(&self, id: String) -> BlockMetricsWriter {
        let device = Arc::new(BlockDeviceState {
            id,
            read_bytes: AtomicU64::new(0),
            write_bytes: AtomicU64::new(0),
        });
        self.state
            .block_devices
            .lock()
            .unwrap()
            .push(Arc::clone(&device));
        BlockMetricsWriter {
            state: Arc::clone(&self.state),
            device,
        }
    }
}

impl BlockMetricsWriter {
    /// Add successful guest logical block read bytes.
    pub fn add_read_bytes(&self, bytes: u64) {
        self.state
            .block_read_bytes
            .fetch_add(bytes, Ordering::Relaxed);
        self.device.read_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Add successful guest logical block write bytes.
    pub fn add_write_bytes(&self, bytes: u64) {
        self.state
            .block_write_bytes
            .fetch_add(bytes, Ordering::Relaxed);
        self.device.write_bytes.fetch_add(bytes, Ordering::Relaxed);
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for MetricsState {
    fn default() -> Self {
        Self {
            vcpu_time_ns: AtomicU64::new(0),
            vcpu_time_valid: AtomicU64::new(0),
            memory_total_bytes: AtomicU64::new(0),
            memory_available_bytes: AtomicU64::new(0),
            memory_available_valid: AtomicU64::new(0),
            memory_host_resident_bytes: AtomicU64::new(0),
            memory_host_resident_valid: AtomicU64::new(0),
            memory_host_resident_sampler: Mutex::new(None),
            block_read_bytes: AtomicU64::new(0),
            block_write_bytes: AtomicU64::new(0),
            block_devices: Mutex::new(Vec::new()),
            filesystem_upper_used_bytes: AtomicU64::new(0),
            filesystem_upper_used_valid: AtomicU64::new(0),
            filesystem_upper_free_bytes: AtomicU64::new(0),
            filesystem_upper_free_valid: AtomicU64::new(0),
            filesystem_upper_sampled_at_unix_ms: AtomicU64::new(0),
        }
    }
}

impl fmt::Debug for MetricsState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MetricsState").finish_non_exhaustive()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn valid_value(valid: &AtomicU64, value: &AtomicU64) -> Option<u64> {
    if valid.load(Ordering::Acquire) == 0 {
        None
    } else {
        Some(value.load(Ordering::Relaxed))
    }
}

fn unix_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_time_is_unavailable_until_written() {
        let writer = MetricsWriter::default();

        assert_eq!(writer.handle().snapshot().cpu.vcpu_time_ns, None);

        writer.add_vcpu_time_ns(12);

        assert_eq!(writer.handle().snapshot().cpu.vcpu_time_ns, Some(12));
    }

    #[test]
    fn memory_used_is_derived_from_configured_total_and_available() {
        let writer = MetricsWriter::default();

        writer.set_memory_total_bytes(1024);

        let snapshot = writer.handle().snapshot();
        assert_eq!(snapshot.memory.total_bytes, 1024);
        assert_eq!(snapshot.memory.available_bytes, None);
        assert_eq!(snapshot.memory.used_bytes, None);

        writer.set_memory_available_bytes(256);

        let snapshot = writer.handle().snapshot();
        assert_eq!(snapshot.memory.available_bytes, Some(256));
        assert_eq!(snapshot.memory.used_bytes, Some(768));
    }

    #[test]
    fn memory_used_is_unavailable_when_available_exceeds_total() {
        let writer = MetricsWriter::default();

        writer.set_memory_total_bytes(1024);
        writer.set_memory_available_bytes(2048);

        let snapshot = writer.handle().snapshot();
        assert_eq!(snapshot.memory.available_bytes, Some(2048));
        assert_eq!(snapshot.memory.used_bytes, None);
    }

    #[test]
    fn host_resident_sampler_refreshes_snapshot() {
        let writer = MetricsWriter::default();
        let value = Arc::new(AtomicU64::new(4096));
        let sampler_value = Arc::clone(&value);

        writer
            .set_memory_host_resident_sampler(move || Some(sampler_value.load(Ordering::Relaxed)));

        assert_eq!(
            writer.handle().snapshot().memory.host_resident_bytes,
            Some(4096)
        );

        value.store(8192, Ordering::Relaxed);

        assert_eq!(
            writer.handle().snapshot().memory.host_resident_bytes,
            Some(8192)
        );
    }

    #[test]
    fn host_resident_sampler_failure_clears_previous_value() {
        let writer = MetricsWriter::default();
        let value = Arc::new(AtomicU64::new(4096));
        let sampler_value = Arc::clone(&value);

        writer.set_memory_host_resident_sampler(move || {
            match sampler_value.load(Ordering::Relaxed) {
                0 => None,
                bytes => Some(bytes),
            }
        });

        assert_eq!(
            writer.handle().snapshot().memory.host_resident_bytes,
            Some(4096)
        );

        value.store(0, Ordering::Relaxed);

        assert_eq!(writer.handle().snapshot().memory.host_resident_bytes, None);
    }

    #[test]
    fn block_metrics_include_aggregate_and_per_device_counters() {
        let writer = MetricsWriter::default();
        let root = writer.register_block_device("root".to_string());
        let data = writer.register_block_device("data".to_string());

        root.add_read_bytes(128);
        root.add_write_bytes(256);
        data.add_read_bytes(512);

        let snapshot = writer.handle().snapshot();
        assert_eq!(snapshot.block.read_bytes, 640);
        assert_eq!(snapshot.block.write_bytes, 256);
        assert_eq!(
            snapshot.block.devices,
            vec![
                BlockDeviceMetrics {
                    id: "root".to_string(),
                    read_bytes: 128,
                    write_bytes: 256,
                },
                BlockDeviceMetrics {
                    id: "data".to_string(),
                    read_bytes: 512,
                    write_bytes: 0,
                },
            ]
        );
    }

    #[test]
    fn aggregate_snapshot_omits_per_device_block_counters() {
        let writer = MetricsWriter::default();
        let root = writer.register_block_device("root".to_string());

        root.add_read_bytes(128);
        root.add_write_bytes(256);

        let snapshot = writer.handle().aggregate_snapshot();
        assert_eq!(snapshot.block.read_bytes, 128);
        assert_eq!(snapshot.block.write_bytes, 256);
        assert!(snapshot.block.devices.is_empty());
    }

    #[test]
    fn filesystem_metrics_are_unavailable_until_written() {
        let writer = MetricsWriter::default();

        assert_eq!(
            writer.handle().snapshot().filesystem,
            FilesystemMetrics::default()
        );

        writer.set_upper_filesystem_bytes(4096, 8192);

        let snapshot = writer.handle().snapshot();
        assert_eq!(snapshot.filesystem.upper_used_bytes, Some(4096));
        assert_eq!(snapshot.filesystem.upper_free_bytes, Some(8192));
        assert!(snapshot.filesystem.upper_sampled_at_unix_ms.is_some());
    }

    #[test]
    fn filesystem_metrics_can_be_cleared() {
        let writer = MetricsWriter::default();

        writer.set_upper_filesystem_bytes(4096, 8192);
        writer.clear_upper_filesystem_bytes();

        assert_eq!(
            writer.handle().snapshot().filesystem,
            FilesystemMetrics::default()
        );
    }
}

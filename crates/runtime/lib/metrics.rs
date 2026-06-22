//! Sandbox guest metrics sampling and shared-memory publication.
//!
//! Samples come from `msb_krun` VMM/device counters plus the runtime network
//! boundary counters. They are written into the process's reserved slot in the
//! shared-memory registry. The catalog database is not touched on the
//! per-sample path; lifecycle rows still flow through `DbWriteConnection`.

use std::num::NonZero;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, Instant};

use microsandbox_metrics::{MetricsError, MetricsSlotWriter, SampleWrite};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Default sampling interval used when the caller does not configure one.
pub const DEFAULT_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);

/// Minimum age after which protected upper filesystem samples are treated as stale.
const MIN_UPPER_FILESYSTEM_STALE_AFTER: Duration = Duration::from_secs(3);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Optional runtime-supplied network byte counters.
pub trait NetworkMetrics: Send + Sync {
    /// Bytes transmitted by the guest into the runtime.
    fn tx_bytes(&self) -> u64;

    /// Bytes received by the guest from the runtime.
    fn rx_bytes(&self) -> u64;
}

impl NetworkMetrics for () {
    fn tx_bytes(&self) -> u64 {
        0
    }

    fn rx_bytes(&self) -> u64 {
        0
    }
}

#[cfg(feature = "net")]
impl NetworkMetrics for microsandbox_network::network::MetricsHandle {
    fn tx_bytes(&self) -> u64 {
        microsandbox_network::network::MetricsHandle::tx_bytes(self)
    }

    fn rx_bytes(&self) -> u64 {
        microsandbox_network::network::MetricsHandle::rx_bytes(self)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Run the background metrics sampler until the sandbox process exits or
/// the slot is reclaimed.
pub async fn run_metrics_sampler(
    writer: MetricsSlotWriter,
    sandbox_id: i32,
    pid: u32,
    interval_ms: NonZero<u64>,
    krun_metrics: msb_krun::MetricsHandle,
    network_metrics: Option<Box<dyn NetworkMetrics>>,
    upper_host_path: Option<std::path::PathBuf>,
) {
    let interval = Duration::from_millis(interval_ms.get());
    let upper_stale_after = upper_filesystem_stale_after(interval);
    let mut previous = krun_metrics.aggregate_snapshot();
    let mut previous_instant = Instant::now();
    let upper_host_path = upper_host_path.as_deref();

    match write_sample(
        &writer,
        None,
        &previous,
        network_metrics.as_deref(),
        upper_host_path,
        upper_stale_after,
    ) {
        Ok(()) => {}
        Err(SampleWriteError::Generation) => {
            tracing::info!(
                sandbox_id,
                pid,
                "metrics slot reclaimed before first sample; stopping sampler"
            );
            return;
        }
        Err(SampleWriteError::Other(err)) => {
            tracing::warn!(sandbox_id, pid, error = %err, "failed to write initial sandbox metrics");
        }
    }

    loop {
        tokio::time::sleep(interval).await;

        let current = krun_metrics.aggregate_snapshot();
        let now = Instant::now();
        let wall_secs = now
            .checked_duration_since(previous_instant)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        let cpu_percent = cpu_percent_from_vcpu_time(
            current.cpu.vcpu_time_ns,
            previous.cpu.vcpu_time_ns,
            wall_secs,
        );

        match write_sample(
            &writer,
            cpu_percent,
            &current,
            network_metrics.as_deref(),
            upper_host_path,
            upper_stale_after,
        ) {
            Ok(()) => {}
            Err(SampleWriteError::Generation) => {
                tracing::info!(sandbox_id, pid, "metrics slot reclaimed; stopping sampler");
                break;
            }
            Err(SampleWriteError::Other(err)) => {
                tracing::warn!(sandbox_id, pid, error = %err, "failed to write sandbox metrics");
            }
        }

        previous = current;
        previous_instant = now;
    }
}

enum SampleWriteError {
    Generation,
    Other(MetricsError),
}

fn write_sample(
    writer: &MetricsSlotWriter,
    cpu_percent: Option<f32>,
    krun: &msb_krun::VmMetrics,
    network_metrics: Option<&dyn NetworkMetrics>,
    upper_host_path: Option<&Path>,
    upper_stale_after: Duration,
) -> Result<(), SampleWriteError> {
    let (rx, tx) = match network_metrics {
        Some(m) => (m.rx_bytes(), m.tx_bytes()),
        None => (0, 0),
    };
    let (upper_used_bytes, upper_free_bytes) =
        upper_filesystem_metrics(krun, upper_stale_after, chrono::Utc::now());
    let sample = SampleWrite {
        sampled_at: chrono::Utc::now(),
        cpu_percent,
        vcpu_time_ns: krun.cpu.vcpu_time_ns,
        memory_bytes: krun.memory.used_bytes,
        memory_available_bytes: krun.memory.available_bytes,
        memory_host_resident_bytes: krun.memory.host_resident_bytes,
        disk_read_bytes: krun.block.read_bytes,
        disk_write_bytes: krun.block.write_bytes,
        net_rx_bytes: rx,
        net_tx_bytes: tx,
        upper_used_bytes,
        upper_free_bytes,
        upper_host_allocated_bytes: upper_host_allocated_bytes(upper_host_path),
    };
    match writer.write_sample(sample) {
        Ok(()) => Ok(()),
        Err(MetricsError::GenerationMismatch { .. }) => Err(SampleWriteError::Generation),
        Err(other) => Err(SampleWriteError::Other(other)),
    }
}

fn upper_host_allocated_bytes(path: Option<&Path>) -> Option<u64> {
    let path = path?;
    #[cfg(unix)]
    {
        let metadata = std::fs::metadata(path).ok()?;
        Some(metadata.blocks().saturating_mul(512))
    }
    #[cfg(windows)]
    {
        let _ = path;
        None
    }
}

fn upper_filesystem_metrics(
    krun: &msb_krun::VmMetrics,
    stale_after: Duration,
    now: chrono::DateTime<chrono::Utc>,
) -> (Option<u64>, Option<u64>) {
    let _ = (krun, stale_after, now);
    (None, None)
}

fn upper_filesystem_stale_after(interval: Duration) -> Duration {
    let millis = interval
        .as_millis()
        .saturating_mul(3)
        .max(MIN_UPPER_FILESYSTEM_STALE_AFTER.as_millis())
        .min(u128::from(u64::MAX)) as u64;
    Duration::from_millis(millis)
}

fn cpu_percent_from_vcpu_time(
    current_ns: Option<u64>,
    previous_ns: Option<u64>,
    wall_secs: f64,
) -> Option<f32> {
    match (current_ns, previous_ns) {
        (Some(current_ns), Some(previous_ns)) if wall_secs > 0.0 => {
            let vcpu_delta_ns = current_ns.saturating_sub(previous_ns);
            Some((((vcpu_delta_ns as f64 / 1_000_000_000.0) / wall_secs) * 100.0) as f32)
        }
        _ => None,
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::ffi::CString;

    use super::*;
    use microsandbox_metrics::{ActivateSlot, MetricsRegistry, ReserveSlot};

    fn unique_shm_name(tag: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("/msb-rtm-{tag}-{}", nanos & 0xffff_ffff)
    }

    fn cleanup_shm(name: &str) {
        #[cfg(unix)]
        {
            let cname = CString::new(name).unwrap();
            unsafe {
                libc::shm_unlink(cname.as_ptr());
            }
        }

        #[cfg(not(unix))]
        let _ = name;
    }

    #[test]
    fn cpu_percent_uses_vcpu_seconds_over_wall_seconds() {
        assert_eq!(
            cpu_percent_from_vcpu_time(Some(2_000_000_000), Some(1_000_000_000), 1.0),
            Some(100.0)
        );
        assert_eq!(
            cpu_percent_from_vcpu_time(Some(3_000_000_000), Some(1_000_000_000), 1.0),
            Some(200.0)
        );
        assert_eq!(
            cpu_percent_from_vcpu_time(Some(1_000_000_000), Some(2_000_000_000), 1.0),
            Some(0.0)
        );
        assert_eq!(cpu_percent_from_vcpu_time(None, Some(0), 1.0), None);
        assert_eq!(cpu_percent_from_vcpu_time(Some(0), Some(0), 0.0), None);
    }

    #[test]
    #[cfg(unix)]
    fn upper_host_allocated_bytes_uses_allocated_blocks() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), vec![1_u8; 8192]).unwrap();

        let metadata = std::fs::metadata(file.path()).unwrap();

        assert_eq!(
            upper_host_allocated_bytes(Some(file.path())),
            Some(metadata.blocks().saturating_mul(512))
        );
    }

    #[test]
    fn upper_host_allocated_bytes_returns_none_without_path() {
        assert_eq!(upper_host_allocated_bytes(None), None);
    }

    #[test]
    fn write_sample_leaves_upper_filesystem_metrics_empty_when_unavailable() {
        let name = unique_shm_name("upper-empty");
        let registry = MetricsRegistry::open_or_create(&name, 1).unwrap();
        let reserved = registry
            .reserve(ReserveSlot {
                sandbox_id: 7,
                name: "upper-empty",
                memory_limit_bytes: 512 * 1024 * 1024,
            })
            .unwrap();
        let writer = registry
            .activate_writer(ActivateSlot {
                slot: reserved.slot,
                generation: reserved.generation,
                run_id: 9,
                pid: std::process::id() as i32,
                started_at: chrono::Utc::now(),
            })
            .unwrap();
        let krun = msb_krun::VmMetrics::default();

        assert!(write_sample(&writer, None, &krun, None, None, Duration::from_secs(3)).is_ok());

        let snapshot = registry.snapshot().unwrap();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].upper_used_bytes, None);
        assert_eq!(snapshot[0].upper_free_bytes, None);
        cleanup_shm(&name);
    }

    #[test]
    fn upper_filesystem_metrics_returns_none_when_krun_has_no_sample() {
        let now = chrono::Utc::now();
        let krun = msb_krun::VmMetrics::default();

        assert_eq!(
            upper_filesystem_metrics(&krun, Duration::from_secs(3), now),
            (None, None)
        );
    }

    #[test]
    fn upper_filesystem_stale_after_scales_with_sample_interval() {
        assert_eq!(
            upper_filesystem_stale_after(Duration::from_millis(250)),
            Duration::from_secs(3)
        );
        assert_eq!(
            upper_filesystem_stale_after(Duration::from_secs(10)),
            Duration::from_secs(30)
        );
    }
}

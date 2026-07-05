//! Sandbox guest metrics sampling and shared-memory publication.
//!
//! Samples come from `msb_krun` VMM/device counters plus the runtime network
//! boundary counters. They are written into the process's reserved slot in the
//! shared-memory registry. The catalog database is not touched on the
//! per-sample path; lifecycle rows still flow through `DbWriteConnection`.

use std::num::NonZero;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::time::{Duration, Instant};

use microsandbox_metrics::{MetricsError, MetricsSlotWriter, SampleWrite};
#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::{GetLastError, NO_ERROR},
    Storage::FileSystem::GetCompressedFileSizeW,
};

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

/// Inputs for [`run_metrics_sampler`].
pub struct MetricsSamplerSpec {
    /// Slot writer owning the sandbox's registry slot.
    pub writer: MetricsSlotWriter,
    /// Catalog sandbox id, used for diagnostics.
    pub sandbox_id: i32,
    /// Runtime process id, used for diagnostics.
    pub pid: u32,
    /// Sampling interval in milliseconds.
    pub interval_ms: NonZero<u64>,
    /// vCPU hotplug ceiling; CPU readings are clamped to `max_cpus * 100`.
    pub max_cpus: u8,
    /// VMM metrics source.
    pub krun_metrics: msb_krun::MetricsHandle,
    /// Optional runtime network byte counters.
    pub network_metrics: Option<Box<dyn NetworkMetrics>>,
    /// Host path of the writable upper image, when one exists.
    pub upper_host_path: Option<std::path::PathBuf>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Run the background metrics sampler until the sandbox process exits or
/// the slot is reclaimed.
pub async fn run_metrics_sampler(spec: MetricsSamplerSpec) {
    let MetricsSamplerSpec {
        writer,
        sandbox_id,
        pid,
        interval_ms,
        max_cpus,
        krun_metrics,
        network_metrics,
        upper_host_path,
    } = spec;
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
        let cpu_percent = clamp_cpu_percent(
            cpu_percent_from_vcpu_time(
                current.cpu.vcpu_time_ns,
                previous.cpu.vcpu_time_ns,
                wall_secs,
            ),
            max_cpus,
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
        windows_allocated_file_bytes(path).ok()
    }
}

#[cfg(windows)]
fn windows_allocated_file_bytes(path: &Path) -> std::io::Result<u64> {
    let mut high = 0_u32;
    let path_wide = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let low = unsafe { GetCompressedFileSizeW(path_wide.as_ptr(), &mut high) };
    if low == u32::MAX {
        let error = unsafe { GetLastError() };
        if error != NO_ERROR {
            return Err(std::io::Error::from_raw_os_error(error as i32));
        }
    }

    Ok((u64::from(high) << 32) | u64::from(low))
}

fn upper_filesystem_metrics(
    krun: &msb_krun::VmMetrics,
    stale_after: Duration,
    now: chrono::DateTime<chrono::Utc>,
) -> (Option<u64>, Option<u64>) {
    let (Some(used), Some(free), Some(sampled_at_ms)) = (
        krun.filesystem.upper_used_bytes,
        krun.filesystem.upper_free_bytes,
        krun.filesystem.upper_sampled_at_unix_ms,
    ) else {
        return (None, None);
    };

    if upper_filesystem_sample_is_fresh(sampled_at_ms, stale_after, now) {
        (Some(used), Some(free))
    } else {
        (None, None)
    }
}

fn upper_filesystem_sample_is_fresh(
    sampled_at_ms: u64,
    stale_after: Duration,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    let now_ms = now.timestamp_millis();
    if now_ms < 0 {
        return false;
    }
    let now_ms = now_ms as u64;
    sampled_at_ms >= now_ms || now_ms.saturating_sub(sampled_at_ms) <= duration_millis(stale_after)
}

fn upper_filesystem_stale_after(interval: Duration) -> Duration {
    let millis = interval
        .as_millis()
        .saturating_mul(3)
        .max(MIN_UPPER_FILESYSTEM_STALE_AFTER.as_millis())
        .min(u128::from(u64::MAX)) as u64;
    Duration::from_millis(millis)
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
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

/// Clamp a CPU reading to the vCPU hotplug ceiling.
///
/// The VMM's counter aggregation can momentarily pair a vCPU-time delta with
/// a shorter wall window (observed as a multi-hundred-percent spike while a
/// concurrent VM boot loaded the host). More vCPU-seconds per second than
/// vCPUs exist is physically impossible, so cap at `max_cpus * 100`.
fn clamp_cpu_percent(cpu_percent: Option<f32>, max_cpus: u8) -> Option<f32> {
    let ceiling = f32::from(max_cpus.max(1)) * 100.0;
    cpu_percent.map(|pct| pct.min(ceiling))
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
    fn cpu_percent_is_clamped_to_the_vcpu_ceiling() {
        // A skewed counter window can report more vCPU-seconds per second
        // than vCPUs exist; the ceiling caps it.
        assert_eq!(clamp_cpu_percent(Some(592.0), 2), Some(200.0));
        assert_eq!(clamp_cpu_percent(Some(197.5), 2), Some(197.5));
        assert_eq!(clamp_cpu_percent(Some(150.0), 0), Some(100.0));
        assert_eq!(clamp_cpu_percent(None, 2), None);
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
    #[cfg(windows)]
    fn upper_host_allocated_bytes_uses_windows_allocation_size() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), vec![1_u8; 8192]).unwrap();

        assert!(upper_host_allocated_bytes(Some(file.path())).is_some_and(|bytes| bytes > 0));
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
    fn write_sample_publishes_upper_filesystem_metrics_from_krun() {
        let name = unique_shm_name("upper");
        let registry = MetricsRegistry::open_or_create(&name, 1).unwrap();
        let reserved = registry
            .reserve(ReserveSlot {
                sandbox_id: 8,
                name: "upper",
                memory_limit_bytes: 512 * 1024 * 1024,
            })
            .unwrap();
        let writer = registry
            .activate_writer(ActivateSlot {
                slot: reserved.slot,
                generation: reserved.generation,
                run_id: 10,
                pid: std::process::id() as i32,
                started_at: chrono::Utc::now(),
            })
            .unwrap();
        let now = chrono::Utc::now();
        let krun = msb_krun::VmMetrics {
            filesystem: msb_krun::FilesystemMetrics {
                upper_used_bytes: Some(53_248),
                upper_free_bytes: Some(450_527_232),
                upper_sampled_at_unix_ms: Some(now.timestamp_millis() as u64),
            },
            ..Default::default()
        };

        assert!(write_sample(&writer, None, &krun, None, None, Duration::from_secs(3)).is_ok());

        let snapshot = registry.snapshot().unwrap();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].upper_used_bytes, Some(53_248));
        assert_eq!(snapshot[0].upper_free_bytes, Some(450_527_232));
        cleanup_shm(&name);
    }

    #[test]
    fn upper_filesystem_metrics_returns_none_for_stale_samples() {
        let now = chrono::Utc::now();
        let stale_sample = (now - chrono::Duration::seconds(10)).timestamp_millis() as u64;
        let krun = msb_krun::VmMetrics {
            filesystem: msb_krun::FilesystemMetrics {
                upper_used_bytes: Some(53_248),
                upper_free_bytes: Some(450_527_232),
                upper_sampled_at_unix_ms: Some(stale_sample),
            },
            ..Default::default()
        };

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

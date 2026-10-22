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

use microsandbox_metrics::{GuestMemoryObservation, MetricsError, MetricsSlotWriter, SampleWrite};
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

/// Maximum counter/clock pairing error tolerated for a CPU sample window,
/// as a fraction of the window's wall time. Normal pairing spread is
/// microseconds against a 1s window; anything past this ratio means the
/// sampler was descheduled mid-read and the window's ratio is unusable.
const MAX_PAIRING_SKEW_RATIO: f64 = 0.05;

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
    /// VM control for live memory size and pause-aware residency sampling.
    pub vm_control: msb_krun::VmControl,
    /// Last guest-confirmed configured allocation, shared with the resize authority.
    pub memory_limit: ConfirmedMemoryLimit,
    /// Optional runtime network byte counters.
    pub network_metrics: Option<Box<dyn NetworkMetrics>>,
    /// Host path of the writable upper image, when one exists.
    pub upper_host_path: Option<std::path::PathBuf>,
}

/// Device allocation and a separately timestamped guest observation. Allocation
/// is not a substitute for guest-reported usable total.
#[derive(Default)]
struct MemorySample<'a> {
    confirmed: Option<&'a ConfirmedMemoryLimit>,
    observation: Option<GuestMemoryObservation>,
    source: Option<&'a msb_krun::MetricsHandle>,
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
        vm_control,
        memory_limit,
        network_metrics,
        upper_host_path,
    } = spec;
    connect_guest_memory_invalidation(&krun_metrics, &writer);
    let interval = Duration::from_millis(interval_ms.get());
    let upper_stale_after = upper_filesystem_stale_after(interval);
    let mut previous = paired_snapshot(&krun_metrics, &vm_control).await;
    let upper_host_path = upper_host_path.as_deref();
    let mut last_cpu_percent: Option<f32> = None;

    match write_sample(
        &writer,
        None,
        &previous.metrics,
        memory_sample(&krun_metrics, &vm_control, &memory_limit),
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

        let current = paired_snapshot(&krun_metrics, &vm_control).await;
        let wall_secs = current
            .at
            .checked_duration_since(previous.at)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        // Each window's error bound is half of each endpoint's read spread:
        // the true counter read lies somewhere inside its bracket.
        let pairing_skew_secs =
            (previous.uncertainty.as_secs_f64() + current.uncertainty.as_secs_f64()) / 2.0;
        let cpu_percent = if pairing_is_reliable(pairing_skew_secs, wall_secs) {
            let computed = clamp_cpu_percent(
                cpu_percent_from_vcpu_time(
                    current.metrics.cpu.vcpu_time_ns,
                    previous.metrics.cpu.vcpu_time_ns,
                    wall_secs,
                ),
                max_cpus,
            );
            if computed.is_some() {
                last_cpu_percent = computed;
            }
            computed
        } else {
            // The (counter, timestamp) pairing was disturbed — the sampler
            // was descheduled mid-read, so this window's ratio is garbage.
            // Carry the last trustworthy reading instead of publishing it.
            tracing::debug!(
                sandbox_id,
                pairing_skew_secs,
                wall_secs,
                "cpu sample window skewed by descheduling; reusing previous reading"
            );
            last_cpu_percent
        };

        match write_sample(
            &writer,
            cpu_percent,
            &current.metrics,
            memory_sample(&krun_metrics, &vm_control, &memory_limit),
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
    }
}

/// A VMM metrics snapshot paired with the wall-clock moment it describes.
///
/// The counter and the clock cannot be read in one atomic step, so the
/// snapshot is bracketed by two `Instant` reads: `at` is the bracket
/// midpoint and `uncertainty` its width. Normally the width is microseconds;
/// when the host deschedules this thread mid-read (observed during a
/// concurrent VM boot) it grows to whatever the scheduler stole, and the
/// sample window it bounds must not be trusted for rate math — pairing a
/// multi-second counter delta with a one-second wall window is exactly how
/// a 2-vCPU sandbox once read 592% CPU.
struct PairedSnapshot {
    metrics: msb_krun::VmMetrics,
    at: Instant,
    uncertainty: Duration,
}

async fn paired_snapshot(
    krun_metrics: &msb_krun::MetricsHandle,
    vm_control: &msb_krun::VmControl,
) -> PairedSnapshot {
    // Use the completed VMM boundary, including checkpoint pauses. A transition
    // racing this observation may permit one final scan or defer one until the
    // next tick; it never blocks pause/resume or caches unrelated counters.
    let paused = matches!(
        vm_control.execution_state(),
        Some(msb_krun::VmExecutionState::Paused(_))
    );
    snapshot_off_worker(krun_metrics, paused).await
}

/// Takes the snapshot on the blocking pool: the residency scan can take hundreds of
/// milliseconds on a large guest, and the runtime's few workers carry the agent relays.
async fn snapshot_off_worker(
    krun_metrics: &msb_krun::MetricsHandle,
    paused: bool,
) -> PairedSnapshot {
    let krun_metrics = krun_metrics.clone();
    tokio::task::spawn_blocking(move || snapshot(&krun_metrics, paused))
        .await
        .expect("metrics snapshot task panicked")
}

fn snapshot(krun_metrics: &msb_krun::MetricsHandle, paused: bool) -> PairedSnapshot {
    let before = Instant::now();
    let metrics = if paused {
        krun_metrics.aggregate_snapshot_without_host_residency()
    } else {
        krun_metrics.aggregate_snapshot()
    };
    let after = Instant::now();
    let uncertainty = after.saturating_duration_since(before);
    PairedSnapshot {
        metrics,
        at: before + uncertainty / 2,
        uncertainty,
    }
}

/// Whether the counter/clock pairing error is small enough for the window's
/// vCPU-time-over-wall-time ratio to be meaningful.
fn pairing_is_reliable(pairing_skew_secs: f64, wall_secs: f64) -> bool {
    wall_secs > 0.0 && pairing_skew_secs <= wall_secs * MAX_PAIRING_SKEW_RATIO
}

fn connect_guest_memory_invalidation(
    metrics: &msb_krun::MetricsHandle,
    writer: &MetricsSlotWriter,
) {
    let writer = writer.clone();
    metrics.register_guest_memory_invalidator(move || {
        // Native invalidation owns the same lock as publication. This callback
        // only touches the mapped slot; no I/O, VM control or device lock is taken.
        match writer.invalidate_guest_memory() {
            Ok(()) | Err(MetricsError::GenerationMismatch { .. }) => {}
            Err(error) => tracing::warn!(%error, "invalidate published guest memory"),
        }
    });
}

fn memory_sample<'a>(
    metrics: &'a msb_krun::MetricsHandle,
    control: &msb_krun::VmControl,
    confirmed: &'a ConfirmedMemoryLimit,
) -> MemorySample<'a> {
    // Read device/execution state before entering the native observation lock.
    // A racing pause is fenced by native invalidation; an already-paused or
    // indeterminate VM conservatively publishes no observation.
    let running = matches!(
        control.execution_state(),
        Some(msb_krun::VmExecutionState::Running { .. })
    );
    MemorySample {
        confirmed: Some(confirmed),
        observation: None,
        source: running.then_some(metrics),
    }
}

fn guest_memory_observation(report: msb_krun::GuestMemoryObservation) -> GuestMemoryObservation {
    // Both libraries use the same host-wide platform clock. Copy the original
    // receipt and guest cadence; host sampling must never renew either value.
    GuestMemoryObservation {
        total_bytes: report.total_bytes,
        available_bytes: report.available_bytes,
        received_at: report.received_at,
        reporting_interval: report.reporting_interval,
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
    memory: MemorySample<'_>,
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
    let mut sample = SampleWrite {
        sampled_at: chrono::Utc::now(),
        cpu_percent,
        vcpu_time_ns: krun.cpu.vcpu_time_ns,
        memory_bytes: None,
        memory_available_bytes: krun.memory.available_bytes,
        memory_host_resident_bytes: krun.memory.host_resident_bytes,
        memory_limit_bytes: None,
        disk_read_bytes: krun.block.read_bytes,
        disk_write_bytes: krun.block.write_bytes,
        net_rx_bytes: rx,
        net_tx_bytes: tx,
        upper_used_bytes,
        upper_free_bytes,
        upper_host_allocated_bytes: upper_host_allocated_bytes(upper_host_path),
    };
    // All filesystem work and counter collection is complete. Only mapped
    // atomic stores run under the native publication/invalidation fence.
    let mut publish = |limit: Option<u64>, after: Option<Duration>| {
        sample.memory_limit_bytes = limit;
        let write = |report: Option<GuestMemoryObservation>| {
            // A ready-device reply and a balloon sample are independent observations.
            // Do not subtract an availability value received before this limit changed.
            let report =
                report.filter(|report| after.is_none_or(|boundary| report.received_at > boundary));
            writer.write_sample_with_guest_memory(sample, report)
        };
        match memory.source {
            Some(metrics) => metrics.with_guest_memory_observation(|report| {
                write(report.map(guest_memory_observation))
            }),
            None => write(memory.observation),
        }
    };
    let result = match memory.confirmed {
        Some(confirmed) => confirmed.publish(|bytes, after| publish(Some(bytes), after)),
        None => publish(None, None),
    };
    match result {
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
/// Skewed windows are already rejected by the pairing check; this is the
/// invariant backstop for anything that still slips through — more
/// vCPU-seconds per second than vCPUs exist is physically impossible, so
/// cap at `max_cpus * 100`.
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
    use msb_krun_utils::metrics::MetricsWriter;

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
    fn pairing_gate_rejects_descheduled_windows() {
        // Normal operation: microsecond read spread against a 1s window.
        assert!(pairing_is_reliable(0.000_05, 1.0));
        // Right at the tolerance boundary.
        assert!(pairing_is_reliable(0.05, 1.0));
        // A deschedule mid-read (the 592%-on-2-vCPUs incident: ~2s stolen
        // between the counter read and its timestamp) must be rejected.
        assert!(!pairing_is_reliable(1.0, 1.0));
        assert!(!pairing_is_reliable(0.051, 1.0));
        // Degenerate window.
        assert!(!pairing_is_reliable(0.0, 0.0));
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

        assert!(
            write_sample(
                &writer,
                None,
                &krun,
                MemorySample::default(),
                None,
                None,
                Duration::from_secs(3)
            )
            .is_ok()
        );

        let snapshot = registry.snapshot().unwrap();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].upper_used_bytes, None);
        assert_eq!(snapshot[0].upper_free_bytes, None);
        cleanup_shm(&name);
    }

    #[test]
    fn write_sample_clears_unavailable_residency_and_restores_it_after_resume() {
        let name = unique_shm_name("residency");
        let registry = MetricsRegistry::open_or_create(&name, 1).unwrap();
        let reserved = registry
            .reserve(ReserveSlot {
                sandbox_id: 10,
                name: "residency",
                memory_limit_bytes: 4096,
            })
            .unwrap();
        let writer = registry
            .activate_writer(ActivateSlot {
                slot: reserved.slot,
                generation: reserved.generation,
                run_id: 11,
                pid: std::process::id() as i32,
                started_at: chrono::Utc::now(),
            })
            .unwrap();
        let mut krun = msb_krun::VmMetrics::default();

        // The pause sample must clear validity, not retain the last value or
        // publish zero resident bytes. Subsequent running samples restore it.
        for residency in [Some(4096), None, None, Some(2048)] {
            krun.memory.host_resident_bytes = residency;
            assert!(
                write_sample(
                    &writer,
                    Some(0.0),
                    &krun,
                    MemorySample::default(),
                    None,
                    None,
                    Duration::from_secs(3)
                )
                .is_ok()
            );
            assert_eq!(
                registry.snapshot().unwrap()[0].memory_host_resident_bytes,
                residency
            );
        }
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

        assert!(
            write_sample(
                &writer,
                None,
                &krun,
                MemorySample::default(),
                None,
                None,
                Duration::from_secs(3)
            )
            .is_ok()
        );

        let snapshot = registry.snapshot().unwrap();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].upper_used_bytes, Some(53_248));
        assert_eq!(snapshot[0].upper_free_bytes, Some(450_527_232));
        cleanup_shm(&name);
    }

    fn krun_memory(used: Option<u64>, available: Option<u64>) -> msb_krun::VmMetrics {
        msb_krun::VmMetrics {
            memory: msb_krun::MemoryMetrics {
                used_bytes: used,
                available_bytes: available,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn confirmed_limit_requires_post_confirmation_statistics() {
        let name = unique_shm_name("cfmlim");
        let registry = MetricsRegistry::open_or_create(&name, 1).unwrap();
        let reserved = registry
            .reserve(ReserveSlot {
                sandbox_id: 14,
                name: "confirmed-limit",
                memory_limit_bytes: 256 << 20,
            })
            .unwrap();
        let writer = registry
            .activate_writer(ActivateSlot {
                slot: reserved.slot,
                generation: reserved.generation,
                run_id: 15,
                pid: std::process::id() as i32,
                started_at: chrono::Utc::now(),
            })
            .unwrap();
        let native = MetricsWriter::default();
        let handle = native.handle();
        let confirmed = ConfirmedMemoryLimit::boot(256 << 20, handle.clone());
        connect_guest_memory_invalidation(&handle, &writer);
        let krun = krun_memory(Some(999), Some(999));
        let publish = || {
            assert!(
                write_sample(
                    &writer,
                    None,
                    &krun,
                    MemorySample {
                        confirmed: Some(&confirmed),
                        source: Some(&handle),
                        observation: None,
                    },
                    None,
                    None,
                    Duration::from_secs(3)
                )
                .is_ok()
            );
            registry.snapshot().unwrap().remove(0)
        };
        assert!(native.record_guest_memory_observation(
            native.guest_memory_epoch(),
            240 << 20,
            128 << 20,
            Duration::from_secs(1)
        ));
        let boot = publish();
        assert_eq!(boot.memory_limit_bytes, 256 << 20);
        assert_eq!(boot.memory_bytes, 128 << 20);

        // Fresh intermediate guest statistics cannot advance the configured allocation.
        let old_epoch = native.guest_memory_epoch();
        assert!(native.record_guest_memory_observation(
            old_epoch,
            740 << 20,
            512 << 20,
            Duration::from_secs(1)
        ));
        let pending = publish();
        assert_eq!(pending.memory_limit_bytes, 256 << 20);
        assert!(!pending.memory_bytes_reported);
        assert!(confirmed.confirm(768 << 20));
        // A reply to a pre-confirmation request must be rejected even if it arrives now.
        assert!(!native.record_guest_memory_observation(
            old_epoch,
            740 << 20,
            512 << 20,
            Duration::from_secs(1)
        ));
        let changed = publish();
        assert_eq!(changed.memory_limit_bytes, 768 << 20);
        assert_eq!(changed.memory_total_bytes, None);
        assert!(!changed.memory_bytes_reported);
        assert!(native.record_guest_memory_observation(
            native.guest_memory_epoch(),
            740 << 20,
            512 << 20,
            Duration::from_secs(1)
        ));
        let grown = publish();
        assert_eq!(grown.memory_total_bytes, Some(740 << 20));
        assert_eq!(grown.memory_available_bytes, Some(512 << 20));
        assert_eq!(
            grown.memory_bytes,
            256 << 20,
            "usage keeps configured allocation as its basis"
        );

        assert!(confirmed.confirm(256 << 20));
        let shrunk = publish();
        assert_eq!(shrunk.memory_limit_bytes, 256 << 20);
        assert!(!shrunk.memory_bytes_reported);
        assert!(native.record_guest_memory_observation(
            native.guest_memory_epoch(),
            240 << 20,
            128 << 20,
            Duration::from_secs(1)
        ));
        assert_eq!(publish().memory_bytes, 128 << 20);
        let receipt = handle.guest_memory_observation().unwrap();
        assert!(confirmed.confirm(256 << 20));
        assert_eq!(handle.guest_memory_observation(), Some(receipt));
        cleanup_shm(&name);
    }

    #[test]
    fn native_guest_report_keeps_its_receipt_and_expires_despite_host_sampling() {
        let name = unique_shm_name("guest-age");
        let registry = MetricsRegistry::open_or_create(&name, 1).unwrap();
        let reserved = registry
            .reserve(ReserveSlot {
                sandbox_id: 12,
                name: "guest-age",
                memory_limit_bytes: 1024 << 20,
            })
            .unwrap();
        let writer = registry
            .activate_writer(ActivateSlot {
                slot: reserved.slot,
                generation: reserved.generation,
                run_id: 13,
                pid: std::process::id() as i32,
                started_at: chrono::Utc::now(),
            })
            .unwrap();
        let native = MetricsWriter::default();
        let handle = native.handle();
        connect_guest_memory_invalidation(&handle, &writer);
        // Deliberately different legacy counters ensure publication uses the
        // coherent pair, not fields independently sampled from VmMetrics.
        native.set_memory_total_bytes(256 << 20);
        native.set_memory_available_bytes(64 << 20);
        assert!(native.record_guest_memory_observation(
            native.guest_memory_epoch(),
            768 << 20,
            128 << 20,
            Duration::from_secs(1),
        ));
        let original = handle.guest_memory_observation().unwrap();
        let mut krun = krun_memory(Some(192 << 20), Some(64 << 20));
        krun.memory.host_resident_bytes = Some(32 << 20);
        for _ in 0..2 {
            assert!(
                write_sample(
                    &writer,
                    None,
                    &krun,
                    MemorySample {
                        confirmed: None,
                        source: Some(&handle),
                        observation: handle
                            .guest_memory_observation()
                            .map(guest_memory_observation),
                    },
                    None,
                    None,
                    Duration::from_secs(3),
                )
                .is_ok()
            );
            let row = registry.snapshot().unwrap().remove(0);
            assert_eq!(row.memory_total_bytes, Some(768 << 20));
            assert_eq!(row.memory_available_bytes, Some(128 << 20));
            // Preserve configured allocation minus available, not total minus available.
            assert_eq!(row.memory_bytes, 896 << 20);
            assert_eq!(
                row.guest_memory_observation.unwrap().received_at,
                original.received_at
            );
        }

        let mut expired = guest_memory_observation(original);
        expired.received_at = expired.received_at.saturating_sub(Duration::from_secs(4));
        handle.invalidate_guest_memory_observation();
        // Invalidation must be visible before another sampler tick/publication.
        let invalidated = registry.snapshot().unwrap().remove(0);
        assert_eq!(invalidated.memory_total_bytes, None);
        assert!(!invalidated.memory_bytes_reported);
        for report in [
            Some(expired),
            handle
                .guest_memory_observation()
                .map(guest_memory_observation),
        ] {
            assert!(
                write_sample(
                    &writer,
                    Some(0.0),
                    &krun,
                    MemorySample {
                        confirmed: None,
                        source: None,
                        observation: report,
                    },
                    None,
                    None,
                    Duration::from_secs(3),
                )
                .is_ok()
            );
            let row = registry.snapshot().unwrap().remove(0);
            assert_eq!(row.memory_total_bytes, None);
            assert_eq!(row.memory_available_bytes, None);
            assert!(!row.memory_bytes_reported);
            assert_eq!(row.memory_host_resident_bytes, Some(32 << 20));
            assert_eq!(row.memory_limit_bytes, 1024 << 20);
        }
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

    #[tokio::test]
    async fn residency_sampling_runs_off_the_async_executor_thread() {
        let (sampling_thread, sampled_thread) = std::sync::mpsc::channel();
        let writer = MetricsWriter::default();
        writer.set_memory_host_resident_sampler(move || {
            sampling_thread.send(std::thread::current().id()).unwrap();
            Some(0)
        });
        let krun_metrics = writer.handle();
        let executor_thread = std::thread::current().id();

        let snapshot = snapshot_off_worker(&krun_metrics, false).await;

        assert_ne!(sampled_thread.try_recv().unwrap(), executor_thread);
        assert_eq!(snapshot.metrics.memory.host_resident_bytes, Some(0));
    }
}

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use super::metrics_memory::ConfirmedMemoryLimit;

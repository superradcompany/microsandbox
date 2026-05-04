//! Sandbox process metrics sampling and persistence.

use std::time::{Duration, Instant};

use microsandbox_db::DbWriteConnection;
use microsandbox_db::entity::sandbox_metric as sandbox_metric_entity;
use sea_orm::{ActiveModelTrait, Set};

use crate::{RuntimeError, RuntimeResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Fixed sampling interval for persisted sandbox metrics.
pub const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);

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

/// Process metrics sampled from the host OS.
#[derive(Clone, Copy, Debug)]
struct ProcessSample {
    cpu_time_secs: f64,
    memory_bytes: u64,
    disk_read_bytes: u64,
    disk_write_bytes: u64,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Run the background metrics sampler until the sandbox process exits.
pub async fn run_metrics_sampler(
    db: DbWriteConnection,
    sandbox_id: i32,
    pid: u32,
    network_metrics: Option<Box<dyn NetworkMetrics>>,
) {
    let pid = pid as i32;

    let mut previous = match sample_process(pid) {
        Ok(sample) => sample,
        Err(err) => {
            tracing::warn!(sandbox_id, pid, error = %err, "failed to capture initial sandbox metrics");
            return;
        }
    };
    let mut previous_instant = Instant::now();

    if let Err(err) =
        persist_sample(&db, sandbox_id, 0.0, previous, network_metrics.as_deref()).await
    {
        tracing::warn!(sandbox_id, pid, error = %err, "failed to persist initial sandbox metrics");
    }

    loop {
        tokio::time::sleep(SAMPLE_INTERVAL).await;

        let current = match sample_process(pid) {
            Ok(sample) => sample,
            Err(err) => {
                tracing::debug!(sandbox_id, pid, error = %err, "stopping metrics sampler");
                break;
            }
        };

        let now = Instant::now();
        let wall_secs = now
            .checked_duration_since(previous_instant)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        let cpu_percent = if wall_secs > 0.0 {
            (((current.cpu_time_secs - previous.cpu_time_secs).max(0.0)) / wall_secs) * 100.0
        } else {
            0.0
        };

        if let Err(err) = persist_sample(
            &db,
            sandbox_id,
            cpu_percent as f32,
            current,
            network_metrics.as_deref(),
        )
        .await
        {
            tracing::warn!(sandbox_id, pid, error = %err, "failed to persist sandbox metrics");
        }

        previous = current;
        previous_instant = now;
    }
}

async fn persist_sample(
    db: &DbWriteConnection,
    sandbox_id: i32,
    cpu_percent: f32,
    process: ProcessSample,
    network_metrics: Option<&dyn NetworkMetrics>,
) -> RuntimeResult<()> {
    let now = chrono::Utc::now().naive_utc();
    let (net_rx_bytes, net_tx_bytes) = if let Some(metrics) = network_metrics {
        (
            Some(to_i64(metrics.rx_bytes())?),
            Some(to_i64(metrics.tx_bytes())?),
        )
    } else {
        (Some(0), Some(0))
    };

    sandbox_metric_entity::ActiveModel {
        sandbox_id: Set(sandbox_id),
        cpu_percent: Set(Some(cpu_percent)),
        memory_bytes: Set(Some(to_i64(process.memory_bytes)?)),
        disk_read_bytes: Set(Some(to_i64(process.disk_read_bytes)?)),
        disk_write_bytes: Set(Some(to_i64(process.disk_write_bytes)?)),
        net_rx_bytes: Set(net_rx_bytes),
        net_tx_bytes: Set(net_tx_bytes),
        sampled_at: Set(Some(now)),
        created_at: Set(Some(now)),
        ..Default::default()
    }
    .insert(db)
    .await?;

    Ok(())
}

fn to_i64(value: u64) -> RuntimeResult<i64> {
    i64::try_from(value)
        .map_err(|_| RuntimeError::Custom(format!("metric value overflowed i64: {value}")))
}

#[cfg(target_os = "linux")]
fn sample_process(pid: i32) -> RuntimeResult<ProcessSample> {
    let stat_path = format!("/proc/{pid}/stat");
    let stat = std::fs::read_to_string(&stat_path)?;
    let rest = stat
        .rsplit_once(") ")
        .map(|(_, rest)| rest)
        .ok_or_else(|| RuntimeError::Custom(format!("unexpected stat format: {stat_path}")))?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    if fields.len() <= 12 {
        return Err(RuntimeError::Custom(format!(
            "unexpected stat field count for pid {pid}: {}",
            fields.len()
        )));
    }

    let clk_tck = sysconf(libc::_SC_CLK_TCK)? as f64;
    let utime_ticks: u64 = parse_u64(fields[11], "utime")?;
    let stime_ticks: u64 = parse_u64(fields[12], "stime")?;

    let statm_path = format!("/proc/{pid}/statm");
    let statm = std::fs::read_to_string(&statm_path)?;
    let statm_fields: Vec<&str> = statm.split_whitespace().collect();
    if statm_fields.len() < 2 {
        return Err(RuntimeError::Custom(format!(
            "unexpected statm field count for pid {pid}: {}",
            statm_fields.len()
        )));
    }
    let resident_pages: u64 = parse_u64(statm_fields[1], "resident_pages")?;
    let page_size = sysconf(libc::_SC_PAGESIZE)? as u64;

    let io_path = format!("/proc/{pid}/io");
    let io = std::fs::read_to_string(&io_path)?;
    let mut disk_read_bytes = None;
    let mut disk_write_bytes = None;
    for line in io.lines() {
        if let Some(value) = line.strip_prefix("read_bytes:") {
            disk_read_bytes = Some(parse_u64(value.trim(), "read_bytes")?);
        } else if let Some(value) = line.strip_prefix("write_bytes:") {
            disk_write_bytes = Some(parse_u64(value.trim(), "write_bytes")?);
        }
    }

    Ok(ProcessSample {
        cpu_time_secs: (utime_ticks + stime_ticks) as f64 / clk_tck,
        memory_bytes: resident_pages.saturating_mul(page_size),
        disk_read_bytes: disk_read_bytes.unwrap_or(0),
        disk_write_bytes: disk_write_bytes.unwrap_or(0),
    })
}

#[cfg(target_os = "macos")]
fn sample_process(pid: i32) -> RuntimeResult<ProcessSample> {
    let mut info = RusageInfoV2::default();
    let result = unsafe {
        proc_pid_rusage(
            pid,
            RUSAGE_INFO_V2,
            (&mut info as *mut RusageInfoV2).cast::<std::ffi::c_void>(),
        )
    };
    if result != 0 {
        return Err(RuntimeError::Io(std::io::Error::last_os_error()));
    }

    Ok(ProcessSample {
        cpu_time_secs: (info.ri_user_time + info.ri_system_time) as f64 / 1_000_000_000.0,
        memory_bytes: info.ri_resident_size,
        disk_read_bytes: info.ri_diskio_bytesread,
        disk_write_bytes: info.ri_diskio_byteswritten,
    })
}

#[cfg(target_os = "linux")]
fn parse_u64(value: &str, field: &str) -> RuntimeResult<u64> {
    value.parse::<u64>().map_err(|err| {
        RuntimeError::Custom(format!("failed to parse {field}='{value}' as u64: {err}"))
    })
}

#[cfg(target_os = "linux")]
fn sysconf(name: libc::c_int) -> RuntimeResult<i64> {
    let value = unsafe { libc::sysconf(name) };
    if value <= 0 {
        return Err(RuntimeError::Io(std::io::Error::last_os_error()));
    }
    Ok(value)
}

#[cfg(target_os = "macos")]
const RUSAGE_INFO_V2: libc::c_int = 2;

#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Default)]
struct RusageInfoV2 {
    ri_uuid: [u8; 16],
    ri_user_time: u64,
    ri_system_time: u64,
    ri_pkg_idle_wkups: u64,
    ri_interrupt_wkups: u64,
    ri_pageins: u64,
    ri_wired_size: u64,
    ri_resident_size: u64,
    ri_phys_footprint: u64,
    ri_proc_start_abstime: u64,
    ri_proc_exit_abstime: u64,
    ri_child_user_time: u64,
    ri_child_system_time: u64,
    ri_child_pkg_idle_wkups: u64,
    ri_child_interrupt_wkups: u64,
    ri_child_pageins: u64,
    ri_child_elapsed_abstime: u64,
    ri_diskio_bytesread: u64,
    ri_diskio_byteswritten: u64,
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn proc_pid_rusage(
        pid: libc::c_int,
        flavor: libc::c_int,
        buffer: *mut std::ffi::c_void,
    ) -> libc::c_int;
}

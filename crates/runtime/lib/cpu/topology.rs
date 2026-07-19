//! Host CPU topology discovery.

#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::io;

use crate::{RuntimeError, RuntimeResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One allowed online host logical processor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LogicalCpu {
    pub(crate) id: u16,
    pub(crate) package: i32,
    pub(crate) die: i32,
    pub(crate) core: i32,
}

/// Effective host topology visible to this runtime process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CpuTopology {
    pub(crate) logical_cpus: Vec<LogicalCpu>,
    pub(crate) fingerprint: String,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub(crate) fn discover() -> RuntimeResult<CpuTopology> {
    let allowed = allowed_logical_cpus()?;
    let mut logical_cpus = Vec::with_capacity(allowed.len());
    for id in allowed {
        if !is_online(id)? {
            continue;
        }
        let topology_dir = format!("/sys/devices/system/cpu/cpu{id}/topology");
        logical_cpus.push(LogicalCpu {
            id,
            package: read_i32(&format!("{topology_dir}/physical_package_id"))?,
            die: read_i32_optional(&format!("{topology_dir}/die_id")).unwrap_or(0),
            core: read_i32(&format!("{topology_dir}/core_id"))?,
        });
    }
    logical_cpus.sort_by_key(|cpu| (cpu.package, cpu.die, cpu.core, cpu.id));
    if logical_cpus.is_empty() {
        return Err(RuntimeError::Custom(
            "CPU placement found no online processors in the process affinity mask".into(),
        ));
    }

    let fingerprint = topology_fingerprint(&logical_cpus);
    Ok(CpuTopology {
        logical_cpus,
        fingerprint,
    })
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn discover() -> RuntimeResult<CpuTopology> {
    Err(RuntimeError::Custom(
        "managed CPU placement is currently supported on Linux hosts only".into(),
    ))
}

#[cfg(target_os = "linux")]
fn allowed_logical_cpus() -> RuntimeResult<BTreeSet<u16>> {
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    let result =
        unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) };
    if result != 0 {
        return Err(io::Error::last_os_error().into());
    }

    let mut allowed = BTreeSet::new();
    for index in 0..libc::CPU_SETSIZE as usize {
        if unsafe { libc::CPU_ISSET(index, &set) } {
            let id = u16::try_from(index).map_err(|_| {
                RuntimeError::Custom(format!("host logical CPU {index} exceeds supported range"))
            })?;
            allowed.insert(id);
        }
    }
    Ok(allowed)
}

#[cfg(target_os = "linux")]
fn read_i32(path: &str) -> RuntimeResult<i32> {
    let value = fs::read_to_string(path)
        .map_err(|error| RuntimeError::Custom(format!("read CPU topology {path}: {error}")))?;
    value.trim().parse::<i32>().map_err(|error| {
        RuntimeError::Custom(format!("parse CPU topology {path} as integer: {error}"))
    })
}

#[cfg(target_os = "linux")]
fn read_i32_optional(path: &str) -> Option<i32> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

#[cfg(target_os = "linux")]
fn is_online(id: u16) -> RuntimeResult<bool> {
    let path = format!("/sys/devices/system/cpu/cpu{id}/online");
    match fs::read_to_string(&path) {
        Ok(value) => match value.trim() {
            "1" => Ok(true),
            "0" => Ok(false),
            value => Err(RuntimeError::Custom(format!(
                "parse CPU online state {path}: expected 0 or 1, got {value:?}"
            ))),
        },
        // Linux omits this file for processors that cannot be hot-unplugged, including CPU 0.
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(RuntimeError::Custom(format!(
            "read CPU online state {path}: {error}"
        ))),
    }
}

#[cfg(target_os = "linux")]
fn topology_fingerprint(cpus: &[LogicalCpu]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for cpu in cpus {
        for byte in cpu
            .id
            .to_le_bytes()
            .into_iter()
            .chain(cpu.package.to_le_bytes())
            .chain(cpu.die.to_le_bytes())
            .chain(cpu.core.to_le_bytes())
        {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    format!("{hash:016x}")
}

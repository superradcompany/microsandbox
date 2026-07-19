//! Host CPU topology discovery.

#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use std::io;
#[cfg(target_os = "windows")]
use std::mem::size_of;

#[cfg(target_os = "windows")]
use windows_sys::Win32::System::SystemInformation::{
    GROUP_AFFINITY, GetLogicalProcessorInformationEx, PROCESSOR_RELATIONSHIP,
    RelationProcessorCore, SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Threading::{GetCurrentThread, GetThreadGroupAffinity};

use crate::{RuntimeError, RuntimeResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One allowed online host logical processor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LogicalCpu {
    pub(crate) id: LogicalCpuId,
    pub(crate) package: i32,
    pub(crate) die: i32,
    pub(crate) core: i32,
    pub(crate) performance_class: u8,
}

/// Stable processor-group coordinate used by planning and the allocation catalog.
#[derive(Clone, Copy, Debug, Hash, Ord, PartialEq, Eq, PartialOrd)]
pub(crate) struct LogicalCpuId {
    pub(crate) group: u16,
    pub(crate) index: u16,
}

/// Effective host topology visible to this runtime process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CpuTopology {
    pub(crate) logical_cpus: Vec<LogicalCpu>,
    pub(crate) fingerprint: String,
}

/// Fixed prefix shared by every variable-sized Windows topology record.
#[cfg(target_os = "windows")]
#[derive(Clone, Copy)]
#[repr(C)]
struct WindowsTopologyHeader {
    relationship: i32,
    size: u32,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LogicalCpuId {
    #[cfg(any(target_os = "linux", test))]
    pub(crate) const fn new(index: u16) -> Self {
        Self { group: 0, index }
    }

    #[cfg(any(target_os = "windows", test))]
    pub(crate) const fn in_group(group: u16, index: u16) -> Self {
        Self { group, index }
    }

    /// Encodes the Windows processor group and index without changing existing Linux catalog keys.
    pub(crate) const fn catalog_key(self) -> i64 {
        ((self.group as i64) << 16) | self.index as i64
    }

    pub(crate) fn from_catalog_key(key: i64) -> RuntimeResult<Self> {
        if !(0..=i64::from(u32::MAX)).contains(&key) {
            return Err(RuntimeError::Custom(format!(
                "logical CPU catalog key {key} is outside the supported range"
            )));
        }
        Ok(Self {
            group: ((key as u32) >> 16) as u16,
            index: key as u16,
        })
    }
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
            id: LogicalCpuId::new(id),
            package: read_i32(&format!("{topology_dir}/physical_package_id"))?,
            die: read_i32_optional(&format!("{topology_dir}/die_id")).unwrap_or(0),
            core: read_i32(&format!("{topology_dir}/core_id"))?,
            performance_class: 0,
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

#[cfg(target_os = "windows")]
pub(crate) fn discover() -> RuntimeResult<CpuTopology> {
    let allowed = current_thread_group_affinity()?;
    let (buffer, buffer_len) = processor_core_information()?;
    let mut logical_cpus = Vec::new();
    let mut offset = 0usize;
    let mut core_index = 0i32;

    while offset < buffer_len {
        let minimum_entry_size =
            size_of::<WindowsTopologyHeader>() + size_of::<PROCESSOR_RELATIONSHIP>();
        if buffer_len - offset < minimum_entry_size {
            return Err(RuntimeError::Custom(
                "Windows returned a truncated processor topology entry".into(),
            ));
        }

        // The Windows buffer is variable-length. Read the fixed header without assuming that the
        // byte offset for each entry retains Rust's native alignment.
        let header = unsafe {
            std::ptr::read_unaligned(
                buffer
                    .as_ptr()
                    .cast::<u8>()
                    .add(offset)
                    .cast::<WindowsTopologyHeader>(),
            )
        };
        let entry_size = header.size as usize;
        if entry_size < minimum_entry_size || entry_size > buffer_len - offset {
            return Err(RuntimeError::Custom(format!(
                "Windows returned invalid processor topology entry size {entry_size}"
            )));
        }
        if header.relationship != RelationProcessorCore {
            return Err(RuntimeError::Custom(format!(
                "Windows returned unexpected processor topology relationship {}",
                header.relationship
            )));
        }

        let processor = unsafe {
            std::ptr::read_unaligned(
                buffer
                    .as_ptr()
                    .cast::<u8>()
                    .add(offset + size_of::<WindowsTopologyHeader>())
                    .cast::<PROCESSOR_RELATIONSHIP>(),
            )
        };
        if processor.GroupCount != 1 {
            return Err(RuntimeError::Custom(format!(
                "Windows processor core spans unsupported group count {}",
                processor.GroupCount
            )));
        }
        let mask = processor.GroupMask[0];
        if mask.Group == allowed.Group {
            let visible_mask = mask.Mask & allowed.Mask;
            for index in 0..usize::BITS {
                if visible_mask & (1usize << index) != 0 {
                    logical_cpus.push(LogicalCpu {
                        id: LogicalCpuId::in_group(mask.Group, index as u16),
                        package: i32::from(mask.Group),
                        die: 0,
                        core: core_index,
                        performance_class: processor.EfficiencyClass,
                    });
                }
            }
        }
        offset += entry_size;
        core_index += 1;
    }

    logical_cpus.sort_by_key(|cpu| {
        (
            std::cmp::Reverse(cpu.performance_class),
            cpu.package,
            cpu.die,
            cpu.core,
            cpu.id,
        )
    });
    if logical_cpus.is_empty() {
        return Err(RuntimeError::Custom(format!(
            "CPU placement found no active processors in Windows processor group {}",
            allowed.Group
        )));
    }

    let fingerprint = topology_fingerprint(&logical_cpus);
    Ok(CpuTopology {
        logical_cpus,
        fingerprint,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub(crate) fn discover() -> RuntimeResult<CpuTopology> {
    Err(RuntimeError::Custom(
        "managed CPU placement is supported on Linux and Windows hosts; use inherit on this platform"
            .into(),
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

#[cfg(target_os = "windows")]
fn current_thread_group_affinity() -> RuntimeResult<GROUP_AFFINITY> {
    let mut affinity = GROUP_AFFINITY::default();
    // SAFETY: the pseudo-handle is valid for the calling runtime thread and the output points to
    // initialized writable storage for the duration of the call.
    let result = unsafe { GetThreadGroupAffinity(GetCurrentThread(), &mut affinity) };
    if result == 0 {
        return Err(io::Error::last_os_error().into());
    }
    if affinity.Mask == 0 {
        return Err(RuntimeError::Custom(format!(
            "Windows processor group {} has an empty thread affinity mask",
            affinity.Group
        )));
    }
    Ok(affinity)
}

#[cfg(target_os = "windows")]
fn processor_core_information() -> RuntimeResult<(Vec<usize>, usize)> {
    let mut byte_len = 0u32;
    // Windows reports the required buffer size through `byte_len` on this sizing call.
    unsafe {
        GetLogicalProcessorInformationEx(
            RelationProcessorCore,
            std::ptr::null_mut(),
            &mut byte_len,
        );
    }
    if byte_len == 0 {
        return Err(io::Error::last_os_error().into());
    }

    let word_len = (byte_len as usize).div_ceil(size_of::<usize>());
    let mut buffer = vec![0usize; word_len];
    // SAFETY: the buffer has exactly the byte capacity reported by the sizing call and Windows
    // updates `byte_len` to the number of bytes initialized.
    let result = unsafe {
        GetLogicalProcessorInformationEx(
            RelationProcessorCore,
            buffer
                .as_mut_ptr()
                .cast::<u8>()
                .cast::<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(),
            &mut byte_len,
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok((buffer, byte_len as usize))
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn topology_fingerprint(cpus: &[LogicalCpu]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for cpu in cpus {
        for byte in cpu
            .id
            .group
            .to_le_bytes()
            .into_iter()
            .chain(cpu.id.index.to_le_bytes())
            .chain(cpu.package.to_le_bytes())
            .chain(cpu.die.to_le_bytes())
            .chain(cpu.core.to_le_bytes())
            .chain([cpu.performance_class])
        {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    format!("{hash:016x}")
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_key_preserves_linux_ids_and_windows_groups() {
        assert_eq!(LogicalCpuId::new(17).catalog_key(), 17);

        let windows = LogicalCpuId::in_group(3, 41);
        assert_eq!(
            LogicalCpuId::from_catalog_key(windows.catalog_key()).unwrap(),
            windows
        );
    }

    #[test]
    fn catalog_key_rejects_values_outside_packed_coordinate() {
        assert!(LogicalCpuId::from_catalog_key(-1).is_err());
        assert!(LogicalCpuId::from_catalog_key(i64::from(u32::MAX) + 1).is_err());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_discovery_stays_inside_the_inherited_group_affinity() {
        let allowed = current_thread_group_affinity().unwrap();
        let topology = discover().unwrap();

        assert!(!topology.logical_cpus.is_empty());
        for cpu in topology.logical_cpus {
            assert_eq!(cpu.id.group, allowed.Group);
            assert_ne!(allowed.Mask & (1usize << cpu.id.index), 0);
        }
    }
}

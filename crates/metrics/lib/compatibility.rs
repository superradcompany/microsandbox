//! Read-only compatibility for metrics registries created by older runtimes.

use std::ffi::CString;
use std::sync::atomic::{
    AtomicI32, AtomicI64, AtomicU8, AtomicU16, AtomicU32, AtomicU64, Ordering,
};

use crate::layout::{
    HEADER_SIZE, Header, NAME_BYTES, REGISTRY_VERSION, SAMPLE_FLAG_MEMORY_AVAILABLE,
    SAMPLE_FLAG_MEMORY_HOST_RESIDENT, SLOT_ACTIVE, SLOT_SIZE, registry_size,
};
use crate::registry::{
    MappedRegion, WaitForReadyError, flag_value, ms_to_datetime, open_existing_read_only_region,
    validate_header_version, wait_for_ready,
};
use crate::{LiveMetric, LiveMetricState, MetricsError, MetricsRegistry, MetricsResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const LEGACY_REGISTRY_VERSION_V2: u32 = 2;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Read-only view over a supported metrics registry ABI.
///
/// This is intentionally separate from [`MetricsRegistry`]: callers cannot
/// reserve or release slots through it, and legacy layouts are never mutated.
pub struct MetricsRegistryReader {
    inner: MetricsRegistryReaderInner,
}

enum MetricsRegistryReaderInner {
    Current(MetricsRegistry),
    V2(LegacyRegistryV2),
}

struct LegacyRegistryV2 {
    mapping: MappedRegion,
    capacity: u32,
}

/// Metrics slot layout used by registry ABI v2.
#[repr(C)]
struct SlotV2 {
    state: AtomicU32,
    generation: AtomicU64,
    seq: AtomicU64,
    sandbox_id: AtomicI32,
    run_id: AtomicI32,
    pid: AtomicI32,
    _pad0: u32,
    started_at_unix_ms: AtomicI64,
    sampled_at_unix_ms: AtomicI64,
    sample_flags: AtomicU32,
    memory_limit_bytes: AtomicU64,
    vcpu_time_ns: AtomicU64,
    cpu_percent_bits: AtomicU32,
    memory_bytes: AtomicU64,
    memory_available_bytes: AtomicU64,
    memory_host_resident_bytes: AtomicU64,
    disk_read_bytes: AtomicU64,
    disk_write_bytes: AtomicU64,
    net_rx_bytes: AtomicU64,
    net_tx_bytes: AtomicU64,
    name_len: AtomicU16,
    _pad1: [AtomicU8; 6],
    name_bytes: [AtomicU8; NAME_BYTES],
    _tail: [u8; SLOT_SIZE - 152 - NAME_BYTES],
}

const _: () = {
    assert!(std::mem::size_of::<SlotV2>() == SLOT_SIZE);
    assert!(std::mem::offset_of!(SlotV2, state) == 0x00);
    assert!(std::mem::offset_of!(SlotV2, generation) == 0x08);
    assert!(std::mem::offset_of!(SlotV2, seq) == 0x10);
    assert!(std::mem::offset_of!(SlotV2, sandbox_id) == 0x18);
    assert!(std::mem::offset_of!(SlotV2, run_id) == 0x1c);
    assert!(std::mem::offset_of!(SlotV2, pid) == 0x20);
    assert!(std::mem::offset_of!(SlotV2, started_at_unix_ms) == 0x28);
    assert!(std::mem::offset_of!(SlotV2, sampled_at_unix_ms) == 0x30);
    assert!(std::mem::offset_of!(SlotV2, sample_flags) == 0x38);
    assert!(std::mem::offset_of!(SlotV2, memory_limit_bytes) == 0x40);
    assert!(std::mem::offset_of!(SlotV2, vcpu_time_ns) == 0x48);
    assert!(std::mem::offset_of!(SlotV2, cpu_percent_bits) == 0x50);
    assert!(std::mem::offset_of!(SlotV2, memory_bytes) == 0x58);
    assert!(std::mem::offset_of!(SlotV2, memory_available_bytes) == 0x60);
    assert!(std::mem::offset_of!(SlotV2, memory_host_resident_bytes) == 0x68);
    assert!(std::mem::offset_of!(SlotV2, disk_read_bytes) == 0x70);
    assert!(std::mem::offset_of!(SlotV2, disk_write_bytes) == 0x78);
    assert!(std::mem::offset_of!(SlotV2, net_rx_bytes) == 0x80);
    assert!(std::mem::offset_of!(SlotV2, net_tx_bytes) == 0x88);
    assert!(std::mem::offset_of!(SlotV2, name_len) == 0x90);
    assert!(std::mem::offset_of!(SlotV2, name_bytes) == 0x98);
};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl MetricsRegistryReader {
    /// Open an existing registry using one explicitly supported ABI layout.
    pub fn open(name: &str, abi_version: u32) -> MetricsResult<Self> {
        let inner = match abi_version {
            REGISTRY_VERSION => MetricsRegistryReaderInner::Current(MetricsRegistry::open(name)?),
            LEGACY_REGISTRY_VERSION_V2 => MetricsRegistryReaderInner::V2(open_v2_registry(name)?),
            version => {
                return Err(MetricsError::Custom(format!(
                    "unsupported readable registry version: {version}"
                )));
            }
        };

        Ok(Self { inner })
    }

    /// Snapshot every active slot without mutating legacy registries.
    pub fn active_snapshot(&self) -> MetricsResult<Vec<LiveMetric>> {
        match &self.inner {
            MetricsRegistryReaderInner::Current(registry) => registry.active_snapshot(),
            MetricsRegistryReaderInner::V2(registry) => Ok(registry.active_snapshot()),
        }
    }
}

impl LegacyRegistryV2 {
    fn active_snapshot(&self) -> Vec<LiveMetric> {
        (0..self.capacity)
            .filter_map(|index| self.read_slot(index))
            .collect()
    }

    fn read_slot(&self, index: u32) -> Option<LiveMetric> {
        let slot = self.slot(index);

        for _ in 0..4096 {
            if slot.state.load(Ordering::Acquire) != SLOT_ACTIVE {
                return None;
            }

            let generation_before = slot.generation.load(Ordering::Acquire);
            let sequence_before = slot.seq.load(Ordering::Acquire);
            if sequence_before & 1 == 1 {
                std::hint::spin_loop();
                continue;
            }

            let sandbox_id = slot.sandbox_id.load(Ordering::Relaxed);
            let run_id = slot.run_id.load(Ordering::Relaxed);
            let pid = slot.pid.load(Ordering::Relaxed);
            let started_at_ms = slot.started_at_unix_ms.load(Ordering::Relaxed);
            let sampled_at_ms = slot.sampled_at_unix_ms.load(Ordering::Relaxed);
            let sample_flags = slot.sample_flags.load(Ordering::Relaxed);
            let memory_limit = slot.memory_limit_bytes.load(Ordering::Relaxed);
            let vcpu_time_ns = slot.vcpu_time_ns.load(Ordering::Relaxed);
            let cpu_bits = slot.cpu_percent_bits.load(Ordering::Relaxed);
            let memory = slot.memory_bytes.load(Ordering::Relaxed);
            let memory_available = slot.memory_available_bytes.load(Ordering::Relaxed);
            let memory_host_resident = slot.memory_host_resident_bytes.load(Ordering::Relaxed);
            let disk_read = slot.disk_read_bytes.load(Ordering::Relaxed);
            let disk_write = slot.disk_write_bytes.load(Ordering::Relaxed);
            let net_rx = slot.net_rx_bytes.load(Ordering::Relaxed);
            let net_tx = slot.net_tx_bytes.load(Ordering::Relaxed);
            let name = read_v2_name(slot);

            let sequence_after = slot.seq.load(Ordering::Acquire);
            let generation_after = slot.generation.load(Ordering::Acquire);
            let state_after = slot.state.load(Ordering::Acquire);
            if sequence_before != sequence_after
                || sequence_after & 1 == 1
                || generation_before != generation_after
                || state_after != SLOT_ACTIVE
            {
                std::hint::spin_loop();
                continue;
            }

            if sampled_at_ms <= 0 {
                return None;
            }

            let timestamp = ms_to_datetime(sampled_at_ms);
            let started_at = ms_to_datetime(started_at_ms);
            let uptime = timestamp
                .signed_duration_since(started_at)
                .to_std()
                .unwrap_or_default();

            return Some(LiveMetric {
                state: LiveMetricState::Active,
                sandbox_id,
                run_id,
                pid,
                name,
                timestamp,
                uptime,
                cpu_percent: f32::from_bits(cpu_bits),
                vcpu_time_ns,
                memory_bytes: memory,
                memory_available_bytes: flag_value(
                    sample_flags,
                    SAMPLE_FLAG_MEMORY_AVAILABLE,
                    memory_available,
                ),
                memory_host_resident_bytes: flag_value(
                    sample_flags,
                    SAMPLE_FLAG_MEMORY_HOST_RESIDENT,
                    memory_host_resident,
                ),
                memory_limit_bytes: memory_limit,
                disk_read_bytes: disk_read,
                disk_write_bytes: disk_write,
                net_rx_bytes: net_rx,
                net_tx_bytes: net_tx,
                upper_used_bytes: None,
                upper_free_bytes: None,
                upper_host_allocated_bytes: None,
            });
        }

        None
    }

    fn slot(&self, index: u32) -> &SlotV2 {
        debug_assert!(index < self.capacity);
        let offset = HEADER_SIZE + (index as usize) * SLOT_SIZE;

        unsafe { &*(self.mapping.as_ptr().add(offset) as *const SlotV2) }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn open_v2_registry(name: &str) -> MetricsResult<LegacyRegistryV2> {
    let name = CString::new(name)
        .map_err(|_| MetricsError::Custom("registry name contains NUL byte".into()))?;
    let header_mapping = open_existing_read_only_region(&name, HEADER_SIZE)?.ok_or_else(|| {
        MetricsError::from(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "metrics registry does not exist",
        ))
    })?;
    let header = unsafe { &*(header_mapping.as_ptr() as *const Header) };

    match wait_for_ready(header) {
        Ok(()) => {}
        Err(WaitForReadyError::Stuck) => {
            return Err(MetricsError::Custom(
                "metrics registry is still initializing".into(),
            ));
        }
        Err(WaitForReadyError::Invalid(state)) => {
            return Err(MetricsError::Custom(format!(
                "invalid registry header state: {state}"
            )));
        }
    }

    validate_header_version(header, LEGACY_REGISTRY_VERSION_V2, None)?;
    let capacity = header.capacity;
    drop(header_mapping);

    let mapping = open_existing_read_only_region(&name, registry_size(capacity))?
        .ok_or_else(|| MetricsError::Custom("registry disappeared during open".into()))?;
    let header = unsafe { &*(mapping.as_ptr() as *const Header) };

    validate_header_version(header, LEGACY_REGISTRY_VERSION_V2, Some(capacity))?;

    Ok(LegacyRegistryV2 { mapping, capacity })
}

fn read_v2_name(slot: &SlotV2) -> String {
    let len = (slot.name_len.load(Ordering::Relaxed) as usize).min(NAME_BYTES);
    let mut bytes = [0u8; NAME_BYTES];
    for (index, byte) in bytes.iter_mut().enumerate().take(len) {
        *byte = slot.name_bytes[index].load(Ordering::Relaxed);
    }

    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::layout::{
        HEADER_STATE_INITIALIZING, HEADER_STATE_READY, REGISTRY_MAGIC, SAMPLE_FLAG_CPU,
        SAMPLE_FLAG_MEMORY_USED,
    };
    use crate::registry::{create_region, unlink_region};

    fn unique_name(tag: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        format!("/msb-mtc-{tag}-{}", nanos & 0xffff_ffff)
    }

    fn create_v2_registry(name: &str, sandbox_id: i32, run_id: i32) -> MappedRegion {
        let name = CString::new(name).unwrap();
        let mapping = create_region(&name, registry_size(1)).unwrap();
        let header = unsafe { &mut *(mapping.as_mut_ptr() as *mut Header) };

        header
            .state
            .store(HEADER_STATE_INITIALIZING, Ordering::Release);
        header.magic = REGISTRY_MAGIC;
        header.version = LEGACY_REGISTRY_VERSION_V2;
        header.header_len = HEADER_SIZE as u32;
        header.slot_len = SLOT_SIZE as u32;
        header.capacity = 1;
        header.created_at_unix_ms = Utc::now().timestamp_millis();
        header.global_generation.store(1, Ordering::Release);

        let slot = unsafe { &*(mapping.as_mut_ptr().add(HEADER_SIZE) as *const SlotV2) };
        let now = Utc::now();
        slot.generation.store(1, Ordering::Release);
        slot.seq.store(2, Ordering::Release);
        slot.sandbox_id.store(sandbox_id, Ordering::Relaxed);
        slot.run_id.store(run_id, Ordering::Relaxed);
        slot.pid.store(42, Ordering::Relaxed);
        slot.started_at_unix_ms.store(
            (now - chrono::Duration::seconds(3)).timestamp_millis(),
            Ordering::Relaxed,
        );
        slot.sampled_at_unix_ms
            .store(now.timestamp_millis(), Ordering::Relaxed);
        slot.sample_flags.store(
            SAMPLE_FLAG_CPU | SAMPLE_FLAG_MEMORY_USED | SAMPLE_FLAG_MEMORY_AVAILABLE,
            Ordering::Relaxed,
        );
        slot.memory_limit_bytes.store(4096, Ordering::Relaxed);
        slot.vcpu_time_ns.store(23, Ordering::Relaxed);
        slot.cpu_percent_bits
            .store(12.5_f32.to_bits(), Ordering::Relaxed);
        slot.memory_bytes.store(1024, Ordering::Relaxed);
        slot.memory_available_bytes.store(3072, Ordering::Relaxed);
        slot.disk_read_bytes.store(11, Ordering::Relaxed);
        slot.disk_write_bytes.store(12, Ordering::Relaxed);
        slot.net_rx_bytes.store(13, Ordering::Relaxed);
        slot.net_tx_bytes.store(14, Ordering::Relaxed);

        let sandbox_name = b"legacy-sandbox";
        slot.name_len
            .store(sandbox_name.len() as u16, Ordering::Relaxed);
        for (index, byte) in sandbox_name.iter().enumerate() {
            slot.name_bytes[index].store(*byte, Ordering::Relaxed);
        }

        slot.state.store(SLOT_ACTIVE, Ordering::Release);
        header.state.store(HEADER_STATE_READY, Ordering::Release);

        mapping
    }

    fn cleanup(name: &str) {
        let name = CString::new(name).unwrap();

        unlink_region(&name);
    }

    #[test]
    fn reader_supports_v2_without_upper_disk_fields() {
        let name = unique_name("v2");
        let _mapping = create_v2_registry(&name, 7, 99);
        let reader = MetricsRegistryReader::open(&name, LEGACY_REGISTRY_VERSION_V2).unwrap();

        let snapshots = reader.active_snapshot().unwrap();

        assert_eq!(snapshots.len(), 1);
        let snapshot = &snapshots[0];
        assert_eq!(snapshot.sandbox_id, 7);
        assert_eq!(snapshot.run_id, 99);
        assert_eq!(snapshot.name, "legacy-sandbox");
        assert_eq!(snapshot.cpu_percent, 12.5);
        assert_eq!(snapshot.memory_available_bytes, Some(3072));
        assert_eq!(snapshot.upper_used_bytes, None);
        assert_eq!(snapshot.upper_free_bytes, None);
        assert_eq!(snapshot.upper_host_allocated_bytes, None);

        cleanup(&name);
    }

    #[test]
    fn reader_rejects_an_unexpected_registry_version() {
        let name = unique_name("v2bad");
        let _mapping = create_v2_registry(&name, 7, 99);

        let error = match MetricsRegistryReader::open(&name, REGISTRY_VERSION) {
            Ok(_) => panic!("v2 registry unexpectedly opened as current ABI"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("incompatible registry version"));
        cleanup(&name);
    }
}

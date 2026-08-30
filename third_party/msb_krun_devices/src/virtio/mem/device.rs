use std::cmp;
use std::io::Write;

use utils::eventfd::EventFd;
use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemoryBackend, GuestMemoryMmap};

use super::super::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, MemError, QueueConfig, VirtioDevice,
};
use super::{defs, defs::uapi};
use crate::virtio::InterruptTransport;

// Request queue.
pub(crate) const REQ_INDEX: usize = 0;

/// Hot(un)plug granularity. 2 MiB satisfies the Linux driver's requirement of
/// max(page size, pageblock size) on 4K x86_64 and aarch64 kernels.
pub const VIRTIO_MEM_BLOCK_SIZE: u64 = 2 << 20;

// Guest request types.
const VIRTIO_MEM_REQ_PLUG: u16 = 0;
const VIRTIO_MEM_REQ_UNPLUG: u16 = 1;
const VIRTIO_MEM_REQ_UNPLUG_ALL: u16 = 2;
const VIRTIO_MEM_REQ_STATE: u16 = 3;

// Response types.
const VIRTIO_MEM_RESP_ACK: u16 = 0;
const VIRTIO_MEM_RESP_NACK: u16 = 1;
const VIRTIO_MEM_RESP_ERROR: u16 = 3;

// STATE response payloads.
const VIRTIO_MEM_STATE_PLUGGED: u16 = 0;
const VIRTIO_MEM_STATE_UNPLUGGED: u16 = 1;
const VIRTIO_MEM_STATE_MIXED: u16 = 2;

pub(crate) const BASE_AVAIL_FEATURES: u64 = 1 << uapi::VIRTIO_F_VERSION_1 as u64;

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioMemConfig {
    block_size: u64,
    node_id: u16,
    padding: [u8; 6],
    addr: u64,
    region_size: u64,
    usable_region_size: u64,
    plugged_size: u64,
    requested_size: u64,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioMemConfig {}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioMemReq {
    req_type: u16,
    padding: [u16; 3],
    addr: u64,
    nb_blocks: u16,
    padding2: [u16; 3],
}

unsafe impl ByteValued for VirtioMemReq {}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioMemResp {
    resp_type: u16,
    padding: [u16; 3],
    state: u16,
}

unsafe impl ByteValued for VirtioMemResp {}

/// Point-in-time view of the device for host-side control and reporting.
#[derive(Debug, Clone, Copy)]
pub struct MemStateSnapshot {
    /// Bytes the host asked the guest to converge on.
    pub requested_size: u64,

    /// Bytes the guest currently has plugged.
    pub plugged_size: u64,

    /// Total hotpluggable capacity in bytes.
    pub region_size: u64,
}

pub struct Mem {
    pub(crate) queues: Option<Vec<DeviceQueue>>,
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) activate_evt: EventFd,
    pub(crate) device_state: DeviceState,
    config: VirtioMemConfig,
    /// One bit per block; set = plugged.
    plugged_blocks: Vec<bool>,
}

impl Mem {
    /// Create a virtio-mem device. The hotplug region location is supplied
    /// later through [`set_region`](Self::set_region) once the memory layout
    /// is known; `requested_size` starts at zero until the host raises it.
    pub fn new() -> super::Result<Mem> {
        Ok(Mem {
            queues: None,
            avail_features: BASE_AVAIL_FEATURES,
            acked_features: 0,
            activate_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(MemError::EventFd)?,
            device_state: DeviceState::Inactive,
            config: VirtioMemConfig {
                block_size: VIRTIO_MEM_BLOCK_SIZE,
                ..Default::default()
            },
            plugged_blocks: Vec::new(),
        })
    }

    pub fn id(&self) -> &str {
        defs::MEM_DEV_ID
    }

    /// Set the guest-physical placement of the hotplug region. Must be called
    /// before the VM boots; both values must be block-aligned.
    pub fn set_region(&mut self, addr: u64, size: u64) -> super::Result<()> {
        if !addr.is_multiple_of(VIRTIO_MEM_BLOCK_SIZE)
            || !size.is_multiple_of(VIRTIO_MEM_BLOCK_SIZE)
        {
            return Err(MemError::UnalignedRegion);
        }
        self.config.addr = addr;
        self.config.region_size = size;
        self.config.usable_region_size = size;
        self.plugged_blocks = vec![false; (size / VIRTIO_MEM_BLOCK_SIZE) as usize];
        Ok(())
    }

    /// Host control: ask the guest to converge on `size` plugged bytes. Rounds
    /// down to block granularity and caps at the region size. Signals a config
    /// change when the device is active.
    pub fn set_requested_size(&mut self, size: u64) -> u64 {
        let size = cmp::min(
            size - (size % VIRTIO_MEM_BLOCK_SIZE),
            self.config.region_size,
        );
        self.config.requested_size = size;
        if let DeviceState::Activated(_, ref interrupt) = self.device_state {
            interrupt.signal_config_change();
        }
        size
    }

    /// Host control: current requested/plugged/capacity view.
    pub fn state_snapshot(&self) -> MemStateSnapshot {
        MemStateSnapshot {
            requested_size: self.config.requested_size,
            plugged_size: self.config.plugged_size,
            region_size: self.config.region_size,
        }
    }

    /// Map a guest request range onto block indices, if fully inside the region.
    fn block_range(&self, addr: u64, nb_blocks: u16) -> Option<std::ops::Range<usize>> {
        let offset = addr.checked_sub(self.config.addr)?;
        if !offset.is_multiple_of(VIRTIO_MEM_BLOCK_SIZE) {
            return None;
        }
        let first = (offset / VIRTIO_MEM_BLOCK_SIZE) as usize;
        let end = first.checked_add(nb_blocks as usize)?;
        if end > self.plugged_blocks.len() {
            return None;
        }
        Some(first..end)
    }

    fn handle_plug(&mut self, addr: u64, nb_blocks: u16) -> VirtioMemResp {
        let Some(range) = self.block_range(addr, nb_blocks) else {
            return resp(VIRTIO_MEM_RESP_ERROR, 0);
        };
        let add = nb_blocks as u64 * VIRTIO_MEM_BLOCK_SIZE;
        if self.config.plugged_size + add > self.config.requested_size
            || self.plugged_blocks[range.clone()].iter().any(|b| *b)
        {
            return resp(VIRTIO_MEM_RESP_NACK, 0);
        }
        for block in &mut self.plugged_blocks[range] {
            *block = true;
        }
        self.config.plugged_size += add;
        resp(VIRTIO_MEM_RESP_ACK, 0)
    }

    fn handle_unplug(&mut self, addr: u64, nb_blocks: u16) -> VirtioMemResp {
        let Some(range) = self.block_range(addr, nb_blocks) else {
            return resp(VIRTIO_MEM_RESP_ERROR, 0);
        };
        if self.plugged_blocks[range.clone()].iter().any(|b| !*b) {
            return resp(VIRTIO_MEM_RESP_NACK, 0);
        }
        for block in &mut self.plugged_blocks[range.clone()] {
            *block = false;
        }
        self.config.plugged_size -= nb_blocks as u64 * VIRTIO_MEM_BLOCK_SIZE;
        self.discard_range(addr, nb_blocks as u64 * VIRTIO_MEM_BLOCK_SIZE);
        resp(VIRTIO_MEM_RESP_ACK, 0)
    }

    fn handle_unplug_all(&mut self) -> VirtioMemResp {
        let addr = self.config.addr;
        let size = self.config.region_size;
        self.plugged_blocks.fill(false);
        self.config.plugged_size = 0;
        self.discard_range(addr, size);
        resp(VIRTIO_MEM_RESP_ACK, 0)
    }

    fn handle_state(&self, addr: u64, nb_blocks: u16) -> VirtioMemResp {
        let Some(range) = self.block_range(addr, nb_blocks) else {
            return resp(VIRTIO_MEM_RESP_ERROR, 0);
        };
        let plugged = self.plugged_blocks[range.clone()]
            .iter()
            .filter(|b| **b)
            .count();
        let state = if plugged == range.len() {
            VIRTIO_MEM_STATE_PLUGGED
        } else if plugged == 0 {
            VIRTIO_MEM_STATE_UNPLUGGED
        } else {
            VIRTIO_MEM_STATE_MIXED
        };
        resp(VIRTIO_MEM_RESP_ACK, state)
    }

    /// Release the host pages backing an unplugged range. The mapping stays in
    /// place (the region is a boot-time reservation); only residency is dropped.
    fn discard_range(&self, guest_addr: u64, len: u64) {
        let DeviceState::Activated(ref mem, _) = self.device_state else {
            return;
        };
        let Ok(host_addr) = mem.get_host_address(GuestAddress(guest_addr)) else {
            error!("virtio-mem: no host mapping for guest addr {guest_addr:#x}");
            return;
        };
        if let Err(e) = discard_host_pages(host_addr, len as usize) {
            error!("virtio-mem: failed to discard {len} bytes at {guest_addr:#x}: {e}");
        }
    }

    pub fn process_req_queue(&mut self) -> bool {
        let mem = match self.device_state {
            DeviceState::Activated(ref mem, _) => mem.clone(),
            DeviceState::Inactive => unreachable!(),
        };

        let mut have_used = false;
        loop {
            let head = {
                let queues = self
                    .queues
                    .as_mut()
                    .expect("queues should exist when activated");
                match queues[REQ_INDEX].queue.pop(&mem) {
                    Some(head) => head,
                    None => break,
                }
            };
            let index = head.index;

            let mut req = VirtioMemReq::default();
            let mut resp_addr = None;
            for desc in head.into_iter() {
                if desc.is_write_only() {
                    resp_addr = Some(desc.addr);
                } else if mem.read_obj::<VirtioMemReq>(desc.addr).is_ok() {
                    req = mem.read_obj(desc.addr).unwrap();
                }
            }

            let response = match req.req_type {
                VIRTIO_MEM_REQ_PLUG => self.handle_plug(req.addr, req.nb_blocks),
                VIRTIO_MEM_REQ_UNPLUG => self.handle_unplug(req.addr, req.nb_blocks),
                VIRTIO_MEM_REQ_UNPLUG_ALL => self.handle_unplug_all(),
                VIRTIO_MEM_REQ_STATE => self.handle_state(req.addr, req.nb_blocks),
                other => {
                    error!("virtio-mem: unknown request type {other}");
                    resp(VIRTIO_MEM_RESP_ERROR, 0)
                }
            };

            let mut written = 0;
            if let Some(addr) = resp_addr {
                if let Err(e) = mem.write_obj(response, addr) {
                    error!("virtio-mem: failed to write response: {e}");
                } else {
                    written = std::mem::size_of::<VirtioMemResp>() as u32;
                }
            }

            have_used = true;
            let queues = self
                .queues
                .as_mut()
                .expect("queues should exist when activated");
            if let Err(e) = queues[REQ_INDEX].queue.add_used(&mem, index, written) {
                error!("virtio-mem: failed to add used element: {e:?}");
            }
        }

        have_used
    }
}

fn resp(resp_type: u16, state: u16) -> VirtioMemResp {
    VirtioMemResp {
        resp_type,
        padding: [0; 3],
        state,
    }
}

#[cfg(unix)]
fn discard_host_pages(host_addr: *mut u8, len: usize) -> std::io::Result<()> {
    let ret = unsafe { libc::madvise(host_addr as *mut libc::c_void, len, libc::MADV_DONTNEED) };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn discard_host_pages(host_addr: *mut u8, len: usize) -> std::io::Result<()> {
    unsafe { crate::windows::memory_mapping::discard_virtual_memory_range(host_addr.cast(), len) }
}

impl VirtioDevice for Mem {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features
    }

    fn device_type(&self) -> u32 {
        uapi::VIRTIO_ID_MEM
    }

    fn device_name(&self) -> &str {
        "mem"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &defs::QUEUE_CONFIG
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_slice = self.config.as_slice();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            error!("virtio-mem: failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        warn!(
            "virtio-mem: guest driver attempted to write device config (offset={:x}, len={:x})",
            offset,
            data.len()
        );
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        if queues.len() != defs::NUM_QUEUES {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                defs::NUM_QUEUES,
                queues.len()
            );
            return Err(ActivateError::BadActivate);
        }

        if self.activate_evt.write(1).is_err() {
            error!("Cannot write to activate_evt");
            return Err(ActivateError::BadActivate);
        }

        self.queues = Some(queues);
        self.device_state = DeviceState::Activated(mem, interrupt);

        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }
}

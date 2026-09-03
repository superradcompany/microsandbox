use std::cmp;
use std::io::Write;
use std::time::Duration;

use utils::eventfd::EventFd;
use utils::metrics::MetricsWriter;
use utils::timerfd::TimerFd;
use vm_memory::{ByteValued, GuestMemoryBackend, GuestMemoryMmap};

use super::super::{
    ActivateError, ActivateResult, BalloonError, DeviceQueue, DeviceState, QueueConfig,
    VirtioDevice,
};
use super::{defs, defs::uapi};
use crate::virtio::InterruptTransport;

// Inflate queue.
pub(crate) const IFQ_INDEX: usize = 0;
// Deflate queue.
pub(crate) const DFQ_INDEX: usize = 1;
// Stats queue.
pub(crate) const STQ_INDEX: usize = 2;
// Page-hinting queue.
pub(crate) const PHQ_INDEX: usize = 3;
// Free page reporting queue.
pub(crate) const FRQ_INDEX: usize = 4;

// Supported features.
pub(crate) const BASE_AVAIL_FEATURES: u64 = (1 << uapi::VIRTIO_F_VERSION_1 as u64)
    | (1 << uapi::VIRTIO_BALLOON_F_STATS_VQ as u64)
    | (1 << uapi::VIRTIO_BALLOON_F_FREE_PAGE_HINT as u64)
    | (1 << uapi::VIRTIO_BALLOON_F_REPORTING as u64);

pub(crate) const VIRTIO_BALLOON_S_AVAIL: u16 = 6;
pub(crate) const MAX_STATS_TAGS: u32 = 256;
pub(crate) const MAX_STATS_DESC_LEN: u32 =
    MAX_STATS_TAGS * std::mem::size_of::<BalloonStat>() as u32;

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
pub struct VirtioBalloonConfig {
    /* Number of pages host wants Guest to give up. */
    num_pages: u32,
    /* Number of pages we've actually got in balloon. */
    actual: u32,
    /* Free page report command id, readonly by guest */
    free_page_report_cmd_id: u32,
    /* Stores PAGE_POISON if page poisoning is in use */
    poison_val: u32,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioBalloonConfig {}

#[derive(Clone, Copy, Default)]
#[repr(C, packed)]
pub(crate) struct BalloonStat {
    pub(crate) tag: vm_memory::Le16,
    pub(crate) val: vm_memory::Le64,
}

unsafe impl ByteValued for BalloonStat {}

pub struct Balloon {
    pub(crate) queues: Option<Vec<DeviceQueue>>,
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) activate_evt: EventFd,
    pub(crate) device_state: DeviceState,
    config: VirtioBalloonConfig,
    pub(crate) metrics: MetricsWriter,
    pub(crate) stats_polling_interval: Option<Duration>,
    pub(crate) stats_timer: TimerFd,
    pub(crate) stats_desc_index: Option<u16>,
}

impl Balloon {
    pub fn new(
        metrics: MetricsWriter,
        stats_polling_interval: Option<Duration>,
    ) -> super::Result<Balloon> {
        Ok(Balloon {
            queues: None,
            avail_features: BASE_AVAIL_FEATURES,
            acked_features: 0,
            activate_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(BalloonError::EventFd)?,
            device_state: DeviceState::Inactive,
            config: VirtioBalloonConfig::default(),
            metrics,
            stats_polling_interval,
            stats_timer: TimerFd::new().map_err(BalloonError::TimerFd)?,
            stats_desc_index: None,
        })
    }

    pub fn id(&self) -> &str {
        defs::BALLOON_DEV_ID
    }

    pub(crate) fn stats_enabled(&self) -> bool {
        self.stats_polling_interval.is_some()
    }

    pub fn process_frq(&mut self) -> bool {
        debug!("balloon: process_frq()");
        let mem = match self.device_state {
            DeviceState::Activated(ref mem, _) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };

        let queues = self
            .queues
            .as_mut()
            .expect("queues should exist when activated");
        let mut have_used = false;

        while let Some(head) = queues[FRQ_INDEX].queue.pop(mem) {
            let index = head.index;
            for desc in head.into_iter() {
                let host_addr = mem.get_host_address(desc.addr).unwrap();
                debug!(
                    "balloon: should release guest_addr={:?} host_addr={:p} len={}",
                    desc.addr, host_addr, desc.len
                );
                if let Err(e) = discard_guest_pages(host_addr, desc.len) {
                    error!("balloon: failed to discard reported free pages: {e:?}");
                }
            }

            have_used = true;
            if let Err(e) = queues[FRQ_INDEX].queue.add_used(mem, index, 0) {
                error!("failed to add used elements to the queue: {e:?}");
            }
        }

        have_used
    }
}

#[cfg(unix)]
fn discard_guest_pages(host_addr: *mut u8, len: u32) -> std::io::Result<()> {
    let ret = unsafe {
        libc::madvise(
            host_addr as *mut libc::c_void,
            len as usize,
            libc::MADV_DONTNEED,
        )
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn discard_guest_pages(host_addr: *mut u8, len: u32) -> std::io::Result<()> {
    // The guest supplied these ranges through virtio-balloon free-page reporting, so the host can
    // discard its resident backing pages without changing the guest-visible address space.
    unsafe {
        crate::windows::memory_mapping::discard_virtual_memory_range(host_addr.cast(), len as usize)
    }
}

impl VirtioDevice for Balloon {
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
        uapi::VIRTIO_ID_BALLOON
    }

    fn device_name(&self) -> &str {
        "balloon"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &defs::QUEUE_CONFIG
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_slice = self.config.as_slice();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
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
            "balloon: guest driver attempted to write device config (offset={:x}, len={:x})",
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
            error!("Cannot write to activate_evt",);
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

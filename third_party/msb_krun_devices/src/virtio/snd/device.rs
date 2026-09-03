use std::io::Write;
use std::thread::JoinHandle;

use utils::eventfd::EventFd;
use vm_memory::{ByteValued, GuestMemoryMmap};

use super::super::{ActivateError, ActivateResult, DeviceQueue, QueueConfig, VirtioDevice};
use super::virtio_sound::VirtioSoundConfig;
use super::worker::SndWorker;
use super::{defs, defs::uapi, Error};

use crate::virtio::{DeviceState, InterruptTransport};

// Supported features.
pub(crate) const AVAIL_FEATURES: u64 = 1 << uapi::VIRTIO_F_VERSION_1 as u64;

pub struct Snd {
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) activate_evt: EventFd,
    pub(crate) device_state: DeviceState,
    worker_thread: Option<JoinHandle<()>>,
    worker_stopfd: EventFd,
}

impl Snd {
    pub fn new() -> super::Result<Snd> {
        Ok(Snd {
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            activate_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(Error::EventFdCreate)?,
            device_state: DeviceState::Inactive,
            worker_thread: None,
            worker_stopfd: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(Error::EventFdCreate)?,
        })
    }

    pub fn id(&self) -> &str {
        defs::SND_DEV_ID
    }
}

impl VirtioDevice for Snd {
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
        uapi::VIRTIO_ID_SND
    }

    fn device_name(&self) -> &str {
        "snd"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &defs::QUEUE_CONFIG
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config = VirtioSoundConfig {
            jacks: 0.into(),
            streams: 2.into(),
            chmaps: 1.into(),
        };

        let config_slice = config.as_slice();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&config_slice[offset as usize..std::cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        warn!(
            "snd: guest driver attempted to write device config (offset={:x}, len={:x})",
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
        if self.worker_thread.is_some() {
            panic!("virtio_snd: worker thread already exists");
        }

        if queues.len() != defs::NUM_QUEUES {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                defs::NUM_QUEUES,
                queues.len()
            );
            return Err(ActivateError::BadActivate);
        }

        let worker = SndWorker::new(
            queues,
            interrupt.clone(),
            mem.clone(),
            self.worker_stopfd.try_clone().unwrap(),
        );
        self.worker_thread = Some(worker.run());

        if self.activate_evt.write(1).is_err() {
            error!("Cannot write to activate_evt",);
            return Err(ActivateError::BadActivate);
        }

        self.device_state = DeviceState::Activated(mem, interrupt);

        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn reset(&mut self) -> bool {
        if let Some(worker) = self.worker_thread.take() {
            let _ = self.worker_stopfd.write(1);
            if let Err(e) = worker.join() {
                error!("error waiting for worker thread: {e:?}");
            }
        }
        self.device_state = DeviceState::Inactive;
        true
    }
}

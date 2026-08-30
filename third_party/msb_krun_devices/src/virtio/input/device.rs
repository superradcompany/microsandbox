use std::cmp;
use std::io::Write;
use std::thread::JoinHandle;

use log::{debug, error};
use utils::eventfd::{EventFd, EFD_NONBLOCK};
use vm_memory::GuestMemoryMmap;

use super::super::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, QueueConfig, VirtioDevice,
};
use super::worker::InputWorker;
use super::{defs, defs::uapi, InputError};

use crate::virtio::input::defs::config_select;
use crate::virtio::input::defs::config_select::VIRTIO_INPUT_CFG_UNSET;
use crate::virtio::InterruptTransport;
use krun_input::{
    InputAbsInfo, InputConfigBackend, InputConfigInstance, InputDeviceIds,
    InputEventProviderBackend, InputQueryConfig,
};

#[derive(Clone, Copy)]
union InputConfig {
    bytes: [u8; size_of::<InputConfigRepr>()],
    repr: InputConfigRepr,
}

impl InputConfig {
    pub fn new() -> Self {
        Self {
            bytes: [0u8; size_of::<Self>()],
        }
    }

    pub fn select(&self) -> u8 {
        unsafe { self.repr.select }
    }

    pub fn subsel(&self) -> u8 {
        unsafe { self.repr.subsel }
    }

    pub fn bytes(&self) -> &[u8; size_of::<Self>()] {
        unsafe { &self.bytes }
    }

    pub fn invalidate(&mut self) {
        self.repr.select = VIRTIO_INPUT_CFG_UNSET;
        self.repr.subsel = 0;
        self.repr.size = 0;
    }

    fn update_select(&mut self, cfg: &InputConfigInstance, select: u8, subsel: u8) {
        if select == self.select() && subsel == self.subsel() {
            return;
        }

        unsafe {
            self.repr.payload.bytes.fill(0);
        }

        let result = match select {
            config_select::VIRTIO_INPUT_CFG_ID_NAME => {
                cfg.query_device_name(unsafe { &mut self.repr.payload.bytes })
            }
            config_select::VIRTIO_INPUT_CFG_ID_SERIAL => {
                cfg.query_serial_name(unsafe { &mut self.repr.payload.bytes })
            }
            config_select::VIRTIO_INPUT_CFG_ID_DEVIDS => cfg
                .query_device_ids(unsafe { &mut self.repr.payload.ids })
                .map(|_| size_of::<InputDeviceIds>() as u8),
            config_select::VIRTIO_INPUT_CFG_PROP_BITS => {
                cfg.query_properties(unsafe { &mut self.repr.payload.bytes })
            }
            config_select::VIRTIO_INPUT_CFG_EV_BITS => {
                cfg.query_event_capabilities(subsel, unsafe { &mut self.repr.payload.bytes })
            }
            config_select::VIRTIO_INPUT_CFG_ABS_INFO => cfg
                .query_abs_info(subsel, unsafe { &mut self.repr.payload.abs })
                .map(|_| size_of::<InputDeviceIds>() as u8),
            select => {
                error!("Invalid config selection select = {select}");
                self.invalidate();
                return;
            }
        };

        match result {
            Ok(len) => {
                self.repr.size = len;
                self.repr.select = select;
                self.repr.subsel = subsel;
            }
            Err(e) => {
                error!("Failed to query config select={select}, subsel={subsel}: {e:?}");
                self.invalidate();
            }
        };
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct InputConfigRepr {
    select: u8,
    subsel: u8,
    size: u8,
    reserved: [u8; 5],
    payload: ConfigPayload,
}

#[derive(Clone, Copy)]
#[repr(C)]
union ConfigPayload {
    bytes: [u8; 128],
    abs: InputAbsInfo,
    ids: InputDeviceIds,
}

/// VirtIO Input device state
pub struct Input {
    avail_features: u64,
    acked_features: u64,
    device_state: DeviceState,
    cfg: InputConfig,
    config_instance: InputConfigInstance,
    event_provider_backend: InputEventProviderBackend<'static>,

    worker_thread: Option<JoinHandle<()>>,
    worker_stopfd: EventFd,
}

impl Input {
    pub fn new(
        config_backend: InputConfigBackend<'static>,
        events_backend: InputEventProviderBackend<'static>,
    ) -> super::Result<Input> {
        Ok(Input {
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            event_provider_backend: events_backend,
            config_instance: config_backend.create_instance().unwrap(),
            device_state: DeviceState::Inactive,
            cfg: InputConfig::new(),
            worker_thread: None,
            worker_stopfd: EventFd::new(EFD_NONBLOCK).map_err(InputError::EventFd)?,
        })
    }

    pub fn id(&self) -> &str {
        defs::INPUT_DEV_ID
    }
}

const AVAIL_FEATURES: u64 = 1 << uapi::VIRTIO_F_VERSION_1;

impl VirtioDevice for Input {
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
        uapi::VIRTIO_ID_INPUT
    }

    fn device_name(&self) -> &str {
        "input"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &defs::QUEUE_CONFIG
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let cfg_slice = self.cfg.bytes();
        let cfg_len = cfg_slice.len() as u64;

        if offset >= cfg_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&cfg_slice[offset as usize..cmp::min(end, cfg_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let len = data.len() as u64;

        let mut select = self.cfg.select();
        let mut subsel = self.cfg.subsel();

        if offset == 0 && len >= 1 {
            select = data[0];
            if len >= 2 {
                subsel = data[1]
            }
        } else if offset == 1 && len >= 1 {
            subsel = data[0]
        }

        self.cfg
            .update_select(&self.config_instance, select, subsel);
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        let [event_q, status_q]: [_; defs::NUM_QUEUES] = queues.try_into().map_err(|_| {
            error!(
                "Cannot perform activate. Expected {} queue(s)",
                defs::NUM_QUEUES
            );
            ActivateError::BadActivate
        })?;

        let worker = InputWorker::new(
            event_q,
            status_q,
            interrupt.clone(),
            mem.clone(),
            self.event_provider_backend,
            self.worker_stopfd.try_clone().unwrap(),
        );

        self.worker_thread = Some(worker.run());

        self.device_state = DeviceState::Activated(mem, interrupt);
        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn reset(&mut self) -> bool {
        if let Some(worker_thread) = self.worker_thread.take() {
            self.worker_stopfd.write(1).unwrap();

            match worker_thread.join() {
                Ok(()) => debug!("Input worker thread stopped"),
                Err(e) => {
                    error!("Failed to join worker thread: {e:?}");
                }
            }
        }
        true
    }
}

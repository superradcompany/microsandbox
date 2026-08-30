#[cfg(any(target_os = "macos", target_os = "windows"))]
use crossbeam_channel::Sender;
use std::cmp;
use std::io::Write;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use utils::eventfd::{EventFd, EFD_NONBLOCK};
#[cfg(any(target_os = "macos", target_os = "windows"))]
use utils::worker_message::WorkerMessage;
use virtio_bindings::{virtio_config::VIRTIO_F_VERSION_1, virtio_ring::VIRTIO_RING_F_EVENT_IDX};
use vm_memory::{ByteValued, GuestMemoryMmap};

use super::super::{
    ActivateResult, DeviceQueue, DeviceState, FsError, QueueConfig, VirtioDevice, VirtioShmRegion,
};
use super::dyn_filesystem::{DynFileSystem, DynFileSystemAdapter};
use super::passthrough::{self, PassthroughFs};
use super::worker::FsWorker;
use super::ExportTable;
use super::{defs, defs::uapi};
use crate::virtio::InterruptTransport;

#[derive(Copy, Clone)]
#[repr(C, packed)]
struct VirtioFsConfig {
    tag: [u8; 36],
    num_request_queues: u32,
}

impl Default for VirtioFsConfig {
    fn default() -> Self {
        VirtioFsConfig {
            tag: [0; 36],
            num_request_queues: 0,
        }
    }
}

unsafe impl ByteValued for VirtioFsConfig {}

enum FsBackend {
    Passthrough(passthrough::Config),
    Custom(Arc<dyn DynFileSystem>),
}

pub struct Fs {
    avail_features: u64,
    acked_features: u64,
    device_state: DeviceState,
    config: VirtioFsConfig,
    shm_region: Option<VirtioShmRegion>,
    backend: FsBackend,
    worker_thread: Option<JoinHandle<()>>,
    worker_stopfd: EventFd,
    exit_code: Arc<AtomicI32>,
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    map_sender: Option<Sender<WorkerMessage>>,
}

impl Fs {
    pub fn new(
        fs_id: String,
        shared_dir: String,
        exit_code: Arc<AtomicI32>,
        allow_root_dir_delete: bool,
    ) -> super::Result<Fs> {
        let avail_features = (1u64 << VIRTIO_F_VERSION_1) | (1u64 << VIRTIO_RING_F_EVENT_IDX);

        let tag = fs_id.into_bytes();
        let mut config = VirtioFsConfig::default();
        config.tag[..tag.len()].copy_from_slice(tag.as_slice());
        config.num_request_queues = 1;

        let fs_cfg = passthrough::Config {
            root_dir: shared_dir,
            allow_root_dir_delete,
            ..Default::default()
        };

        Ok(Fs {
            avail_features,
            acked_features: 0,
            device_state: DeviceState::Inactive,
            config,
            shm_region: None,
            backend: FsBackend::Passthrough(fs_cfg),
            worker_thread: None,
            worker_stopfd: EventFd::new(EFD_NONBLOCK).map_err(FsError::EventFd)?,
            exit_code,
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            map_sender: None,
        })
    }

    pub fn with_custom_backend(
        fs_id: String,
        backend: Arc<dyn DynFileSystem>,
        exit_code: Arc<AtomicI32>,
    ) -> super::Result<Fs> {
        let avail_features = (1u64 << VIRTIO_F_VERSION_1) | (1u64 << VIRTIO_RING_F_EVENT_IDX);

        let tag = fs_id.into_bytes();
        let mut config = VirtioFsConfig::default();
        config.tag[..tag.len()].copy_from_slice(tag.as_slice());
        config.num_request_queues = 1;

        Ok(Fs {
            avail_features,
            acked_features: 0,
            device_state: DeviceState::Inactive,
            config,
            shm_region: None,
            backend: FsBackend::Custom(backend),
            worker_thread: None,
            worker_stopfd: EventFd::new(EFD_NONBLOCK).map_err(FsError::EventFd)?,
            exit_code,
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            map_sender: None,
        })
    }

    pub fn id(&self) -> &str {
        defs::FS_DEV_ID
    }

    pub fn set_shm_region(&mut self, shm_region: VirtioShmRegion) {
        self.shm_region = Some(shm_region);
    }

    pub fn set_export_table(&mut self, export_table: ExportTable) -> u64 {
        match &mut self.backend {
            FsBackend::Passthrough(cfg) => {
                static FS_UNIQUE_ID: AtomicU64 = AtomicU64::new(0);
                cfg.export_fsid = FS_UNIQUE_ID.fetch_add(1, Ordering::Relaxed);
                cfg.export_table = Some(export_table);
                cfg.export_fsid
            }
            FsBackend::Custom(_) => 0,
        }
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    pub fn set_map_sender(&mut self, map_sender: Sender<WorkerMessage>) {
        self.map_sender = Some(map_sender);
    }
}

impl VirtioDevice for Fs {
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
        uapi::VIRTIO_ID_FS
    }

    fn device_name(&self) -> &str {
        "fs"
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
            "fs: guest driver attempted to write device config (offset={:x}, len={:x})",
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
            panic!("virtio_fs: worker thread already exists");
        }

        // Extract queues and eventfds from DeviceQueues.
        let mut worker_queues = Vec::with_capacity(queues.len());
        let mut queue_evts = Vec::with_capacity(queues.len());
        for dq in queues {
            worker_queues.push(dq.queue);
            queue_evts.push(dq.event);
        }

        let join_handle = match &self.backend {
            FsBackend::Passthrough(cfg) => {
                let worker = FsWorker::new(
                    PassthroughFs::new(cfg.clone()).unwrap(),
                    worker_queues,
                    queue_evts,
                    interrupt.clone(),
                    mem.clone(),
                    self.shm_region.clone(),
                    self.worker_stopfd.try_clone().unwrap(),
                    self.exit_code.clone(),
                    #[cfg(any(target_os = "macos", target_os = "windows"))]
                    self.map_sender.clone(),
                );
                worker.run()
            }
            FsBackend::Custom(dyn_fs) => {
                let worker = FsWorker::new(
                    DynFileSystemAdapter::new(Arc::clone(dyn_fs)),
                    worker_queues,
                    queue_evts,
                    interrupt.clone(),
                    mem.clone(),
                    self.shm_region.clone(),
                    self.worker_stopfd.try_clone().unwrap(),
                    self.exit_code.clone(),
                    #[cfg(any(target_os = "macos", target_os = "windows"))]
                    self.map_sender.clone(),
                );
                worker.run()
            }
        };
        self.worker_thread = Some(join_handle);

        self.device_state = DeviceState::Activated(mem, interrupt);
        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn shm_region(&self) -> Option<&VirtioShmRegion> {
        self.shm_region.as_ref()
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

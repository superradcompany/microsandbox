mod device;
mod event_handler;

pub use self::defs::uapi::VIRTIO_ID_MEM as TYPE_MEM;
pub use self::device::{Mem, MemStateSnapshot, VIRTIO_MEM_BLOCK_SIZE};

mod defs {
    use super::super::QueueConfig;

    pub const MEM_DEV_ID: &str = "virtio_mem";
    pub const NUM_QUEUES: usize = 1;
    pub const QUEUE_SIZE: u16 = 128;
    pub static QUEUE_CONFIG: [QueueConfig; NUM_QUEUES] = [QueueConfig::new(QUEUE_SIZE); NUM_QUEUES];

    pub mod uapi {
        pub const VIRTIO_F_VERSION_1: u32 = 32;
        pub const VIRTIO_ID_MEM: u32 = 24;
    }
}

#[derive(Debug)]
pub enum MemError {
    /// Failed to create event fd.
    EventFd(std::io::Error),
    /// The hotplug region size is not a multiple of the block size.
    UnalignedRegion,
}

type Result<T> = std::result::Result<T, MemError>;

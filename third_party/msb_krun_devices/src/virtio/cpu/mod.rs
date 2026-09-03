mod device;
mod event_handler;

pub use self::defs::uapi::VIRTIO_ID_MSB_CPU as TYPE_MSB_CPU;
pub use self::device::{
    Cpu, CpuEnforcement, CpuKickSlot, CpuStateSnapshot, ENFORCEMENT_GRACE, THROTTLE_PARK,
};

mod defs {
    use super::super::QueueConfig;

    pub const CPU_DEV_ID: &str = "virtio_msb_cpu";
    pub const NUM_QUEUES: usize = 1;
    pub const QUEUE_SIZE: u16 = 16;
    pub static QUEUE_CONFIG: [QueueConfig; NUM_QUEUES] = [QueueConfig::new(QUEUE_SIZE); NUM_QUEUES];

    pub mod uapi {
        pub const VIRTIO_F_VERSION_1: u32 = 32;
        pub const VIRTIO_ID_MSB_CPU: u32 = 0x4d43;
    }
}

#[derive(Debug)]
pub enum CpuDeviceError {
    /// Failed to create event fd.
    EventFd(std::io::Error),
}

type Result<T> = std::result::Result<T, CpuDeviceError>;

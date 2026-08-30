mod device;
mod event_handler;

pub use self::defs::uapi::VIRTIO_ID_MSB_METRICS as TYPE_MSB_METRICS;
pub use self::device::{MsbMetrics, UpperFilesystemSample};

mod defs {
    use crate::virtio::QueueConfig;

    pub const MSB_METRICS_DEV_ID: &str = "virtio_msb_metrics";
    pub const NUM_QUEUES: usize = 1;
    const QUEUE_SIZE: u16 = 64;
    pub static QUEUE_CONFIG: [QueueConfig; NUM_QUEUES] = [QueueConfig::new(QUEUE_SIZE); NUM_QUEUES];

    pub mod uapi {
        pub const VIRTIO_F_VERSION_1: u32 = 32;
        pub const VIRTIO_ID_MSB_METRICS: u32 = 0x4d53;
    }
}

#[derive(Debug)]
pub enum MsbMetricsError {
    /// Failed to create event fd.
    EventFd(std::io::Error),
}

type Result<T> = std::result::Result<T, MsbMetricsError>;

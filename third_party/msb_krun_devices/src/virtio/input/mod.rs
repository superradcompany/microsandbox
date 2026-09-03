mod device;
pub mod passthrough;
mod worker;

pub use self::defs::uapi::VIRTIO_ID_INPUT as TYPE_INPUT;
pub use self::device::Input;

use super::QueueConfig;

mod defs {
    use super::QueueConfig;

    pub const INPUT_DEV_ID: &str = "virtio_input";
    pub const NUM_QUEUES: usize = 2;

    const QUEUE_SIZE: u16 = 256;
    pub static QUEUE_CONFIG: [QueueConfig; NUM_QUEUES] = [QueueConfig::new(QUEUE_SIZE); NUM_QUEUES];

    pub mod uapi {
        pub const VIRTIO_F_VERSION_1: u32 = 32;
        pub const VIRTIO_ID_INPUT: u32 = 18;
    }

    pub mod config_select {
        pub const VIRTIO_INPUT_CFG_UNSET: u8 = 0x00;
        pub const VIRTIO_INPUT_CFG_ID_NAME: u8 = 0x01;
        pub const VIRTIO_INPUT_CFG_ID_SERIAL: u8 = 0x02;
        pub const VIRTIO_INPUT_CFG_ID_DEVIDS: u8 = 0x03;
        pub const VIRTIO_INPUT_CFG_PROP_BITS: u8 = 0x10;
        pub const VIRTIO_INPUT_CFG_EV_BITS: u8 = 0x11;
        pub const VIRTIO_INPUT_CFG_ABS_INFO: u8 = 0x12;
    }
}

#[derive(Debug)]
pub enum InputError {
    /// Failed to create event fd.
    EventFd(std::io::Error),

    /// Backend error
    BackendError(String),

    SendNotificationFailed,

    EventFdError,

    HandleEventNotEpollIn,

    HandleEventUnknownEvent,

    UnexpectedConfig(u8),

    UnexpectedFetchEventError,

    UnexpectedDescriptorCount(usize),

    UnexpectedInputDeviceError,

    UnexpectedWriteDescriptorError,

    UnexpectedWriteVringError,
}

type Result<T> = std::result::Result<T, InputError>;

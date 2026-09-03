mod console_control;
mod device;
mod event_handler;
mod port;
pub mod port_io;
mod port_queue_mapping;
mod process_rx;
mod process_tx;

use polly::event_manager::Pollable;
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
use utils::eventfd::EventFd;

pub use self::defs::uapi::VIRTIO_ID_CONSOLE as TYPE_CONSOLE;
pub use self::device::Console;
pub use self::port::PortDescription;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Default descriptor count for virtio-console control and port queues.
pub const DEFAULT_QUEUE_SIZE: u16 = 32;

/// Smallest supported per-port descriptor count.
pub const MIN_QUEUE_SIZE: u16 = 16;

/// Largest supported per-port descriptor count.
pub const MAX_QUEUE_SIZE: u16 = 1024;

#[cfg(unix)]
pub(crate) fn eventfd_pollable(event: &EventFd) -> Pollable {
    event.as_raw_fd()
}

#[cfg(windows)]
pub(crate) fn eventfd_pollable(event: &EventFd) -> Pollable {
    event.as_raw_handle()
}

#[cfg(unix)]
pub(crate) fn pollable_token(pollable: Pollable) -> u64 {
    pollable as u64
}

#[cfg(windows)]
pub(crate) fn pollable_token(pollable: Pollable) -> u64 {
    pollable as usize as u64
}

mod defs {
    pub const CONSOLE_DEV_ID: &str = "virtio_console";

    pub mod uapi {
        /// The device conforms to the virtio spec version 1.0.
        pub const VIRTIO_CONSOLE_F_SIZE: u32 = 0;
        pub const VIRTIO_CONSOLE_F_MULTIPORT: u32 = 1;
        pub const VIRTIO_F_VERSION_1: u32 = 32;
        pub const VIRTIO_ID_CONSOLE: u32 = 3;
    }

    #[allow(dead_code)]
    pub mod control_event {
        pub const VIRTIO_CONSOLE_DEVICE_READY: u16 = 0;
        // Also known as VIRTIO_CONSOLE_DEVICE_ADD in spec, but kernel uses this (more descriptive) name
        pub const VIRTIO_CONSOLE_PORT_ADD: u16 = 1;
        /// Also known as VIRTIO_CONSOLE_DEVICE_REMOVE in spec, but kernel uses this (more descriptive) name
        pub const VIRTIO_CONSOLE_PORT_REMOVE: u16 = 2;
        pub const VIRTIO_CONSOLE_PORT_READY: u16 = 3;
        pub const VIRTIO_CONSOLE_CONSOLE_PORT: u16 = 4;
        pub const VIRTIO_CONSOLE_RESIZE: u16 = 5;
        pub const VIRTIO_CONSOLE_PORT_OPEN: u16 = 6;
        pub const VIRTIO_CONSOLE_PORT_NAME: u16 = 7;
    }
}

#[derive(Debug)]
pub enum ConsoleError {
    /// Failed to create event fd.
    EventFd(std::io::Error),
    /// Failed to create SIGWINCH pipe.
    SigwinchPipe(std::io::Error),
    /// A port requested a queue size unsupported by the virtio-console device.
    InvalidQueueSize { port_id: usize, queue_size: u16 },
}

type Result<T> = std::result::Result<T, ConsoleError>;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Return whether a virtio-console port queue size is supported.
pub fn is_valid_queue_size(queue_size: u16) -> bool {
    (MIN_QUEUE_SIZE..=MAX_QUEUE_SIZE).contains(&queue_size) && queue_size.is_power_of_two()
}

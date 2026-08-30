use std::collections::VecDeque;
use std::ops::Deref;
use std::sync::{Arc, Mutex};

use utils::eventfd::EventFd;
use utils::eventfd::EFD_NONBLOCK;
use vm_memory::{ByteValued, GuestMemoryMmap};

use crate::virtio::console::defs::control_event::{
    VIRTIO_CONSOLE_CONSOLE_PORT, VIRTIO_CONSOLE_PORT_ADD, VIRTIO_CONSOLE_PORT_NAME,
    VIRTIO_CONSOLE_PORT_OPEN, VIRTIO_CONSOLE_RESIZE,
};

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed(4))]
pub struct VirtioConsoleControl {
    /// Port number
    pub id: u32,
    /// The kind of control event
    pub event: u16,
    /// Extra information for the event
    pub value: u16,
}

// Safe because it only has data and has no implicit padding.
// But NOTE that this relies on CPU being little endian, to have correct semantics
unsafe impl ByteValued for VirtioConsoleControl {}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
pub struct VirtioConsoleResize {
    // NOTE: the order of these fields in older Linux kernels and in the spec were swapped.
    // Linux changed it in commit 5326ab737a47 to match the specs.
    pub cols: u16,
    pub rows: u16,
}

// Safe because it only has data and has no implicit padding.
// but NOTE, that we rely on CPU being little endian, for the values to be correct
unsafe impl ByteValued for VirtioConsoleResize {}

pub enum Payload {
    ConsoleControl(VirtioConsoleControl),
    Bytes(Vec<u8>),
}

impl Deref for Payload {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Payload::ConsoleControl(b) => b.as_slice(),
            Payload::Bytes(b) => b.as_slice(),
        }
    }
}

// Utility for sending commands into control rx queue
pub struct ConsoleControl {
    queue: Mutex<VecDeque<Payload>>,
    queue_evt: EventFd,
}

impl ConsoleControl {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            queue: Default::default(),
            queue_evt: EventFd::new(EFD_NONBLOCK).unwrap(),
        })
    }

    pub fn mark_console_port(&self, _mem: &GuestMemoryMmap, port_id: u32) {
        self.push_msg(VirtioConsoleControl {
            id: port_id,
            event: VIRTIO_CONSOLE_CONSOLE_PORT,
            value: 1,
        })
    }

    pub fn console_resize(&self, port_id: u32, new_size: VirtioConsoleResize) {
        let mut buf = Vec::new();
        buf.extend(
            VirtioConsoleControl {
                id: port_id,
                event: VIRTIO_CONSOLE_RESIZE,
                value: 0,
            }
            .as_slice(),
        );
        buf.extend(new_size.as_slice());
        self.push_vec(buf)
    }

    /// Adds another port with the specified port_id
    pub fn port_add(&self, port_id: u32) {
        self.push_msg(VirtioConsoleControl {
            id: port_id,
            event: VIRTIO_CONSOLE_PORT_ADD,
            value: 0,
        })
    }

    pub fn port_open(&self, port_id: u32, open: bool) {
        self.push_msg(VirtioConsoleControl {
            id: port_id,
            event: VIRTIO_CONSOLE_PORT_OPEN,
            value: open as u16,
        })
    }

    pub fn port_name(&self, port_id: u32, name: &str) {
        let mut buf: Vec<u8> = Vec::new();

        buf.extend_from_slice(
            VirtioConsoleControl {
                id: port_id,
                event: VIRTIO_CONSOLE_PORT_NAME,
                value: 1, // Unspecified/unused in the spec, lets use the same value as QEMU.
            }
            .as_slice(),
        );

        // The spec says the name shouldn't be NUL terminated.
        buf.extend(name.as_bytes());
        self.push_vec(buf)
    }

    pub fn queue_pop(&self) -> Option<Payload> {
        let mut queue = self.queue.lock().expect("Poisoned lock");
        queue.pop_front()
    }

    pub fn queue_evt(&self) -> &EventFd {
        &self.queue_evt
    }

    fn push_msg(&self, msg: VirtioConsoleControl) {
        let mut queue = self.queue.lock().expect("Poisoned lock");
        queue.push_back(Payload::ConsoleControl(msg));
        if let Err(e) = self.queue_evt.write(1) {
            log::trace!("ConsoleControl failed to write to notify {e}")
        }
    }

    fn push_vec(&self, buf: Vec<u8>) {
        let mut queue = self.queue.lock().expect("Poisoned lock");
        queue.push_back(Payload::Bytes(buf));
        if let Err(e) = self.queue_evt.write(1) {
            log::trace!("ConsoleControl failed to write to notify {e}")
        }
    }
}

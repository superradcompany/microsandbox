//! virtio-input devices fed by the display viewer: a keyboard and an
//! absolute-position pointer (the shape of QEMU's `virtio-tablet`).

use std::os::fd::{AsFd, BorrowedFd};

use msb_krun::krun_input::{
    write_bitmap, InputAbsInfo, InputBackendError, InputConfigBackend, InputDeviceIds,
    InputEvent, InputEventProviderBackend, InputEventType, InputEventsImpl, InputQueryConfig,
    IntoInputConfig, IntoInputEvents, ObjectNew,
};
use msb_krun_utils::pollable_channel::{pollable_channel, PollableChannelReciever, PollableChannelSender};

use super::protocol::evdev::*;
use super::protocol::ABS_RANGE;

const VENDOR_ID: u16 = u16::from_le_bytes(*b"MS");
const KEYBOARD_PRODUCT: u16 = 0x0001;
const POINTER_PRODUCT: u16 = 0x0002;

/// Build one evdev event.
pub fn event(type_: u16, code: u16, value: u32) -> InputEvent {
    InputEvent { type_, code, value }
}

/// The `SYN_REPORT` that terminates a batch of events.
pub fn syn() -> InputEvent {
    event(EV_SYN, SYN_REPORT, 0)
}

fn copy_name(name: &[u8], buf: &mut [u8]) -> Result<u8, InputBackendError> {
    let n = name.len().min(buf.len());
    buf[..n].copy_from_slice(&name[..n]);
    Ok(n as u8)
}

fn parse_type(event_type: u8) -> Result<InputEventType, InputBackendError> {
    InputEventType::try_from(event_type as u16).map_err(|_| InputBackendError::InvalidParam)
}

/// Device description of the virtual keyboard.
#[derive(Clone, Copy)]
pub struct KeyboardConfig;

impl ObjectNew<()> for KeyboardConfig {
    fn new(_userdata: Option<&()>) -> Self {
        Self
    }
}

impl InputQueryConfig for KeyboardConfig {
    fn query_device_name(&self, buf: &mut [u8]) -> Result<u8, InputBackendError> {
        copy_name(b"microsandbox keyboard", buf)
    }

    fn query_serial_name(&self, buf: &mut [u8]) -> Result<u8, InputBackendError> {
        copy_name(b"MSB-KBD", buf)
    }

    fn query_device_ids(&self, ids: &mut InputDeviceIds) -> Result<(), InputBackendError> {
        *ids = InputDeviceIds {
            bustype: BUS_VIRTUAL,
            vendor: VENDOR_ID,
            product: KEYBOARD_PRODUCT,
            version: 1,
        };
        Ok(())
    }

    fn query_event_capabilities(
        &self,
        event_type: u8,
        bitmap: &mut [u8],
    ) -> Result<u8, InputBackendError> {
        match parse_type(event_type)? {
            // Type 0 asks which event types exist.
            InputEventType::Syn => Ok(write_bitmap(bitmap, &[EV_KEY])),
            InputEventType::Key => Ok(write_bitmap(bitmap, KEYBOARD_KEYS)),
            _ => Ok(0),
        }
    }

    fn query_abs_info(&self, _axis: u8, info: &mut InputAbsInfo) -> Result<(), InputBackendError> {
        *info = InputAbsInfo {
            min: 0,
            max: 0,
            fuzz: 0,
            flat: 0,
            res: 0,
        };
        Ok(())
    }

    fn query_properties(&self, bitmap: &mut [u8]) -> Result<u8, InputBackendError> {
        Ok(write_bitmap(bitmap, &[]))
    }
}

/// Device description of the virtual pointer: absolute X/Y, three buttons,
/// two wheels. libinput drives it as an absolute mouse.
#[derive(Clone, Copy)]
pub struct PointerConfig;

impl ObjectNew<()> for PointerConfig {
    fn new(_userdata: Option<&()>) -> Self {
        Self
    }
}

impl InputQueryConfig for PointerConfig {
    fn query_device_name(&self, buf: &mut [u8]) -> Result<u8, InputBackendError> {
        copy_name(b"microsandbox pointer", buf)
    }

    fn query_serial_name(&self, buf: &mut [u8]) -> Result<u8, InputBackendError> {
        copy_name(b"MSB-PTR", buf)
    }

    fn query_device_ids(&self, ids: &mut InputDeviceIds) -> Result<(), InputBackendError> {
        *ids = InputDeviceIds {
            bustype: BUS_VIRTUAL,
            vendor: VENDOR_ID,
            product: POINTER_PRODUCT,
            version: 1,
        };
        Ok(())
    }

    fn query_event_capabilities(
        &self,
        event_type: u8,
        bitmap: &mut [u8],
    ) -> Result<u8, InputBackendError> {
        match parse_type(event_type)? {
            InputEventType::Syn => Ok(write_bitmap(bitmap, &[EV_KEY, EV_REL, EV_ABS])),
            InputEventType::Key => Ok(write_bitmap(bitmap, &[BTN_LEFT, BTN_RIGHT, BTN_MIDDLE])),
            InputEventType::Rel => Ok(write_bitmap(bitmap, &[REL_WHEEL, REL_HWHEEL])),
            InputEventType::Abs => Ok(write_bitmap(bitmap, &[ABS_X, ABS_Y])),
            _ => Ok(0),
        }
    }

    fn query_abs_info(&self, axis: u8, info: &mut InputAbsInfo) -> Result<(), InputBackendError> {
        // The guest writes `select` and `subsel` separately, so the device
        // first queries with a stale axis; an error there invalidates the
        // config and loses the real query that follows. Answer every axis.
        let max = if u16::from(axis) == ABS_X || u16::from(axis) == ABS_Y {
            ABS_RANGE
        } else {
            0
        };
        *info = InputAbsInfo {
            min: 0,
            max,
            fuzz: 0,
            flat: 0,
            res: 0,
        };
        Ok(())
    }

    fn query_properties(&self, bitmap: &mut [u8]) -> Result<u8, InputBackendError> {
        Ok(write_bitmap(bitmap, &[]))
    }
}

/// Event provider reading from a pollable channel filled by the viewer.
pub struct ChannelEvents {
    rx: PollableChannelReciever<InputEvent>,
}

impl ObjectNew<PollableChannelReciever<InputEvent>> for ChannelEvents {
    fn new(userdata: Option<&PollableChannelReciever<InputEvent>>) -> Self {
        Self {
            rx: userdata
                .expect("ChannelEvents is created with its receiver as userdata")
                .clone(),
        }
    }
}

impl InputEventsImpl for ChannelEvents {
    fn get_read_notify_fd(&self) -> Result<BorrowedFd<'_>, InputBackendError> {
        Ok(self.rx.as_fd())
    }

    fn next_event(&mut self) -> Result<Option<InputEvent>, InputBackendError> {
        match self.rx.try_recv() {
            Ok(event) => Ok(event),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(_) => Err(InputBackendError::InternalError),
        }
    }
}

/// One virtual input device: the sender the display server pushes events
/// into, plus the two backends handed to the VM builder.
pub struct InputDevice {
    /// Events queued here reach the guest.
    pub tx: PollableChannelSender<InputEvent>,
    /// Device description backend.
    pub config: InputConfigBackend<'static>,
    /// Event source backend.
    pub events: InputEventProviderBackend<'static>,
}

fn device<C: IntoInputConfig<()>>() -> std::io::Result<InputDevice> {
    let (tx, rx) = pollable_channel()?;
    // The backends need `'static` userdata; the receiver lives as long as
    // the sandbox process.
    let rx: &'static PollableChannelReciever<InputEvent> = Box::leak(Box::new(rx));
    Ok(InputDevice {
        tx,
        config: C::into_input_config(None),
        events: ChannelEvents::into_input_events(Some(rx)),
    })
}

/// Create the virtual keyboard.
pub fn keyboard() -> std::io::Result<InputDevice> {
    device::<KeyboardConfig>()
}

/// Create the virtual pointer.
pub fn pointer() -> std::io::Result<InputDevice> {
    device::<PointerConfig>()
}

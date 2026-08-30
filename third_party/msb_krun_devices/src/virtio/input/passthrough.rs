use krun_input::{
    InputAbsInfo, InputBackendError, InputDeviceIds, InputEvent, InputEventsImpl, InputQueryConfig,
    ObjectNew,
};
use nix::fcntl::{fcntl, OFlag, F_GETFL, F_SETFL};
use nix::{errno::Errno, ioctl_read, ioctl_read_buf, unistd};
use std::mem;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};

/// Internal passthrough input backend that forwards host /dev/input/* devices
pub struct PassthroughInputBackend {
    fd: BorrowedFd<'static>,
}

impl InputQueryConfig for PassthroughInputBackend {
    fn query_serial_name(&self, serial_buf: &mut [u8]) -> Result<u8, InputBackendError> {
        match unsafe { eviocguniq(self.fd.as_raw_fd(), serial_buf) } {
            Ok(len) => Ok(len as u8),
            Err(e) => {
                error!("Failed to get device serial (eviocguniq): {e}");
                Err(InputBackendError::InternalError)
            }
        }
    }

    fn query_device_name(&self, name_buf: &mut [u8]) -> Result<u8, InputBackendError> {
        match unsafe { eviocgname(self.fd.as_raw_fd(), name_buf) } {
            Ok(len) => Ok(len as u8),
            Err(e) => {
                error!("Failed to get device name (eviocgname): {e}");
                Err(InputBackendError::InternalError)
            }
        }
    }

    fn query_device_ids(&self, ids: &mut InputDeviceIds) -> Result<(), InputBackendError> {
        match unsafe { eviocgid(self.fd.as_raw_fd(), ids) } {
            Ok(_) => Ok(()),
            Err(e) => {
                error!("Failed to get device information ids (eviocgid): {e}");
                Err(InputBackendError::InternalError)
            }
        }
    }

    fn query_event_capabilities(
        &self,
        event_type: u8,
        bitmap_buf: &mut [u8],
    ) -> Result<u8, InputBackendError> {
        match unsafe { eviocgbit(self.fd.as_raw_fd(), event_type, bitmap_buf) } {
            Ok(n) => {
                let len = find_length(&bitmap_buf[..n as usize]) as u8;
                debug!(
                    "eviocgbit: {event_type}, got {n} bytes (from n): {:#?}",
                    &bitmap_buf[..n as usize]
                );
                Ok(len)
            }
            Err(e) => {
                error!("Failed to get device event capabilities (eviocgbit): {e}");
                Err(InputBackendError::InternalError)
            }
        }
    }

    fn query_abs_info(
        &self,
        abs_axis: u8,
        abs_info: &mut InputAbsInfo,
    ) -> Result<(), InputBackendError> {
        let mut linux_abs_info = LinuxAbsInfo::default();
        match unsafe { eviocgabs(self.fd.as_raw_fd(), abs_axis, &mut linux_abs_info) } {
            Ok(_) => {
                *abs_info = InputAbsInfo {
                    min: linux_abs_info.minimum,
                    max: linux_abs_info.maximum,
                    fuzz: linux_abs_info.fuzz,
                    flat: linux_abs_info.flat,
                    res: linux_abs_info.resolution,
                };
                Ok(())
            }
            Err(e) => {
                error!("Failed to get device abs_info (eviocgabs): {e}");
                Err(InputBackendError::InternalError)
            }
        }
    }

    fn query_properties(&self, properties: &mut [u8]) -> Result<u8, InputBackendError> {
        match unsafe { eviocgprop(self.fd.as_raw_fd(), properties) } {
            Ok(len) => Ok(len as u8),
            Err(e) => {
                error!("Failed to query device properties (eviocgprop): {e}");
                Err(InputBackendError::InternalError)
            }
        }
    }
}

impl ObjectNew<BorrowedFd<'static>> for PassthroughInputBackend {
    fn new(userdata: Option<&BorrowedFd<'static>>) -> Self {
        let fd = userdata
            .copied()
            .expect("Missing argument for PassthroughInputBackend::new");

        make_non_blocking(&fd)
            .expect("Cannot make device fd non-blocking (Invalid file descriptor?)");
        Self { fd }
    }
}

impl InputEventsImpl for PassthroughInputBackend {
    fn get_read_notify_fd(&self) -> Result<BorrowedFd<'_>, InputBackendError> {
        Ok(self.fd)
    }

    fn next_event(&mut self) -> Result<Option<InputEvent>, InputBackendError> {
        let mut linux_event = unsafe { std::mem::zeroed::<LinuxInputEvent>() };
        let event_slice = unsafe {
            std::slice::from_raw_parts_mut(
                &mut linux_event as *mut _ as *mut u8,
                size_of::<LinuxInputEvent>(),
            )
        };

        match unistd::read(self.fd, event_slice) {
            Ok(bytes_read) if bytes_read == size_of::<LinuxInputEvent>() => {
                trace!("Forwarding input: {linux_event:?}");
                Ok(Some(InputEvent {
                    type_: linux_event.type_,
                    code: linux_event.code,
                    value: linux_event.value,
                }))
            }
            Ok(_bytes_read) => {
                error!("Partial read from /dev/input was unexpected, not implemented!");
                Err(InputBackendError::InternalError)
            }
            Err(Errno::EAGAIN) => Ok(None),
            Err(e) => {
                error!("Failed to read event from input device: {e}");
                Err(InputBackendError::InternalError)
            }
        }
    }
}

#[repr(C)]
#[derive(Debug)]
struct LinuxInputEvent {
    time: libc::timeval,
    type_: u16,
    code: u16,
    value: u32,
}

#[repr(C)]
#[derive(Debug, Default)]
struct LinuxAbsInfo {
    value: u32,
    minimum: u32,
    maximum: u32,
    fuzz: u32,
    flat: u32,
    resolution: u32,
}

ioctl_read!(eviocgid, b'E', 0x02, InputDeviceIds); // Kernel uapi struct is the same as virtio
ioctl_read_buf!(eviocgname, b'E', 0x06, u8);
ioctl_read_buf!(eviocguniq, b'E', 0x08, u8);
ioctl_read_buf!(eviocgprop, b'E', 0x09, u8);

unsafe fn eviocgbit(fd: RawFd, evt: u8, buf: &mut [u8]) -> Result<u32, Errno> {
    let ioctl_num = nix::request_code_read!(b'E', 0x20 + evt, buf.len());

    let n = libc::ioctl(fd, ioctl_num as _, buf.as_mut_ptr());
    if n < 0 {
        return Err(Errno::last());
    }
    Ok(n as u32)
}

unsafe fn eviocgabs(fd: RawFd, axis: u8, abs_info: &mut LinuxAbsInfo) -> Result<u32, Errno> {
    let ioctl_num = nix::request_code_read!(b'E', 0x40 + axis, size_of::<LinuxAbsInfo>());

    let n = libc::ioctl(fd, ioctl_num as _, abs_info as *mut _);
    if n < 0 {
        return Err(Errno::last());
    }
    Ok(mem::size_of::<InputAbsInfo>() as u32)
}

fn make_non_blocking(fd: &impl AsFd) -> Result<(), nix::Error> {
    let flags = fcntl(fd, F_GETFL)?;
    fcntl(
        fd,
        F_SETFL(OFlag::from_bits_retain(flags) | OFlag::O_NONBLOCK),
    )?;

    Ok(())
}

fn find_length(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .rposition(|b| *b != 0)
        .map(|idx| idx + 1)
        .unwrap_or(0)
}

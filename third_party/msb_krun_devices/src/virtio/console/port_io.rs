#[cfg(unix)]
use libc::{
    fcntl, F_GETFL, F_SETFL, O_NONBLOCK, STDERR_FILENO, STDIN_FILENO, STDOUT_FILENO, TIOCGWINSZ,
};
use log::Level;
#[cfg(unix)]
use nix::errno::Errno;
#[cfg(unix)]
use nix::ioctl_read_bad;
#[cfg(unix)]
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
#[cfg(unix)]
use nix::unistd::{dup, isatty};
#[cfg(windows)]
use std::collections::VecDeque;
#[cfg(windows)]
use std::ffi::OsStr;
use std::fs::File;
use std::io;
#[cfg(unix)]
use std::io::ErrorKind;
#[cfg(windows)]
use std::io::Write;
#[cfg(unix)]
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
#[cfg(windows)]
use std::ptr;
#[cfg(any(unix, windows))]
use std::sync::Arc;
#[cfg(windows)]
use std::sync::Mutex;
#[cfg(windows)]
use std::thread;
#[cfg(windows)]
use std::time::Duration;
#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_NO_DATA, ERROR_OPERATION_ABORTED, ERROR_PIPE_BUSY,
    ERROR_PIPE_NOT_CONNECTED, FALSE, HANDLE, INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0,
};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING,
};
#[cfg(windows)]
use windows_sys::Win32::System::Pipes::WaitNamedPipeW;
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    CreateEventW, SetEvent, WaitForMultipleObjects, WaitForSingleObject,
};
#[cfg(windows)]
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

use utils::eventfd::EventFd;
#[cfg(any(unix, windows))]
use utils::eventfd::EFD_NONBLOCK;
#[cfg(unix)]
use vm_memory::bitmap::Bitmap;
use vm_memory::{VolatileSlice, WriteVolatile};

#[cfg(windows)]
const INFINITE_TIMEOUT_MS: u32 = u32::MAX;
#[cfg(windows)]
const PIPE_BUSY_RETRIES: usize = 10;
#[cfg(windows)]
const PIPE_CONNECT_TIMEOUT_MS: u32 = 5000;
#[cfg(windows)]
const PIPE_BUFFER_SIZE: usize = 4096;

pub trait PortInput {
    fn read_volatile(&mut self, buf: &mut VolatileSlice) -> Result<usize, io::Error>;

    fn wait_until_readable(&self, stopfd: Option<&EventFd>);
}

pub trait PortOutput {
    fn write_volatile(&mut self, buf: &VolatileSlice) -> Result<usize, io::Error>;

    fn wait_until_writable(&self);
}

/// Terminal properties associated with this port
pub trait PortTerminalProperties: Send + Sync {
    fn get_win_size(&self) -> (u16, u16);
}

#[cfg(unix)]
pub fn stdin() -> Result<Box<dyn PortInput + Send>, nix::Error> {
    let fd = dup_raw_fd_into_owned(STDIN_FILENO)?;
    make_non_blocking(&fd)?;
    Ok(Box::new(PortInputFd(fd)))
}

#[cfg(windows)]
pub fn stdin() -> io::Result<Box<dyn PortInput + Send>> {
    input_empty()
}

#[cfg(unix)]
pub fn input_to_raw_fd_dup(fd: RawFd) -> Result<Box<dyn PortInput + Send>, nix::Error> {
    let fd = dup_raw_fd_into_owned(fd)?;
    make_non_blocking(&fd)?;
    Ok(Box::new(PortInputFd(fd)))
}

#[cfg(unix)]
pub fn stdout() -> Result<Box<dyn PortOutput + Send>, nix::Error> {
    output_to_raw_fd_dup(STDOUT_FILENO)
}

#[cfg(windows)]
pub fn stdout() -> io::Result<Box<dyn PortOutput + Send>> {
    Ok(Box::new(PortOutputStdout))
}

#[cfg(unix)]
pub fn stderr() -> Result<Box<dyn PortOutput + Send>, nix::Error> {
    output_to_raw_fd_dup(STDERR_FILENO)
}

#[cfg(windows)]
pub fn stderr() -> io::Result<Box<dyn PortOutput + Send>> {
    Ok(Box::new(PortOutputStderr))
}

#[cfg(unix)]
pub fn term_fd(
    term_fd: RawFd,
) -> Result<Box<dyn PortTerminalProperties + Send + Sync>, nix::Error> {
    let fd = dup_raw_fd_into_owned(term_fd)?;
    assert!(
        isatty(&fd).is_ok_and(|v| v),
        "Expected fd {fd:?}, to be a tty, to query the window size!"
    );
    Ok(Box::new(PortTerminalPropertiesFd(fd)))
}

pub fn term_fixed_size(width: u16, height: u16) -> Box<dyn PortTerminalProperties + Send + Sync> {
    Box::new(PortTerminalPropertiesFixed((width, height)))
}

#[cfg(unix)]
pub fn input_empty() -> Result<Box<dyn PortInput + Send>, nix::Error> {
    Ok(Box::new(PortInputEmpty {}))
}

#[cfg(windows)]
pub fn input_empty() -> io::Result<Box<dyn PortInput + Send>> {
    Ok(Box::new(PortInputEmpty {}))
}

#[cfg(unix)]
pub fn output_file(file: File) -> Result<Box<dyn PortOutput + Send>, nix::Error> {
    output_to_raw_fd_dup(file.as_raw_fd())
}

#[cfg(windows)]
pub fn output_file(file: File) -> io::Result<Box<dyn PortOutput + Send>> {
    Ok(Box::new(PortOutputFile(file)))
}

#[cfg(windows)]
pub fn named_pipe(
    name: &str,
) -> io::Result<(Box<dyn PortInput + Send>, Box<dyn PortOutput + Send>)> {
    let handle = Arc::new(open_byte_pipe(name)?);
    let rx_queue = Arc::new(Mutex::new(VecDeque::new()));
    let rx_error = Arc::new(Mutex::new(None));
    let rx_closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let rx_event = Arc::new(EventFd::new(EFD_NONBLOCK)?);
    let stop_event = Arc::new(create_event()?);

    let reader = spawn_named_pipe_reader(
        Arc::clone(&handle),
        Arc::clone(&rx_queue),
        Arc::clone(&rx_error),
        Arc::clone(&rx_closed),
        Arc::clone(&rx_event),
        Arc::clone(&stop_event),
    );

    Ok((
        Box::new(PortInputNamedPipe {
            handle: Arc::clone(&handle),
            rx_queue,
            rx_error,
            rx_closed,
            rx_event,
            stop_event,
            reader: Some(reader),
        }),
        Box::new(PortOutputNamedPipe { handle }),
    ))
}

#[cfg(unix)]
pub fn output_to_raw_fd_dup(fd: RawFd) -> Result<Box<dyn PortOutput + Send>, nix::Error> {
    let fd = dup_raw_fd_into_owned(fd)?;
    make_non_blocking(&fd)?;
    Ok(Box::new(PortOutputFd(fd)))
}

pub fn output_to_log_as_err() -> Box<dyn PortOutput + Send> {
    Box::new(PortOutputLog::new())
}

#[cfg(unix)]
struct PortInputFd(OwnedFd);

#[cfg(unix)]
impl AsRawFd for PortInputFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

#[cfg(unix)]
impl PortInput for PortInputFd {
    fn read_volatile(&mut self, buf: &mut VolatileSlice) -> io::Result<usize> {
        // This source code is copied from vm-memory, except it fixes an issue, where
        // the original code does not handle EWOULDBLOCK.

        let fd = self.as_raw_fd();
        let guard = buf.ptr_guard_mut();

        let dst = guard.as_ptr().cast::<libc::c_void>();

        // SAFETY: We got a valid file descriptor from `AsRawFd`. The memory pointed to by `dst` is
        // valid for writes of length `buf.len()` by the invariants upheld by the constructor
        // of `VolatileSlice`.
        let bytes_read = unsafe { libc::read(fd, dst, buf.len()) };

        if bytes_read < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() != ErrorKind::WouldBlock {
                // We don't know if a partial read might have happened, so mark everything as dirty.
                buf.bitmap().mark_dirty(0, buf.len());
            }

            Err(err)
        } else {
            let bytes_read = bytes_read.try_into().unwrap();
            buf.bitmap().mark_dirty(0, bytes_read);
            Ok(bytes_read)
        }
    }

    fn wait_until_readable(&self, stopfd: Option<&EventFd>) {
        let mut poll_fds = Vec::new();
        poll_fds.push(PollFd::new(self.0.as_fd(), PollFlags::POLLIN));
        if let Some(stopfd) = stopfd {
            // SAFETY: we trust stopfd won't go away to avoid a dup call here.
            let borrowed_fd = unsafe { BorrowedFd::borrow_raw(stopfd.as_raw_fd()) };
            poll_fds.push(PollFd::new(borrowed_fd, PollFlags::POLLIN));
        }
        poll(&mut poll_fds, PollTimeout::NONE).expect("Failed to poll");
    }
}

#[cfg(unix)]
struct PortOutputFd(OwnedFd);

#[cfg(unix)]
impl AsRawFd for PortOutputFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

#[cfg(unix)]
impl PortOutput for PortOutputFd {
    fn write_volatile(&mut self, buf: &VolatileSlice) -> Result<usize, io::Error> {
        let fd = self.as_raw_fd();
        let guard = buf.ptr_guard();
        let src = guard.as_ptr().cast::<libc::c_void>();

        // SAFETY: We got a valid file descriptor from `AsRawFd`. The memory pointed to by `src` is
        // valid for reads of length `buf.len()` by the invariants upheld by the constructor of
        // `VolatileSlice`.
        let bytes_written = unsafe { libc::write(fd, src, buf.len()) };

        if bytes_written < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(bytes_written.try_into().unwrap())
        }
    }

    fn wait_until_writable(&self) {
        let mut poll_fds = [PollFd::new(self.0.as_fd(), PollFlags::POLLOUT)];
        poll(&mut poll_fds, PollTimeout::NONE).expect("Failed to poll");
    }
}

#[cfg(windows)]
struct PortOutputFile(File);

#[cfg(windows)]
struct PortOutputStdout;

#[cfg(windows)]
struct PortOutputStderr;

#[cfg(windows)]
struct PortInputNamedPipe {
    handle: Arc<OwnedHandle>,
    rx_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    rx_error: Arc<Mutex<Option<io::Error>>>,
    rx_closed: Arc<std::sync::atomic::AtomicBool>,
    rx_event: Arc<EventFd>,
    stop_event: Arc<OwnedHandle>,
    reader: Option<thread::JoinHandle<()>>,
}

#[cfg(windows)]
struct PortOutputNamedPipe {
    handle: Arc<OwnedHandle>,
}

#[cfg(windows)]
impl PortOutput for PortOutputFile {
    fn write_volatile(&mut self, buf: &VolatileSlice) -> Result<usize, io::Error> {
        write_volatile_to_writer(&mut self.0, buf)
    }

    fn wait_until_writable(&self) {}
}

#[cfg(windows)]
impl PortOutput for PortOutputStdout {
    fn write_volatile(&mut self, buf: &VolatileSlice) -> Result<usize, io::Error> {
        let mut stdout = io::stdout().lock();
        write_volatile_to_writer(&mut stdout, buf)
    }

    fn wait_until_writable(&self) {}
}

#[cfg(windows)]
impl PortOutput for PortOutputStderr {
    fn write_volatile(&mut self, buf: &VolatileSlice) -> Result<usize, io::Error> {
        let mut stderr = io::stderr().lock();
        write_volatile_to_writer(&mut stderr, buf)
    }

    fn wait_until_writable(&self) {}
}

#[cfg(windows)]
impl PortInput for PortInputNamedPipe {
    fn read_volatile(&mut self, buf: &mut VolatileSlice) -> Result<usize, io::Error> {
        let mut rx_queue = self.rx_queue.lock().unwrap();

        if let Some(front) = rx_queue.front_mut() {
            let len = front.len().min(buf.len());
            buf.copy_from(&front[..len]);
            if len == front.len() {
                rx_queue.pop_front();
            } else {
                front.drain(..len);
            }

            if rx_queue.is_empty() {
                drain_named_pipe_event(&self.rx_event);
            }

            return Ok(len);
        }

        drain_named_pipe_event(&self.rx_event);
        drop(rx_queue);

        if let Some(err) = self.rx_error.lock().unwrap().take() {
            return Err(err);
        }

        if self.rx_closed.load(std::sync::atomic::Ordering::Acquire) {
            return Ok(0);
        }

        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "named-pipe console input is not ready",
        ))
    }

    fn wait_until_readable(&self, stopfd: Option<&EventFd>) {
        if named_pipe_input_ready(&self.rx_queue, &self.rx_error, &self.rx_closed) {
            return;
        }

        wait_for_named_pipe_input(&self.rx_event, stopfd);
    }
}

#[cfg(windows)]
impl Drop for PortInputNamedPipe {
    fn drop(&mut self) {
        let _ = unsafe { SetEvent(self.stop_event.as_raw_handle() as HANDLE) };
        let _ = unsafe { CancelIoEx(self.handle.as_raw_handle() as HANDLE, ptr::null()) };
        if let Some(reader) = self.reader.take() {
            if let Err(err) = reader.join() {
                log::warn!("named-pipe console reader thread panicked: {err:?}");
            }
        }
    }
}

#[cfg(windows)]
impl PortOutput for PortOutputNamedPipe {
    fn write_volatile(&mut self, buf: &VolatileSlice) -> Result<usize, io::Error> {
        let guard = buf.ptr_guard();

        // SAFETY: The VolatileSlice invariant guarantees the memory region is valid for reads of
        // `buf.len()` bytes for the lifetime of the guard.
        let src = unsafe { std::slice::from_raw_parts(guard.as_ptr(), buf.len()) };
        let written = overlapped_write(self.handle.as_raw_handle() as HANDLE, src)?;
        if written as usize != src.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "named-pipe console output completed with a short write",
            ));
        }

        Ok(src.len())
    }

    fn wait_until_writable(&self) {}
}

#[cfg(windows)]
fn write_volatile_to_writer(
    writer: &mut impl Write,
    buf: &VolatileSlice,
) -> Result<usize, io::Error> {
    let guard = buf.ptr_guard();

    // SAFETY: The VolatileSlice invariant guarantees the memory region is valid for reads of
    // `buf.len()` bytes for the lifetime of the guard.
    let src = unsafe { std::slice::from_raw_parts(guard.as_ptr(), buf.len()) };
    writer.write_all(src)?;
    writer.flush()?;
    Ok(src.len())
}

#[cfg(windows)]
fn open_byte_pipe(name: &str) -> io::Result<OwnedHandle> {
    let wide_name = wide_null(name);

    for _ in 0..PIPE_BUSY_RETRIES {
        let handle = unsafe {
            CreateFileW(
                wide_name.as_ptr(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                ptr::null_mut(),
            )
        };

        if handle != INVALID_HANDLE_VALUE {
            return Ok(unsafe { OwnedHandle::from_raw_handle(handle as _) });
        }

        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(ERROR_PIPE_BUSY as i32) {
            return Err(err);
        }

        let ok = unsafe { WaitNamedPipeW(wide_name.as_ptr(), PIPE_CONNECT_TIMEOUT_MS) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
    }

    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "named-pipe console server stayed busy",
    ))
}

#[cfg(windows)]
fn spawn_named_pipe_reader(
    handle: Arc<OwnedHandle>,
    rx_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    rx_error: Arc<Mutex<Option<io::Error>>>,
    rx_closed: Arc<std::sync::atomic::AtomicBool>,
    rx_event: Arc<EventFd>,
    stop_event: Arc<OwnedHandle>,
) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("virtio-console named-pipe reader".to_string())
        .spawn(move || {
            read_named_pipe_bytes(handle, rx_queue, rx_error, rx_closed, rx_event, stop_event)
        })
        .expect("failed to spawn virtio-console named-pipe reader")
}

#[cfg(windows)]
fn read_named_pipe_bytes(
    handle: Arc<OwnedHandle>,
    rx_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    rx_error: Arc<Mutex<Option<io::Error>>>,
    rx_closed: Arc<std::sync::atomic::AtomicBool>,
    rx_event: Arc<EventFd>,
    stop_event: Arc<OwnedHandle>,
) {
    loop {
        let mut buf = vec![0u8; PIPE_BUFFER_SIZE];
        match overlapped_read_cancelable(
            handle.as_raw_handle() as HANDLE,
            stop_event.as_raw_handle() as HANDLE,
            &mut buf,
        ) {
            Ok(Some(0)) => continue,
            Ok(Some(bytes_read)) => {
                buf.truncate(bytes_read as usize);
                rx_queue.lock().unwrap().push_back(buf);
                wake_named_pipe_event(&rx_event);
            }
            Ok(None) => break,
            Err(err) => {
                if is_pipe_closed(&err) {
                    rx_closed.store(true, std::sync::atomic::Ordering::Release);
                } else if err.raw_os_error() != Some(ERROR_OPERATION_ABORTED as i32) {
                    *rx_error.lock().unwrap() = Some(err);
                }
                wake_named_pipe_event(&rx_event);
                break;
            }
        }
    }
}

#[cfg(windows)]
fn overlapped_read_cancelable(
    handle: HANDLE,
    stop_event: HANDLE,
    buf: &mut [u8],
) -> io::Result<Option<u32>> {
    let mut operation = OverlappedOperation::new()?;
    let ok = unsafe {
        ReadFile(
            handle,
            buf.as_mut_ptr(),
            buf.len() as u32,
            ptr::null_mut(),
            operation.overlapped_mut(),
        )
    };

    if ok != 0 {
        return operation.finish_now(handle).map(Some);
    }

    let err = io::Error::last_os_error();
    if err.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
        return Err(err);
    }

    let handles = [operation.event_handle(), stop_event];
    let result =
        unsafe { WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), FALSE, u32::MAX) };

    if result == WAIT_OBJECT_0 {
        return operation.finish_now(handle).map(Some);
    }

    if result == WAIT_OBJECT_0 + 1 {
        let _ = unsafe { CancelIoEx(handle, operation.overlapped_ptr()) };
        let _ = operation.finish_wait(handle);
        return Ok(None);
    }

    if result == WAIT_FAILED {
        return Err(io::Error::last_os_error());
    }

    Err(io::Error::last_os_error())
}

#[cfg(windows)]
fn overlapped_write(handle: HANDLE, buf: &[u8]) -> io::Result<u32> {
    let mut operation = OverlappedOperation::new()?;
    let ok = unsafe {
        WriteFile(
            handle,
            buf.as_ptr(),
            buf.len() as u32,
            ptr::null_mut(),
            operation.overlapped_mut(),
        )
    };

    if ok != 0 {
        return operation.finish_now(handle);
    }

    let err = io::Error::last_os_error();
    if err.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
        return Err(err);
    }

    operation.finish_wait(handle)
}

#[cfg(windows)]
struct OverlappedOperation {
    overlapped: OVERLAPPED,
    _event: OwnedHandle,
}

#[cfg(windows)]
impl OverlappedOperation {
    fn new() -> io::Result<Self> {
        let event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
        if event.is_null() {
            return Err(io::Error::last_os_error());
        }

        let event = unsafe { OwnedHandle::from_raw_handle(event as _) };
        let overlapped = OVERLAPPED {
            hEvent: event.as_raw_handle() as HANDLE,
            ..Default::default()
        };

        Ok(Self {
            overlapped,
            _event: event,
        })
    }

    fn event_handle(&self) -> HANDLE {
        self._event.as_raw_handle() as HANDLE
    }

    fn overlapped_mut(&mut self) -> *mut OVERLAPPED {
        &mut self.overlapped
    }

    fn overlapped_ptr(&self) -> *const OVERLAPPED {
        &self.overlapped
    }

    fn finish_now(&mut self, handle: HANDLE) -> io::Result<u32> {
        let mut bytes_transferred = 0;
        let ok =
            unsafe { GetOverlappedResult(handle, &self.overlapped, &mut bytes_transferred, 0) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(bytes_transferred)
    }

    fn finish_wait(&mut self, handle: HANDLE) -> io::Result<u32> {
        let mut bytes_transferred = 0;
        let ok =
            unsafe { GetOverlappedResult(handle, &self.overlapped, &mut bytes_transferred, 1) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(bytes_transferred)
    }
}

#[cfg(windows)]
fn named_pipe_input_ready(
    rx_queue: &Mutex<VecDeque<Vec<u8>>>,
    rx_error: &Mutex<Option<io::Error>>,
    rx_closed: &std::sync::atomic::AtomicBool,
) -> bool {
    !rx_queue.lock().unwrap().is_empty()
        || rx_error.lock().unwrap().is_some()
        || rx_closed.load(std::sync::atomic::Ordering::Acquire)
}

#[cfg(windows)]
fn wait_for_named_pipe_input(rx_event: &EventFd, stopfd: Option<&EventFd>) {
    let rx_handle = rx_event.as_raw_handle() as HANDLE;
    let result = if let Some(stopfd) = stopfd {
        let handles = [rx_handle, stopfd.as_raw_handle() as HANDLE];
        unsafe { WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), FALSE, u32::MAX) }
    } else {
        unsafe { WaitForSingleObject(rx_handle, INFINITE_TIMEOUT_MS) }
    };

    if result == WAIT_FAILED {
        log::error!(
            "Failed to wait for named-pipe console input: {}",
            io::Error::last_os_error()
        );
    }
}

#[cfg(windows)]
fn drain_named_pipe_event(rx_event: &EventFd) {
    match rx_event.read() {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
        Err(err) => log::warn!("failed to drain named-pipe console event: {err}"),
    }
}

#[cfg(windows)]
fn wake_named_pipe_event(rx_event: &EventFd) {
    if let Err(err) = rx_event.write(1) {
        if err.kind() != io::ErrorKind::WouldBlock {
            log::warn!("failed to wake named-pipe console event: {err}");
        }
    }
}

#[cfg(windows)]
fn is_pipe_closed(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(code)
            if code == ERROR_BROKEN_PIPE as i32
                || code == ERROR_NO_DATA as i32
                || code == ERROR_PIPE_NOT_CONNECTED as i32
    )
}

#[cfg(windows)]
fn create_event() -> io::Result<OwnedHandle> {
    let event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    if event.is_null() {
        return Err(io::Error::last_os_error());
    }

    Ok(unsafe { OwnedHandle::from_raw_handle(event as _) })
}

#[cfg(windows)]
fn wide_null(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(Some(0)).collect()
}

//--------------------------------------------------------------------------------------------------
// Types: Custom Console Port Backend Adapters
//--------------------------------------------------------------------------------------------------

/// Trait for custom virtio-console port backends.
///
/// Implementors provide bidirectional byte I/O between the host and guest without going through file descriptors on the data path. The console device's RX thread calls [`read`](Self::read) and the TX thread calls [`write`](Self::write) -- both via `&self`, so the implementation must use interior mutability, for example lock-free ring buffers.
///
/// [`read_wake_fd`](Self::read_wake_fd) returns a file descriptor that becomes readable when [`read`](Self::read) would return data. The console RX thread uses this fd in a `poll()` call to block efficiently.
#[cfg(unix)]
pub trait ConsolePortBackend: Send + Sync {
    /// Read bytes destined for the guest (host -> guest direction).
    ///
    /// Copies up to `buf.len()` bytes into `buf`. Returns the number of bytes written, or `WouldBlock` if no data is available.
    fn read(&self, buf: &mut [u8]) -> io::Result<usize>;

    /// Write bytes from the guest (guest -> host direction).
    ///
    /// Accepts up to `buf.len()` bytes. Returns the number of bytes consumed, or `WouldBlock` if the backend cannot accept data.
    fn write(&self, buf: &[u8]) -> io::Result<usize>;

    /// File descriptor that becomes readable when [`read`](Self::read) has data.
    ///
    /// Used by the console RX thread for `poll()`-based blocking. Typically the read end of a wake pipe.
    fn read_wake_fd(&self) -> RawFd;

    /// Wait until [`write`](Self::write) may accept more guest bytes.
    ///
    /// The default is intentionally inert for compatibility with existing backends. Bounded
    /// backends should override this hook so a full output buffer blocks instead of busy-spinning.
    fn wait_until_writable(&self) {}
}

/// Adapter that wraps a [`ConsolePortBackend`] as a [`PortInput`].
///
/// Used by the console RX thread to read data from the backend into guest memory via VolatileSlice.
#[cfg(unix)]
pub struct ConsolePortBackendInputAdapter {
    backend: Arc<dyn ConsolePortBackend>,
}

#[cfg(unix)]
impl ConsolePortBackendInputAdapter {
    pub fn new(backend: Arc<dyn ConsolePortBackend>) -> Self {
        Self { backend }
    }
}

#[cfg(unix)]
impl PortInput for ConsolePortBackendInputAdapter {
    fn read_volatile(&mut self, buf: &mut VolatileSlice) -> io::Result<usize> {
        let guard = buf.ptr_guard_mut();

        // SAFETY: The VolatileSlice invariant guarantees the memory region is
        // valid for writes of `buf.len()` bytes for the lifetime of the guard.
        let dst = unsafe { std::slice::from_raw_parts_mut(guard.as_ptr(), buf.len()) };

        let n = self.backend.read(dst)?;

        if n > 0 {
            buf.bitmap().mark_dirty(0, n);
        }

        Ok(n)
    }

    fn wait_until_readable(&self, stopfd: Option<&EventFd>) {
        let wake_fd = self.backend.read_wake_fd();
        let mut poll_fds = Vec::with_capacity(2);
        let wake_bfd = unsafe { BorrowedFd::borrow_raw(wake_fd) };
        poll_fds.push(PollFd::new(wake_bfd, PollFlags::POLLIN));
        if let Some(stopfd) = stopfd {
            let stop_bfd = unsafe { BorrowedFd::borrow_raw(stopfd.as_raw_fd()) };
            poll_fds.push(PollFd::new(stop_bfd, PollFlags::POLLIN));
        }
        poll(&mut poll_fds, PollTimeout::NONE).expect("Failed to poll");
    }
}

/// Adapter that wraps a [`ConsolePortBackend`] as a [`PortOutput`].
///
/// Used by the console TX thread to write guest data to the backend.
#[cfg(unix)]
pub struct ConsolePortBackendOutputAdapter {
    backend: Arc<dyn ConsolePortBackend>,
}

#[cfg(unix)]
impl ConsolePortBackendOutputAdapter {
    pub fn new(backend: Arc<dyn ConsolePortBackend>) -> Self {
        Self { backend }
    }
}

#[cfg(unix)]
impl PortOutput for ConsolePortBackendOutputAdapter {
    fn write_volatile(&mut self, buf: &VolatileSlice) -> io::Result<usize> {
        let guard = buf.ptr_guard();

        // SAFETY: The VolatileSlice invariant guarantees the memory region is
        // valid for reads of `buf.len()` bytes for the lifetime of the guard.
        let src = unsafe { std::slice::from_raw_parts(guard.as_ptr(), buf.len()) };

        self.backend.write(src)
    }

    fn wait_until_writable(&self) {
        self.backend.wait_until_writable();
    }
}

#[cfg(unix)]
fn dup_raw_fd_into_owned(raw_fd: RawFd) -> Result<OwnedFd, nix::Error> {
    // SAFETY: if raw_fd is invalid the `dup` call below will fail.
    let borrowed_fd = unsafe { BorrowedFd::borrow_raw(raw_fd) };
    let fd = dup(borrowed_fd)?;
    Ok(fd)
}

#[cfg(unix)]
fn make_non_blocking(as_rw_fd: &impl AsRawFd) -> Result<(), nix::Error> {
    let fd = as_rw_fd.as_raw_fd();
    unsafe {
        let flags = fcntl(fd, F_GETFL, 0);
        if flags < 0 {
            return Err(Errno::last());
        }

        if fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 {
            return Err(Errno::last());
        }
    }
    Ok(())
}

// Utility to relay log from the VM (the kernel boot log and messages from init)
// to the rust log.
#[derive(Default)]
pub struct PortOutputLog {
    buf: Vec<u8>,
}

impl PortOutputLog {
    const FORCE_FLUSH_TRESHOLD: usize = 512;
    const LOG_TARGET: &'static str = "init_or_kernel";

    fn new() -> Self {
        Self::default()
    }

    fn force_flush(&mut self) {
        log::log!(target: PortOutputLog::LOG_TARGET, Level::Error, "[missing newline]{}", String::from_utf8_lossy(&self.buf));
        self.buf.clear();
    }
}

impl PortOutput for PortOutputLog {
    fn write_volatile(&mut self, buf: &VolatileSlice) -> Result<usize, io::Error> {
        self.buf.write_volatile(buf).map_err(io::Error::other)?;

        let mut start = 0;
        for (i, ch) in self.buf.iter().cloned().enumerate() {
            if ch == b'\n' {
                log::log!(target: PortOutputLog::LOG_TARGET, Level::Error, "{}", String::from_utf8_lossy(&self.buf[start..i]));
                start = i + 1;
            }
        }
        self.buf.drain(0..start);
        // Make sure to not grow the internal buffer forever.
        if self.buf.len() > PortOutputLog::FORCE_FLUSH_TRESHOLD {
            self.force_flush()
        }
        Ok(buf.len())
    }

    fn wait_until_writable(&self) {}
}

#[cfg(unix)]
pub struct PortInputSigInt {
    sigint_evt: EventFd,
}

#[cfg(unix)]
impl PortInputSigInt {
    pub fn new() -> Self {
        PortInputSigInt {
            sigint_evt: EventFd::new(EFD_NONBLOCK)
                .expect("Failed to create EventFd for SIGINT signaling"),
        }
    }

    pub fn sigint_evt(&self) -> &EventFd {
        &self.sigint_evt
    }
}

#[cfg(unix)]
impl Default for PortInputSigInt {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(unix)]
impl PortInput for PortInputSigInt {
    fn read_volatile(&mut self, buf: &mut VolatileSlice) -> Result<usize, io::Error> {
        self.sigint_evt.read()?;
        log::trace!("SIGINT received");
        buf.copy_from(&[3u8]);
        Ok(1)
    }

    fn wait_until_readable(&self, stopfd: Option<&EventFd>) {
        let mut poll_fds = Vec::with_capacity(2);
        // SAFETY: we trust sigint_evt won't go away to avoid a dup call here.
        let sigint_bfd = unsafe { BorrowedFd::borrow_raw(self.sigint_evt.as_raw_fd()) };
        poll_fds.push(PollFd::new(sigint_bfd, PollFlags::POLLIN));
        if let Some(stopfd) = stopfd {
            // SAFETY: we trust stopfd won't go away to avoid a dup call here.
            let stop_bfd = unsafe { BorrowedFd::borrow_raw(stopfd.as_raw_fd()) };
            poll_fds.push(PollFd::new(stop_bfd, PollFlags::POLLIN));
        }

        poll(&mut poll_fds, PollTimeout::NONE).expect("Failed to poll");
    }
}

pub struct PortInputEmpty {}

impl PortInputEmpty {
    pub fn new() -> Self {
        PortInputEmpty {}
    }
}

impl Default for PortInputEmpty {
    fn default() -> Self {
        Self::new()
    }
}

impl PortInput for PortInputEmpty {
    fn read_volatile(&mut self, _buf: &mut VolatileSlice) -> Result<usize, io::Error> {
        Ok(0)
    }

    fn wait_until_readable(&self, stopfd: Option<&EventFd>) {
        wait_for_stopfd_or_forever(stopfd)
    }
}

#[cfg(unix)]
fn wait_for_stopfd_or_forever(stopfd: Option<&EventFd>) {
    if let Some(stopfd) = stopfd {
        // SAFETY: we trust stopfd won't go away to avoid a dup call here.
        let borrowed_fd = unsafe { BorrowedFd::borrow_raw(stopfd.as_raw_fd()) };
        let mut poll_fds = [PollFd::new(borrowed_fd, PollFlags::POLLIN)];
        poll(&mut poll_fds, PollTimeout::NONE).expect("Failed to poll");
    } else {
        std::thread::sleep(std::time::Duration::MAX);
    }
}

#[cfg(windows)]
fn wait_for_stopfd_or_forever(stopfd: Option<&EventFd>) {
    if let Some(stopfd) = stopfd {
        let result =
            unsafe { WaitForSingleObject(stopfd.as_raw_handle() as HANDLE, INFINITE_TIMEOUT_MS) };
        match result {
            WAIT_OBJECT_0 => {
                let _ = stopfd.read();
            }
            WAIT_FAILED => {
                log::error!(
                    "Failed to wait for console stop event: {}",
                    io::Error::last_os_error()
                );
            }
            _ => {}
        }
    } else {
        std::thread::sleep(Duration::MAX);
    }
}

struct PortTerminalPropertiesFixed((u16, u16));

impl PortTerminalProperties for PortTerminalPropertiesFixed {
    fn get_win_size(&self) -> (u16, u16) {
        self.0
    }
}

#[cfg(unix)]
struct PortTerminalPropertiesFd(OwnedFd);

#[cfg(unix)]
impl PortTerminalProperties for PortTerminalPropertiesFd {
    fn get_win_size(&self) -> (u16, u16) {
        let mut ws: WS = WS::default();

        if let Err(err) = unsafe { tiocgwinsz(self.0.as_raw_fd(), &mut ws) } {
            error!("Couldn't get terminal dimensions: {err}");
            return (0, 0);
        }
        (ws.cols, ws.rows)
    }
}

#[cfg(unix)]
#[repr(C)]
#[derive(Default)]
struct WS {
    rows: u16,
    cols: u16,
    xpixel: u16,
    ypixel: u16,
}

#[cfg(unix)]
ioctl_read_bad!(tiocgwinsz, TIOCGWINSZ, WS);

#[cfg(all(test, unix))]
mod unix_tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};

    struct WritableWaitBackend {
        waits: Arc<AtomicUsize>,
    }

    impl ConsolePortBackend for WritableWaitBackend {
        fn read(&self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::WouldBlock.into())
        }

        fn write(&self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::WouldBlock.into())
        }

        fn read_wake_fd(&self) -> RawFd {
            -1
        }

        fn wait_until_writable(&self) {
            self.waits.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn custom_output_adapter_delegates_writable_wait() {
        let waits = Arc::new(AtomicUsize::new(0));
        let backend: Arc<dyn ConsolePortBackend> = Arc::new(WritableWaitBackend {
            waits: Arc::clone(&waits),
        });
        let adapter = ConsolePortBackendOutputAdapter::new(backend);

        PortOutput::wait_until_writable(&adapter);

        assert_eq!(waits.load(Ordering::Relaxed), 1);
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    use std::fs::OpenOptions;
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    use vm_memory::{Bytes, GuestAddress, GuestMemoryBackend, GuestMemoryMmap};
    use windows_sys::Win32::Foundation::ERROR_PIPE_CONNECTED;
    use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_UNLIMITED_INSTANCES,
        PIPE_WAIT,
    };

    #[test]
    fn windows_input_empty_returns_eof() {
        let mem: GuestMemoryMmap<()> =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let mut slice = mem.get_slice(GuestAddress(0x100), 16).unwrap();
        let mut input = input_empty().unwrap();

        assert_eq!(input.read_volatile(&mut slice).unwrap(), 0);
    }

    #[test]
    fn windows_output_file_writes_volatile_slice() {
        let payload = b"windows virtio console output\n";
        let path = temp_path("output-file");
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mem: GuestMemoryMmap<()> =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        mem.write(payload, GuestAddress(0x100)).unwrap();
        let source = mem.get_slice(GuestAddress(0x100), payload.len()).unwrap();

        let mut output = output_file(file).unwrap();
        assert_eq!(output.write_volatile(&source).unwrap(), payload.len());
        drop(output);

        let contents = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(contents, payload);
    }

    #[test]
    fn windows_named_pipe_exchanges_bytes() {
        let pipe_name = unique_pipe_name();
        let helper_to_guest = b"from helper to guest\n".to_vec();
        let guest_to_helper = b"from guest to helper\n".to_vec();
        let (server_ready, server) = spawn_byte_pipe_server(
            pipe_name.clone(),
            helper_to_guest.clone(),
            guest_to_helper.clone(),
        );

        server_ready
            .recv_timeout(Duration::from_secs(2))
            .expect("named-pipe server did not start")
            .expect("named-pipe server failed to start");

        let (mut input, mut output) = named_pipe(&pipe_name).unwrap();

        let mem: GuestMemoryMmap<()> =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let mut input_slice = mem
            .get_slice(GuestAddress(0x100), helper_to_guest.len())
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(2);
        let bytes_read = loop {
            match input.read_volatile(&mut input_slice) {
                Ok(n) => break n,
                Err(err)
                    if err.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(err) => panic!("failed to read named-pipe console input: {err}"),
            }
        };
        assert_eq!(bytes_read, helper_to_guest.len());

        let mut received = vec![0u8; helper_to_guest.len()];
        mem.read_slice(&mut received, GuestAddress(0x100)).unwrap();
        assert_eq!(received, helper_to_guest);

        mem.write(&guest_to_helper, GuestAddress(0x200)).unwrap();
        let output_slice = mem
            .get_slice(GuestAddress(0x200), guest_to_helper.len())
            .unwrap();
        assert_eq!(
            output.write_volatile(&output_slice).unwrap(),
            guest_to_helper.len()
        );

        drop(input);
        drop(output);

        server
            .join()
            .expect("named-pipe server thread panicked")
            .expect("named-pipe server failed");
    }

    fn spawn_byte_pipe_server(
        name: String,
        initial_write: Vec<u8>,
        expected_read: Vec<u8>,
    ) -> (
        mpsc::Receiver<io::Result<()>>,
        thread::JoinHandle<io::Result<()>>,
    ) {
        let (ready_tx, ready_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let wide_name = wide_null(&name);
            let handle = unsafe {
                CreateNamedPipeW(
                    wide_name.as_ptr(),
                    PIPE_ACCESS_DUPLEX,
                    PIPE_WAIT,
                    PIPE_UNLIMITED_INSTANCES,
                    PIPE_BUFFER_SIZE as u32,
                    PIPE_BUFFER_SIZE as u32,
                    0,
                    ptr::null(),
                )
            };

            if handle == INVALID_HANDLE_VALUE {
                let err = io::Error::last_os_error();
                let _ = ready_tx.send(Err(io::Error::new(err.kind(), err.to_string())));
                return Err(err);
            }

            let handle = unsafe { OwnedHandle::from_raw_handle(handle as _) };
            ready_tx.send(Ok(())).unwrap();

            let connected =
                unsafe { ConnectNamedPipe(handle.as_raw_handle() as HANDLE, ptr::null_mut()) };
            if connected == 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() != Some(ERROR_PIPE_CONNECTED as i32) {
                    return Err(err);
                }
            }

            write_all_to_pipe(handle.as_raw_handle() as HANDLE, &initial_write)?;
            let actual_read =
                read_exact_from_pipe(handle.as_raw_handle() as HANDLE, expected_read.len())?;
            if actual_read != expected_read {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "named-pipe console server received unexpected bytes",
                ));
            }

            unsafe {
                DisconnectNamedPipe(handle.as_raw_handle() as HANDLE);
            }

            Ok(())
        });

        (ready_rx, server)
    }

    fn write_all_to_pipe(handle: HANDLE, mut bytes: &[u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            let mut bytes_written = 0;
            let ok = unsafe {
                WriteFile(
                    handle,
                    bytes.as_ptr(),
                    bytes.len() as u32,
                    &mut bytes_written,
                    ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }

            bytes = &bytes[bytes_written as usize..];
        }

        Ok(())
    }

    fn read_exact_from_pipe(handle: HANDLE, len: usize) -> io::Result<Vec<u8>> {
        let mut bytes = vec![0u8; len];
        let mut offset = 0;
        while offset < len {
            let mut bytes_read = 0;
            let ok = unsafe {
                ReadFile(
                    handle,
                    bytes[offset..].as_mut_ptr(),
                    (len - offset) as u32,
                    &mut bytes_read,
                    ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }

            offset += bytes_read as usize;
        }

        Ok(bytes)
    }

    fn temp_path(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "msb-krun-console-port-{}-{}-{suffix}.tmp",
            name,
            std::process::id()
        ))
    }

    fn unique_pipe_name() -> String {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        format!(r"\\.\pipe\msb-krun-console-test-{suffix}")
    }
}

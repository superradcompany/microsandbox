//! Windows console integration for interactive sessions.
//!
//! Owns the host console handles, virtual-terminal modes, and the input/resize
//! event pump shared by sandbox attach and SSH sessions.

use std::os::windows::io::AsRawHandle;
use std::{ptr, thread, time::Duration};

use tokio::sync::mpsc;
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
        WAIT_TIMEOUT,
    },
    Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING},
    System::{
        Console::{
            CONSOLE_SCREEN_BUFFER_INFO, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_MOUSE_INPUT,
            ENABLE_PROCESSED_INPUT, ENABLE_VIRTUAL_TERMINAL_INPUT,
            ENABLE_VIRTUAL_TERMINAL_PROCESSING, ENABLE_WINDOW_INPUT, GetConsoleMode,
            GetConsoleScreenBufferInfo, GetStdHandle, ReadConsoleW, STD_INPUT_HANDLE,
            STD_OUTPUT_HANDLE, SetConsoleMode, WriteConsoleW,
        },
        IO::CancelSynchronousIo,
        Threading::{CreateEventW, SetEvent, WaitForMultipleObjects},
    },
};

use crate::{MicrosandboxError, MicrosandboxResult};

use super::encoding::{
    MAX_CONSOLE_WRITE_UNITS, Utf8ToUtf16Decoder, Utf16ToUtf8Decoder,
    split_separates_surrogate_pair, surrogate_safe_split,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const TERMINAL_EVENT_POLL_INTERVAL: Duration = Duration::from_millis(100);
/// Console input buffer size, in UTF-16 units (not bytes) because input is
/// read with `ReadConsoleW`.
const TERMINAL_INPUT_BUFFER_UNITS: usize = 2048;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct ConsoleHandle {
    raw: HANDLE,
    owned: bool,
}

unsafe impl Send for ConsoleHandle {}

struct OwnedWindowsHandle(HANDLE);

unsafe impl Send for OwnedWindowsHandle {}

pub(crate) struct WindowsTerminalGuard {
    input: ConsoleHandle,
    output: ConsoleHandle,
    input_mode: u32,
    output_mode: u32,

    /// Carries an incomplete UTF-8 sequence between guest output frames.
    output_decoder: Utf8ToUtf16Decoder,
}

pub(crate) struct WindowsTerminalEventPump {
    stop: OwnedWindowsHandle,
    handle: Option<thread::JoinHandle<()>>,
    rx: mpsc::UnboundedReceiver<WindowsTerminalEvent>,
}

pub(crate) enum WindowsTerminalEvent {
    Input(Vec<u8>),
    Resize { cols: u16, rows: u16 },
    Error(String),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl WindowsTerminalGuard {
    pub(crate) fn enter() -> MicrosandboxResult<Self> {
        let (input, input_mode) = get_console_handle(STD_INPUT_HANDLE, "stdin")?;
        let (output, output_mode) = get_console_handle(STD_OUTPUT_HANDLE, "stdout")?;

        let mut guard = Self {
            input,
            output,
            input_mode,
            output_mode,
            output_decoder: Utf8ToUtf16Decoder::default(),
        };

        if let Err(error) = guard.enable_virtual_terminal_modes() {
            guard.restore();
            return Err(error);
        }

        Ok(guard)
    }

    fn enable_virtual_terminal_modes(&mut self) -> MicrosandboxResult<()> {
        let raw_input_mode = console_mode(&self.input, "stdin")?;
        let raw_output_mode = console_mode(&self.output, "stdout")?;

        let input_mode = (raw_input_mode | ENABLE_VIRTUAL_TERMINAL_INPUT)
            & !(ENABLE_LINE_INPUT
                | ENABLE_ECHO_INPUT
                | ENABLE_PROCESSED_INPUT
                | ENABLE_WINDOW_INPUT
                | ENABLE_MOUSE_INPUT);
        set_console_mode(&self.input, input_mode, "configure stdin")?;

        let output_mode = raw_output_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        set_console_mode(&self.output, output_mode, "configure stdout")?;

        Ok(())
    }

    fn restore(&mut self) {
        let _ = unsafe { SetConsoleMode(self.input.raw, self.input_mode) };
        let _ = unsafe { SetConsoleMode(self.output.raw, self.output_mode) };
    }

    /// Forward guest output to the console.
    ///
    /// Guest bytes are UTF-8, so they are decoded to UTF-16 and written with
    /// `WriteConsoleW`. The byte-oriented alternative (`WriteFile`, which the
    /// console treats as `WriteConsoleA`) would reinterpret them in the
    /// console's current code page and corrupt anything non-ASCII.
    ///
    /// A frame may end partway through a character, so the decoder keeps the
    /// incomplete tail and completes it from the next frame.
    pub(crate) fn write_output(&mut self, data: &[u8]) -> MicrosandboxResult<()> {
        let units = self.output_decoder.decode(data);
        self.write_console(&units)
    }

    /// Flush a trailing incomplete sequence when the session ends.
    pub(crate) fn finish_output(&mut self) -> MicrosandboxResult<()> {
        let units = self.output_decoder.finish();
        self.write_console(&units)
    }

    fn write_console(&self, units: &[u16]) -> MicrosandboxResult<()> {
        let mut offset = 0usize;
        while offset < units.len() {
            let chunk_len = surrogate_safe_split(&units[offset..], MAX_CONSOLE_WRITE_UNITS);
            let written = self.write_console_once(&units[offset..offset + chunk_len])?;
            offset += written;

            if written < chunk_len && split_separates_surrogate_pair(units, offset) {
                // A successful partial write can still stop after the high
                // half of a surrogate pair. Write its low half immediately,
                // matching Rust's Windows stdout recovery, before continuing.
                offset += self.write_console_once(&units[offset..offset + 1])?;
            }
        }

        Ok(())
    }

    fn write_console_once(&self, units: &[u16]) -> MicrosandboxResult<usize> {
        let mut written = 0u32;
        let result = unsafe {
            WriteConsoleW(
                self.output.raw,
                units.as_ptr(),
                units.len() as u32,
                &mut written,
                ptr::null(),
            )
        };
        if result == 0 {
            return Err(MicrosandboxError::Terminal(format!(
                "terminal output: {}",
                std::io::Error::last_os_error()
            )));
        }
        if written == 0 {
            // No progress would mean silently dropping the rest of the
            // guest's output; fail loudly instead.
            return Err(MicrosandboxError::Terminal(
                "terminal output: console accepted no characters".to_string(),
            ));
        }

        Ok(written as usize)
    }
}

impl Drop for WindowsTerminalGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

impl WindowsTerminalEventPump {
    pub(crate) fn spawn_for_guard(guard: &WindowsTerminalGuard) -> MicrosandboxResult<Self> {
        Self::spawn(guard.input.raw, guard.output.raw)
    }

    fn spawn(input: HANDLE, output: HANDLE) -> MicrosandboxResult<Self> {
        let (tx, rx) = mpsc::unbounded_channel();
        let stop = create_event("terminal stop")?;
        let input_handle = input as isize;
        let output_handle = output as isize;
        let stop_handle = stop.0 as isize;
        let handle = thread::spawn(move || {
            let input = input_handle as HANDLE;
            let output = output_handle as HANDLE;
            let stop_handle = stop_handle as HANDLE;
            let mut last_size = terminal_size_from_output(output);

            // Outside the loop: a surrogate pair can straddle two reads.
            let mut decoder = Utf16ToUtf8Decoder::default();
            let wait_handles = [input, stop_handle];
            let timeout_ms = TERMINAL_EVENT_POLL_INTERVAL.as_millis() as u32;

            loop {
                let wait_result = unsafe {
                    WaitForMultipleObjects(
                        wait_handles.len() as u32,
                        wait_handles.as_ptr(),
                        0,
                        timeout_ms,
                    )
                };

                if wait_result == WAIT_OBJECT_0 + 1 {
                    break;
                }

                if wait_result == WAIT_OBJECT_0 {
                    // `ReadConsoleW` rather than `ReadFile`, which the console
                    // treats as `ReadConsoleA` and so encodes typed text in the
                    // console's input code page instead of the UTF-8 the guest
                    // expects.
                    let mut input_buf = [0u16; TERMINAL_INPUT_BUFFER_UNITS];
                    let mut units_read = 0u32;
                    let result = unsafe {
                        ReadConsoleW(
                            input,
                            input_buf.as_mut_ptr().cast(),
                            input_buf.len() as u32,
                            &mut units_read,
                            ptr::null(),
                        )
                    };

                    if result == 0 {
                        let _ = tx.send(WindowsTerminalEvent::Error(format!(
                            "terminal input: {}",
                            std::io::Error::last_os_error()
                        )));
                        break;
                    }

                    if units_read == 0 {
                        break;
                    }

                    let data = decoder.decode(&input_buf[..units_read as usize]);

                    // A read that held nothing but a high surrogate yields no
                    // bytes yet; wait for its pair instead of sending nothing.
                    if !data.is_empty() && tx.send(WindowsTerminalEvent::Input(data)).is_err() {
                        break;
                    }
                } else if wait_result != WAIT_TIMEOUT {
                    let _ = tx.send(WindowsTerminalEvent::Error(format!(
                        "terminal wait: {}",
                        std::io::Error::last_os_error()
                    )));
                    break;
                }

                let size = terminal_size_from_output(output);
                if size != last_size {
                    last_size = size;
                    if let Some((cols, rows)) = size
                        && tx
                            .send(WindowsTerminalEvent::Resize { cols, rows })
                            .is_err()
                    {
                        break;
                    }
                }
            }
        });

        Ok(Self {
            stop,
            handle: Some(handle),
            rx,
        })
    }

    pub(crate) async fn recv(&mut self) -> Option<WindowsTerminalEvent> {
        self.rx.recv().await
    }
}

impl Drop for WindowsTerminalEventPump {
    fn drop(&mut self) {
        let _ = unsafe { SetEvent(self.stop.0) };
        if let Some(handle) = self.handle.take() {
            // The pump thread may already be blocked in a synchronous
            // console read. The stop event only prevents the next wait
            // from entering another read, so cancel the in-flight read
            // before joining or finite guest commands appear to hang
            // until the user presses another key.
            let _ = unsafe { CancelSynchronousIo(handle.as_raw_handle() as HANDLE) };
            let _ = handle.join();
        }
    }
}

impl ConsoleHandle {
    fn borrowed(raw: HANDLE) -> Self {
        Self { raw, owned: false }
    }

    fn owned(raw: HANDLE) -> Self {
        Self { raw, owned: true }
    }
}

impl Drop for ConsoleHandle {
    fn drop(&mut self) {
        if self.owned {
            let _ = unsafe { CloseHandle(self.raw) };
        }
    }
}

fn get_console_handle(kind: u32, name: &str) -> MicrosandboxResult<(ConsoleHandle, u32)> {
    let handle = unsafe { GetStdHandle(kind) };
    if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
        let handle = ConsoleHandle::borrowed(handle);
        if let Ok(mode) = console_mode(&handle, name) {
            return Ok((handle, mode));
        }
    }

    let handle = open_console_device(kind, name)?;
    let mode = console_mode(&handle, name)?;
    Ok((handle, mode))
}

fn open_console_device(kind: u32, name: &str) -> MicrosandboxResult<ConsoleHandle> {
    let device = match kind {
        STD_INPUT_HANDLE => "CONIN$",
        STD_OUTPUT_HANDLE => "CONOUT$",
        _ => {
            return Err(MicrosandboxError::Terminal(format!(
                "{name} console handle is unavailable"
            )));
        }
    };
    let wide = device
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<u16>>();
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(MicrosandboxError::Terminal(format!(
            "{name} console handle is unavailable: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(ConsoleHandle::owned(raw))
}

fn console_mode(handle: &ConsoleHandle, name: &str) -> MicrosandboxResult<u32> {
    let mut mode = 0u32;
    let result = unsafe { GetConsoleMode(handle.raw, &mut mode) };
    if result == 0 {
        return Err(MicrosandboxError::Terminal(format!(
            "{name} is not an interactive Windows console: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(mode)
}

fn set_console_mode(handle: &ConsoleHandle, mode: u32, context: &str) -> MicrosandboxResult<()> {
    let result = unsafe { SetConsoleMode(handle.raw, mode) };
    if result == 0 {
        return Err(MicrosandboxError::Terminal(format!(
            "{context}: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn create_event(context: &str) -> MicrosandboxResult<OwnedWindowsHandle> {
    let handle = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    if handle.is_null() {
        return Err(MicrosandboxError::Terminal(format!(
            "{context}: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(OwnedWindowsHandle(handle))
}

pub(crate) fn current_terminal_size() -> Option<(u16, u16)> {
    let (output, _) = get_console_handle(STD_OUTPUT_HANDLE, "stdout").ok()?;
    terminal_size_from_output(output.raw)
}

fn terminal_size_from_output(output: HANDLE) -> Option<(u16, u16)> {
    let mut info = CONSOLE_SCREEN_BUFFER_INFO {
        dwSize: Default::default(),
        dwCursorPosition: Default::default(),
        wAttributes: 0,
        srWindow: Default::default(),
        dwMaximumWindowSize: Default::default(),
    };

    let result = unsafe { GetConsoleScreenBufferInfo(output, &mut info) };
    if result == 0 {
        return None;
    }

    let cols = i32::from(info.srWindow.Right) - i32::from(info.srWindow.Left) + 1;
    let rows = i32::from(info.srWindow.Bottom) - i32::from(info.srWindow.Top) + 1;
    if cols <= 0 || rows <= 0 {
        return None;
    }

    Some((
        cols.min(i32::from(u16::MAX)) as u16,
        rows.min(i32::from(u16::MAX)) as u16,
    ))
}

impl Drop for OwnedWindowsHandle {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

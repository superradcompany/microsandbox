// Copyright 2026 Super Rad Company.
// SPDX-License-Identifier: Apache-2.0

//! Windows eventfd-style wake primitive.
//!
//! Windows does not have file descriptors or Linux `eventfd`. This type preserves the small API
//! surface libkrun uses for wake notifications while exposing the underlying waitable handle to
//! Windows event loops.

use std::io;
use std::os::windows::io::{AsRawHandle, RawHandle};
use std::sync::{Arc, Mutex};

use windows_sys::Win32::Foundation::{
    CloseHandle, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, ResetEvent, SetEvent, WaitForSingleObject,
};

pub const EFD_NONBLOCK: i32 = 1;
pub const EFD_SEMAPHORE: i32 = 2;

const ZERO_TIMEOUT_MS: u32 = 0;

#[derive(Debug)]
pub struct EventFd {
    inner: Arc<EventHandle>,
}

#[derive(Debug)]
struct EventHandle {
    handle: HANDLE,
    counter: Mutex<u64>,
    nonblocking: bool,
    semaphore: bool,
}

impl EventFd {
    pub fn new(flag: i32) -> io::Result<Self> {
        let handle = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            inner: Arc::new(EventHandle {
                handle,
                counter: Mutex::new(0),
                nonblocking: flag & EFD_NONBLOCK != 0,
                semaphore: flag & EFD_SEMAPHORE != 0,
            }),
        })
    }

    pub fn write(&self, v: u64) -> io::Result<()> {
        if v == 0 {
            return Ok(());
        }

        let mut counter = self.inner.counter.lock().unwrap();
        *counter = counter.saturating_add(v);
        set_event(self.inner.handle)
    }

    pub fn read(&self) -> io::Result<u64> {
        let timeout = if self.inner.nonblocking {
            ZERO_TIMEOUT_MS
        } else {
            u32::MAX
        };

        match unsafe { WaitForSingleObject(self.inner.handle, timeout) } {
            WAIT_OBJECT_0 => {
                let mut counter = self.inner.counter.lock().unwrap();
                if *counter == 0 {
                    reset_event(self.inner.handle)?;
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "event counter is empty",
                    ));
                }

                let value = if self.inner.semaphore {
                    *counter -= 1;
                    1
                } else {
                    let value = *counter;
                    *counter = 0;
                    value
                };

                if *counter == 0 {
                    reset_event(self.inner.handle)?;
                } else {
                    set_event(self.inner.handle)?;
                }

                Ok(value)
            }
            WAIT_TIMEOUT => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "event is not signaled",
            )),
            WAIT_FAILED => Err(io::Error::last_os_error()),
            _ => Err(io::Error::last_os_error()),
        }
    }

    pub fn try_clone(&self) -> io::Result<EventFd> {
        Ok(Self {
            inner: self.inner.clone(),
        })
    }

    pub fn get_write_handle(&self) -> RawHandle {
        self.inner.handle as RawHandle
    }
}

impl AsRawHandle for EventFd {
    fn as_raw_handle(&self) -> RawHandle {
        self.inner.handle as RawHandle
    }
}

// The handle is owned by EventHandle and Windows waitable-event operations are safe to call from
// multiple threads. The counter is protected by a mutex, so clones share one coherent value.
unsafe impl Send for EventHandle {}
unsafe impl Sync for EventHandle {}

impl Drop for EventHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

unsafe impl Send for EventFd {}
unsafe impl Sync for EventFd {}

fn set_event(handle: HANDLE) -> io::Result<()> {
    if unsafe { SetEvent(handle) } == 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

fn reset_event(handle: HANDLE) -> io::Result<()> {
    if unsafe { ResetEvent(handle) } == 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_write_preserves_counter_value() {
        let event = EventFd::new(EFD_NONBLOCK).unwrap();

        event.write(1).unwrap();
        event.write(4).unwrap();

        assert_eq!(event.read().unwrap(), 5);
        assert_eq!(event.read().unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn clone_reads_shared_counter() {
        let event = EventFd::new(EFD_NONBLOCK).unwrap();
        let clone = event.try_clone().unwrap();

        event.write(7).unwrap();

        assert_eq!(clone.read().unwrap(), 7);
        assert_eq!(event.read().unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn semaphore_reads_one_count_at_a_time() {
        let event = EventFd::new(EFD_NONBLOCK | EFD_SEMAPHORE).unwrap();

        event.write(2).unwrap();

        assert_eq!(event.read().unwrap(), 1);
        assert_eq!(event.read().unwrap(), 1);
        assert_eq!(event.read().unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }
}

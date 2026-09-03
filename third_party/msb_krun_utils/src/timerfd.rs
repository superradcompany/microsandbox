use std::io;
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, RawHandle};
use std::time::Duration;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Pollable timer used by event-loop driven devices.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct TimerFd {
    fd: RawFd,
}

/// Pollable timer used by event-loop driven devices.
#[cfg(any(target_os = "macos", target_os = "windows"))]
#[derive(Debug)]
pub struct TimerFd {
    event: crate::eventfd::EventFd,
    worker: std::sync::Mutex<Option<TimerWorker>>,
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
#[derive(Debug)]
struct TimerWorker {
    stop: std::sync::mpsc::Sender<()>,
    handle: std::thread::JoinHandle<()>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[cfg(target_os = "linux")]
impl TimerFd {
    /// Create a nonblocking timer file descriptor.
    pub fn new() -> io::Result<Self> {
        let fd = unsafe {
            libc::timerfd_create(
                libc::CLOCK_MONOTONIC,
                libc::TFD_NONBLOCK | libc::TFD_CLOEXEC,
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self { fd })
        }
    }

    /// Arm the timer to fire once after `duration`.
    pub fn arm_oneshot(&self, duration: Duration) -> io::Result<()> {
        validate_duration(duration)?;
        self.set_time(duration, Duration::ZERO)
    }

    /// Disarm the timer.
    pub fn disarm(&self) -> io::Result<()> {
        self.set_time(Duration::ZERO, Duration::ZERO)
    }

    /// Read and return the number of expirations.
    pub fn read(&self) -> io::Result<u64> {
        let mut value = 0u64;
        let ret = unsafe {
            libc::read(
                self.fd,
                &mut value as *mut u64 as *mut libc::c_void,
                std::mem::size_of::<u64>(),
            )
        };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(value)
        }
    }

    fn set_time(&self, value: Duration, interval: Duration) -> io::Result<()> {
        let spec = libc::itimerspec {
            it_interval: duration_to_timespec(interval),
            it_value: duration_to_timespec(value),
        };
        let ret = unsafe { libc::timerfd_settime(self.fd, 0, &spec, std::ptr::null_mut()) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl TimerFd {
    /// Create a nonblocking pollable timer.
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            event: crate::eventfd::EventFd::new(crate::eventfd::EFD_NONBLOCK)?,
            worker: std::sync::Mutex::new(None),
        })
    }

    /// Arm the timer to fire once after `duration`.
    pub fn arm_oneshot(&self, duration: Duration) -> io::Result<()> {
        validate_duration(duration)?;
        self.disarm()?;

        let event = self.event.try_clone()?;
        let (stop, rx) = std::sync::mpsc::channel();
        let handle = std::thread::Builder::new()
            .name("msb_krun_timer".to_string())
            .spawn(move || {
                if let Err(std::sync::mpsc::RecvTimeoutError::Timeout) = rx.recv_timeout(duration) {
                    let _ = event.write(1);
                }
            })?;

        *self.worker.lock().unwrap() = Some(TimerWorker { stop, handle });
        Ok(())
    }

    /// Disarm the timer.
    pub fn disarm(&self) -> io::Result<()> {
        if let Some(worker) = self.worker.lock().unwrap().take() {
            let _ = worker.stop.send(());
            let _ = worker.handle.join();
        }
        Ok(())
    }

    /// Read and return the number of expirations.
    pub fn read(&self) -> io::Result<u64> {
        self.event.read()
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

#[cfg(target_os = "linux")]
impl AsRawFd for TimerFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

#[cfg(target_os = "macos")]
impl AsRawFd for TimerFd {
    fn as_raw_fd(&self) -> RawFd {
        self.event.as_raw_fd()
    }
}

#[cfg(target_os = "windows")]
impl AsRawHandle for TimerFd {
    fn as_raw_handle(&self) -> RawHandle {
        self.event.as_raw_handle()
    }
}

#[cfg(target_os = "linux")]
impl Drop for TimerFd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl Drop for TimerFd {
    fn drop(&mut self) {
        let _ = self.disarm();
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn validate_duration(duration: Duration) -> io::Result<()> {
    if duration.is_zero() {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "timer duration must be nonzero",
        ))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn duration_to_timespec(duration: Duration) -> libc::timespec {
    libc::timespec {
        tv_sec: duration.as_secs() as libc::time_t,
        tv_nsec: duration.subsec_nanos() as libc::c_long,
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero_duration() {
        let timer = TimerFd::new().unwrap();
        assert!(timer.arm_oneshot(Duration::ZERO).is_err());
    }

    #[test]
    fn one_shot_timer_fires() {
        let timer = TimerFd::new().unwrap();
        timer
            .arm_oneshot(Duration::from_millis(10))
            .expect("arm timer");
        std::thread::sleep(Duration::from_millis(30));
        assert!(timer.read().unwrap() >= 1);
    }
}

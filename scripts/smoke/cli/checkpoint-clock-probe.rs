//! Static Linux 64-bit guest fixture: survives in RAM across a full checkpoint.

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const REALTIME: i32 = 0;
const MONOTONIC: i32 = 1;
const BOOTTIME: i32 = 7;
const TFD_NONBLOCK: i32 = 2048;
const TFD_CLOEXEC: i32 = 524288;
const TFD_TIMER_ABSTIME: i32 = 1;
const TFD_TIMER_CANCEL_ON_SET: i32 = 2;
const ECANCELED: i32 = 125;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
struct Timespec {
    sec: i64,
    nsec: i64,
}
#[repr(C)]
struct Itimer {
    interval: Timespec,
    value: Timespec,
}
//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

unsafe extern "C" {
    fn clock_gettime(id: i32, ts: *mut Timespec) -> i32;
    fn timerfd_create(clock: i32, flags: i32) -> i32;
    fn timerfd_settime(fd: i32, flags: i32, new: *const Itimer, old: *mut Itimer) -> i32;
    fn read(fd: i32, buf: *mut u64, size: usize) -> isize;
    fn __errno_location() -> *mut i32;
}
fn now(clock: i32) -> u64 {
    let mut t = Timespec { sec: 0, nsec: 0 };
    assert_eq!(unsafe { clock_gettime(clock, &mut t) }, 0);
    t.sec as u64 * 1_000_000_000 + t.nsec as u64
}
fn timer(clock: i32, cancel: bool) -> i32 {
    let fd = unsafe { timerfd_create(clock, TFD_NONBLOCK | TFD_CLOEXEC) };
    assert!(fd >= 0);
    let deadline = now(clock) + 5_000_000_000;
    let t = Itimer {
        interval: Timespec { sec: 0, nsec: 0 },
        value: Timespec {
            sec: (deadline / 1_000_000_000) as i64,
            nsec: (deadline % 1_000_000_000) as i64,
        },
    };
    assert_eq!(
        unsafe {
            timerfd_settime(
                fd,
                TFD_TIMER_ABSTIME | if cancel { TFD_TIMER_CANCEL_ON_SET } else { 0 },
                &t,
                std::ptr::null_mut(),
            )
        },
        0
    );
    fd
}
fn drain(fd: i32) -> i64 {
    let mut value = 0;
    let n = unsafe { read(fd, &mut value, 8) };
    if n == 8 {
        value as i64
    } else if unsafe { *__errno_location() } == ECANCELED {
        -1
    } else {
        0
    }
}
fn main() {
    let mut out = std::fs::File::create("/tmp/clock-records.csv").unwrap();
    let origin = now(MONOTONIC);
    let last = Arc::new(Mutex::new(0u64));
    let backwards = Arc::new(AtomicU64::new(0));
    for _ in 0..4 {
        let last = last.clone();
        let backwards = backwards.clone();
        std::thread::spawn(move || {
            loop {
                {
                    let mut previous = last.lock().unwrap();
                    // Serialize readings, not just writes: this establishes an actual ordering
                    // between threads so scheduling alone cannot look like a backward clock.
                    let current = now(MONOTONIC);
                    if current < *previous {
                        backwards.fetch_add(1, Ordering::Relaxed);
                    }
                    *previous = current;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        });
    }
    let relative = timer(MONOTONIC, false);
    let wall = timer(REALTIME, false);
    let cancel = timer(REALTIME, true);
    let mut seq = 0;
    let mut relative_total = 0;
    let mut wall_total = 0;
    let mut canceled = false;
    loop {
        relative_total += drain(relative).max(0);
        wall_total += drain(wall).max(0);
        canceled |= drain(cancel) < 0;
        writeln!(
            out,
            "{seq},{},{},{},{relative_total},{wall_total},{},{},{}",
            now(REALTIME),
            now(MONOTONIC),
            now(BOOTTIME),
            u8::from(canceled),
            backwards.load(Ordering::Relaxed),
            origin
        )
        .unwrap();
        out.flush().unwrap();
        seq += 1;
        std::thread::sleep(Duration::from_millis(10));
    }
}

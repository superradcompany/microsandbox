//! Guest clock utilities for boot timing measurement.

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Returns the current `CLOCK_BOOTTIME` value in nanoseconds.
///
/// `CLOCK_BOOTTIME` counts from kernel boot and includes time spent in suspend,
/// making it ideal for measuring total time since the VM kernel started.
///
/// # Panics
///
/// Panics if `clock_gettime` fails, which should never happen for `CLOCK_BOOTTIME`.
pub fn boottime_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let ret = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    assert!(ret == 0, "clock_gettime(CLOCK_BOOTTIME) failed");
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

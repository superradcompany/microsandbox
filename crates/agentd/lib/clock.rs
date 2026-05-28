//! Guest clock utilities for boot timing measurement.

use std::io;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const NANOS_PER_SECOND: u64 = 1_000_000_000;
const CLOCK_SYNC_TOLERANCE_NANOS: u64 = 100 * 1_000_000;

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

/// Synchronizes `CLOCK_REALTIME` from a Unix timestamp in nanoseconds.
///
/// Used by the host runtime to correct the guest wall clock after suspend,
/// resume, or other host-side pauses. Small deltas are ignored so normal
/// message delivery latency does not cause tiny backwards or forwards clock
/// steps.
pub fn sync_realtime_unix_nanos(unix_time_nanos: u64) -> io::Result<()> {
    let current = realtime_unix_nanos()?;
    if !clock_delta_exceeds_tolerance(current, unix_time_nanos) {
        return Ok(());
    }

    set_realtime_unix_nanos(unix_time_nanos)
}

fn realtime_unix_nanos() -> io::Result<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let ret = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    if ret == 0 {
        unix_nanos_from_timespec(ts)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn set_realtime_unix_nanos(unix_time_nanos: u64) -> io::Result<()> {
    let ts = timespec_from_unix_nanos(unix_time_nanos);
    let ret = unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &ts) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn unix_nanos_from_timespec(ts: libc::timespec) -> io::Result<u64> {
    let seconds = u64::try_from(ts.tv_sec)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative realtime seconds"))?;
    let nanos = u64::try_from(ts.tv_nsec)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative realtime nanoseconds"))?;
    seconds
        .checked_mul(NANOS_PER_SECOND)
        .and_then(|n| n.checked_add(nanos))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "realtime timestamp does not fit in u64 nanoseconds",
            )
        })
}

fn timespec_from_unix_nanos(unix_time_nanos: u64) -> libc::timespec {
    libc::timespec {
        tv_sec: (unix_time_nanos / NANOS_PER_SECOND) as libc::time_t,
        tv_nsec: (unix_time_nanos % NANOS_PER_SECOND) as libc::c_long,
    }
}

fn clock_delta_exceeds_tolerance(current_unix_nanos: u64, target_unix_nanos: u64) -> bool {
    current_unix_nanos.abs_diff(target_unix_nanos) > CLOCK_SYNC_TOLERANCE_NANOS
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timespec_from_unix_nanos_splits_seconds_and_nanos() {
        let ts = timespec_from_unix_nanos(1_700_000_000_123_456_789);

        assert_eq!(ts.tv_sec, 1_700_000_000);
        assert_eq!(ts.tv_nsec, 123_456_789);
    }

    #[test]
    fn unix_nanos_from_timespec_combines_seconds_and_nanos() {
        let ts = libc::timespec {
            tv_sec: 1_700_000_000,
            tv_nsec: 123_456_789,
        };

        assert_eq!(
            unix_nanos_from_timespec(ts).unwrap(),
            1_700_000_000_123_456_789
        );
    }

    #[test]
    fn clock_delta_exceeds_tolerance_only_for_meaningful_drift() {
        assert!(!clock_delta_exceeds_tolerance(
            1_000_000_000,
            1_000_000_000 + CLOCK_SYNC_TOLERANCE_NANOS
        ));
        assert!(clock_delta_exceeds_tolerance(
            1_000_000_000,
            1_000_000_001 + CLOCK_SYNC_TOLERANCE_NANOS
        ));
        assert!(clock_delta_exceeds_tolerance(
            1_000_000_001 + CLOCK_SYNC_TOLERANCE_NANOS,
            1_000_000_000
        ));
    }
}

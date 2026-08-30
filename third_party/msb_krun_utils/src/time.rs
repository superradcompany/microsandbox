// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt;
#[cfg(windows)]
use std::sync::OnceLock;
#[cfg(windows)]
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Constant to convert seconds to nanoseconds.
pub const NANOS_PER_SECOND: u64 = 1_000_000_000;

/// Wrapper over `libc::clockid_t` to specify Linux Kernel clock source.
pub enum ClockType {
    /// Equivalent to `libc::CLOCK_MONOTONIC`.
    Monotonic,
    /// Equivalent to `libc::CLOCK_REALTIME`.
    Real,
    /// Equivalent to `libc::CLOCK_PROCESS_CPUTIME_ID`.
    ProcessCpu,
    /// Equivalent to `libc::CLOCK_THREAD_CPUTIME_ID`.
    ThreadCpu,
}

#[cfg(unix)]
impl From<ClockType> for libc::clockid_t {
    fn from(ctype: ClockType) -> libc::clockid_t {
        match ctype {
            ClockType::Monotonic => libc::CLOCK_MONOTONIC,
            ClockType::Real => libc::CLOCK_REALTIME,
            ClockType::ProcessCpu => libc::CLOCK_PROCESS_CPUTIME_ID,
            ClockType::ThreadCpu => libc::CLOCK_THREAD_CPUTIME_ID,
        }
    }
}

/// Structure representing the date in local time with nanosecond precision.
pub struct LocalTime {
    /// Seconds in current minute.
    sec: i32,
    /// Minutes in current hour.
    min: i32,
    /// Hours in current day, 24H format.
    hour: i32,
    /// Days in current month.
    mday: i32,
    /// Months in current year.
    mon: i32,
    /// Years passed since 1900 BC.
    year: i32,
    /// Nanoseconds in current second.
    nsec: i64,
}

impl LocalTime {
    /// Returns the [LocalTime](struct.LocalTime.html) structure for the calling moment.
    #[cfg(unix)]
    pub fn now() -> LocalTime {
        let mut timespec = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let mut tm: libc::tm = libc::tm {
            tm_sec: 0,
            tm_min: 0,
            tm_hour: 0,
            tm_mday: 0,
            tm_mon: 0,
            tm_year: 0,
            tm_wday: 0,
            tm_yday: 0,
            tm_isdst: 0,
            tm_gmtoff: 0,
            #[cfg(target_os = "linux")]
            tm_zone: std::ptr::null(),
            #[cfg(target_os = "macos")]
            tm_zone: std::ptr::null_mut(),
        };

        // Safe because the parameters are valid.
        unsafe {
            libc::clock_gettime(libc::CLOCK_REALTIME, &mut timespec);
            libc::localtime_r(&timespec.tv_sec, &mut tm);
        }

        LocalTime {
            sec: tm.tm_sec,
            min: tm.tm_min,
            hour: tm.tm_hour,
            mday: tm.tm_mday,
            mon: tm.tm_mon,
            year: tm.tm_year,
            nsec: timespec.tv_nsec,
        }
    }

    /// Returns the current UTC timestamp on Windows.
    #[cfg(windows)]
    pub fn now() -> LocalTime {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let (year, mon, mday, hour, min, sec) = unix_seconds_to_utc(duration.as_secs());

        LocalTime {
            sec,
            min,
            hour,
            mday,
            mon,
            year: year - 1900,
            nsec: duration.subsec_nanos() as i64,
        }
    }
}

impl fmt::Display for LocalTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}",
            self.year + 1900,
            self.mon + 1,
            self.mday,
            self.hour,
            self.min,
            self.sec,
            self.nsec
        )
    }
}

/// Holds a micro-second resolution timestamp with both the real time and cpu time.
#[derive(Clone)]
pub struct TimestampUs {
    /// Real time in microseconds.
    pub time_us: u64,
    /// Cpu time in microseconds.
    pub cputime_us: u64,
}

impl Default for TimestampUs {
    fn default() -> TimestampUs {
        TimestampUs {
            time_us: get_time(ClockType::Monotonic) / 1000,
            cputime_us: get_time(ClockType::ProcessCpu) / 1000,
        }
    }
}

/// Returns a timestamp in nanoseconds from a monotonic clock.
///
/// Uses `_rdstc` on `x86_64` and [`get_time`](fn.get_time.html) on other architectures.
pub fn timestamp_cycles() -> u64 {
    #[cfg(target_arch = "x86_64")]
    // Safe because there's nothing that can go wrong with this call.
    unsafe {
        std::arch::x86_64::_rdtsc()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        get_time(ClockType::Monotonic)
    }
}

/// Returns a timestamp in nanoseconds based on the provided clock type.
///
/// # Arguments
///
/// * `clock_type` - Identifier of the Linux Kernel clock on which to act.
pub fn get_time(clock_type: ClockType) -> u64 {
    #[cfg(unix)]
    {
        let mut time_struct = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // Safe because the parameters are valid.
        unsafe { libc::clock_gettime(clock_type.into(), &mut time_struct) };
        seconds_to_nanoseconds(time_struct.tv_sec).unwrap() as u64 + (time_struct.tv_nsec as u64)
    }

    #[cfg(windows)]
    {
        match clock_type {
            ClockType::Real => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
            ClockType::Monotonic | ClockType::ProcessCpu | ClockType::ThreadCpu => {
                static START: OnceLock<Instant> = OnceLock::new();
                START.get_or_init(Instant::now).elapsed().as_nanos() as u64
            }
        }
    }
}

/// Converts a timestamp in seconds to an equivalent one in nanoseconds.
/// Returns `None` if the conversion overflows.
///
/// # Arguments
///
/// * `value` - Timestamp in seconds.
pub fn seconds_to_nanoseconds(value: i64) -> Option<i64> {
    value.checked_mul(NANOS_PER_SECOND as i64)
}

#[cfg(windows)]
fn unix_seconds_to_utc(seconds: u64) -> (i32, i32, i32, i32, i32, i32) {
    let days = (seconds / 86_400) as i64;
    let seconds_of_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = (seconds_of_day / 3600) as i32;
    let min = ((seconds_of_day % 3600) / 60) as i32;
    let sec = (seconds_of_day % 60) as i32;

    (year, month - 1, day, hour, min, sec)
}

#[cfg(windows)]
fn civil_from_days(days: i64) -> (i32, i32, i32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + i64::from(month <= 2);

    (year as i32, month as i32, day as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_time() {
        for _ in 0..1000 {
            assert!(get_time(ClockType::Monotonic) <= get_time(ClockType::Monotonic));
        }

        for _ in 0..1000 {
            assert!(get_time(ClockType::ProcessCpu) <= get_time(ClockType::ProcessCpu));
        }

        for _ in 0..1000 {
            assert!(get_time(ClockType::ThreadCpu) <= get_time(ClockType::ThreadCpu));
        }

        assert_ne!(get_time(ClockType::Real), 0);
    }

    #[test]
    fn test_local_time_display() {
        let local_time = LocalTime {
            sec: 30,
            min: 15,
            hour: 10,
            mday: 4,
            mon: 6,
            year: 119,
            nsec: 123_456_789,
        };
        assert_eq!(
            String::from("2019-07-04T10:15:30.123456789"),
            local_time.to_string()
        );

        let local_time = LocalTime {
            sec: 5,
            min: 5,
            hour: 5,
            mday: 23,
            mon: 7,
            year: 44,
            nsec: 123,
        };
        assert_eq!(
            String::from("1944-08-23T05:05:05.000000123"),
            local_time.to_string()
        );

        let local_time = LocalTime::now();
        assert!(local_time.mon >= 0 && local_time.mon <= 11);
    }

    #[test]
    fn test_seconds_to_nanoseconds() {
        assert_eq!(
            seconds_to_nanoseconds(100).unwrap() as u64,
            100 * NANOS_PER_SECOND
        );

        assert!(seconds_to_nanoseconds(9_223_372_037).is_none());
    }
}

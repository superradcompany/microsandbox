//! Guest memory observations use a host-wide monotonic clock, never export time.

use std::time::Duration;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A complete guest report, timestamped by the host when it arrived.
///
/// Total is usable capacity reported by the guest, not the configured allocation
/// or a resize acknowledgement. Values and receipt time must come from the same
/// report. Repeated publication must retain the original receipt time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestMemoryObservation {
    /// Guest-reported usable capacity in bytes.
    pub total_bytes: u64,
    /// Guest-reported available memory in bytes.
    pub available_bytes: u64,
    /// Host receipt time from [`guest_memory_clock`].
    pub received_at: Duration,
    /// Negotiated guest reporting interval, independent of collector cadence.
    pub reporting_interval: Duration,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl GuestMemoryObservation {
    /// Whether this complete observation is valid and has not expired.
    pub fn is_fresh_at(&self, now: Duration) -> bool {
        if self.total_bytes == 0
            || self.available_bytes > self.total_bytes
            || self.reporting_interval.is_zero()
        {
            return false;
        }
        let Some(age) = now.checked_sub(self.received_at) else {
            // A future receipt is not evidence of freshness (for example after
            // accidentally transporting a clock value from another host).
            return false;
        };
        let expiry = self
            .reporting_interval
            .saturating_mul(3)
            .max(Duration::from_secs(3));
        age < expiry
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Read the host-wide monotonic clock used for guest report receipt and expiry.
///
/// Unlike `Instant`, the value has a shared origin across processes. It is only
/// meaningful on the same host boot and must not be restored from a checkpoint.
/// Clock failure makes observations unavailable; wall-clock fallback is unsafe.
pub fn guest_memory_clock() -> Option<Duration> {
    #[cfg(unix)]
    {
        #[cfg(target_os = "linux")]
        let clock = libc::CLOCK_BOOTTIME;
        #[cfg(not(target_os = "linux"))]
        let clock = libc::CLOCK_MONOTONIC;
        let mut time = std::mem::MaybeUninit::<libc::timespec>::uninit();
        // SAFETY: clock_gettime initializes the pointed-to timespec on success.
        if unsafe { libc::clock_gettime(clock, time.as_mut_ptr()) } != 0 {
            return None;
        }
        let time = unsafe { time.assume_init() };
        Some(Duration::new(
            u64::try_from(time.tv_sec).ok()?,
            u32::try_from(time.tv_nsec).ok()?,
        ))
    }
    #[cfg(windows)]
    {
        // SAFETY: GetTickCount64 has no preconditions and includes system sleep.
        Some(Duration::from_millis(unsafe {
            windows_sys::Win32::System::SystemInformation::GetTickCount64()
        }))
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(interval: Duration) -> GuestMemoryObservation {
        GuestMemoryObservation {
            total_bytes: 1024,
            available_bytes: 256,
            received_at: Duration::from_secs(100),
            reporting_interval: interval,
        }
    }

    #[test]
    fn expiry_tracks_guest_cadence_with_a_three_second_floor() {
        for (interval, expiry) in [(0.1, 3), (1.0, 3), (5.0, 15), (10.0, 30)] {
            let report = observation(Duration::from_secs_f64(interval));
            let expires = report.received_at + Duration::from_secs(expiry);
            assert!(report.is_fresh_at(expires - Duration::from_nanos(1)));
            assert!(!report.is_fresh_at(expires));
        }
    }

    #[test]
    fn invalid_or_future_reports_are_unavailable() {
        let mut report = observation(Duration::from_secs(1));
        assert!(!report.is_fresh_at(report.received_at - Duration::from_nanos(1)));
        report.available_bytes = report.total_bytes + 1;
        assert!(!report.is_fresh_at(report.received_at));
        report.available_bytes = 0;
        report.total_bytes = 0;
        assert!(!report.is_fresh_at(report.received_at));
        report.total_bytes = 1024;
        report.reporting_interval = Duration::ZERO;
        assert!(!report.is_fresh_at(report.received_at));
    }

    #[test]
    fn host_clock_does_not_move_backwards() {
        let first = guest_memory_clock().unwrap();
        assert!(guest_memory_clock().unwrap() >= first);
    }
}

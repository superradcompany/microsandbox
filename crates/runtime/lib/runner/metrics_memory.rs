//! Last confirmed configured allocation and observation ordering at a resize boundary.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use microsandbox_metrics::guest_memory_clock;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Shared configured allocation for runtime resize confirmation and metrics publication.
///
/// Publication holds this guard through the mapped-slot write so an earlier allocation
/// cannot overwrite a later confirmation. This is independent of guest usable MemTotal.
#[derive(Clone)]
pub struct ConfirmedMemoryLimit {
    allocation: Arc<Mutex<Allocation>>,
    source: msb_krun::MetricsHandle,
}

#[derive(Clone, Copy)]
struct Allocation {
    bytes: u64,
    available_after: Option<Duration>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ConfirmedMemoryLimit {
    /// Initialize the known boot allocation. Restored hotplug capacity requires fresh confirmation.
    pub fn boot(bytes: u64, source: msb_krun::MetricsHandle) -> Self {
        Self {
            allocation: Arc::new(Mutex::new(Allocation {
                bytes,
                available_after: None,
            })),
            source,
        }
    }

    /// The caller must hold mutation authority and have matched host and guest readiness.
    pub(crate) fn confirm(&self, bytes: u64) -> bool {
        self.confirm_at(bytes, guest_memory_clock())
    }

    fn confirm_at(&self, bytes: u64, at: Option<Duration>) -> bool {
        let mut allocation = self.allocation.lock().unwrap();
        if allocation.bytes == bytes {
            return true;
        }
        let Some(at) = at else {
            // Without a comparable receipt boundary we cannot safely combine the new
            // allocation with balloon statistics. Retain the last confirmed metric.
            return false;
        };
        // Advance the native request epoch too. Receipt ordering alone cannot reject a
        // pre-confirmation sample whose reply arrives late. Lock order matches the sampler:
        // allocation -> native observation -> registry slot, never VMM/device locks.
        self.source.invalidate_guest_memory_observation();
        *allocation = Allocation {
            bytes,
            available_after: Some(at),
        };
        true
    }

    /// Complete filesystem/counter work before calling; the closure only publishes mapped data.
    pub(crate) fn publish<R>(&self, publish: impl FnOnce(u64, Option<Duration>) -> R) -> R {
        let allocation = self.allocation.lock().unwrap();
        publish(allocation.bytes, allocation.available_after)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_or_unclocked_changes_cannot_advance_the_limit() {
        let native = msb_krun_utils::metrics::MetricsWriter::default();
        let limit = ConfirmedMemoryLimit::boot(256 << 20, native.handle());
        assert!(!limit.confirm_at(512 << 20, None));
        assert_eq!(
            limit.publish(|bytes, after| (bytes, after)),
            (256 << 20, None)
        );
        let at = Duration::from_secs(10);
        assert!(limit.confirm_at(512 << 20, Some(at)));
        assert_eq!(
            limit.publish(|bytes, after| (bytes, after)),
            (512 << 20, Some(at))
        );
        // A repeated confirmation of the same allocation does not perpetually defer statistics.
        assert!(limit.confirm_at(512 << 20, Some(at + Duration::from_secs(1))));
        assert_eq!(limit.publish(|_, after| after), Some(at));
        assert!(limit.confirm_at(256 << 20, Some(at + Duration::from_secs(2))));
        assert_eq!(
            limit.publish(|bytes, after| (bytes, after)),
            (256 << 20, Some(at + Duration::from_secs(2)))
        );
    }
}

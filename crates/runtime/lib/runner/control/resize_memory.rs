//! Join a query-bound guest memory report to the host device and accepted operation.

use microsandbox_protocol::resize::ResizeObservation;
use microsandbox_protocol::resources::{
    MemoryReadiness, ObservationUnavailable, ResourceObservation,
};
use microsandbox_types::modify::{ResourceConvergenceState, ResourceResizeStatus};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Byte-exact host evidence, kept separate from the guest's onlining assertion.
#[derive(Clone, Copy)]
pub(super) struct MemoryDeviceEvidence {
    pub boot_size: u64,
    pub address: u64,
    pub region_size: u64,
    pub requested_size: u64,
    pub plugged_size: u64,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// The caller fences the guest query against mutations and holds mutation authority
/// while matching the host read.
/// Plugged capacity remains the existing actual/enforced quantity; only the guest
/// can establish whether that capacity is online and ready for this operation.
pub(super) fn observe_memory(
    status: &mut ResourceResizeStatus,
    accepted_mib: u64,
    host: Option<MemoryDeviceEvidence>,
    guest: ResourceObservation<MemoryReadiness>,
) -> ResizeObservation {
    let guest = match guest {
        ResourceObservation::Available { value } => value,
        ResourceObservation::Unavailable {
            reason: ObservationUnavailable::Unsupported,
        } => return ResizeObservation::Unsupported,
        ResourceObservation::Unavailable { .. } => return ResizeObservation::Unavailable,
    };
    let Some(host) = host else {
        return ResizeObservation::Unavailable;
    };
    let target = accepted_mib
        .checked_mul(1 << 20)
        .and_then(|total| total.checked_sub(host.boot_size));
    let current = host.boot_size.checked_add(host.plugged_size);
    if !guest.is_valid()
        || host.region_size == 0
        || host.address.checked_add(host.region_size).is_none()
        || host.boot_size.checked_add(host.region_size).is_none()
        || host.requested_size > host.region_size
        || host.plugged_size > host.region_size
        || target != Some(host.requested_size)
        || current.is_none()
        || guest.address != host.address
        || guest.region_size != host.region_size
    {
        // A different region, a changed target, or invalid arithmetic is not
        // partial progress for this operation. Keep its last valid quantities.
        return ResizeObservation::Unavailable;
    }
    status.actual = format!("{} MiB", current.unwrap() >> 20);
    status.enforced = status.actual.clone();
    status.state = if guest.requested_size == host.requested_size
        && guest.plugged_size == host.plugged_size
        && host.plugged_size == host.requested_size
        && guest.all_online
    {
        ResourceConvergenceState::Applied
    } else {
        ResourceConvergenceState::Converging
    };
    ResizeObservation::Available
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use microsandbox_types::modify::ResourceKind;

    fn fixture() -> (ResourceResizeStatus, MemoryDeviceEvidence, MemoryReadiness) {
        let host = MemoryDeviceEvidence {
            boot_size: 256 << 20,
            address: 1 << 32,
            region_size: 768 << 20,
            requested_size: 256 << 20,
            plugged_size: 256 << 20,
        };
        let guest = MemoryReadiness {
            address: host.address,
            region_size: host.region_size,
            requested_size: host.requested_size,
            plugged_size: host.plugged_size,
            all_online: true,
        };
        let status = ResourceResizeStatus {
            resource: ResourceKind::Memory,
            requested: "512 MiB".into(),
            actual: "256 MiB".into(),
            enforced: "256 MiB".into(),
            state: ResourceConvergenceState::Accepted,
        };
        (status, host, guest)
    }

    #[test]
    fn completion_requires_device_target_plugging_and_guest_onlining() {
        for case in 0..6 {
            let (mut status, mut host, mut guest) = fixture();
            match case {
                0 => {}
                1 => guest.all_online = false,
                2 => guest.requested_size /= 2,
                3 => guest.plugged_size /= 2,
                4 => {
                    host.plugged_size /= 2;
                    guest.plugged_size = host.plugged_size;
                }
                _ => {
                    host.plugged_size *= 2;
                    guest.plugged_size = host.plugged_size;
                }
            }
            assert_eq!(
                observe_memory(
                    &mut status,
                    512,
                    Some(host),
                    ResourceObservation::Available { value: guest }
                ),
                ResizeObservation::Available
            );
            assert_eq!(
                status.state,
                if case == 0 {
                    ResourceConvergenceState::Applied
                } else {
                    ResourceConvergenceState::Converging
                }
            );
            assert_eq!(status.actual, status.enforced);
            assert_eq!(status.requested, "512 MiB");
        }
    }

    #[test]
    fn changed_identity_target_or_invalid_capacity_preserves_last_evidence() {
        for case in 0..9 {
            let (mut status, mut host, mut guest) = fixture();
            let original = status.clone();
            let mut target = 512;
            match case {
                0 => guest.address += 4096,
                1 => guest.region_size /= 2,
                2 => host.requested_size /= 2,
                3 => host.plugged_size = u64::MAX,
                4 => host.address = u64::MAX,
                5 => host.boot_size = u64::MAX,
                6 => guest.plugged_size = u64::MAX,
                7 => target = u64::MAX,
                _ => target = 1,
            }
            assert_eq!(
                observe_memory(
                    &mut status,
                    target,
                    Some(host),
                    ResourceObservation::Available { value: guest }
                ),
                ResizeObservation::Unavailable
            );
            assert_eq!(status, original);
        }
    }

    #[test]
    fn missing_observation_is_not_refusal_or_completion() {
        let (status, host, guest) = fixture();
        let mut actual = status.clone();
        assert_eq!(
            observe_memory(
                &mut actual,
                512,
                None,
                ResourceObservation::Available { value: guest }
            ),
            ResizeObservation::Unavailable
        );
        for reason in [
            ObservationUnavailable::Unsupported,
            ObservationUnavailable::Invalid,
        ] {
            let expected = if reason == ObservationUnavailable::Unsupported {
                ResizeObservation::Unsupported
            } else {
                ResizeObservation::Unavailable
            };
            assert_eq!(
                observe_memory(
                    &mut actual,
                    512,
                    Some(host),
                    ResourceObservation::Unavailable { reason }
                ),
                expected
            );
            assert_eq!(actual, status);
        }
    }

    #[test]
    fn fully_unplugged_target_can_confirm_return_to_boot_memory() {
        let (mut status, mut host, mut guest) = fixture();
        host.requested_size = 0;
        host.plugged_size = 0;
        guest.requested_size = 0;
        guest.plugged_size = 0;
        assert_eq!(
            observe_memory(
                &mut status,
                256,
                Some(host),
                ResourceObservation::Available { value: guest }
            ),
            ResizeObservation::Available
        );
        assert_eq!(status.state, ResourceConvergenceState::Applied);
        assert_eq!(status.actual, "256 MiB");
    }

    #[test]
    fn rounding_uses_accepted_target_without_rewriting_the_original_request() {
        let (mut status, host, guest) = fixture();
        status.requested = "513 MiB".into();
        assert_eq!(
            observe_memory(
                &mut status,
                512,
                Some(host),
                ResourceObservation::Available { value: guest }
            ),
            ResizeObservation::Available
        );
        assert_eq!(status.state, ResourceConvergenceState::Applied);
        assert_eq!(status.actual, "512 MiB");
        assert_eq!(status.requested, "513 MiB");
    }

    #[test]
    fn sub_mib_difference_cannot_disappear_through_display_rounding() {
        let (mut status, host, mut guest) = fixture();
        guest.plugged_size -= 1;
        assert_eq!(
            observe_memory(
                &mut status,
                512,
                Some(host),
                ResourceObservation::Available { value: guest }
            ),
            ResizeObservation::Available
        );
        assert_eq!(status.state, ResourceConvergenceState::Converging);
    }
}

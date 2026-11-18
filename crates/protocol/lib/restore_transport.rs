//! Host/guest payloads used on the private full-restore transport.
use serde::{Deserialize, Serialize};

use crate::core::Ready;
use crate::init_observation::{InitObservation, ObservedReady};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The relay retains these guest capabilities in the checkpoint and exposes
/// just the public readiness payload to ordinary clients.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GuestReady {
    #[serde(flatten)]
    pub public: Ready,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restore_tcp_reset_version: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub init_observation: Option<InitObservation>,
}

/// The distinct mode makes an unsupported guest reject a misdirected request
/// instead of acknowledging a legacy thaw without doing the reset.
#[derive(Debug, Serialize, Deserialize)]
pub struct GuestThaw {
    pub attempt_id: String,
    pub mode: GuestThawMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestThawMode {
    Continue,
    Restore,
    RestoreResetTcp,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl GuestReady {
    /// Forward init evidence to clients while keeping guest-only reset capability in the relay.
    pub fn client_ready(&self) -> ObservedReady {
        ObservedReady {
            ready: self.public.clone(),
            init_observation: self.init_observation.clone(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl From<Ready> for GuestReady {
    fn from(public: Ready) -> Self {
        Self {
            public,
            restore_tcp_reset_version: None,
            init_observation: None,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{WorkloadThaw, WorkloadThawMode};

    #[test]
    fn private_ready_capability_is_optional_for_both_peers() {
        let legacy = Ready {
            boot_time_ns: 27,
            ..Default::default()
        };
        let mut wire = Vec::new();
        ciborium::into_writer(&legacy, &mut wire).unwrap();
        let decoded: GuestReady = ciborium::from_reader(wire.as_slice()).unwrap();
        assert_eq!(decoded.restore_tcp_reset_version, None);
        let capable = GuestReady {
            public: legacy,
            restore_tcp_reset_version: Some(1),
            init_observation: Some(InitObservation::Builtin),
        };
        wire.clear();
        ciborium::into_writer(&capable, &mut wire).unwrap();
        let decoded: Ready = ciborium::from_reader(wire.as_slice()).unwrap();
        assert_eq!(decoded.boot_time_ns, 27);
    }

    #[test]
    fn legacy_thaw_modes_round_trip_and_old_guests_reject_a_reset() {
        for mode in [WorkloadThawMode::Continue, WorkloadThawMode::Restore] {
            let legacy = WorkloadThaw {
                attempt_id: "cut".into(),
                mode,
            };
            let mut wire = Vec::new();
            ciborium::into_writer(&legacy, &mut wire).unwrap();
            let decoded: GuestThaw = ciborium::from_reader(wire.as_slice()).unwrap();
            wire.clear();
            ciborium::into_writer(&decoded, &mut wire).unwrap();
            assert_eq!(
                ciborium::from_reader::<WorkloadThaw, _>(wire.as_slice()).unwrap(),
                legacy
            );
        }
        let mut wire = Vec::new();
        ciborium::into_writer(
            &GuestThaw {
                attempt_id: "cut".into(),
                mode: GuestThawMode::RestoreResetTcp,
            },
            &mut wire,
        )
        .unwrap();
        assert!(ciborium::from_reader::<WorkloadThaw, _>(wire.as_slice()).is_err());
    }
}

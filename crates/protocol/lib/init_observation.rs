//! Optional boot selection evidence carried by the existing Ready payload.
//!
//! This records which init executable was selected, not application readiness or proof that a
//! foreign init completed exec. No arguments, environment values or host paths are included.

use serde::{Deserialize, Serialize};

use crate::core::Ready;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Guest-side init selection at this boot. Absence is unknown, never implicit builtin init.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InitObservation {
    /// Agentd retained PID 1; no foreign executable was selected.
    Builtin,
    /// Exact guest path selected and preflighted before the PID 1 fork/exec handoff.
    Handoff {
        /// Guest path passed to exec, preserving symlink spelling and `auto` resolution.
        path: String,
    },
}

/// Additive Ready envelope, preserving existing public `Ready` struct literals and wire fields.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct ObservedReady {
    /// Existing transport and readiness fields.
    #[serde(flatten)]
    pub ready: Ready,
    /// Missing on older agents or after passage through an older relay.
    #[serde(default)]
    pub init_observation: Option<InitObservation>,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Serialize for ObservedReady {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let Some(observation) = &self.init_observation else {
            // A flattened serde wrapper uses an indefinite CBOR map. Preserve the original
            // encoding exactly when there is no observation, including historical restores.
            return self.ready.serialize(serializer);
        };
        #[derive(Serialize)]
        struct Advertisement<'a> {
            #[serde(flatten)]
            ready: &'a Ready,
            init_observation: &'a InitObservation,
        }
        Advertisement {
            ready: &self.ready,
            init_observation: observation,
        }
        .serialize(serializer)
    }
}

impl From<Ready> for ObservedReady {
    fn from(ready: Ready) -> Self {
        Self {
            ready,
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
    use crate::message::{Message, MessageType};

    #[test]
    fn absent_observation_keeps_legacy_bytes_and_does_not_claim_builtin() {
        let ready = Ready::default();
        let observed = ObservedReady::from(ready.clone());
        let legacy = Message::with_payload(MessageType::Ready, 0, &ready).unwrap();
        let encoded = Message::with_payload(MessageType::Ready, 0, &observed).unwrap();
        assert_eq!(legacy.p, encoded.p);
        assert!(
            legacy
                .payload::<ObservedReady>()
                .unwrap()
                .init_observation
                .is_none()
        );
        assert_eq!(
            serde_json::to_value(&ready).unwrap(),
            serde_json::to_value(&observed).unwrap()
        );
    }

    #[test]
    fn host_exec_advertisement_preserves_selection() {
        use crate::exec_control::{ExecControlAdvertisement, ExecControlReady};
        let observed = ObservedReady {
            ready: Ready::default(),
            init_observation: Some(InitObservation::Builtin),
        };
        let capability = ExecControlReady {
            version: 1,
            endpoint: "test-control".into(),
            connection: [0; 16],
        };
        let advertisement = ExecControlAdvertisement {
            ready: &observed,
            exec_control: &capability,
        };
        let message = Message::with_payload(MessageType::Ready, 0, &advertisement).unwrap();
        assert_eq!(
            message.payload::<ObservedReady>().unwrap().init_observation,
            Some(InitObservation::Builtin)
        );
        assert!(message.payload::<Ready>().is_ok());
    }

    #[test]
    fn old_ready_readers_ignore_selection_and_new_readers_preserve_it() {
        for observation in [
            InitObservation::Builtin,
            InitObservation::Handoff {
                path: "/sbin/init".into(),
            },
        ] {
            let observed = ObservedReady {
                ready: Ready {
                    agent_version: "legacy-compatible".into(),
                    ..Default::default()
                },
                init_observation: Some(observation.clone()),
            };
            let msg = Message::with_payload(MessageType::Ready, 0, &observed).unwrap();
            assert_eq!(
                msg.payload::<Ready>().unwrap().agent_version,
                "legacy-compatible"
            );
            assert_eq!(
                msg.payload::<ObservedReady>().unwrap().init_observation,
                Some(observation)
            );
            let persisted = serde_json::to_string(&observed).unwrap();
            assert_eq!(
                serde_json::from_str::<Ready>(&persisted)
                    .unwrap()
                    .agent_version,
                "legacy-compatible"
            );
            assert_eq!(
                serde_json::from_str::<ObservedReady>(&persisted)
                    .unwrap()
                    .init_observation,
                observed.init_observation
            );
        }
    }
}

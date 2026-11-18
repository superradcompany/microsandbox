//! Capability-probed host metadata updates, independent of the guest protocol.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::wire::{Envelope, WireError, decode_value, validate_record};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Read-only discovery and fenced label updates use this additive extension.
pub const LABELS_REQUEST: &str = "control.labels";
/// Successful terminal reply; failures use the existing control error envelope.
pub const LABELS_RESPONSE: &str = "control.labels.result";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The caller must complete discovery before dispatching a mutation.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum LabelsRequest {
    /// Read-only discovery. Older framed peers can refuse without receiving a mutation.
    Hello,
    /// Change active labels only while the selected runtime and active record still match.
    Update {
        /// Identity returned by discovery on this runtime session.
        runtime_boot_id: String,
        /// SHA-256 of the exact private active-config JSON selected by the SDK.
        expected_active_sha256: String,
        /// Validated desired configuration from the SDK's modification plan. Host-private;
        /// committed together with active labels and their catalog index.
        desired_config_json: String,
        /// Labels to set. Values never appear in diagnostics.
        set: BTreeMap<String, String>,
        /// Labels to remove; must not overlap with `set`.
        remove: Vec<String>,
    },
    /// Compact update, sent only after discovery explicitly advertises support.
    UpdateDelta {
        /// Runtime identity selected before dispatch.
        runtime_boot_id: String,
        /// Digest of the selected active catalog JSON.
        expected_active_sha256: String,
        /// Digest of the selected desired catalog JSON; checked again at commit.
        expected_desired_sha256: String,
        /// Private structural delta, never included in diagnostics.
        desired_delta_json: String,
        /// Active labels to set.
        set: BTreeMap<String, String>,
        /// Active labels to remove.
        remove: Vec<String>,
    },
}

/// A successful operation. Unsupported and uncertain outcomes remain errors.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
#[non_exhaustive]
pub enum LabelsResponse {
    /// Support and fresh runtime identity, without changing metadata.
    Supported {
        /// This identity fences the subsequent mutation.
        runtime_boot_id: String,
        /// Optional capability; older responses imply the original full update only.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        config_delta: bool,
    },
    /// Active configuration and its durable confirmation were written.
    Updated {
        /// Runtime identity which performed the mutation.
        runtime_boot_id: String,
        /// Confirmed journal generation, not a guest resource observation.
        generation: u64,
    },
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for LabelsRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Metadata may contain private application information, and the active digest
        // must not become an externally logged fingerprint of a secret-bearing config.
        f.debug_struct("LabelsRequest").finish_non_exhaustive()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Validate nested label keys before serde could silently collapse duplicates.
pub fn decode_request(envelope: &Envelope) -> Result<LabelsRequest, WireError> {
    let value = decode_value(&envelope.p)?;
    validate_record(&value)?;
    if let ciborium::Value::Map(fields) = &value
        && let Some((_, labels)) = fields.iter().find(|(key, _)| key.as_text() == Some("set"))
    {
        validate_record(labels)?;
    }
    value.deserialized().map_err(|_| WireError::InvalidRecord)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_remains_compatible_in_both_directions() {
        let old = r#"{"result":"supported","runtime_boot_id":"boot"}"#;
        assert!(matches!(
            serde_json::from_str::<LabelsResponse>(old).unwrap(),
            LabelsResponse::Supported {
                config_delta: false,
                ..
            }
        ));
        // This mirrors the original decoder: the extra capability must not make
        // an older client reject a runtime that still accepts its full update.
        #[derive(Deserialize)]
        #[serde(tag = "result", rename_all = "snake_case")]
        enum OriginalResponse {
            Supported { runtime_boot_id: String },
        }
        let encoded = serde_json::to_string(&LabelsResponse::Supported {
            runtime_boot_id: "boot".into(),
            config_delta: true,
        })
        .unwrap();
        let OriginalResponse::Supported { runtime_boot_id } =
            serde_json::from_str(&encoded).unwrap();
        assert_eq!(runtime_boot_id, "boot");
    }

    #[test]
    fn private_label_requests_are_redacted_and_released_control_enums_stay_unchanged() {
        let request = LabelsRequest::Update {
            runtime_boot_id: "PRIVATE_BOOT".into(),
            expected_active_sha256: "PRIVATE_DIGEST".into(),
            desired_config_json: "PRIVATE_CONFIG".into(),
            set: BTreeMap::from([("key".into(), "PRIVATE_VALUE".into())]),
            remove: vec![],
        };
        assert!(!format!("{request:?}").contains("PRIVATE"));
        let envelope = Envelope::new(2, LABELS_REQUEST, &request).unwrap();
        assert!(matches!(
            decode_request(&envelope).unwrap(),
            LabelsRequest::Update { .. }
        ));
        assert_eq!(
            crate::control::control_message_min_generation(LABELS_REQUEST),
            Some(2)
        );
        assert!(crate::control::ControlMessageType::from_wire_str(LABELS_REQUEST).is_none());
    }
    #[test]
    fn duplicate_label_keys_are_rejected_before_deserialization() {
        use ciborium::Value;
        let request = Value::Map(vec![
            ("op".into(), "update".into()),
            ("runtime_boot_id".into(), "boot".into()),
            ("expected_active_sha256".into(), "a".repeat(64).into()),
            (
                "set".into(),
                Value::Map(vec![
                    ("team".into(), "first".into()),
                    ("team".into(), "second".into()),
                ]),
            ),
            ("remove".into(), Value::Array(vec![])),
        ]);
        let envelope = Envelope::new(2, LABELS_REQUEST, &request).unwrap();
        assert!(matches!(
            decode_request(&envelope),
            Err(WireError::DuplicateKey)
        ));
    }
}

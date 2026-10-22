//! Explicit unknown/default/value states; absence is represented by the containing field.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Observation or input provenance; never permission to reuse a value or weaken security.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SavedOrigin {
    /// Explicitly configured ordinary data, after capture-time secret exclusion.
    Configured,
    /// Resolved from the immutable image configuration.
    Image,
    /// Resolved from the source platform's defaults.
    Platform,
    /// Observed from the active runtime, rather than inferred from desired configuration.
    Observed,
}

/// Closed reasons for unavailable observations, without arbitrary diagnostic text or values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SavedUnknownReason {
    /// The historical source did not record this distinction.
    NotRecorded,
    /// No authoritative active observation exists for the source.
    NotObserved,
    /// A resource change has not reached a confirmed stable state.
    Converging,
}

/// A recorded field. `None` on the containing struct means it was omitted altogether.
///
/// In particular, `Value(false)`, `Value(0)`, and an empty list/map remain explicit
/// values; `Default` selects the field's documented default, while `Unknown` must
/// not be treated as a confirmed source setting. Pending fields use the same type
/// but are never inputs to the saved-default resolver.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum SavedValue<T> {
    /// The source deliberately used this field's default behavior.
    // An empty struct variant is intentional: Serde's internally tagged unit
    // variants ignore extra fields even with deny_unknown_fields on the enum.
    Default {},
    /// The active value cannot be established safely.
    Unknown {
        /// Why active observation is unavailable.
        reason: SavedUnknownReason,
    },
    /// A concrete value, including explicit false, zero or empty collections.
    Value {
        /// Typed portable data; never a raw host configuration object.
        value: T,
        /// How capture established this value, not an archive-supplied safety decision.
        origin: SavedOrigin,
    },
}

/// Ordinary literal text or a logical destination binding. Resolved secrets are never literals.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SavedText {
    /// Declared ordinary text allowed by capture policy and exclusion controls.
    Literal {
        /// Exact text; no expansion, source-host lookup, or implicit execution on restore.
        value: String,
    },
    /// A logical reference resolved at the consumer's activation boundary.
    Binding {
        /// Opaque identifier in the config's binding inventory, not a host path or URL.
        id: String,
    },
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<T> SavedValue<T> {
    /// Borrow only a confirmed concrete value; no defaulting of unknown observations.
    pub fn value(&self) -> Option<&T> {
        match self {
            Self::Value { value, .. } => Some(value),
            Self::Default {} | Self::Unknown { .. } => None,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<T> fmt::Debug for SavedValue<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Ordinary literals can contain sensitive content too. Logging a configuration
        // must not become an accidental second export channel for env, argv or scripts.
        match self {
            Self::Default {} => formatter.write_str("Default"),
            Self::Unknown { reason } => formatter.debug_tuple("Unknown").field(reason).finish(),
            Self::Value { origin, .. } => formatter
                .debug_struct("Value")
                .field("origin", origin)
                .finish_non_exhaustive(),
        }
    }
}

impl fmt::Debug for SavedText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Literal { .. } => formatter.write_str("Literal(..)"),
            Self::Binding { .. } => formatter.write_str("Binding(..)"),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// `serde(default)` handles absence; a present null must not collapse into that same state.
pub(super) fn deserialize_present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concrete_zero_false_and_empty_are_not_defaults_or_unknown() {
        for json in [
            r#"{"state":"value","value":0,"origin":"observed"}"#,
            r#"{"state":"value","value":false,"origin":"configured"}"#,
            r#"{"state":"value","value":[],"origin":"image"}"#,
            r#"{"state":"value","value":{},"origin":"platform"}"#,
        ] {
            let parsed: SavedValue<serde_json::Value> = serde_json::from_str(json).unwrap();
            assert!(parsed.value().is_some());
        }
        assert!(SavedValue::<bool>::Default {}.value().is_none());
        assert!(
            SavedValue::<bool>::Unknown {
                reason: SavedUnknownReason::Converging
            }
            .value()
            .is_none()
        );
    }

    #[test]
    fn state_tags_do_not_accept_hidden_values_or_authorization() {
        for json in [
            r#"{"state":"default","value":"secret"}"#,
            r#"{"state":"unknown","reason":"not_observed","value":"secret"}"#,
            r#"{"state":"value","value":"plain","origin":"host_secret"}"#,
            r#"{"state":"value","value":"plain","origin":"configured","safe_to_apply":true}"#,
            r#"{"state":"value","origin":"configured"}"#,
        ] {
            assert!(serde_json::from_str::<SavedValue<String>>(json).is_err());
        }
        assert!(
            serde_json::from_str::<SavedText>(
                r#"{"kind":"binding","id":"token","value":"secret"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn debug_does_not_export_values_or_binding_identifiers() {
        let literal = SavedText::Literal {
            value: "SENTINEL_CREDENTIAL".into(),
        };
        let binding = SavedText::Binding {
            id: "SENTINEL_BINDING".into(),
        };
        let recorded = SavedValue::Value {
            value: literal.clone(),
            origin: SavedOrigin::Configured,
        };
        assert!(!format!("{literal:?} {binding:?} {recorded:?}").contains("SENTINEL"));
    }
}

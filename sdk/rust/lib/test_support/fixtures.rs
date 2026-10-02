//! Previous fixture decoding for SDK tests. Production reads use ordinary serde.

use microsandbox_db::compat as db_compat;
use serde_json::{Value, json};

use crate::test_support::json::UniqueValue;
use crate::{MicrosandboxError, MicrosandboxResult, SandboxConfig};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn decode(input: &str) -> MicrosandboxResult<SandboxConfig> {
    let UniqueValue(mut value) =
        serde_json::from_str(input).map_err(|_| unsupported("invalid JSON or duplicate field"))?;
    to_current(&mut value)?;
    let config: SandboxConfig = serde_json::from_value(value.clone())
        .map_err(|_| unsupported("unrecognized configuration shape"))?;
    let roundtrip = serde_json::to_value(&config)?;
    preserve_values(&value, &roundtrip, "config")?;
    Ok(config)
}

fn unsupported(reason: &str) -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(format!(
        "unsupported persisted sandbox configuration: {reason}"
    ))
}

fn to_current(value: &mut Value) -> MicrosandboxResult<()> {
    db_compat::config::to_current(value).map_err(unsupported)
}

fn preserve_values(input: &Value, output: &Value, path: &str) -> MicrosandboxResult<()> {
    match (input, output) {
        (Value::Object(input), Value::Object(output)) => {
            for (key, value) in input {
                let actual = output.get(key).unwrap_or(&Value::Null);
                preserve_values(value, actual, &format!("{path}.{key}"))?;
            }
        }
        (Value::Array(input), Value::Array(output)) if input.len() == output.len() => {
            for (index, (value, actual)) in input.iter().zip(output).enumerate() {
                preserve_values(value, actual, &format!("{path}[{index}]"))?;
            }
        }
        (input, output) if input == output => {}
        _ => return Err(unsupported(&format!("field {path} cannot be preserved"))),
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests: Decoding
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const FLOOR: &str = include_str!("../db/fixtures/config-0.6.0.json");
    const SNAKE: &str = include_str!("../db/fixtures/config-0.6.5.json");
    const TYPED: &str = include_str!("../db/fixtures/config-0.6.9.json");
    const LATEST: &str = include_str!("../db/fixtures/config-0.6.18.json");

    // Captured from sandboxes created by the released 0.6.18 Python SDK and
    // runtime. The only secret value is synthetic test material.
    #[test]
    fn released_secret_configurations_decode() {
        for raw in [
            include_str!("../db/fixtures/config-0.6.18-secret-default.json"),
            include_str!("../db/fixtures/config-0.6.18-global-passthrough.json"),
            // Hand-extended released fixture: inheritance, blocking override, and entry passthrough.
            include_str!("../db/fixtures/config-0.6.18-global-passthrough-with-entries.json"),
            include_str!("../db/fixtures/config-0.6.18-secret-passthrough.json"),
        ] {
            let original: Value = serde_json::from_str(raw).unwrap();
            let config = decode(raw).unwrap();
            assert_eq!(config.spec.name, original["name"].as_str().unwrap());
            assert_eq!(
                config.spec.network.secrets.as_ref().unwrap().secrets.len(),
                original["network"]["secrets"]["secrets"]
                    .as_array()
                    .unwrap()
                    .len()
            );
        }
    }

    #[test]
    fn typed_secret_conversion_does_not_hide_unknown_saved_fields() {
        for location in [
            "/network/secrets",
            "/network/secrets/secrets/0",
            "/network/secrets/secrets/0/injection",
            "/network/secrets/secrets/0/source",
        ] {
            let mut value: Value = serde_json::from_str(include_str!(
                "../db/fixtures/config-0.6.18-secret-default.json"
            ))
            .unwrap();
            value["network"]["secrets"]["secrets"][0]["source"] = json!({"kind":"env","var":"KEY"});
            value
                .pointer_mut(location)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("future_policy".into(), json!("synthetic-private"));
            let error = decode(&value.to_string()).unwrap_err().to_string();
            assert!(error.contains("cannot be preserved"), "{error}");
            assert!(!error.contains("synthetic-private"));
        }
    }

    #[test]
    fn released_configs_decode_without_losing_resources_or_mounts() {
        for raw in [FLOOR, SNAKE, TYPED, LATEST] {
            let config = decode(raw).unwrap();
            assert_eq!(config.spec.name, "catalog-fixture");
            assert_eq!(config.spec.resources.cpus, 1);
            assert_eq!(config.spec.resources.memory_mib, 256);
            assert_eq!(config.spec.mounts.len(), 1);
            let Value::Object(value) = serde_json::to_value(&config).unwrap() else {
                unreachable!()
            };
            assert_eq!(value["image"]["Oci"]["root_disk"]["size_mib"], 4096);
        }
        assert_eq!(decode(SNAKE).unwrap().spec.resources.max_cpus, 2);
    }

    #[test]
    fn duplicate_policy_keys_are_rejected_before_normalization() {
        let raw = LATEST.replace("\"strict\": false", "\"strict\": true, \"strict\": false");
        assert_ne!(raw, LATEST);
        assert!(decode(&raw).unwrap_err().to_string().contains("duplicate"));
        // The same rule applies inside arrays, and errors must not expose keys.
        let error = decode(r#"{"mounts":[{"private-key":1,"private-key":2}]}"#)
            .unwrap_err()
            .to_string();
        assert!(error.contains("duplicate"));
        assert!(!error.contains("private-key"));
    }

    #[test]
    fn strict_authority_policy_is_never_silently_disabled() {
        let mut raw: Value = serde_json::from_str(LATEST).unwrap();
        raw["network"]["strict"] = Value::Bool(true);
        let decoded = decode(&raw.to_string()).unwrap();
        assert_eq!(
            serde_json::to_value(decoded).unwrap()["network"]["strict"],
            Value::Bool(true)
        );
    }

    #[test]
    fn unknown_policies_and_conflicting_aliases_are_never_dropped() {
        let mut value: Value = serde_json::from_str(SNAKE).unwrap();
        value["network"]["future_policy"] = json!({"secret":"must-not-appear"});
        let error = decode(&value.to_string()).unwrap_err().to_string();
        assert!(error.contains("future_policy"));
        assert!(!error.contains("must-not-appear"));
        value["network"]
            .as_object_mut()
            .unwrap()
            .remove("future_policy");
        value["resources"]["cpus"] = json!(3);
        assert!(
            decode(&value.to_string())
                .unwrap_err()
                .to_string()
                .contains("conflicting")
        );
    }
}

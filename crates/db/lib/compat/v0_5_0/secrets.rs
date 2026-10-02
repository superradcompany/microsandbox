//! Saved secret-policy conversion for database downgrades.

use microsandbox_types::{SecretsConfig, compat as types_compat};
use serde_json::Value;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Convert the previous policy inside a saved configuration.
/// The policy shape is shared with launch payloads, so reuse its types adapter.
pub fn to_current(value: &mut Value) -> Result<(), &'static str> {
    if let Some(secrets) = value
        .pointer_mut("/network/secrets")
        .filter(|value| !value.is_null())
    {
        types_compat::v0_5_0::local::secrets::to_current(
            secrets.as_object_mut().ok_or("invalid secrets object")?,
        )?;
    }
    Ok(())
}

/// Convert saved secret policies to the format introduced in v0.5.0,
/// also used by v0.6, preserving other fields.
pub fn to_previous_version(raw: &str) -> Result<Option<String>, &'static str> {
    let mut value: Value = serde_json::from_str(raw).map_err(|_| "invalid configuration JSON")?;
    let Some(secrets) = value
        .pointer_mut("/network/secrets")
        .filter(|v| !v.is_null())
    else {
        return Ok(None);
    };
    let current = secrets.get("violation_action").is_some()
        || secrets.get("passthrough_hosts").is_some()
        || secrets
            .get("secrets")
            .or_else(|| secrets.get("entries"))
            .and_then(Value::as_array)
            .is_some_and(|entries| {
                entries.iter().any(|entry| {
                    entry.get("substitution").is_some()
                        || entry.get("violation_action").is_some()
                        || entry.get("passthrough_hosts").is_some()
                })
            });
    // Records already in the previous format retain their exact bytes and independent
    // header/Basic Auth switches; downgrade must not reconvert them.
    if !current {
        return Ok(None);
    }
    let original = secrets.clone();
    let fields = secrets.as_object_mut().ok_or("invalid secrets object")?;
    types_compat::v0_5_0::local::secrets::to_current(fields)?;
    let expected: SecretsConfig =
        serde_json::from_value(secrets.clone()).map_err(|_| "invalid secret policy")?;
    let canonical = serde_json::to_value(expected).map_err(|_| "invalid secret policy")?;
    if !preserves(secrets, &canonical) {
        return Err("secret policy contains fields unsupported by the downgrade codec");
    }
    // Serialize defaults explicitly so previous defaults cannot enable scopes.
    *secrets = canonical.clone();
    types_compat::v0_5_0::local::secrets::to_previous_version(
        secrets.as_object_mut().ok_or("invalid secrets object")?,
    )?;
    let mut roundtrip = secrets.clone();
    types_compat::v0_5_0::local::secrets::to_current(
        roundtrip.as_object_mut().ok_or("invalid secrets object")?,
    )?;
    let restored: SecretsConfig =
        serde_json::from_value(roundtrip).map_err(|_| "invalid converted policy")?;
    if serde_json::to_value(restored).map_err(|_| "invalid converted policy")? != canonical {
        return Err("secret policy cannot be preserved in v0.6");
    }
    if *secrets == original {
        return Ok(None);
    }
    serde_json::to_string(&value)
        .map(Some)
        .map_err(|_| "invalid configuration JSON")
}

fn preserves(input: &Value, output: &Value) -> bool {
    match (input, output) {
        (Value::Object(input), Value::Object(output)) => input
            .iter()
            .all(|(key, value)| preserves(value, output.get(key).unwrap_or(&Value::Null))),
        (Value::Array(input), Value::Array(output)) => {
            input.len() == output.len() && input.iter().zip(output).all(|(a, b)| preserves(a, b))
        }
        _ => input == output,
    }
}

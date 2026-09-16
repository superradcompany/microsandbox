//! In-memory translation of persisted v0.6.x sandbox configuration.
//!
//! Decoding never rewrites the original catalog. Check every supplied value
//! against the typed result so an unrecognized historical policy cannot be
//! silently discarded by serde's default handling of unknown fields.

use serde_json::{Map, Value, json};

use crate::{MicrosandboxError, MicrosandboxResult, SandboxConfig};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn decode(input: &str) -> MicrosandboxResult<SandboxConfig> {
    let super::json::UniqueValue(mut value) =
        serde_json::from_str(input).map_err(|_| unsupported("invalid JSON or duplicate field"))?;
    normalize(&mut value)?;
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

fn rename(object: &mut Map<String, Value>, old: &str, new: &str) -> MicrosandboxResult<()> {
    if let Some(value) = object.remove(old)
        && object.insert(new.to_owned(), value).is_some()
    {
        return Err(unsupported("conflicting historical and current fields"));
    }
    Ok(())
}

pub(super) fn normalize(value: &mut Value) -> MicrosandboxResult<()> {
    let object = value
        .as_object_mut()
        .ok_or_else(|| unsupported("expected an object"))?;
    if let Some(image) = object.get_mut("image").and_then(Value::as_object_mut) {
        for (old, new) in [
            ("oci", "Oci"),
            ("bind", "Bind"),
            ("disk_image", "DiskImage"),
        ] {
            rename(image, old, new)?;
        }
        if let Some(bind) = image.get_mut("Bind")
            && let Some(path) = bind.as_str()
        {
            *bind = json!({"path": path, "follow_root_symlinks": false});
        }
        if let Some(oci) = image.get_mut("Oci").and_then(Value::as_object_mut)
            && let Some(size) = oci.remove("upper_size_mib")
        {
            // A legacy null uses the historical default managed root size.
            // Preserve explicit sizes; never replace a requested disk kind.
            if oci.contains_key("root_disk") {
                return Err(unsupported("conflicting root-disk representations"));
            }
            if !size.is_null() {
                oci.insert(
                    "root_disk".into(),
                    json!({"kind":"managed", "size_mib":size}),
                );
            }
        }
    }
    if let Some(resources) = object.get_mut("resources").and_then(Value::as_object_mut) {
        rename(resources, "vcpus", "cpus")?;
        rename(resources, "max_vcpus", "max_cpus")?;
    }
    if let Some(mounts) = object.get_mut("mounts").and_then(Value::as_array_mut) {
        for mount in mounts {
            let Some(old) = mount.as_object_mut() else {
                continue;
            };
            if old.contains_key("type") {
                continue;
            }
            let variants = [
                ("bind", "Bind"),
                ("named", "Named"),
                ("tmpfs", "Tmpfs"),
                ("disk_image", "DiskImage"),
            ];
            if let Some((key, tag)) = variants.into_iter().find(|(key, _)| old.contains_key(*key)) {
                if old.len() != 1 {
                    return Err(unsupported("ambiguous mount representation"));
                }
                let mut fields = old
                    .remove(key)
                    .and_then(|value| value.as_object().cloned())
                    .ok_or_else(|| unsupported("invalid mount fields"))?;
                if fields.insert("type".into(), json!(tag)).is_some() {
                    return Err(unsupported("conflicting mount tag"));
                }
                *mount = Value::Object(fields);
            }
        }
    }
    if let Some(policy) = object.get_mut("pull_policy") {
        match policy.as_str() {
            Some("if_missing") => *policy = json!("IfMissing"),
            Some("always") => *policy = json!("Always"),
            Some("never") => *policy = json!("Never"),
            _ => {}
        }
    }
    if let Some(secrets) = object
        .get_mut("network")
        .and_then(|network| network.get_mut("secrets"))
        .and_then(Value::as_object_mut)
    {
        rename(secrets, "entries", "secrets")?;
        rename(secrets, "on_violation", "violation_action")?;
        if let Some(entries) = secrets.get_mut("secrets").and_then(Value::as_array_mut) {
            for entry in entries {
                if let Some(entry) = entry.as_object_mut() {
                    rename(entry, "injection", "substitution")?;
                    rename(entry, "on_violation", "violation_action")?;
                }
            }
        }
        if let Some(policy) = secrets.get_mut("violation_action")
            && policy.as_str() == Some("block_and_log")
        {
            *policy = json!("block-and-log");
        }
    }
    Ok(())
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
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const FLOOR: &str = include_str!("fixtures/config-0.6.0.json");
    const SNAKE: &str = include_str!("fixtures/config-0.6.5.json");
    const TYPED: &str = include_str!("fixtures/config-0.6.9.json");
    const LATEST: &str = include_str!("fixtures/config-0.6.18.json");

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

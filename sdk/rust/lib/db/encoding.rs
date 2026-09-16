//! Preserve a catalog record's historical JSON representation when changing it.

use serde_json::{Value, json};

use super::config::decode;
use crate::{MicrosandboxError, MicrosandboxResult, SandboxConfig};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Apply only semantic changes to the original document. Defaults introduced by
/// the current SDK must not materialize new fields in an older CLI's catalog.
pub(crate) fn encode_like(config: &SandboxConfig, original: &str) -> MicrosandboxResult<String> {
    let before = serde_json::to_value(decode(original)?)?;
    let after = serde_json::to_value(config)?;
    if before == after {
        return Ok(original.to_owned());
    }
    let raw: Value = serde_json::from_str(original)?;
    let mut normalized = raw.clone();
    super::config::normalize(&mut normalized)?;
    if raw == before {
        return Ok(serde_json::to_string(config)?);
    }
    let mut changed = apply_changes(&normalized, &before, &after, "config")?;
    restore_representation(&mut changed, &raw)?;
    let encoded = serde_json::to_string(&changed)?;
    if serde_json::to_value(decode(&encoded)?)? != after {
        return Err(unavailable("configuration does not round trip"));
    }
    Ok(encoded)
}

fn unavailable(path: &str) -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(format!(
        "the existing catalog format cannot represent this change ({path}); preserve the older CLI's catalog or explicitly upgrade it before using this feature"
    ))
}

fn apply_changes(
    original: &Value,
    before: &Value,
    after: &Value,
    path: &str,
) -> MicrosandboxResult<Value> {
    if before == after {
        return Ok(original.clone());
    }
    // These open maps and string/value lists have the same representation in
    // every supported release. Other collections retain their original shape.
    if matches!(
        path,
        "config.labels"
            | "config.env"
            | "config.runtime.scripts"
            | "config.runtime.cmd"
            | "config.runtime.entrypoint"
    ) {
        return Ok(after.clone());
    }
    match (original, before, after) {
        (Value::Object(original), Value::Object(before), Value::Object(after)) => {
            let mut result = original.clone();
            for (key, next) in after {
                let previous = before.get(key).unwrap_or(&Value::Null);
                if previous == next {
                    continue;
                }
                let child_path = format!("{path}.{key}");
                if !original.contains_key(key) && path == "config.resources" {
                    let boot = match key.as_str() {
                        "max_cpus" => Some("cpus"),
                        "max_memory_mib" => Some("memory_mib"),
                        _ => None,
                    };
                    if boot.is_some_and(|boot| after.get(boot) == Some(next)) {
                        continue;
                    }
                }
                let stored = original.get(key).ok_or_else(|| unavailable(&child_path))?;
                result.insert(
                    key.clone(),
                    apply_changes(stored, previous, next, &child_path)?,
                );
            }
            for key in before.keys().filter(|key| !after.contains_key(*key)) {
                result.remove(key);
            }
            Ok(Value::Object(result))
        }
        (Value::Array(original), Value::Array(before), Value::Array(after))
            if original.len() == before.len() && before.len() == after.len() =>
        {
            original
                .iter()
                .zip(before)
                .zip(after)
                .enumerate()
                .map(|(index, ((stored, previous), next))| {
                    apply_changes(stored, previous, next, &format!("{path}[{index}]"))
                })
                .collect::<MicrosandboxResult<Vec<_>>>()
                .map(Value::Array)
        }
        (Value::Array(_), _, _) | (Value::Object(_), _, _) => Err(unavailable(path)),
        _ => Ok(after.clone()),
    }
}

fn restore_representation(value: &mut Value, original: &Value) -> MicrosandboxResult<()> {
    if original.get("network").and_then(|v| v.get("strict")) == Some(&Value::Bool(false)) {
        value["network"]["strict"] = Value::Bool(false);
    }
    if let Some(old_secrets) = original.get("network").and_then(|v| v.get("secrets"))
        && let Some(secrets) = value
            .get_mut("network")
            .and_then(|v| v.get_mut("secrets"))
            .and_then(Value::as_object_mut)
    {
        if old_secrets.get("on_violation").is_some()
            && let Some(action) = secrets.remove("violation_action")
        {
            secrets.insert("on_violation".into(), action);
        }
        if let (Some(entries), Some(old_entries)) = (
            secrets.get_mut("secrets").and_then(Value::as_array_mut),
            old_secrets
                .get("secrets")
                .or_else(|| old_secrets.get("entries"))
                .and_then(Value::as_array),
        ) {
            for (entry, old) in entries.iter_mut().zip(old_entries) {
                if let Some(entry) = entry.as_object_mut() {
                    for (current, legacy) in [
                        ("substitution", "injection"),
                        ("violation_action", "on_violation"),
                    ] {
                        if old.get(legacy).is_some()
                            && let Some(value) = entry.remove(current)
                        {
                            entry.insert(legacy.into(), value);
                        }
                    }
                }
            }
        }
    }
    let snake = original
        .get("resources")
        .is_some_and(|v| v.get("vcpus").is_some());
    let old_image = original.get("image").and_then(Value::as_object);
    if let Some(image) = value.get_mut("image").and_then(Value::as_object_mut) {
        if let Some(oci) = image.get_mut("Oci").and_then(Value::as_object_mut)
            && old_image
                .and_then(|v| v.get(if snake { "oci" } else { "Oci" }))
                .is_some_and(|v| v.get("upper_size_mib").is_some())
            && let Some(root) = oci.remove("root_disk")
        {
            if root.get("kind").and_then(Value::as_str) != Some("managed") {
                return Err(unavailable("image root disk kind"));
            }
            oci.insert("upper_size_mib".into(), root["size_mib"].clone());
        }
        if let Some(bind) = image.get_mut("Bind")
            && old_image
                .and_then(|v| v.get(if snake { "bind" } else { "Bind" }))
                .is_some_and(Value::is_string)
        {
            if bind.get("follow_root_symlinks").and_then(Value::as_bool) == Some(true) {
                return Err(unavailable("follow_root_symlinks"));
            }
            *bind = bind["path"].clone();
        }
        if snake {
            for (current, old) in [
                ("Oci", "oci"),
                ("Bind", "bind"),
                ("DiskImage", "disk_image"),
            ] {
                if let Some(v) = image.remove(current) {
                    image.insert(old.into(), v);
                }
            }
        }
    }
    if snake {
        if let Some(resources) = value.get_mut("resources").and_then(Value::as_object_mut) {
            for (current, old) in [("cpus", "vcpus"), ("max_cpus", "max_vcpus")] {
                if let Some(v) = resources.remove(current) {
                    resources.insert(old.into(), v);
                }
            }
        }
        if let Some(mounts) = value.get_mut("mounts").and_then(Value::as_array_mut) {
            for mount in mounts {
                let fields = mount.as_object_mut().ok_or_else(|| unavailable("mount"))?;
                let tag = fields
                    .remove("type")
                    .ok_or_else(|| unavailable("mount type"))?;
                let key = match tag.as_str() {
                    Some("Bind") => "bind",
                    Some("Named") => "named",
                    Some("Tmpfs") => "tmpfs",
                    Some("DiskImage") => "disk_image",
                    _ => return Err(unavailable("mount type")),
                };
                *mount = json!({key: fields});
            }
        }
        if let Some(policy) = value.get_mut("pull_policy") {
            *policy = match policy.as_str() {
                Some("IfMissing") => json!("if_missing"),
                Some("Always") => json!("always"),
                Some("Never") => json!("never"),
                _ => return Err(unavailable("pull policy")),
            };
        }
        if let Some(secrets) = value
            .get_mut("network")
            .and_then(|v| v.get_mut("secrets"))
            .and_then(Value::as_object_mut)
        {
            if let Some(entries) = secrets.remove("secrets") {
                secrets.insert("entries".into(), entries);
            }
            if secrets.get("on_violation").and_then(Value::as_str) == Some("block-and-log") {
                secrets.insert("on_violation".into(), json!("block_and_log"));
            }
        }
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unchanged_records_keep_exact_bytes_and_changes_keep_historical_shape() {
        for original in [
            include_str!("fixtures/config-0.6.0.json"),
            include_str!("fixtures/config-0.6.5.json"),
            include_str!("fixtures/config-0.6.9.json"),
            include_str!("fixtures/config-0.6.18.json"),
        ] {
            let mut config = decode(original).unwrap();
            assert_eq!(encode_like(&config, original).unwrap(), original);
            config.spec.resources.memory_mib = 384;
            if serde_json::from_str::<Value>(original).unwrap()["resources"]
                .get("max_memory_mib")
                .is_none()
            {
                config.spec.resources.max_memory_mib = 384;
            }
            config.spec.labels.insert("test".into(), "kept".into());
            let encoded = encode_like(&config, original).unwrap();
            let raw: Value = serde_json::from_str(original).unwrap();
            let next: Value = serde_json::from_str(&encoded).unwrap();
            assert_eq!(next["image"], raw["image"]);
            assert_eq!(next["mounts"], raw["mounts"]);
            assert_eq!(next["pull_policy"], raw["pull_policy"]);
            assert_eq!(decode(&encoded).unwrap().spec.resources.memory_mib, 384);
        }
    }

    #[test]
    fn new_resource_feature_is_refused_in_floor_record() {
        let original = include_str!("fixtures/config-0.6.0.json");
        let mut config = decode(original).unwrap();
        config.spec.resources.max_cpus = 4;
        assert!(
            encode_like(&config, original)
                .unwrap_err()
                .to_string()
                .contains("max_cpus")
        );
    }
}

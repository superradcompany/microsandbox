//! Released configuration spellings and capabilities, independent of example values.

use serde_json::{Value, json};

use super::config::decode;
use crate::{MicrosandboxError, MicrosandboxResult, SandboxConfig};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct HistoricalFormat {
    pub patch: u64,
    pub snake: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl HistoricalFormat {
    pub(super) fn for_patch(patch: u64) -> Self {
        Self {
            patch,
            snake: (5..=6).contains(&patch),
        }
    }

    pub(super) fn encode(self, config: &SandboxConfig) -> MicrosandboxResult<String> {
        let expected = serde_json::to_value(config)?;
        let mut value = expected.clone();
        // Only fields in the released contract are emitted. Dropping a field is
        // permitted only when the final semantic roundtrip proves it was inert.
        retain(
            &mut value,
            &[
                "name",
                "image",
                "resources",
                "runtime",
                "env",
                "labels",
                "rlimits",
                "mounts",
                "patches",
                "network",
                "vsock",
                "init",
                "pull_policy",
                "security_profile",
                "deployment_profile",
                "lifecycle",
                "manifest_digest",
            ],
        );
        let resources = &mut value["resources"];
        retain(
            resources,
            &[
                "cpus",
                "memory_mib",
                "max_cpus",
                "max_memory_mib",
                "cpu_placement",
                "placement_profile",
                "thp",
            ],
        );
        if self.patch < 4 {
            remove(resources, "max_cpus");
            remove(resources, "max_memory_mib");
        }
        if self.patch < 9 {
            for key in ["cpu_placement", "placement_profile", "thp"] {
                remove(resources, key);
            }
            remove(&mut value, "vsock");
            remove(&mut value, "deployment_profile");
        }
        let network = &mut value["network"];
        retain(
            network,
            &[
                "enabled",
                "interface",
                "ports",
                "policy",
                "dns",
                "tls",
                "strict",
                "secrets",
                "max_connections",
                "rate_limiter",
                "trust_host_cas",
                "outbound_proxy",
            ],
        );
        if self.patch < 18 {
            remove(network, "strict");
        }
        if self.patch < 9 {
            remove(network, "rate_limiter");
        }
        if self.patch < 17 {
            remove(network, "outbound_proxy");
        }
        if let Some(secrets) = network.get_mut("secrets") {
            rename(secrets, "violation_action", "on_violation");
            if let Some(entries) = secrets.get_mut("secrets").and_then(Value::as_array_mut) {
                for entry in entries {
                    remove(entry, "passthrough_hosts");
                    if let Some(substitution) = entry.get_mut("substitution") {
                        remove(substitution, "query");
                    }
                    rename(entry, "substitution", "injection");
                    rename(entry, "violation_action", "on_violation");
                }
            }
            if self.snake {
                rename(secrets, "secrets", "entries");
                if secrets["on_violation"] == "block-and-log" {
                    secrets["on_violation"] = json!("block_and_log");
                }
            }
        }
        if let Some(mounts) = value["mounts"].as_array_mut() {
            for mount in mounts {
                let historical = match mount["type"].as_str() {
                    Some("Bind") => "bind",
                    Some("Named") => "named",
                    Some("Tmpfs") => "tmpfs",
                    Some("DiskImage") => "disk_image",
                    _ => return Err(unavailable("config.mounts.type")),
                };
                if self.patch < 15 {
                    remove(&mut mount["options"], "override_uid");
                    remove(&mut mount["options"], "override_gid");
                }
                if self.patch < 7 {
                    remove(mount, "follow_root_symlinks");
                }
                if self.snake {
                    remove(mount, "type");
                    *mount = json!({historical: mount.clone()});
                }
            }
        }
        let image = &mut value["image"];
        if self.patch < 9
            && image.pointer("/Oci/root_disk/kind").and_then(Value::as_str) == Some("flat")
        {
            return Err(unavailable("config.image.root_disk.flat"));
        }
        if self.patch < 7 {
            if let Some(oci) = image.get_mut("Oci") {
                let root = remove(oci, "root_disk").unwrap_or(Value::Null);
                if !root.is_null() && root["kind"] != "managed" {
                    return Err(unavailable("config.image.root_disk"));
                }
                oci["upper_size_mib"] = root.get("size_mib").cloned().unwrap_or(Value::Null);
            }
            if let Some(bind) = image.get_mut("Bind") {
                if bind["follow_root_symlinks"] == true {
                    return Err(unavailable("config.image.follow_root_symlinks"));
                }
                *bind = bind["path"].clone();
            }
        }
        if self.snake {
            for (new, old) in [
                ("Oci", "oci"),
                ("Bind", "bind"),
                ("DiskImage", "disk_image"),
            ] {
                rename(image, new, old);
            }
            rename(&mut value["resources"], "cpus", "vcpus");
            rename(&mut value["resources"], "max_cpus", "max_vcpus");
            value["pull_policy"] = match value["pull_policy"].as_str() {
                Some("IfMissing") => json!("if_missing"),
                Some("Always") => json!("always"),
                Some("Never") => json!("never"),
                _ => return Err(unavailable("config.pull_policy")),
            };
        }
        let encoded = serde_json::to_string(&value)?;
        let actual = serde_json::to_value(decode(&encoded)?)?;
        if let Some(path) = difference(&expected, &actual, "config") {
            return Err(unavailable(&path));
        }
        Ok(encoded)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn retain(value: &mut Value, keys: &[&str]) {
    if let Some(object) = value.as_object_mut() {
        object.retain(|key, _| keys.contains(&key.as_str()));
    }
}

fn remove(value: &mut Value, key: &str) -> Option<Value> {
    value.as_object_mut().and_then(|object| object.remove(key))
}

fn rename(value: &mut Value, new: &str, old: &str) {
    if let Some(field) = remove(value, new) {
        value[old] = field;
    }
}

fn difference(expected: &Value, actual: &Value, path: &str) -> Option<String> {
    if expected == actual {
        return None;
    }
    if let (Some(expected), Some(actual)) = (expected.as_object(), actual.as_object()) {
        for key in expected.keys().chain(actual.keys()) {
            if let Some(path) = difference(
                expected.get(key).unwrap_or(&Value::Null),
                actual.get(key).unwrap_or(&Value::Null),
                &format!("{path}.{key}"),
            ) {
                return Some(path);
            }
        }
    }
    Some(path.to_owned())
}

fn unavailable(path: &str) -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(format!(
        "the existing catalog format cannot represent {path}; upgrade the installed msb runtime before using this feature"
    ))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn released_formats_accept_zero_one_and_multiple_mounts() {
        for (patch, original) in [
            (0, include_str!("fixtures/config-0.6.0.json")),
            (5, include_str!("fixtures/config-0.6.5.json")),
            (9, include_str!("fixtures/config-0.6.9.json")),
            (18, include_str!("fixtures/config-0.6.18.json")),
        ] {
            let mut config = decode(original).unwrap();
            let mount = config.spec.mounts[0].clone();
            for count in [0, 1, 3] {
                config.spec.mounts = vec![mount.clone(); count];
                let encoded = HistoricalFormat::for_patch(patch).encode(&config).unwrap();
                assert_eq!(decode(&encoded).unwrap().spec.mounts.len(), count);
            }
        }
    }

    #[test]
    fn unrepresentable_fields_are_not_silently_dropped() {
        let mut config = decode(include_str!("fixtures/config-0.6.0.json")).unwrap();
        config.spec.resources.max_cpus = 4;
        assert!(
            HistoricalFormat::for_patch(0)
                .encode(&config)
                .unwrap_err()
                .to_string()
                .contains("max_cpus")
        );
        let mut config = decode(include_str!("fixtures/config-0.6.18.json")).unwrap();
        config.spec.network.max_udp_connections = Some(50);
        assert!(
            HistoricalFormat::for_patch(18)
                .encode(&config)
                .unwrap_err()
                .to_string()
                .contains("max_udp_connections")
        );
    }

    #[test]
    fn collections_are_encoded_from_the_request_not_fixture_shapes() {
        for patch in [0, 4, 5, 6, 7, 9, 15, 16, 17, 18] {
            let base = decode(include_str!("fixtures/config-0.6.0.json")).unwrap();
            for count in [0, 1, 4] {
                let mut value = serde_json::to_value(&base).unwrap();
                value["env"] = json!(
                    (0..count)
                        .map(|index| json!({
                            "key": format!("APP_{index}"), "value": format!("value-{index}")
                        }))
                        .collect::<Vec<_>>()
                );
                let rule = json!({
                    "direction": "egress", "destination": {"group": "public"},
                    "protocols": ["tcp"], "ports": [], "action": "allow"
                });
                value["network"]["policy"]["rules"] = json!(vec![rule; count]);
                value["labels"] = json!({"app": "new-app", "role": "worker"});
                let config: SandboxConfig = serde_json::from_value(value).unwrap();
                let encoded = HistoricalFormat::for_patch(patch).encode(&config).unwrap();
                assert_eq!(
                    serde_json::to_value(decode(&encoded).unwrap()).unwrap(),
                    serde_json::to_value(config).unwrap(),
                    "patch {patch}, collection length {count}"
                );
            }
        }
    }
}

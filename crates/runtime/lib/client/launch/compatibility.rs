//! Decode historical launch JSON at the process boundary.

use std::path::{Path, PathBuf};

use serde_json::Value;

use super::LaunchConfig;

#[path = "json.rs"]
mod json;
#[path = "legacy_bootstrap.rs"]
mod legacy_bootstrap;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn decode(bytes: &[u8]) -> Result<LaunchConfig, String> {
    let json::UniqueValue(mut value) = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    let fields = value
        .as_object_mut()
        .ok_or("launch config must be an object")?;
    if fields.contains_key("execution") {
        return serde_json::from_value(value).map_err(|e| e.to_string());
    }
    fields.insert("execution".into(), Value::String("boot".into()));
    let legacy = !fields.contains_key("bootstrap");
    if legacy {
        let env = serde_json::from_value(
            fields
                .remove("env")
                .ok_or("missing bootstrap or legacy env")?,
        )
        .map_err(|_| "invalid legacy launch field: env")?;
        let workdir = serde_json::from_value(fields.remove("workdir").unwrap_or(Value::Null))
            .map_err(|_| "invalid legacy launch field: workdir")?;
        let bootstrap = legacy_bootstrap::decode(env, workdir)
            .map_err(|field| format!("invalid legacy launch field: {field}"))?;
        fields.insert(
            "bootstrap".into(),
            serde_json::to_value(bootstrap).map_err(|e| e.to_string())?,
        );
    }

    // These policies arrived together in v0.6.9. Only a legacy producer that
    // omits the entire group receives the pre-policy `inherit` behavior.
    let legacy_leases = legacy
        && ["cpu_lease_dir", "writeback_lease_dir", "cpu_placement"]
            .iter()
            .all(|key| !fields.contains_key(*key));
    if legacy_leases {
        fields.insert("cpu_placement".into(), Value::String("inherit".into()));
        fields.insert("cpu_lease_dir".into(), Value::String(String::new()));
        fields.insert("writeback_lease_dir".into(), Value::String(String::new()));
    }
    #[cfg(feature = "net")]
    if let Some(network) = fields.get_mut("network") {
        if !network.is_null() && network.get("config").is_none() {
            *network = serde_json::json!({"config":network.take(), "outbound_proxy":null});
        }
        if let Some(secrets) = network
            .pointer_mut("/config/secrets")
            .and_then(Value::as_object_mut)
        {
            // Do not let serde ignore a historical security policy and apply defaults.
            rename(secrets, "entries", "secrets")?;
            rename(secrets, "on_violation", "violation_action")?;
            if let Some(entries) = secrets.get_mut("secrets").and_then(Value::as_array_mut) {
                for entry in entries {
                    if let Some(fields) = entry.as_object_mut() {
                        rename(fields, "injection", "substitution")?;
                        rename(fields, "on_violation", "violation_action")?;
                    }
                }
            }
        }
    }
    // Historical optional fields were absent before the launch contract grew.
    let defaults = serde_json::to_value(LaunchConfig::default()).map_err(|e| e.to_string())?;
    for name in [
        "file_mounts",
        "checkpoint_restore",
        "execution_restore",
        "rootfs_restore",
        "host_cid",
        "agent_transport",
        "startup_progress",
    ] {
        if !fields.contains_key(name)
            && let Some(default) = defaults.get(name)
        {
            fields.insert(name.into(), default.clone());
        }
    }
    fields.remove("env");
    fields.remove("workdir");
    let mut launch: LaunchConfig = serde_json::from_value(value).map_err(|e| e.to_string())?;
    if legacy_leases {
        let root = run_dir(&launch);
        if root.as_os_str().is_empty() {
            return Err("legacy launch configuration has no runtime artifact root".into());
        }
        launch.cpu_lease_dir = root.join("cpu-leases");
        launch.writeback_lease_dir = root.join("writeback-leases");
        launch.run_dir = root;
    }
    Ok(launch)
}

/// Use the same endpoint/home inference as the historical lifecycle guard.
fn run_dir(launch: &LaunchConfig) -> PathBuf {
    if !launch.run_dir.as_os_str().is_empty() {
        return launch.run_dir.clone();
    }
    if let Some(agent_dir) = launch.agent_sock.parent()
        && agent_dir.file_name().is_some_and(|name| name == "agent")
        && let Some(root) = agent_dir.parent()
        && root != Path::new("")
    {
        return root.to_path_buf();
    }
    launch
        .sandboxes_dir
        .parent()
        .filter(|home| !home.as_os_str().is_empty())
        .map(|home| home.join(microsandbox_utils::RUN_SUBDIR))
        .unwrap_or_default()
}

#[cfg(feature = "net")]
fn rename(fields: &mut serde_json::Map<String, Value>, old: &str, new: &str) -> Result<(), String> {
    if let Some(value) = fields.remove(old)
        && fields.insert(new.into(), value).is_some()
    {
        return Err("conflicting historical and current network policy fields".into());
    }
    Ok(())
}

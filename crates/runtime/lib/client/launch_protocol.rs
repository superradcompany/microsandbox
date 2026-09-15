//! Versioned SDK/process launch codecs, independent of package versions.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::launch::{ExecutionIntent, LaunchConfig};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Side-effect-free response to `msb __launch-protocol`.
#[derive(Debug, Serialize, Deserialize)]
pub struct LaunchCapabilities {
    /// Supported wire generations: 1 is the v0.6.17 boot contract; 2 adds explicit intent.
    pub protocols: Vec<u32>,
}

/// Selected launch format. Releases predating the probe need two legacy feature boundaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaunchProtocol {
    /// Strict `machine` contract with boot and restore intent.
    Current,
    /// Boot-only `sandbox` contract used before v0.7.0.
    Legacy {
        /// v0.6.16 introduced isolated host-file mounts.
        file_mounts: bool,
        /// v0.6.17 introduced resolved network envelopes, proxies, and strict policy.
        resolved_network: bool,
    },
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LaunchProtocol {
    /// The internal command belonging to this wire generation.
    pub fn command(self) -> &'static str {
        match self {
            Self::Current => "machine",
            Self::Legacy { .. } => "sandbox",
        }
    }

    /// Encode only representable behavior; never let legacy readers ignore restore intent.
    pub fn encode(self, config: &LaunchConfig) -> Result<Vec<u8>, String> {
        let bytes = serde_json::to_vec(config).map_err(|e| e.to_string())?;
        LaunchConfig::decode(&bytes)?;
        let Self::Legacy {
            file_mounts,
            resolved_network,
        } = self
        else {
            return Ok(bytes);
        };
        if config.execution != ExecutionIntent::Boot {
            return Err(upgrade_required("checkpoint restore or branch"));
        }
        if !config.rootfs.disk_layers.is_empty() || !config.rootfs.upper_layers.is_empty() {
            return Err(upgrade_required("checkpoint disk chains"));
        }
        if !file_mounts && !config.file_mounts.is_empty() {
            return Err(upgrade_required("isolated host-file mounts"));
        }
        let mut value: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        let object = value
            .as_object_mut()
            .expect("LaunchConfig serializes as an object");
        // These fields describe capabilities absent in legacy runtimes. The guards above
        // reject requested behavior; only optional checkpoint bookkeeping is discarded.
        object.remove("execution");
        object.remove("checkpoint_restore");
        object.remove("memory_cache_dir");
        let root = object["rootfs"].as_object_mut().expect("rootfs object");
        root.remove("disk_layers");
        root.remove("upper_layers");
        root.remove("disk_runtime_owned");
        if !file_mounts {
            object.remove("file_mounts");
        }
        if !resolved_network
            && let Some(network) = object.get_mut("network").filter(|v| !v.is_null())
        {
            let flat = &network["config"];
            if flat["strict"] == true
                || !flat["outbound_proxy"].is_null()
                || !network["outbound_proxy"].is_null()
            {
                return Err(upgrade_required(
                    "strict network policy or outbound proxies",
                ));
            }
            *network = flat.clone();
        }
        serde_json::to_vec(&value).map_err(|e| e.to_string())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Decode the legacy boot entry point without weakening the strict modern decoder.
pub fn decode_legacy(bytes: &[u8]) -> Result<LaunchConfig, String> {
    let mut value: Value =
        serde_json::from_slice(bytes).map_err(|e| format!("invalid legacy launch config: {e}"))?;
    let object = value
        .as_object_mut()
        .ok_or("legacy launch config must be an object")?;
    // Never reinterpret a malformed modern/restore request as an implicit legacy boot.
    if object.contains_key("execution") || object.contains_key("checkpoint_restore") {
        return Err("legacy sandbox launcher accepts boot-only payloads; use machine for explicit execution intent".into());
    }
    object.insert("execution".into(), Value::String("boot".into()));
    // Pre-v0.6.17 SDKs send a flat network object. Preserve all its policy values;
    // deserializing that object directly as NetworkConfig at the wrong level defaults them.
    if let Some(network) = object.get_mut("network").filter(|v| !v.is_null())
        && network.get("config").is_none()
    {
        *network = serde_json::json!({"config": network.clone(), "outbound_proxy": null});
    }
    let config = LaunchConfig::decode(&serde_json::to_vec(&value).map_err(|e| e.to_string())?)?;
    if !config.rootfs.disk_layers.is_empty() || !config.rootfs.upper_layers.is_empty() {
        return Err("legacy sandbox launcher does not accept checkpoint disk chains".into());
    }
    Ok(config)
}

/// A consistent, actionable refusal for features that cannot be downgraded.
pub fn upgrade_required(feature: &str) -> String {
    format!(
        "selected msb runtime does not support {feature}; upgrade msb in the configured home or select a newer runtime explicitly"
    )
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const LEGACY: LaunchProtocol = LaunchProtocol::Legacy {
        file_mounts: true,
        resolved_network: true,
    };

    #[cfg(feature = "net")]
    #[test]
    fn released_sdk_payload_preserves_deny_all_policy() {
        for bytes in [
            include_bytes!("../../tests/fixtures/launch-v0.6.18.json").as_slice(),
            include_bytes!("../../tests/fixtures/launch-v0.6.10.json").as_slice(),
        ] {
            let config = decode_legacy(bytes).unwrap();
            assert_eq!(config.execution, ExecutionIntent::Boot);
            assert_eq!(
                config.db_path,
                std::path::PathBuf::from("/compat-home/db/msb.db")
            );
            let network = serde_json::to_value(config.network.unwrap()).unwrap();
            assert_eq!(network["config"]["policy"]["default_egress"], "deny");
            assert_eq!(network["config"]["policy"]["default_ingress"], "deny");
        }
    }

    #[test]
    fn legacy_boot_round_trip_keeps_paths_and_startup() {
        let config = LaunchConfig {
            agent_sock: "/tmp/agent.sock".into(),
            ..Default::default()
        };
        let bytes = LEGACY.encode(&config).unwrap();
        assert!(LaunchConfig::decode(&bytes).is_err());
        assert_eq!(decode_legacy(&bytes).unwrap().agent_sock, config.agent_sock);
        assert!(
            !serde_json::from_slice::<Value>(&bytes)
                .unwrap()
                .as_object()
                .unwrap()
                .contains_key("execution")
        );
    }

    #[test]
    fn modern_payload_cannot_be_reinterpreted_as_legacy() {
        let bytes = serde_json::to_vec(&LaunchConfig::default()).unwrap();
        assert!(decode_legacy(&bytes).unwrap_err().contains("boot-only"));
        let mut value: Value =
            serde_json::from_slice(&LEGACY.encode(&LaunchConfig::default()).unwrap()).unwrap();
        value["checkpoint_restore"] = Value::Null;
        assert!(decode_legacy(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn disk_chains_cannot_be_silently_dropped() {
        let mut config = LaunchConfig::default();
        config
            .rootfs
            .disk_layers
            .push(super::super::launch::RootfsUpperLayerConfig {
                path: "/tmp/disk".into(),
                format: "qcow2".into(),
            });
        assert!(LEGACY.encode(&config).unwrap_err().contains("upgrade msb"));
    }

    #[test]
    fn legacy_codec_refuses_valid_restore_and_new_file_mount_features() {
        let config = LaunchConfig {
            execution: ExecutionIntent::Restore,
            checkpoint_restore: Some(super::super::launch::CheckpointRestoreConfig {
                closure: "/tmp/checkpoint".into(),
                checkpoint_root: "blake3:root".into(),
                checkpoint_id: "saved".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(LEGACY.encode(&config).unwrap_err().contains("upgrade msb"));
        assert!(LaunchProtocol::Current.encode(&config).is_ok());
        let config = LaunchConfig {
            file_mounts: vec![super::super::launch::FileMountConfig {
                mount: "tag:/tmp/file".into(),
                filename: "file".into(),
            }],
            ..Default::default()
        };
        let old = LaunchProtocol::Legacy {
            file_mounts: false,
            resolved_network: false,
        };
        assert!(
            old.encode(&config)
                .unwrap_err()
                .contains("isolated host-file mounts")
        );
        assert!(LEGACY.encode(&config).is_ok());
    }

    #[cfg(feature = "net")]
    #[test]
    fn flat_network_round_trip_preserves_disabled_network() {
        let mut value = serde_json::to_value(LaunchConfig::default()).unwrap();
        value["network"] =
            serde_json::json!({"config": {"enabled": false}, "outbound_proxy": null});
        let config: LaunchConfig = serde_json::from_value(value).unwrap();
        let bytes = LaunchProtocol::Legacy {
            file_mounts: false,
            resolved_network: false,
        }
        .encode(&config)
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap()["network"]["enabled"],
            false
        );
        assert!(
            !decode_legacy(&bytes)
                .unwrap()
                .network
                .unwrap()
                .config()
                .enabled
        );
    }
}

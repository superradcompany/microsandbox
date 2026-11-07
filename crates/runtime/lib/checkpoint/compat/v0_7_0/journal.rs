//! Bounded historical journal shapes. Source authorization belongs to migration.

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Layer {
    pub layer_id: String,
    pub path: PathBuf,
    pub format: String,
    pub integrity_root: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RootJournal {
    pub schema: String,
    pub volume_id: String,
    pub device_id: String,
    #[serde(default = "managed")]
    pub layout: String,
    pub published_generation: u64,
    #[serde(default)]
    pub launch_base: Option<PathBuf>,
    #[serde(default)]
    pub growth_target: Option<u64>,
    pub layers: Vec<Layer>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnedJournal {
    pub schema: String,
    pub volume_id: String,
    pub device_id: String,
    pub launch_base: PathBuf,
    pub read_only: bool,
    pub generation: u64,
    pub layers: Vec<Layer>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RootJournal {
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let value: Self =
            serde_json::from_slice(bytes).map_err(|_| "invalid legacy root journal")?;
        if value.schema != "microsandbox.runtime-root-disk/1"
            || !valid_id(&value.volume_id, "vol")
            || !matches!(
                (value.layout.as_str(), value.device_id.as_str()),
                ("managed-upper", "vdb") | ("flat-root", "vda")
            )
        {
            return Err("unsupported legacy root journal identity".into());
        }
        validate_layers(&value.layers)?;
        Ok(value)
    }
}

impl OwnedJournal {
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let value: Self =
            serde_json::from_slice(bytes).map_err(|_| "invalid legacy owned-disk journal")?;
        if value.schema != "microsandbox.runtime-owned-disk/1" || !valid_id(&value.volume_id, "vol")
        {
            return Err("unsupported legacy owned-disk journal identity".into());
        }
        validate_layers(&value.layers)?;
        Ok(value)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn managed() -> String {
    "managed-upper".into()
}

fn valid_id(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .and_then(|v| v.strip_prefix('_'))
        .is_some_and(|v| {
            v.len() == 32
                && v.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

fn validate_layers(layers: &[Layer]) -> Result<(), String> {
    let mut ids = BTreeSet::new();
    let mut paths = BTreeSet::new();
    if layers.is_empty() || layers.len() > 256 {
        return Err("legacy chain exceeds its layer bound".into());
    }
    for (index, layer) in layers.iter().enumerate() {
        if !valid_id(&layer.layer_id, "layer")
            || !ids.insert(&layer.layer_id)
            || !paths.insert(&layer.path)
            || !matches!(layer.format.as_str(), "raw" | "qcow2")
            || (index > 0 && layer.format != "qcow2")
        {
            return Err("legacy chain has invalid or duplicate layers".into());
        }
    }
    Ok(())
}

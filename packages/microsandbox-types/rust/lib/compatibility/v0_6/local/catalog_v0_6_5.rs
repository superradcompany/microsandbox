//! Alternate secret catalog spelling used by v0.6.5 and v0.6.6.

use serde::{Serialize, Serializer};
use serde_json::{Map, Value};

use super::secrets::{HistoricalAction, HistoricalEntry, historical, object};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The v0.6.5–v0.6.6 catalog used `entries` and an underscored default action.
#[derive(Serialize)]
struct CatalogConfigV0_6_5 {
    entries: Vec<HistoricalEntry>,
    #[serde(serialize_with = "serialize_catalog_v0_6_5_action")]
    on_violation: HistoricalAction,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Restore the alternate catalog spelling used by v0.6.5 and v0.6.6.
pub fn encode(fields: &mut Map<String, Value>) -> Result<(), &'static str> {
    let config = historical(fields)?;
    *fields = object(CatalogConfigV0_6_5 {
        entries: config.secrets,
        on_violation: config.on_violation,
        extra: config.extra,
    })?;
    Ok(())
}

fn serialize_catalog_v0_6_5_action<S: Serializer>(
    action: &HistoricalAction,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match action {
        HistoricalAction::BlockAndLog => serializer.serialize_str("block_and_log"),
        _ => action.serialize(serializer),
    }
}

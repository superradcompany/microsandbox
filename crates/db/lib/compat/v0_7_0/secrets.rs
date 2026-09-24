//! Saved secret-policy contract introduced in v0.7.0.

use microsandbox_types::compat as types_compat;
use serde_json::Value;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Prepare a saved policy for the contract used by released v0.7.0-v0.7.2 SDKs.
/// Supported records need no rewrite. Reject defaults this contract cannot preserve.
pub fn to_previous_version(raw: &str) -> Result<Option<String>, &'static str> {
    let value: Value = serde_json::from_str(raw).map_err(|_| "invalid configuration JSON")?;
    let Some(policy) = value
        .pointer("/network/secrets")
        .filter(|value| !value.is_null())
    else {
        return Ok(None);
    };
    let mut fields = policy.as_object().ok_or("invalid secrets object")?.clone();
    // Recognize both persisted spellings without changing the source record.
    types_compat::v0_5_0::local::secrets::to_current(&mut fields)?;
    if fields
        .get("passthrough_hosts")
        .is_some_and(|hosts| !hosts.is_null())
    {
        return Err(
            "v0.7.0-v0.7.2 cannot preserve global secret passthrough defaults; choose a runtime version that supports them",
        );
    }
    Ok(None)
}

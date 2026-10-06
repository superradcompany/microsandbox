//! Saved secret-policy contract introduced in v0.7.3.

use serde_json::Value;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Check policies for v0.7.3-v0.7.6 without rewriting them.
/// These releases support global passthrough defaults but not header restrictions.
pub fn to_previous_version(raw: &str) -> Result<Option<String>, &'static str> {
    let value: Value = serde_json::from_str(raw).map_err(|_| "invalid configuration JSON")?;

    if let Some(policy) = value
        .pointer("/network/secrets")
        .filter(|value| !value.is_null())
    {
        crate::compat::secrets::reject_scoped_header_fields(policy)?;
    }

    Ok(None)
}

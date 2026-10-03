//! Compatibility for sandbox configurations persisted in the local SQLite database.

use serde_json::Value;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Reject a saved secret policy that scopes header substitution to specific
/// field names while header substitution is enabled.
///
/// The allowlist was added to the current build; every released v0.6 and
/// v0.7.0-v0.7.2 runtime deserializes secret substitution leniently and would
/// drop the field, silently substituting the placeholder in every header.
/// Those targets must refuse the downgrade rather than lose the restriction.
/// When `headers` is false the list is inert, so dropping it cannot widen the
/// policy and must not block an otherwise safe downgrade.
/// The policy may use either the current (`substitution`) or historical
/// (`injection`) spelling.
pub(crate) fn reject_scoped_header_fields(policy: &Value) -> Result<(), &'static str> {
    let Some(entries) = policy
        .get("secrets")
        .or_else(|| policy.get("entries"))
        .and_then(Value::as_array)
    else {
        return Ok(());
    };
    for entry in entries {
        let Some(scopes) = entry
            .get("substitution")
            .or_else(|| entry.get("injection"))
            .and_then(Value::as_object)
        else {
            continue;
        };
        // Missing `headers` means the current default of true.
        let headers_enabled = scopes
            .get("headers")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        if headers_enabled
            && scopes
                .get("header_fields")
                .and_then(Value::as_array)
                .is_some_and(|fields| !fields.is_empty())
        {
            return Err(
                "secret header-field substitution scope requires a runtime that supports it; choose a newer runtime version",
            );
        }
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub mod config;
/// Saved policies using the original secret contract.
pub mod v0_5_0;
/// Previous image, resource and mount representations.
pub mod v0_6_5;
/// Saved policies using the substitution contract.
pub mod v0_7_0;

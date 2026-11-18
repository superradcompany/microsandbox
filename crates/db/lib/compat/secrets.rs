//! Shared downgrade checks for persisted secret policies.
//!
//! Each version's adapter selects the checks its target needs.

use serde_json::Value;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Reject header restrictions that the target version cannot enforce.
///
/// Older runtimes ignore the restriction and substitute in every header.
/// Disabled header substitution is safe. Accepts both `substitution` and the
/// older `injection` field name.
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
                "secret header-field substitution scope requires a runtime that supports it; \
                choose a newer runtime version",
            );
        }
    }

    Ok(())
}

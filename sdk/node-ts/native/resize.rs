//! Lossless operation records across the JSON boundary to the TypeScript wrapper.

use microsandbox::MicrosandboxResult;
use microsandbox::sandbox::{
    ResizeOperation, SandboxModificationBuilder, SandboxModificationResult,
};
use napi::{Error, Result};
use serde_json::Value;

use crate::error::to_napi_error;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) async fn run_modify_tracked(
    builder: SandboxModificationBuilder,
    dry_run: bool,
) -> Result<String> {
    let result = if dry_run {
        SandboxModificationResult {
            plan: builder.dry_run().await.map_err(to_napi_error)?,
            resize_operations: None,
        }
    } else {
        builder
            .apply_with_resize_tracking()
            .await
            .map_err(to_napi_error)?
    };
    let operations = result
        .resize_operations
        .map(encode_operations)
        .transpose()?;
    serde_json::to_string(&serde_json::json!({
        "plan": result.plan,
        "resize_operations": operations,
    }))
    .map_err(serialization_error)
}

pub(crate) fn operations_json(result: MicrosandboxResult<Vec<ResizeOperation>>) -> Result<String> {
    let operations = encode_operations(result.map_err(to_napi_error)?)?;
    serde_json::to_string(&operations).map_err(serialization_error)
}

/// Decimal strings exist only at the Node JSON boundary. The control protocol and Rust domain
/// retain u64 values; parsing them as JavaScript numbers would silently lose operation identity.
fn encode_operations(operations: Vec<ResizeOperation>) -> Result<Value> {
    let mut value = serde_json::to_value(operations).map_err(serialization_error)?;
    for operation in value.as_array_mut().ok_or_else(invalid_operation)? {
        map_u64_fields(operation, |value| {
            value.as_u64().map(|value| Value::String(value.to_string()))
        })?;
    }
    Ok(value)
}

/// Validate the boundary representation before any control lookup or mutation. The Rust waiter
/// independently checks the immutable fields against the runtime; caller bytes are never evidence.
pub(crate) fn parse_operations(raw: &str) -> Result<Vec<ResizeOperation>> {
    let mut value: Value = serde_json::from_str(raw).map_err(|_| invalid_operation())?;
    let list = value.as_array_mut().ok_or_else(invalid_operation)?;
    if list.is_empty() || list.len() > 2 {
        return Err(Error::from_reason("expected one or two resize operations"));
    }
    for operation in list {
        map_u64_fields(operation, |value| {
            let value = value.as_str()?;
            // Reject numeric JSON and signed/noncanonical spellings instead of repairing a
            // potentially rounded generation supplied by a JavaScript caller.
            let parsed = value.parse::<u64>().ok()?;
            (parsed.to_string() == value).then(|| Value::from(parsed))
        })?;
    }
    serde_json::from_value(value).map_err(|_| invalid_operation())
}

fn map_u64_fields(operation: &mut Value, convert: impl Fn(&Value) -> Option<Value>) -> Result<()> {
    let fields = operation.as_object_mut().ok_or_else(invalid_operation)?;
    let generation = fields.get_mut("generation").ok_or_else(invalid_operation)?;
    *generation = convert(generation).ok_or_else(invalid_operation)?;
    for key in ["requested_target", "accepted_target"] {
        let target = fields
            .get_mut(key)
            .and_then(Value::as_object_mut)
            .ok_or_else(invalid_operation)?;
        if target.get("resource").and_then(Value::as_str) == Some("memory") {
            let total = target.get_mut("total_mib").ok_or_else(invalid_operation)?;
            *total = convert(total).ok_or_else(invalid_operation)?;
        }
    }
    Ok(())
}

fn invalid_operation() -> Error {
    Error::from_reason("invalid resize operation record; u64 fields must be exact decimal strings")
}

fn serialization_error(error: serde_json::Error) -> Error {
    Error::from_reason(error.to_string())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> ResizeOperation {
        serde_json::from_value(serde_json::json!({
            "id": "operation-a", "runtime_boot_id": "run-a", "generation": u64::MAX,
            "requested_target": { "resource": "memory", "total_mib": u64::MAX },
            "accepted_target": { "resource": "memory", "total_mib": 514 },
            "status": { "resource": "memory", "requested": "514 MiB", "actual": "256 MiB",
                "enforced": "256 MiB", "state": "converging" },
            "outcome": "pending", "observation": "paused"
        }))
        .unwrap()
    }

    #[test]
    fn operation_round_trip_preserves_all_u64_fields() {
        let original = record();
        let value = encode_operations(vec![original.clone()]).unwrap();
        assert_eq!(value[0]["generation"], u64::MAX.to_string());
        assert_eq!(
            value[0]["requested_target"]["total_mib"],
            u64::MAX.to_string()
        );
        assert_eq!(
            parse_operations(&value.to_string()).unwrap(),
            vec![original]
        );
    }

    #[test]
    fn malformed_or_rounded_records_fail_before_dispatch() {
        for raw in ["[]", "null", "{}", "[{}]", "[{}, {}, {}]"] {
            assert!(parse_operations(raw).is_err(), "{raw}");
        }
        let record = encode_operations(vec![record()]).unwrap();
        for generation in [
            serde_json::json!(u64::MAX),
            serde_json::json!("18446744073709551616"),
            serde_json::json!("-1"),
            serde_json::json!("01"),
        ] {
            let mut invalid = record.clone();
            invalid[0]["generation"] = generation;
            assert!(parse_operations(&invalid.to_string()).is_err());
        }
        let mut invalid = record;
        invalid[0]["outcome"] = "unknown-outcome".into();
        assert!(parse_operations(&invalid.to_string()).is_err());
    }
}

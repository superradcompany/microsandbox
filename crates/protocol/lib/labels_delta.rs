//! Bounded, host-private desired-configuration changes for negotiated label updates.

use serde::{Deserialize, Serialize};
use serde_json::Value;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const MAX_EDITS: usize = 4096;
const MAX_DEPTH: usize = 64;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

// Explicit operations distinguish removing a member from assigning JSON null. Paths
// contain object keys, not JSON Pointer strings: slashes and tildes remain literal.
#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Edit {
    Set { path: Vec<String>, value: Value },
    Remove { path: Vec<String> },
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Encode only changed fields. Diagnostics never contain source configuration values.
pub fn between(before: &str, after: &str) -> Result<String, &'static str> {
    let before: Value = serde_json::from_str(before).map_err(|_| "invalid delta source")?;
    let after: Value = serde_json::from_str(after).map_err(|_| "invalid delta target")?;
    if !before.is_object() || !after.is_object() {
        return Err("configuration delta requires objects");
    }
    let mut edits = Vec::new();
    if collect(&before, &after, &mut Vec::new(), &mut edits).is_err() {
        // Bound traversal without imposing a new limit on existing configuration
        // updates. A rare oversized delta can still carry one fenced replacement.
        edits = vec![Edit::Set {
            path: Vec::new(),
            value: after,
        }];
    }
    serde_json::to_string(&edits).map_err(|_| "cannot encode configuration delta")
}

/// Apply a delta to a private copy; the caller must fence the exact source at commit.
pub fn apply(before: &str, encoded: &str) -> Result<String, &'static str> {
    let mut value: Value = serde_json::from_str(before).map_err(|_| "invalid delta source")?;
    let edits: Vec<Edit> =
        serde_json::from_str(encoded).map_err(|_| "invalid configuration delta")?;
    if !value.is_object() || edits.len() > MAX_EDITS {
        return Err("invalid configuration delta bounds");
    }
    for edit in edits {
        let path = match &edit {
            Edit::Set { path, .. } | Edit::Remove { path } => path,
        };
        if path.is_empty() {
            match edit {
                Edit::Set {
                    value: replacement, ..
                } if replacement.is_object() => {
                    value = replacement;
                    continue;
                }
                _ => return Err("invalid configuration delta root"),
            }
        }
        if path.len() > MAX_DEPTH {
            return Err("invalid configuration delta path");
        }
        let mut parent = &mut value;
        for key in &path[..path.len() - 1] {
            parent = parent
                .as_object_mut()
                .and_then(|object| object.get_mut(key))
                .ok_or("configuration delta parent is missing")?;
        }
        let parent = parent
            .as_object_mut()
            .ok_or("configuration delta parent is not an object")?;
        let key = path.last().unwrap().clone();
        match edit {
            Edit::Set { value, .. } => {
                parent.insert(key, value);
            }
            Edit::Remove { .. } => {
                parent
                    .remove(&key)
                    .ok_or("configuration delta member is missing")?;
            }
        }
    }
    serde_json::to_string(&value).map_err(|_| "cannot encode delta result")
}

fn collect(
    before: &Value,
    after: &Value,
    path: &mut Vec<String>,
    edits: &mut Vec<Edit>,
) -> Result<(), &'static str> {
    if before == after {
        return Ok(());
    }
    if path.len() > MAX_DEPTH || edits.len() >= MAX_EDITS {
        return Err("configuration delta exceeds bounds");
    }
    if let (Some(before), Some(after)) = (before.as_object(), after.as_object()) {
        for key in before.keys().filter(|key| !after.contains_key(*key)) {
            path.push(key.clone());
            edits.push(Edit::Remove { path: path.clone() });
            path.pop();
            if edits.len() > MAX_EDITS {
                return Err("configuration delta exceeds bounds");
            }
        }
        for (key, value) in after {
            path.push(key.clone());
            if let Some(old) = before.get(key) {
                collect(old, value, path, edits)?;
            } else {
                edits.push(Edit::Set {
                    path: path.clone(),
                    value: value.clone(),
                });
            }
            path.pop();
            if edits.len() > MAX_EDITS {
                return Err("configuration delta exceeds bounds");
            }
        }
    } else {
        edits.push(Edit::Set {
            path: path.clone(),
            value: after.clone(),
        });
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn many_changed_fields_use_one_fenced_replacement() {
        let after: serde_json::Map<String, Value> = (0..MAX_EDITS + 1)
            .map(|index| (index.to_string(), json!(index)))
            .collect();
        let after = Value::Object(after);
        let encoded = between("{}", &after.to_string()).unwrap();
        let edits: Vec<Edit> = serde_json::from_str(&encoded).unwrap();
        assert_eq!(edits.len(), 1);
        assert_eq!(
            serde_json::from_str::<Value>(&apply("{}", &encoded).unwrap()).unwrap(),
            after
        );
    }

    #[test]
    fn unchanged_large_script_is_never_transmitted_and_mixed_changes_round_trip() {
        let before = json!({"runtime":{"scripts":{"large":"x".repeat(5 * 1024 * 1024)},"cmd":["old"]},"labels":{"gone":"old"},"nullable":false,"remove":1});
        let mut after = before.clone();
        after["runtime"]["cmd"] = json!(["new"]);
        after["labels"] = json!({"a/b~c":"value"});
        after["nullable"] = Value::Null;
        after.as_object_mut().unwrap().remove("remove");
        let delta = between(&before.to_string(), &after.to_string()).unwrap();
        assert!(delta.len() < 1024);
        assert!(!delta.contains("scripts"));
        assert_eq!(
            serde_json::from_str::<Value>(&apply(&before.to_string(), &delta).unwrap()).unwrap(),
            after
        );
    }

    #[test]
    fn invalid_paths_and_excessive_operations_fail_without_diagnostics_leaking_values() {
        for delta in [
            json!([{"op":"set","path":[],"value":"PRIVATE"}]),
            json!([{"op":"set","path":["missing","child"],"value":"PRIVATE"}]),
            json!([{"op":"remove","path":["missing"]}]),
            Value::Array(vec![
                json!({"op":"set","path":["x"],"value":null});
                MAX_EDITS + 1
            ]),
        ] {
            let error = apply("{}", &delta.to_string()).unwrap_err();
            assert!(!error.contains("PRIVATE"));
        }
    }
}

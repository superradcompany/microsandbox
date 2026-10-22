//! Operation-bound resize conversion. No Python-side retry or latest-operation substitution.

use microsandbox::sandbox::{
    ResizeOperation, SandboxModificationBuilder, SandboxModificationResult,
};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use crate::error::to_py_err;
use crate::helpers::str_enum_member;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Validate caller-owned records before opening a control connection. The runtime still checks
/// every identity and the Rust waiter compares immutable request fields; these bytes are not proof.
pub(crate) fn parse_operations(
    py: Python<'_>,
    operations: &Bound<'_, PyAny>,
) -> PyResult<Vec<ResizeOperation>> {
    let list = operations.downcast::<PyList>()?;
    if list.is_empty() || list.len() > 2 {
        return Err(PyValueError::new_err(
            "expected one or two resize operations",
        ));
    }
    let encoded: String = py
        .import("json")?
        .call_method1("dumps", (list,))?
        .extract()?;
    serde_json::from_str(&encoded)
        .map_err(|_| PyValueError::new_err("invalid resize operation record"))
}

pub(crate) async fn run_modify_tracked(
    builder: SandboxModificationBuilder,
    dry_run: bool,
) -> PyResult<PyObject> {
    let result = if dry_run {
        SandboxModificationResult {
            plan: builder.dry_run().await.map_err(to_py_err)?,
            resize_operations: None,
        }
    } else {
        builder
            .apply_with_resize_tracking()
            .await
            .map_err(to_py_err)?
    };
    Python::with_gil(|py| {
        let dict = PyDict::new(py);
        let plan = serde_json::to_value(result.plan).map_err(invalid_serialization)?;
        dict.set_item("plan", crate::sandbox::modification_plan_to_py(py, plan)?)?;
        let operations = match result.resize_operations {
            Some(operations) => operations_to_py(py, operations)?,
            None => py.None(),
        };
        dict.set_item("resize_operations", operations)?;
        Ok(dict.unbind().into())
    })
}

pub(crate) fn operations_result_to_py(
    result: microsandbox::MicrosandboxResult<Vec<ResizeOperation>>,
) -> PyResult<PyObject> {
    let operations = result.map_err(to_py_err)?;
    Python::with_gil(|py| operations_to_py(py, operations))
}

fn operations_to_py(py: Python<'_>, operations: Vec<ResizeOperation>) -> PyResult<PyObject> {
    let list = PyList::empty(py);
    for operation in operations {
        let value = serde_json::to_value(operation).map_err(invalid_serialization)?;
        let dict = PyDict::new(py);
        for (key, value) in value.as_object().ok_or_else(|| {
            PyRuntimeError::new_err("serialized resize operation must be an object")
        })? {
            let value = match key.as_str() {
                "status" => crate::sandbox::resize_status_to_py(py, value.clone())?,
                "outcome" => enum_to_py(py, value, "ResizeOutcome")?,
                "observation" => enum_to_py(py, value, "ResizeObservation")?,
                "requested_target" | "accepted_target" => {
                    let target = PyDict::new(py);
                    for (key, value) in value.as_object().ok_or_else(|| {
                        PyRuntimeError::new_err("serialized resize target must be an object")
                    })? {
                        target.set_item(
                            key,
                            if key == "resource" {
                                enum_to_py(py, value, "ResourceKind")?
                            } else {
                                crate::sandbox_handle::json_value_to_py(py, value.clone())?
                            },
                        )?;
                    }
                    target.unbind().into()
                }
                _ => crate::sandbox_handle::json_value_to_py(py, value.clone())?,
            };
            dict.set_item(key, value)?;
        }
        list.append(dict)?;
    }
    Ok(list.unbind().into())
}

fn enum_to_py(py: Python<'_>, value: &serde_json::Value, name: &str) -> PyResult<PyObject> {
    str_enum_member(
        py,
        name,
        value.as_str().ok_or_else(|| {
            PyRuntimeError::new_err("serialized resize discriminator must be a string")
        })?,
    )
}

fn invalid_serialization(error: serde_json::Error) -> PyErr {
    PyRuntimeError::new_err(error.to_string())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_operations_are_rejected_before_dispatch() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let json = py.import("json").unwrap();
            for raw in ["[]", "[{}, {}, {}]", "[{}]", "null", "{}"] {
                let value = json.call_method1("loads", (raw,)).unwrap();
                assert!(parse_operations(py, &value).is_err(), "{raw}");
            }
        });
    }

    #[test]
    fn operation_input_preserves_exact_u64_identity_and_closed_discriminators() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let json = py.import("json").unwrap();
            let raw = serde_json::json!([{
                "id": "operation-a", "runtime_boot_id": "run-a", "generation": u64::MAX,
                "requested_target": { "resource": "memory", "total_mib": 513 },
                "accepted_target": { "resource": "memory", "total_mib": 514 },
                "status": { "resource": "memory", "requested": "514 MiB", "actual": "256 MiB",
                    "enforced": "256 MiB", "state": "converging" },
                "outcome": "pending", "observation": "paused"
            }]);
            let value = json.call_method1("loads", (raw.to_string(),)).unwrap();
            let operations = parse_operations(py, &value).unwrap();
            assert_eq!(operations[0].generation, u64::MAX);
            assert_eq!(serde_json::to_value(operations).unwrap(), raw);
            let mut invalid = raw;
            invalid[0]["outcome"] = "future-unsupported-outcome".into();
            let value = json.call_method1("loads", (invalid.to_string(),)).unwrap();
            assert!(parse_operations(py, &value).is_err());
        });
    }
}

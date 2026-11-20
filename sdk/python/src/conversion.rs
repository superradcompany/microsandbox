use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyList};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn json_value_to_py(py: Python<'_>, value: serde_json::Value) -> PyResult<Py<PyAny>> {
    match value {
        serde_json::Value::Null => Ok(py.None()),
        serde_json::Value::Bool(value) => Ok(PyBool::new(py, value).to_owned().unbind().into()),
        serde_json::Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                Ok(value.into_pyobject(py)?.unbind().into())
            } else if let Some(value) = value.as_u64() {
                Ok(value.into_pyobject(py)?.unbind().into())
            } else if let Some(value) = value.as_f64() {
                Ok(value.into_pyobject(py)?.unbind().into())
            } else {
                Ok(py.None())
            }
        }
        serde_json::Value::String(value) => Ok(value.into_pyobject(py)?.unbind().into()),
        serde_json::Value::Array(values) => {
            let values = values
                .into_iter()
                .map(|value| json_value_to_py(py, value))
                .collect::<PyResult<Vec<_>>>()?;
            Ok(PyList::new(py, values)?.unbind().into())
        }
        serde_json::Value::Object(values) => {
            let dict = PyDict::new(py);
            for (key, value) in values {
                dict.set_item(key, json_value_to_py(py, value)?)?;
            }
            Ok(dict.unbind().into())
        }
    }
}

pub(crate) fn parse_sandbox_status(status: &str) -> PyResult<microsandbox::sandbox::SandboxStatus> {
    match status {
        "created" => Ok(microsandbox::sandbox::SandboxStatus::Created),
        "starting" => Ok(microsandbox::sandbox::SandboxStatus::Starting),
        "running" => Ok(microsandbox::sandbox::SandboxStatus::Running),
        "draining" => Ok(microsandbox::sandbox::SandboxStatus::Draining),
        "paused" => Ok(microsandbox::sandbox::SandboxStatus::Paused),
        "stopped" => Ok(microsandbox::sandbox::SandboxStatus::Stopped),
        "crashed" => Ok(microsandbox::sandbox::SandboxStatus::Crashed),
        other => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "invalid sandbox status {other:?}"
        ))),
    }
}

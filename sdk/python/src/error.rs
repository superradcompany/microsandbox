use pyo3::prelude::*;
use pyo3::{PyErr, Python};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Error returned when a sandbox handle has been consumed (detached/removed).
pub fn consumed() -> PyErr {
    pyo3::exceptions::PyRuntimeError::new_err("sandbox has been consumed")
}

/// Convert a `microsandbox::MicrosandboxError` into a typed Python exception.
pub fn to_py_err(err: microsandbox::MicrosandboxError) -> PyErr {
    use microsandbox::MicrosandboxError::*;

    Python::with_gil(|py| {
        let errors_mod = match py.import("microsandbox.errors") {
            Ok(m) => m,
            Err(_) => return pyo3::exceptions::PyRuntimeError::new_err(err.to_string()),
        };

        let (cls_name, msg) = match &err {
            InvalidConfig(_) => ("InvalidConfigError", err.to_string()),
            SandboxNotFound(_) => ("SandboxNotFoundError", err.to_string()),
            SandboxStillRunning(_) => ("SandboxStillRunningError", err.to_string()),
            ExecTimeout(_) => ("ExecTimeoutError", err.to_string()),
            SandboxFs(_) => ("FilesystemError", err.to_string()),
            ImageNotFound(_) => ("ImageNotFoundError", err.to_string()),
            VolumeNotFound(_) => ("VolumeNotFoundError", err.to_string()),
            Io(_) => ("IoError", err.to_string()),
            Terminal(_) => ("MicrosandboxError", err.to_string()),
            _ => ("MicrosandboxError", err.to_string()),
        };

        match errors_mod.getattr(cls_name) {
            Ok(cls) => match cls.call1((msg,)) {
                Ok(instance) => PyErr::from_value(instance),
                Err(_) => pyo3::exceptions::PyRuntimeError::new_err(err.to_string()),
            },
            Err(_) => pyo3::exceptions::PyRuntimeError::new_err(err.to_string()),
        }
    })
}

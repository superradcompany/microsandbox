use microsandbox::{Operation, UnsupportedReason};
use pyo3::prelude::*;
use pyo3::{PyErr, Python};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Error returned when a sandbox handle has been consumed (detached/removed).
pub fn consumed() -> PyErr {
    pyo3::exceptions::PyRuntimeError::new_err("sandbox has been consumed")
}

/// `UnsupportedError` for shim-only entry points that require the local
/// backend but have no SDK [`Operation`] (Python-only diagnostic hooks).
pub fn local_only(name: &str) -> PyErr {
    let msg = format!("{name}() is not supported by this backend: use a local backend");
    Python::with_gil(|py| {
        let instance = py
            .import("microsandbox.errors")
            .and_then(|m| m.getattr("UnsupportedError"))
            .and_then(|cls| cls.call1((msg.as_str(),)));
        match instance {
            Ok(instance) => PyErr::from_value(instance),
            Err(_) => pyo3::exceptions::PyRuntimeError::new_err(msg),
        }
    })
}

/// Convert a `microsandbox::MicrosandboxError` into a typed Python exception.
pub fn to_py_err(err: microsandbox::MicrosandboxError) -> PyErr {
    use microsandbox::MicrosandboxError::*;

    Python::with_gil(|py| {
        let errors_mod = match py.import("microsandbox.errors") {
            Ok(m) => m,
            Err(_) => return pyo3::exceptions::PyRuntimeError::new_err(err.to_string()),
        };

        // Unsupported gets a Python-idiom message (`sandbox.kill()` instead of
        // `Sandbox::kill`) plus structured `operation` / `hint` attributes.
        if let Unsupported { op, reason } = &err {
            let operation = py_api_name(*op);
            let hint = py_hint(reason);
            let msg = format!("{operation} is not supported by this backend: {hint}");
            let instance = errors_mod
                .getattr("UnsupportedError")
                .and_then(|cls| cls.call1((msg.as_str(),)));
            return match instance {
                Ok(instance) => {
                    // Best-effort extras; the message already carries both.
                    let _ = instance.setattr("operation", operation);
                    let _ = instance.setattr("hint", hint);
                    PyErr::from_value(instance)
                }
                Err(_) => pyo3::exceptions::PyRuntimeError::new_err(msg),
            };
        }

        let (cls_name, msg) = match &err {
            InvalidConfig(_) => ("InvalidConfigError", err.to_string()),
            NoDefaultCommand => ("NoDefaultCommandError", err.to_string()),
            CloudHttp { .. } => ("CloudHttpError", err.to_string()),
            SandboxNotFound(_) => ("SandboxNotFoundError", err.to_string()),
            SandboxAlreadyExists(_) => ("SandboxAlreadyExistsError", err.to_string()),
            SandboxStillRunning(_) => ("SandboxStillRunningError", err.to_string()),
            SandboxNotRunning(_) => ("SandboxNotRunningError", err.to_string()),
            ExecTimeout(_) => ("ExecTimeoutError", err.to_string()),
            SandboxFsOps(_) => ("FilesystemError", err.to_string()),
            ImageNotFound(_) => ("ImageNotFoundError", err.to_string()),
            ImageInUse(_) => ("ImageInUseError", err.to_string()),
            VolumeNotFound(_) => ("VolumeNotFoundError", err.to_string()),
            Io(_) => ("IoError", err.to_string()),
            MetricsDisabled(_) => ("MetricsDisabledError", err.to_string()),
            MetricsUnavailable(_) => ("MetricsUnavailableError", err.to_string()),
            AgentClient(microsandbox::AgentClientError::UnsupportedOperation { .. }) => {
                ("UnsupportedOperationError", err.to_string())
            }
            Unsupported { .. } => ("UnsupportedError", err.to_string()),
            SnapshotMigration { .. } => ("SnapshotMigrationError", err.to_string()),
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

/// Render an [`Operation`] as the Python API it corresponds to:
/// `Sandbox::kill` becomes `sandbox.kill()` and `SandboxFsOps::stat_handle`
/// becomes `sandbox_fs_ops.stat_handle()`. Plain phrases without a
/// `Type::method` shape (`config`, `snapshot operations`) pass through as-is.
fn py_api_name(op: Operation) -> String {
    let path = op.api_path();
    let Some((ty, method)) = path.split_once("::") else {
        return path.to_string();
    };
    let mut name = format!("{}.{method}", camel_to_snake(ty));
    if !method.ends_with(')') {
        name.push_str("()");
    }
    name
}

/// Render an [`UnsupportedReason`] with `use instead` targets pointing at the
/// Python API name rather than the Rust path.
fn py_hint(reason: &UnsupportedReason) -> String {
    match reason {
        UnsupportedReason::UseInstead(op) => format!("use {}", py_api_name(*op)),
        other => other.hint(),
    }
}

/// Lower a `CamelCase` type name to `snake_case` (`SandboxFsOps` becomes
/// `sandbox_fs_ops`).
fn camel_to_snake(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 4);
    for (i, ch) in name.char_indices() {
        if ch.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

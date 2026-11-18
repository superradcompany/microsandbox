use std::time::Duration;

use microsandbox::{ChangeState, Operation, ServiceError, UnsupportedReason};
use pyo3::prelude::*;
use pyo3::{PyErr, Python};

use crate::helpers::str_enum_member;

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
    Python::attach(|py| {
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

    // Missing snapshot selectors are resolved when the create future is awaited, like explicit
    // artifact paths. Retain Python's useful missing-file exception without duplicating resolution.
    if let SnapshotNotFound(_) = &err {
        return pyo3::exceptions::PyFileNotFoundError::new_err(err.to_string());
    }

    Python::attach(|py| {
        let errors_mod = match py.import("microsandbox.errors") {
            Ok(m) => m,
            Err(_) => return pyo3::exceptions::PyRuntimeError::new_err(err.to_string()),
        };

        if let SnapshotSourceRecovery(recovery) = &err {
            // Keep the structured recovery locator across the native boundary. The Python class
            // turns this internal payload into typed attributes; callers never parse the message.
            let instance = (|| -> PyResult<Bound<'_, PyAny>> {
                let payload = serde_json::to_string(recovery).map_err(|error| {
                    pyo3::exceptions::PyRuntimeError::new_err(error.to_string())
                })?;
                let details = py.import("json")?.call_method1("loads", (payload,))?;
                let details = details.cast::<pyo3::types::PyDict>()?;
                errors_mod
                    .getattr("SnapshotSourceRecoveryError")?
                    .call((err.to_string(),), Some(details))
            })();
            return match instance {
                Ok(instance) => PyErr::from_value(instance),
                // The textual fallback still contains the saved artifact locator.
                Err(_) => pyo3::exceptions::PyRuntimeError::new_err(err.to_string()),
            };
        }

        if let Service { slug, error } = &err {
            // Keep the reason, retry delay and change state as typed attributes.
            let (reason, retry_after, raw_code, raw_status, raw_message) = service_reason(error);
            let changed = change_state_value(error.changed());
            let instance = (|| -> PyResult<Bound<'_, PyAny>> {
                let kwargs = pyo3::types::PyDict::new(py);
                kwargs.set_item("slug", slug)?;
                kwargs.set_item("reason", reason)?;
                kwargs.set_item("retry_after", retry_after.map(|wait| wait.as_secs_f64()))?;
                kwargs.set_item("changed", changed)?;
                kwargs.set_item("raw_code", raw_code)?;
                kwargs.set_item("raw_status", raw_status)?;
                kwargs.set_item("raw_message", raw_message)?;
                errors_mod
                    .getattr("ServiceError")?
                    .call((err.to_string(),), Some(&kwargs))
            })();
            return match instance {
                Ok(instance) => PyErr::from_value(instance),
                Err(_) => pyo3::exceptions::PyRuntimeError::new_err(err.to_string()),
            };
        }

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

        // Preserve the SDK's established Python exception mapping for missing
        // snapshot references across backends.
        if matches!(err, SnapshotNotFound(_)) {
            return pyo3::exceptions::PyFileNotFoundError::new_err(err.to_string());
        }
        if matches!(err, SnapshotIntegrity(_)) {
            return pyo3::exceptions::PyValueError::new_err(err.to_string());
        }

        let (cls_name, msg) = match &err {
            RuntimeNotInstalled(_) => ("RuntimeNotInstalledError", err.to_string()),
            RuntimeIncomplete(_) => ("RuntimeIncompleteError", err.to_string()),
            InvalidConfig(_) | MissingRestoreBindings { .. } => {
                ("InvalidConfigError", err.to_string())
            }
            NoDefaultCommand => ("NoDefaultCommandError", err.to_string()),
            CloudHttp { .. } => ("CloudHttpError", err.to_string()),
            ModificationNotConfirmed { .. } => ("ModificationNotConfirmedError", err.to_string()),
            SandboxNotFound(_) => ("SandboxNotFoundError", err.to_string()),
            SandboxAlreadyExists(_) => ("SandboxAlreadyExistsError", err.to_string()),
            SandboxReplaced { .. } => ("SandboxReplacedError", err.to_string()),
            SandboxStillRunning(_) => ("SandboxStillRunningError", err.to_string()),
            SandboxNotRunning(_) => ("SandboxNotRunningError", err.to_string()),
            SandboxStopTimedOut { .. } => ("SandboxStopTimedOutError", err.to_string()),
            ExecTimeout(_) => ("ExecTimeoutError", err.to_string()),
            StopTimeout { .. } => ("StopTimeoutError", err.to_string()),
            SandboxFsOps(_) => ("FilesystemError", err.to_string()),
            ImageNotFound(_) => ("ImageNotFoundError", err.to_string()),
            ImageInUse(_) => ("ImageInUseError", err.to_string()),
            VolumeNotFound(_) => ("VolumeNotFoundError", err.to_string()),
            ServiceNotFound(_) => ("ServiceNotFoundError", err.to_string()),
            ServiceAlreadyExists(_) => ("ServiceAlreadyExistsError", err.to_string()),
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

/// Convert a Service change error and attach its change state to the Python exception.
pub fn to_py_change_err(err: microsandbox::MicrosandboxError) -> PyErr {
    let changed = change_state_value(err.changed());
    let py_err = to_py_err(err);

    Python::attach(|py| {
        if let Ok(changed) = str_enum_member(py, "ChangeState", changed) {
            // A failed setattr leaves `changed` None, which callers treat as not a change error.
            let _ = py_err.value(py).setattr("changed", changed);
        }
    });

    py_err
}

fn service_reason(
    error: &ServiceError,
) -> (
    &'static str,
    Option<Duration>,
    Option<&str>,
    Option<u16>,
    Option<&str>,
) {
    match error {
        ServiceError::QuotaExceeded => ("service_quota_exceeded", None, None, None, None),
        ServiceError::SandboxLimitExceeded => {
            ("sandbox_service_limit_exceeded", None, None, None, None)
        }
        ServiceError::Conflict => ("service_conflict", None, None, None, None),
        ServiceError::Detached => ("service_detached", None, None, None, None),
        ServiceError::TargetUnreachable { retry_after } => {
            ("target_unreachable", *retry_after, None, None, None)
        }
        ServiceError::TargetNotRunning => ("sandbox_not_running", None, None, None, None),
        ServiceError::ChangesPaused { retry_after } => {
            ("service_changes_paused", *retry_after, None, None, None)
        }
        ServiceError::OutcomeUnknown => ("outcome_unknown", None, None, None, None),
        ServiceError::Other {
            code,
            status,
            message,
        } => ("other", None, Some(code), Some(*status), Some(message)),
        // `ServiceError` is non-exhaustive; `changed` still reports a newer reason correctly.
        _ => ("other", None, None, None, None),
    }
}

fn change_state_value(changed: ChangeState) -> &'static str {
    match changed {
        ChangeState::Unchanged => "unchanged",
        ChangeState::Unknown => "unknown",
    }
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

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Make `microsandbox.errors` importable from the source tree without the
    /// native module: an empty `microsandbox` package over the source dir.
    fn import_source_errors(py: Python<'_>) {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/microsandbox");
        let package = pyo3::types::PyModule::new(py, "microsandbox").unwrap();
        package.setattr("__path__", vec![dir]).unwrap();
        py.import("sys")
            .unwrap()
            .getattr("modules")
            .unwrap()
            .set_item("microsandbox", package)
            .unwrap();
    }

    #[test]
    fn an_unconfirmed_modification_keeps_its_class_and_message() {
        Python::initialize();
        Python::attach(|py| {
            import_source_errors(py);
            let error = microsandbox::MicrosandboxError::ModificationNotConfirmed {
                cause: "the running sandbox does not hold the secret".to_string(),
            };
            let message = error.to_string();

            let raised = to_py_err(error);
            let class = py
                .import("microsandbox.errors")
                .unwrap()
                .getattr("ModificationNotConfirmedError")
                .unwrap();
            assert!(raised.value(py).is_instance(&class).unwrap());
            assert_eq!(raised.value(py).str().unwrap().to_string(), message);
            assert_eq!(
                raised
                    .value(py)
                    .getattr("code")
                    .unwrap()
                    .extract::<String>()
                    .unwrap(),
                "modification-not-confirmed"
            );
        });
    }

    #[test]
    fn sandbox_service_limit_has_a_public_reason() {
        assert_eq!(
            service_reason(&ServiceError::SandboxLimitExceeded),
            ("sandbox_service_limit_exceeded", None, None, None, None)
        );
    }
}

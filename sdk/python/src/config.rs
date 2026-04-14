use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::helpers::build_config_from_kwargs;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Build a `SandboxConfig` from either a pre-built config dict or kwargs.
///
/// Supports two overloads:
/// - `Sandbox.create(name, **kwargs)` — builds config from kwargs
/// - `Sandbox.create(config)` — passes a pre-built config dict directly
pub fn resolve_config(
    name_or_config: &Bound<'_, PyAny>,
    kwargs: Option<&Bound<'_, PyDict>>,
) -> PyResult<microsandbox::sandbox::SandboxConfig> {
    // If the first arg is a dict, treat it as a pre-built config.
    if let Ok(config_dict) = name_or_config.downcast::<PyDict>() {
        let name: String = config_dict
            .get_item("name")?
            .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("config.name is required"))?
            .extract()?;
        return build_config_from_kwargs(name, Some(config_dict));
    }

    // Otherwise, treat it as a name string.
    let name: String = name_or_config.extract()?;
    build_config_from_kwargs(name, kwargs)
}

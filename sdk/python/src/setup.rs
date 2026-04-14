use pyo3::prelude::*;

use crate::error::to_py_err;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Download and install msb + libkrunfw to ~/.microsandbox/.
#[pyfunction]
pub fn install<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
        microsandbox::setup::install().await.map_err(to_py_err)?;
        Ok(())
    })
}

/// Check if msb and libkrunfw are installed and available.
#[pyfunction]
pub fn is_installed() -> bool {
    microsandbox::setup::is_installed()
}

//! Own the async bridge workers so Python can join them before finalization.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Mutex, OnceLock};

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3_async_runtimes::TaskLocals;
use pyo3_async_runtimes::generic::{self, ContextExt, Runtime as AsyncRuntime};
use tokio::runtime::{Builder, Handle, Runtime};
use tokio::task::{JoinError, JoinHandle};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

static RUNTIME: Mutex<RuntimeState> = Mutex::new(RuntimeState {
    runtime: None,
    closed: false,
});
// A handle does not keep a Runtime alive. Retain it so bridge tasks racing with
// shutdown are cancelled by Tokio instead of initializing a second runtime.
static HANDLE: OnceLock<Handle> = OnceLock::new();

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct RuntimeState {
    runtime: Option<Runtime>,
    closed: bool,
}

struct PythonRuntime;

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl AsyncRuntime for PythonRuntime {
    type JoinError = JoinError;
    type JoinHandle = JoinHandle<()>;

    fn spawn<F>(future: F) -> Self::JoinHandle
    where
        F: Future<Output = ()> + Send + 'static,
    {
        HANDLE
            .get()
            .expect("async bridge runtime initialized")
            .spawn(future)
    }

    fn spawn_blocking<F>(function: F) -> Self::JoinHandle
    where
        F: FnOnce() + Send + 'static,
    {
        HANDLE
            .get()
            .expect("async bridge runtime initialized")
            .spawn_blocking(function)
    }
}

impl ContextExt for PythonRuntime {
    fn scope<F, R>(locals: TaskLocals, future: F) -> Pin<Box<dyn Future<Output = R> + Send>>
    where
        F: Future<Output = R> + Send + 'static,
    {
        Box::pin(TASK_LOCALS.scope(locals, future))
    }

    fn get_task_locals() -> Option<TaskLocals> {
        TASK_LOCALS.try_with(Clone::clone).ok()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Register one exit hook per native provider, before exposing its async APIs.
pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    let shutdown = wrap_pyfunction!(_shutdown_runtime, module)?;
    module
        .py()
        .import("atexit")?
        .call_method1("register", (&shutdown,))?;
    module.add_function(shutdown)
}

/// Get an active runtime, refusing new work once interpreter shutdown starts.
pub(crate) fn get_runtime() -> PyResult<Handle> {
    let mut state = RUNTIME.lock().expect("Python runtime state poisoned");
    if state.closed {
        return Err(PyRuntimeError::new_err(
            "microsandbox async runtime has shut down",
        ));
    }
    if state.runtime.is_none() {
        let runtime = Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|error| {
                PyRuntimeError::new_err(format!("initialize async runtime: {error}"))
            })?;
        HANDLE.get_or_init(|| runtime.handle().clone());
        state.runtime = Some(runtime);
    }
    Ok(HANDLE
        .get()
        .expect("async bridge runtime initialized")
        .clone())
}

/// Preserve upstream cancellation and context propagation on the owned runtime.
pub(crate) fn future_into_py<F, T>(py: Python<'_>, future: F) -> PyResult<Bound<'_, PyAny>>
where
    F: Future<Output = PyResult<T>> + Send + 'static,
    T: for<'py> IntoPyObject<'py> + Send + 'static,
{
    get_runtime()?;
    generic::future_into_py::<PythonRuntime, F, T>(py, future)
}

#[pyfunction]
fn _shutdown_runtime(py: Python<'_>) {
    let runtime = {
        let mut state = RUNTIME.lock().expect("Python runtime state poisoned");
        state.closed = true;
        state.runtime.take()
    };
    // Native completions may already be inside Python or waiting for the GIL.
    // Release it while Runtime::drop cancels async work and joins its workers.
    // A timeout/background shutdown would let those callbacks outlive Python.
    py.detach(move || drop(runtime));
}

//--------------------------------------------------------------------------------------------------
// Macros
//--------------------------------------------------------------------------------------------------

tokio::task_local! {
    static TASK_LOCALS: TaskLocals;
}

use std::sync::Arc;

use pyo3::prelude::*;
use tokio::sync::Mutex;

use crate::error::to_py_err;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Filesystem operations on a running sandbox.
/// Holds a direct Arc<AgentClient> — no Sandbox mutex lock per operation.
#[pyclass(name = "SandboxFs")]
pub struct PySandboxFs {
    client: Arc<microsandbox::agent::AgentClient>,
}

/// Streaming reader for file data.
#[pyclass(name = "FsReadStream")]
pub struct PyFsReadStream {
    inner: Arc<Mutex<microsandbox::sandbox::FsReadStream>>,
}

/// Streaming writer for file data.
#[pyclass(name = "FsWriteSink")]
pub struct PyFsWriteSink {
    inner: Arc<Mutex<Option<microsandbox::sandbox::FsWriteSink>>>,
}

//--------------------------------------------------------------------------------------------------
// Methods: SandboxFs
//--------------------------------------------------------------------------------------------------

impl PySandboxFs {
    pub fn from_client(client: Arc<microsandbox::agent::AgentClient>) -> Self {
        Self { client }
    }
}

#[pymethods]
impl PySandboxFs {
    /// Read an entire file as bytes.
    fn read<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let client = Arc::clone(&self.client);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let fs = microsandbox::sandbox::SandboxFs::new(&client);
            let data = fs.read(&path).await.map_err(to_py_err)?;
            Ok(data.to_vec())
        })
    }

    /// Read a file as a UTF-8 string.
    fn read_text<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let client = Arc::clone(&self.client);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let fs = microsandbox::sandbox::SandboxFs::new(&client);
            let text = fs.read_to_string(&path).await.map_err(to_py_err)?;
            Ok(text)
        })
    }

    /// Read a file with streaming. Returns an async iterator of bytes chunks.
    fn read_stream<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let client = Arc::clone(&self.client);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let fs = microsandbox::sandbox::SandboxFs::new(&client);
            let stream = fs.read_stream(&path).await.map_err(to_py_err)?;
            Ok(PyFsReadStream {
                inner: Arc::new(Mutex::new(stream)),
            })
        })
    }

    /// Write data to a file (accepts str or bytes).
    fn write<'py>(
        &self,
        py: Python<'py>,
        path: String,
        data: Vec<u8>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = Arc::clone(&self.client);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let fs = microsandbox::sandbox::SandboxFs::new(&client);
            fs.write(&path, &data).await.map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Write with streaming. Returns an async context manager.
    fn write_stream<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let client = Arc::clone(&self.client);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let fs = microsandbox::sandbox::SandboxFs::new(&client);
            let sink = fs.write_stream(&path).await.map_err(to_py_err)?;
            Ok(PyFsWriteSink {
                inner: Arc::new(Mutex::new(Some(sink))),
            })
        })
    }

    /// List directory contents.
    fn list<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let client = Arc::clone(&self.client);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let fs = microsandbox::sandbox::SandboxFs::new(&client);
            let entries = fs.list(&path).await.map_err(to_py_err)?;
            let py_entries: Vec<PyFsEntry> = entries.into_iter().map(convert_fs_entry).collect();
            Ok(py_entries)
        })
    }

    /// Create a directory (and parents).
    fn mkdir<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let client = Arc::clone(&self.client);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let fs = microsandbox::sandbox::SandboxFs::new(&client);
            fs.mkdir(&path).await.map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Remove a file.
    fn remove<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let client = Arc::clone(&self.client);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let fs = microsandbox::sandbox::SandboxFs::new(&client);
            fs.remove(&path).await.map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Remove a directory recursively.
    fn remove_dir<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let client = Arc::clone(&self.client);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let fs = microsandbox::sandbox::SandboxFs::new(&client);
            fs.remove_dir(&path).await.map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Copy a file within the sandbox.
    fn copy<'py>(&self, py: Python<'py>, src: String, dst: String) -> PyResult<Bound<'py, PyAny>> {
        let client = Arc::clone(&self.client);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let fs = microsandbox::sandbox::SandboxFs::new(&client);
            fs.copy(&src, &dst).await.map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Rename a file or directory.
    fn rename<'py>(
        &self,
        py: Python<'py>,
        src: String,
        dst: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = Arc::clone(&self.client);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let fs = microsandbox::sandbox::SandboxFs::new(&client);
            fs.rename(&src, &dst).await.map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Get file/directory metadata.
    fn stat<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let client = Arc::clone(&self.client);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let fs = microsandbox::sandbox::SandboxFs::new(&client);
            let meta = fs.stat(&path).await.map_err(to_py_err)?;
            Ok(convert_fs_metadata(&meta))
        })
    }

    /// Check if a path exists.
    fn exists<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let client = Arc::clone(&self.client);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let fs = microsandbox::sandbox::SandboxFs::new(&client);
            let exists = fs.exists(&path).await.map_err(to_py_err)?;
            Ok(exists)
        })
    }

    /// Copy a file from the host into the sandbox.
    fn copy_from_host<'py>(
        &self,
        py: Python<'py>,
        host_path: String,
        guest_path: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = Arc::clone(&self.client);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let fs = microsandbox::sandbox::SandboxFs::new(&client);
            fs.copy_from_host(&host_path, &guest_path)
                .await
                .map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Copy a file from the sandbox to the host.
    fn copy_to_host<'py>(
        &self,
        py: Python<'py>,
        guest_path: String,
        host_path: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = Arc::clone(&self.client);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let fs = microsandbox::sandbox::SandboxFs::new(&client);
            fs.copy_to_host(&guest_path, &host_path)
                .await
                .map_err(to_py_err)?;
            Ok(())
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: FsReadStream
//--------------------------------------------------------------------------------------------------

#[pymethods]
impl PyFsReadStream {
    fn __aiter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __anext__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            match guard.recv().await.map_err(to_py_err)? {
                Some(chunk) => Ok(chunk.to_vec()),
                None => Err(pyo3::exceptions::PyStopAsyncIteration::new_err(())),
            }
        })
    }

    /// Collect all remaining data.
    fn collect<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            // We need to take the stream out since collect consumes self.
            let mut guard = inner.lock().await;
            let mut data = Vec::new();
            while let Some(chunk) = guard.recv().await.map_err(to_py_err)? {
                data.extend_from_slice(&chunk);
            }
            Ok(data)
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: FsWriteSink
//--------------------------------------------------------------------------------------------------

#[pymethods]
impl PyFsWriteSink {
    /// Write a chunk of data.
    fn write<'py>(&self, py: Python<'py>, data: Vec<u8>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let sink = guard
                .as_ref()
                .ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("write stream closed"))?;
            sink.write(&data).await.map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Close the stream (sends EOF).
    fn close<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            if let Some(sink) = guard.take() {
                sink.close().await.map_err(to_py_err)?;
            }
            Ok(())
        })
    }

    fn __aenter__<'py>(slf: Bound<'py, Self>) -> PyResult<Bound<'py, PyAny>> {
        let py = slf.py();
        let obj: PyObject = slf.into();
        pyo3_async_runtimes::tokio::future_into_py(py, async move { Ok(obj) })
    }

    fn __aexit__<'py>(
        &self,
        py: Python<'py>,
        _exc_type: &Bound<'py, PyAny>,
        _exc_val: &Bound<'py, PyAny>,
        _exc_tb: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            if let Some(sink) = guard.take() {
                sink.close().await.map_err(to_py_err)?;
            }
            Ok(false)
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Types: Python-exposed structs
//--------------------------------------------------------------------------------------------------

#[pyclass(name = "FsEntry")]
pub struct PyFsEntry {
    #[pyo3(get)]
    path: String,
    #[pyo3(get)]
    kind: String,
    #[pyo3(get)]
    size: u64,
    #[pyo3(get)]
    mode: u32,
    #[pyo3(get)]
    modified: Option<f64>,
}

#[pyclass(name = "FsMetadata")]
pub struct PyFsMetadata {
    #[pyo3(get)]
    kind: String,
    #[pyo3(get)]
    size: u64,
    #[pyo3(get)]
    mode: u32,
    #[pyo3(get)]
    readonly: bool,
    #[pyo3(get)]
    modified: Option<f64>,
    #[pyo3(get)]
    created: Option<f64>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn kind_str(kind: microsandbox::sandbox::FsEntryKind) -> &'static str {
    match kind {
        microsandbox::sandbox::FsEntryKind::File => "file",
        microsandbox::sandbox::FsEntryKind::Directory => "directory",
        microsandbox::sandbox::FsEntryKind::Symlink => "symlink",
        microsandbox::sandbox::FsEntryKind::Other => "other",
    }
}

pub(crate) fn convert_fs_entry(entry: microsandbox::sandbox::FsEntry) -> PyFsEntry {
    PyFsEntry {
        path: entry.path,
        kind: kind_str(entry.kind).to_string(),
        size: entry.size,
        mode: entry.mode,
        modified: entry.modified.map(|dt| dt.timestamp_millis() as f64),
    }
}

fn convert_fs_metadata(meta: &microsandbox::sandbox::FsMetadata) -> PyFsMetadata {
    PyFsMetadata {
        kind: kind_str(meta.kind).to_string(),
        size: meta.size,
        mode: meta.mode,
        readonly: meta.readonly,
        modified: meta.modified.map(|dt| dt.timestamp_millis() as f64),
        created: meta.created.map(|dt| dt.timestamp_millis() as f64),
    }
}

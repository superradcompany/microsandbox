use std::path::PathBuf;
use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use crate::error::to_py_err;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// SSH namespace for a sandbox.
#[pyclass(name = "SandboxSsh")]
pub struct PySandboxSsh {
    inner: Arc<Mutex<Option<microsandbox::sandbox::Sandbox>>>,
}

/// Output from an SSH exec request.
#[pyclass(name = "SshOutput")]
pub struct PySshOutput {
    status: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Native in-process SSH client session.
#[pyclass(name = "SshClient")]
pub struct PySshClient {
    inner: Arc<Mutex<Option<microsandbox::sandbox::SshClient>>>,
}

/// High-level SFTP client session.
#[pyclass(name = "SftpClient")]
pub struct PySftpClient {
    inner: Arc<Mutex<Option<microsandbox::sandbox::SftpClient>>>,
}

/// Reusable SSH server endpoint for a sandbox.
#[pyclass(name = "SshServer")]
pub struct PySshServer {
    inner: Arc<Mutex<Option<microsandbox::sandbox::SshServer>>>,
}

//--------------------------------------------------------------------------------------------------
// Methods: SandboxSsh
//--------------------------------------------------------------------------------------------------

impl PySandboxSsh {
    pub fn new(inner: Arc<Mutex<Option<microsandbox::sandbox::Sandbox>>>) -> Self {
        Self { inner }
    }

    async fn clone_sandbox(&self) -> PyResult<microsandbox::sandbox::Sandbox> {
        let guard = self.inner.lock().await;
        guard.as_ref().cloned().ok_or_else(crate::error::consumed)
    }
}

#[pymethods]
impl PySandboxSsh {
    /// Connect a native in-process SSH client to this sandbox.
    #[pyo3(signature = (*, user = "root".to_string(), term = None, sftp = true))]
    fn connect<'py>(
        &self,
        py: Python<'py>,
        user: String,
        term: Option<String>,
        sftp: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let ssh = Self {
            inner: self.inner.clone(),
        };
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let sandbox = ssh.clone_sandbox().await?;
            let client = sandbox
                .ssh()
                .connect_with(|builder| {
                    let mut builder = builder.user(user).sftp(sftp);
                    if let Some(term) = term {
                        builder = builder.term(term);
                    }
                    builder
                })
                .await
                .map_err(to_py_err)?;
            Ok(PySshClient::from_rust(client))
        })
    }

    /// Prepare a reusable SSH server endpoint for this sandbox.
    #[pyo3(signature = (
        *,
        host_key_path = None,
        authorized_keys_path = None,
        user = None,
        sftp = true,
    ))]
    fn server<'py>(
        &self,
        py: Python<'py>,
        host_key_path: Option<PathBuf>,
        authorized_keys_path: Option<PathBuf>,
        user: Option<String>,
        sftp: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let ssh = Self {
            inner: self.inner.clone(),
        };
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let sandbox = ssh.clone_sandbox().await?;
            let server = sandbox
                .ssh()
                .server_with(|builder| {
                    let mut builder = builder.sftp(sftp);
                    if let Some(path) = host_key_path {
                        builder = builder.host_key_path(path);
                    }
                    if let Some(path) = authorized_keys_path {
                        builder = builder.authorized_keys_path(path);
                    }
                    if let Some(user) = user {
                        builder = builder.user(user);
                    }
                    builder
                })
                .await
                .map_err(to_py_err)?;
            Ok(PySshServer::from_rust(server))
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: SshOutput
//--------------------------------------------------------------------------------------------------

impl PySshOutput {
    fn from_rust(inner: microsandbox::sandbox::SshOutput) -> Self {
        Self {
            status: inner.status,
            stdout: inner.stdout.to_vec(),
            stderr: inner.stderr.to_vec(),
        }
    }
}

#[pymethods]
impl PySshOutput {
    /// Exit status code.
    #[getter]
    fn status(&self) -> i32 {
        self.status
    }

    /// Whether the command exited successfully.
    #[getter]
    fn success(&self) -> bool {
        self.status == 0
    }

    /// Stdout as UTF-8 text.
    #[getter]
    fn stdout_text(&self) -> PyResult<String> {
        String::from_utf8(self.stdout.clone())
            .map_err(|e| pyo3::exceptions::PyUnicodeDecodeError::new_err(e.to_string()))
    }

    /// Stderr as UTF-8 text.
    #[getter]
    fn stderr_text(&self) -> PyResult<String> {
        String::from_utf8(self.stderr.clone())
            .map_err(|e| pyo3::exceptions::PyUnicodeDecodeError::new_err(e.to_string()))
    }

    /// Stdout as raw bytes.
    #[getter]
    fn stdout_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.stdout)
    }

    /// Stderr as raw bytes.
    #[getter]
    fn stderr_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.stderr)
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: SshClient
//--------------------------------------------------------------------------------------------------

impl PySshClient {
    pub fn from_rust(inner: microsandbox::sandbox::SshClient) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Some(inner))),
        }
    }
}

#[pymethods]
impl PySshClient {
    /// Run an SSH exec request and collect stdout, stderr, and exit status.
    #[pyo3(signature = (command, *, tty = false))]
    fn exec<'py>(
        &self,
        py: Python<'py>,
        command: String,
        tty: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let client = guard.as_ref().ok_or_else(crate::error::consumed)?;
            let output = client
                .exec_with(command, |builder| builder.tty(tty))
                .await
                .map_err(to_py_err)?;
            Ok(PySshOutput::from_rust(output))
        })
    }

    /// Attach the local terminal to an interactive SSH shell.
    #[pyo3(signature = (*, term = None, detach_keys = None))]
    fn attach<'py>(
        &self,
        py: Python<'py>,
        term: Option<String>,
        detach_keys: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let client = guard.as_ref().ok_or_else(crate::error::consumed)?;
            client
                .attach_with(|builder| {
                    let mut builder = builder;
                    if let Some(term) = term {
                        builder = builder.term(term);
                    }
                    if let Some(detach_keys) = detach_keys {
                        builder = builder.detach_keys(detach_keys);
                    }
                    builder
                })
                .await
                .map_err(to_py_err)
        })
    }

    /// Open an SFTP session over this SSH connection.
    fn sftp<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let client = guard.as_ref().ok_or_else(crate::error::consumed)?;
            let sftp = client.sftp().await.map_err(to_py_err)?;
            Ok(PySftpClient::from_rust(sftp))
        })
    }

    /// Close this SSH client session.
    fn close<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let client = {
                let mut guard = inner.lock().await;
                guard.take().ok_or_else(crate::error::consumed)?
            };
            client.close().await.map_err(to_py_err)?;
            Ok(())
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: SftpClient
//--------------------------------------------------------------------------------------------------

impl PySftpClient {
    pub fn from_rust(inner: microsandbox::sandbox::SftpClient) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Some(inner))),
        }
    }
}

#[pymethods]
impl PySftpClient {
    /// Read a file into memory.
    fn read<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let sftp = guard.as_ref().ok_or_else(crate::error::consumed)?;
            let data = sftp.read(path).await.map_err(sftp_py_err)?;
            Ok(Python::with_gil(|py| PyBytes::new(py, &data).unbind()))
        })
    }

    /// Write a file, creating or truncating it.
    fn write<'py>(
        &self,
        py: Python<'py>,
        path: String,
        data: Vec<u8>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let sftp = guard.as_ref().ok_or_else(crate::error::consumed)?;
            let mut file = sftp.create(path).await.map_err(sftp_py_err)?;
            file.write_all(&data).await.map_err(sftp_py_err)?;
            file.shutdown().await.map_err(sftp_py_err)?;
            Ok(())
        })
    }

    /// Create a directory.
    fn mkdir<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let sftp = guard.as_ref().ok_or_else(crate::error::consumed)?;
            sftp.create_dir(path).await.map_err(sftp_py_err)
        })
    }

    /// Remove a file.
    fn remove_file<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let sftp = guard.as_ref().ok_or_else(crate::error::consumed)?;
            sftp.remove_file(path).await.map_err(sftp_py_err)
        })
    }

    /// Remove an empty directory.
    fn remove_dir<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let sftp = guard.as_ref().ok_or_else(crate::error::consumed)?;
            sftp.remove_dir(path).await.map_err(sftp_py_err)
        })
    }

    /// Rename a file or directory.
    fn rename<'py>(
        &self,
        py: Python<'py>,
        old_path: String,
        new_path: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let sftp = guard.as_ref().ok_or_else(crate::error::consumed)?;
            sftp.rename(old_path, new_path).await.map_err(sftp_py_err)
        })
    }

    /// Resolve a path to its canonical absolute form.
    fn real_path<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let sftp = guard.as_ref().ok_or_else(crate::error::consumed)?;
            sftp.canonicalize(path).await.map_err(sftp_py_err)
        })
    }

    /// Read a symlink target.
    fn read_link<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let sftp = guard.as_ref().ok_or_else(crate::error::consumed)?;
            sftp.read_link(path).await.map_err(sftp_py_err)
        })
    }

    /// Create a symlink.
    fn symlink<'py>(
        &self,
        py: Python<'py>,
        target: String,
        link_path: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let sftp = guard.as_ref().ok_or_else(crate::error::consumed)?;
            sftp.symlink(target, link_path).await.map_err(sftp_py_err)
        })
    }

    /// Close this SFTP session.
    fn close<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let sftp = {
                let mut guard = inner.lock().await;
                guard.take().ok_or_else(crate::error::consumed)?
            };
            sftp.close().await.map_err(sftp_py_err)?;
            Ok(())
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: SshServer
//--------------------------------------------------------------------------------------------------

impl PySshServer {
    pub fn from_rust(inner: microsandbox::sandbox::SshServer) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Some(inner))),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn sftp_py_err(error: impl std::fmt::Display) -> PyErr {
    pyo3::exceptions::PyRuntimeError::new_err(format!("SFTP error: {error}"))
}

#[pymethods]
impl PySshServer {
    /// Serve one SSH transport over this process's stdin/stdout.
    fn serve_stdio<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let server = {
                let guard = inner.lock().await;
                guard.as_ref().ok_or_else(crate::error::consumed)?.clone()
            };
            server
                .serve(microsandbox::sandbox::SshStdioStream::new())
                .await
                .map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Release this prepared server endpoint.
    fn close(&self) -> PyResult<()> {
        let mut guard = self
            .inner
            .try_lock()
            .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("SSH server is busy"))?;
        guard.take().ok_or_else(crate::error::consumed)?;
        Ok(())
    }
}

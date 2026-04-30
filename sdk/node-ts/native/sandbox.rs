use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use napi::bindgen_prelude::*;
use napi_derive::napi;
use tokio::sync::Mutex;

use crate::attach_options_builder::JsAttachOptionsBuilder;
use crate::error::to_napi_error;
use crate::exec::{ExecOutput, JsExecHandle};
use crate::exec_options_builder::JsExecOptionsBuilder;
use crate::fs::JsSandboxFs;
use crate::sandbox_handle::JsSandboxHandle;
use crate::types::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A running sandbox instance.
///
/// Created via `Sandbox.create()` or `Sandbox.start()`. Holds a live connection
/// to the guest VM and can execute commands, access the filesystem, and query metrics.
#[napi]
pub struct Sandbox {
    inner: Arc<Mutex<Option<microsandbox::sandbox::Sandbox>>>,
}

/// A streaming subscription for sandbox metrics at a regular interval.
///
/// Supports both manual `recv()` calls and `for await...of` iteration:
/// ```js
/// const stream = await sb.metricsStream(1000);
/// for await (const m of stream) {
///   console.log(`CPU: ${m.cpuPercent.toFixed(1)}%`);
/// }
/// ```
#[napi(async_iterator, js_name = "MetricsStream")]
pub struct JsMetricsStream {
    rx: Arc<Mutex<tokio::sync::mpsc::Receiver<napi::Result<SandboxMetrics>>>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    pub fn from_rust(inner: microsandbox::sandbox::Sandbox) -> Self {
        Sandbox {
            inner: Arc::new(Mutex::new(Some(inner))),
        }
    }
}

#[napi]
impl Sandbox {
    //----------------------------------------------------------------------------------------------
    // Static Methods — Creation
    //----------------------------------------------------------------------------------------------

    /// Start an existing stopped sandbox (attached mode).
    #[napi(factory)]
    pub async fn start(name: String) -> Result<Sandbox> {
        let inner = microsandbox::sandbox::Sandbox::start(&name)
            .await
            .map_err(to_napi_error)?;
        Ok(Sandbox {
            inner: Arc::new(Mutex::new(Some(inner))),
        })
    }

    /// Start an existing stopped sandbox (detached mode).
    #[napi(factory)]
    pub async fn start_detached(name: String) -> Result<Sandbox> {
        let inner = microsandbox::sandbox::Sandbox::start_detached(&name)
            .await
            .map_err(to_napi_error)?;
        Ok(Sandbox {
            inner: Arc::new(Mutex::new(Some(inner))),
        })
    }

    //----------------------------------------------------------------------------------------------
    // Static Methods — Lookup
    //----------------------------------------------------------------------------------------------

    /// Get a lightweight handle to an existing sandbox.
    #[napi]
    pub async fn get(name: String) -> Result<JsSandboxHandle> {
        let handle = microsandbox::sandbox::Sandbox::get(&name)
            .await
            .map_err(to_napi_error)?;
        Ok(JsSandboxHandle::from_rust(handle))
    }

    /// List all sandboxes.
    #[napi]
    pub async fn list() -> Result<Vec<SandboxInfo>> {
        let handles = microsandbox::sandbox::Sandbox::list()
            .await
            .map_err(to_napi_error)?;
        Ok(handles.iter().map(sandbox_handle_to_info).collect())
    }

    /// Remove a stopped sandbox from the database.
    #[napi(js_name = "remove")]
    pub async fn remove_static(name: String) -> Result<()> {
        microsandbox::sandbox::Sandbox::remove(&name)
            .await
            .map_err(to_napi_error)
    }

    //----------------------------------------------------------------------------------------------
    // Properties
    //----------------------------------------------------------------------------------------------

    /// Sandbox name.
    #[napi(getter)]
    pub async fn name(&self) -> Result<String> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        Ok(sb.name().to_string())
    }

    /// Whether this handle owns the sandbox lifecycle (attached mode).
    #[napi(getter)]
    pub async fn owns_lifecycle(&self) -> Result<bool> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        Ok(sb.owns_lifecycle())
    }

    /// Get the full configuration this sandbox was created with
    /// (image, cpus, memory, env, mounts, etc.) as a JSON string.
    /// The TS layer parses + camelCase-remaps this into a plain object.
    #[napi(js_name = "configJson")]
    pub async fn config_json(&self) -> Result<String> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        serde_json::to_string(sb.config())
            .map_err(|e| napi::Error::from_reason(format!("failed to serialize config: {e}")))
    }

    //----------------------------------------------------------------------------------------------
    // Execution
    //----------------------------------------------------------------------------------------------

    /// Execute a command and wait for completion.
    #[napi]
    pub async fn exec(&self, cmd: String, args: Option<Vec<String>>) -> Result<ExecOutput> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        let args_owned = args.unwrap_or_default();
        let output = sb.exec(&cmd, args_owned).await.map_err(to_napi_error)?;
        Ok(ExecOutput::from_rust(output))
    }

    /// Execute a command using a populated `ExecOptionsBuilder`. The TS
    /// layer wraps this in a closure-callback API (`execWith(cmd, b => …)`).
    #[napi(js_name = "execWithBuilder")]
    pub async unsafe fn exec_with_builder(
        &self,
        cmd: String,
        builder: &mut JsExecOptionsBuilder,
    ) -> Result<ExecOutput> {
        let opts_builder = builder.take_inner_builder()?;
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        let output = sb
            .exec_with(&cmd, |_default| opts_builder)
            .await
            .map_err(to_napi_error)?;
        Ok(ExecOutput::from_rust(output))
    }

    /// Execute a command with streaming I/O.
    #[napi]
    pub async fn exec_stream(
        &self,
        cmd: String,
        args: Option<Vec<String>>,
    ) -> Result<JsExecHandle> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        let args_owned = args.unwrap_or_default();
        let handle = sb
            .exec_stream(&cmd, args_owned)
            .await
            .map_err(to_napi_error)?;
        Ok(JsExecHandle::from_rust(handle))
    }

    /// Execute a command with streaming I/O using a populated
    /// `ExecOptionsBuilder`. The TS layer wraps this in a closure-callback
    /// API (`execStreamWith(cmd, b => …)`). Set `b.stdinPipe()` on the
    /// builder for bidirectional streams.
    #[napi(js_name = "execStreamWithBuilder")]
    pub async unsafe fn exec_stream_with_builder(
        &self,
        cmd: String,
        builder: &mut JsExecOptionsBuilder,
    ) -> Result<JsExecHandle> {
        let opts_builder = builder.take_inner_builder()?;
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        let handle = sb
            .exec_stream_with(&cmd, |_default| opts_builder)
            .await
            .map_err(to_napi_error)?;
        Ok(JsExecHandle::from_rust(handle))
    }

    /// Execute a shell command using the sandbox's configured shell.
    #[napi]
    pub async fn shell(&self, script: String) -> Result<ExecOutput> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        let output = sb.shell(&script).await.map_err(to_napi_error)?;
        Ok(ExecOutput::from_rust(output))
    }

    /// Execute a shell command with streaming I/O.
    #[napi]
    pub async fn shell_stream(&self, script: String) -> Result<JsExecHandle> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        let handle = sb.shell_stream(&script).await.map_err(to_napi_error)?;
        Ok(JsExecHandle::from_rust(handle))
    }

    //----------------------------------------------------------------------------------------------
    // Filesystem
    //----------------------------------------------------------------------------------------------

    /// Get a filesystem handle for operations on the running sandbox.
    #[napi]
    pub fn fs(&self) -> JsSandboxFs {
        JsSandboxFs::new(self.inner.clone())
    }

    //----------------------------------------------------------------------------------------------
    // Metrics
    //----------------------------------------------------------------------------------------------

    /// Get point-in-time resource metrics.
    #[napi]
    pub async fn metrics(&self) -> Result<SandboxMetrics> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        let m = sb.metrics().await.map_err(to_napi_error)?;
        Ok(metrics_to_js(&m))
    }

    /// Stream metrics snapshots at the requested interval (in milliseconds).
    #[napi]
    pub async fn metrics_stream(&self, interval_ms: f64) -> Result<JsMetricsStream> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        let interval = Duration::from_millis(interval_ms as u64);
        let mut stream = Box::pin(sb.metrics_stream(interval));

        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            while let Some(result) = stream.next().await {
                let item = result.map(|m| metrics_to_js(&m)).map_err(to_napi_error);
                if tx.send(item).await.is_err() {
                    break;
                }
            }
        });

        Ok(JsMetricsStream {
            rx: Arc::new(Mutex::new(rx)),
        })
    }

    //----------------------------------------------------------------------------------------------
    // Attach
    //----------------------------------------------------------------------------------------------

    /// Attach to an interactive PTY session inside the sandbox.
    ///
    /// Bridges the host terminal to the guest process. Returns the exit code.
    #[napi]
    pub async fn attach(&self, cmd: String, args: Option<Vec<String>>) -> Result<i32> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        let args_owned = args.unwrap_or_default();
        sb.attach(&cmd, args_owned).await.map_err(to_napi_error)
    }

    /// Attach using a populated `AttachOptionsBuilder`. The TS layer
    /// wraps this in a closure-callback API (`attachWith(cmd, b => …)`).
    #[napi(js_name = "attachWithBuilder")]
    pub async unsafe fn attach_with_builder(
        &self,
        cmd: String,
        builder: &mut JsAttachOptionsBuilder,
    ) -> Result<i32> {
        let opts_builder = builder.take_inner_builder()?;
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        sb.attach_with(&cmd, |_default| opts_builder)
            .await
            .map_err(to_napi_error)
    }

    /// Attach to the sandbox's default shell.
    #[napi]
    pub async fn attach_shell(&self) -> Result<i32> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        sb.attach_shell().await.map_err(to_napi_error)
    }

    //----------------------------------------------------------------------------------------------
    // Lifecycle
    //----------------------------------------------------------------------------------------------

    /// Stop the sandbox gracefully (SIGTERM).
    #[napi]
    pub async fn stop(&self) -> Result<()> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        sb.stop().await.map_err(to_napi_error)
    }

    /// Stop and wait for exit, returning the exit status.
    #[napi]
    pub async fn stop_and_wait(&self) -> Result<ExitStatus> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        let status = sb.stop_and_wait().await.map_err(to_napi_error)?;
        Ok(exit_status_to_js(status))
    }

    /// Kill the sandbox immediately (SIGKILL).
    #[napi]
    pub async fn kill(&self) -> Result<()> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        sb.kill().await.map_err(to_napi_error)
    }

    /// Graceful drain (SIGUSR1 — for load balancing).
    #[napi]
    pub async fn drain(&self) -> Result<()> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        sb.drain().await.map_err(to_napi_error)
    }

    /// Wait for the sandbox process to exit.
    #[napi(js_name = "wait")]
    pub async fn wait_for_exit(&self) -> Result<ExitStatus> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        let status = sb.wait().await.map_err(to_napi_error)?;
        Ok(exit_status_to_js(status))
    }

    /// Detach from the sandbox — it will continue running after this handle is dropped.
    #[napi]
    pub async fn detach(&self) -> Result<()> {
        let mut guard = self.inner.lock().await;
        if let Some(sb) = guard.take() {
            sb.detach().await;
        }
        Ok(())
    }

    /// Remove the persisted database record after stopping.
    #[napi]
    pub async fn remove_persisted(&self) -> Result<()> {
        let mut guard = self.inner.lock().await;
        let sb = guard.take().ok_or_else(consumed_error)?;
        sb.remove_persisted().await.map_err(to_napi_error)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsMetricsStream {
    /// Receive the next metrics snapshot. Returns `null` when the stream ends.
    #[napi]
    pub async fn recv(&self) -> Result<Option<SandboxMetrics>> {
        let mut guard = self.rx.lock().await;
        match guard.recv().await {
            Some(result) => Ok(Some(result?)),
            None => Ok(None),
        }
    }
}

#[napi]
impl AsyncGenerator for JsMetricsStream {
    type Yield = SandboxMetrics;
    type Next = ();
    type Return = ();

    fn next(
        &mut self,
        _value: Option<Self::Next>,
    ) -> impl std::future::Future<Output = Result<Option<Self::Yield>>> + Send + 'static {
        let rx = Arc::clone(&self.rx);
        async move {
            let mut guard = rx.lock().await;
            match guard.recv().await {
                Some(result) => Ok(Some(result?)),
                None => Ok(None),
            }
        }
    }
}

pub fn metrics_to_js(m: &microsandbox::sandbox::SandboxMetrics) -> SandboxMetrics {
    SandboxMetrics {
        cpu_percent: m.cpu_percent as f64,
        memory_bytes: m.memory_bytes as f64,
        memory_limit_bytes: m.memory_limit_bytes as f64,
        disk_read_bytes: m.disk_read_bytes as f64,
        disk_write_bytes: m.disk_write_bytes as f64,
        net_rx_bytes: m.net_rx_bytes as f64,
        net_tx_bytes: m.net_tx_bytes as f64,
        uptime_ms: m.uptime.as_millis() as f64,
        timestamp_ms: datetime_to_ms(&m.timestamp),
    }
}

fn sandbox_handle_to_info(handle: &microsandbox::sandbox::SandboxHandle) -> SandboxInfo {
    SandboxInfo {
        name: handle.name().to_string(),
        status: format!("{:?}", handle.status()).to_lowercase(),
        config_json: handle.config_json().to_string(),
        created_at: opt_datetime_to_ms(&handle.created_at()),
        updated_at: opt_datetime_to_ms(&handle.updated_at()),
    }
}

fn exit_status_to_js(status: std::process::ExitStatus) -> ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    let code = status.code().unwrap_or_else(|| {
        // If no code, the process was killed by a signal.
        status.signal().map(|s| 128 + s).unwrap_or(-1)
    });
    ExitStatus {
        code,
        success: status.success(),
    }
}

fn consumed_error() -> napi::Error {
    napi::Error::from_reason("Sandbox handle has been consumed (detached or removed)")
}

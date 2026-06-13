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
use crate::fs::JsSandboxFsOps;
use crate::sandbox_handle::JsSandboxHandle;
use crate::ssh::{JsSshClient, JsSshServer, apply_client_options, apply_server_options};
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

/// A streaming subscription for sandbox log entries.
///
/// Supports both manual `recv()` calls and `for await...of` iteration:
/// ```js
/// const stream = await sb.logStream({ follow: true });
/// for await (const entry of stream) {
///   process.stdout.write(entry.data);
/// }
/// ```
#[napi(async_iterator, js_name = "LogStream")]
pub struct JsLogStream {
    rx: Arc<Mutex<tokio::sync::mpsc::Receiver<napi::Result<LogEntry>>>>,
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
    ///
    /// Sandbox names are limited to 128 UTF-8 bytes.
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
    ///
    /// Sandbox names are limited to 128 UTF-8 bytes.
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
    ///
    /// Sandbox names are limited to 128 UTF-8 bytes.
    #[napi]
    pub async fn get(name: String) -> Result<JsSandboxHandle> {
        let handle = microsandbox::sandbox::Sandbox::get(&name)
            .await
            .map_err(to_napi_error)?;
        Ok(JsSandboxHandle::from_rust(handle))
    }

    /// List all sandboxes.
    #[napi]
    pub async fn list() -> Result<Vec<JsSandboxHandle>> {
        let handles = microsandbox::sandbox::Sandbox::list()
            .await
            .map_err(to_napi_error)?;
        Ok(handles
            .into_iter()
            .map(JsSandboxHandle::from_rust)
            .collect())
    }

    /// List sandboxes filtered to those carrying all of the filter's labels
    /// (AND-matched).
    #[napi]
    pub async fn list_with(filter: SandboxListFilter) -> Result<Vec<JsSandboxHandle>> {
        let labels = filter.labels.unwrap_or_default();
        let filter = microsandbox::sandbox::SandboxFilter::new().labels(labels);
        let handles = microsandbox::sandbox::Sandbox::list_with(filter)
            .await
            .map_err(to_napi_error)?;
        Ok(handles
            .into_iter()
            .map(JsSandboxHandle::from_rust)
            .collect())
    }

    /// Remove a stopped sandbox from the database.
    ///
    /// Sandbox names are limited to 128 UTF-8 bytes.
    #[napi(js_name = "remove")]
    pub async fn remove_static(name: String) -> Result<()> {
        microsandbox::sandbox::Sandbox::remove(&name)
            .await
            .map_err(to_napi_error)
    }

    //----------------------------------------------------------------------------------------------
    // Properties
    //----------------------------------------------------------------------------------------------

    /// Sandbox name. Names are limited to 128 UTF-8 bytes.
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
    pub fn fs(&self) -> JsSandboxFsOps {
        JsSandboxFsOps::new(self.inner.clone())
    }

    //----------------------------------------------------------------------------------------------
    // SSH
    //----------------------------------------------------------------------------------------------

    /// Connect a native in-process SSH client to this sandbox.
    #[napi(js_name = "sshConnect")]
    pub async fn ssh_connect(&self, options: Option<SshClientOptions>) -> Result<JsSshClient> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        let client = sb
            .ssh()
            .open_client_with(|builder| apply_client_options(options, builder))
            .await
            .map_err(to_napi_error)?;
        Ok(JsSshClient::from_rust(client))
    }

    /// Prepare a reusable SSH server endpoint for this sandbox.
    #[napi(js_name = "sshServer")]
    pub async fn ssh_server(&self, options: Option<SshServerOptions>) -> Result<JsSshServer> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        let server = sb
            .ssh()
            .prepare_server_with(|builder| apply_server_options(options, builder))
            .await
            .map_err(to_napi_error)?;
        Ok(JsSshServer::from_rust(server))
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

    /// Stop the sandbox gracefully and wait until stopped state is observed.
    #[napi]
    pub async fn stop(&self) -> Result<()> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        sb.stop().await.map_err(to_napi_error)
    }

    /// Request graceful shutdown without waiting for stopped-state observation.
    #[napi]
    pub async fn request_stop(&self) -> Result<()> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        sb.request_stop().await.map_err(to_napi_error)
    }

    /// Stop the sandbox gracefully with an explicit timeout in milliseconds.
    #[napi]
    pub async fn stop_with_timeout(&self, timeout_ms: u32) -> Result<()> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        sb.stop_with_timeout(Duration::from_millis(timeout_ms.into()))
            .await
            .map_err(to_napi_error)
    }

    /// Force-kill the sandbox and wait until stopped state is observed.
    #[napi]
    pub async fn kill(&self) -> Result<()> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        sb.kill().await.map_err(to_napi_error)
    }

    /// Request force termination without waiting for stopped-state observation.
    #[napi]
    pub async fn request_kill(&self) -> Result<()> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        sb.request_kill().await.map_err(to_napi_error)
    }

    /// Force-kill the sandbox with an explicit observation timeout in milliseconds.
    #[napi]
    pub async fn kill_with_timeout(&self, timeout_ms: u32) -> Result<()> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        sb.kill_with_timeout(Duration::from_millis(timeout_ms.into()))
            .await
            .map_err(to_napi_error)
    }

    /// Request graceful drain without waiting for completion.
    #[napi]
    pub async fn request_drain(&self) -> Result<()> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        sb.request_drain().await.map_err(to_napi_error)
    }

    /// Wait until the sandbox is observed in a terminal non-running state.
    #[napi]
    pub async fn wait_until_stopped(&self) -> Result<SandboxStopResult> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        let result = sb.wait_until_stopped().await.map_err(to_napi_error)?;
        Ok(sandbox_stop_result_to_js(result))
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

    /// Read captured output from `exec.log` for this sandbox.
    ///
    /// Reads the on-disk JSON Lines file the runtime writes via the
    /// relay tap. Works on running and stopped sandboxes alike — no
    /// protocol traffic.
    #[napi]
    pub async fn logs(&self, opts: Option<LogOptions>) -> Result<Vec<LogEntry>> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        let name = sb.name().to_string();
        let rust_opts = log_options_from_js(opts).map_err(napi::Error::from_reason)?;
        let entries = microsandbox::logs::read_logs(&name, &rust_opts)
            .await
            .map_err(to_napi_error)?;
        Ok(entries.into_iter().map(log_entry_to_js).collect())
    }

    /// Stream captured output as it appears, with optional follow.
    ///
    /// Returns an async iterable of `LogEntry`. Each entry carries
    /// an opaque `cursor` token suitable for passing back via
    /// `fromCursor` on a later call to resume exactly after that
    /// entry.
    #[napi]
    pub async fn log_stream(&self, opts: Option<LogStreamOptions>) -> Result<JsLogStream> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        let name = sb.name().to_string();
        let rust_opts = log_stream_options_from_js(opts).map_err(napi::Error::from_reason)?;
        spawn_log_stream(&name, rust_opts).await
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

#[napi]
impl JsLogStream {
    /// Receive the next entry. Returns `null` when the stream ends
    /// (snapshot drained, `until` reached, or fatal stream error
    /// already surfaced).
    #[napi]
    pub async fn recv(&self) -> Result<Option<LogEntry>> {
        let mut guard = self.rx.lock().await;
        match guard.recv().await {
            Some(result) => Ok(Some(result?)),
            None => Ok(None),
        }
    }
}

#[napi]
impl AsyncGenerator for JsLogStream {
    type Yield = LogEntry;
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

/// Open a log stream against the given sandbox name and bridge it
/// onto a JS-side mpsc channel. Shared between `Sandbox::log_stream`
/// and `SandboxHandle::log_stream`.
pub async fn spawn_log_stream(
    name: &str,
    opts: microsandbox::logs::LogStreamOptions,
) -> Result<JsLogStream> {
    let mut stream = Box::pin(
        microsandbox::logs::log_stream(name, &opts)
            .await
            .map_err(to_napi_error)?,
    );
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    tokio::spawn(async move {
        while let Some(result) = stream.next().await {
            let item = result.map(log_entry_to_js).map_err(to_napi_error);
            if tx.send(item).await.is_err() {
                break;
            }
        }
    });
    Ok(JsLogStream {
        rx: Arc::new(Mutex::new(rx)),
    })
}

pub fn log_entry_to_js(entry: microsandbox::logs::LogEntry) -> LogEntry {
    let source = match entry.source {
        microsandbox::logs::LogSource::Stdout => "stdout",
        microsandbox::logs::LogSource::Stderr => "stderr",
        microsandbox::logs::LogSource::Output => "output",
        microsandbox::logs::LogSource::System => "system",
    };
    LogEntry {
        timestamp_ms: entry.timestamp.timestamp_millis() as f64,
        source: source.to_string(),
        session_id: entry.session_id.map(|id| id as f64),
        data: entry.data.to_vec().into(),
        cursor: entry.cursor.to_string(),
    }
}

pub fn log_options_from_js(
    opts: Option<LogOptions>,
) -> std::result::Result<microsandbox::logs::LogOptions, String> {
    let Some(o) = opts else {
        return Ok(microsandbox::logs::LogOptions::default());
    };
    let mut out = microsandbox::logs::LogOptions {
        tail: o.tail.map(|n| n as usize),
        since: o.since_ms.and_then(ms_to_datetime),
        until: o.until_ms.and_then(ms_to_datetime),
        sources: Vec::new(),
    };
    if let Some(srcs) = o.sources {
        for s in srcs {
            match s.as_str() {
                "stdout" => out.sources.push(microsandbox::logs::LogSource::Stdout),
                "stderr" => out.sources.push(microsandbox::logs::LogSource::Stderr),
                "output" => out.sources.push(microsandbox::logs::LogSource::Output),
                "system" => out.sources.push(microsandbox::logs::LogSource::System),
                "all" => {
                    out.sources = vec![
                        microsandbox::logs::LogSource::Stdout,
                        microsandbox::logs::LogSource::Stderr,
                        microsandbox::logs::LogSource::Output,
                        microsandbox::logs::LogSource::System,
                    ];
                }
                other => return Err(format!("unknown log source {other:?}")),
            }
        }
    }
    Ok(out)
}

pub fn log_stream_options_from_js(
    opts: Option<LogStreamOptions>,
) -> std::result::Result<microsandbox::logs::LogStreamOptions, String> {
    let Some(o) = opts else {
        return Ok(microsandbox::logs::LogStreamOptions::default());
    };
    if o.since_ms.is_some() && o.from_cursor.is_some() {
        return Err("sinceMs and fromCursor are mutually exclusive".into());
    }
    let start = if let Some(ms) = o.since_ms {
        let ts = ms_to_datetime(ms).ok_or_else(|| format!("invalid sinceMs value {ms}"))?;
        microsandbox::logs::LogStreamStart::Since(ts)
    } else if let Some(token) = o.from_cursor.as_deref() {
        let cursor: microsandbox::logs::LogCursor =
            token
                .parse()
                .map_err(|e: microsandbox::logs::LogCursorParseError| {
                    format!("invalid fromCursor: {e}")
                })?;
        microsandbox::logs::LogStreamStart::From(cursor)
    } else {
        microsandbox::logs::LogStreamStart::Beginning
    };
    let mut sources = Vec::new();
    if let Some(srcs) = o.sources {
        for s in srcs {
            match s.as_str() {
                "stdout" => sources.push(microsandbox::logs::LogSource::Stdout),
                "stderr" => sources.push(microsandbox::logs::LogSource::Stderr),
                "output" => sources.push(microsandbox::logs::LogSource::Output),
                "system" => sources.push(microsandbox::logs::LogSource::System),
                "all" => {
                    sources = vec![
                        microsandbox::logs::LogSource::Stdout,
                        microsandbox::logs::LogSource::Stderr,
                        microsandbox::logs::LogSource::Output,
                        microsandbox::logs::LogSource::System,
                    ];
                }
                other => return Err(format!("unknown log source {other:?}")),
            }
        }
    }
    Ok(microsandbox::logs::LogStreamOptions {
        sources,
        start,
        until: o.until_ms.and_then(ms_to_datetime),
        follow: o.follow.unwrap_or(false),
    })
}

fn ms_to_datetime(ms: f64) -> Option<chrono::DateTime<chrono::Utc>> {
    let secs = (ms / 1000.0).trunc() as i64;
    let nsecs = ((ms - secs as f64 * 1000.0) * 1_000_000.0).round() as u32;
    chrono::DateTime::from_timestamp(secs, nsecs)
}

pub fn metrics_to_js(m: &microsandbox::sandbox::SandboxMetrics) -> SandboxMetrics {
    SandboxMetrics {
        cpu_percent: m.cpu_percent as f64,
        vcpu_time_ns: m.vcpu_time_ns as f64,
        memory_bytes: m.memory_bytes as f64,
        memory_available_bytes: m.memory_available_bytes.map(|bytes| bytes as f64),
        memory_host_resident_bytes: m.memory_host_resident_bytes.map(|bytes| bytes as f64),
        memory_limit_bytes: m.memory_limit_bytes as f64,
        disk_read_bytes: m.disk_read_bytes as f64,
        disk_write_bytes: m.disk_write_bytes as f64,
        net_rx_bytes: m.net_rx_bytes as f64,
        net_tx_bytes: m.net_tx_bytes as f64,
        uptime_ms: m.uptime.as_millis() as f64,
        timestamp_ms: datetime_to_ms(&m.timestamp),
    }
}

pub(crate) fn sandbox_stop_result_to_js(
    result: microsandbox::sandbox::SandboxStopResult,
) -> SandboxStopResult {
    SandboxStopResult {
        name: result.name,
        status: format!("{:?}", result.status).to_lowercase(),
        exit_code: result.exit_code,
        signal: result.signal,
        observed_at: result.observed_at.timestamp_millis() as f64,
        source: result.source,
    }
}

fn consumed_error() -> napi::Error {
    napi::Error::from_reason("Sandbox handle has been consumed (detached or removed)")
}

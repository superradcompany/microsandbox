use microsandbox::sandbox::exec::{ExecEvent as RustExecEvent, ExecHandle, ExecSink};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use tokio::sync::Mutex;

use crate::error::to_napi_error;
use crate::types::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Output of a completed command execution.
///
/// Provides both string and raw byte access to stdout/stderr:
/// ```js
/// const output = await sandbox.shell("echo hello");
/// console.log(output.stdout());       // "hello\n"
/// console.log(output.stdoutBytes());   // <Buffer 68 65 6c 6c 6f 0a>
/// console.log(output.code);            // 0
/// console.log(output.success);         // true
/// ```
#[napi]
pub struct ExecOutput {
    code: i32,
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Handle for a streaming command execution.
///
/// Use `recv()` to get events one at a time, or iterate with a loop:
/// ```js
/// const handle = await sandbox.execStream("tail", ["-f", "/var/log/app.log"]);
/// let event;
/// while ((event = await handle.recv()) !== null) {
///   if (event.eventType === "stdout") process.stdout.write(event.data);
/// }
/// ```
#[napi(js_name = "ExecHandle")]
pub struct JsExecHandle {
    inner: Mutex<ExecHandle>,
}

/// Stdin writer for a running process.
#[napi(js_name = "ExecSink")]
pub struct JsExecSink {
    inner: ExecSink,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ExecOutput {
    pub(crate) fn from_rust(output: microsandbox::sandbox::ExecOutput) -> Self {
        let status = output.status();
        Self {
            code: status.code,
            success: status.success,
            stdout: output.stdout_bytes().to_vec(),
            stderr: output.stderr_bytes().to_vec(),
        }
    }
}

#[napi]
impl ExecOutput {
    /// Exit code of the process.
    #[napi(getter)]
    pub fn code(&self) -> i32 {
        self.code
    }

    /// Whether the process exited successfully (code == 0).
    #[napi(getter)]
    pub fn success(&self) -> bool {
        self.success
    }

    /// Get stdout as a UTF-8 string.
    #[napi]
    pub fn stdout(&self) -> String {
        String::from_utf8_lossy(&self.stdout).to_string()
    }

    /// Get stderr as a UTF-8 string.
    #[napi]
    pub fn stderr(&self) -> String {
        String::from_utf8_lossy(&self.stderr).to_string()
    }

    /// Get stdout as raw bytes.
    #[napi(js_name = "stdoutBytes")]
    pub fn stdout_bytes(&self) -> Buffer {
        self.stdout.clone().into()
    }

    /// Get stderr as raw bytes.
    #[napi(js_name = "stderrBytes")]
    pub fn stderr_bytes(&self) -> Buffer {
        self.stderr.clone().into()
    }

    /// Get the exit status.
    #[napi]
    pub fn status(&self) -> ExitStatus {
        ExitStatus {
            code: self.code,
            success: self.success,
        }
    }
}

impl JsExecHandle {
    pub fn from_rust(handle: ExecHandle) -> Self {
        Self {
            inner: Mutex::new(handle),
        }
    }
}

#[napi]
impl JsExecHandle {
    /// Get the correlation ID for this execution.
    #[napi(getter)]
    pub async fn id(&self) -> String {
        let guard = self.inner.lock().await;
        guard.id()
    }

    /// Receive the next event. Returns `null` when the stream ends.
    #[napi]
    pub async fn recv(&self) -> Result<Option<ExecEvent>> {
        let mut guard = self.inner.lock().await;
        match guard.recv().await {
            Some(event) => Ok(Some(exec_event_to_js(event))),
            None => Ok(None),
        }
    }

    /// Take the stdin writer. Can only be called once; returns `null` on subsequent calls.
    #[napi]
    pub async fn take_stdin(&self) -> Option<JsExecSink> {
        let mut guard = self.inner.lock().await;
        guard.take_stdin().map(|sink| JsExecSink { inner: sink })
    }

    /// Wait for the process to exit and return the exit status.
    #[napi(js_name = "wait")]
    pub async fn wait_for_exit(&self) -> Result<ExitStatus> {
        let mut guard = self.inner.lock().await;
        let status = guard.wait().await.map_err(to_napi_error)?;
        Ok(ExitStatus {
            code: status.code,
            success: status.success,
        })
    }

    /// Wait for completion and collect all output.
    #[napi]
    pub async fn collect(&self) -> Result<ExecOutput> {
        let mut guard = self.inner.lock().await;
        let output = guard.collect().await.map_err(to_napi_error)?;
        Ok(ExecOutput::from_rust(output))
    }

    /// Send a signal to the running process.
    #[napi]
    pub async fn signal(&self, signal: i32) -> Result<()> {
        let guard = self.inner.lock().await;
        guard.signal(signal).await.map_err(to_napi_error)
    }

    /// Kill the running process (SIGKILL).
    #[napi]
    pub async fn kill(&self) -> Result<()> {
        let guard = self.inner.lock().await;
        guard.kill().await.map_err(to_napi_error)
    }
}

#[napi]
impl JsExecSink {
    /// Write data to the process stdin.
    #[napi]
    pub async fn write(&self, data: Buffer) -> Result<()> {
        let bytes: Vec<u8> = data.to_vec();
        self.inner.write(&bytes).await.map_err(to_napi_error)
    }

    /// Close stdin (sends EOF to the process).
    #[napi]
    pub async fn close(&self) -> Result<()> {
        self.inner.close().await.map_err(to_napi_error)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn exec_event_to_js(event: RustExecEvent) -> ExecEvent {
    match event {
        RustExecEvent::Started { pid } => ExecEvent {
            event_type: "started".to_string(),
            pid: Some(pid),
            data: None,
            code: None,
        },
        RustExecEvent::Stdout(data) => ExecEvent {
            event_type: "stdout".to_string(),
            pid: None,
            data: Some(data.to_vec().into()),
            code: None,
        },
        RustExecEvent::Stderr(data) => ExecEvent {
            event_type: "stderr".to_string(),
            pid: None,
            data: Some(data.to_vec().into()),
            code: None,
        },
        RustExecEvent::Exited { code } => ExecEvent {
            event_type: "exited".to_string(),
            pid: None,
            data: None,
            code: Some(code),
        },
        // Spawn-time failure: surface as a synthetic exec event so
        // existing JS consumers iterating events see something. The
        // canonical way to surface this is via the `ExecFailed`
        // typed error returned from `exec()`/`exec_with()`/`collect()`.
        RustExecEvent::Failed(payload) => ExecEvent {
            event_type: "failed".to_string(),
            pid: None,
            data: Some(payload.message.into_bytes().into()),
            code: payload.errno,
        },
    }
}

use microsandbox::sandbox::SandboxHandle;
use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::error::to_napi_error;
use crate::sandbox::Sandbox;
use crate::types::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A lightweight handle to a sandbox from the database.
///
/// Does NOT hold a live connection — use `connect()` or `start()` to get a live `Sandbox`.
#[napi(js_name = "SandboxHandle")]
pub struct JsSandboxHandle {
    inner: SandboxHandle,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl JsSandboxHandle {
    pub fn from_rust(handle: SandboxHandle) -> Self {
        Self { inner: handle }
    }
}

#[napi]
impl JsSandboxHandle {
    /// Sandbox name. Names are limited to 128 UTF-8 bytes.
    #[napi(getter)]
    pub fn name(&self) -> String {
        self.inner.name().to_string()
    }

    /// Status at time of query: "running", "stopped", "crashed", or "draining".
    #[napi(getter)]
    pub fn status(&self) -> String {
        format!("{:?}", self.inner.status_snapshot()).to_lowercase()
    }

    /// Raw config JSON string from the database.
    #[napi(getter)]
    pub fn config_json(&self) -> String {
        self.inner.config_json().to_string()
    }

    /// Return a fresh handle for the same sandbox.
    #[napi]
    pub async fn refresh(&self) -> Result<JsSandboxHandle> {
        let handle = self.inner.refresh().await.map_err(to_napi_error)?;
        Ok(JsSandboxHandle::from_rust(handle))
    }

    /// Creation timestamp as ms since Unix epoch.
    #[napi(getter)]
    pub fn created_at(&self) -> Option<f64> {
        opt_datetime_to_ms(&self.inner.created_at())
    }

    /// Last update timestamp as ms since Unix epoch.
    #[napi(getter)]
    pub fn updated_at(&self) -> Option<f64> {
        opt_datetime_to_ms(&self.inner.updated_at())
    }

    /// Get point-in-time metrics from the database.
    #[napi]
    pub async fn metrics(&self) -> Result<SandboxMetrics> {
        let m = self.inner.metrics().await.map_err(to_napi_error)?;
        Ok(crate::sandbox::metrics_to_js(&m))
    }

    /// Check whether agentd is reachable without refreshing idle activity.
    ///
    /// Connects to an already-running sandbox; stopped sandboxes are not
    /// started implicitly.
    #[napi]
    pub async fn ping(&self) -> Result<SandboxPingResult> {
        let result = self.inner.ping().await.map_err(to_napi_error)?;
        Ok(crate::sandbox::sandbox_ping_result_to_js(result))
    }

    /// Explicitly refresh this sandbox's idle activity timer.
    ///
    /// Connects to an already-running sandbox; stopped sandboxes are not
    /// started implicitly.
    #[napi]
    pub async fn touch(&self) -> Result<SandboxTouchResult> {
        let result = self.inner.touch().await.map_err(to_napi_error)?;
        Ok(crate::sandbox::sandbox_touch_result_to_js(result))
    }

    /// Plan or apply a sandbox modification. Returns the plan as a JSON
    /// string; the TS wrapper parses it into a `SandboxModificationPlan`.
    #[napi]
    pub async fn modify(&self, options: Option<SandboxModifyOptions>) -> Result<String> {
        let builder = crate::sandbox::configure_modify(self.inner.modify(), options.as_ref())?;
        crate::sandbox::run_modify(builder, crate::sandbox::modify_dry_run(options.as_ref())).await
    }

    /// Start the sandbox (attached mode) — returns a live Sandbox handle.
    #[napi]
    pub async fn start(&self) -> Result<Sandbox> {
        let inner = self.inner.start().await.map_err(to_napi_error)?;
        Ok(Sandbox::from_rust(inner))
    }

    /// Start the sandbox (detached mode).
    #[napi]
    pub async fn start_detached(&self) -> Result<Sandbox> {
        let inner = self.inner.start_detached().await.map_err(to_napi_error)?;
        Ok(Sandbox::from_rust(inner))
    }

    /// Connect to an already-running sandbox (no lifecycle ownership).
    #[napi]
    pub async fn connect(&self) -> Result<Sandbox> {
        let inner = self.inner.connect().await.map_err(to_napi_error)?;
        Ok(Sandbox::from_rust(inner))
    }

    /// Connect with an explicit timeout in milliseconds.
    ///
    /// If the sandbox doesn't respond within this window, the call
    /// returns a typed error instead of blocking. `connect()` uses
    /// 10_000 ms by default.
    #[napi]
    pub async fn connect_with_timeout(&self, timeout_ms: u32) -> Result<Sandbox> {
        let timeout = std::time::Duration::from_millis(timeout_ms.into());
        let inner = self
            .inner
            .connect_with_timeout(timeout)
            .await
            .map_err(to_napi_error)?;
        Ok(Sandbox::from_rust(inner))
    }

    /// Stop the sandbox gracefully.
    ///
    /// Lets the sandbox finish writing any pending data to disk before
    /// it exits, so files written inside the sandbox aren't lost across
    /// a later restart. Waits 10_000 ms by default before force-kill;
    /// override with `stopWithTimeout(timeoutMs)`.
    #[napi]
    pub async fn stop(&self) -> Result<()> {
        self.inner.stop().await.map_err(to_napi_error)
    }

    /// Request graceful shutdown without waiting.
    #[napi]
    pub async fn request_stop(&self) -> Result<()> {
        self.inner.request_stop().await.map_err(to_napi_error)
    }

    /// Stop the sandbox gracefully with an explicit timeout in
    /// milliseconds before escalation.
    #[napi]
    pub async fn stop_with_timeout(&self, timeout_ms: u32) -> Result<()> {
        let timeout = std::time::Duration::from_millis(timeout_ms.into());
        self.inner
            .stop_with_timeout(timeout)
            .await
            .map_err(to_napi_error)
    }

    /// Force-kill the sandbox and wait until stopped state is observed.
    #[napi]
    pub async fn kill(&self) -> Result<()> {
        self.inner.kill().await.map_err(to_napi_error)
    }

    /// Request force termination without waiting.
    #[napi]
    pub async fn request_kill(&self) -> Result<()> {
        self.inner.request_kill().await.map_err(to_napi_error)
    }

    /// Force-kill the sandbox with an explicit observation timeout in milliseconds.
    #[napi]
    pub async fn kill_with_timeout(&self, timeout_ms: u32) -> Result<()> {
        let timeout = std::time::Duration::from_millis(timeout_ms.into());
        self.inner
            .kill_with_timeout(timeout)
            .await
            .map_err(to_napi_error)
    }

    /// Request graceful drain without waiting for completion.
    #[napi]
    pub async fn request_drain(&self) -> Result<()> {
        self.inner.request_drain().await.map_err(to_napi_error)
    }

    /// Wait until the sandbox is observed in a terminal non-running state.
    #[napi]
    pub async fn wait_until_stopped(&self) -> Result<SandboxStopResult> {
        let result = self
            .inner
            .wait_until_stopped()
            .await
            .map_err(to_napi_error)?;
        Ok(crate::sandbox::sandbox_stop_result_to_js(result))
    }

    /// Remove the sandbox from the database.
    #[napi]
    pub async fn remove(&self) -> Result<()> {
        self.inner.remove().await.map_err(to_napi_error)
    }

    /// Read captured output from `exec.log` for this sandbox.
    ///
    /// Works without starting the sandbox.
    #[napi]
    pub async fn logs(&self, opts: Option<LogOptions>) -> Result<Vec<LogEntry>> {
        let rust_opts =
            crate::sandbox::log_options_from_js(opts).map_err(napi::Error::from_reason)?;
        let entries = self.inner.logs(&rust_opts).await.map_err(to_napi_error)?;
        Ok(entries
            .into_iter()
            .map(crate::sandbox::log_entry_to_js)
            .collect())
    }

    /// Stream captured output as it appears, with optional follow.
    ///
    /// Works without starting the sandbox; with `follow: true`, the
    /// stream picks up new entries the moment they land in
    /// `exec.log`.
    #[napi]
    pub async fn log_stream(
        &self,
        opts: Option<LogStreamOptions>,
    ) -> Result<crate::sandbox::JsLogStream> {
        let rust_opts =
            crate::sandbox::log_stream_options_from_js(opts).map_err(napi::Error::from_reason)?;
        let stream = self
            .inner
            .log_stream(&rust_opts)
            .await
            .map_err(to_napi_error)?;
        crate::sandbox::spawn_log_stream_from_stream(stream).await
    }

    /// Snapshot this (stopped) sandbox under a bare name.
    ///
    /// Resolves under `~/.microsandbox/snapshots/<name>/`. Move
    /// artifacts with `Snapshot.save`/`Snapshot.load`.
    #[napi]
    pub async fn snapshot(&self, name: String) -> Result<crate::snapshot::JsSnapshot> {
        let snap = self.inner.snapshot(&name).await.map_err(to_napi_error)?;
        Ok(crate::snapshot::JsSnapshot::from_rust(snap))
    }
}

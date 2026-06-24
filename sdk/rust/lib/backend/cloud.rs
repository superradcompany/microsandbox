//! Cloud backend implementation — talks to an msb-cloud control plane over HTTP.
//!
//! Holds the (url, api_key) tuple and a `reqwest::Client`. Sub-trait
//! implementations (sandbox lifecycle, exec, volumes, …) land alongside the
//! `Backend` trait's sub-trait surface as that surface is filled in.
//!
//! Construction is URL + API key first; `from_env` and `from_profile` are sugar.
//! Auth is API-key-only — the same `msb_live_*` / `msb_test_*` tokens msb-cloud
//! issues today. No OAuth or session credentials are honored here.

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::{SinkExt, StreamExt, stream};
use microsandbox_protocol::{
    codec,
    exec::{ExecExited, ExecFailed, ExecStarted, ExecStderr, ExecStdin, ExecStdout},
    message::{Message, MessageType},
};
use reqwest::Response;
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderName, HeaderValue, USER_AGENT};
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        client::IntoClientRequest,
        http::{
            HeaderValue as WsHeaderValue,
            header::{
                AUTHORIZATION as WS_AUTHORIZATION, SEC_WEBSOCKET_PROTOCOL,
                USER_AGENT as WS_USER_AGENT,
            },
        },
        protocol::Message as WsMessage,
    },
};

use super::{Backend, BackendKind, SandboxBackend, VolumeBackend, sandbox::LogStream};
use crate::logs::{LogCursor, LogEntry, LogOptions, LogSource, LogStreamOptions, LogStreamStart};
use crate::sandbox::{
    SandboxConfig, build_exec_request,
    exec::{ExecOptions, ExecOutput, ExitStatus, StdinMode},
};
use crate::{MicrosandboxError, MicrosandboxResult};
use microsandbox_types::{
    CloudCreateSandboxRequest, CloudErrorBody, CloudMessageResponse, CloudPaginated, CloudSandbox,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const CLOUD_EXEC_ID: u32 = 1;
const CLOUD_EXEC_SUBPROTOCOL: &str = "msb.cbor";

/// Default User-Agent header value.
fn default_user_agent() -> String {
    format!("microsandbox-sdk/{}", env!("CARGO_PKG_VERSION"))
}

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Cloud-runtime backend: talks to an msb-cloud control plane over HTTP.
///
/// Holds the deployment URL and API key. The `(url, api_key)` pair determines
/// which org's view the backend sees: msb-cloud derives the org from the API
/// key, so there is no per-call org argument.
///
/// Constructors:
/// - [`CloudBackend::new`] — primary; explicit URL + key. Works for hosted SaaS,
///   self-hosted, and on-prem deployments identically.
/// - [`CloudBackend::from_env`] — reads `MSB_API_URL` + `MSB_API_KEY`.
/// - [`CloudBackend::from_profile`] — reads a named profile from the SDK config.
/// - [`CloudBackend::builder`] — tuned construction (custom client, timeout,
///   user agent).
pub struct CloudBackend {
    url: String,
    api_key: String,
    http: reqwest::Client,
}

/// Fluent builder for `CloudBackend`. Use for tuned construction.
///
/// ```ignore
/// let cloud = CloudBackend::builder()
///     .url("https://msb.example.com")
///     .api_key(key)
///     .request_timeout(Duration::from_secs(60))
///     .build()?;
/// ```
pub struct CloudBackendBuilder {
    url: Option<String>,
    api_key: Option<String>,
    request_timeout: Duration,
    user_agent: Option<String>,
    custom_client: Option<reqwest::Client>,
}

#[derive(Debug, Deserialize)]
struct CloudLogPayload {
    source: String,
    ts: chrono::DateTime<chrono::Utc>,
    text: String,
}

#[derive(Default)]
struct CloudSseEvent {
    id: Option<String>,
    event: Option<String>,
    data: String,
}

enum CloudSseItem {
    Entry(LogEntry),
    End,
    Ignore,
}

//--------------------------------------------------------------------------------------------------
// Methods: CloudBackend
//--------------------------------------------------------------------------------------------------

impl CloudBackend {
    /// Construct a `CloudBackend` with an explicit URL and API key.
    ///
    /// Primary constructor. Works identically for hosted msb-cloud, self-hosted
    /// deployments, and on-prem installs — no constructor implies a specific
    /// deployment shape.
    pub fn new(url: impl Into<String>, api_key: impl Into<String>) -> MicrosandboxResult<Self> {
        Self::builder().url(url).api_key(api_key).build()
    }

    /// Construct from `MSB_API_URL` + `MSB_API_KEY` env vars.
    ///
    /// Returns `InvalidConfig` if either is missing or empty.
    pub fn from_env() -> MicrosandboxResult<Self> {
        let url = std::env::var("MSB_API_URL").map_err(|_| {
            MicrosandboxError::InvalidConfig(
                "MSB_API_URL not set — required for cloud backend".into(),
            )
        })?;
        let api_key = std::env::var("MSB_API_KEY").map_err(|_| {
            MicrosandboxError::InvalidConfig(
                "MSB_API_KEY not set — required for cloud backend".into(),
            )
        })?;
        Self::new(url.trim(), api_key.trim())
    }

    /// Construct from a named SDK profile in `~/.microsandbox/config.json`.
    ///
    /// Profiles are local SDK sugar over the primary `(url, api_key)` constructor;
    /// msb-cloud does not receive or interpret profile names.
    pub fn from_profile(name: &str) -> MicrosandboxResult<Self> {
        super::profile::cloud_backend_from_profile(name)
    }

    /// Start building a `CloudBackend` with custom options. Call `.build()` when done.
    pub fn builder() -> CloudBackendBuilder {
        CloudBackendBuilder::default()
    }

    /// Configured msb-cloud endpoint URL (no trailing slash).
    pub fn url(&self) -> &str {
        &self.url
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Sandbox lifecycle
//
// HTTP dispatch for the SDK's sandbox lifecycle ops, hitting msb-cloud's
// API-key-authenticated routes (`/v1/sandboxes/*` and `/v1/sandboxes/by-name/*`).
//--------------------------------------------------------------------------------------------------

impl CloudBackend {
    /// `POST /v1/sandboxes` (optionally `?start=true`).
    ///
    /// Pass `start=true` to atomically create-and-start in a single round-trip
    /// — mirrors the `POST /v1/sandboxes?start=true` shorthand on msb-cloud.
    pub async fn create_sandbox(
        &self,
        req: &CloudCreateSandboxRequest,
        start: bool,
    ) -> MicrosandboxResult<CloudSandbox> {
        let path = if start {
            "/v1/sandboxes?start=true"
        } else {
            "/v1/sandboxes"
        };
        let url = format!("{}{}", self.url, path);
        let resp = self
            .http
            .post(&url)
            .json(req)
            .send()
            .await
            .map_err(|e| cloud_io_error("POST /v1/sandboxes", e))?;
        decode_json(resp, "POST /v1/sandboxes").await
    }

    /// `GET /v1/sandboxes` — paginated.
    pub async fn list_sandboxes(
        &self,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> MicrosandboxResult<CloudPaginated<CloudSandbox>> {
        let mut url = format!("{}/v1/sandboxes", self.url);
        let mut query = Vec::new();
        if let Some(c) = cursor {
            query.push(format!("cursor={}", urlencoding(c)));
        }
        if let Some(l) = limit {
            query.push(format!("limit={l}"));
        }
        if !query.is_empty() {
            url.push('?');
            url.push_str(&query.join("&"));
        }
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| cloud_io_error("GET /v1/sandboxes", e))?;
        decode_json(resp, "GET /v1/sandboxes").await
    }

    /// `GET /v1/sandboxes/by-name/:name`.
    pub async fn get_sandbox(&self, name: &str) -> MicrosandboxResult<CloudSandbox> {
        let url = format!("{}/v1/sandboxes/by-name/{}", self.url, urlencoding(name));
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| cloud_io_error("GET /v1/sandboxes/by-name/:name", e))?;
        decode_json(resp, "GET /v1/sandboxes/by-name/:name").await
    }

    /// `POST /v1/sandboxes/by-name/:name/start`.
    pub async fn start_sandbox(&self, name: &str) -> MicrosandboxResult<CloudSandbox> {
        let url = format!(
            "{}/v1/sandboxes/by-name/{}/start",
            self.url,
            urlencoding(name)
        );
        let resp = self
            .http
            .post(&url)
            .json(&serde_json::json!({}))
            .send()
            .await
            .map_err(|e| cloud_io_error("POST start", e))?;
        decode_json(resp, "POST /v1/sandboxes/by-name/:name/start").await
    }

    /// `POST /v1/sandboxes/by-name/:name/stop`.
    pub async fn stop_sandbox(&self, name: &str) -> MicrosandboxResult<CloudSandbox> {
        let url = format!(
            "{}/v1/sandboxes/by-name/{}/stop",
            self.url,
            urlencoding(name)
        );
        let resp = self
            .http
            .post(&url)
            .json(&serde_json::json!({}))
            .send()
            .await
            .map_err(|e| cloud_io_error("POST stop", e))?;
        decode_json(resp, "POST /v1/sandboxes/by-name/:name/stop").await
    }

    /// `DELETE /v1/sandboxes/by-name/:name`. Returns the typed `MessageResponse`
    /// msb-cloud emits.
    pub async fn destroy_sandbox(&self, name: &str) -> MicrosandboxResult<CloudMessageResponse> {
        let url = format!("{}/v1/sandboxes/by-name/{}", self.url, urlencoding(name));
        let resp = self
            .http
            .delete(&url)
            .send()
            .await
            .map_err(|e| cloud_io_error("DELETE /v1/sandboxes/by-name/:name", e))?;
        decode_json(resp, "DELETE /v1/sandboxes/by-name/:name").await
    }

    /// Stream logs from `GET /v1/sandboxes/:id/logs`.
    ///
    /// msb-cloud exposes logs as Server-Sent Events keyed by sandbox UUID, so
    /// the SDK resolves the current name to a cloud sandbox first. The cloud
    /// endpoint is streaming-only and requires a running sandbox, so callers
    /// must set `follow: true`.
    pub async fn log_stream(
        &self,
        name: &str,
        opts: &LogStreamOptions,
    ) -> MicrosandboxResult<LogStream> {
        if !opts.follow {
            return Err(MicrosandboxError::Unsupported {
                feature: "Sandbox::log_stream(follow=false) on cloud".into(),
                available_when: "when msb-cloud exposes bounded log snapshots".into(),
            });
        }

        let sandbox = self.get_sandbox(name).await?;
        self.open_log_stream_by_id(&sandbox.id, opts).await
    }

    /// Read a bounded log snapshot.
    pub async fn logs(&self, _name: &str, _opts: &LogOptions) -> MicrosandboxResult<Vec<LogEntry>> {
        Err(MicrosandboxError::Unsupported {
            feature: "Sandbox::logs on cloud".into(),
            available_when: "when msb-cloud exposes bounded log snapshots; use Sandbox::log_stream with follow=true for live logs".into(),
        })
    }

    /// Run a command via `GET /v1/sandboxes/:id/exec.cbor`.
    pub async fn exec(
        &self,
        name: &str,
        config: &SandboxConfig,
        cmd: String,
        opts: ExecOptions,
    ) -> MicrosandboxResult<ExecOutput> {
        let timeout_duration = opts.timeout;
        let exec = self.exec_without_timeout(name, config, cmd, opts);

        match timeout_duration {
            Some(duration) => match tokio::time::timeout(duration, exec).await {
                Ok(result) => result,
                Err(_) => Err(MicrosandboxError::ExecTimeout(duration)),
            },
            None => exec.await,
        }
    }

    async fn exec_without_timeout(
        &self,
        name: &str,
        config: &SandboxConfig,
        cmd: String,
        opts: ExecOptions,
    ) -> MicrosandboxResult<ExecOutput> {
        let sandbox = self.get_sandbox(name).await?;
        let url = cloud_exec_ws_url(&self.url, &sandbox.id)?;
        let mut request = url
            .into_client_request()
            .map_err(|e| MicrosandboxError::Runtime(format!("cloud exec request: {e}")))?;
        let bearer = format!("Bearer {}", self.api_key);
        let mut auth_value = WsHeaderValue::from_str(&bearer).map_err(|e| {
            MicrosandboxError::InvalidConfig(format!("invalid API key header value: {e}"))
        })?;
        auth_value.set_sensitive(true);
        request.headers_mut().insert(WS_AUTHORIZATION, auth_value);
        request.headers_mut().insert(
            WS_USER_AGENT,
            WsHeaderValue::from_str(&default_user_agent()).map_err(|e| {
                MicrosandboxError::InvalidConfig(format!("invalid user-agent value: {e}"))
            })?,
        );
        request.headers_mut().insert(
            SEC_WEBSOCKET_PROTOCOL,
            WsHeaderValue::from_static(CLOUD_EXEC_SUBPROTOCOL),
        );

        let (socket, _) = connect_async(request)
            .await
            .map_err(|e| MicrosandboxError::Runtime(format!("cloud exec websocket: {e}")))?;
        let (mut writer, mut reader) = socket.split();

        let ExecOptions {
            args,
            cwd,
            user,
            env,
            rlimits,
            timeout: _,
            stdin: stdin_mode,
            tty,
        } = opts;
        let req = build_exec_request(config, cmd, args, cwd, user, &env, &rlimits, tty, 24, 80);
        send_cloud_exec_message(&mut writer, MessageType::ExecRequest, &req).await?;

        if let StdinMode::Bytes(data) = stdin_mode {
            let stdin = ExecStdin { data };
            send_cloud_exec_message(&mut writer, MessageType::ExecStdin, &stdin).await?;
            let close = ExecStdin { data: Vec::new() };
            send_cloud_exec_message(&mut writer, MessageType::ExecStdin, &close).await?;
        }

        let mut frame_buf = Vec::new();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        while let Some(frame) = reader.next().await {
            match frame {
                Ok(WsMessage::Binary(bytes)) => {
                    frame_buf.extend_from_slice(&bytes);
                    while let Some(msg) = codec::try_decode_from_buf(&mut frame_buf)? {
                        match msg.t {
                            MessageType::ExecStarted => {
                                let _ = msg.payload::<ExecStarted>()?;
                            }
                            MessageType::ExecStdout => {
                                stdout.extend_from_slice(&msg.payload::<ExecStdout>()?.data);
                            }
                            MessageType::ExecStderr => {
                                stderr.extend_from_slice(&msg.payload::<ExecStderr>()?.data);
                            }
                            MessageType::ExecExited => {
                                let exited = msg.payload::<ExecExited>()?;
                                let _ = writer.close().await;
                                return Ok(ExecOutput::from_parts(
                                    ExitStatus {
                                        code: exited.code,
                                        success: exited.code == 0,
                                    },
                                    Bytes::from(stdout),
                                    Bytes::from(stderr),
                                ));
                            }
                            MessageType::ExecFailed => {
                                let failed = msg.payload::<ExecFailed>()?;
                                let _ = writer.close().await;
                                return Err(MicrosandboxError::ExecFailed(failed));
                            }
                            MessageType::ExecStdinError => {}
                            _ => {}
                        }
                    }
                }
                Ok(WsMessage::Close(_)) => break,
                Ok(_) => {}
                Err(error) => {
                    return Err(MicrosandboxError::Runtime(format!(
                        "cloud exec websocket read: {error}"
                    )));
                }
            }
        }

        Err(MicrosandboxError::Runtime(
            "cloud exec websocket closed before exit event".into(),
        ))
    }

    async fn open_log_stream_by_id(
        &self,
        sandbox_id: &str,
        opts: &LogStreamOptions,
    ) -> MicrosandboxResult<LogStream> {
        let mut query = Vec::new();
        let cloud_sources = cloud_log_sources(&opts.sources)?;
        if !cloud_sources.is_empty() {
            query.push(format!("sources={}", cloud_sources.join(",")));
        }

        let mut url = format!("{}/v1/sandboxes/{}/logs", self.url, urlencoding(sandbox_id));
        if !query.is_empty() {
            url.push('?');
            url.push_str(&query.join("&"));
        }

        let mut request = self
            .http
            .get(&url)
            .header(ACCEPT, HeaderValue::from_static("text/event-stream"));
        if let LogStreamStart::From(cursor) = &opts.start {
            request = request.header(HeaderName::from_static("last-event-id"), cursor.to_string());
        }

        let resp = request
            .send()
            .await
            .map_err(|e| cloud_io_error("GET /v1/sandboxes/:id/logs", e))?;
        let status = resp.status();
        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            let typed: Option<CloudErrorBody> = serde_json::from_str(&body_text).ok();
            return Err(cloud_http_error(
                status.as_u16(),
                typed.as_ref(),
                &body_text,
                "GET /v1/sandboxes/:id/logs",
            ));
        }

        let (tx, rx) = mpsc::unbounded_channel();
        let opts = opts.clone();
        tokio::spawn(async move {
            parse_cloud_log_sse(Box::pin(resp.bytes_stream()), opts, tx).await;
        });

        Ok(Box::pin(stream::unfold(rx, |mut rx| async {
            rx.recv().await.map(|item| (item, rx))
        })))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Logs
//--------------------------------------------------------------------------------------------------

async fn parse_cloud_log_sse(
    mut chunks: Pin<Box<dyn futures::Stream<Item = Result<Bytes, reqwest::Error>> + Send>>,
    opts: LogStreamOptions,
    tx: mpsc::UnboundedSender<MicrosandboxResult<LogEntry>>,
) {
    let mut buffer = Vec::new();

    while let Some(chunk) = chunks.next().await {
        match chunk {
            Ok(bytes) => buffer.extend_from_slice(&bytes),
            Err(error) => {
                let _ = tx.send(Err(MicrosandboxError::Http(error)));
                return;
            }
        }

        while let Some((block, consumed)) = take_sse_block(&buffer) {
            buffer.drain(..consumed);
            match parse_cloud_sse_item(&block, &opts) {
                Ok(CloudSseItem::Entry(entry)) => {
                    if tx.send(Ok(entry)).is_err() {
                        return;
                    }
                }
                Ok(CloudSseItem::End) => return,
                Ok(CloudSseItem::Ignore) => {}
                Err(error) => {
                    let _ = tx.send(Err(error));
                    return;
                }
            }
        }
    }
}

fn take_sse_block(buffer: &[u8]) -> Option<(Vec<u8>, usize)> {
    for i in 0..buffer.len() {
        if i + 3 < buffer.len() && &buffer[i..i + 4] == b"\r\n\r\n" {
            return Some((buffer[..i].to_vec(), i + 4));
        }
        if i + 1 < buffer.len() && &buffer[i..i + 2] == b"\n\n" {
            return Some((buffer[..i].to_vec(), i + 2));
        }
    }
    None
}

fn parse_cloud_sse_item(block: &[u8], opts: &LogStreamOptions) -> MicrosandboxResult<CloudSseItem> {
    let event = parse_cloud_sse_event(block)?;
    match event.event.as_deref().unwrap_or("message") {
        "log" => cloud_log_event_to_entry(event, opts),
        "end" => Ok(CloudSseItem::End),
        _ => Ok(CloudSseItem::Ignore),
    }
}

fn parse_cloud_sse_event(block: &[u8]) -> MicrosandboxResult<CloudSseEvent> {
    let text = std::str::from_utf8(block)
        .map_err(|e| MicrosandboxError::Custom(format!("invalid cloud log SSE utf-8: {e}")))?;
    let mut event = CloudSseEvent::default();

    for raw_line in text.lines() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        let (field, value) = line
            .split_once(':')
            .map(|(field, value)| (field, value.strip_prefix(' ').unwrap_or(value)))
            .unwrap_or((line, ""));
        match field {
            "id" => event.id = Some(value.to_string()),
            "event" => event.event = Some(value.to_string()),
            "data" => {
                if !event.data.is_empty() {
                    event.data.push('\n');
                }
                event.data.push_str(value);
            }
            _ => {}
        }
    }

    Ok(event)
}

fn cloud_log_event_to_entry(
    event: CloudSseEvent,
    opts: &LogStreamOptions,
) -> MicrosandboxResult<CloudSseItem> {
    let payload: CloudLogPayload = serde_json::from_str(&event.data)
        .map_err(|e| MicrosandboxError::Custom(format!("invalid cloud log event payload: {e}")))?;

    if let Some(until) = opts.until
        && payload.ts >= until
    {
        return Ok(CloudSseItem::End);
    }
    if let LogStreamStart::Since(since) = opts.start
        && payload.ts < since
    {
        return Ok(CloudSseItem::Ignore);
    }

    let source = parse_cloud_log_source(&payload.source)?;
    let cursor = match event.id {
        Some(id) if !id.is_empty() => id
            .parse::<LogCursor>()
            .map_err(|e| MicrosandboxError::InvalidCursor(e.to_string()))?,
        _ => LogCursor::empty(),
    };

    Ok(CloudSseItem::Entry(LogEntry {
        timestamp: payload.ts,
        source,
        session_id: None,
        data: Bytes::from(payload.text),
        cursor,
    }))
}

fn cloud_log_sources(requested: &[LogSource]) -> MicrosandboxResult<Vec<String>> {
    if requested.is_empty() {
        return Ok(Vec::new());
    }

    LogSource::effective(requested)
        .into_iter()
        .map(|source| match source {
            LogSource::Stdout => Ok("stdout".to_string()),
            LogSource::Stderr => Ok("stderr".to_string()),
            LogSource::System => Ok("system".to_string()),
            LogSource::Output => Err(MicrosandboxError::Unsupported {
                feature: "cloud log source 'output'".into(),
                available_when: "when msb-cloud accepts the output log source".into(),
            }),
        })
        .collect()
}

fn parse_cloud_log_source(source: &str) -> MicrosandboxResult<LogSource> {
    match source {
        "stdout" => Ok(LogSource::Stdout),
        "stderr" => Ok(LogSource::Stderr),
        "system" => Ok(LogSource::System),
        "output" => Ok(LogSource::Output),
        other => Err(MicrosandboxError::Custom(format!(
            "unknown cloud log source: {other}"
        ))),
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Exec
//--------------------------------------------------------------------------------------------------

async fn send_cloud_exec_message<S, T>(
    writer: &mut S,
    t: MessageType,
    payload: &T,
) -> MicrosandboxResult<()>
where
    S: futures::Sink<WsMessage, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
    T: serde::Serialize,
{
    let msg = Message::with_payload(t, CLOUD_EXEC_ID, payload)?;
    let mut buf = Vec::new();
    codec::encode_to_buf(&msg, &mut buf)?;
    writer
        .send(WsMessage::Binary(buf.into()))
        .await
        .map_err(|e| MicrosandboxError::Runtime(format!("cloud exec websocket write: {e}")))
}

fn cloud_exec_ws_url(base: &str, sandbox_id: &str) -> MicrosandboxResult<String> {
    let ws_base = if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else {
        return Err(MicrosandboxError::InvalidConfig(format!(
            "cloud backend URL must start with http:// or https://: {base}"
        )));
    };

    Ok(format!(
        "{}/v1/sandboxes/{}/exec.cbor",
        ws_base,
        urlencoding(sandbox_id)
    ))
}

//--------------------------------------------------------------------------------------------------
// Functions: HTTP helpers
//--------------------------------------------------------------------------------------------------

/// Parse a JSON response into `T`, mapping HTTP errors to typed
/// `MicrosandboxError` variants. Tries to decode msb-cloud's typed error body
/// for richer messages on 4xx/5xx.
async fn decode_json<T: serde::de::DeserializeOwned>(
    resp: Response,
    op: &str,
) -> MicrosandboxResult<T> {
    let status = resp.status();
    if status.is_success() {
        return resp
            .json::<T>()
            .await
            .map_err(|e| MicrosandboxError::Custom(format!("{op}: failed to decode body: {e}")));
    }
    let body_text = resp.text().await.unwrap_or_default();
    let typed: Option<CloudErrorBody> = serde_json::from_str(&body_text).ok();
    Err(cloud_http_error(
        status.as_u16(),
        typed.as_ref(),
        &body_text,
        op,
    ))
}

fn cloud_io_error(op: &str, e: reqwest::Error) -> MicrosandboxError {
    tracing::debug!(operation = op, error = %e, "cloud backend transport error");
    MicrosandboxError::Http(e)
}

fn cloud_http_error(
    status: u16,
    body: Option<&CloudErrorBody>,
    raw_body: &str,
    op: &str,
) -> MicrosandboxError {
    let code = cloud_error_code(body).map(ToOwned::to_owned);
    let summary = cloud_error_message(body)
        .or_else(|| (!raw_body.trim().is_empty()).then_some(raw_body.trim()))
        .unwrap_or("no response body");
    let message = format!("{op}: {summary}");

    match code.as_deref() {
        Some("sandbox_not_found") => return MicrosandboxError::SandboxNotFound(message),
        Some("name_already_exists") => return MicrosandboxError::SandboxAlreadyExists(message),
        Some("invalid_request") | Some("invalid_sandbox_config") => {
            return MicrosandboxError::InvalidConfig(message);
        }
        Some("orchestrator_unreachable") | Some("nomad_job_failed") => {
            return MicrosandboxError::Runtime(message);
        }
        _ => {}
    }

    match status {
        400 | 422 => MicrosandboxError::InvalidConfig(message),
        404 => MicrosandboxError::SandboxNotFound(message),
        409 if op == "POST /v1/sandboxes" => MicrosandboxError::SandboxAlreadyExists(message),
        502 => MicrosandboxError::Runtime(message),
        _ => MicrosandboxError::CloudHttp {
            status,
            code,
            message,
        },
    }
}

fn cloud_error_code(body: Option<&CloudErrorBody>) -> Option<&str> {
    body.and_then(|body| {
        body.error
            .as_ref()
            .and_then(|err| err.code.as_deref())
            .or(body.code.as_deref())
    })
}

fn cloud_error_message(body: Option<&CloudErrorBody>) -> Option<&str> {
    body.and_then(|body| {
        body.error
            .as_ref()
            .and_then(|err| err.message.as_deref())
            .or(body.message.as_deref())
    })
}

/// Minimal percent-encoding for path segments. Avoids pulling in another crate
/// for one call site. Encodes characters outside the unreserved set per RFC
/// 3986 (`ALPHA / DIGIT / "-" / "." / "_" / "~"`).
fn urlencoding(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match *b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(*b as char);
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

//--------------------------------------------------------------------------------------------------
// Methods: CloudBackendBuilder
//--------------------------------------------------------------------------------------------------

impl CloudBackendBuilder {
    /// Set the msb-cloud endpoint URL.
    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    /// Set the API key (`msb_live_...` / `msb_test_...`).
    pub fn api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    /// Set the per-request timeout for outbound HTTP calls.
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Override the default `User-Agent` header value.
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// Provide a fully custom `reqwest::Client`. When set, `request_timeout`
    /// and `user_agent` builder options are ignored — the supplied client owns
    /// its own configuration.
    pub fn client(mut self, client: reqwest::Client) -> Self {
        self.custom_client = Some(client);
        self
    }

    /// Build the `CloudBackend`. Errors when URL or API key are missing, or
    /// when the underlying HTTP client fails to construct.
    pub fn build(self) -> MicrosandboxResult<CloudBackend> {
        let url = self.url.ok_or_else(|| {
            MicrosandboxError::InvalidConfig("CloudBackend requires a URL (call .url(...))".into())
        })?;
        let url = url.trim();
        if url.is_empty() {
            return Err(MicrosandboxError::InvalidConfig(
                "CloudBackend URL must not be empty".into(),
            ));
        }
        let api_key = self.api_key.ok_or_else(|| {
            MicrosandboxError::InvalidConfig(
                "CloudBackend requires an API key (call .api_key(...))".into(),
            )
        })?;
        let api_key = api_key.trim();
        if api_key.is_empty() {
            return Err(MicrosandboxError::InvalidConfig(
                "CloudBackend API key must not be empty".into(),
            ));
        }
        // Normalise trailing slash so per-route construction can append cleanly.
        let url = url.trim_end_matches('/').to_string();
        let api_key = api_key.to_string();

        let http = if let Some(client) = self.custom_client {
            client
        } else {
            let mut headers = HeaderMap::new();
            let bearer = format!("Bearer {api_key}");
            let mut auth_value = HeaderValue::from_str(&bearer).map_err(|e| {
                MicrosandboxError::InvalidConfig(format!("invalid API key header value: {e}"))
            })?;
            auth_value.set_sensitive(true);
            headers.insert(AUTHORIZATION, auth_value);
            let ua = self.user_agent.unwrap_or_else(default_user_agent);
            headers.insert(
                USER_AGENT,
                HeaderValue::from_str(&ua).map_err(|e| {
                    MicrosandboxError::InvalidConfig(format!("invalid user-agent value: {e}"))
                })?,
            );

            reqwest::Client::builder()
                .timeout(self.request_timeout)
                .default_headers(headers)
                .build()
                .map_err(|e| {
                    MicrosandboxError::InvalidConfig(format!("failed to build HTTP client: {e}"))
                })?
        };

        Ok(CloudBackend { url, api_key, http })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Backend for CloudBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Cloud
    }

    fn sandboxes(&self) -> &dyn SandboxBackend {
        self
    }

    fn volumes(&self) -> &dyn VolumeBackend {
        self
    }
}

impl Default for CloudBackendBuilder {
    fn default() -> Self {
        Self {
            url: None,
            api_key: None,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            user_agent: None,
            custom_client: None,
        }
    }
}

impl From<CloudBackend> for Arc<dyn Backend> {
    fn from(backend: CloudBackend) -> Self {
        Arc::new(backend)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_succeeds_with_url_and_key() {
        let b = CloudBackend::new("https://msb.example.com", "msb_test_abc").unwrap();
        assert_eq!(b.kind(), BackendKind::Cloud);
        assert_eq!(b.url(), "https://msb.example.com");
    }

    #[test]
    fn new_strips_trailing_slash() {
        let b = CloudBackend::new("https://msb.example.com/", "msb_test_abc").unwrap();
        assert_eq!(b.url(), "https://msb.example.com");
    }

    #[test]
    fn builder_rejects_missing_url() {
        assert!(CloudBackendBuilder::default().api_key("k").build().is_err());
    }

    #[test]
    fn builder_rejects_missing_key() {
        assert!(
            CloudBackendBuilder::default()
                .url("https://x")
                .build()
                .is_err()
        );
    }

    #[test]
    fn builder_rejects_empty_url() {
        assert!(CloudBackend::new("", "k").is_err());
    }

    #[test]
    fn builder_rejects_whitespace_url() {
        assert!(CloudBackend::new("   ", "k").is_err());
    }

    #[test]
    fn builder_rejects_empty_key() {
        assert!(CloudBackend::new("https://x", "").is_err());
    }

    #[test]
    fn builder_rejects_whitespace_key() {
        assert!(CloudBackend::new("https://x", "   ").is_err());
    }

    #[test]
    fn from_env_errors_when_url_missing() {
        // Note: this test can race with parallel tests setting env vars. Just
        // verify the function returns an error when MSB_API_URL is clearly absent;
        // we don't try to scrub env state.
        unsafe { std::env::remove_var("MSB_API_URL") };
        assert!(CloudBackend::from_env().is_err());
    }

    #[test]
    fn cloud_http_error_uses_nested_error_body() {
        let body: CloudErrorBody = serde_json::from_str(
            r#"{"error":{"code":"sandbox_not_found","message":"sandbox missing"}}"#,
        )
        .unwrap();
        let err = cloud_http_error(404, Some(&body), "", "GET /v1/sandboxes/by-name/:name");
        assert!(
            matches!(err, MicrosandboxError::SandboxNotFound(msg) if msg.contains("sandbox missing"))
        );
    }

    #[test]
    fn cloud_http_error_maps_create_conflict_to_already_exists() {
        let body: CloudErrorBody = serde_json::from_str(
            r#"{"error":{"code":"name_already_exists","message":"name taken"}}"#,
        )
        .unwrap();
        let err = cloud_http_error(409, Some(&body), "", "POST /v1/sandboxes");
        assert!(
            matches!(err, MicrosandboxError::SandboxAlreadyExists(msg) if msg.contains("name taken"))
        );
    }

    #[test]
    fn cloud_exec_ws_url_maps_http_schemes() {
        assert_eq!(
            cloud_exec_ws_url("http://127.0.0.1:8080", "sandbox id").unwrap(),
            "ws://127.0.0.1:8080/v1/sandboxes/sandbox%20id/exec.cbor"
        );
        assert_eq!(
            cloud_exec_ws_url("https://cloud.example.com", "abc").unwrap(),
            "wss://cloud.example.com/v1/sandboxes/abc/exec.cbor"
        );
    }

    #[test]
    fn cloud_exec_ws_url_rejects_non_http_url() {
        let err = cloud_exec_ws_url("file:///tmp/api", "abc").unwrap_err();

        assert!(matches!(err, MicrosandboxError::InvalidConfig(_)));
    }

    #[test]
    fn cloud_log_sse_event_maps_to_log_entry() {
        let cursor = LogCursor::empty().to_string();
        let block = format!(
            "id: {cursor}\nevent: log\ndata: {{\"source\":\"stdout\",\"ts\":\"2026-05-31T10:00:00Z\",\"text\":\"hello\"}}"
        );

        let item = parse_cloud_sse_item(block.as_bytes(), &LogStreamOptions::default()).unwrap();

        let CloudSseItem::Entry(entry) = item else {
            panic!("expected log entry");
        };
        assert_eq!(entry.source, LogSource::Stdout);
        assert_eq!(entry.data, Bytes::from_static(b"hello"));
        assert_eq!(entry.cursor.to_string(), cursor);
    }

    #[test]
    fn cloud_log_sse_since_filters_old_entries() {
        let opts = LogStreamOptions {
            start: LogStreamStart::Since(
                "2026-05-31T10:00:01Z"
                    .parse::<chrono::DateTime<chrono::Utc>>()
                    .unwrap(),
            ),
            ..Default::default()
        };
        let block =
            b"event: log\ndata: {\"source\":\"stderr\",\"ts\":\"2026-05-31T10:00:00Z\",\"text\":\"old\"}";

        let item = parse_cloud_sse_item(block, &opts).unwrap();

        assert!(matches!(item, CloudSseItem::Ignore));
    }

    #[test]
    fn cloud_log_sources_rejects_output_until_cloud_supports_it() {
        let err = cloud_log_sources(&[LogSource::Output]).unwrap_err();

        assert!(matches!(err, MicrosandboxError::Unsupported { .. }));
    }
}

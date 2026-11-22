//! HTTP and SSE plumbing for the cloud backend.
//!
//! Route-level methods on [`RemoteContext`] (sandbox lifecycle, volumes, log
//! streaming), the SSE parser behind the log stream, and the shared
//! decode/error helpers they route through. Connection construction (URL,
//! API key, HTTP client) stays in the parent module.

use std::pin::Pin;
use std::time::Duration;

use bytes::Bytes;
use futures::{StreamExt, stream};
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderName, HeaderValue, USER_AGENT};
use reqwest::{Body, Method, RequestBuilder, Response, StatusCode};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use super::{RemoteContext, sandbox::CloudCreateBody, volume::CloudVolume};
use crate::context::sandbox::LogStream;
use crate::error::{Operation, UnsupportedReason};
use crate::logs::{LogCursor, LogEntry, LogOptions, LogSource, LogStreamOptions, LogStreamStart};
use crate::sandbox::{SandboxListBuilder, SandboxModificationPlan};
use crate::{MicrosandboxError, MicrosandboxResult};
use microsandbox_types::{
    CloudCreateSandboxResponse, CloudErrorBody, CloudMessageResponse, CloudPaginated,
    CloudSandboxModificationApplyRequest, CloudSandboxModificationPlan,
    CloudSandboxModificationPlanRequest,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Server-held readiness budget requested for lifecycle start calls.
const CLOUD_READY_WAIT_TIMEOUT_SECS: u64 = 90;

/// Network headroom beyond the server wait so the JSON response can arrive
/// before reqwest's ordinary 30-second client timeout applies.
const CLOUD_READY_HTTP_TIMEOUT: Duration = Duration::from_secs(95);

/// Extra time a restart request waits beyond its shutdown timeout.
const CLOUD_RESTART_HTTP_ALLOWANCE: Duration = Duration::from_secs(4 * 60);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

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

/// How a volume file request bounds its time on the network.
pub(in crate::context) enum FileTransfer {
    /// Small request and response, bounded by the request timeout as a total.
    Request,
    /// File read: the request timeout bounds the wait for the response and
    /// each wait for more data, not the whole transfer.
    Download,
    /// File write, retaining the ordinary total request timeout (or the custom
    /// client's timeout). Body polling cannot measure transport write progress.
    Upload(Body),
}

#[derive(Serialize)]
struct CloudSandboxListQuery<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<&'a str>,
    limit: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    labels: Option<String>,
}

#[derive(Serialize)]
struct CloudSandboxRestartQuery {
    force: bool,
    timeout: u64,
}

#[derive(Serialize)]
struct CloudSandboxWaitQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    start: Option<bool>,
    wait_for: &'static str,
    wait_timeout: u64,
}

//--------------------------------------------------------------------------------------------------
// Methods: Sandbox lifecycle
//
// HTTP dispatch for the SDK's sandbox lifecycle ops, hitting the cloud API's
// API-key-authenticated routes (`/v1/sandboxes/*` and `/v1/sandboxes/by-name/*`).
//--------------------------------------------------------------------------------------------------

impl RemoteContext {
    /// Authentication belongs to the destination, not the shared connection pool. A derived
    /// context can safely reuse a custom client without inheriting its default credentials.
    pub(super) fn request(&self, method: Method, url: &str) -> RequestBuilder {
        self.authorize_request(self.inner.http.request(method, url))
    }

    fn stream_request(&self, method: Method, url: &str) -> RequestBuilder {
        self.apply_request_headers(self.inner.http.request(method, url))
    }

    pub(super) fn authorize_request(&self, request: RequestBuilder) -> RequestBuilder {
        let request = self.apply_request_headers(request);
        if self.inner.user_agent_header.is_some() {
            request.timeout(self.inner.request_timeout)
        } else {
            request
        }
    }

    fn apply_request_headers(&self, request: RequestBuilder) -> RequestBuilder {
        let request = request.header(AUTHORIZATION, self.inner.authorization.clone());
        match &self.inner.user_agent_header {
            Some(agent) => request.header(USER_AGENT, agent.clone()),
            None => request,
        }
    }

    /// `POST /v1/sandboxes` (optionally create, start, and wait for readiness).
    ///
    /// Pass `start=true` to atomically create-and-start in a single round-trip
    /// — mirrors the cloud API's create-and-start shorthand. The SDK also requests
    /// the opt-in server-side readiness barrier so a successful high-level
    /// create has the same immediately-usable contract as the local backend.
    pub(in crate::context) async fn create_sandbox(
        &self,
        req: &CloudCreateBody,
        start: bool,
    ) -> MicrosandboxResult<CloudCreateSandboxResponse> {
        let url = format!("{}/v1/sandboxes", self.inner.url);
        let mut request = self.request(Method::POST, &url).json(req);
        if start {
            let query = CloudSandboxWaitQuery {
                start: Some(true),
                wait_for: "running",
                wait_timeout: CLOUD_READY_WAIT_TIMEOUT_SECS,
            };
            request = request.query(&query).timeout(CLOUD_READY_HTTP_TIMEOUT);
        }
        let resp = request
            .send()
            .await
            .map_err(|e| cloud_io_error("POST /v1/sandboxes", e))?;
        decode_json(resp, "POST /v1/sandboxes").await
    }

    /// `GET /v1/sandboxes` — paginated.
    pub async fn list_sandboxes(
        &self,
        query: &SandboxListBuilder,
    ) -> MicrosandboxResult<CloudPaginated<CloudCreateSandboxResponse>> {
        let url = format!("{}/v1/sandboxes", self.inner.url);
        let labels = (!query.labels.is_empty())
            .then(|| serde_json::to_string(&query.labels))
            .transpose()?;
        let params = CloudSandboxListQuery {
            cursor: query.cursor.as_deref(),
            limit: query.limit,
            labels,
        };
        let resp = self
            .request(Method::GET, &url)
            .query(&params)
            .send()
            .await
            .map_err(|e| cloud_io_error("GET /v1/sandboxes", e))?;
        decode_json(resp, "GET /v1/sandboxes").await
    }

    /// `GET /v1/sandboxes/by-name/:name`.
    pub async fn get_sandbox(&self, name: &str) -> MicrosandboxResult<CloudCreateSandboxResponse> {
        let path = format!("/v1/sandboxes/by-name/{}", urlencoding(name));
        let url = format!("{}{path}", self.inner.url);
        let op = format!("GET {path}");
        let resp = self
            .request(Method::GET, &url)
            .send()
            .await
            .map_err(|e| cloud_io_error(&op, e))?;
        decode_json(resp, &op).await
    }

    /// `GET /v1/sandboxes/:id` for identity-safe receiver operations.
    pub(in crate::context) async fn get_sandbox_by_id(
        &self,
        id: &str,
    ) -> MicrosandboxResult<CloudCreateSandboxResponse> {
        let path = format!("/v1/sandboxes/{}", urlencoding(id));
        let url = format!("{}{path}", self.inner.url);
        let op = format!("GET {path}");
        let resp = self
            .request(Method::GET, &url)
            .send()
            .await
            .map_err(|e| cloud_io_error(&op, e))?;
        decode_json(resp, &op).await
    }

    /// `POST /v1/sandboxes/by-name/:name/start`, waiting for readiness.
    pub async fn start_sandbox(
        &self,
        name: &str,
    ) -> MicrosandboxResult<CloudCreateSandboxResponse> {
        let path = format!("/v1/sandboxes/by-name/{}/start", urlencoding(name));
        let url = format!("{}{path}", self.inner.url);
        let op = format!("POST {path}");
        let query = CloudSandboxWaitQuery {
            start: None,
            wait_for: "running",
            wait_timeout: CLOUD_READY_WAIT_TIMEOUT_SECS,
        };
        let resp = self
            .request(Method::POST, &url)
            .json(&serde_json::json!({}))
            .query(&query)
            .timeout(CLOUD_READY_HTTP_TIMEOUT)
            .send()
            .await
            .map_err(|e| cloud_io_error(&op, e))?;
        decode_json(resp, &op).await
    }

    /// `POST /v1/sandboxes/:id/start`, waiting for readiness.
    pub(in crate::context) async fn start_sandbox_by_id(
        &self,
        id: &str,
    ) -> MicrosandboxResult<CloudCreateSandboxResponse> {
        let path = format!("/v1/sandboxes/{}/start", urlencoding(id));
        let url = format!("{}{path}", self.inner.url);
        let op = format!("POST {path}");
        let query = CloudSandboxWaitQuery {
            start: None,
            wait_for: "running",
            wait_timeout: CLOUD_READY_WAIT_TIMEOUT_SECS,
        };
        let resp = self
            .request(Method::POST, &url)
            .json(&serde_json::json!({}))
            .query(&query)
            .timeout(CLOUD_READY_HTTP_TIMEOUT)
            .send()
            .await
            .map_err(|e| cloud_io_error(&op, e))?;
        decode_json(resp, &op).await
    }

    /// `POST /v1/sandboxes/:id/restart`.
    pub(in crate::context) async fn restart_sandbox_by_id(
        &self,
        id: &str,
        force: bool,
        timeout_secs: u64,
    ) -> MicrosandboxResult<CloudCreateSandboxResponse> {
        let url = format!(
            "{}/v1/sandboxes/{}/restart",
            self.inner.url,
            urlencoding(id)
        );
        let query = CloudSandboxRestartQuery {
            force,
            timeout: timeout_secs,
        };
        let http_timeout =
            Duration::from_secs(timeout_secs).saturating_add(CLOUD_RESTART_HTTP_ALLOWANCE);
        let resp = self
            .request(Method::POST, &url)
            .json(&serde_json::json!({}))
            .query(&query)
            .timeout(http_timeout)
            .send()
            .await
            .map_err(|e| cloud_io_error("POST /v1/sandboxes/:id/restart", e))?;
        if resp.status() != StatusCode::NOT_FOUND {
            return decode_json(resp, "POST /v1/sandboxes/:id/restart").await;
        }

        // A missing sandbox carries an error code; a bare 404 is an API
        // without this route.
        let body_text = resp.text().await.unwrap_or_default();
        let typed: Option<CloudErrorBody> = serde_json::from_str(&body_text).ok();
        if cloud_error_code(typed.as_ref()).is_none() {
            return Err(MicrosandboxError::unsupported(
                Operation::SandboxRestart,
                UnsupportedReason::NotAvailable(
                    "this Microsandbox Cloud API does not support restart yet".into(),
                ),
            ));
        }
        Err(cloud_http_error(
            404,
            typed.as_ref(),
            &body_text,
            "POST /v1/sandboxes/:id/restart",
        ))
    }

    /// `POST /v1/sandboxes/:id/plan`, a dry run whose body carries no secret value.
    pub(in crate::context) async fn post_modification_plan(
        &self,
        id: &str,
        req: &CloudSandboxModificationPlanRequest,
    ) -> MicrosandboxResult<SandboxModificationPlan> {
        let url = format!("{}/v1/sandboxes/{}/plan", self.inner.url, urlencoding(id));
        let resp = self
            .request(Method::POST, &url)
            .json(req)
            .send()
            .await
            .map_err(|e| cloud_io_error("POST /v1/sandboxes/:id/plan", e))?;
        let plan: CloudSandboxModificationPlan =
            decode_json(resp, "POST /v1/sandboxes/:id/plan").await?;
        Ok(plan.into())
    }

    /// `PATCH /v1/sandboxes/:id`, sent once. The body is the only
    /// place a secret value travels; the caller reads and classifies the outcome.
    pub(in crate::context) async fn patch_modification(
        &self,
        id: &str,
        req: &CloudSandboxModificationApplyRequest,
        timeout: Duration,
    ) -> Result<Response, reqwest::Error> {
        let url = format!("{}/v1/sandboxes/{}", self.inner.url, urlencoding(id));
        self.request(Method::PATCH, &url)
            .json(req)
            .timeout(timeout)
            .send()
            .await
    }

    /// `POST /v1/sandboxes/by-name/:name/stop`.
    pub async fn stop_sandbox(&self, name: &str) -> MicrosandboxResult<CloudCreateSandboxResponse> {
        let path = format!("/v1/sandboxes/by-name/{}/stop", urlencoding(name));
        let url = format!("{}{path}", self.inner.url);
        let op = format!("POST {path}");
        let resp = self
            .request(Method::POST, &url)
            .json(&serde_json::json!({}))
            .send()
            .await
            .map_err(|e| cloud_io_error(&op, e))?;
        decode_json(resp, &op).await
    }

    /// `POST /v1/sandboxes/:id/stop` for identity-safe receiver operations.
    pub(in crate::context) async fn stop_sandbox_by_id(
        &self,
        id: &str,
    ) -> MicrosandboxResult<CloudCreateSandboxResponse> {
        let path = format!("/v1/sandboxes/{}/stop", urlencoding(id));
        let url = format!("{}{path}", self.inner.url);
        let op = format!("POST {path}");
        let resp = self
            .request(Method::POST, &url)
            .json(&serde_json::json!({}))
            .send()
            .await
            .map_err(|e| cloud_io_error(&op, e))?;
        decode_json(resp, &op).await
    }

    /// `DELETE /v1/sandboxes/by-name/:name`. Returns the typed `MessageResponse`
    /// returned by the API.
    pub async fn destroy_sandbox(&self, name: &str) -> MicrosandboxResult<CloudMessageResponse> {
        let path = format!("/v1/sandboxes/by-name/{}", urlencoding(name));
        let url = format!("{}{path}", self.inner.url);
        let op = format!("DELETE {path}");
        let resp = self
            .request(Method::DELETE, &url)
            .send()
            .await
            .map_err(|e| cloud_io_error(&op, e))?;
        decode_json(resp, &op).await
    }

    /// `DELETE /v1/sandboxes/:id` for identity-safe receiver operations.
    pub(in crate::context) async fn destroy_sandbox_by_id(
        &self,
        id: &str,
    ) -> MicrosandboxResult<CloudMessageResponse> {
        let path = format!("/v1/sandboxes/{}", urlencoding(id));
        let url = format!("{}{path}", self.inner.url);
        let op = format!("DELETE {path}");
        let resp = self
            .request(Method::DELETE, &url)
            .send()
            .await
            .map_err(|e| cloud_io_error(&op, e))?;
        decode_json(resp, &op).await
    }

    /// Stream logs from `GET /v1/sandboxes/:id/logs`.
    ///
    /// The API exposes logs as Server-Sent Events keyed by sandbox UUID, so
    /// the SDK resolves the current name to a cloud sandbox first. The cloud
    /// endpoint is streaming-only and requires a running sandbox, so callers
    /// must set `follow: true`.
    pub async fn log_stream(
        &self,
        name: &str,
        opts: &LogStreamOptions,
    ) -> MicrosandboxResult<LogStream> {
        if !opts.follow {
            return Err(MicrosandboxError::unsupported(
                Operation::SandboxLogStreamNoFollow,
                UnsupportedReason::UseInstead(Operation::SandboxLogStreamFollow),
            ));
        }

        let sandbox = self.get_sandbox(name).await?;
        self.open_log_stream_by_id(&sandbox.id, opts).await
    }

    /// Read a bounded log snapshot.
    pub async fn logs(&self, _name: &str, _opts: &LogOptions) -> MicrosandboxResult<Vec<LogEntry>> {
        Err(MicrosandboxError::unsupported(
            Operation::SandboxLogs,
            UnsupportedReason::UseInstead(Operation::SandboxLogStreamFollow),
        ))
    }

    async fn open_log_stream_by_id(
        &self,
        sandbox_id: &str,
        opts: &LogStreamOptions,
    ) -> MicrosandboxResult<LogStream> {
        let mut query = Vec::new();
        let cloud_sources = cloud_log_sources(&opts.sources);
        if !cloud_sources.is_empty() {
            query.push(format!("sources={}", cloud_sources.join(",")));
        }

        let mut url = format!(
            "{}/v1/sandboxes/{}/logs",
            self.inner.url,
            urlencoding(sandbox_id)
        );
        if !query.is_empty() {
            url.push('?');
            url.push_str(&query.join("&"));
        }

        let mut request = self
            .stream_request(Method::GET, &url)
            .header(ACCEPT, HeaderValue::from_static("text/event-stream"));
        if let LogStreamStart::From(cursor) = &opts.start {
            request = request.header(HeaderName::from_static("last-event-id"), cursor.to_string());
        }

        let resp = tokio::time::timeout(self.inner.request_timeout, request.send())
            .await
            .map_err(|_| {
                MicrosandboxError::Custom(format!(
                    "log stream: no response within {:?}",
                    self.inner.request_timeout
                ))
            })?
            .map_err(|e| cloud_io_error("GET /v1/sandboxes/:id/logs", e))?;
        let status = resp.status();
        if !status.is_success() {
            let body_text = error_body_text(resp, Some(self.inner.request_timeout)).await;
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

    //--------------------------------------------------------------------------------------------------
    // Methods: Volumes
    //--------------------------------------------------------------------------------------------------

    /// `GET /v1/volumes`.
    pub(in crate::context) async fn list_volumes(&self) -> MicrosandboxResult<Vec<CloudVolume>> {
        let url = format!("{}/v1/volumes", self.inner.url);
        let resp = self
            .request(Method::GET, &url)
            .send()
            .await
            .map_err(|e| cloud_io_error("GET /v1/volumes", e))?;
        decode_json(resp, "GET /v1/volumes").await
    }

    /// `GET /v1/volumes/default`.
    pub(in crate::context) async fn get_default_volume(&self) -> MicrosandboxResult<CloudVolume> {
        let url = format!("{}/v1/volumes/default", self.inner.url);
        let resp = self
            .request(Method::GET, &url)
            .send()
            .await
            .map_err(|e| cloud_io_error("GET /v1/volumes/default", e))?;
        decode_json(resp, "GET /v1/volumes/default").await
    }

    /// `POST /v1/volumes`.
    pub(in crate::context) async fn create_volume(
        &self,
        name: &str,
        capacity_gib: Option<u32>,
        labels: &[(String, String)],
    ) -> MicrosandboxResult<CloudVolume> {
        let labels: std::collections::BTreeMap<&str, &str> = labels
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let mut body = serde_json::json!({ "name": name, "labels": labels });
        if let Some(gib) = capacity_gib {
            body["capacity_gib"] = gib.into();
        }
        let url = format!("{}/v1/volumes", self.inner.url);
        let resp = self
            .request(Method::POST, &url)
            .json(&body)
            .send()
            .await
            .map_err(|e| cloud_io_error("POST /v1/volumes", e))?;
        decode_json(resp, "POST /v1/volumes").await
    }

    /// `DELETE /v1/volumes/:id`.
    pub(in crate::context) async fn delete_volume(
        &self,
        id: &str,
    ) -> MicrosandboxResult<CloudMessageResponse> {
        let url = format!("{}/v1/volumes/{}", self.inner.url, urlencoding(id));
        let resp = self
            .request(Method::DELETE, &url)
            .send()
            .await
            .map_err(|e| cloud_io_error("DELETE /v1/volumes/:id", e))?;
        decode_json(resp, "DELETE /v1/volumes/:id").await
    }

    /// Resolve a named volume. The cloud addresses volumes by id, so the SDK's
    /// name-based calls list and match on the user-facing name.
    pub(in crate::context) async fn find_volume(
        &self,
        name: &str,
    ) -> MicrosandboxResult<CloudVolume> {
        let volumes = self.list_volumes().await?;
        volumes
            .into_iter()
            .find(|volume| volume.name.as_deref() == Some(name))
            .ok_or_else(|| MicrosandboxError::VolumeNotFound(name.to_string()))
    }

    /// Send a volume filesystem request and preserve the streaming response.
    pub(in crate::context) async fn volume_file_request(
        &self,
        method: Method,
        id: &str,
        suffix: &str,
        headers: &[(&str, String)],
        json: Option<serde_json::Value>,
        transfer: FileTransfer,
    ) -> MicrosandboxResult<Response> {
        let url = format!(
            "{}/v1/volumes/{}/files{}",
            self.inner.url,
            urlencoding(id),
            suffix
        );
        let download = matches!(&transfer, FileTransfer::Download);
        let mut request = if download {
            self.stream_request(method, &url)
        } else {
            self.request(method, &url)
        };
        for (name, value) in headers {
            request = request.header(*name, value);
        }
        if let Some(json) = json {
            request = request.json(&json);
        }
        if let FileTransfer::Upload(body) = transfer {
            request = request.body(body);
        }
        let response = if download {
            tokio::time::timeout(self.inner.request_timeout, request.send())
                .await
                .map_err(|_| {
                    MicrosandboxError::Custom(format!(
                        "volume read: no response within {:?}",
                        self.inner.request_timeout
                    ))
                })?
                .map_err(|e| cloud_io_error("volume filesystem request", e))?
        } else {
            request
                .send()
                .await
                .map_err(|e| cloud_io_error("volume filesystem request", e))?
        };
        ensure_success_with_timeout(
            response,
            "volume filesystem request",
            download.then_some(self.inner.request_timeout),
        )
        .await
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: HTTP helpers
//--------------------------------------------------------------------------------------------------

/// Stream a volume file read, failing when no data arrives within `timeout`.
pub(super) fn volume_download_stream(
    response: Response,
    timeout: Duration,
) -> Pin<Box<dyn futures::Stream<Item = MicrosandboxResult<Bytes>> + Send>> {
    let chunks = Box::pin(response.bytes_stream());
    let stream = stream::unfold((chunks, false), move |(mut chunks, finished)| async move {
        if finished {
            return None;
        }

        match tokio::time::timeout(timeout, chunks.next()).await {
            Ok(Some(Ok(bytes))) => Some((Ok(bytes), (chunks, false))),
            Ok(Some(Err(error))) => Some((
                Err(MicrosandboxError::Custom(format!(
                    "volume read failed: {error}"
                ))),
                (chunks, true),
            )),
            Ok(None) => None,
            Err(_) => Some((
                Err(MicrosandboxError::Custom(format!(
                    "volume read stalled: no data for {timeout:?}"
                ))),
                (chunks, true),
            )),
        }
    });
    Box::pin(stream)
}

/// Parse a JSON response into `T`, mapping HTTP errors to typed
/// `MicrosandboxError` variants. Tries to decode the cloud API's typed error body
/// for richer messages on 4xx/5xx.
pub(super) async fn decode_json<T: serde::de::DeserializeOwned>(
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

pub(super) async fn ensure_success(resp: Response, op: &str) -> MicrosandboxResult<Response> {
    ensure_success_with_timeout(resp, op, None).await
}

async fn ensure_success_with_timeout(
    resp: Response,
    op: &str,
    timeout: Option<Duration>,
) -> MicrosandboxResult<Response> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    let body_text = error_body_text(resp, timeout).await;
    let typed: Option<CloudErrorBody> = serde_json::from_str(&body_text).ok();
    Err(cloud_http_error(
        status.as_u16(),
        typed.as_ref(),
        &body_text,
        op,
    ))
}

async fn error_body_text(resp: Response, timeout: Option<Duration>) -> String {
    match timeout {
        Some(timeout) => tokio::time::timeout(timeout, resp.text())
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or_default(),
        None => resp.text().await.unwrap_or_default(),
    }
}

pub(super) fn cloud_io_error(op: &str, e: reqwest::Error) -> MicrosandboxError {
    tracing::debug!(operation = op, error = %e, "cloud backend transport error");
    MicrosandboxError::Http(e)
}

pub(super) fn cloud_http_error(
    status: u16,
    body: Option<&CloudErrorBody>,
    raw_body: &str,
    op: &str,
) -> MicrosandboxError {
    let code = cloud_error_code(body).map(ToOwned::to_owned);
    let summary = cloud_error_message(body)
        .or_else(|| (!raw_body.trim().is_empty()).then_some(raw_body.trim()))
        .unwrap_or("no response body");
    let message = if status == 401 {
        format!(
            "{op}: {summary}. Check MSB_API_KEY or the selected cloud profile's credentials; create a replacement key at https://dashboard.microsandbox.dev if the key has expired or been revoked"
        )
    } else {
        format!("{op}: {summary}")
    };

    match code.as_deref() {
        Some("sandbox_not_found") => return MicrosandboxError::SandboxNotFound(message),
        Some("snapshot_not_found") => return MicrosandboxError::SnapshotNotFound(message),
        Some("snapshot_operation_not_found") => {
            return MicrosandboxError::SnapshotNotFound(message);
        }
        Some("volume_not_found") => return MicrosandboxError::VolumeNotFound(message),
        Some("service_not_found") => return MicrosandboxError::ServiceNotFound(message),
        Some("service_already_exists") => {
            return MicrosandboxError::ServiceAlreadyExists(message);
        }
        Some("volume_file_not_found") => return MicrosandboxError::SandboxFsOps(message),
        Some("snapshot_name_already_exists") | Some("snapshot_already_exists") => {
            return MicrosandboxError::SnapshotAlreadyExists(message);
        }
        Some("name_already_exists") if op == "POST /v1/snapshots" => {
            return MicrosandboxError::SnapshotAlreadyExists(message);
        }
        Some("name_already_exists") if op == "POST /v1/volumes" => {
            return MicrosandboxError::VolumeAlreadyExists(message);
        }
        Some("name_already_exists") => return MicrosandboxError::SandboxAlreadyExists(message),
        Some("invalid_request") | Some("invalid_sandbox_config") | Some("invalid_volume_path") => {
            return MicrosandboxError::InvalidConfig(message);
        }
        Some(
            "invalid_pagination"
            | "invalid_snapshot_name"
            | "invalid_snapshot_path"
            | "invalid_snapshot_source"
            | microsandbox_types::CLOUD_MODIFICATION_FAILED,
        ) if matches!(status, 400 | 422) => {
            // Preserve known API client-rejection contracts without classifying
            // an unrecognized proxy response from its HTTP status alone.
            return MicrosandboxError::InvalidConfig(message);
        }
        Some("orchestrator_unreachable") | Some("nomad_job_failed") => {
            return MicrosandboxError::Runtime(message);
        }
        Some(microsandbox_types::CLOUD_MODIFICATION_UNSUPPORTED) => {
            return MicrosandboxError::unsupported(
                Operation::SandboxModify,
                UnsupportedReason::NotAvailable(message),
            );
        }
        _ => {}
    }

    // A proxy or a misrouted request can also return 400/422. Only the explicit
    // validation codes above establish that the caller's configuration is wrong.
    match status {
        404 if op.contains("/v1/snapshots") || op.contains("/v1/snapshot-operations") => {
            MicrosandboxError::SnapshotNotFound(message)
        }
        404 if op.contains("/v1/volumes") => MicrosandboxError::VolumeNotFound(message),
        404 if op.contains("/v1/services") => MicrosandboxError::ServiceNotFound(message),
        404 => MicrosandboxError::SandboxNotFound(message),
        409 if op == "POST /v1/sandboxes" => MicrosandboxError::SandboxAlreadyExists(message),
        409 if op == "POST /v1/volumes" => MicrosandboxError::VolumeAlreadyExists(message),
        409 if op == "POST /v1/snapshots" => MicrosandboxError::SnapshotAlreadyExists(message),
        502 => MicrosandboxError::Runtime(message),
        _ => MicrosandboxError::CloudHttp {
            status,
            code,
            message,
        },
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

    loop {
        let chunk = tokio::select! {
            biased;
            _ = tx.closed() => return,
            chunk = chunks.next() => chunk,
        };
        let Some(chunk) = chunk else {
            return;
        };

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

fn cloud_log_sources(requested: &[LogSource]) -> Vec<String> {
    LogSource::effective(requested)
        .into_iter()
        .map(|source| {
            match source {
                LogSource::Stdout => "stdout",
                LogSource::Stderr => "stderr",
                LogSource::System => "system",
                LogSource::Output => "output",
            }
            .to_string()
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

pub(super) fn cloud_error_code(body: Option<&CloudErrorBody>) -> Option<&str> {
    body.and_then(|body| {
        body.error
            .as_ref()
            .and_then(|err| err.code.as_deref())
            .or(body.code.as_deref())
    })
}

pub(super) fn cloud_error_message(body: Option<&CloudErrorBody>) -> Option<&str> {
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
pub(super) fn urlencoding(s: &str) -> String {
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
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    use super::*;
    use crate::test_support;

    #[test]
    fn unexpected_http_errors_preserve_status_and_server_message() {
        let raw = "Connection header did not include upgrade";
        for status in [400, 405, 422, 500, 503] {
            for body in [
                None,
                Some(
                    serde_json::from_value::<CloudErrorBody>(
                        serde_json::json!({"error": {"code": "routing_error", "message": raw}}),
                    )
                    .unwrap(),
                ),
            ] {
                let error = cloud_http_error(status, body.as_ref(), raw, "GET /v1/sandboxes");
                let MicrosandboxError::CloudHttp {
                    status: actual,
                    code,
                    message,
                } = error
                else {
                    panic!("unexpected server error was misclassified: {error:?}");
                };
                assert_eq!(actual, status);
                assert_eq!(code.as_deref(), body.as_ref().map(|_| "routing_error"));
                assert_eq!(message, format!("GET /v1/sandboxes: {raw}"));
            }
        }
    }

    #[test]
    fn explicit_validation_codes_keep_invalid_config_classification() {
        for code in [
            "invalid_request",
            "invalid_sandbox_config",
            "invalid_volume_path",
            "invalid_pagination",
            "invalid_snapshot_name",
            "invalid_snapshot_path",
            "invalid_snapshot_source",
            microsandbox_types::CLOUD_MODIFICATION_FAILED,
        ] {
            for status in [400, 422] {
                // Both API error envelopes have shipped; keep their existing classification.
                for value in [
                    serde_json::json!({"code": code, "message": "invalid field"}),
                    serde_json::json!({"error": {"code": code, "message": "invalid field"}}),
                ] {
                    let body = serde_json::from_value(value).unwrap();
                    assert!(matches!(
                        cloud_http_error(status, Some(&body), "", "POST /v1/sandboxes"),
                        MicrosandboxError::InvalidConfig(message) if message.contains("invalid field")
                    ));
                }
            }
        }
    }

    #[tokio::test]
    async fn lifecycle_errors_identify_the_actual_encoded_request_path() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend = test_support::cloud_backend(
            format!("http://{}", listener.local_addr().unwrap()),
            "test-key-not-for-diagnostics",
        )
        .unwrap();
        let operations = [
            ("GET", "/v1/sandboxes/by-name/team%20agent%2Fone"),
            ("POST", "/v1/sandboxes/by-name/team%20agent%2Fone/start"),
            ("POST", "/v1/sandboxes/by-name/team%20agent%2Fone/stop"),
            ("DELETE", "/v1/sandboxes/by-name/team%20agent%2Fone"),
            ("GET", "/v1/sandboxes/sandbox-id"),
            ("POST", "/v1/sandboxes/sandbox-id/start"),
            ("POST", "/v1/sandboxes/sandbox-id/stop"),
            ("DELETE", "/v1/sandboxes/sandbox-id"),
        ];
        let server = tokio::spawn(async move {
            for (method, path) in operations {
                let (stream, _) = listener.accept().await.unwrap();
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                reader.read_line(&mut line).await.unwrap();
                let query = if path.ends_with("/start") {
                    "?wait_for=running&wait_timeout=90"
                } else {
                    ""
                };
                assert_eq!(line.trim(), format!("{method} {path}{query} HTTP/1.1"));
                let mut length = 0;
                loop {
                    line.clear();
                    assert_ne!(reader.read_line(&mut line).await.unwrap(), 0);
                    if line == "\r\n" {
                        break;
                    }
                    if let Some((key, value)) = line.split_once(':')
                        && key.eq_ignore_ascii_case("content-length")
                    {
                        length = value.trim().parse::<usize>().unwrap();
                    }
                }
                reader.read_exact(&mut vec![0; length]).await.unwrap();
                let body = "Connection header did not include upgrade";
                reader.get_mut().write_all(format!(
                    "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()
                ).as_bytes()).await.unwrap();
            }
        });
        for (index, (method, path)) in operations.into_iter().enumerate() {
            let error = tokio::time::timeout(Duration::from_secs(5), async {
                match index {
                    0 => backend.get_sandbox("team agent/one").await.unwrap_err(),
                    1 => backend.start_sandbox("team agent/one").await.unwrap_err(),
                    2 => backend.stop_sandbox("team agent/one").await.unwrap_err(),
                    3 => backend.destroy_sandbox("team agent/one").await.unwrap_err(),
                    4 => backend.get_sandbox_by_id("sandbox-id").await.unwrap_err(),
                    5 => backend.start_sandbox_by_id("sandbox-id").await.unwrap_err(),
                    6 => backend.stop_sandbox_by_id("sandbox-id").await.unwrap_err(),
                    _ => backend
                        .destroy_sandbox_by_id("sandbox-id")
                        .await
                        .unwrap_err(),
                }
            })
            .await
            .unwrap();
            let MicrosandboxError::CloudHttp {
                status,
                code,
                message,
            } = error
            else {
                panic!("unexpected server error was misclassified: {error:?}");
            };
            assert_eq!(status, 400);
            assert_eq!(code, None);
            assert_eq!(
                message,
                format!("{method} {path}: Connection header did not include upgrade")
            );
        }
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn unauthorized_errors_keep_their_type_and_explain_credential_recovery() {
        let body: CloudErrorBody =
            serde_json::from_str(r#"{"error":{"code":"unauthorized","message":"unauthorized"}}"#)
                .unwrap();
        let error = cloud_http_error(401, Some(&body), "", "GET /v1/sandboxes");
        let MicrosandboxError::CloudHttp {
            status,
            code,
            message,
        } = error
        else {
            panic!("authentication error type changed")
        };
        assert_eq!(status, 401);
        assert_eq!(code.as_deref(), Some("unauthorized"));
        assert!(message.contains("MSB_API_KEY"));
        assert!(message.contains("https://dashboard.microsandbox.dev"));
        let forbidden = cloud_http_error(403, Some(&body), "", "GET /v1/sandboxes");
        assert!(!forbidden.to_string().contains("replacement key"));
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

        let err = cloud_http_error(409, Some(&body), "", "POST /v1/volumes");
        assert!(matches!(
            err,
            MicrosandboxError::VolumeAlreadyExists(msg) if msg.contains("name taken")
        ));
    }

    #[test]
    fn cloud_http_error_maps_snapshot_lifecycle_errors() {
        let missing: CloudErrorBody = serde_json::from_str(
            r#"{"error":{"code":"snapshot_not_found","message":"snapshot missing"}}"#,
        )
        .unwrap();
        let conflict: CloudErrorBody = serde_json::from_str(
            r#"{"error":{"code":"snapshot_name_already_exists","message":"name taken"}}"#,
        )
        .unwrap();

        assert!(matches!(
            cloud_http_error(404, Some(&missing), "", "GET /v1/snapshots/:id"),
            MicrosandboxError::SnapshotNotFound(_)
        ));
        assert!(matches!(
            cloud_http_error(409, Some(&conflict), "", "POST /v1/snapshots"),
            MicrosandboxError::SnapshotAlreadyExists(_)
        ));
    }

    #[test]
    fn cloud_http_error_distinguishes_volume_and_file_not_found() {
        let volume: CloudErrorBody = serde_json::from_str(
            r#"{"error":{"code":"volume_not_found","message":"volume missing"}}"#,
        )
        .unwrap();
        let file: CloudErrorBody = serde_json::from_str(
            r#"{"error":{"code":"volume_file_not_found","message":"path missing"}}"#,
        )
        .unwrap();

        assert!(matches!(
            cloud_http_error(404, Some(&volume), "", "volume filesystem request"),
            MicrosandboxError::VolumeNotFound(_)
        ));
        assert!(matches!(
            cloud_http_error(404, Some(&file), "", "volume filesystem request"),
            MicrosandboxError::SandboxFsOps(_)
        ));
    }

    #[test]
    fn cloud_http_error_maps_modification_unsupported() {
        let unsupported: CloudErrorBody = serde_json::from_str(
            r#"{"error":{"code":"modification_unsupported","message":"secrets: not supported"}}"#,
        )
        .unwrap();
        let op = "PATCH /v1/sandboxes/:id";

        assert!(matches!(
            cloud_http_error(409, Some(&unsupported), "", op),
            MicrosandboxError::Unsupported {
                op: Operation::SandboxModify,
                reason: UnsupportedReason::NotAvailable(message),
            } if message == format!("{op}: secrets: not supported")
        ));
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
    fn cloud_log_sources_include_pty_output() {
        let sources = cloud_log_sources(&[LogSource::Output]);

        assert_eq!(sources, ["output"]);
    }

    #[test]
    fn cloud_log_sources_use_the_cross_backend_default() {
        let sources = cloud_log_sources(&[]);

        assert_eq!(sources, ["stdout", "stderr", "output"]);
    }

    #[test]
    fn cloud_log_sse_event_maps_pty_output_to_log_entry() {
        let block = b"event: log\ndata: {\"source\":\"output\",\"ts\":\"2026-05-31T10:00:00Z\",\"text\":\"pty\"}";

        let item = parse_cloud_sse_item(block, &LogStreamOptions::default()).unwrap();

        let CloudSseItem::Entry(entry) = item else {
            panic!("expected log entry");
        };
        assert_eq!(entry.source, LogSource::Output);
        assert_eq!(entry.data, Bytes::from_static(b"pty"));
    }
}

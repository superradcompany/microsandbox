//! Cloud Services: the [`ServiceBackend`] impl for [`CloudBackend`] and the mapping of Service
//! change responses to typed errors.
//!
//! Every change call sends at most one request and never retries it. A change whose outcome the
//! SDK cannot know (a server error, a response lost after the request was sent, or an unexpected
//! success status) is reported as [`ServiceError::OutcomeUnknown`]. A connection that fails
//! before the request is sent returns the transport error.

use std::fmt::Display;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use futures::future::BoxFuture;
use microsandbox_types::{
    CloudCreateServiceRequest, CloudErrorBody, CloudPaginated, CloudService, CloudServiceTarget,
    CloudUpdateServiceRequest,
};
use reqwest::header::{HeaderMap, RETRY_AFTER};
use reqwest::{RequestBuilder, Response, StatusCode};
use serde::Serialize;

use super::CloudBackend;
use super::http::{
    cloud_error_code, cloud_error_message, cloud_http_error, cloud_io_error, decode_json,
    urlencoding,
};
use crate::backend::{Backend, ServiceBackend};
use crate::error::{SERVICE_CHANGES_PAUSED_CODE, ServiceError};
use crate::service::{Service, ServiceListBuilder, ServicePage};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const GET_OP: &str = "GET /v1/services/:slug";
const LIST_OP: &str = "GET /v1/services";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Serialize)]
struct ServiceListQuery<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    sandbox: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<&'a str>,
    limit: u32,
}

/// A Service change call: its route label and the success status its contract allows.
#[derive(Clone, Copy)]
enum ServiceChange {
    Create,
    Update,
    Enable,
    Disable,
    Remove,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ServiceChange {
    fn op(self) -> &'static str {
        match self {
            ServiceChange::Create => "POST /v1/services",
            ServiceChange::Update => "PATCH /v1/services/:slug",
            ServiceChange::Enable => "POST /v1/services/:slug/enable",
            ServiceChange::Disable => "POST /v1/services/:slug/disable",
            ServiceChange::Remove => "DELETE /v1/services/:slug",
        }
    }

    /// Create answers `201`, or `200` for a repeat of the same create; update and actions answer
    /// `200`; remove answers `204` without a body.
    fn succeeded(self, status: StatusCode) -> bool {
        match self {
            ServiceChange::Create => status == StatusCode::CREATED || status == StatusCode::OK,
            ServiceChange::Update | ServiceChange::Enable | ServiceChange::Disable => {
                status == StatusCode::OK
            }
            ServiceChange::Remove => status == StatusCode::NO_CONTENT,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl ServiceBackend for CloudBackend {
    fn create<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        request: CloudCreateServiceRequest,
    ) -> BoxFuture<'a, MicrosandboxResult<Service>> {
        Box::pin(async move {
            validate_target(&request.target)?;

            let url = format!("{}/v1/services", self.url);
            let sent = self.service_http.post(&url).json(&request);
            let info = change_service(sent, ServiceChange::Create, &request.slug).await?;
            Ok(Service::from_cloud(backend, info))
        })
    }

    fn get<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        slug: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Service>> {
        Box::pin(async move {
            let url = service_url(&self.url, slug, None)?;
            let response = self
                .http
                .get(&url)
                .send()
                .await
                .map_err(|e| cloud_io_error(GET_OP, e))?;
            let info: CloudService = decode_json(response, GET_OP)
                .await
                .map_err(|error| name_service(error, slug))?;
            Ok(Service::from_cloud(backend, info))
        })
    }

    fn list<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        query: ServiceListBuilder,
    ) -> BoxFuture<'a, MicrosandboxResult<ServicePage>> {
        Box::pin(async move {
            let url = format!("{}/v1/services", self.url);
            let params = ServiceListQuery {
                sandbox: query.sandbox.as_deref(),
                cursor: query.cursor.as_deref(),
                limit: query.limit,
            };
            let response = self
                .http
                .get(&url)
                .query(&params)
                .send()
                .await
                .map_err(|e| cloud_io_error(LIST_OP, e))?;
            let page: CloudPaginated<CloudService> = decode_json(response, LIST_OP).await?;

            let services = page
                .data
                .into_iter()
                .map(|info| Service::from_cloud(backend.clone(), info))
                .collect();
            Ok(ServicePage {
                services,
                next_cursor: page.next_cursor,
            })
        })
    }

    fn update<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        slug: &'a str,
        request: CloudUpdateServiceRequest,
    ) -> BoxFuture<'a, MicrosandboxResult<Service>> {
        Box::pin(async move {
            validate_update(slug, &request)?;

            let url = service_url(&self.url, slug, None)?;
            let sent = self.service_http.patch(&url).json(&request);
            let info = change_service(sent, ServiceChange::Update, slug).await?;
            Ok(Service::from_cloud(backend, info))
        })
    }

    fn enable<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        slug: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Service>> {
        change_status(self, backend, slug, "enable", ServiceChange::Enable)
    }

    fn disable<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        slug: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Service>> {
        change_status(self, backend, slug, "disable", ServiceChange::Disable)
    }

    fn remove<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        slug: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            let url = service_url(&self.url, slug, None)?;
            send_change(self.service_http.delete(&url), ServiceChange::Remove, slug).await?;
            Ok(())
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Request URLs
//--------------------------------------------------------------------------------------------------

/// The URL of one Service, with the slug percent-encoded as one path segment.
///
/// URL parsing resolves a `.` or `..` segment, and an empty slug leaves an empty segment, so each
/// would reach another route; those slugs fail before any request.
fn service_url(base: &str, slug: &str, action: Option<&str>) -> MicrosandboxResult<String> {
    if matches!(slug, "" | "." | "..") {
        return Err(MicrosandboxError::InvalidConfig(format!(
            "service slug {slug:?} is not valid"
        )));
    }

    let mut url = format!("{base}/v1/services/{}", urlencoding(slug));
    if let Some(action) = action {
        url.push('/');
        url.push_str(action);
    }
    Ok(url)
}

//--------------------------------------------------------------------------------------------------
// Functions: Validation
//--------------------------------------------------------------------------------------------------

fn validate_target(target: &CloudServiceTarget) -> MicrosandboxResult<()> {
    if target.port == 0 {
        return Err(MicrosandboxError::InvalidConfig(format!(
            "service target port must be between 1 and 65535: got 0 for sandbox {}",
            target.sandbox
        )));
    }
    Ok(())
}

fn validate_update(slug: &str, request: &CloudUpdateServiceRequest) -> MicrosandboxResult<()> {
    let Some(target) = &request.target else {
        return Err(MicrosandboxError::InvalidConfig(format!(
            "service {slug} update requires a target"
        )));
    };
    validate_target(target)
}

//--------------------------------------------------------------------------------------------------
// Functions: Change requests
//--------------------------------------------------------------------------------------------------

/// Client settings for Service changes: requests are neither resent nor redirected, so each
/// change call reaches only the requested endpoint at most once.
pub(super) fn service_change_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .retry(reqwest::retry::never())
        .redirect(reqwest::redirect::Policy::none())
}

/// Send one body-less enable or disable action and return the Service once committed.
fn change_status<'a>(
    cloud: &'a CloudBackend,
    backend: Arc<dyn Backend>,
    slug: &'a str,
    action: &'static str,
    change: ServiceChange,
) -> BoxFuture<'a, MicrosandboxResult<Service>> {
    Box::pin(async move {
        let url = service_url(&cloud.url, slug, Some(action))?;
        let info = change_service(cloud.service_http.post(&url), change, slug).await?;
        Ok(Service::from_cloud(backend, info))
    })
}

async fn change_service(
    request: RequestBuilder,
    change: ServiceChange,
    slug: &str,
) -> MicrosandboxResult<CloudService> {
    let response = send_change(request, change, slug).await?;
    response
        .json::<CloudService>()
        .await
        .map_err(|e| outcome_unknown(change, slug, e))
}

async fn send_change(
    request: RequestBuilder,
    change: ServiceChange,
    slug: &str,
) -> MicrosandboxResult<Response> {
    let response = request.send().await.map_err(|e| {
        // A failed connection sent no part of the request, so nothing changed.
        if e.is_connect() {
            cloud_io_error(change.op(), e)
        } else {
            outcome_unknown(change, slug, e)
        }
    })?;
    let status = response.status();
    if change.succeeded(status) {
        return Ok(response);
    }

    // `Retry-After` is read before `text()` consumes the response.
    let retry_after = parse_retry_after(response.headers());
    let raw_body = response.text().await.unwrap_or_default();
    let body: Option<CloudErrorBody> = serde_json::from_str(&raw_body).ok();
    Err(service_change_error(
        status.as_u16(),
        body.as_ref(),
        &raw_body,
        change,
        slug,
        retry_after,
    ))
}

/// Map a change response whose status is not the contract's success.
///
/// A `4xx`, or the `service_changes_paused` code, means nothing changed unless the code is
/// `outcome_unknown`. Any other status, including a `5xx` without an error body, means the
/// change may have been applied.
fn service_change_error(
    status: u16,
    body: Option<&CloudErrorBody>,
    raw_body: &str,
    change: ServiceChange,
    slug: &str,
    retry_after: Option<Duration>,
) -> MicrosandboxError {
    let code = cloud_error_code(body);
    let refused = (400..500).contains(&status) || code == Some(SERVICE_CHANGES_PAUSED_CODE);
    if !refused {
        return service_error(slug, ServiceError::OutcomeUnknown);
    }

    if let Some(code) = code {
        if let Some(error) = service_error_for_code(code, retry_after) {
            return service_error(slug, error);
        }
        if !is_shared_error_code(code) {
            let message = cloud_error_message(body)
                .or_else(|| (!raw_body.trim().is_empty()).then_some(raw_body.trim()))
                .unwrap_or("no response body")
                .to_owned();
            return service_error(
                slug,
                ServiceError::Other {
                    code: code.to_owned(),
                    status,
                    message,
                },
            );
        }
    }

    name_service(cloud_http_error(status, body, raw_body, change.op()), slug)
}

/// Name the requested slug in Service-level errors, in place of the route and server message.
fn name_service(error: MicrosandboxError, slug: &str) -> MicrosandboxError {
    if matches!(error, MicrosandboxError::ServiceNotFound(_)) {
        return MicrosandboxError::ServiceNotFound(slug.to_owned());
    }
    if matches!(error, MicrosandboxError::ServiceAlreadyExists(_)) {
        return MicrosandboxError::ServiceAlreadyExists(slug.to_owned());
    }
    error
}

fn service_error_for_code(code: &str, retry_after: Option<Duration>) -> Option<ServiceError> {
    let error = match code {
        "service_quota_exceeded" => ServiceError::QuotaExceeded,
        "sandbox_service_limit_exceeded" => ServiceError::SandboxLimitExceeded,
        "service_conflict" => ServiceError::Conflict,
        "service_detached" => ServiceError::Detached,
        "target_unreachable" => ServiceError::TargetUnreachable { retry_after },
        SERVICE_CHANGES_PAUSED_CODE => ServiceError::ChangesPaused { retry_after },
        "sandbox_not_running" => ServiceError::TargetNotRunning,
        "outcome_unknown" => ServiceError::OutcomeUnknown,
        _ => return None,
    };
    Some(error)
}

fn is_shared_error_code(code: &str) -> bool {
    matches!(
        code,
        "sandbox_not_found"
            | "service_not_found"
            | "service_already_exists"
            | "invalid_request"
            | "invalid_sandbox_config"
    )
}

fn service_error(slug: &str, error: ServiceError) -> MicrosandboxError {
    MicrosandboxError::Service {
        slug: slug.to_owned(),
        error,
    }
}

fn outcome_unknown(change: ServiceChange, slug: &str, cause: impl Display) -> MicrosandboxError {
    tracing::debug!(operation = change.op(), slug, error = %cause, "service change outcome unknown");
    service_error(slug, ServiceError::OutcomeUnknown)
}

/// Parse a delta-seconds or HTTP-date `Retry-After` header. A past date gives zero; a malformed
/// value is ignored.
fn parse_retry_after(headers: &HeaderMap) -> Option<Duration> {
    let value = headers.get(RETRY_AFTER)?.to_str().ok()?;
    let value = value.trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }

    let deadline = httpdate::parse_http_date(value).ok()?;
    Some(
        deadline
            .duration_since(SystemTime::now())
            .unwrap_or_default(),
    )
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;

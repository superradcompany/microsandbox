//! HTTP clients used by the cloud backend.

use std::time::Duration;

use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue, USER_AGENT};

use super::service;
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The clients a cloud backend sends its requests with.
pub(super) struct CloudHttpClients {
    /// Ordinary requests, bounded by the request timeout as a total.
    pub(super) http: reqwest::Client,
    /// Log follows and volume file transfers.
    pub(super) stream: reqwest::Client,
    /// Service changes.
    pub(super) service: reqwest::Client,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Build the cloud clients, or use a caller-supplied client for all of them.
pub(super) fn build_clients(
    custom: Option<reqwest::Client>,
    api_key: &str,
    user_agent: Option<String>,
    request_timeout: Duration,
) -> MicrosandboxResult<CloudHttpClients> {
    if let Some(client) = custom {
        return Ok(CloudHttpClients {
            http: client.clone(),
            stream: client.clone(),
            service: client,
        });
    }

    let mut headers = HeaderMap::new();
    let bearer = format!("Bearer {api_key}");
    let mut auth_value = HeaderValue::from_str(&bearer).map_err(|e| {
        MicrosandboxError::InvalidConfig(format!("invalid API key header value: {e}"))
    })?;
    auth_value.set_sensitive(true);
    headers.insert(AUTHORIZATION, auth_value);
    let ua = user_agent.unwrap_or_else(super::default_user_agent);
    headers.insert(
        USER_AGENT,
        HeaderValue::from_str(&ua).map_err(|e| {
            MicrosandboxError::InvalidConfig(format!("invalid user-agent value: {e}"))
        })?,
    );

    let build = |builder: reqwest::ClientBuilder| {
        builder
            .default_headers(headers.clone())
            .build()
            .map_err(|e| {
                MicrosandboxError::InvalidConfig(format!("failed to build HTTP client: {e}"))
            })
    };
    Ok(CloudHttpClients {
        http: build(reqwest::Client::builder().timeout(request_timeout))?,
        stream: build(reqwest::Client::builder().connect_timeout(request_timeout))?,
        service: build(service::service_change_client_builder().timeout(request_timeout))?,
    })
}

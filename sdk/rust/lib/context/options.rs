//! Shared construction boundary for native language bindings.

#[cfg(feature = "cloud")]
use std::time::Duration;
use std::{path::PathBuf, sync::Arc};

use serde::Deserialize;

use super::Context;
use crate::{ComputeType, MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Explicit options captured once by a language binding. Never an ambient selector.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ContextOptions {
    kind: String,
    home: Option<PathBuf>,
    config_path: Option<PathBuf>,
    url: Option<String>,
    api_key: Option<String>,
    profile: Option<String>,
    request_timeout_ms: Option<u64>,
    user_agent: Option<String>,
    compute_type: Option<ComputeType>,
}

/// Only explicit overrides cross the binding boundary; captured credentials stay in Rust.
#[derive(Deserialize)]
#[cfg_attr(not(feature = "cloud"), allow(dead_code))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RemoteOverrides {
    url: Option<String>,
    api_key: Option<String>,
    request_timeout_ms: Option<u64>,
    user_agent: Option<String>,
    compute_type: Option<ComputeType>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Construct an explicitly selected context for a native binding.
/// Credentials are never included in a diagnostic or returned serialization.
#[doc(hidden)]
pub fn from_options_json(json: &str) -> MicrosandboxResult<Arc<dyn Context>> {
    let options: ContextOptions = serde_json::from_str(json)
        .map_err(|error| MicrosandboxError::InvalidConfig(error.to_string()))?;
    match options.kind.as_str() {
        "local" => {
            if options.url.is_some()
                || options.api_key.is_some()
                || options.profile.is_some()
                || options.request_timeout_ms.is_some()
                || options.user_agent.is_some()
                || options.compute_type.is_some()
            {
                return Err(invalid("remote options cannot configure a local context"));
            }
            #[cfg(feature = "local")]
            {
                let mut builder = super::LocalContext::builder();
                if let Some(home) = options.home {
                    builder = builder.home(home);
                }
                if let Some(path) = options.config_path {
                    builder = builder.config_path(path);
                }
                // Capture paths/configuration now; opening the catalog remains lazy.
                Ok(builder.build()?.clone_shared())
            }
            #[cfg(not(feature = "local"))]
            Err(invalid("this SDK distribution has no local provider"))
        }
        "remote" => {
            if options.home.is_some() || options.config_path.is_some() {
                return Err(invalid("local paths cannot configure a remote context"));
            }
            #[cfg(feature = "cloud")]
            {
                if let Some(profile) = options.profile {
                    if options.url.is_some()
                        || options.api_key.is_some()
                        || options.request_timeout_ms.is_some()
                        || options.user_agent.is_some()
                        || options.compute_type.is_some()
                    {
                        return Err(invalid(
                            "a profile cannot be combined with explicit remote options",
                        ));
                    }
                    return Ok(super::RemoteContext::from_profile(&profile)?.clone_shared());
                }
                let mut builder = super::RemoteContext::builder();
                if let Some(key) = options.api_key {
                    builder = builder.api_key(key);
                }
                if let Some(url) = options.url {
                    builder = builder.url(url);
                }
                if let Some(timeout) = options.request_timeout_ms {
                    builder = builder.request_timeout(Duration::from_millis(timeout));
                }
                if let Some(agent) = options.user_agent {
                    builder = builder.user_agent(agent);
                }
                if let Some(compute_type) = options.compute_type {
                    builder = builder.compute_type(compute_type);
                }
                Ok(builder.build()?.clone_shared())
            }
            #[cfg(not(feature = "cloud"))]
            Err(invalid("this SDK distribution has no remote provider"))
        }
        _ => Err(invalid("context kind must be local or remote")),
    }
}

fn invalid(message: &str) -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(message.into())
}

/// Derive from retained native state without exporting credentials or reselecting a provider.
#[doc(hidden)]
pub fn derive_remote_from_options_json(
    context: &dyn Context,
    json: &str,
) -> MicrosandboxResult<Arc<dyn Context>> {
    let overrides: RemoteOverrides = serde_json::from_str(json)
        .map_err(|error| MicrosandboxError::InvalidConfig(error.to_string()))?;
    #[cfg(feature = "cloud")]
    {
        let remote = context
            .as_cloud()
            .ok_or_else(|| invalid("derivation requires a remote context"))?;
        let mut builder = remote.to_builder();
        if let Some(url) = overrides.url {
            builder = builder.url(url);
        }
        if let Some(key) = overrides.api_key {
            builder = builder.api_key(key);
        }
        if let Some(timeout) = overrides.request_timeout_ms {
            builder = builder.request_timeout(Duration::from_millis(timeout));
        }
        if let Some(agent) = overrides.user_agent {
            builder = builder.user_agent(agent);
        }
        if let Some(compute_type) = overrides.compute_type {
            builder = builder.compute_type(compute_type);
        }
        Ok(builder.build()?.clone_shared())
    }
    #[cfg(not(feature = "cloud"))]
    {
        let _ = (context, overrides);
        Err(invalid("this SDK distribution has no remote provider"))
    }
}

/// Capture the explicit remote selector for a native binding, never ambient backend routing.
#[doc(hidden)]
pub fn remote_from_env() -> MicrosandboxResult<Arc<dyn Context>> {
    #[cfg(feature = "cloud")]
    {
        Ok(super::RemoteContext::from_env()?.clone_shared())
    }
    #[cfg(not(feature = "cloud"))]
    {
        Err(invalid("this SDK distribution has no remote provider"))
    }
}

//! Public Service request and response wire contracts.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types: Services
//--------------------------------------------------------------------------------------------------

/// A public Service and its current target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CloudService {
    /// Globally unique Service slug.
    pub slug: String,
    /// Absolute HTTPS URL for the Service.
    pub url: String,
    /// Whether the Service routes requests, is disabled, or has no target.
    pub status: CloudServiceStatus,
    /// Current target, or no target when the Service is detached.
    pub target: Option<CloudServiceTarget>,
    /// Creation timestamp.
    #[cfg_attr(feature = "ts", ts(type = "string"))]
    pub created_at: DateTime<Utc>,
    /// Timestamp of the most recent state change.
    #[cfg_attr(feature = "ts", ts(type = "string"))]
    pub updated_at: DateTime<Utc>,
}

/// Whether a Service routes requests, is disabled, or has no target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CloudServiceStatus {
    /// The Service routes requests to its target.
    Enabled,
    /// The Service retains its target without routing requests.
    Disabled,
    /// The Service has no target.
    Detached,
    /// The backend returned a status this SDK does not recognize.
    #[serde(other)]
    Unknown,
}

/// The sandbox and port that receive requests for a Service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CloudServiceTarget {
    /// Sandbox name.
    pub sandbox: String,
    /// Sandbox port that receives requests.
    pub port: u16,
}

/// Service create request body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CloudCreateServiceRequest {
    /// Globally unique Service slug.
    pub slug: String,
    /// Initial Service target.
    pub target: CloudServiceTarget,
}

/// Service update request body.
///
/// A modification request: unknown fields are refused, so a server never applies part of a change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(deny_unknown_fields)]
pub struct CloudUpdateServiceRequest {
    /// New target when moving or reattaching the Service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<CloudServiceTarget>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CloudServiceStatus {
    /// Return the lowercase status used by Service API and SDK surfaces.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
            Self::Detached => "detached",
            Self::Unknown => "unknown",
        }
    }
}

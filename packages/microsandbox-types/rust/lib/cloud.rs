//! Wire types for the cloud backend's HTTP calls.
//!
//! The create request is the shared [`SandboxSpec`] (flattened) — control-plane
//! consumers that need extra fields wrap this type rather than re-declaring the
//! spec, so it can never drift from `domain.rs`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::domain::SandboxSpec;

//--------------------------------------------------------------------------------------------------
// Types: Request
//--------------------------------------------------------------------------------------------------

/// Wire shape of a cloud sandbox create request body: the shared [`SandboxSpec`],
/// flattened onto the request. Consumers that need control-plane-only fields
/// compose this rather than restating spec fields.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CloudCreateSandboxRequest {
    /// The shared sandbox specification, flattened onto the request body.
    #[serde(flatten)]
    pub spec: SandboxSpec,
}

//--------------------------------------------------------------------------------------------------
// Types: Response
//--------------------------------------------------------------------------------------------------

/// Wire shape of the cloud sandbox response returned by sandbox endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CloudCreateSandboxResponse {
    /// Server-side UUID.
    pub id: String,
    /// Owning org's UUID.
    pub org_id: String,
    /// User-facing, per-org sandbox name.
    pub name: String,
    /// Canonical, resolved SSH username token.
    pub slug: String,
    /// Current lifecycle status.
    pub status: CloudSandboxStatus,
    /// Create request stored by the cloud control plane.
    pub config: CloudCreateSandboxRequest,
    /// Whether the sandbox should be removed when its allocation terminates.
    pub ephemeral: bool,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last start timestamp, when known.
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(optional = nullable))]
    pub started_at: Option<DateTime<Utc>>,
    /// Last stop timestamp, when known.
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(optional = nullable))]
    pub stopped_at: Option<DateTime<Utc>>,
    /// Last failure reason, when any.
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(optional = nullable))]
    pub last_error: Option<String>,
}

/// Sandbox lifecycle status returned by the cloud control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum CloudSandboxStatus {
    /// Created in the database but not yet started.
    Created,
    /// Start request has been submitted.
    Starting,
    /// Sandbox is running.
    Running,
    /// Stop request has been submitted.
    Stopping,
    /// Sandbox is stopped.
    Stopped,
    /// Sandbox failed.
    Failed,
}

/// Wire shape of paginated list responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CloudPaginated<T> {
    /// Page of response items.
    pub data: Vec<T>,
    /// Cursor for the next page, when one exists.
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(optional = nullable))]
    pub next_cursor: Option<String>,
}

/// Wire shape of the message response returned by mutation endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CloudMessageResponse {
    /// Human-readable response message.
    pub message: String,
}

/// Wire shape of the typed error body returned by cloud APIs on 4xx/5xx responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CloudErrorBody {
    /// Flat machine-readable error code, when returned in this shape.
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(optional = nullable))]
    pub code: Option<String>,
    /// Flat human-readable error message, when returned in this shape.
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(optional = nullable))]
    pub message: Option<String>,
    /// Nested error object returned by the API error responder.
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(optional = nullable))]
    pub error: Option<CloudErrorDetails>,
}

/// Nested cloud API error details.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CloudErrorDetails {
    /// Machine-readable error code.
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(optional = nullable))]
    pub code: Option<String>,
    /// Human-readable error message.
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(optional = nullable))]
    pub message: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{OciRootfsSource, RootfsSource};

    fn spec(name: &str) -> SandboxSpec {
        SandboxSpec {
            name: name.into(),
            image: RootfsSource::Oci(OciRootfsSource {
                reference: "python:3.12".into(),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn create_request_flattens_spec() {
        let req = CloudCreateSandboxRequest {
            spec: spec("agent-1"),
        };
        let json = serde_json::to_value(&req).unwrap();
        // Spec fields are flattened onto the top level (SDK parity).
        assert_eq!(json["name"], "agent-1");
        assert!(json.get("image").is_some());

        let back: CloudCreateSandboxRequest = serde_json::from_value(json).unwrap();
        assert_eq!(back.spec.name, "agent-1");
    }

    #[test]
    fn create_request_minimal_defaults() {
        // Only the spec's name + image are set; everything else defaults.
        let req = CloudCreateSandboxRequest {
            spec: spec("agent-1"),
        };
        let json = serde_json::to_value(&req).unwrap();
        let back: CloudCreateSandboxRequest = serde_json::from_value(json).unwrap();
        assert_eq!(back.spec.name, "agent-1");
    }

    #[test]
    fn sandbox_status_round_trips_snake_case() {
        for status in [
            CloudSandboxStatus::Created,
            CloudSandboxStatus::Starting,
            CloudSandboxStatus::Running,
            CloudSandboxStatus::Stopping,
            CloudSandboxStatus::Stopped,
            CloudSandboxStatus::Failed,
        ] {
            let s = serde_json::to_string(&status).unwrap();
            assert_eq!(
                serde_json::from_str::<CloudSandboxStatus>(&s).unwrap(),
                status
            );
        }
        assert_eq!(
            serde_json::to_string(&CloudSandboxStatus::Starting).unwrap(),
            "\"starting\""
        );
    }

    #[test]
    fn sandbox_response_round_trips() {
        let sb = CloudCreateSandboxResponse {
            id: "00000000-0000-0000-0000-000000000002".into(),
            org_id: "00000000-0000-0000-0000-000000000001".into(),
            name: "agent-1".into(),
            slug: "brave-otter".into(),
            status: CloudSandboxStatus::Created,
            config: CloudCreateSandboxRequest {
                spec: spec("agent-1"),
            },
            ephemeral: true,
            created_at: "2026-05-17T12:00:00Z".parse().unwrap(),
            started_at: None,
            stopped_at: None,
            last_error: None,
        };
        let json = serde_json::to_value(&sb).unwrap();
        assert_eq!(json["slug"], "brave-otter");
        assert_eq!(json["name"], "agent-1");

        let back: CloudCreateSandboxResponse = serde_json::from_value(json).unwrap();
        assert_eq!(back.slug, "brave-otter");
        assert_eq!(back.status, CloudSandboxStatus::Created);
        assert_eq!(back.config.spec.name, "agent-1");
        assert!(back.started_at.is_none());
    }
}

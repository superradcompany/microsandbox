//! Wire types for the cloud backend's HTTP calls to msb-cloud.
//!
//! These mirror msb-cloud's `crates/msb-models/src/sandbox.rs` shape — name +
//! field set + JSON serialisation must match byte-for-byte. The shared
//! `task-config.golden.json` fixture on the msb-cloud side is the contract;
//! drift breaks the contract test there.
//!
//! Duplicated here (rather than depending on msb-cloud crates) to keep
//! microsandbox a single-repo build. If the duplication becomes painful, the
//! candidate is extracting to a shared `microsandbox-protocol` crate that both
//! projects pull in.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types: Request
//--------------------------------------------------------------------------------------------------

/// Wire shape of `POST /v1/sandboxes` request body.
///
/// **Must stay in sync** with msb-cloud's `CreateSandboxRequest` in
/// `crates/msb-models/src/sandbox.rs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CloudCreateSandboxRequest {
    /// User-facing sandbox name.
    pub name: String,
    /// OCI image reference to run.
    pub image: String,
    /// Virtual CPU count.
    pub vcpus: u8,
    /// Guest memory in MiB.
    pub memory_mib: u32,
    /// Environment variables injected into the sandbox.
    pub env: HashMap<String, String>,
    /// Whether the sandbox should be removed when its allocation terminates.
    pub ephemeral: bool,

    // Optional config fields.
    /// Working directory inside the guest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workdir: Option<String>,
    /// Default shell inside the guest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
    /// OCI entrypoint override.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<Vec<String>>,
    /// Guest hostname override.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Guest user identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Runtime log verbosity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_level: Option<String>,
    /// Named scripts mounted into the guest.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub scripts: HashMap<String, String>,
    /// Hard sandbox lifetime cap in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_duration_secs: Option<u64>,
    /// Idle timeout in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_timeout_secs: Option<u64>,
}

impl Default for CloudCreateSandboxRequest {
    fn default() -> Self {
        Self {
            name: String::new(),
            image: String::new(),
            vcpus: 1,
            memory_mib: 512,
            env: HashMap::new(),
            ephemeral: true,
            workdir: None,
            shell: None,
            entrypoint: None,
            hostname: None,
            user: None,
            log_level: None,
            scripts: HashMap::new(),
            max_duration_secs: None,
            idle_timeout_secs: None,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Types: Response
//--------------------------------------------------------------------------------------------------

/// Wire shape of the `Sandbox` response from msb-cloud — what every sandbox
/// endpoint returns. Mirrors msb-cloud's `Sandbox` model with `skip_serializing`
/// fields excluded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudSandbox {
    /// Server-side UUID (as a string — avoids pulling in the `uuid` crate here).
    pub id: String,
    /// Owning org's UUID (as a string).
    pub org_id: String,
    /// User-facing sandbox name.
    pub name: String,
    /// Current lifecycle status.
    pub status: CloudSandboxStatus,
    /// Create request stored by msb-cloud.
    pub config: CloudCreateSandboxRequest,
    /// Whether the sandbox should be removed when its allocation terminates.
    pub ephemeral: bool,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last start timestamp, when known.
    #[serde(default)]
    pub started_at: Option<DateTime<Utc>>,
    /// Last stop timestamp, when known.
    #[serde(default)]
    pub stopped_at: Option<DateTime<Utc>>,
    /// Last failure reason, when any.
    #[serde(default)]
    pub last_error: Option<String>,
}

/// Sandbox lifecycle status — must match msb-cloud's `SandboxStatus` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

/// Wire shape of paginated list responses: `{ data: [...], next_cursor: "..." }`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudPaginated<T> {
    /// Page of response items.
    pub data: Vec<T>,
    /// Cursor for the next page, when one exists.
    #[serde(default)]
    pub next_cursor: Option<String>,
}

/// Wire shape of the `MessageResponse` returned by `DELETE` endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudMessageResponse {
    /// Human-readable response message.
    pub message: String,
}

/// Wire shape of the typed error body msb-cloud returns on 4xx/5xx.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudErrorBody {
    /// Flat machine-readable error code, when returned in this shape.
    #[serde(default)]
    pub code: Option<String>,
    /// Flat human-readable error message, when returned in this shape.
    #[serde(default)]
    pub message: Option<String>,
    /// Nested error object returned by msb-cloud's `ApiError` responder.
    #[serde(default)]
    pub error: Option<CloudErrorDetails>,
}

/// Nested msb-cloud API error details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudErrorDetails {
    /// Machine-readable error code.
    #[serde(default)]
    pub code: Option<String>,
    /// Human-readable error message.
    #[serde(default)]
    pub message: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_request_serialises_minimal() {
        let req = CloudCreateSandboxRequest {
            name: "agent-1".into(),
            image: "python:3.12".into(),
            ..Default::default()
        };
        let json = serde_json::to_value(&req).unwrap();
        // Required fields present.
        assert_eq!(json["name"], "agent-1");
        assert_eq!(json["image"], "python:3.12");
        assert_eq!(json["vcpus"], 1);
        assert_eq!(json["memory_mib"], 512);
        assert_eq!(json["ephemeral"], true);
        // Optional fields elided when unset.
        assert!(json.get("workdir").is_none());
        assert!(json.get("entrypoint").is_none());
        assert!(json.get("max_duration_secs").is_none());
    }

    #[test]
    fn create_request_serialises_full_d13() {
        let mut req = CloudCreateSandboxRequest {
            name: "agent-1".into(),
            image: "python:3.12".into(),
            workdir: Some("/app".into()),
            shell: Some("/bin/bash".into()),
            entrypoint: Some(vec!["python".into(), "-u".into()]),
            hostname: Some("worker".into()),
            user: Some("appuser".into()),
            log_level: Some("info".into()),
            max_duration_secs: Some(3600),
            idle_timeout_secs: Some(600),
            ..Default::default()
        };
        req.scripts.insert("setup".into(), "echo hi".into());
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["workdir"], "/app");
        assert_eq!(json["shell"], "/bin/bash");
        assert_eq!(json["entrypoint"], serde_json::json!(["python", "-u"]));
        assert_eq!(json["max_duration_secs"], 3600);
        assert_eq!(json["scripts"]["setup"], "echo hi");
    }

    #[test]
    fn sandbox_status_round_trips() {
        for status in [
            CloudSandboxStatus::Created,
            CloudSandboxStatus::Starting,
            CloudSandboxStatus::Running,
            CloudSandboxStatus::Stopping,
            CloudSandboxStatus::Stopped,
            CloudSandboxStatus::Failed,
        ] {
            let s = serde_json::to_string(&status).unwrap();
            let parsed: CloudSandboxStatus = serde_json::from_str(&s).unwrap();
            assert_eq!(status, parsed);
        }
    }

    #[test]
    fn sandbox_status_serialises_snake_case() {
        let s = serde_json::to_string(&CloudSandboxStatus::Starting).unwrap();
        assert_eq!(s, "\"starting\"");
    }

    #[test]
    fn sandbox_response_parses_typical() {
        let json = r#"{
            "id": "00000000-0000-0000-0000-000000000002",
            "org_id": "00000000-0000-0000-0000-000000000001",
            "name": "agent-1",
            "status": "created",
            "config": { "name": "agent-1", "image": "python:3.12" },
            "ephemeral": true,
            "created_at": "2026-05-17T12:00:00Z"
        }"#;
        let sb: CloudSandbox = serde_json::from_str(json).unwrap();
        assert_eq!(sb.name, "agent-1");
        assert_eq!(sb.status, CloudSandboxStatus::Created);
        assert_eq!(sb.config.image, "python:3.12");
        assert!(sb.started_at.is_none());
    }
}

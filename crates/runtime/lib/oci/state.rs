//! OCI state model persisted by the runtime layer.

use std::collections::BTreeMap;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// OCI runtime lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OciStatus {
    /// The runtime is creating the container environment.
    Creating,

    /// The container environment exists, but the configured process has not run.
    Created,

    /// The configured process has started and has not exited.
    Running,

    /// The container process has exited.
    Stopped,

    /// The VM or container process group is suspended.
    ///
    /// `paused` is a de-facto runtime status used by Docker/runc-style CLIs,
    /// although the core OCI spec only standardizes creating/created/running/stopped.
    Paused,
}

/// OCI state returned by the `state` command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciState {
    /// OCI Runtime Specification version represented by this state.
    pub oci_version: String,

    /// Host-unique container ID supplied by Docker/containerd.
    pub id: String,

    /// Current OCI lifecycle status.
    pub status: OciStatus,

    /// Host PID of the Microsandbox VMM/sandbox process.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<i32>,

    /// Absolute path to the OCI bundle.
    pub bundle: PathBuf,

    /// OCI annotations copied from `config.json`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,

    /// Microsandbox-specific state extensions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub microsandbox: Option<MicrosandboxState>,
}

/// Microsandbox-specific extension fields persisted beside OCI state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MicrosandboxState {
    /// Durable Microsandbox sandbox name derived from the OCI container ID.
    pub sandbox_name: String,

    /// Path to this container's private OCI state directory.
    pub state_dir: PathBuf,

    /// Rootfs path resolved from the OCI bundle.
    pub rootfs: PathBuf,

    /// Guest PID reported for the OCI init process, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest_pid: Option<u32>,

    /// Agent protocol exec session ID for the OCI init process, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init_exec_session_id: Option<u32>,

    /// Exit code reported for the OCI init process, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,

    /// Time at which create started.
    pub created_at: DateTime<Utc>,

    /// Time at which the init process started.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,

    /// Time at which the init process exited or the VM stopped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stopped_at: Option<DateTime<Utc>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl OciStatus {
    /// Return the status string used by OCI JSON and diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Creating => "creating",
            Self::Created => "created",
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::Paused => "paused",
        }
    }

    /// Whether OCI permits signals to be sent in this state.
    pub fn can_receive_signal(self) -> bool {
        matches!(self, Self::Created | Self::Running | Self::Paused)
    }

    /// Whether the state is terminal from Docker/containerd's perspective.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Stopped)
    }
}

impl OciState {
    /// Construct new persisted state for a just-created OCI environment.
    pub fn created(
        id: impl Into<String>,
        oci_version: impl Into<String>,
        bundle: impl Into<PathBuf>,
        annotations: BTreeMap<String, String>,
        microsandbox: MicrosandboxState,
    ) -> Self {
        Self {
            oci_version: oci_version.into(),
            id: id.into(),
            status: OciStatus::Created,
            pid: None,
            bundle: bundle.into(),
            annotations,
            microsandbox: Some(microsandbox),
        }
    }

    /// Mark the container init process as running.
    pub fn mark_running(
        &mut self,
        host_pid: i32,
        guest_pid: Option<u32>,
        init_exec_session_id: Option<u32>,
        now: DateTime<Utc>,
    ) {
        self.status = OciStatus::Running;
        self.pid = Some(host_pid);
        if let Some(msb) = self.microsandbox.as_mut() {
            msb.guest_pid = guest_pid;
            msb.init_exec_session_id = init_exec_session_id;
            msb.started_at = Some(now);
        }
    }

    /// Mark the container as stopped.
    pub fn mark_stopped(&mut self, exit_code: Option<i32>, now: DateTime<Utc>) {
        self.status = OciStatus::Stopped;
        if let Some(msb) = self.microsandbox.as_mut() {
            msb.exit_code = exit_code;
            msb.stopped_at = Some(now);
        }
    }
}

impl MicrosandboxState {
    /// Construct Microsandbox extension state for a newly created OCI container.
    pub fn new(
        sandbox_name: impl Into<String>,
        state_dir: impl Into<PathBuf>,
        rootfs: impl Into<PathBuf>,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            sandbox_name: sandbox_name.into(),
            state_dir: state_dir.into(),
            rootfs: rootfs.into(),
            guest_pid: None,
            init_exec_session_id: None,
            exit_code: None,
            created_at: now,
            started_at: None,
            stopped_at: None,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use chrono::TimeZone;

    use super::*;

    #[test]
    fn serializes_oci_state_with_camel_case_fields() {
        let now = Utc
            .with_ymd_and_hms(2026, 6, 25, 12, 0, 0)
            .single()
            .expect("valid test time");
        let state = OciState::created(
            "abc",
            "1.2.0",
            "/bundle",
            BTreeMap::from([("com.example".to_string(), "yes".to_string())]),
            MicrosandboxState::new("oci-abc", "/state/abc", "/bundle/rootfs", now),
        );

        let json = serde_json::to_value(&state).expect("serialize state");

        assert_eq!(json["ociVersion"], "1.2.0");
        assert_eq!(json["id"], "abc");
        assert_eq!(json["status"], "created");
        assert_eq!(json["bundle"], "/bundle");
        assert_eq!(json["annotations"]["com.example"], "yes");
        assert_eq!(json["microsandbox"]["sandboxName"], "oci-abc");
        assert_eq!(json["microsandbox"]["stateDir"], "/state/abc");
        assert_eq!(json["microsandbox"]["rootfs"], "/bundle/rootfs");
    }

    #[test]
    fn mark_running_and_stopped_updates_runtime_fields() {
        let now = Utc
            .with_ymd_and_hms(2026, 6, 25, 12, 0, 0)
            .single()
            .expect("valid test time");
        let mut state = OciState::created(
            "abc",
            "1.2.0",
            PathBuf::from("/bundle"),
            BTreeMap::new(),
            MicrosandboxState::new("oci-abc", "/state/abc", "/bundle/rootfs", now),
        );

        state.mark_running(42, Some(7), Some(99), now);
        assert_eq!(state.status, OciStatus::Running);
        assert_eq!(state.pid, Some(42));
        assert_eq!(
            state.microsandbox.as_ref().and_then(|msb| msb.guest_pid),
            Some(7)
        );
        assert_eq!(
            state
                .microsandbox
                .as_ref()
                .and_then(|msb| msb.init_exec_session_id),
            Some(99)
        );
        let json = serde_json::to_value(&state).expect("state JSON");
        assert_eq!(json["microsandbox"]["initExecSessionId"], 99);

        state.mark_stopped(Some(0), now);
        assert_eq!(state.status, OciStatus::Stopped);
        assert_eq!(
            state.microsandbox.as_ref().and_then(|msb| msb.exit_code),
            Some(0)
        );
    }
}

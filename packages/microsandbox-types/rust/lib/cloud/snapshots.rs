//! Cloud snapshot request, resource, and operation wire contracts.

use std::collections::BTreeMap;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::CloudErrorDetails;
use crate::snapshot::Manifest as SnapshotManifest;

//--------------------------------------------------------------------------------------------------
// Types: Snapshots
//--------------------------------------------------------------------------------------------------

/// Kind of cloud snapshot artifact or capture operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum CloudSnapshotKind {
    /// Capture disk state only.
    Disk,
}

/// Settings shared by every cloud snapshot capture kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CloudSnapshotSpec {
    /// Immutable identifier of the sandbox to capture.
    pub source_sandbox_id: String,
    /// Snapshot name.
    pub name: String,
    /// Directory on a mounted host volume to write the artifact into. `None`
    /// stores the snapshot in managed snapshot storage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(type = "string | null"))]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<String>))]
    pub dest_dir: Option<PathBuf>,
    /// User-defined labels stored on the snapshot.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    /// Replace an existing snapshot with the same name.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub force: bool,
    /// Record payload integrity metadata during capture.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub record_integrity: bool,
}

/// Wire shape of a cloud snapshot create request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CloudCreateSnapshotRequest {
    /// Capture disk state only.
    Disk {
        /// Settings shared by every snapshot kind.
        #[serde(flatten)]
        snapshot: CloudSnapshotSpec,
    },
}

/// Fields shared by every completed cloud snapshot kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CloudSnapshotDetails {
    /// Snapshot name.
    pub name: String,
    /// Where the snapshot artifact resides.
    pub location: CloudSnapshotLocation,
    /// Identifier of the sandbox the snapshot was captured from, when known.
    #[serde(default)]
    pub source_sandbox_id: Option<String>,
    /// Snapshot identity: the `sha256:` digest of the canonical descriptor.
    pub digest: String,
    /// Stored payload size in bytes.
    pub size_bytes: u64,
    /// Canonical snapshot descriptor.
    pub manifest: SnapshotManifest,
    /// User-defined labels stored on the snapshot.
    pub labels: BTreeMap<String, String>,
    /// Creation timestamp.
    #[cfg_attr(feature = "ts", ts(type = "string"))]
    pub created_at: DateTime<Utc>,
}

/// Wire shape of a completed cloud snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CloudSnapshot {
    /// A disk-only snapshot.
    Disk {
        /// Fields shared by every snapshot kind.
        #[serde(flatten)]
        snapshot: CloudSnapshotDetails,
    },
}

/// Public locator for a managed or host-volume cloud snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CloudSnapshotLocation {
    /// Held in managed snapshot storage.
    Managed {
        /// Identifier of the stored artifact.
        id: String,
    },
    /// Stored in a directory on a mounted host volume.
    HostVolume {
        /// Artifact directory path on the host volume.
        path: String,
    },
}

/// Wire shape of the asynchronous snapshot operation returned by snapshot
/// capture endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CloudSnapshotOperation {
    /// Server-side operation identifier.
    pub id: String,
    /// Kind of snapshot being captured.
    pub kind: CloudSnapshotKind,
    /// Current operation status.
    pub status: CloudSnapshotOperationStatus,
    /// The resulting snapshot, present once the operation succeeds.
    #[serde(default)]
    pub result: Option<CloudSnapshot>,
    /// Error details for a failed operation.
    #[serde(default)]
    pub error: Option<CloudErrorDetails>,
    /// Creation timestamp.
    #[cfg_attr(feature = "ts", ts(type = "string"))]
    pub created_at: DateTime<Utc>,
    /// Timestamp of the most recent status change.
    #[cfg_attr(feature = "ts", ts(type = "string"))]
    pub updated_at: DateTime<Utc>,
    /// Timestamp of the terminal status, when the operation has finished.
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(type = "string | null"))]
    pub completed_at: Option<DateTime<Utc>>,
}

/// Status of an asynchronous cloud snapshot operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum CloudSnapshotOperationStatus {
    /// Accepted but not yet started.
    Queued,
    /// The operation is running.
    InProgress,
    /// The snapshot is complete and available.
    Succeeded,
    /// The operation failed.
    Failed,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CloudCreateSnapshotRequest {
    /// Return the requested snapshot kind.
    pub const fn kind(&self) -> CloudSnapshotKind {
        match self {
            Self::Disk { .. } => CloudSnapshotKind::Disk,
        }
    }

    /// Return settings shared by every snapshot kind.
    pub const fn snapshot_spec(&self) -> &CloudSnapshotSpec {
        match self {
            Self::Disk { snapshot } => snapshot,
        }
    }

    /// Return mutable settings shared by every snapshot kind.
    pub const fn snapshot_spec_mut(&mut self) -> &mut CloudSnapshotSpec {
        match self {
            Self::Disk { snapshot } => snapshot,
        }
    }
}

impl CloudSnapshot {
    /// Return the completed snapshot kind.
    pub const fn kind(&self) -> CloudSnapshotKind {
        match self {
            Self::Disk { .. } => CloudSnapshotKind::Disk,
        }
    }

    /// Return fields shared by every snapshot kind.
    pub const fn details(&self) -> &CloudSnapshotDetails {
        match self {
            Self::Disk { snapshot } => snapshot,
        }
    }

    /// Consume this snapshot and return its shared fields.
    pub fn into_details(self) -> CloudSnapshotDetails {
        match self {
            Self::Disk { snapshot } => snapshot,
        }
    }
}

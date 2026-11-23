//! Normalize loaded descriptors without changing their wire digest or persisted representation.

use std::{collections::BTreeMap, sync::Arc};

use super::{Checkpoint, Manifest, SnapshotReference, SnapshotState};
use crate::{
    MicrosandboxError, MicrosandboxResult,
    context::{Context, ContextKind},
};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Checkpoint {
    pub(crate) fn from_descriptor(
        backend: Arc<dyn Context>,
        reference: SnapshotReference,
        digest: String,
        manifest: Manifest,
        labels: BTreeMap<String, String>,
        reported_size_bytes: Option<u64>,
    ) -> MicrosandboxResult<Self> {
        let (format, fstype, checkpoint_manifest_digest) = match &manifest.state {
            SnapshotState::File(state) => (
                Some(state.disk_format),
                Some(state.filesystem.clone()),
                None,
            ),
            SnapshotState::Checkpoint(state) => (None, None, Some(state.checkpoint_root.clone())),
        };
        let is_local = backend.kind() == ContextKind::Local;
        // Match the existing local index tolerance while preserving remote validation.
        let created_at = chrono::DateTime::parse_from_rfc3339(&manifest.capture.created_at)
            .map(|value| value.naive_utc())
            .or_else(|error| {
                if is_local {
                    Ok(chrono::Utc::now().naive_utc())
                } else {
                    Err(MicrosandboxError::InvalidConfig(format!(
                        "remote snapshot has invalid created_at: {error}"
                    )))
                }
            })?;
        let locality = if is_local {
            "embedded"
        } else {
            "provider_linked"
        };
        Ok(Self {
            backend,
            reference,
            snapshot_id: manifest.snapshot_id.to_string(),
            group: None,
            head_update: None,
            digest,
            name: None,
            parent_digest: manifest.parent.as_ref().map(ToString::to_string),
            scope: manifest.scope,
            image_ref: manifest.image.reference.clone(),
            state_kind: manifest.state.kind().into(),
            format,
            fstype,
            checkpoint_manifest_digest,
            size_bytes: reported_size_bytes
                .or_else(|| manifest.state.as_file().map(|file| file.virtual_size)),
            locality: locality.into(),
            // These constructors are called only after the backend has successfully opened the artifact.
            availability: "ready".into(),
            migration_state: if is_local { "canonical" } else { "complete" }.into(),
            migration_error_code: None,
            created_at,
            loaded_manifest: Some(manifest),
            labels,
            #[cfg(feature = "local")]
            previous_upper: None,
        })
    }
}

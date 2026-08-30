//! Mutable local metadata attached to a snapshot artifact.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{MicrosandboxError, MicrosandboxResult};

use super::Manifest;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

pub(crate) const METADATA_FILENAME: &str = "metadata.json";
const METADATA_SCHEMA: &str = "microsandbox.snapshot-metadata/1";
const MAX_METADATA_BYTES: u64 = 1024 * 1024;
const LEGACY_LABEL_EXTENSION: &str = "org.microsandbox.capture-labels";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotMetadata {
    schema: String,
    labels: BTreeMap<String, String>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn encode(labels: &BTreeMap<String, String>) -> MicrosandboxResult<Vec<u8>> {
    let bytes = serde_json::to_vec(&SnapshotMetadata {
        schema: METADATA_SCHEMA.into(),
        labels: labels.clone(),
    })
    .map_err(MicrosandboxError::from)?;
    if bytes.len() as u64 > MAX_METADATA_BYTES {
        return Err(MicrosandboxError::InvalidConfig(
            "snapshot labels exceed the 1 MiB metadata limit".into(),
        ));
    }
    Ok(bytes)
}

pub(crate) fn decode(bytes: &[u8]) -> MicrosandboxResult<BTreeMap<String, String>> {
    if bytes.len() as u64 > MAX_METADATA_BYTES {
        return Err(MicrosandboxError::SnapshotIntegrity(
            "snapshot metadata exceeds the 1 MiB limit".into(),
        ));
    }
    let metadata: SnapshotMetadata = serde_json::from_slice(bytes).map_err(|error| {
        MicrosandboxError::SnapshotIntegrity(format!("invalid snapshot metadata: {error}"))
    })?;
    if metadata.schema != METADATA_SCHEMA {
        return Err(MicrosandboxError::SnapshotIntegrity(format!(
            "unsupported snapshot metadata schema: {}",
            metadata.schema
        )));
    }
    Ok(metadata.labels)
}

pub(crate) async fn read(
    artifact_dir: &Path,
    manifest: &Manifest,
    translated_labels: Option<BTreeMap<String, String>>,
) -> MicrosandboxResult<BTreeMap<String, String>> {
    let path = artifact_dir.join(METADATA_FILENAME);
    match tokio::fs::symlink_metadata(&path).await {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || metadata.len() > MAX_METADATA_BYTES {
                return Err(MicrosandboxError::SnapshotIntegrity(format!(
                    "snapshot metadata is not a bounded regular file: {}",
                    path.display()
                )));
            }
            decode(&tokio::fs::read(path).await?)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => match translated_labels {
            Some(labels) => Ok(labels),
            None => legacy_labels(manifest),
        },
        Err(error) => Err(error.into()),
    }
}

pub(crate) async fn write(
    artifact_dir: &Path,
    labels: &BTreeMap<String, String>,
) -> MicrosandboxResult<()> {
    if labels.is_empty() {
        return Ok(());
    }
    let bytes = encode(labels)?;
    let path = artifact_dir.join(METADATA_FILENAME);
    match tokio::fs::symlink_metadata(&path).await {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || metadata.len() > MAX_METADATA_BYTES {
                return Err(MicrosandboxError::SnapshotIntegrity(format!(
                    "snapshot metadata is not a bounded regular file: {}",
                    path.display()
                )));
            }
            if decode(&tokio::fs::read(&path).await?)? == *labels {
                return Ok(());
            }
            return Err(MicrosandboxError::SnapshotIntegrity(format!(
                "snapshot metadata already exists with different labels: {}",
                path.display()
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let temporary = artifact_dir.join(format!(".{METADATA_FILENAME}.tmp"));
    let mut durable = tokio::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&temporary)
        .await?;
    use tokio::io::AsyncWriteExt as _;
    durable.write_all(&bytes).await?;
    durable.sync_all().await?;
    drop(durable);
    tokio::fs::rename(temporary, path).await?;
    Ok(())
}

pub(crate) fn write_sync(
    artifact_dir: &Path,
    labels: &BTreeMap<String, String>,
) -> MicrosandboxResult<()> {
    if labels.is_empty() {
        return Ok(());
    }
    let bytes = encode(labels)?;
    let path = artifact_dir.join(METADATA_FILENAME);
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || metadata.len() > MAX_METADATA_BYTES {
                return Err(MicrosandboxError::SnapshotIntegrity(format!(
                    "snapshot metadata is not a bounded regular file: {}",
                    path.display()
                )));
            }
            if decode(&std::fs::read(&path)?)? == *labels {
                return Ok(());
            }
            return Err(MicrosandboxError::SnapshotIntegrity(format!(
                "snapshot metadata already exists with different labels: {}",
                path.display()
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let temporary = artifact_dir.join(format!(".{METADATA_FILENAME}.tmp.{}", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    use std::io::Write as _;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(temporary, path)?;
    Ok(())
}

pub(crate) fn read_sync(
    artifact_dir: &Path,
    manifest: &Manifest,
    translated_labels: Option<BTreeMap<String, String>>,
) -> MicrosandboxResult<BTreeMap<String, String>> {
    let path = artifact_dir.join(METADATA_FILENAME);
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || metadata.len() > MAX_METADATA_BYTES {
                return Err(MicrosandboxError::SnapshotIntegrity(format!(
                    "snapshot metadata is not a bounded regular file: {}",
                    path.display()
                )));
            }
            decode(&std::fs::read(path)?)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => match translated_labels {
            Some(labels) => Ok(labels),
            None => legacy_labels(manifest),
        },
        Err(error) => Err(error.into()),
    }
}

fn legacy_labels(manifest: &Manifest) -> MicrosandboxResult<BTreeMap<String, String>> {
    match manifest.extensions.get(LEGACY_LABEL_EXTENSION) {
        Some(value) => serde_json::from_value(value.clone()).map_err(|error| {
            MicrosandboxError::SnapshotIntegrity(format!(
                "invalid labels in released snapshot descriptor: {error}"
            ))
        }),
        None => Ok(BTreeMap::new()),
    }
}

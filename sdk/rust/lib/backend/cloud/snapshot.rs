//! Cloud snapshot lifecycle and host-volume artifact access.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::future::BoxFuture;
use microsandbox_types::{
    CloudCreateSnapshotRequest, CloudPaginated, CloudSnapshot, CloudSnapshotLocation,
    CloudSnapshotOperation, CloudSnapshotOperationStatus,
};
use serde::Serialize;

use super::CloudBackend;
use super::http::{cloud_io_error, decode_json, ensure_success, urlencoding};
use crate::backend::{Backend, SnapshotBackend};
use crate::sandbox::{FsEntryKind, SandboxConfig};
use crate::snapshot::{
    DESCRIPTOR_FILENAME, Manifest, SaveOpts, Snapshot, SnapshotConfig, SnapshotHandle,
    SnapshotReference, SnapshotState, SnapshotVerifyReport,
};
use crate::{MicrosandboxError, MicrosandboxResult, Operation};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const SNAPSHOT_OPERATION_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const SNAPSHOT_OPERATION_INITIAL_POLL_INTERVAL: Duration = Duration::from_millis(250);
const SNAPSHOT_OPERATION_MAX_POLL_INTERVAL: Duration = Duration::from_secs(5);
const SNAPSHOT_LIST_PAGE_SIZE: u32 = 100;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Serialize)]
struct SnapshotListQuery<'a> {
    limit: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<&'a str>,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl SnapshotBackend for CloudBackend {
    fn create<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        config: SnapshotConfig,
    ) -> BoxFuture<'a, MicrosandboxResult<Snapshot>> {
        Box::pin(async move {
            let source = self.get_sandbox(&config.source_sandbox).await?;
            let request = CloudCreateSnapshotRequest {
                source_sandbox_id: source.id,
                name: config.name,
                dest_dir: config.dest_dir,
                labels: config.labels.into_iter().collect::<BTreeMap<_, _>>(),
                force: config.force,
                record_integrity: config.record_integrity,
                resumable: config.resumable,
            };
            let operation = self.create_snapshot(&request).await?;
            let snapshot = self.wait_for_snapshot(operation).await?;

            Ok(snapshot_from_cloud(backend, snapshot))
        })
    }

    fn open<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        reference: SnapshotReference,
    ) -> BoxFuture<'a, MicrosandboxResult<Snapshot>> {
        Box::pin(async move {
            let snapshot = match reference {
                SnapshotReference::Id(id) => self.find_snapshot_by_id(&id).await?,
                SnapshotReference::Path(path) => self.open_host_volume_snapshot(path).await?,
                SnapshotReference::Auto(reference) if looks_like_path(&reference) => {
                    self.open_host_volume_snapshot(reference).await?
                }
                SnapshotReference::Auto(identifier) => self.find_snapshot(&identifier).await?,
            };

            Ok(snapshot_from_cloud(backend, snapshot))
        })
    }

    fn get<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        identifier: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<SnapshotHandle>> {
        Box::pin(async move {
            let snapshot = self.find_snapshot(identifier).await?;
            snapshot_handle_from_cloud(backend, snapshot)
        })
    }

    fn list(
        &self,
        backend: Arc<dyn Backend>,
    ) -> BoxFuture<'_, MicrosandboxResult<Vec<SnapshotHandle>>> {
        Box::pin(async move {
            self.list_all_snapshots()
                .await?
                .into_iter()
                .map(|snapshot| snapshot_handle_from_cloud(backend.clone(), snapshot))
                .collect()
        })
    }

    fn remove<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        reference: SnapshotReference,
        _force: bool,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            match reference {
                SnapshotReference::Id(id) => self.delete_snapshot_by_id(&id).await,
                SnapshotReference::Path(path) => self.volumes().fs_remove("", &path, true).await,
                SnapshotReference::Auto(reference) if looks_like_path(&reference) => {
                    self.volumes().fs_remove("", &reference, true).await
                }
                SnapshotReference::Auto(identifier) => self.delete_snapshot(&identifier).await,
            }
        })
    }

    fn prepare_restore<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        config: &'a mut SandboxConfig,
        reference: SnapshotReference,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            config.snapshot_reference = Some(reference);
            Ok(())
        })
    }

    fn verify<'a>(
        &'a self,
        _snapshot: &'a Snapshot,
    ) -> BoxFuture<'a, MicrosandboxResult<SnapshotVerifyReport>> {
        Box::pin(async move { Err(MicrosandboxError::local_only(Operation::SnapshotOps)) })
    }

    fn list_dir(
        &self,
        _backend: Arc<dyn Backend>,
        _dir: PathBuf,
    ) -> BoxFuture<'_, MicrosandboxResult<Vec<Snapshot>>> {
        Box::pin(async move { Err(MicrosandboxError::local_only(Operation::SnapshotOps)) })
    }

    fn reindex(&self, _dir: Option<PathBuf>) -> BoxFuture<'_, MicrosandboxResult<usize>> {
        Box::pin(async move { Err(MicrosandboxError::local_only(Operation::SnapshotOps)) })
    }

    fn save<'a>(
        &'a self,
        _reference: SnapshotReference,
        _out: &'a Path,
        _opts: SaveOpts,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { Err(MicrosandboxError::local_only(Operation::SnapshotOps)) })
    }

    fn load<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _archive: &'a Path,
        _dest: Option<&'a Path>,
    ) -> BoxFuture<'a, MicrosandboxResult<SnapshotHandle>> {
        Box::pin(async move { Err(MicrosandboxError::local_only(Operation::SnapshotOps)) })
    }
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CloudBackend {
    async fn create_snapshot(
        &self,
        request: &CloudCreateSnapshotRequest,
    ) -> MicrosandboxResult<CloudSnapshotOperation> {
        let url = format!("{}/v1/snapshots", self.url);
        let response = self
            .http
            .post(&url)
            .json(request)
            .send()
            .await
            .map_err(|error| cloud_io_error("POST /v1/snapshots", error))?;
        decode_json(response, "POST /v1/snapshots").await
    }

    async fn get_snapshot_operation(&self, id: &str) -> MicrosandboxResult<CloudSnapshotOperation> {
        let url = format!("{}/v1/snapshot-operations/{}", self.url, urlencoding(id));
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|error| cloud_io_error("GET /v1/snapshot-operations/:id", error))?;
        decode_json(response, "GET /v1/snapshot-operations/:id").await
    }

    async fn wait_for_snapshot(
        &self,
        mut operation: CloudSnapshotOperation,
    ) -> MicrosandboxResult<CloudSnapshot> {
        let started = Instant::now();
        let mut poll_interval = SNAPSHOT_OPERATION_INITIAL_POLL_INTERVAL;
        loop {
            match operation.status {
                CloudSnapshotOperationStatus::Succeeded => {
                    return operation.result.ok_or_else(|| {
                        MicrosandboxError::Runtime(format!(
                            "snapshot operation {} succeeded without a result",
                            operation.id
                        ))
                    });
                }
                CloudSnapshotOperationStatus::Failed => {
                    let detail =
                        operation
                            .error
                            .and_then(|error| match (error.code, error.message) {
                                (Some(code), Some(message)) => Some(format!("{code}: {message}")),
                                (Some(code), None) => Some(code),
                                (None, Some(message)) => Some(message),
                                (None, None) => None,
                            });
                    return Err(MicrosandboxError::Runtime(format!(
                        "snapshot operation {} failed{}",
                        operation.id,
                        detail
                            .map(|detail| format!(": {detail}"))
                            .unwrap_or_default()
                    )));
                }
                CloudSnapshotOperationStatus::Queued | CloudSnapshotOperationStatus::InProgress => {
                }
            }

            if started.elapsed() >= SNAPSHOT_OPERATION_TIMEOUT {
                return Err(MicrosandboxError::Runtime(format!(
                    "snapshot operation {} did not finish within {:?}; server-side work may still be continuing",
                    operation.id, SNAPSHOT_OPERATION_TIMEOUT,
                )));
            }

            tokio::time::sleep(poll_interval).await;
            operation = self.get_snapshot_operation(&operation.id).await?;
            poll_interval = poll_interval
                .saturating_mul(2)
                .min(SNAPSHOT_OPERATION_MAX_POLL_INTERVAL);
        }
    }

    async fn find_snapshot(&self, identifier: &str) -> MicrosandboxResult<CloudSnapshot> {
        if looks_like_uuid(identifier) {
            match self.find_snapshot_by_id(identifier).await {
                Err(error) if is_snapshot_not_found(&error) => {}
                result => return result,
            }
        }
        self.find_snapshot_by_name(identifier).await
    }

    async fn find_snapshot_by_id(&self, id: &str) -> MicrosandboxResult<CloudSnapshot> {
        let route = format!("/v1/snapshots/{}", urlencoding(id));
        self.find_snapshot_at(&route).await
    }

    async fn find_snapshot_by_name(&self, name: &str) -> MicrosandboxResult<CloudSnapshot> {
        let route = format!("/v1/snapshots/by-name/{}", urlencoding(name));
        self.find_snapshot_at(&route).await
    }

    async fn find_snapshot_at(&self, route: &str) -> MicrosandboxResult<CloudSnapshot> {
        let url = format!("{}{}", self.url, route);
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|error| cloud_io_error("GET /v1/snapshots/:identifier", error))?;
        decode_json(response, "GET /v1/snapshots/:identifier").await
    }

    async fn list_all_snapshots(&self) -> MicrosandboxResult<Vec<CloudSnapshot>> {
        let mut snapshots = Vec::new();
        let mut cursor: Option<String> = None;

        loop {
            let url = format!("{}/v1/snapshots", self.url);
            let query = SnapshotListQuery {
                limit: SNAPSHOT_LIST_PAGE_SIZE,
                cursor: cursor.as_deref(),
            };
            let response = self
                .http
                .get(&url)
                .query(&query)
                .send()
                .await
                .map_err(|error| cloud_io_error("GET /v1/snapshots", error))?;
            let page: CloudPaginated<CloudSnapshot> =
                decode_json(response, "GET /v1/snapshots").await?;
            snapshots.extend(page.data);

            let Some(next) = page.next_cursor else {
                return Ok(snapshots);
            };
            cursor = Some(next);
        }
    }

    async fn delete_snapshot(&self, identifier: &str) -> MicrosandboxResult<()> {
        if looks_like_uuid(identifier) {
            match self.delete_snapshot_by_id(identifier).await {
                Err(error) if is_snapshot_not_found(&error) => {}
                result => return result,
            }
        }
        self.delete_snapshot_by_name(identifier).await
    }

    async fn delete_snapshot_by_id(&self, id: &str) -> MicrosandboxResult<()> {
        let route = format!("/v1/snapshots/{}", urlencoding(id));
        self.delete_snapshot_at(&route).await
    }

    async fn delete_snapshot_by_name(&self, name: &str) -> MicrosandboxResult<()> {
        let route = format!("/v1/snapshots/by-name/{}", urlencoding(name));
        self.delete_snapshot_at(&route).await
    }

    async fn delete_snapshot_at(&self, route: &str) -> MicrosandboxResult<()> {
        let url = format!("{}{}", self.url, route);
        let response = self
            .http
            .delete(&url)
            .send()
            .await
            .map_err(|error| cloud_io_error("DELETE /v1/snapshots/:identifier", error))?;
        ensure_success(response, "DELETE /v1/snapshots/:identifier").await?;
        Ok(())
    }

    async fn open_host_volume_snapshot(&self, path: String) -> MicrosandboxResult<CloudSnapshot> {
        let descriptor_path = format!("{}/{DESCRIPTOR_FILENAME}", path.trim_end_matches('/'));
        let descriptor = self
            .volumes()
            .fs_read_to_string("", &descriptor_path)
            .await?;
        let manifest = Manifest::from_bytes(descriptor.as_bytes()).map_err(|error| {
            MicrosandboxError::SnapshotIntegrity(format!(
                "invalid host-volume snapshot descriptor at {path}: {error}"
            ))
        })?;
        let digest = manifest.digest().map_err(|error| {
            MicrosandboxError::SnapshotIntegrity(format!(
                "could not identify host-volume snapshot at {path}: {error}"
            ))
        })?;
        if let SnapshotState::File(state) = &manifest.state {
            let upper_path = format!(
                "{}/{}",
                path.trim_end_matches('/'),
                state.upper.file.trim_start_matches('/')
            );
            let metadata = self.volumes().fs_stat("", &upper_path).await?;
            if metadata.kind != FsEntryKind::File {
                return Err(MicrosandboxError::SnapshotIntegrity(format!(
                    "host-volume snapshot payload at {upper_path} is not a regular file"
                )));
            }
            if metadata.size != state.upper.size_bytes {
                return Err(MicrosandboxError::SnapshotIntegrity(format!(
                    "host-volume snapshot payload at {upper_path} has size {}, expected {}",
                    metadata.size, state.upper.size_bytes
                )));
            }
        }
        let created_at = chrono::DateTime::parse_from_rfc3339(&manifest.created_at)
            .map_err(|error| {
                MicrosandboxError::SnapshotIntegrity(format!(
                    "invalid host-volume snapshot timestamp at {path}: {error}"
                ))
            })?
            .with_timezone(&chrono::Utc);
        let size_bytes = match &manifest.state {
            SnapshotState::File(state) => state.upper.size_bytes,
            SnapshotState::Checkpoint(_) => 0,
        };
        let name = Path::new(&path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(&path)
            .to_string();

        Ok(CloudSnapshot {
            name,
            location: CloudSnapshotLocation::HostVolume { path },
            source_sandbox_id: None,
            digest,
            size_bytes,
            labels: manifest.labels.clone(),
            created_at,
            manifest,
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn cloud_reference(
    reference: SnapshotReference,
) -> MicrosandboxResult<CloudSnapshotLocation> {
    match reference {
        SnapshotReference::Id(id) => Ok(CloudSnapshotLocation::Managed { id }),
        SnapshotReference::Path(path) => Ok(CloudSnapshotLocation::HostVolume { path }),
        SnapshotReference::Auto(reference) => {
            if reference.contains(['/', '\\'])
                || reference.starts_with('.')
                || reference.starts_with('~')
            {
                return Ok(CloudSnapshotLocation::HostVolume { path: reference });
            }
            Ok(CloudSnapshotLocation::Managed { id: reference })
        }
    }
}

fn snapshot_from_cloud(backend: Arc<dyn Backend>, snapshot: CloudSnapshot) -> Snapshot {
    Snapshot {
        backend,
        reference: reference_from_cloud_location(snapshot.location),
        digest: snapshot.digest,
        manifest: snapshot.manifest,
        reported_size_bytes: Some(snapshot.size_bytes),
    }
}

fn snapshot_handle_from_cloud(
    backend: Arc<dyn Backend>,
    snapshot: CloudSnapshot,
) -> MicrosandboxResult<SnapshotHandle> {
    let (format, fstype, checkpoint_manifest_digest) = match &snapshot.manifest.state {
        SnapshotState::File(state) => (Some(state.format), Some(state.fstype.clone()), None),
        SnapshotState::Checkpoint(state) => (None, None, Some(state.manifest.clone())),
    };
    let created_at = chrono::DateTime::parse_from_rfc3339(&snapshot.manifest.created_at)
        .map_err(|error| {
            MicrosandboxError::InvalidConfig(format!(
                "cloud snapshot has invalid created_at: {error}"
            ))
        })?
        .naive_utc();

    Ok(SnapshotHandle {
        backend,
        reference: reference_from_cloud_location(snapshot.location),
        digest: snapshot.digest,
        name: Some(snapshot.name),
        parent_digest: snapshot.manifest.parent,
        scope: snapshot.manifest.scope,
        image_ref: snapshot.manifest.image.reference,
        state_kind: snapshot.manifest.state.kind().to_string(),
        format,
        fstype,
        checkpoint_manifest_digest,
        size_bytes: Some(snapshot.size_bytes),
        locality: "provider_linked".into(),
        availability: "ready".into(),
        migration_state: "complete".into(),
        migration_error_code: None,
        created_at,
    })
}

fn reference_from_cloud_location(location: CloudSnapshotLocation) -> SnapshotReference {
    match location {
        CloudSnapshotLocation::Managed { id } => SnapshotReference::id(id),
        CloudSnapshotLocation::HostVolume { path } => SnapshotReference::path(path),
    }
}

fn looks_like_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

fn looks_like_path(reference: &str) -> bool {
    reference.contains(['/', '\\']) || reference.starts_with('.') || reference.starts_with('~')
}

fn is_snapshot_not_found(error: &MicrosandboxError) -> bool {
    matches!(
        error,
        MicrosandboxError::SnapshotNotFound(_) | MicrosandboxError::CloudHttp { status: 404, .. }
    )
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_unsupported(result: MicrosandboxResult<impl Sized>) {
        assert!(matches!(result, Err(MicrosandboxError::Unsupported { .. })));
    }

    #[test]
    fn auto_references_preserve_managed_and_host_volume_meaning() {
        assert_eq!(
            cloud_reference(SnapshotReference::auto("snapshot-id")).unwrap(),
            CloudSnapshotLocation::Managed {
                id: "snapshot-id".into()
            }
        );
        assert_eq!(
            cloud_reference(SnapshotReference::auto("snapshots/base")).unwrap(),
            CloudSnapshotLocation::HostVolume {
                path: "snapshots/base".into()
            }
        );
    }

    #[test]
    fn typed_references_map_to_cloud_storage_modes() {
        assert_eq!(
            cloud_reference(SnapshotReference::id("snapshot-id")).unwrap(),
            CloudSnapshotLocation::Managed {
                id: "snapshot-id".into()
            }
        );
        assert_eq!(
            cloud_reference(SnapshotReference::path("snapshots/base")).unwrap(),
            CloudSnapshotLocation::HostVolume {
                path: "snapshots/base".into()
            }
        );
    }

    #[test]
    fn uuid_detection_does_not_treat_names_as_ids() {
        assert!(looks_like_uuid("00000000-0000-0000-0000-000000000003"));
        assert!(!looks_like_uuid("nightly"));
        assert!(!looks_like_uuid("00000000-0000-0000-0000-00000000000z"));
    }

    #[test]
    fn typed_snapshot_not_found_allows_uuid_name_fallback() {
        assert!(is_snapshot_not_found(&MicrosandboxError::SnapshotNotFound(
            "missing id".into()
        )));
        assert!(is_snapshot_not_found(&MicrosandboxError::CloudHttp {
            status: 404,
            code: None,
            message: "missing id".into(),
        }));
        assert!(!is_snapshot_not_found(
            &MicrosandboxError::SnapshotAlreadyExists("conflict".into())
        ));
    }

    #[tokio::test]
    async fn artifact_file_operations_return_typed_unsupported_errors() {
        let cloud = CloudBackend::new("https://example.invalid", "test-key").unwrap();
        let backend: Arc<dyn Backend> = Arc::new(cloud.clone());

        assert_unsupported(
            SnapshotBackend::list_dir(&cloud, backend.clone(), PathBuf::from("snapshots")).await,
        );
        assert_unsupported(SnapshotBackend::reindex(&cloud, None).await);
        assert_unsupported(
            SnapshotBackend::save(
                &cloud,
                SnapshotReference::id("snapshot-id"),
                Path::new("snapshot.tar.zst"),
                SaveOpts::default(),
            )
            .await,
        );
        assert_unsupported(
            SnapshotBackend::load(&cloud, backend, Path::new("snapshot.tar.zst"), None).await,
        );
    }
}

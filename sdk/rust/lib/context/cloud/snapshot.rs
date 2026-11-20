//! Cloud snapshot lifecycle and host-volume artifact access.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::future::BoxFuture;
use microsandbox_types::snapshot::{cloud_manifest, legacy::project_cloud_descriptor};
use microsandbox_types::{
    CloudCreateSnapshotRequest, CloudPaginated, CloudSnapshot, CloudSnapshotDetails,
    CloudSnapshotLocation, CloudSnapshotOperation, CloudSnapshotOperationStatus, CloudSnapshotSpec,
};
use serde::Serialize;

use super::RemoteContext;
use super::http::{cloud_io_error, decode_json, ensure_success, urlencoding};
use crate::context::{Context, SnapshotOps};
use crate::sandbox::{FsEntryKind, SandboxConfig};
use crate::snapshot::{
    Checkpoint as Snapshot, DESCRIPTOR_FILENAME, Manifest, SaveOpts, SnapshotConfig,
    SnapshotReference, SnapshotVerifyReport,
};
use crate::{MicrosandboxError, MicrosandboxResult, Operation, UnsupportedReason};

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

impl SnapshotOps for RemoteContext {
    fn create<'a>(
        &'a self,
        backend: Arc<dyn Context>,
        config: SnapshotConfig,
    ) -> BoxFuture<'a, MicrosandboxResult<Snapshot>> {
        Box::pin(async move {
            if config.guest_flush != microsandbox_types::GuestFlush::Auto {
                return Err(MicrosandboxError::local_only(Operation::SnapshotOps));
            }
            if config.full {
                return Err(MicrosandboxError::unsupported(
                    Operation::SnapshotOps,
                    UnsupportedReason::NotAvailable(
                        "full snapshots are not supported by the cloud backend".into(),
                    ),
                ));
            }

            if config.group.is_some() {
                return Err(MicrosandboxError::local_only(Operation::SnapshotOps));
            }

            let source = self.get_sandbox(&config.source_sandbox).await?;
            let request = cloud_snapshot_request(source.id, config);
            let operation = self.create_snapshot(&request).await?;
            let snapshot = self.wait_for_snapshot(operation).await?;

            snapshot_from_cloud(backend, snapshot)
        })
    }

    fn create_from<'a>(
        &'a self,
        backend: Arc<dyn Context>,
        config: SnapshotConfig,
        expected: &'a crate::sandbox::SandboxId,
    ) -> BoxFuture<'a, MicrosandboxResult<Snapshot>> {
        Box::pin(async move {
            if config.guest_flush != microsandbox_types::GuestFlush::Auto {
                return Err(MicrosandboxError::local_only(Operation::SnapshotOps));
            }
            if config.full {
                return Err(MicrosandboxError::unsupported(
                    Operation::SnapshotOps,
                    UnsupportedReason::NotAvailable(
                        "full snapshots are not supported by the cloud backend".into(),
                    ),
                ));
            }

            if config.group.is_some() {
                return Err(MicrosandboxError::local_only(Operation::SnapshotOps));
            }

            let source = self.get_sandbox(&config.source_sandbox).await?;
            if crate::sandbox::SandboxId::cloud(&source.id) != *expected {
                return Err(MicrosandboxError::SandboxReplaced {
                    name: config.source_sandbox,
                    expected: expected.to_string(),
                    actual: crate::sandbox::SandboxId::cloud(&source.id).to_string(),
                });
            }
            let request = cloud_snapshot_request(source.id, config);
            let operation = self.create_snapshot(&request).await?;
            let snapshot = self.wait_for_snapshot(operation).await?;

            snapshot_from_cloud(backend, snapshot)
        })
    }

    fn open<'a>(
        &'a self,
        backend: Arc<dyn Context>,
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

            snapshot_from_cloud(backend, snapshot)
        })
    }

    fn get<'a>(
        &'a self,
        backend: Arc<dyn Context>,
        identifier: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Snapshot>> {
        Box::pin(async move {
            let snapshot = self.find_snapshot(identifier).await?;
            snapshot_from_cloud(backend, snapshot)
        })
    }

    fn list(&self, backend: Arc<dyn Context>) -> BoxFuture<'_, MicrosandboxResult<Vec<Snapshot>>> {
        Box::pin(async move {
            self.list_all_snapshots()
                .await?
                .into_iter()
                .map(|snapshot| snapshot_from_cloud(backend.clone(), snapshot))
                .collect()
        })
    }

    fn remove<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        reference: SnapshotReference,
        _force: bool,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            match reference {
                SnapshotReference::Id(id) => self.delete_snapshot_by_id(&id).await,
                SnapshotReference::Path(path) => self.volume_ops().fs_remove("", &path, true).await,
                SnapshotReference::Auto(reference) if looks_like_path(&reference) => {
                    self.volume_ops().fs_remove("", &reference, true).await
                }
                SnapshotReference::Auto(identifier) => self.delete_snapshot(&identifier).await,
            }
        })
    }

    fn destroy<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        reference: SnapshotReference,
        _expected_digest: &'a str,
        _force: bool,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            match reference {
                SnapshotReference::Id(id) => self.delete_snapshot_by_id(&id).await,
                // A read/check followed by a path DELETE would still race with replacement.
                // Do not send a mutation until the provider has conditional deletion support.
                SnapshotReference::Path(_) | SnapshotReference::Auto(_) => {
                    Err(MicrosandboxError::unsupported(
                        Operation::SnapshotOps,
                        crate::error::UnsupportedReason::NotAvailable(
                            "identity-bound deletion of remote path snapshots requires provider conditional deletion support; use explicit path-selected remove only when intended".into(),
                        ),
                    ))
                }
            }
        })
    }

    fn prepare_restore<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        config: &'a mut SandboxConfig,
        reference: SnapshotReference,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            config.snapshot_reference = Some(reference);
            Ok(())
        })
    }

    fn path<'a>(&self, _reference: &'a SnapshotReference) -> MicrosandboxResult<&'a Path> {
        Err(MicrosandboxError::local_only(Operation::SnapshotOps))
    }

    fn verify<'a>(
        &'a self,
        _snapshot: &'a Snapshot,
    ) -> BoxFuture<'a, MicrosandboxResult<SnapshotVerifyReport>> {
        Box::pin(async move { Err(MicrosandboxError::local_only(Operation::SnapshotOps)) })
    }

    fn copy<'a>(
        &'a self,
        _snapshot: &'a Snapshot,
        _output_archive_path: &'a Path,
        _labels: BTreeMap<String, String>,
        _record_integrity: bool,
    ) -> BoxFuture<'a, MicrosandboxResult<Manifest>> {
        Box::pin(async move { Err(MicrosandboxError::local_only(Operation::SnapshotOps)) })
    }

    fn list_dir(
        &self,
        _backend: Arc<dyn Context>,
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
        _backend: Arc<dyn Context>,
        _archive: &'a Path,
        _dest: Option<&'a Path>,
    ) -> BoxFuture<'a, MicrosandboxResult<Snapshot>> {
        Box::pin(async move { Err(MicrosandboxError::local_only(Operation::SnapshotOps)) })
    }
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RemoteContext {
    async fn create_snapshot(
        &self,
        request: &CloudCreateSnapshotRequest,
    ) -> MicrosandboxResult<CloudSnapshotOperation> {
        let url = format!("{}/v1/snapshots", self.inner.url);
        let response = self
            .request(reqwest::Method::POST, &url)
            .json(request)
            .send()
            .await
            .map_err(|error| cloud_io_error("POST /v1/snapshots", error))?;
        decode_json(response, "POST /v1/snapshots").await
    }

    async fn get_snapshot_operation(&self, id: &str) -> MicrosandboxResult<CloudSnapshotOperation> {
        let url = format!(
            "{}/v1/snapshot-operations/{}",
            self.inner.url,
            urlencoding(id)
        );
        let response = self
            .request(reqwest::Method::GET, &url)
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
        let url = format!("{}{}", self.inner.url, route);
        let response = self
            .request(reqwest::Method::GET, &url)
            .send()
            .await
            .map_err(|error| cloud_io_error("GET /v1/snapshots/:identifier", error))?;
        decode_json(response, "GET /v1/snapshots/:identifier").await
    }

    async fn list_all_snapshots(&self) -> MicrosandboxResult<Vec<CloudSnapshot>> {
        let mut snapshots = Vec::new();
        let mut cursor: Option<String> = None;

        loop {
            let url = format!("{}/v1/snapshots", self.inner.url);
            let query = SnapshotListQuery {
                limit: SNAPSHOT_LIST_PAGE_SIZE,
                cursor: cursor.as_deref(),
            };
            let response = self
                .request(reqwest::Method::GET, &url)
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
        let url = format!("{}{}", self.inner.url, route);
        let response = self
            .request(reqwest::Method::DELETE, &url)
            .send()
            .await
            .map_err(|error| cloud_io_error("DELETE /v1/snapshots/:identifier", error))?;
        ensure_success(response, "DELETE /v1/snapshots/:identifier").await?;
        Ok(())
    }

    async fn open_host_volume_snapshot(&self, path: String) -> MicrosandboxResult<CloudSnapshot> {
        let descriptor_path = format!("{}/{DESCRIPTOR_FILENAME}", path.trim_end_matches('/'));
        let descriptor = self
            .volume_ops()
            .fs_read_to_string("", &descriptor_path)
            .await?;
        let manifest =
            cloud_manifest::Manifest::from_bytes(descriptor.as_bytes()).map_err(|error| {
                MicrosandboxError::SnapshotIntegrity(format!(
                    "invalid host-volume snapshot descriptor at {path}: {error}"
                ))
            })?;
        let digest = manifest.digest().map_err(|error| {
            MicrosandboxError::SnapshotIntegrity(format!(
                "could not identify host-volume snapshot at {path}: {error}"
            ))
        })?;
        if let cloud_manifest::SnapshotState::File(state) = &manifest.state {
            let upper_path = format!(
                "{}/{}",
                path.trim_end_matches('/'),
                state.upper.file.trim_start_matches('/')
            );
            let metadata = self.volume_ops().fs_stat("", &upper_path).await?;
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
            cloud_manifest::SnapshotState::File(state) => state.upper.size_bytes,
            cloud_manifest::SnapshotState::Checkpoint(_) => 0,
        };
        let name = Path::new(&path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(&path)
            .to_string();

        let snapshot = CloudSnapshotDetails {
            name,
            location: CloudSnapshotLocation::HostVolume { path },
            sandbox_id: None,
            digest,
            size_bytes,
            labels: manifest.labels.clone(),
            created_at,
            manifest,
        };

        match snapshot.manifest.scope {
            cloud_manifest::SnapshotScope::Disk => Ok(CloudSnapshot::Disk { snapshot }),
            cloud_manifest::SnapshotScope::Resumable => Err(MicrosandboxError::unsupported(
                Operation::SnapshotOps,
                UnsupportedReason::NotAvailable(
                    "full snapshots are not supported by the cloud backend".into(),
                ),
            )),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn cloud_snapshot_request(
    sandbox_id: String,
    config: SnapshotConfig,
) -> CloudCreateSnapshotRequest {
    let snapshot = CloudSnapshotSpec {
        sandbox_id,
        name: config.name,
        dest_dir: config.dest_dir,
        labels: config.labels.into_iter().collect::<BTreeMap<_, _>>(),
        force: config.force,
        record_integrity: config.record_integrity,
    };

    CloudCreateSnapshotRequest::Disk { snapshot }
}

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

fn snapshot_from_cloud(
    backend: Arc<dyn Context>,
    snapshot: CloudSnapshot,
) -> MicrosandboxResult<Snapshot> {
    let snapshot = snapshot.into_details();
    // Verify the wire codec before projecting it. Never hash the normalized SDK view as a wire digest.
    let manifest = project_cloud_descriptor(&snapshot.manifest, &snapshot.digest)?;
    let mut resource = Snapshot::from_descriptor(
        backend,
        reference_from_cloud_location(snapshot.location),
        snapshot.digest,
        manifest,
        snapshot.labels,
        Some(snapshot.size_bytes),
    )?;
    resource.name = Some(snapshot.name);
    Ok(resource)
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
    use microsandbox_types::CloudSnapshotKind;

    use super::*;

    #[tokio::test]
    async fn snapshot_routes_use_derived_auth_even_with_custom_client() {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let mut routes = Vec::new();
            for _ in 0..5 {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                let mut route = String::new();
                stream.read_line(&mut route).await.unwrap();
                routes.push(route);
                let mut auth = false;
                let mut length = 0usize;
                loop {
                    let mut line = String::new();
                    stream.read_line(&mut line).await.unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    let lower = line.to_ascii_lowercase();
                    if lower.starts_with("authorization:") {
                        assert_eq!(lower.trim(), "authorization: bearer derived-key");
                        auth = true;
                    }
                    if let Some(value) = lower.strip_prefix("content-length:") {
                        length = value.trim().parse().unwrap();
                    }
                }
                assert!(auth, "snapshot request omitted context authentication");
                let mut body = vec![0; length];
                stream.read_exact(&mut body).await.unwrap();
                stream.get_mut().write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await.unwrap();
            }
            routes
        });
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_static("Bearer wrong-client-key"),
        );
        let original = RemoteContext::builder()
            .url(url)
            .api_key("original-key")
            .client(
                reqwest::Client::builder()
                    .default_headers(headers)
                    .build()
                    .unwrap(),
            )
            .config_sources(crate::config::layers::BackendConfig::new(
                Default::default(),
                Default::default(),
            ))
            .build()
            .unwrap();
        let derived = original
            .to_builder()
            .api_key("derived-key")
            .build()
            .unwrap();
        assert!(
            derived
                .create_snapshot(&cloud_snapshot_request(
                    "source-id".into(),
                    snapshot_config()
                ))
                .await
                .is_err()
        );
        assert!(derived.get_snapshot_operation("op").await.is_err());
        assert!(derived.find_snapshot_by_id("id").await.is_err());
        assert!(derived.list_all_snapshots().await.is_err());
        assert!(derived.delete_snapshot_by_id("id").await.is_err());
        let routes = tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(routes.len(), 5);
    }

    fn assert_unsupported(result: MicrosandboxResult<impl Sized>) {
        assert!(matches!(result, Err(MicrosandboxError::Unsupported { .. })));
    }

    fn snapshot_config() -> SnapshotConfig {
        SnapshotConfig {
            guest_flush: microsandbox_types::GuestFlush::Auto,
            name: "checkpoint".into(),
            dest_dir: None,
            source_sandbox: "source".into(),
            labels: Vec::new(),
            force: false,
            record_integrity: false,
            full: false,
            group: None,
        }
    }

    fn wire_manifest() -> cloud_manifest::Manifest {
        cloud_manifest::Manifest::from_bytes(br#"{"schema":1,"artifact":"snapshot","scope":"disk","created_at":"2026-05-01T12:00:00Z","parent":null,"image":{"ref":"docker.io/library/python:3.12","manifest_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"source_sandbox":"build-1","state":{"kind":"file","format":"raw","fstype":"ext4","upper":{"file":"upper.ext4","size_bytes":4096,"integrity":null}},"labels":{"owner":"alice"},"extensions":{},"requires":[]}"#).unwrap()
    }

    #[tokio::test]
    async fn cloud_projection_retains_source_digest_and_actual_backend_reference() {
        let cloud =
            crate::test_support::cloud_backend("https://example.invalid", "test-key").unwrap();
        let backend: Arc<dyn Context> = Arc::new(cloud);
        let wire = wire_manifest();
        let source_bytes = wire.to_canonical_bytes().unwrap();
        let digest = wire.digest().unwrap();
        let projected = project_cloud_descriptor(&wire, &digest).unwrap();
        for location in [
            CloudSnapshotLocation::Managed {
                id: "managed-resource-id".into(),
            },
            CloudSnapshotLocation::HostVolume {
                path: "snapshots/base".into(),
            },
        ] {
            let reference = reference_from_cloud_location(location.clone());
            let details = CloudSnapshotDetails {
                name: "base".into(),
                location,
                sandbox_id: None,
                digest: digest.clone(),
                size_bytes: 4096,
                labels: wire.labels.clone(),
                created_at: chrono::DateTime::parse_from_rfc3339(&wire.created_at)
                    .unwrap()
                    .with_timezone(&chrono::Utc),
                manifest: wire.clone(),
            };
            let snapshot = snapshot_from_cloud(
                backend.clone(),
                CloudSnapshot::Disk {
                    snapshot: details.clone(),
                },
            )
            .unwrap();
            assert_eq!(snapshot.reference(), reference);
            assert_eq!(snapshot.digest(), digest);
            assert_eq!(snapshot.loaded_manifest().unwrap(), &projected);
            assert_eq!(
                snapshot.id(),
                microsandbox_types::snapshot::legacy::snapshot_id(&digest)
                    .unwrap()
                    .as_str()
            );
            assert_ne!(
                snapshot.loaded_manifest().unwrap().digest().unwrap(),
                digest
            );
            let handle = snapshot_from_cloud(
                backend.clone(),
                CloudSnapshot::Disk {
                    snapshot: details.clone(),
                },
            )
            .unwrap();
            assert_eq!(handle.reference(), reference);
            assert_eq!(handle.id(), snapshot.id());
            if matches!(reference, SnapshotReference::Path(_)) {
                let result = handle
                    .spawn_sandbox_with(|_| panic!("mutable path reached launch configuration"))
                    .await;
                assert!(matches!(result, Err(MicrosandboxError::Unsupported { .. })));
                // The progress entry point must preserve the same exact-source guard
                // in remote-only builds before invoking user configuration or I/O.
                let result = handle
                    .spawn_sandbox_with_progress_with(|_| {
                        panic!("mutable path reached progress launch configuration")
                    })
                    .await;
                assert!(matches!(result, Err(MicrosandboxError::Unsupported { .. })));
            }
            assert_eq!(handle.digest(), digest);
            if matches!(reference, SnapshotReference::Path(_)) {
                for force in [false, true] {
                    // The invalid endpoint proves refusal happens before any provider I/O.
                    assert!(matches!(
                        snapshot.destroy(force).await,
                        Err(MicrosandboxError::Unsupported { .. })
                    ));
                    assert!(matches!(
                        handle.destroy(force).await,
                        Err(MicrosandboxError::Unsupported { .. })
                    ));
                }
            }
            // A read-side SDK projection must never mutate the DTO used on the wire.
            assert_eq!(details.manifest.to_canonical_bytes().unwrap(), source_bytes);
            assert!(snapshot.path().is_err());
        }
    }

    #[test]
    fn cloud_projection_rejects_a_mismatched_wire_digest() {
        let wire = wire_manifest();
        assert!(project_cloud_descriptor(&wire, &format!("sha256:{}", "0".repeat(64))).is_err());
    }

    #[tokio::test]
    async fn full_capture_and_local_group_requests_reject_before_network_access() {
        let cloud =
            crate::test_support::cloud_backend("https://example.invalid", "test-key").unwrap();
        let backend: Arc<dyn Context> = Arc::new(cloud.clone());
        for policy in [
            microsandbox_types::GuestFlush::Required,
            microsandbox_types::GuestFlush::Skip,
        ] {
            let mut config = snapshot_config();
            config.guest_flush = policy;
            assert_unsupported(SnapshotOps::create(&cloud, backend.clone(), config).await);
        }
        let mut full = snapshot_config();
        full.full = true;
        assert_unsupported(SnapshotOps::create(&cloud, backend.clone(), full).await);
        let mut grouped = snapshot_config();
        grouped.group = Some("local-group".into());
        assert_unsupported(SnapshotOps::create(&cloud, backend, grouped).await);
    }

    #[test]
    fn cloud_snapshot_request_is_disk_kind() {
        let disk = cloud_snapshot_request("sandbox-id".into(), snapshot_config());
        assert_eq!(disk.kind(), CloudSnapshotKind::Disk);
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
        let cloud =
            crate::test_support::cloud_backend("https://example.invalid", "test-key").unwrap();
        let backend: Arc<dyn Context> = Arc::new(cloud.clone());

        assert_unsupported(SnapshotOps::path(
            &cloud,
            &SnapshotReference::path("snapshots/base"),
        ));

        assert_unsupported(
            SnapshotOps::list_dir(&cloud, backend.clone(), PathBuf::from("snapshots")).await,
        );
        assert_unsupported(SnapshotOps::reindex(&cloud, None).await);
        assert_unsupported(
            SnapshotOps::save(
                &cloud,
                SnapshotReference::id("snapshot-id"),
                Path::new("snapshot.tar.zst"),
                SaveOpts::default(),
            )
            .await,
        );
        assert_unsupported(
            SnapshotOps::load(&cloud, backend, Path::new("snapshot.tar.zst"), None).await,
        );
    }

    #[tokio::test]
    async fn destroy_managed_snapshot_addresses_only_captured_id() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let context: Arc<dyn Context> = Arc::new(
            crate::test_support::cloud_backend(
                format!("http://{}", listener.local_addr().unwrap()),
                "test-key",
            )
            .unwrap(),
        );
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            let mut request = String::new();
            stream.read_line(&mut request).await.unwrap();
            assert_eq!(request, "DELETE /v1/snapshots/captured-id HTTP/1.1\r\n");
            loop {
                let mut line = String::new();
                stream.read_line(&mut line).await.unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }
            stream
                .get_mut()
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });
        context
            .snapshot_ops()
            .destroy(
                context.clone(),
                SnapshotReference::id("captured-id"),
                "captured-digest",
                false,
            )
            .await
            .unwrap();
        server.await.unwrap();
    }
}

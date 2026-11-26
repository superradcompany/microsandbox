//! Fail-closed backend used when ambient backend configuration is invalid.

use crate::context::sandbox::SandboxRecordPage;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use futures::stream;
use microsandbox_types::{CloudCreateServiceRequest, CloudUpdateServiceRequest};

use super::sandbox::{LogStream, MetricsStream};
use super::{Context, ContextKind, SandboxOps, ServiceOps, SnapshotOps, VolumeOps};
use crate::logs::{BootError, LogEntry, LogOptions, LogStreamOptions};
use crate::sandbox::metrics::SandboxMetrics;
use crate::sandbox::{Sandbox, SandboxConfig, SandboxListBuilder, SandboxRecord};
use crate::service::{Service, ServiceListBuilder, ServicePage};
use crate::snapshot::{
    Checkpoint as Snapshot, HeadUpdate, Manifest, SaveOpts, SnapshotConfig, SnapshotId,
    SnapshotReference, SnapshotVerifyReport,
};
use crate::volume::{Volume, VolumeConfig, VolumeFsReadStream, VolumeFsWriteSink};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Context sentinel that preserves a configuration error instead of silently
/// running local workloads after explicit Cloud selection fails.
#[derive(Clone)]
pub(crate) struct ConfigurationErrorBackend {
    message: String,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ConfigurationErrorBackend {
    /// Preserve the resolver error text for every subsequent operation.
    pub(crate) fn new(error: MicrosandboxError) -> Self {
        let message = match error {
            MicrosandboxError::InvalidConfig(message) => message,
            error => error.to_string(),
        };
        Self { message }
    }

    /// Build a fresh owned error because `MicrosandboxError` contains source
    /// errors that cannot be cloned safely across concurrent SDK calls.
    fn error(&self) -> MicrosandboxError {
        MicrosandboxError::InvalidConfig(self.message.clone())
    }

    fn fail<T>(&self) -> BoxFuture<'static, MicrosandboxResult<T>>
    where
        T: Send + 'static,
    {
        let error = self.error();
        Box::pin(async move { Err(error) })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Context for ConfigurationErrorBackend {
    fn clone_shared(&self) -> Arc<dyn Context> {
        Arc::new(self.clone())
    }

    fn kind(&self) -> ContextKind {
        // Resolver failures must never enter local-only branches. Cloud is the
        // safe intent marker until ContextKind grows a configuration-error
        // variant in a future breaking release.
        ContextKind::Remote
    }

    fn info(&self) -> MicrosandboxResult<super::ContextInfo> {
        Err(self.error())
    }

    fn sandbox_ops(&self) -> &dyn SandboxOps {
        self
    }

    fn volume_ops(&self) -> &dyn VolumeOps {
        self
    }

    fn snapshot_ops(&self) -> &dyn SnapshotOps {
        self
    }

    fn service_ops(&self) -> &dyn ServiceOps {
        self
    }

    fn dial_agent<'a>(
        &'a self,
        _name: &'a str,
        _timeout: Duration,
    ) -> BoxFuture<'a, MicrosandboxResult<crate::agent::AgentClient>> {
        self.fail()
    }
}

impl SandboxOps for ConfigurationErrorBackend {
    fn create<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _config: SandboxConfig,
        _start: bool,
    ) -> BoxFuture<'a, MicrosandboxResult<Sandbox>> {
        self.fail()
    }

    fn create_detached<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _config: SandboxConfig,
    ) -> BoxFuture<'a, MicrosandboxResult<Sandbox>> {
        self.fail()
    }

    fn start<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Sandbox>> {
        self.fail()
    }

    fn start_detached<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Sandbox>> {
        self.fail()
    }

    fn get<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<SandboxRecord>> {
        self.fail()
    }

    fn list<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _query: SandboxListBuilder,
    ) -> BoxFuture<'a, MicrosandboxResult<SandboxRecordPage>> {
        self.fail()
    }

    fn remove<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        self.fail()
    }

    fn stop<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        self.fail()
    }

    fn kill<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        self.fail()
    }

    fn drain<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        self.fail()
    }

    fn boot_error<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Option<BootError>>> {
        self.fail()
    }

    fn logs<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _name: &'a str,
        _opts: &'a LogOptions,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<LogEntry>>> {
        self.fail()
    }

    fn log_stream<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _name: &'a str,
        _opts: &'a LogStreamOptions,
    ) -> BoxFuture<'a, MicrosandboxResult<LogStream>> {
        self.fail()
    }

    fn follow_logs<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _name: &'a str,
        _opts: &'a LogOptions,
    ) -> BoxFuture<'a, MicrosandboxResult<LogStream>> {
        self.fail()
    }

    fn metrics<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _name: &'a str,
        _config: &'a SandboxConfig,
    ) -> BoxFuture<'a, MicrosandboxResult<SandboxMetrics>> {
        self.fail()
    }

    fn metrics_stream(
        &self,
        _backend: Arc<dyn Context>,
        _name: String,
        _config: SandboxConfig,
        _interval: Duration,
    ) -> MetricsStream {
        let error = self.error();
        Box::pin(stream::once(async move { Err(error) }))
    }
}

impl SnapshotOps for ConfigurationErrorBackend {
    fn group_head<'a>(
        &'a self,
        _group: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Option<SnapshotId>>> {
        self.fail()
    }

    fn set_group_head<'a>(
        &'a self,
        _group: &'a str,
        _id: &'a SnapshotId,
    ) -> BoxFuture<'a, MicrosandboxResult<HeadUpdate>> {
        self.fail()
    }

    fn create<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _config: SnapshotConfig,
    ) -> BoxFuture<'a, MicrosandboxResult<Snapshot>> {
        self.fail()
    }

    fn open<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _reference: SnapshotReference,
    ) -> BoxFuture<'a, MicrosandboxResult<Snapshot>> {
        self.fail()
    }

    fn get<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _identifier: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Snapshot>> {
        self.fail()
    }

    fn list(&self, _backend: Arc<dyn Context>) -> BoxFuture<'_, MicrosandboxResult<Vec<Snapshot>>> {
        self.fail()
    }

    fn remove<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _reference: SnapshotReference,
        _force: bool,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        self.fail()
    }

    fn destroy<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _reference: SnapshotReference,
        _expected_digest: &'a str,
        _force: bool,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        self.fail()
    }

    fn prepare_restore<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _config: &'a mut SandboxConfig,
        _reference: SnapshotReference,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        self.fail()
    }

    fn path<'a>(&self, _reference: &'a SnapshotReference) -> MicrosandboxResult<&'a Path> {
        Err(self.error())
    }

    fn verify<'a>(
        &'a self,
        _snapshot: &'a Snapshot,
    ) -> BoxFuture<'a, MicrosandboxResult<SnapshotVerifyReport>> {
        self.fail()
    }

    fn copy<'a>(
        &'a self,
        _snapshot: &'a Snapshot,
        _output_archive_path: &'a Path,
        _labels: std::collections::BTreeMap<String, String>,
        _record_integrity: bool,
    ) -> BoxFuture<'a, MicrosandboxResult<Manifest>> {
        self.fail()
    }

    fn list_dir(
        &self,
        _backend: Arc<dyn Context>,
        _dir: PathBuf,
    ) -> BoxFuture<'_, MicrosandboxResult<Vec<Snapshot>>> {
        self.fail()
    }

    fn reindex(&self, _dir: Option<PathBuf>) -> BoxFuture<'_, MicrosandboxResult<usize>> {
        self.fail()
    }

    fn save<'a>(
        &'a self,
        _reference: SnapshotReference,
        _out: &'a Path,
        _opts: SaveOpts,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        self.fail()
    }

    fn load<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _archive: &'a Path,
        _dest: Option<&'a Path>,
    ) -> BoxFuture<'a, MicrosandboxResult<Snapshot>> {
        self.fail()
    }
}

impl VolumeOps for ConfigurationErrorBackend {
    fn create<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _config: VolumeConfig,
    ) -> BoxFuture<'a, MicrosandboxResult<Volume>> {
        self.fail()
    }

    fn get<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Volume>> {
        self.fail()
    }

    fn get_default(&self, _backend: Arc<dyn Context>) -> BoxFuture<'_, MicrosandboxResult<Volume>> {
        self.fail()
    }

    fn list<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<Volume>>> {
        self.fail()
    }

    fn remove<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        self.fail()
    }

    fn destroy<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _target: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        self.fail()
    }

    fn fs_read<'a>(
        &'a self,
        _name: &'a str,
        _path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<bytes::Bytes>> {
        self.fail()
    }

    fn fs_read_to_string<'a>(
        &'a self,
        _name: &'a str,
        _path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<String>> {
        self.fail()
    }

    fn fs_write<'a>(
        &'a self,
        _name: &'a str,
        _path: &'a str,
        _data: Vec<u8>,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        self.fail()
    }

    fn fs_list<'a>(
        &'a self,
        _name: &'a str,
        _path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<crate::sandbox::fs::FsEntry>>> {
        self.fail()
    }

    fn fs_stat<'a>(
        &'a self,
        _name: &'a str,
        _path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<crate::sandbox::fs::FsMetadata>> {
        self.fail()
    }

    fn fs_mkdir<'a>(
        &'a self,
        _name: &'a str,
        _path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        self.fail()
    }

    fn fs_remove<'a>(
        &'a self,
        _name: &'a str,
        _path: &'a str,
        _recursive: bool,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        self.fail()
    }

    fn fs_copy<'a>(
        &'a self,
        _name: &'a str,
        _from: &'a str,
        _to: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        self.fail()
    }

    fn fs_rename<'a>(
        &'a self,
        _name: &'a str,
        _from: &'a str,
        _to: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        self.fail()
    }

    fn fs_exists<'a>(
        &'a self,
        _name: &'a str,
        _path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<bool>> {
        self.fail()
    }

    fn fs_read_stream<'a>(
        &'a self,
        _name: &'a str,
        _path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<VolumeFsReadStream>> {
        self.fail()
    }

    fn fs_write_stream<'a>(
        &'a self,
        _name: &'a str,
        _path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<VolumeFsWriteSink>> {
        self.fail()
    }
}

impl ServiceOps for ConfigurationErrorBackend {
    fn create<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _request: CloudCreateServiceRequest,
    ) -> BoxFuture<'a, MicrosandboxResult<Service>> {
        self.fail()
    }

    fn get<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _slug: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Service>> {
        self.fail()
    }

    fn list<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _query: ServiceListBuilder,
    ) -> BoxFuture<'a, MicrosandboxResult<ServicePage>> {
        self.fail()
    }

    fn update<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _slug: &'a str,
        _request: CloudUpdateServiceRequest,
    ) -> BoxFuture<'a, MicrosandboxResult<Service>> {
        self.fail()
    }

    fn enable<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _slug: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Service>> {
        self.fail()
    }

    fn disable<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _slug: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Service>> {
        self.fail()
    }

    fn remove<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _slug: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        self.fail()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sandbox_and_volume_calls_preserve_configuration_error() {
        let backend: Arc<dyn Context> = Arc::new(ConfigurationErrorBackend::new(
            MicrosandboxError::InvalidConfig("MSB_BACKEND=cloud requires a key".into()),
        ));

        let sandbox_result = backend
            .sandbox_ops()
            .list(backend.clone(), SandboxListBuilder::default())
            .await;
        let sandbox_error = match sandbox_result {
            Ok(_) => panic!("misconfigured backend unexpectedly listed sandboxes"),
            Err(error) => error,
        };
        let volume_error = backend
            .volume_ops()
            .list(backend.clone())
            .await
            .unwrap_err();
        let default_volume_error = backend
            .volume_ops()
            .get_default(backend.clone())
            .await
            .unwrap_err();

        assert!(sandbox_error.to_string().contains("MSB_BACKEND=cloud"));
        assert!(volume_error.to_string().contains("MSB_BACKEND=cloud"));
        assert!(
            default_volume_error
                .to_string()
                .contains("MSB_BACKEND=cloud")
        );
        #[cfg(feature = "local")]
        assert!(backend.as_local().is_none());
    }
}

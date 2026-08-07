//! Fail-closed backend used when ambient backend configuration is invalid.

use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use futures::stream;

use super::sandbox::{LogStream, MetricsStream};
use super::{Backend, BackendKind, SandboxBackend, VolumeBackend};
use crate::logs::{LogEntry, LogOptions, LogStreamOptions};
use crate::sandbox::metrics::SandboxMetrics;
use crate::sandbox::{Sandbox, SandboxConfig, SandboxHandle, SandboxListBuilder, SandboxPage};
use crate::volume::{Volume, VolumeConfig, VolumeFsReadStream, VolumeFsWriteSink, VolumeHandle};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Backend sentinel that preserves a configuration error instead of silently
/// running local workloads after explicit Cloud selection fails.
pub(super) struct ConfigurationErrorBackend {
    message: String,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ConfigurationErrorBackend {
    /// Preserve the resolver error text for every subsequent operation.
    pub(super) fn new(error: MicrosandboxError) -> Self {
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

impl Backend for ConfigurationErrorBackend {
    fn kind(&self) -> BackendKind {
        // Resolver failures must never enter local-only branches. Cloud is the
        // safe intent marker until BackendKind grows a configuration-error
        // variant in a future breaking release.
        BackendKind::Cloud
    }

    fn sandboxes(&self) -> &dyn SandboxBackend {
        self
    }

    fn volumes(&self) -> &dyn VolumeBackend {
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

impl SandboxBackend for ConfigurationErrorBackend {
    fn create<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _config: SandboxConfig,
        _start: bool,
    ) -> BoxFuture<'a, MicrosandboxResult<Sandbox>> {
        self.fail()
    }

    fn create_detached<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _config: SandboxConfig,
    ) -> BoxFuture<'a, MicrosandboxResult<Sandbox>> {
        self.fail()
    }

    fn start<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Sandbox>> {
        self.fail()
    }

    fn start_detached<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Sandbox>> {
        self.fail()
    }

    fn get<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<SandboxHandle>> {
        self.fail()
    }

    fn list<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _query: SandboxListBuilder,
    ) -> BoxFuture<'a, MicrosandboxResult<SandboxPage>> {
        self.fail()
    }

    fn remove<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        self.fail()
    }

    fn stop<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        self.fail()
    }

    fn kill<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        self.fail()
    }

    fn drain<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        self.fail()
    }

    fn logs<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _name: &'a str,
        _opts: &'a LogOptions,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<LogEntry>>> {
        self.fail()
    }

    fn log_stream<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _name: &'a str,
        _opts: &'a LogStreamOptions,
    ) -> BoxFuture<'a, MicrosandboxResult<LogStream>> {
        self.fail()
    }

    fn metrics<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _name: &'a str,
        _config: &'a SandboxConfig,
    ) -> BoxFuture<'a, MicrosandboxResult<SandboxMetrics>> {
        self.fail()
    }

    fn metrics_stream(
        &self,
        _backend: Arc<dyn Backend>,
        _name: String,
        _config: SandboxConfig,
        _interval: Duration,
    ) -> MetricsStream {
        let error = self.error();
        Box::pin(stream::once(async move { Err(error) }))
    }
}

impl VolumeBackend for ConfigurationErrorBackend {
    fn create<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _config: VolumeConfig,
    ) -> BoxFuture<'a, MicrosandboxResult<Volume>> {
        self.fail()
    }

    fn get<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<VolumeHandle>> {
        self.fail()
    }

    fn get_default(
        &self,
        _backend: Arc<dyn Backend>,
    ) -> BoxFuture<'_, MicrosandboxResult<VolumeHandle>> {
        self.fail()
    }

    fn list<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<VolumeHandle>>> {
        self.fail()
    }

    fn remove<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _name: &'a str,
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

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sandbox_and_volume_calls_preserve_configuration_error() {
        let backend: Arc<dyn Backend> = Arc::new(ConfigurationErrorBackend::new(
            MicrosandboxError::InvalidConfig("MSB_BACKEND=cloud requires a key".into()),
        ));

        let sandbox_result = backend
            .sandboxes()
            .list(backend.clone(), SandboxListBuilder::default())
            .await;
        let sandbox_error = match sandbox_result {
            Ok(_) => panic!("misconfigured backend unexpectedly listed sandboxes"),
            Err(error) => error,
        };
        let volume_error = backend.volumes().list(backend.clone()).await.unwrap_err();
        let default_volume_error = backend
            .volumes()
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
        assert!(backend.as_local().is_none());
    }
}

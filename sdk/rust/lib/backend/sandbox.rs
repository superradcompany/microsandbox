//! Sandbox lifecycle backend trait.
//!
//! Per the SDK local-cloud parity plan (D6.4): `Sandbox` and `SandboxHandle`
//! stay single types with no variants. They hold `Arc<dyn Backend>` plus a
//! backend-private `*Inner` enum that the outer types never expose directly.
//! The trait returns the outer types — the local/cloud `Inner` variants are
//! constructed inside each backend's trait impl and wrapped with the
//! `Arc<dyn Backend>` the caller passes in.

use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures::Stream;
use futures::future::BoxFuture;

use super::{Backend, CloudBackend, LocalBackend};
use crate::agent::AgentClient;
use crate::logs::{LogEntry, LogOptions, LogStreamOptions};
use crate::runtime::{ProcessHandle, SpawnMode};
use crate::sandbox::exec::{ExecHandle, ExecOptions, ExecOutput};
use crate::sandbox::fs::{FsEntry, FsMetadata, FsReadStream, FsWriteSink};
use crate::sandbox::metrics::SandboxMetrics;
use crate::sandbox::{
    OciRootfsSource, RootfsSource, Sandbox, SandboxConfig, SandboxHandle, SandboxStatus,
};
use crate::{MicrosandboxError, MicrosandboxResult};
use microsandbox_types::{
    CloudCreateSandboxRequest, CloudSandbox, CloudSandboxStatus, EnvVar, SandboxPolicy,
    SandboxResources, SandboxRuntimeOptions, SandboxSpec,
};

//--------------------------------------------------------------------------------------------------
// Type Aliases
//--------------------------------------------------------------------------------------------------

/// Boxed stream of metrics samples returned by [`SandboxBackend::metrics_stream`].
pub type MetricsStream =
    Pin<Box<dyn Stream<Item = MicrosandboxResult<SandboxMetrics>> + Send + 'static>>;

/// Boxed stream of log entries returned by [`SandboxBackend::log_stream`].
pub type LogStream = Pin<Box<dyn Stream<Item = MicrosandboxResult<LogEntry>> + Send + 'static>>;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Backend-private state behind [`Sandbox`].
///
/// Users never see this enum directly — they get the outer `Sandbox` and reach
/// variant-specific data through the [`Sandbox::local`](crate::sandbox::Sandbox::local)
/// / [`Sandbox::cloud`](crate::sandbox::Sandbox::cloud) accessors.
pub enum SandboxInner {
    /// Local libkrun-backed sandbox state.
    Local(SandboxLocalState),
    /// Cloud msb-cloud-backed sandbox state.
    Cloud(SandboxCloudState),
}

/// Local libkrun-backed sandbox state held inside [`SandboxInner::Local`].
pub struct SandboxLocalState {
    /// SQLite row id for this sandbox.
    pub db_id: i32,
    /// Owned libkrun process handle, when this `Sandbox` owns the lifecycle.
    pub handle: Option<Arc<tokio::sync::Mutex<ProcessHandle>>>,
    /// UDS connection to the in-VM agentd relay.
    pub client: Arc<AgentClient>,
}

/// Cloud msb-cloud-backed sandbox state held inside [`SandboxInner::Cloud`].
pub struct SandboxCloudState {
    /// Server-side UUID (kept as a string to match the cloud wire format).
    pub id: String,
    /// Owning org's UUID.
    pub org_id: String,
    /// Creation timestamp returned by msb-cloud.
    pub created_at: DateTime<Utc>,
}

/// Backend-private state behind [`SandboxHandle`] — the lightweight DB-row view.
pub enum SandboxHandleInner {
    /// Local persisted sandbox handle.
    Local(SandboxHandleLocalState),
    /// Cloud msb-cloud sandbox handle.
    Cloud(SandboxHandleCloudState),
}

/// Local handle state. Snapshot of the database row + active PID, if any.
pub struct SandboxHandleLocalState {
    /// SQLite row id for this sandbox.
    pub db_id: i32,
    /// Sandbox lifecycle status at handle-creation time.
    pub status: SandboxStatus,
    /// Serialized `SandboxConfig` as stored in the database.
    pub config_json: String,
    /// When this sandbox was first created, if recorded.
    pub created_at: Option<DateTime<Utc>>,
    /// When this sandbox's database record was last modified.
    pub updated_at: Option<DateTime<Utc>>,
    /// Active sandbox process PID, if any.
    pub pid: Option<i32>,
}

/// Cloud handle state. Captures the snapshot msb-cloud returned at fetch time.
pub struct SandboxHandleCloudState {
    /// Server-side UUID.
    pub id: String,
    /// Owning org's UUID.
    pub org_id: String,
    /// Lifecycle status mapped from msb-cloud's [`CloudSandboxStatus`].
    pub status: SandboxStatus,
    /// Serialized [`CloudCreateSandboxRequest`] returned by msb-cloud.
    pub config_json: String,
    /// Creation timestamp returned by msb-cloud.
    pub created_at: Option<DateTime<Utc>>,
    /// Last start timestamp, when known.
    pub started_at: Option<DateTime<Utc>>,
    /// Last stop timestamp, when known.
    pub stopped_at: Option<DateTime<Utc>>,
    /// Last failure reason, when any.
    pub last_error: Option<String>,
}

/// Paginated sandbox list result returned by [`SandboxBackend::list`].
pub struct SandboxList {
    /// Returned sandbox records.
    pub sandboxes: Vec<SandboxHandle>,
    /// Cursor for the next page, when one exists.
    pub next_cursor: Option<String>,
}

/// Resource-specific backend for sandbox lifecycle operations.
///
/// Trait methods take the [`Arc<dyn Backend>`] that they should wrap any
/// returned [`Sandbox`] / [`SandboxHandle`] with. Callers (e.g.
/// `Sandbox::create`) resolve the backend via
/// [`default_backend`](super::default_backend) and forward it through.
pub trait SandboxBackend: Send + Sync {
    /// Create a sandbox. The returned outer [`Sandbox`] carries the supplied
    /// `backend` Arc and the variant-specific state inside `SandboxInner`.
    ///
    /// `start` controls whether the sandbox is booted as part of create.
    /// **Cloud honours `start`** (forwards it as `?start=true|false` on the
    /// create request). **Local always boots immediately** — the local impl
    /// ignores the flag, because libkrun has no equivalent "create-without-
    /// start" state. This asymmetry is intentional per the SDK parity plan
    /// (D6.4); callers that need a stopped local sandbox should create then
    /// `stop()` it explicitly.
    fn create<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        config: SandboxConfig,
        start: bool,
    ) -> BoxFuture<'a, MicrosandboxResult<Sandbox>>;

    /// Create a sandbox that must survive after the creating process exits.
    fn create_detached<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        config: SandboxConfig,
    ) -> BoxFuture<'a, MicrosandboxResult<Sandbox>>;

    /// Start a stopped sandbox by name.
    fn start<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Sandbox>>;

    /// Start a stopped sandbox by name in detached mode.
    fn start_detached<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Sandbox>>;

    /// Get a sandbox handle by name.
    fn get<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<SandboxHandle>>;

    /// List sandboxes. Local ignores pagination; cloud passes it through.
    fn list<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        cursor: Option<&'a str>,
        limit: Option<u32>,
    ) -> BoxFuture<'a, MicrosandboxResult<SandboxList>>;

    /// Remove/destroy a sandbox by name.
    fn remove<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>>;

    /// Stop a running sandbox by name (graceful).
    fn stop<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>>;

    /// Kill a running sandbox by name (SIGKILL).
    fn kill<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>>;

    /// Trigger a graceful drain on a sandbox by name.
    fn drain<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>>;

    // ============================================================
    // Exec
    // ============================================================

    /// Execute a command inside the named sandbox and wait for it to complete.
    fn exec<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
        config: &'a SandboxConfig,
        cmd: String,
        opts: ExecOptions,
    ) -> BoxFuture<'a, MicrosandboxResult<ExecOutput>>;

    /// Execute a command and return a streaming [`ExecHandle`].
    fn exec_stream<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
        config: &'a SandboxConfig,
        cmd: String,
        opts: ExecOptions,
    ) -> BoxFuture<'a, MicrosandboxResult<ExecHandle>>;

    /// Attach the host terminal to a PTY session in the named sandbox.
    ///
    /// Returns the exit code. Local routes through libkrun + agentd; cloud
    /// returns [`MicrosandboxError::Unsupported`] until cloud attach lands.
    fn attach<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
        config: &'a SandboxConfig,
        cmd: String,
        opts: crate::sandbox::AttachOptionsBuilder,
    ) -> BoxFuture<'a, MicrosandboxResult<i32>>;

    // ============================================================
    // Logs / metrics
    // ============================================================

    /// Read captured output for the named sandbox.
    fn logs<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
        opts: &'a LogOptions,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<LogEntry>>>;

    /// Stream captured output for the named sandbox.
    fn log_stream<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
        opts: &'a LogStreamOptions,
    ) -> BoxFuture<'a, MicrosandboxResult<LogStream>>;

    /// Latest metrics sample for the named sandbox.
    fn metrics<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
        config: &'a SandboxConfig,
    ) -> BoxFuture<'a, MicrosandboxResult<SandboxMetrics>>;

    /// Streaming metrics samples at `interval`. Local opens a DB poll loop;
    /// cloud returns a stream that yields a single [`MicrosandboxError::Unsupported`].
    fn metrics_stream(
        &self,
        backend: Arc<dyn Backend>,
        name: String,
        config: SandboxConfig,
        interval: Duration,
    ) -> MetricsStream;

    // ============================================================
    // Guest FS (sandbox.fs() surface)
    // ============================================================

    /// Read an entire guest file into memory.
    fn fs_read<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Bytes>>;

    /// Stream a guest file. Returns a [`FsReadStream`] yielding chunks.
    fn fs_read_stream<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<FsReadStream>>;

    /// Write `data` to a guest file (overwriting if it exists).
    fn fs_write<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
        path: &'a str,
        data: Vec<u8>,
    ) -> BoxFuture<'a, MicrosandboxResult<()>>;

    /// Open a streaming writer for a guest file.
    fn fs_write_stream<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<FsWriteSink>>;

    /// List immediate children of a guest directory.
    fn fs_list<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<FsEntry>>>;

    /// Get file/directory metadata.
    fn fs_stat<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<FsMetadata>>;

    /// Create a directory (and parents).
    fn fs_mkdir<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>>;

    /// Remove a file or (when `recursive`) directory.
    fn fs_remove<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
        path: &'a str,
        recursive: bool,
    ) -> BoxFuture<'a, MicrosandboxResult<()>>;

    /// Copy a guest file from `from` to `to`.
    fn fs_copy<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
        from: &'a str,
        to: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>>;

    /// Rename/move a guest file or directory.
    fn fs_rename<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
        from: &'a str,
        to: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>>;

    /// Check whether a guest path exists.
    fn fs_exists<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<bool>>;

    /// Copy a host file into the guest sandbox.
    fn fs_copy_from_host<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
        host: &'a Path,
        guest: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>>;

    /// Copy a guest file out to the host.
    fn fs_copy_to_host<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
        guest: &'a str,
        host: &'a Path,
    ) -> BoxFuture<'a, MicrosandboxResult<()>>;
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations: LocalBackend
//--------------------------------------------------------------------------------------------------

impl SandboxBackend for LocalBackend {
    fn create<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        config: SandboxConfig,
        _start: bool,
    ) -> BoxFuture<'a, MicrosandboxResult<Sandbox>> {
        Box::pin(async move {
            // Local backend always boots immediately — `start` only differs
            // for cloud where create-without-start is a distinct state.
            crate::sandbox::create_local(backend, config, SpawnMode::Attached, None).await
        })
    }

    fn create_detached<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        config: SandboxConfig,
    ) -> BoxFuture<'a, MicrosandboxResult<Sandbox>> {
        Box::pin(async move {
            crate::sandbox::create_local(backend, config, SpawnMode::Detached, None).await
        })
    }

    fn start<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Sandbox>> {
        Box::pin(
            async move { crate::sandbox::start_local(backend, name, SpawnMode::Attached).await },
        )
    }

    fn start_detached<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Sandbox>> {
        Box::pin(
            async move { crate::sandbox::start_local(backend, name, SpawnMode::Detached).await },
        )
    }

    fn get<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<SandboxHandle>> {
        Box::pin(async move {
            let (model, pid) = crate::sandbox::get_local_handle_state(self, name).await?;
            Ok(SandboxHandle::from_local_model(backend, model, pid))
        })
    }

    fn list<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        _cursor: Option<&'a str>,
        _limit: Option<u32>,
    ) -> BoxFuture<'a, MicrosandboxResult<SandboxList>> {
        Box::pin(async move {
            let rows = crate::sandbox::list_local_handle_state(self).await?;
            let sandboxes = rows
                .into_iter()
                .map(|(model, pid)| SandboxHandle::from_local_model(backend.clone(), model, pid))
                .collect();
            Ok(SandboxList {
                sandboxes,
                next_cursor: None,
            })
        })
    }

    fn remove<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { crate::sandbox::remove_local(backend, name).await })
    }

    fn stop<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { crate::sandbox::stop_local(backend, name).await })
    }

    fn kill<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { crate::sandbox::kill_local(backend, name).await })
    }

    fn drain<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { crate::sandbox::drain_local(backend, name).await })
    }

    fn exec<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        name: &'a str,
        config: &'a SandboxConfig,
        cmd: String,
        opts: ExecOptions,
    ) -> BoxFuture<'a, MicrosandboxResult<ExecOutput>> {
        Box::pin(
            async move { crate::sandbox::exec::local::exec(self, name, config, cmd, opts).await },
        )
    }

    fn exec_stream<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        name: &'a str,
        config: &'a SandboxConfig,
        cmd: String,
        opts: ExecOptions,
    ) -> BoxFuture<'a, MicrosandboxResult<ExecHandle>> {
        Box::pin(async move {
            crate::sandbox::exec::local::exec_stream(self, name, config, cmd, opts).await
        })
    }

    fn attach<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        name: &'a str,
        config: &'a SandboxConfig,
        cmd: String,
        opts: crate::sandbox::AttachOptionsBuilder,
    ) -> BoxFuture<'a, MicrosandboxResult<i32>> {
        Box::pin(async move {
            crate::sandbox::attach::local::attach(self, name, config, cmd, opts).await
        })
    }

    fn logs<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        name: &'a str,
        opts: &'a LogOptions,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<LogEntry>>> {
        Box::pin(async move { crate::logs::read_logs_local(self, name, opts).await })
    }

    fn log_stream<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        name: &'a str,
        opts: &'a LogStreamOptions,
    ) -> BoxFuture<'a, MicrosandboxResult<LogStream>> {
        Box::pin(async move {
            let stream = crate::logs::log_stream_local(self, name, opts).await?;
            Ok(Box::pin(stream) as LogStream)
        })
    }

    fn metrics<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        name: &'a str,
        config: &'a SandboxConfig,
    ) -> BoxFuture<'a, MicrosandboxResult<SandboxMetrics>> {
        Box::pin(async move { crate::sandbox::metrics::local_metrics(self, name, config).await })
    }

    fn metrics_stream(
        &self,
        backend: Arc<dyn Backend>,
        name: String,
        config: SandboxConfig,
        interval: Duration,
    ) -> MetricsStream {
        crate::sandbox::metrics::local_metrics_stream(backend, name, config, interval)
    }

    fn fs_read<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Bytes>> {
        Box::pin(async move { crate::sandbox::fs::local::read(self, name, path).await })
    }

    fn fs_read_stream<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<FsReadStream>> {
        Box::pin(async move { crate::sandbox::fs::local::read_stream(self, name, path).await })
    }

    fn fs_write<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        name: &'a str,
        path: &'a str,
        data: Vec<u8>,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { crate::sandbox::fs::local::write(self, name, path, data).await })
    }

    fn fs_write_stream<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<FsWriteSink>> {
        Box::pin(async move { crate::sandbox::fs::local::write_stream(self, name, path).await })
    }

    fn fs_list<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<FsEntry>>> {
        Box::pin(async move { crate::sandbox::fs::local::list(self, name, path).await })
    }

    fn fs_stat<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<FsMetadata>> {
        Box::pin(async move { crate::sandbox::fs::local::stat(self, name, path).await })
    }

    fn fs_mkdir<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { crate::sandbox::fs::local::mkdir(self, name, path).await })
    }

    fn fs_remove<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        name: &'a str,
        path: &'a str,
        recursive: bool,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(
            async move { crate::sandbox::fs::local::remove(self, name, path, recursive).await },
        )
    }

    fn fs_copy<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        name: &'a str,
        from: &'a str,
        to: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { crate::sandbox::fs::local::copy(self, name, from, to).await })
    }

    fn fs_rename<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        name: &'a str,
        from: &'a str,
        to: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { crate::sandbox::fs::local::rename(self, name, from, to).await })
    }

    fn fs_exists<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<bool>> {
        Box::pin(async move { crate::sandbox::fs::local::exists(self, name, path).await })
    }

    fn fs_copy_from_host<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        name: &'a str,
        host: &'a Path,
        guest: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(
            async move { crate::sandbox::fs::local::copy_from_host(self, name, host, guest).await },
        )
    }

    fn fs_copy_to_host<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        name: &'a str,
        guest: &'a str,
        host: &'a Path,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(
            async move { crate::sandbox::fs::local::copy_to_host(self, name, guest, host).await },
        )
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations: CloudBackend
//--------------------------------------------------------------------------------------------------

impl SandboxBackend for CloudBackend {
    fn create<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        config: SandboxConfig,
        start: bool,
    ) -> BoxFuture<'a, MicrosandboxResult<Sandbox>> {
        Box::pin(async move {
            let req = cloud_create_request_from_config(config.clone())?;
            let cloud = CloudBackend::create_sandbox(self, &req, start).await?;
            Ok(Sandbox::from_cloud(backend, cloud, config))
        })
    }

    fn create_detached<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        config: SandboxConfig,
    ) -> BoxFuture<'a, MicrosandboxResult<Sandbox>> {
        // Cloud has no notion of "detached" — the sandbox lifecycle is owned
        // by msb-cloud, not by this process. Reuse the eager-start path.
        Box::pin(async move {
            let req = cloud_create_request_from_config(config.clone())?;
            let cloud = CloudBackend::create_sandbox(self, &req, true).await?;
            Ok(Sandbox::from_cloud(backend, cloud, config))
        })
    }

    fn start<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Sandbox>> {
        Box::pin(async move {
            let cloud = CloudBackend::start_sandbox(self, name).await?;
            let config = sandbox_config_from_cloud(&cloud);
            Ok(Sandbox::from_cloud(backend, cloud, config))
        })
    }

    fn start_detached<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Sandbox>> {
        // Cloud start is detached by definition — the sandbox keeps running
        // after this process exits. Same code path as `start`.
        Box::pin(async move {
            let cloud = CloudBackend::start_sandbox(self, name).await?;
            let config = sandbox_config_from_cloud(&cloud);
            Ok(Sandbox::from_cloud(backend, cloud, config))
        })
    }

    fn get<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<SandboxHandle>> {
        Box::pin(async move {
            let cloud = CloudBackend::get_sandbox(self, name).await?;
            SandboxHandle::from_cloud(backend, cloud)
        })
    }

    fn list<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        cursor: Option<&'a str>,
        limit: Option<u32>,
    ) -> BoxFuture<'a, MicrosandboxResult<SandboxList>> {
        Box::pin(async move {
            let page = CloudBackend::list_sandboxes(self, cursor, limit).await?;
            let sandboxes = page
                .data
                .into_iter()
                .map(|sb| SandboxHandle::from_cloud(backend.clone(), sb))
                .collect::<MicrosandboxResult<Vec<_>>>()?;
            Ok(SandboxList {
                sandboxes,
                next_cursor: page.next_cursor,
            })
        })
    }

    fn remove<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            CloudBackend::destroy_sandbox(self, name).await?;
            Ok(())
        })
    }

    fn stop<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            CloudBackend::stop_sandbox(self, name).await?;
            Ok(())
        })
    }

    fn kill<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            Err(unsupported(
                "cloud sandbox kill",
                "when cloud forced-stop lands",
            ))
        })
    }

    fn drain<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            Err(unsupported(
                "cloud sandbox drain",
                "when cloud graceful-drain lands",
            ))
        })
    }

    fn exec<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        name: &'a str,
        config: &'a SandboxConfig,
        cmd: String,
        opts: ExecOptions,
    ) -> BoxFuture<'a, MicrosandboxResult<ExecOutput>> {
        Box::pin(async move { CloudBackend::exec(self, name, config, cmd, opts).await })
    }

    fn exec_stream<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _name: &'a str,
        _config: &'a SandboxConfig,
        _cmd: String,
        _opts: ExecOptions,
    ) -> BoxFuture<'a, MicrosandboxResult<ExecHandle>> {
        Box::pin(async move { Err(unsupported_exec("Sandbox::exec_stream")) })
    }

    fn attach<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _name: &'a str,
        _config: &'a SandboxConfig,
        _cmd: String,
        _opts: crate::sandbox::AttachOptionsBuilder,
    ) -> BoxFuture<'a, MicrosandboxResult<i32>> {
        Box::pin(async move { Err(unsupported_exec("Sandbox::attach")) })
    }

    fn logs<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _name: &'a str,
        _opts: &'a LogOptions,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<LogEntry>>> {
        Box::pin(async move { CloudBackend::logs(self, _name, _opts).await })
    }

    fn log_stream<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        name: &'a str,
        opts: &'a LogStreamOptions,
    ) -> BoxFuture<'a, MicrosandboxResult<LogStream>> {
        Box::pin(async move { CloudBackend::log_stream(self, name, opts).await })
    }

    fn metrics<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _name: &'a str,
        _config: &'a SandboxConfig,
    ) -> BoxFuture<'a, MicrosandboxResult<SandboxMetrics>> {
        Box::pin(async move { Err(unsupported_metrics("Sandbox::metrics")) })
    }

    fn metrics_stream(
        &self,
        _backend: Arc<dyn Backend>,
        _name: String,
        _config: SandboxConfig,
        _interval: Duration,
    ) -> MetricsStream {
        Box::pin(futures::stream::once(async {
            Err(unsupported_metrics("Sandbox::metrics_stream"))
        }))
    }

    fn fs_read<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _name: &'a str,
        _path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Bytes>> {
        Box::pin(async move { Err(unsupported_fs("SandboxFs::read")) })
    }

    fn fs_read_stream<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _name: &'a str,
        _path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<FsReadStream>> {
        Box::pin(async move { Err(unsupported_fs("SandboxFs::read_stream")) })
    }

    fn fs_write<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _name: &'a str,
        _path: &'a str,
        _data: Vec<u8>,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { Err(unsupported_fs("SandboxFs::write")) })
    }

    fn fs_write_stream<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _name: &'a str,
        _path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<FsWriteSink>> {
        Box::pin(async move { Err(unsupported_fs("SandboxFs::write_stream")) })
    }

    fn fs_list<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _name: &'a str,
        _path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<FsEntry>>> {
        Box::pin(async move { Err(unsupported_fs("SandboxFs::list")) })
    }

    fn fs_stat<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _name: &'a str,
        _path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<FsMetadata>> {
        Box::pin(async move { Err(unsupported_fs("SandboxFs::stat")) })
    }

    fn fs_mkdir<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _name: &'a str,
        _path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { Err(unsupported_fs("SandboxFs::mkdir")) })
    }

    fn fs_remove<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _name: &'a str,
        _path: &'a str,
        _recursive: bool,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { Err(unsupported_fs("SandboxFs::remove")) })
    }

    fn fs_copy<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _name: &'a str,
        _from: &'a str,
        _to: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { Err(unsupported_fs("SandboxFs::copy")) })
    }

    fn fs_rename<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _name: &'a str,
        _from: &'a str,
        _to: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { Err(unsupported_fs("SandboxFs::rename")) })
    }

    fn fs_exists<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _name: &'a str,
        _path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<bool>> {
        Box::pin(async move { Err(unsupported_fs("SandboxFs::exists")) })
    }

    fn fs_copy_from_host<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _name: &'a str,
        _host: &'a Path,
        _guest: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { Err(unsupported_fs("SandboxFs::copy_from_host")) })
    }

    fn fs_copy_to_host<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _name: &'a str,
        _guest: &'a str,
        _host: &'a Path,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { Err(unsupported_fs("SandboxFs::copy_to_host")) })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Map [`CloudSandboxStatus`] to the SDK's [`SandboxStatus`] enum.
///
/// `Stopping` collapses to `Draining` (microsandbox uses `Draining` for
/// the graceful-stop state); `Failed` collapses to `Crashed`. All other
/// variants map 1:1.
pub(crate) fn cloud_status_to_sandbox_status(s: CloudSandboxStatus) -> SandboxStatus {
    match s {
        CloudSandboxStatus::Created => SandboxStatus::Created,
        CloudSandboxStatus::Starting => SandboxStatus::Starting,
        CloudSandboxStatus::Running => SandboxStatus::Running,
        CloudSandboxStatus::Stopping => SandboxStatus::Draining,
        CloudSandboxStatus::Stopped => SandboxStatus::Stopped,
        CloudSandboxStatus::Failed => SandboxStatus::Crashed,
    }
}

/// Synthesize a [`SandboxConfig`] from a [`CloudSandbox`] response. Used when
/// the SDK didn't drive the create call (e.g. `start(name)` returns a
/// `Sandbox` for a sandbox the cloud created earlier).
///
/// Maps every field that exists on the cloud wire shape
/// ([`CloudCreateSandboxRequest`]) into the shared [`SandboxSpec`]. Fields
/// with no cloud counterpart are filled from [`SandboxConfig::default()`], so
/// a caller inspecting `sb.config()` after `Sandbox::start(name)` can reason
/// about which fields are "live" vs. "synthesized stub".
fn sandbox_config_from_cloud(cloud: &CloudSandbox) -> SandboxConfig {
    let spec = SandboxSpec {
        name: cloud.config.name.clone(),
        image: RootfsSource::Oci(OciRootfsSource {
            reference: cloud.config.image.clone(),
            upper_size_mib: None,
        }),
        resources: SandboxResources {
            cpus: cloud.config.vcpus,
            memory_mib: cloud.config.memory_mib,
        },
        runtime: SandboxRuntimeOptions {
            workdir: cloud.config.workdir.clone(),
            shell: cloud.config.shell.clone(),
            scripts: cloud.config.scripts.clone().into_iter().collect(),
            entrypoint: cloud.config.entrypoint.clone(),
            hostname: cloud.config.hostname.clone(),
            user: cloud.config.user.clone(),
            log_level: cloud
                .config
                .log_level
                .as_deref()
                .and_then(|level| level.parse().ok()),
            ..Default::default()
        },
        env: cloud
            .config
            .env
            .clone()
            .into_iter()
            .map(|(key, value)| EnvVar::new(key, value))
            .collect(),
        lifecycle: SandboxPolicy {
            ephemeral: cloud.config.ephemeral,
            max_duration_secs: cloud.config.max_duration_secs,
            idle_timeout_secs: cloud.config.idle_timeout_secs,
        },
        ..Default::default()
    };

    SandboxConfig {
        spec,
        ..Default::default()
    }
}

pub(super) fn cloud_create_request_from_config(
    config: SandboxConfig,
) -> MicrosandboxResult<CloudCreateSandboxRequest> {
    reject_cloud_deferred(
        !config.spec.mounts.is_empty(),
        "mounts",
        "when cloud volumes ship",
    )?;
    reject_cloud_deferred(
        !config.spec.patches.is_empty(),
        "patches",
        "when cloud volumes ship",
    )?;
    reject_cloud_deferred(
        !config.spec.rlimits.is_empty(),
        "rlimits",
        "when rlimits land on the cloud API",
    )?;
    reject_cloud_deferred(
        config.spec.runtime.cmd.is_some(),
        "cmd",
        "when cmd lands on the cloud API",
    )?;
    reject_cloud_deferred(
        config.replace_existing,
        ".replace()",
        "when cloud sandbox replace semantics land",
    )?;
    reject_cloud_deferred(
        config.spec.init.is_some(),
        "init",
        "when cloud init wrapper lands",
    )?;
    reject_cloud_deferred(
        config.spec.pull_policy != crate::sandbox::PullPolicy::IfMissing,
        "pull_policy",
        "when cloud pull policy lands",
    )?;
    reject_cloud_deferred(
        config.registry_auth.is_some(),
        "registry_auth",
        "when cloud registry auth lands",
    )?;
    reject_cloud_deferred(
        config.insecure,
        "insecure registries",
        "when cloud insecure-registry support lands",
    )?;
    reject_cloud_deferred(
        !config.ca_certs.is_empty(),
        "ca_certs",
        "when cloud custom CA certs land",
    )?;
    #[cfg(feature = "net")]
    {
        // Only flag user-set opt-in fields. The default `NetworkConfig`
        // ships with a baseline policy (`public_only`) and built-in DNS
        // settings, so comparing those would always trigger; instead we
        // catch the explicit-add fields (ports, secrets, custom DNS
        // resolvers, host-CA trust).
        let net = config.local_network_config()?;
        let has_custom_network = !net.ports.is_empty()
            || !net.secrets.secrets.is_empty()
            || !net.dns.nameservers.is_empty()
            || net.trust_host_cas;
        reject_cloud_deferred(
            has_custom_network,
            "network policy / ports / secrets",
            "when cloud networking ships",
        )?;
    }

    let SandboxSpec {
        name,
        image,
        resources,
        runtime,
        env,
        lifecycle,
        ..
    } = config.spec;

    let image = match image {
        RootfsSource::Oci(image) => image.reference,
        RootfsSource::Bind(_) => {
            return Err(unsupported(
                "image-from-host-dir",
                "when cloud volumes ship",
            ));
        }
        RootfsSource::DiskImage { .. } => {
            return Err(unsupported("disk-image rootfs", "never on cloud"));
        }
    };

    Ok(CloudCreateSandboxRequest {
        name,
        image,
        vcpus: resources.cpus,
        memory_mib: resources.memory_mib,
        env: env.into_iter().map(Into::into).collect(),
        ephemeral: lifecycle.ephemeral,
        workdir: runtime.workdir,
        shell: runtime.shell,
        entrypoint: runtime.entrypoint,
        hostname: runtime.hostname,
        user: runtime.user,
        log_level: runtime.log_level.map(|level| level.as_str().to_string()),
        scripts: runtime.scripts.into_iter().collect(),
        max_duration_secs: lifecycle.max_duration_secs,
        idle_timeout_secs: lifecycle.idle_timeout_secs,
    })
}

fn reject_cloud_deferred(
    present: bool,
    feature: &'static str,
    available_when: &'static str,
) -> MicrosandboxResult<()> {
    if present {
        return Err(unsupported(feature, available_when));
    }
    Ok(())
}

fn unsupported(feature: &'static str, available_when: &'static str) -> MicrosandboxError {
    MicrosandboxError::Unsupported {
        feature: feature.into(),
        available_when: available_when.into(),
    }
}

fn unsupported_exec(feature: &'static str) -> MicrosandboxError {
    MicrosandboxError::Unsupported {
        feature: feature.into(),
        available_when: "when cloud exec lands".into(),
    }
}

fn unsupported_fs(feature: &'static str) -> MicrosandboxError {
    MicrosandboxError::Unsupported {
        feature: feature.into(),
        available_when: "when cloud guest fs lands".into(),
    }
}

fn unsupported_metrics(feature: &'static str) -> MicrosandboxError {
    MicrosandboxError::Unsupported {
        feature: feature.into(),
        available_when: "when cloud metrics land".into(),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::SandboxBuilder;

    #[tokio::test]
    async fn cloud_create_request_maps_common_fields() {
        let config = SandboxBuilder::new("agent-1")
            .image("python:3.12")
            .cpus(2)
            .memory(1024)
            .env("A", "B")
            .workdir("/app")
            .shell("/bin/bash")
            .entrypoint(["python", "-u"])
            .build()
            .await
            .unwrap();

        let req = cloud_create_request_from_config(config).unwrap();

        assert_eq!(req.name, "agent-1");
        assert_eq!(req.image, "python:3.12");
        assert_eq!(req.vcpus, 2);
        assert_eq!(req.memory_mib, 1024);
        assert_eq!(req.env["A"], "B");
        assert_eq!(req.workdir.as_deref(), Some("/app"));
        assert_eq!(req.shell.as_deref(), Some("/bin/bash"));
        assert_eq!(
            req.entrypoint,
            Some(vec!["python".to_string(), "-u".to_string()])
        );
    }

    #[tokio::test]
    async fn cloud_create_request_rejects_disk_image_rootfs() {
        let config = SandboxConfig {
            spec: SandboxSpec {
                name: "agent-1".into(),
                image: RootfsSource::DiskImage {
                    path: "rootfs.img".into(),
                    format: crate::sandbox::DiskImageFormat::Raw,
                    fstype: None,
                },
                ..Default::default()
            },
            ..Default::default()
        };

        let err = cloud_create_request_from_config(config).unwrap_err();
        assert!(matches!(err, MicrosandboxError::Unsupported { .. }));
    }

    /// Build a minimal OCI-backed [`SandboxConfig`] suitable for the
    /// cloud-reject tests. Each test then mutates one field and asserts
    /// the resulting request errors with `Unsupported`.
    fn base_cloud_config() -> SandboxConfig {
        SandboxConfig {
            spec: SandboxSpec {
                name: "agent-1".into(),
                image: RootfsSource::Oci(OciRootfsSource {
                    reference: "python:3.12".into(),
                    upper_size_mib: None,
                }),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn cloud_create_request_rejects_replace_existing() {
        let mut config = base_cloud_config();
        config.replace_existing = true;
        let err = cloud_create_request_from_config(config).unwrap_err();
        assert!(matches!(err, MicrosandboxError::Unsupported { .. }));
    }

    #[test]
    fn cloud_create_request_rejects_init() {
        let mut config = base_cloud_config();
        config.spec.init = Some(crate::sandbox::HandoffInit {
            cmd: "/sbin/init".into(),
            args: Vec::new(),
            env: Vec::new(),
        });
        let err = cloud_create_request_from_config(config).unwrap_err();
        assert!(matches!(err, MicrosandboxError::Unsupported { .. }));
    }

    #[test]
    fn cloud_create_request_rejects_non_default_pull_policy() {
        let mut config = base_cloud_config();
        config.spec.pull_policy = crate::sandbox::PullPolicy::Always;
        let err = cloud_create_request_from_config(config).unwrap_err();
        assert!(matches!(err, MicrosandboxError::Unsupported { .. }));
    }

    #[test]
    fn cloud_create_request_rejects_registry_auth() {
        let mut config = base_cloud_config();
        config.registry_auth = Some(microsandbox_image::RegistryAuth::Basic {
            username: "u".into(),
            password: "p".into(),
        });
        let err = cloud_create_request_from_config(config).unwrap_err();
        assert!(matches!(err, MicrosandboxError::Unsupported { .. }));
    }

    #[test]
    fn cloud_create_request_rejects_insecure() {
        let mut config = base_cloud_config();
        config.insecure = true;
        let err = cloud_create_request_from_config(config).unwrap_err();
        assert!(matches!(err, MicrosandboxError::Unsupported { .. }));
    }

    #[test]
    fn cloud_create_request_rejects_ca_certs() {
        let mut config = base_cloud_config();
        config
            .ca_certs
            .push(b"-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----".to_vec());
        let err = cloud_create_request_from_config(config).unwrap_err();
        assert!(matches!(err, MicrosandboxError::Unsupported { .. }));
    }

    #[cfg(feature = "net")]
    #[test]
    fn cloud_create_request_rejects_published_ports() {
        let mut config = base_cloud_config();
        config
            .spec
            .network
            .ports
            .push(microsandbox_types::PublishedPortSpec {
                host_port: 8080,
                guest_port: 80,
                protocol: microsandbox_types::PortProtocol::Tcp,
                host_bind: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST).to_string(),
            });
        let err = cloud_create_request_from_config(config).unwrap_err();
        assert!(matches!(err, MicrosandboxError::Unsupported { .. }));
    }

    #[test]
    fn sandbox_config_from_cloud_round_trips_d13_fields() {
        let cloud = CloudSandbox {
            id: "00000000-0000-0000-0000-000000000002".into(),
            org_id: "00000000-0000-0000-0000-000000000001".into(),
            name: "agent-1".into(),
            status: CloudSandboxStatus::Running,
            config: CloudCreateSandboxRequest {
                name: "agent-1".into(),
                image: "python:3.12".into(),
                vcpus: 4,
                memory_mib: 2048,
                env: [("A".to_string(), "B".to_string())].into_iter().collect(),
                ephemeral: true,
                workdir: Some("/app".into()),
                shell: Some("/bin/bash".into()),
                entrypoint: Some(vec!["python".into(), "-u".into()]),
                hostname: Some("worker".into()),
                user: Some("appuser".into()),
                log_level: Some("debug".into()),
                scripts: [("setup".to_string(), "echo hi".to_string())]
                    .into_iter()
                    .collect(),
                max_duration_secs: Some(3600),
                idle_timeout_secs: Some(600),
            },
            ephemeral: true,
            created_at: chrono::Utc::now(),
            started_at: None,
            stopped_at: None,
            last_error: None,
        };

        let config = sandbox_config_from_cloud(&cloud);

        assert_eq!(config.spec.name, "agent-1");
        assert!(
            matches!(config.spec.image, RootfsSource::Oci(ref s) if s.reference == "python:3.12")
        );
        assert_eq!(config.spec.resources.cpus, 4);
        assert_eq!(config.spec.resources.memory_mib, 2048);
        assert_eq!(
            config.spec.env,
            vec![EnvVar::new("A", "B")],
            "env round-trip"
        );
        assert_eq!(config.spec.runtime.workdir.as_deref(), Some("/app"));
        assert_eq!(config.spec.runtime.shell.as_deref(), Some("/bin/bash"));
        assert_eq!(
            config.spec.runtime.entrypoint,
            Some(vec!["python".to_string(), "-u".to_string()])
        );
        assert_eq!(config.spec.runtime.hostname.as_deref(), Some("worker"));
        assert_eq!(config.spec.runtime.user.as_deref(), Some("appuser"));
        assert_eq!(
            config.spec.runtime.log_level,
            Some(microsandbox_types::SandboxLogLevel::Debug),
            "log_level should round-trip via string mapping",
        );
        assert_eq!(
            config.spec.runtime.scripts.get("setup"),
            Some(&"echo hi".to_string())
        );
        assert_eq!(config.spec.lifecycle.max_duration_secs, Some(3600));
        assert_eq!(config.spec.lifecycle.idle_timeout_secs, Some(600));
    }

    #[test]
    fn sandbox_config_from_cloud_drops_unknown_log_level() {
        let cloud = CloudSandbox {
            id: "00000000-0000-0000-0000-000000000002".into(),
            org_id: "00000000-0000-0000-0000-000000000001".into(),
            name: "agent-1".into(),
            status: CloudSandboxStatus::Running,
            config: CloudCreateSandboxRequest {
                name: "agent-1".into(),
                image: "python:3.12".into(),
                log_level: Some("verbose".into()),
                ..Default::default()
            },
            ephemeral: true,
            created_at: chrono::Utc::now(),
            started_at: None,
            stopped_at: None,
            last_error: None,
        };

        let config = sandbox_config_from_cloud(&cloud);
        assert!(
            config.spec.runtime.log_level.is_none(),
            "unknown log_level should map to None"
        );
    }

    #[test]
    fn cloud_status_maps_created_and_starting_one_to_one() {
        assert_eq!(
            cloud_status_to_sandbox_status(CloudSandboxStatus::Created),
            SandboxStatus::Created,
        );
        assert_eq!(
            cloud_status_to_sandbox_status(CloudSandboxStatus::Starting),
            SandboxStatus::Starting,
        );
        assert_eq!(
            cloud_status_to_sandbox_status(CloudSandboxStatus::Running),
            SandboxStatus::Running,
        );
        assert_eq!(
            cloud_status_to_sandbox_status(CloudSandboxStatus::Stopping),
            SandboxStatus::Draining,
        );
        assert_eq!(
            cloud_status_to_sandbox_status(CloudSandboxStatus::Stopped),
            SandboxStatus::Stopped,
        );
        assert_eq!(
            cloud_status_to_sandbox_status(CloudSandboxStatus::Failed),
            SandboxStatus::Crashed,
        );
    }
}

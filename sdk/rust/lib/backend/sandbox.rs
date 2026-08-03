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

use super::Backend;
use crate::MicrosandboxResult;
use crate::agent::AgentClient;
use crate::logs::{LogEntry, LogOptions, LogStreamOptions};
use crate::runtime::ProcessHandle;
use crate::sandbox::exec::{ExecHandle, ExecOptions, ExecOutput};
use crate::sandbox::fs::{FsEntry, FsMetadata, FsReadStream, FsWriteSink};
use crate::sandbox::metrics::SandboxMetrics;
use crate::sandbox::{
    Sandbox, SandboxConfig, SandboxHandle, SandboxListBuilder, SandboxPage, SandboxStatus,
};

// Keep the pre-split path `crate::backend::sandbox::cloud_status_to_sandbox_status`
// working for callers like `sandbox/handle.rs`.
pub(crate) use super::cloud::sandbox::{
    cloud_status_to_sandbox_status, sandbox_config_from_cloud_spec,
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
    /// Serialized `SandboxConfig` used by the active VM, when known.
    pub active_config_json: Option<String>,
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
    /// Lifecycle status mapped from msb-cloud's
    /// [`CloudSandboxStatus`](crate::CloudSandboxStatus).
    pub status: SandboxStatus,
    /// Serialized [`CloudCreateSandboxRequest`](crate::CloudCreateSandboxRequest)
    /// returned by msb-cloud.
    pub config_json: String,
    /// Creation timestamp returned by msb-cloud.
    pub created_at: Option<DateTime<Utc>>,
    /// Last start timestamp, when known.
    pub started_at: Option<DateTime<Utc>>,
    /// Last stop timestamp, when known.
    pub stopped_at: Option<DateTime<Utc>>,
    /// Human-readable message for the most recent failure, when any.
    pub last_failure_message: Option<String>,
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

    /// List a filtered page of sandboxes.
    fn list<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        query: SandboxListBuilder,
    ) -> BoxFuture<'a, MicrosandboxResult<SandboxPage>>;

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
    ) -> BoxFuture<'a, MicrosandboxResult<ExecOutput>> {
        Box::pin(async move {
            crate::sandbox::exec::agent::exec(backend.as_ref(), name, config, cmd, opts).await
        })
    }

    /// Execute a command and return a streaming [`ExecHandle`].
    fn exec_stream<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
        config: &'a SandboxConfig,
        cmd: String,
        opts: ExecOptions,
    ) -> BoxFuture<'a, MicrosandboxResult<ExecHandle>> {
        Box::pin(async move {
            crate::sandbox::exec::agent::exec_stream(backend.as_ref(), name, config, cmd, opts)
                .await
        })
    }

    /// Attach the host terminal to a PTY session in the named sandbox.
    ///
    /// Returns the exit code. Local routes through libkrun + agentd; cloud
    /// routes the same session over the sandbox's agent WebSocket route.
    fn attach<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
        config: &'a SandboxConfig,
        cmd: String,
        opts: crate::sandbox::AttachOptionsBuilder,
    ) -> BoxFuture<'a, MicrosandboxResult<i32>> {
        Box::pin(async move {
            crate::sandbox::attach::agent::attach(backend.as_ref(), name, config, cmd, opts).await
        })
    }

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
    /// cloud returns a stream that yields a single
    /// [`MicrosandboxError::Unsupported`](crate::MicrosandboxError::Unsupported).
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
    ) -> BoxFuture<'a, MicrosandboxResult<Bytes>> {
        Box::pin(async move { crate::sandbox::fs::agent::read(backend.as_ref(), name, path).await })
    }

    /// Stream a guest file. Returns a [`FsReadStream`] yielding chunks.
    fn fs_read_stream<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<FsReadStream>> {
        Box::pin(async move {
            crate::sandbox::fs::agent::read_stream(backend.as_ref(), name, path).await
        })
    }

    /// Write `data` to a guest file (overwriting if it exists).
    fn fs_write<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
        path: &'a str,
        data: Vec<u8>,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            crate::sandbox::fs::agent::write(backend.as_ref(), name, path, data).await
        })
    }

    /// Open a streaming writer for a guest file.
    fn fs_write_stream<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<FsWriteSink>> {
        Box::pin(async move {
            crate::sandbox::fs::agent::write_stream(backend.as_ref(), name, path).await
        })
    }

    /// List immediate children of a guest directory.
    fn fs_list<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<FsEntry>>> {
        Box::pin(async move { crate::sandbox::fs::agent::list(backend.as_ref(), name, path).await })
    }

    /// Get file/directory metadata.
    fn fs_stat<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<FsMetadata>> {
        Box::pin(async move { crate::sandbox::fs::agent::stat(backend.as_ref(), name, path).await })
    }

    /// Create a directory (and parents).
    fn fs_mkdir<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(
            async move { crate::sandbox::fs::agent::mkdir(backend.as_ref(), name, path).await },
        )
    }

    /// Remove a file or (when `recursive`) directory.
    fn fs_remove<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
        path: &'a str,
        recursive: bool,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            crate::sandbox::fs::agent::remove(backend.as_ref(), name, path, recursive).await
        })
    }

    /// Copy a guest file from `from` to `to`.
    fn fs_copy<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
        from: &'a str,
        to: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(
            async move { crate::sandbox::fs::agent::copy(backend.as_ref(), name, from, to).await },
        )
    }

    /// Rename/move a guest file or directory.
    fn fs_rename<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
        from: &'a str,
        to: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            crate::sandbox::fs::agent::rename(backend.as_ref(), name, from, to).await
        })
    }

    /// Check whether a guest path exists.
    fn fs_exists<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<bool>> {
        Box::pin(
            async move { crate::sandbox::fs::agent::exists(backend.as_ref(), name, path).await },
        )
    }

    /// Copy a host file into the guest sandbox.
    fn fs_copy_from_host<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
        host: &'a Path,
        guest: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            crate::sandbox::fs::agent::copy_from_host(backend.as_ref(), name, host, guest).await
        })
    }

    /// Copy a guest file out to the host.
    fn fs_copy_to_host<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
        guest: &'a str,
        host: &'a Path,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            crate::sandbox::fs::agent::copy_to_host(backend.as_ref(), name, guest, host).await
        })
    }
}

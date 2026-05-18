//! Sandbox lifecycle backend trait.
//!
//! Per the SDK local-cloud parity plan (D6.4): `Sandbox` and `SandboxHandle`
//! stay single types with no variants. They hold `Arc<dyn Backend>` plus a
//! backend-private `*Inner` enum that the outer types never expose directly.
//! The trait returns the outer types — the local/cloud `Inner` variants are
//! constructed inside each backend's trait impl and wrapped with the
//! `Arc<dyn Backend>` the caller passes in.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use futures::future::BoxFuture;

use super::cloud_wire::{CloudCreateSandboxRequest, CloudSandbox, CloudSandboxStatus};
use super::{Backend, CloudBackend, LocalBackend};
use crate::agent::AgentClient;
use crate::runtime::{ProcessHandle, SpawnMode};
use crate::sandbox::{RootfsSource, Sandbox, SandboxConfig, SandboxHandle, SandboxStatus};
use crate::{MicrosandboxError, MicrosandboxResult};

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
    fn remove<'a>(&'a self, name: &'a str) -> BoxFuture<'a, MicrosandboxResult<()>>;

    /// Stop a running sandbox by name (graceful).
    fn stop<'a>(&'a self, name: &'a str) -> BoxFuture<'a, MicrosandboxResult<()>>;

    /// Kill a running sandbox by name (SIGKILL).
    fn kill<'a>(&'a self, name: &'a str) -> BoxFuture<'a, MicrosandboxResult<()>>;

    /// Trigger a graceful drain on a sandbox by name.
    fn drain<'a>(&'a self, name: &'a str) -> BoxFuture<'a, MicrosandboxResult<()>>;
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
            let (model, pid) = crate::sandbox::get_local_handle_state(name).await?;
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
            let rows = crate::sandbox::list_local_handle_state().await?;
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

    fn remove<'a>(&'a self, name: &'a str) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { crate::sandbox::remove_local(name).await })
    }

    fn stop<'a>(&'a self, name: &'a str) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { crate::sandbox::stop_local(name).await })
    }

    fn kill<'a>(&'a self, name: &'a str) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { crate::sandbox::kill_local(name).await })
    }

    fn drain<'a>(&'a self, name: &'a str) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { crate::sandbox::drain_local(name).await })
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
            Ok(SandboxHandle::from_cloud(backend, cloud))
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
                .collect();
            Ok(SandboxList {
                sandboxes,
                next_cursor: page.next_cursor,
            })
        })
    }

    fn remove<'a>(&'a self, name: &'a str) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            CloudBackend::destroy_sandbox(self, name).await?;
            Ok(())
        })
    }

    fn stop<'a>(&'a self, name: &'a str) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            CloudBackend::stop_sandbox(self, name).await?;
            Ok(())
        })
    }

    fn kill<'a>(&'a self, _name: &'a str) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            Err(unsupported(
                "cloud sandbox kill",
                "when cloud forced-stop lands",
            ))
        })
    }

    fn drain<'a>(&'a self, _name: &'a str) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            Err(unsupported(
                "cloud sandbox drain",
                "when cloud graceful-drain lands",
            ))
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Map [`CloudSandboxStatus`] to the SDK's [`SandboxStatus`] enum.
///
/// `Created` and `Starting` both collapse to `Stopped` (the sandbox is not
/// running yet); `Stopping` collapses to `Draining`; `Failed` to `Crashed`.
pub(crate) fn cloud_status_to_sandbox_status(s: CloudSandboxStatus) -> SandboxStatus {
    match s {
        CloudSandboxStatus::Created | CloudSandboxStatus::Starting => SandboxStatus::Stopped,
        CloudSandboxStatus::Running => SandboxStatus::Running,
        CloudSandboxStatus::Stopping => SandboxStatus::Draining,
        CloudSandboxStatus::Stopped => SandboxStatus::Stopped,
        CloudSandboxStatus::Failed => SandboxStatus::Crashed,
    }
}

/// Synthesize a [`SandboxConfig`] from a [`CloudSandbox`] response. Used when
/// the SDK didn't drive the create call (e.g. `start(name)` returns a
/// `Sandbox` for a sandbox the cloud created earlier).
fn sandbox_config_from_cloud(cloud: &CloudSandbox) -> SandboxConfig {
    let mut config = SandboxConfig {
        name: cloud.config.name.clone(),
        image: RootfsSource::Oci(cloud.config.image.clone()),
        cpus: cloud.config.vcpus,
        memory_mib: cloud.config.memory_mib,
        env: cloud.config.env.clone().into_iter().collect(),
        workdir: cloud.config.workdir.clone(),
        shell: cloud.config.shell.clone(),
        entrypoint: cloud.config.entrypoint.clone(),
        hostname: cloud.config.hostname.clone(),
        user: cloud.config.user.clone(),
        scripts: cloud.config.scripts.clone(),
        ..Default::default()
    };
    config.policy.max_duration_secs = cloud.config.max_duration_secs;
    config.policy.idle_timeout_secs = cloud.config.idle_timeout_secs;
    config
}

pub(super) fn cloud_create_request_from_config(
    config: SandboxConfig,
) -> MicrosandboxResult<CloudCreateSandboxRequest> {
    reject_cloud_deferred(
        !config.mounts.is_empty(),
        "mounts",
        "when cloud volumes ship",
    )?;
    reject_cloud_deferred(
        !config.patches.is_empty(),
        "patches",
        "when cloud volumes ship",
    )?;
    reject_cloud_deferred(
        !config.rlimits.is_empty(),
        "rlimits",
        "when rlimits land on the cloud API",
    )?;
    reject_cloud_deferred(
        config.cmd.is_some(),
        "cmd",
        "when cmd lands on the cloud API",
    )?;

    let image = match config.image {
        RootfsSource::Oci(image) => image,
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
        name: config.name,
        image,
        vcpus: config.cpus,
        memory_mib: config.memory_mib,
        env: config.env.into_iter().collect(),
        ephemeral: true,
        workdir: config.workdir,
        shell: config.shell,
        entrypoint: config.entrypoint,
        hostname: config.hostname,
        user: config.user,
        log_level: config.log_level.map(log_level_to_cloud),
        scripts: config.scripts,
        max_duration_secs: config.policy.max_duration_secs,
        idle_timeout_secs: config.policy.idle_timeout_secs,
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

fn log_level_to_cloud(level: microsandbox_runtime::logging::LogLevel) -> String {
    match level {
        microsandbox_runtime::logging::LogLevel::Error => "error",
        microsandbox_runtime::logging::LogLevel::Warn => "warn",
        microsandbox_runtime::logging::LogLevel::Info => "info",
        microsandbox_runtime::logging::LogLevel::Debug => "debug",
        microsandbox_runtime::logging::LogLevel::Trace => "trace",
    }
    .to_string()
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
            name: "agent-1".into(),
            image: RootfsSource::DiskImage {
                path: "rootfs.img".into(),
                format: crate::sandbox::DiskImageFormat::Raw,
                fstype: None,
            },
            ..Default::default()
        };

        let err = cloud_create_request_from_config(config).unwrap_err();
        assert!(matches!(err, MicrosandboxError::Unsupported { .. }));
    }
}

//! Cloud sandbox lifecycle: the [`SandboxOps`] impl for [`RemoteContext`]
//! plus the conversions between the SDK's [`SandboxConfig`] and the cloud's
//! create wire shape.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;

use super::{RemoteContext, snapshot::cloud_reference};
use crate::context::{
    Context,
    sandbox::{LogStream, MetricsStream, SandboxIdentity, SandboxOps, SandboxRecordPage},
};
use crate::error::{Operation, UnsupportedReason};
use crate::logs::{BootError, LogEntry, LogOptions, LogStreamOptions};
use crate::sandbox::metrics::SandboxMetrics;
use crate::sandbox::{
    OciRootfsSource, RestartOptions, RootfsSource, Sandbox, SandboxBuilder, SandboxConfig,
    SandboxListBuilder, SandboxRecord, SandboxSpec, SandboxStatus, get_identified_handle,
    restart_by_stop_and_start,
};
use crate::{MicrosandboxError, MicrosandboxResult};
use microsandbox_types::{
    CloudCompute, CloudCreateSandboxRequest, CloudCreateSandboxResponse, CloudSandboxStatus,
    CloudSecretSource, CloudSecretValue, CloudSecretsConfig, NamedVolumeMode, NetworkSpec,
    RootDisk, SandboxRuntimeOptions, TlsConfig, VolumeKind, VolumeMount,
};
use microsandbox_types::{HttpDenyResponseFormat, RegistryAuth};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Allows the worker's five-minute checkpoint deadline plus control-plane
/// reconciliation before reporting that a Cloud stop timed out.
const DEFAULT_CLOUD_STOP_TIMEOUT: Duration = Duration::from_secs(360);

/// Maximum stop budget accepted by the Cloud restart route, in whole seconds.
const MAX_CLOUD_RESTART_TIMEOUT_SECS: u64 = 60;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Execution-facing fields of a provider inspection response. These fields
/// are independent of root-source, mount-source and secret redaction, and must
/// not be decoded through the creation-request contract.
#[derive(serde::Deserialize)]
struct RemoteRuntimeInspection {
    runtime: Option<SandboxRuntimeOptions>,
    env: Option<Vec<microsandbox_types::EnvVar>>,
}

/// Create request, retaining the flat contract unless compute selection requires
/// the newer nested envelope. Both forms are accepted by the newer cloud API.
#[derive(Debug, Clone)]
pub(in crate::context) struct CloudCreateBody {
    /// The shared sandbox spec.
    pub spec: CloudCreateSandboxRequest,
    /// Requested globally-unique slug; the cloud assigns one when omitted.
    pub slug: Option<String>,
    /// Registry-credential selection for the image pull, derived from the
    /// config's [`RegistryAuth`]. Omitted (`None`) lets the cloud pick the
    /// stored credential configured for the image's registry host.
    pub registry: Option<CloudRegistrySelection>,
    /// Machine type for this creation; omitted to retain the server default.
    pub compute: Option<CloudCompute>,
}

/// Borrowed wire representation; no sandbox options are dropped or translated.
#[derive(serde::Serialize)]
struct CloudCreateWire<'a> {
    #[serde(flatten)]
    spec: CloudCreateSpec<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    slug: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    registry: &'a Option<CloudRegistrySelection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    compute: &'a Option<CloudCompute>,
}

#[derive(serde::Serialize)]
#[serde(untagged)]
enum CloudCreateSpec<'a> {
    Flat(&'a CloudCreateSandboxRequest),
    Nested { spec: &'a CloudCreateSandboxRequest },
}

/// Wire shape of the cloud's registry-credential selection.
///
/// `auto` is expressed by omitting the field.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub(in crate::context) enum CloudRegistrySelection {
    /// Pull anonymously, even when a stored credential matches the registry.
    Anonymous,
    /// Credentials for this sandbox's image pull only; the cloud applies them
    /// to the registry host derived from the image reference and never stores
    /// them with the org's registry credentials.
    Inline {
        /// Registry username.
        username: String,
        /// Registry password or access token.
        password: String,
    },
}

/// Fields used by SDK operations from the sandbox's spec as returned by the API.
///
/// Declared here rather than reusing the shared spec types so decoding stays
/// lenient: no strict enums, and any field may be missing.
#[derive(Debug, serde::Deserialize)]
struct CloudSpecProjection {
    image: Option<String>,
    resources: Option<CloudSpecResourcesProjection>,
    #[serde(default)]
    labels: BTreeMap<String, String>,
    lifecycle: Option<CloudSpecLifecycleProjection>,
}

#[derive(Debug, serde::Deserialize)]
struct CloudSpecResourcesProjection {
    vcpus: Option<u8>,
    memory_mib: Option<u32>,
    disk_size_mib: Option<u32>,
}

#[derive(Debug, serde::Deserialize)]
struct CloudSpecLifecycleProjection {
    max_duration_secs: Option<u64>,
    idle_timeout_secs: Option<u64>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RemoteContext {
    /// Stop the captured cloud identity and observe completion, including ephemeral deletion.
    pub(crate) async fn stop_complete(&self, id: &str) -> MicrosandboxResult<()> {
        let current = self.get_sandbox_by_id(id).await?;
        let unrecognized_status = || {
            MicrosandboxError::Runtime(format!(
                "cloud sandbox {:?} reported a status this SDK does not recognize; upgrade the SDK",
                current.name
            ))
        };
        match current.status {
            CloudSandboxStatus::Stopped | CloudSandboxStatus::Failed => return Ok(()),
            // A stop is already in flight. Poll it without submitting a duplicate.
            CloudSandboxStatus::Stopping | CloudSandboxStatus::SavingState => {}
            CloudSandboxStatus::Created
            | CloudSandboxStatus::Starting
            | CloudSandboxStatus::Running
            | CloudSandboxStatus::TemporarilyUnavailable
            | CloudSandboxStatus::RecoveryDecisionRequired => {
                self.stop_sandbox_by_id(id).await?;
            }
            CloudSandboxStatus::Unknown => return Err(unrecognized_status()),
            _ => return Err(unrecognized_status()),
        }
        loop {
            match self.get_sandbox_by_id(id).await {
                Ok(observed) => match observed.status {
                    CloudSandboxStatus::Stopped | CloudSandboxStatus::Failed => return Ok(()),
                    CloudSandboxStatus::RecoveryDecisionRequired => {
                        return Err(MicrosandboxError::Runtime(format!(
                            "cloud sandbox {:?} needs a recovery decision before it can stop",
                            current.name
                        )));
                    }
                    CloudSandboxStatus::Unknown => return Err(unrecognized_status()),
                    CloudSandboxStatus::Created
                    | CloudSandboxStatus::Starting
                    | CloudSandboxStatus::Running
                    | CloudSandboxStatus::Stopping
                    | CloudSandboxStatus::SavingState
                    | CloudSandboxStatus::TemporarilyUnavailable => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    _ => return Err(unrecognized_status()),
                },
                // Only disappearance after a successful stop of a confirmed ephemeral
                // sandbox is completion. Missing persistent sandboxes and failed stop
                // requests still surface their errors, and a reused name is never followed.
                Err(MicrosandboxError::SandboxNotFound(_)) if current.ephemeral => return Ok(()),
                Err(error) => return Err(error),
            }
        }
    }

    /// Apply captured device settings before validating or sending a cloud create request.
    pub(crate) async fn create_from_builder(
        &self,
        backend: Arc<dyn Context>,
        builder: SandboxBuilder,
        start: bool,
    ) -> MicrosandboxResult<Sandbox> {
        let (req, config) = self.build_create_request(builder).await?;
        let cloud = self.create_sandbox(&req, start).await?;
        if start {
            ensure_cloud_sandbox_ready(&cloud)?;
        }

        Ok(Sandbox::from_cloud(backend, cloud, config))
    }

    /// Resolve the request body and runtime config for a cloud create.
    pub(in crate::context) async fn build_create_request(
        &self,
        builder: SandboxBuilder,
    ) -> MicrosandboxResult<(CloudCreateBody, SandboxConfig)> {
        let mut config = self.build_sandbox_config(builder).await?;
        let mut names = BTreeSet::new();
        for mount in &mut config.spec.mounts {
            let VolumeMount::Named { name, create, .. } = mount else {
                continue;
            };
            let Some(requested) = create.take() else {
                continue;
            };
            if requested.name != *name {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "named volume {name:?} has a different creation name"
                )));
            }
            if requested.mode != NamedVolumeMode::EnsureExists
                || requested.kind != VolumeKind::Directory
                || requested.quota_mib.is_some()
                || requested.capacity_mib.is_some()
                || !requested.labels.is_empty()
            {
                return Err(MicrosandboxError::unsupported(
                    Operation::SandboxCreate,
                    UnsupportedReason::ConfigField("named volume inline create"),
                ));
            }
            names.insert(name.clone());
        }

        // Validate the whole request before provisioning anything. Only the default
        // ensure-exists behavior is resolved here; the wire and retained config use
        // plain named mounts, while the local backend keeps its inline-create path.
        let (mut request, config) =
            cloud_create_body_and_config(config, super::modify::resolve_env)?;
        request.compute = self
            .inner
            .compute_type
            .map(|compute_type| CloudCompute { compute_type });
        for name in names {
            match self.find_volume(&name).await {
                Ok(_) => {}
                Err(MicrosandboxError::VolumeNotFound(_)) => {
                    match self.create_volume(&name, None, &[]).await {
                        Ok(_) => {}
                        // Another client may have created the same volume since lookup.
                        Err(MicrosandboxError::VolumeAlreadyExists(_)) => {
                            self.find_volume(&name).await?;
                        }
                        Err(error) => return Err(error),
                    }
                }
                Err(error) => return Err(error),
            }
        }

        Ok((request, config))
    }

    /// Resolve cloud request settings for both explicit build and immediate creation.
    pub(crate) async fn build_sandbox_config(
        &self,
        mut builder: SandboxBuilder,
    ) -> MicrosandboxResult<SandboxConfig> {
        builder.prepare(Arc::new(self.clone())).await?;

        // The cloud worker resolves image metadata. Device policy is applied on this client.
        builder.finish_cloud(self.config_sources())
    }

    async fn restart_running_sandbox(
        &self,
        backend: Arc<dyn Context>,
        name: &str,
        identity: SandboxIdentity,
        options: RestartOptions,
    ) -> MicrosandboxResult<Sandbox> {
        // A zero budget must not dispatch shutdown, matching a timed stop.
        if options.timeout.is_zero() {
            return Err(stop_timed_out(name, &identity, options.timeout));
        }

        // The route takes whole seconds; round up so shutdown never gets less
        // time than the caller asked for.
        let timeout_secs = options
            .timeout
            .as_secs()
            .saturating_add(u64::from(options.timeout.subsec_nanos() > 0));
        if timeout_secs > MAX_CLOUD_RESTART_TIMEOUT_SECS {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "Cloud restart timeout cannot exceed {MAX_CLOUD_RESTART_TIMEOUT_SECS} seconds"
            )));
        }

        let id = cloud_identity(identity.clone())?;
        let cloud = self
            .restart_sandbox_by_id(&id, options.force, timeout_secs)
            .await
            .map_err(|error| match error {
                // Only a graceful shutdown reports a timeout.
                MicrosandboxError::CloudHttp {
                    code: Some(ref code),
                    ..
                } if code == "restart_stop_timed_out" => {
                    stop_timed_out(name, &identity, options.timeout)
                }
                error => error,
            })?;
        ensure_cloud_sandbox_ready(&cloud)?;

        let config = sandbox_config_from_cloud(&cloud)?;
        Ok(Sandbox::from_cloud(backend, cloud, config))
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl SandboxOps for RemoteContext {
    fn default_stop_timeout(&self) -> Duration {
        DEFAULT_CLOUD_STOP_TIMEOUT
    }

    fn should_force_kill_after_stop_timeout(&self) -> bool {
        false
    }

    fn create<'a>(
        &'a self,
        backend: Arc<dyn Context>,
        config: SandboxConfig,
        start: bool,
    ) -> BoxFuture<'a, MicrosandboxResult<Sandbox>> {
        Box::pin(self.create_from_builder(backend, SandboxBuilder::from(config), start))
    }

    fn create_detached<'a>(
        &'a self,
        backend: Arc<dyn Context>,
        config: SandboxConfig,
    ) -> BoxFuture<'a, MicrosandboxResult<Sandbox>> {
        // Cloud has no notion of "detached" — the sandbox lifecycle is owned
        // by the cloud API, not by this process. Reuse the eager-start path.
        self.create(backend, config, true)
    }

    fn start<'a>(
        &'a self,
        backend: Arc<dyn Context>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Sandbox>> {
        Box::pin(async move {
            let current = RemoteContext::get_sandbox(self, name).await?;
            let config = sandbox_config_from_cloud(&current)?;
            let cloud = RemoteContext::start_sandbox(self, name).await?;
            ensure_cloud_sandbox_ready(&cloud)?;
            Ok(Sandbox::from_cloud(backend, cloud, config))
        })
    }

    fn start_detached<'a>(
        &'a self,
        backend: Arc<dyn Context>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Sandbox>> {
        // Cloud start is detached by definition — the sandbox keeps running
        // after this process exits. Same code path as `start`.
        Box::pin(async move {
            let current = RemoteContext::get_sandbox(self, name).await?;
            let config = sandbox_config_from_cloud(&current)?;
            let cloud = RemoteContext::start_sandbox(self, name).await?;
            ensure_cloud_sandbox_ready(&cloud)?;
            Ok(Sandbox::from_cloud(backend, cloud, config))
        })
    }

    fn start_identified<'a>(
        &'a self,
        backend: Arc<dyn Context>,
        _name: &'a str,
        identity: SandboxIdentity,
    ) -> BoxFuture<'a, MicrosandboxResult<Sandbox>> {
        Box::pin(async move {
            let id = cloud_identity(identity)?;
            let current = RemoteContext::get_sandbox_by_id(self, &id).await?;
            let config = sandbox_config_from_cloud(&current)?;
            let cloud = RemoteContext::start_sandbox_by_id(self, &id).await?;
            ensure_cloud_sandbox_ready(&cloud)?;
            Ok(Sandbox::from_cloud(backend, cloud, config))
        })
    }

    fn start_detached_identified<'a>(
        &'a self,
        backend: Arc<dyn Context>,
        name: &'a str,
        identity: SandboxIdentity,
    ) -> BoxFuture<'a, MicrosandboxResult<Sandbox>> {
        self.start_identified(backend, name, identity)
    }

    fn get<'a>(
        &'a self,
        backend: Arc<dyn Context>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<SandboxRecord>> {
        Box::pin(async move {
            let cloud = RemoteContext::get_sandbox(self, name).await?;
            SandboxRecord::from_cloud(backend, cloud)
        })
    }

    fn list<'a>(
        &'a self,
        backend: Arc<dyn Context>,
        query: SandboxListBuilder,
    ) -> BoxFuture<'a, MicrosandboxResult<SandboxRecordPage>> {
        Box::pin(async move {
            let page = RemoteContext::list_sandboxes(self, &query).await?;
            let sandboxes = page
                .data
                .into_iter()
                .map(|sb| SandboxRecord::from_cloud(backend.clone(), sb))
                .collect::<MicrosandboxResult<Vec<_>>>()?;
            Ok(SandboxRecordPage {
                sandboxes,
                next_cursor: page.next_cursor,
            })
        })
    }

    fn remove<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            RemoteContext::destroy_sandbox(self, name).await?;
            Ok(())
        })
    }

    fn remove_identified<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _name: &'a str,
        identity: SandboxIdentity,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            RemoteContext::destroy_sandbox_by_id(self, &cloud_identity(identity)?).await?;
            Ok(())
        })
    }

    fn stop<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            RemoteContext::stop_sandbox(self, name).await?;
            Ok(())
        })
    }

    fn stop_identified<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _name: &'a str,
        identity: SandboxIdentity,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            RemoteContext::stop_sandbox_by_id(self, &cloud_identity(identity)?).await?;
            Ok(())
        })
    }

    fn kill<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            Err(MicrosandboxError::unsupported(
                Operation::SandboxKill,
                UnsupportedReason::UseInstead(Operation::SandboxStop),
            ))
        })
    }

    fn restart_identified<'a>(
        &'a self,
        backend: Arc<dyn Context>,
        name: &'a str,
        identity: SandboxIdentity,
        options: RestartOptions,
    ) -> BoxFuture<'a, MicrosandboxResult<Sandbox>> {
        // Cloud start is always detached, so `options.detached` changes nothing.
        Box::pin(async move {
            // The route's answer when the sandbox left Running after it was read.
            let mut not_running = None;
            loop {
                let current = get_identified_handle(&backend, name, &identity).await?;
                match current.status_snapshot() {
                    SandboxStatus::Running => {
                        if let Some(error) = not_running.take() {
                            return Err(error);
                        }
                        match self
                            .restart_running_sandbox(
                                backend.clone(),
                                name,
                                identity.clone(),
                                options,
                            )
                            .await
                        {
                            Err(error) if is_cloud_code(&error, "sandbox_not_running") => {
                                not_running = Some(error);
                            }
                            result => return result,
                        }
                    }
                    SandboxStatus::Created | SandboxStatus::Stopped | SandboxStatus::Crashed => {
                        return current.start().await;
                    }
                    SandboxStatus::Starting => {
                        not_running = None;
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    SandboxStatus::Draining | SandboxStatus::Paused => {
                        return restart_by_stop_and_start(backend, name, identity, options).await;
                    }
                }
            }
        })
    }

    fn drain<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            Err(MicrosandboxError::unsupported(
                Operation::SandboxDrain,
                UnsupportedReason::UseInstead(Operation::SandboxStop),
            ))
        })
    }

    fn boot_error<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Option<BootError>>> {
        // The cloud API does not currently expose a boot-error concept. Keep
        // the optional backend contract so it can provide one in the future.
        Box::pin(async { Ok(None) })
    }

    fn logs<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _name: &'a str,
        _opts: &'a LogOptions,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<LogEntry>>> {
        Box::pin(async move { RemoteContext::logs(self, _name, _opts).await })
    }

    fn log_stream<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        name: &'a str,
        opts: &'a LogStreamOptions,
    ) -> BoxFuture<'a, MicrosandboxResult<LogStream>> {
        Box::pin(async move { RemoteContext::log_stream(self, name, opts).await })
    }

    fn follow_logs<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        name: &'a str,
        opts: &'a LogOptions,
    ) -> BoxFuture<'a, MicrosandboxResult<LogStream>> {
        Box::pin(async move {
            if opts.tail.is_some() || opts.since.is_some() || opts.until.is_some() {
                return Err(MicrosandboxError::unsupported(
                    Operation::SandboxFollowLogs,
                    UnsupportedReason::NotAvailable(
                        "bounded cloud log follow filters are not yet available".to_string(),
                    ),
                ));
            }
            let stream_opts = LogStreamOptions {
                sources: opts.sources.clone(),
                follow: true,
                ..Default::default()
            };
            RemoteContext::log_stream(self, name, &stream_opts).await
        })
    }

    fn metrics<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        _name: &'a str,
        _config: &'a SandboxConfig,
    ) -> BoxFuture<'a, MicrosandboxResult<SandboxMetrics>> {
        Box::pin(async move { Err(MicrosandboxError::local_only(Operation::SandboxMetrics)) })
    }

    fn metrics_stream(
        &self,
        _backend: Arc<dyn Context>,
        _name: String,
        _config: SandboxConfig,
        _interval: Duration,
    ) -> MetricsStream {
        Box::pin(futures::stream::once(async {
            Err(MicrosandboxError::local_only(
                Operation::SandboxMetricsStream,
            ))
        }))
    }
}

impl serde::Serialize for CloudCreateBody {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Production APIs predating the nested envelope require the source fields
        // at the top level. Explicit compute selection must stay nested: those
        // APIs ignore unknown flat fields and could silently select the wrong tier.
        let spec = if self.compute.is_some() {
            CloudCreateSpec::Nested { spec: &self.spec }
        } else {
            CloudCreateSpec::Flat(&self.spec)
        };
        CloudCreateWire {
            spec,
            slug: &self.slug,
            registry: &self.registry,
            compute: &self.compute,
        }
        .serialize(serializer)
    }
}

impl TryFrom<SandboxConfig> for CloudCreateBody {
    type Error = MicrosandboxError;

    /// Build the cloud create body from an SDK config, rejecting the
    /// create-time options the cloud does not accept.
    fn try_from(mut config: SandboxConfig) -> MicrosandboxResult<Self> {
        if config.forked {
            return Err(MicrosandboxError::unsupported(
                Operation::SandboxCreate,
                UnsupportedReason::ConfigField("forked"),
            ));
        }
        if config.replace_existing {
            return Err(MicrosandboxError::unsupported(
                Operation::SandboxCreate,
                UnsupportedReason::ConfigField("replace"),
            ));
        }
        if config.insecure {
            return Err(MicrosandboxError::unsupported(
                Operation::SandboxCreate,
                UnsupportedReason::ConfigField("insecure"),
            ));
        }
        if !config.ca_certs.is_empty() {
            return Err(MicrosandboxError::unsupported(
                Operation::SandboxCreate,
                UnsupportedReason::ConfigField("ca_certs"),
            ));
        }
        if config.image_cache_dir.is_some() {
            return Err(MicrosandboxError::unsupported(
                Operation::SandboxCreate,
                UnsupportedReason::ConfigField("image_cache_dir"),
            ));
        }
        reject_dropped_cloud_create_fields(&config)?;
        #[cfg(feature = "net")]
        {
            // Only flag user-set opt-in fields the cloud's create contract does
            // not accept (published ports, custom DNS resolvers, host-CA trust).
            // Policy and secrets ride in the request's network section, and the
            // default `NetworkConfig` ships with a baseline policy plus built-in
            // DNS settings, so comparing those would always trigger.
            let net = config.local_network_config()?;
            if !net.ports.is_empty() || !net.dns.nameservers.is_empty() || net.trust_host_cas {
                return Err(MicrosandboxError::unsupported(
                    Operation::SandboxCreate,
                    UnsupportedReason::ConfigField("network ports / custom DNS / host-CA trust"),
                ));
            }
        }

        // Direct SandboxConfig callers bypass the fluent builder, so impose
        // the shared path validation and deterministic order at this final
        // client-side boundary before constructing the cloud wire request.
        crate::sandbox::validate_volume_mounts(&mut config.spec.mounts)?;
        // registry_auth converts into the cloud's credential selection: absent
        // means the cloud picks the stored credential configured for the
        // image's registry host (mirroring the local fallback to configured
        // registries), Anonymous forces an unauthenticated pull, and Basic
        // credentials ride as sandbox-scoped inline credentials.
        let registry = match &config.registry_auth {
            None => None,
            Some(RegistryAuth::Anonymous) => Some(CloudRegistrySelection::Anonymous),
            Some(RegistryAuth::Basic { username, password }) => {
                Some(CloudRegistrySelection::Inline {
                    username: username.clone(),
                    password: password.clone(),
                })
            }
        };

        let spec = match config.snapshot_reference {
            None => {
                validate_fresh_cloud_rootfs(&config.spec.image)?;
                CloudCreateSandboxRequest::from(config.spec)
            }
            Some(reference) => {
                let CloudCreateSandboxRequest::Oci {
                    sandbox,
                    resources,
                    pull_policy,
                    ..
                } = CloudCreateSandboxRequest::from(config.spec)
                else {
                    return Err(MicrosandboxError::unsupported(
                        Operation::SandboxCreate,
                        UnsupportedReason::ConfigField("from_snapshot with non-OCI rootfs"),
                    ));
                };

                CloudCreateSandboxRequest::DiskSnapshot {
                    sandbox,
                    disk_snapshot_ref: cloud_reference(reference)?,
                    resources: resources.into(),
                    pull_policy,
                }
            }
        };

        Ok(Self {
            spec,
            slug: config.slug,
            registry,
            compute: None,
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn stop_timed_out(name: &str, identity: &SandboxIdentity, timeout: Duration) -> MicrosandboxError {
    MicrosandboxError::StopTimeout {
        name: name.to_string(),
        identity: format!("{identity:?}"),
        timeout,
    }
}

fn is_cloud_code(error: &MicrosandboxError, code: &str) -> bool {
    matches!(error, MicrosandboxError::CloudHttp { code: Some(actual), .. } if actual == code)
}

fn cloud_identity(identity: SandboxIdentity) -> MicrosandboxResult<String> {
    match identity {
        SandboxIdentity::Cloud(id) => Ok(id),
        SandboxIdentity::Local(id) => Err(MicrosandboxError::Runtime(format!(
            "local sandbox identity {id} was routed to the cloud backend"
        ))),
    }
}

fn cloud_create_body_and_config(
    mut config: SandboxConfig,
    resolve_env: impl FnMut(&str) -> Option<CloudSecretValue>,
) -> MicrosandboxResult<(CloudCreateBody, SandboxConfig)> {
    // Build the request first to preserve cloud-specific error precedence,
    // then apply the same successful canonicalization to the config retained
    // by Sandbox::config().
    let mut request = CloudCreateBody::try_from(config.clone())?;
    resolve_secret_sources(
        request.spec.sandbox_spec_mut().network.secrets.as_mut(),
        resolve_env,
    )?;
    crate::sandbox::validate_volume_mounts(&mut config.spec.mounts)?;
    Ok((request, config))
}

/// Env references are read from the caller's environment when the sandbox is
/// created, while the sandbox config keeps the reference. A source wins over
/// a value set on the same secret, as it does on a local create.
fn resolve_secret_sources(
    spec_secrets: Option<&mut CloudSecretsConfig>,
    mut resolve_env: impl FnMut(&str) -> Option<CloudSecretValue>,
) -> MicrosandboxResult<()> {
    let Some(spec_secrets) = spec_secrets else {
        return Ok(());
    };

    for entry in &mut spec_secrets.entries {
        let Some(source) = &entry.source else {
            continue;
        };

        match source {
            CloudSecretSource::Env { var } => {
                let var = var.clone();
                let value = resolve_env(&var).ok_or_else(|| {
                    MicrosandboxError::InvalidConfig(format!(
                        "invalid secret configuration: secret {}: host environment variable {var} is not set",
                        entry.env_var
                    ))
                })?;
                if value.expose().is_empty() {
                    return Err(MicrosandboxError::InvalidConfig(format!(
                        "invalid secret configuration: secret {}: host environment variable {var} is empty",
                        entry.env_var
                    )));
                }

                entry.value = value.expose().to_owned();
                entry.source = None;
            }
            CloudSecretSource::Store { .. } => {
                return Err(MicrosandboxError::Custom(format!(
                    "invalid secret configuration: secret {}: store-backed secret sources are not supported yet",
                    entry.env_var
                )));
            }
        }
    }

    Ok(())
}

/// Validate the root filesystem before converting a normal cloud create. The
/// conversion intentionally omits unsupported root-disk variants, so this must
/// run against the original domain spec.
fn validate_fresh_cloud_rootfs(rootfs: &RootfsSource) -> MicrosandboxResult<()> {
    match rootfs {
        RootfsSource::Oci(oci) => {
            if matches!(
                oci.root_disk,
                Some(RootDisk::Tmpfs { .. } | RootDisk::DiskImage { .. } | RootDisk::Flat { .. })
            ) {
                return Err(MicrosandboxError::unsupported(
                    Operation::SandboxCreate,
                    UnsupportedReason::ConfigField("non-managed root_disk"),
                ));
            }
        }
        RootfsSource::Bind {
            follow_root_symlinks: true,
            ..
        } => {
            return Err(MicrosandboxError::unsupported(
                Operation::SandboxCreate,
                UnsupportedReason::ConfigField("rootfs follow_root_symlinks"),
            ));
        }
        RootfsSource::Bind { .. } | RootfsSource::DiskImage { .. } => {}
    }

    Ok(())
}

/// Reject SDK configuration whose meaning is absent from the current cloud
/// wire shape. Failing at the backend boundary prevents a successful create
/// from quietly producing a sandbox different from the one requested.
fn reject_dropped_cloud_create_fields(config: &SandboxConfig) -> MicrosandboxResult<()> {
    let unsupported = |field| {
        MicrosandboxError::unsupported(
            Operation::SandboxCreate,
            UnsupportedReason::ConfigField(field),
        )
    };

    if config.spec.resources.nested_virt == Some(true) {
        return Err(unsupported("nested_virt (local-only)"));
    }
    if config.spec.resources.max_cpus != config.spec.resources.cpus {
        return Err(unsupported("max_cpus"));
    }
    if config.spec.resources.max_memory_mib != config.spec.resources.memory_mib {
        return Err(unsupported("max_memory"));
    }
    if config.spec.runtime.hostname.is_some() {
        return Err(unsupported("hostname"));
    }
    // The cloud wire has no clock policy field; refuse `off` rather than drop it.
    if config
        .spec
        .runtime
        .guest_clock
        .is_some_and(|policy| !policy.is_sync())
    {
        return Err(unsupported("guest_clock"));
    }

    // The shared default is harmless because Cloud owns metrics collection.
    // Any caller override would otherwise be mistaken for an honored guest
    // sampling configuration.
    let runtime_defaults = SandboxRuntimeOptions::default();
    if config.spec.runtime.metrics_sample_interval_ms != runtime_defaults.metrics_sample_interval_ms
    {
        return Err(unsupported("metrics_sample_interval"));
    }
    if config.spec.runtime.disable_metrics_sample {
        return Err(unsupported("disable_metrics_sample"));
    }

    if config
        .spec
        .network
        .interface
        .as_ref()
        .is_some_and(|interface| interface != &Default::default())
    {
        return Err(unsupported("network.interface"));
    }
    if let Some(tls) = &config.spec.network.tls
        && !cloud_tls_config_is_harmless(tls, config)?
    {
        return Err(unsupported("network.tls"));
    }
    if config.spec.network.rate_limiter.is_some() {
        return Err(unsupported("network.rate_limiter"));
    }
    if config.spec.network.nat64_prefixes != NetworkSpec::default().nat64_prefixes {
        return Err(unsupported("network.nat64_prefixes"));
    }

    let http = &config.spec.network.http;
    // Cloud has no HTTP denial-response configuration. Accept the local defaults
    // so ordinary creation still works; reject enabled custom/legacy settings.
    if http.deny_response
        && (http.deny_response_format != HttpDenyResponseFormat::Json
            || http.deny_message.is_some()
            || http.network_deny_message.is_some()
            || http.secret_deny_message.is_some())
    {
        return Err(unsupported("network.http.deny_response (local-only)"));
    }

    if config.spec.network.outbound_proxy.is_some() {
        return Err(unsupported("network.outbound_proxy"));
    }
    if config.spec.network.max_inbound_tcp_connections.is_some() {
        return Err(unsupported("network.max_inbound_tcp_connections"));
    }
    // Tunes published-port listeners, which the cloud create contract does not carry.
    if config.spec.network.tcp_accept_queue_size.is_some() {
        return Err(unsupported("network.tcp_accept_queue_size"));
    }

    if config
        .spec
        .mounts
        .iter()
        .any(|mount| mount.named_create().is_some())
    {
        return Err(unsupported("named volume inline create"));
    }
    if config
        .spec
        .mounts
        .iter()
        .any(|mount| matches!(mount, microsandbox_types::VolumeMount::Owned { .. }))
    {
        return Err(unsupported("sandbox-owned volumes"));
    }
    if config.snapshot_upper_source.is_some() || config.snapshot_archive_source.is_some() {
        return Err(unsupported("from_snapshot"));
    }
    // Cloud's restore request currently names a disk snapshot. These local
    // execution/archive choices have no wire representation; dropping one
    // could report success after booting a different kind of sandbox.
    if config.forked {
        return Err(unsupported("forked"));
    }
    if config.snapshot_restore_mode == crate::sandbox::config::SnapshotRestoreMode::DiskOnly {
        return Err(unsupported("disk_only"));
    }
    if config.snapshot_base.is_some() {
        return Err(unsupported("snapshot_base"));
    }
    if config.restore_resources.inherit {
        return Err(unsupported("inherit_resources"));
    }
    if config.restore_resources.allow_missing {
        return Err(unsupported("allow_missing_resources"));
    }
    if !config.restore_resources.captured.is_empty() {
        return Err(unsupported("captured resources"));
    }
    #[cfg(feature = "local")]
    if config.checkpoint_restore.is_some()
        || config.branch_source.is_some()
        || !config.snapshot_root_layer_sources.is_empty()
        || config.snapshot_owned_source.is_some()
        || !config.snapshot_upper_layers.is_empty()
    {
        return Err(unsupported("prepared local restore"));
    }
    if config.snapshot_reference.is_some() {
        match &config.spec.image {
            RootfsSource::Oci(oci) if oci.reference.is_empty() && oci.root_disk.is_none() => {}
            _ => return Err(unsupported("rootfs with from_snapshot")),
        }
    }
    if !config.spec.vsock.is_empty() {
        return Err(unsupported("vsock"));
    }

    Ok(())
}

/// Return whether a TLS subdocument only contains defaults the cloud owns.
/// Secret helpers enable TLS as an implementation detail; preserve that path
/// while rejecting actual interception customization that the wire drops.
fn cloud_tls_config_is_harmless(
    tls: &TlsConfig,
    config: &SandboxConfig,
) -> MicrosandboxResult<bool> {
    let actual = serde_json::to_value(tls)?;
    let default = serde_json::to_value(TlsConfig::default())?;
    if actual == default {
        return Ok(true);
    }

    let has_secrets = config
        .spec
        .network
        .secrets
        .as_ref()
        .is_some_and(|secrets| !secrets.secrets.is_empty());
    if !has_secrets {
        return Ok(false);
    }

    let secret_helper_default = TlsConfig {
        enabled: true,
        ..Default::default()
    };
    Ok(actual == serde_json::to_value(secret_helper_default)?)
}

/// Map [`CloudSandboxStatus`] to the SDK's [`SandboxStatus`] enum.
///
/// `Stopping` and `SavingState` collapse to `Draining`; `Failed` collapses to
/// `Crashed`; `TemporarilyUnavailable`, `RecoveryDecisionRequired`, `Unknown`,
/// and any unrecognized status collapse to `Paused`. All other variants map 1:1.
pub(crate) fn cloud_status_to_sandbox_status(s: CloudSandboxStatus) -> SandboxStatus {
    match s {
        CloudSandboxStatus::Created => SandboxStatus::Created,
        CloudSandboxStatus::Starting => SandboxStatus::Starting,
        CloudSandboxStatus::Running => SandboxStatus::Running,
        CloudSandboxStatus::Stopping => SandboxStatus::Draining,
        CloudSandboxStatus::SavingState => SandboxStatus::Draining,
        CloudSandboxStatus::TemporarilyUnavailable => SandboxStatus::Paused,
        CloudSandboxStatus::RecoveryDecisionRequired => SandboxStatus::Paused,
        CloudSandboxStatus::Stopped => SandboxStatus::Stopped,
        CloudSandboxStatus::Failed => SandboxStatus::Crashed,
        CloudSandboxStatus::Unknown => SandboxStatus::Paused,
        _ => SandboxStatus::Paused,
    }
}

/// Enforce the cross-backend lifecycle contract: a successful create or start
/// returns a sandbox whose agent-facing operations are immediately usable.
fn ensure_cloud_sandbox_ready(cloud: &CloudCreateSandboxResponse) -> MicrosandboxResult<()> {
    match cloud.status {
        CloudSandboxStatus::Running => Ok(()),
        CloudSandboxStatus::Failed => Err(MicrosandboxError::Runtime(format!(
            "cloud sandbox {:?} failed to start: {}",
            cloud.name,
            cloud
                .last_failure_message
                .as_deref()
                .unwrap_or("the cloud API reported no failure reason")
        ))),
        CloudSandboxStatus::Starting => Err(MicrosandboxError::Runtime(format!(
            "cloud sandbox {:?} did not reach running before the readiness wait expired",
            cloud.name
        ))),
        status => Err(MicrosandboxError::Runtime(format!(
            "cloud sandbox {:?} entered {status:?} instead of running",
            cloud.name
        ))),
    }
}

/// Build the runtime config from the sandbox's spec as returned by the API.
///
/// The provider may omit `spec` or return a curated shape. Runtime settings
/// are decoded independently from creation metadata; malformed settings fail
/// preparation. An omitted projection retains the existing legacy behavior.
fn sandbox_config_from_cloud(
    cloud: &CloudCreateSandboxResponse,
) -> MicrosandboxResult<SandboxConfig> {
    sandbox_config_from_cloud_spec(&cloud.name, cloud.spec.clone())
}

/// Decode the sandbox's spec as returned by the API for SDK operations.
///
/// This internal session config is not the public live configuration result.
/// Preserve execution settings even when a redacted projection cannot supply
/// creation metadata; never discard a runtime decoding error.
pub(crate) fn sandbox_config_from_cloud_spec(
    name: &str,
    spec: Option<serde_json::Value>,
) -> MicrosandboxResult<SandboxConfig> {
    // Validate the fields consumed by execution independently. In particular,
    // malformed runtime settings are not permission to run with other defaults.
    let spec_projection = spec
        .as_ref()
        .and_then(|value| serde_json::from_value::<CloudSpecProjection>(value.clone()).ok());
    let runtime = spec
        .as_ref()
        .map(|value| serde_json::from_value::<RemoteRuntimeInspection>(value.clone()))
        .transpose()?;
    let complete_spec = spec
        .and_then(|value| serde_json::from_value::<CloudCreateSandboxRequest>(value).ok())
        .and_then(|request| SandboxSpec::try_from(request).ok());
    let sandbox_spec = complete_spec.unwrap_or_else(|| {
        let mut spec = SandboxSpec::default();
        if let Some(projection) = spec_projection {
            apply_cloud_metadata_projection(&mut spec, projection);
        }
        spec
    });
    let mut config = SandboxConfig {
        spec: sandbox_spec,
        ..Default::default()
    };

    if let Some(runtime) = runtime {
        if let Some(options) = runtime.runtime {
            config.spec.runtime = options;
        }
        if let Some(env) = runtime.env {
            config.spec.env = env;
        }
    }

    // The top-level response name is canonical even when a complete spec was
    // unavailable or carried stale inspection data.
    config.spec.name = name.to_string();
    Ok(config)
}

/// Copy the settings SDK operations use from the API spec into an SDK spec.
fn apply_cloud_metadata_projection(spec: &mut SandboxSpec, projection: CloudSpecProjection) {
    if let Some(image) = projection.image {
        let root_disk = projection
            .resources
            .as_ref()
            .and_then(|resources| resources.disk_size_mib)
            .map(RootDisk::managed);
        spec.image = RootfsSource::Oci(OciRootfsSource {
            reference: image,
            root_disk,
        });
    }

    if let Some(resources) = projection.resources {
        if let Some(vcpus) = resources.vcpus {
            spec.resources.cpus = vcpus;
            spec.resources.max_cpus = vcpus;
        }
        if let Some(memory_mib) = resources.memory_mib {
            spec.resources.memory_mib = memory_mib;
            spec.resources.max_memory_mib = memory_mib;
        }
    }

    spec.labels = projection.labels;

    if let Some(lifecycle) = projection.lifecycle {
        spec.lifecycle.max_duration_secs = lifecycle.max_duration_secs;
        spec.lifecycle.idle_timeout_secs = lifecycle.idle_timeout_secs;
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;

    use microsandbox_types::{
        CloudSecretsConfig, HostPermissions, MountOptions, NamedVolumeCreate, NamedVolumeMode,
        SecretSource, SecretsConfig, StatVirtualization, VolumeKind, VolumeMount,
    };

    #[cfg(feature = "net")]
    use zeroize::Zeroizing;

    use super::*;
    use crate::ComputeType;
    use crate::context::{Context, SandboxOps};
    use crate::sandbox::{EnvVar, OciRootfsSource, RootDisk, SandboxBuilder, SandboxSpec};
    use crate::snapshot::SnapshotReference;
    use crate::test_support;
    use microsandbox_types::CloudSnapshotLocation;
    use microsandbox_types::{HttpDenyResponseFormat, SandboxLogLevel};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    use super::super::ws_io::WsByteStream;

    const CLOUD_SANDBOX_RESPONSE_FIXTURE: &str = r#"
{
  "id": "00000000-0000-0000-0000-0000000000a1",
  "org_id": "00000000-0000-0000-0000-0000000000b1",
  "name": "spec-decode",
  "slug": "spec-decode-abc123",
  "status": "running",
  "compute": {
    "type": "standard"
  },
  "status_reason": null,
  "ephemeral": false,
  "created_at": "2026-11-18T03:10:37.559567Z",
  "last_failure_message": null,
  "temporarily_unavailable_since": null,
  "automatic_recovery_ends_at": null,
  "started_at": "2026-11-18T03:10:37.559567Z",
  "stopped_at": null,
  "spec": {
    "image": "alpine:3.20",
    "resources": {
      "vcpus": 1,
      "memory_mib": 512,
      "disk_size_mib": 4096
    },
    "runtime": {
      "workdir": "/tmp",
      "shell": "/bin/ash",
      "scripts": {},
      "entrypoint": [
        "/bin/sh",
        "-c"
      ],
      "cmd": [
        "printf attached"
      ],
      "hostname": null,
      "user": "nobody",
      "log_level": null,
      "metrics_sample_interval_ms": 1000,
      "disable_metrics_sample": false
    },
    "env": [
      {
        "key": "FOO",
        "value": "bar"
      }
    ],
    "labels": {},
    "rlimits": [],
    "lifecycle": {
      "ephemeral": false,
      "max_duration_secs": 900,
      "idle_timeout_secs": null
    },
    "mounts": [],
    "network": {
      "enabled": true,
      "ports": [],
      "trust_host_cas": false,
      "secret_violation_action": "block-and-log"
    }
  }
}
"#;

    #[test]
    fn cloud_default_stop_timeout_covers_checkpoint_convergence() {
        let backend = crate::test_support::cloud_backend("http://127.0.0.1:1", "test-key").unwrap();

        assert_eq!(backend.default_stop_timeout(), Duration::from_secs(360));
        assert!(!backend.should_force_kill_after_stop_timeout());
    }

    type ConfigMutation = fn(&mut SandboxConfig);

    #[tokio::test]
    async fn every_cloud_create_entry_point_sends_captured_file_policy() {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

        for (entry, cpus, memory, explicit_max) in (0..6).flat_map(|entry| {
            [
                (1, 512, false),
                (1, 512, true),
                (8, 2048, false),
                (8, 2048, true),
            ]
            .map(|(cpus, memory, explicit_max)| (entry, cpus, memory, explicit_max))
        }) {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut reader = BufReader::new(stream);
                let mut content_length = 0;
                loop {
                    let mut line = String::new();
                    assert_ne!(reader.read_line(&mut line).await.unwrap(), 0);
                    if line == "\r\n" {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':')
                        && name.eq_ignore_ascii_case("content-length")
                    {
                        content_length = value.trim().parse::<usize>().unwrap();
                    }
                }
                let mut body = vec![0; content_length];
                reader.read_exact(&mut body).await.unwrap();
                let response =
                    serde_json::to_string(&cloud_response(CloudSandboxStatus::Running)).unwrap();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response.len(),
                    response
                );
                reader
                    .get_mut()
                    .write_all(response.as_bytes())
                    .await
                    .unwrap();
                serde_json::from_slice::<serde_json::Value>(&body).unwrap()
            });
            let directory = tempfile::tempdir().unwrap();
            let user = directory.path().join("config.json");
            let managed = directory.path().join("managed.json");
            std::fs::write(
                &user,
                r#"{"sandbox_defaults":{"cpus":6,"memory_mib":4096,"workdir":"/user"}}"#,
            )
            .unwrap();
            std::fs::write(&managed, r#"{"version":1,"overrides":{"sandbox_defaults":{"cpus":2,"memory_mib":1024,"workdir":"/managed","shell":"/bin/admin"}}}"#).unwrap();
            let mut builder = RemoteContext::builder()
                .url(url)
                .api_key("test-token")
                .config_sources(
                    crate::config::layers::BackendConfig::load_from(&user, Some(&managed)).unwrap(),
                );
            if explicit_max {
                builder = builder.compute_type(ComputeType::Shared);
            }
            let backend = builder.build().unwrap();
            // Existing backends keep captured policy. A new backend must fail on
            // these invalid files, but no create entry point should reload them.
            std::fs::write(&user, "invalid").unwrap();
            std::fs::write(&managed, "invalid").unwrap();
            assert!(
                crate::config::layers::BackendConfig::load_from(&user, Some(&managed)).is_err()
            );
            let backend: Arc<dyn Context> = Arc::new(backend);
            let request = || {
                let builder = backend
                    .sandboxes()
                    .builder("policy-request")
                    .image("alpine")
                    .cpus(cpus)
                    .memory(memory)
                    .workdir("/request")
                    .shell("/bin/request");
                if explicit_max {
                    builder.max_cpus(cpus).max_memory(memory)
                } else {
                    builder
                }
            };
            let empty =
                crate::config::layers::BackendConfig::new(Default::default(), Default::default());
            let concrete = request().finish(Some(&empty), None).unwrap();
            let operation = async {
                let destination: std::sync::Arc<dyn crate::Context> = backend.clone();

                match entry {
                    0 => request().create().await,
                    1 => request().create_detached().await,
                    2 => destination.sandboxes().create(concrete).await,
                    3 => destination.sandboxes().create_detached(concrete).await,
                    4 => {
                        let config =
                            SandboxBuilder::from_config_for_context(backend.clone(), concrete)
                                .build()
                                .await?;
                        destination.sandboxes().create(config).await
                    }
                    _ => {
                        backend
                            .sandbox_ops()
                            .create(backend.clone(), concrete, false)
                            .await
                    }
                }
            };
            let sandbox = tokio::time::timeout(Duration::from_secs(5), operation)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                sandbox
                    .prepared_runtime()
                    .unwrap()
                    .config
                    .spec
                    .resources
                    .cpus,
                2
            );
            let body = server.await.unwrap();
            if explicit_max {
                assert_eq!(body["compute"], serde_json::json!({"type": "shared"}));
            } else {
                assert!(body.get("compute").is_none());
            }
            let body = if explicit_max { &body["spec"] } else { &body };
            assert_eq!(body["resources"]["vcpus"], 2, "entry {entry}");
            assert_eq!(body["resources"]["memory_mib"], 1024, "entry {entry}");
            assert_eq!(body["runtime"]["workdir"], "/managed", "entry {entry}");
            assert_eq!(body["runtime"]["shell"], "/bin/admin", "entry {entry}");
        }
    }

    #[tokio::test]
    async fn unsupported_managed_cloud_settings_fail_before_http() {
        let policy =
            serde_json::from_str(r#"{"sandbox_defaults":{"disable_metrics_sample":true}}"#)
                .unwrap();
        let backend = RemoteContext::builder()
            .url("http://127.0.0.1:1")
            .api_key("test-key")
            .config_sources(crate::config::layers::BackendConfig::new(
                Default::default(),
                policy,
            ))
            .build()
            .unwrap();
        let error = async {
            let destination: std::sync::Arc<dyn crate::Context> = (backend).into();

            destination
                .sandboxes()
                .builder("unsupported-policy")
                .image("alpine")
                .cpus(2)
                .create()
                .await
                .err()
                .unwrap()
        }
        .await;
        assert!(matches!(
            error,
            MicrosandboxError::Unsupported {
                reason: UnsupportedReason::ConfigField("disable_metrics_sample"),
                ..
            }
        ));
    }

    #[cfg(feature = "net")]
    #[tokio::test]
    async fn http_deny_response_is_rejected_before_cloud_http() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend = RemoteContext::builder()
            .url(format!("http://{}", listener.local_addr().unwrap()))
            .api_key("test-key")
            .build()
            .unwrap();
        let error = async {
            let destination: std::sync::Arc<dyn crate::Context> = (backend).into();

            destination
                .sandboxes()
                .builder("http-deny-cloud")
                .image("alpine")
                .network(|network| {
                    network.http(|h| {
                        h.deny_response(true)
                            .deny_response_format(HttpDenyResponseFormat::Text)
                    })
                })
                .create()
                .await
                .err()
                .expect("cloud must reject the local-only option")
        }
        .await;

        assert!(
            matches!(
                error,
                MicrosandboxError::Unsupported {
                    reason: UnsupportedReason::ConfigField(
                        "network.http.deny_response (local-only)"
                    ),
                    ..
                }
            ),
            "{error}"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );

        let mut defaults = base_cloud_config();
        defaults.spec.network.http = Default::default();
        reject_dropped_cloud_create_fields(&defaults).unwrap();

        for message in [None, Some(""), Some("blocked {host}")] {
            let mut config = base_cloud_config();
            config.spec.network.http.deny_response = false;
            config.spec.network.http.deny_response_format = HttpDenyResponseFormat::Text;
            config.spec.network.http.network_deny_message = message.map(str::to_owned);
            reject_dropped_cloud_create_fields(&config).unwrap();
            config.spec.network.http.deny_response = true;
            assert_unsupported_config_field(config, "network.http.deny_response (local-only)");
        }
        for field in [
            "deny_message",
            "network_deny_message",
            "secret_deny_message",
        ] {
            for message in ["", "Check policy."] {
                let mut config = base_cloud_config();
                config.spec.network.http = Default::default();
                let http = &mut config.spec.network.http;
                match field {
                    "deny_message" => http.deny_message = Some(message.into()),
                    "network_deny_message" => http.network_deny_message = Some(message.into()),
                    "secret_deny_message" => http.secret_deny_message = Some(message.into()),
                    _ => unreachable!(),
                }
                assert_unsupported_config_field(config, "network.http.deny_response (local-only)");
            }
        }
    }

    #[tokio::test]
    async fn running_cloud_restart_sends_force_and_timeout() {
        let cases = [
            (
                RestartOptions::default(),
                "POST /v1/sandboxes/00000000-0000-0000-0000-000000000002/restart?force=false&timeout=10 HTTP/1.1",
            ),
            (
                RestartOptions {
                    force: true,
                    timeout: Duration::from_millis(2500),
                    detached: true,
                },
                "POST /v1/sandboxes/00000000-0000-0000-0000-000000000002/restart?force=true&timeout=3 HTTP/1.1",
            ),
            (
                RestartOptions {
                    timeout: Duration::from_nanos(1),
                    ..RestartOptions::default()
                },
                "POST /v1/sandboxes/00000000-0000-0000-0000-000000000002/restart?force=false&timeout=1 HTTP/1.1",
            ),
            (
                RestartOptions {
                    timeout: Duration::from_millis(59_001),
                    ..RestartOptions::default()
                },
                "POST /v1/sandboxes/00000000-0000-0000-0000-000000000002/restart?force=false&timeout=60 HTTP/1.1",
            ),
            (
                RestartOptions {
                    timeout: Duration::from_secs(60),
                    ..RestartOptions::default()
                },
                "POST /v1/sandboxes/00000000-0000-0000-0000-000000000002/restart?force=false&timeout=60 HTTP/1.1",
            ),
        ];

        for (options, expected_restart) in cases {
            let server = ScriptedCloud::start(vec![
                (200, cloud_response_json(CloudSandboxStatus::Running)),
                (200, cloud_response_json(CloudSandboxStatus::Running)),
            ])
            .await;
            let handle = server.handle(CloudSandboxStatus::Running);

            let sandbox = handle.restart_with(options).await.unwrap();

            assert_eq!(sandbox.name(), "agent-1");
            assert_eq!(
                server.finish().await,
                [
                    "GET /v1/sandboxes/by-name/agent-1 HTTP/1.1",
                    expected_restart,
                ]
            );
        }
    }

    #[tokio::test]
    async fn stopped_cloud_restart_starts_directly() {
        let server = ScriptedCloud::start(vec![
            (200, cloud_response_json(CloudSandboxStatus::Stopped)),
            (200, cloud_response_json(CloudSandboxStatus::Stopped)),
            (200, cloud_response_json(CloudSandboxStatus::Running)),
        ])
        .await;
        let handle = server.handle(CloudSandboxStatus::Stopped);

        let sandbox = handle
            .restart_with(RestartOptions {
                force: true,
                ..RestartOptions::default()
            })
            .await
            .unwrap();

        assert_eq!(sandbox.name(), "agent-1");
        assert_eq!(
            server.finish().await,
            [
                "GET /v1/sandboxes/by-name/agent-1 HTTP/1.1",
                "GET /v1/sandboxes/00000000-0000-0000-0000-000000000002 HTTP/1.1",
                "POST /v1/sandboxes/00000000-0000-0000-0000-000000000002/start?wait_for=running&wait_timeout=90 HTTP/1.1",
            ]
        );
    }

    #[tokio::test]
    async fn starting_cloud_restart_waits_then_restarts() {
        let server = ScriptedCloud::start(vec![
            (200, cloud_response_json(CloudSandboxStatus::Starting)),
            (200, cloud_response_json(CloudSandboxStatus::Running)),
            (200, cloud_response_json(CloudSandboxStatus::Running)),
        ])
        .await;
        let handle = server.handle(CloudSandboxStatus::Starting);

        let _ = handle.restart().await.unwrap();

        assert_eq!(
            server.finish().await,
            [
                "GET /v1/sandboxes/by-name/agent-1 HTTP/1.1",
                "GET /v1/sandboxes/by-name/agent-1 HTTP/1.1",
                "POST /v1/sandboxes/00000000-0000-0000-0000-000000000002/restart?force=false&timeout=10 HTTP/1.1",
            ]
        );
    }

    #[tokio::test]
    async fn cloud_restart_failures_carry_the_server_message() {
        let boot_failed = r#"{"error":{"code":"restart_boot_failed","message":"the restart failed and the sandbox was stopped"}}"#;
        let unconfirmed = r#"{"error":{"code":"orchestrator_unreachable","message":"could not confirm the restart; check the sandbox status before retrying"}}"#;

        let server = ScriptedCloud::start(vec![
            (200, cloud_response_json(CloudSandboxStatus::Running)),
            (409, boot_failed.to_string()),
        ])
        .await;
        let error = server
            .handle(CloudSandboxStatus::Running)
            .restart()
            .await
            .err()
            .expect("restart must fail");
        assert_eq!(
            server.finish().await,
            [
                "GET /v1/sandboxes/by-name/agent-1 HTTP/1.1",
                "POST /v1/sandboxes/00000000-0000-0000-0000-000000000002/restart?force=false&timeout=10 HTTP/1.1",
            ]
        );

        assert!(
            matches!(
                &error,
                MicrosandboxError::CloudHttp {
                    status: 409,
                    code: Some(code),
                    message,
                } if code == "restart_boot_failed"
                    && message.contains("the sandbox was stopped")
            ),
            "{error:?}"
        );

        let server = ScriptedCloud::start(vec![
            (200, cloud_response_json(CloudSandboxStatus::Running)),
            (503, unconfirmed.to_string()),
        ])
        .await;
        let error = server
            .handle(CloudSandboxStatus::Running)
            .restart()
            .await
            .err()
            .expect("restart must fail");
        assert_eq!(
            server.finish().await,
            [
                "GET /v1/sandboxes/by-name/agent-1 HTTP/1.1",
                "POST /v1/sandboxes/00000000-0000-0000-0000-000000000002/restart?force=false&timeout=10 HTTP/1.1",
            ]
        );

        assert!(
            matches!(
                &error,
                MicrosandboxError::Runtime(message)
                    if message.contains("could not confirm the restart")
            ),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn cloud_restart_refuses_a_replaced_name_before_restarting() {
        let server = ScriptedCloud::start(vec![(
            200,
            cloud_response_json(CloudSandboxStatus::Running),
        )])
        .await;
        let mut stale = cloud_response(CloudSandboxStatus::Running);
        stale.id = "00000000-0000-0000-0000-000000000009".into();
        let handle = SandboxRecord::from_cloud(server.backend.clone(), stale).unwrap();

        let error = handle.restart().await.err().expect("restart must fail");

        assert!(
            matches!(
                &error,
                MicrosandboxError::SandboxReplaced {
                    name,
                    expected,
                    actual,
                } if name == "agent-1"
                    && expected == "cloud:00000000-0000-0000-0000-000000000009"
                    && actual == "cloud:00000000-0000-0000-0000-000000000002"
            ),
            "{error:?}"
        );
        assert_eq!(
            server.finish().await,
            ["GET /v1/sandboxes/by-name/agent-1 HTTP/1.1"]
        );
    }

    #[tokio::test]
    async fn cloud_restart_with_zero_timeout_does_not_dispatch() {
        let server = ScriptedCloud::start(vec![(
            200,
            cloud_response_json(CloudSandboxStatus::Running),
        )])
        .await;

        let error = server
            .handle(CloudSandboxStatus::Running)
            .restart_with(RestartOptions {
                timeout: Duration::ZERO,
                ..RestartOptions::default()
            })
            .await
            .err()
            .expect("restart must fail");

        assert!(
            matches!(error, MicrosandboxError::StopTimeout { ref name, .. } if name == "agent-1"),
            "{error:?}"
        );
        assert_eq!(
            server.finish().await,
            ["GET /v1/sandboxes/by-name/agent-1 HTTP/1.1"]
        );
    }

    #[tokio::test]
    async fn cloud_restart_rejects_timeout_above_server_limit_before_dispatch() {
        for timeout in [
            Duration::from_secs(60) + Duration::from_nanos(1),
            Duration::from_secs(61),
            Duration::MAX,
        ] {
            for force in [false, true] {
                let server = ScriptedCloud::start(vec![(
                    200,
                    cloud_response_json(CloudSandboxStatus::Running),
                )])
                .await;
                let handle = server.handle(CloudSandboxStatus::Running);

                let error = tokio::time::timeout(
                    Duration::from_secs(1),
                    handle.restart_with(RestartOptions {
                        timeout,
                        force,
                        ..RestartOptions::default()
                    }),
                )
                .await
                .expect("invalid timeout must fail before sending a restart request")
                .err()
                .expect("restart must fail");

                assert!(
                    matches!(error, MicrosandboxError::InvalidConfig(ref message)
                        if message == "Cloud restart timeout cannot exceed 60 seconds"),
                    "{error:?}"
                );
                assert_eq!(
                    server.finish().await,
                    ["GET /v1/sandboxes/by-name/agent-1 HTTP/1.1"]
                );
            }
        }
    }

    #[tokio::test]
    async fn cloud_restart_stop_timeout_is_the_local_stop_timeout() {
        let timed_out = r#"{"error":{"code":"restart_stop_timed_out","message":"the sandbox did not stop within the timeout and was not restarted"}}"#;
        let server = ScriptedCloud::start(vec![
            (200, cloud_response_json(CloudSandboxStatus::Running)),
            (409, timed_out.to_string()),
        ])
        .await;

        let error = server
            .handle(CloudSandboxStatus::Running)
            .restart()
            .await
            .err()
            .expect("restart must fail");

        assert!(
            matches!(
                error,
                MicrosandboxError::StopTimeout { ref name, timeout, .. }
                    if name == "agent-1" && timeout == Duration::from_secs(10)
            ),
            "{error:?}"
        );
        assert_eq!(server.finish().await.len(), 2);
    }

    #[tokio::test]
    async fn cloud_restart_starts_after_concurrent_stop() {
        let not_running = r#"{"error":{"code":"sandbox_not_running","message":"cannot restart sandbox in 'stopped' state"}}"#;
        let server = ScriptedCloud::start(vec![
            (200, cloud_response_json(CloudSandboxStatus::Running)),
            (409, not_running.to_string()),
            (200, cloud_response_json(CloudSandboxStatus::Stopped)),
            (200, cloud_response_json(CloudSandboxStatus::Stopped)),
            (200, cloud_response_json(CloudSandboxStatus::Running)),
        ])
        .await;

        let _ = server
            .handle(CloudSandboxStatus::Running)
            .restart()
            .await
            .unwrap();

        assert_eq!(
            server.finish().await,
            [
                "GET /v1/sandboxes/by-name/agent-1 HTTP/1.1",
                "POST /v1/sandboxes/00000000-0000-0000-0000-000000000002/restart?force=false&timeout=10 HTTP/1.1",
                "GET /v1/sandboxes/by-name/agent-1 HTTP/1.1",
                "GET /v1/sandboxes/00000000-0000-0000-0000-000000000002 HTTP/1.1",
                "POST /v1/sandboxes/00000000-0000-0000-0000-000000000002/start?wait_for=running&wait_timeout=90 HTTP/1.1",
            ]
        );
    }

    #[tokio::test]
    async fn cloud_restart_reports_not_running_once_for_a_sandbox_still_running() {
        let not_running =
            r#"{"error":{"code":"sandbox_not_running","message":"sandbox is not running"}}"#;
        let server = ScriptedCloud::start(vec![
            (200, cloud_response_json(CloudSandboxStatus::Running)),
            (409, not_running.to_string()),
            (200, cloud_response_json(CloudSandboxStatus::Running)),
        ])
        .await;

        let error = server
            .handle(CloudSandboxStatus::Running)
            .restart()
            .await
            .err()
            .expect("restart must fail");

        assert!(is_cloud_code(&error, "sandbox_not_running"), "{error:?}");
        assert_eq!(
            server.finish().await,
            [
                "GET /v1/sandboxes/by-name/agent-1 HTTP/1.1",
                "POST /v1/sandboxes/00000000-0000-0000-0000-000000000002/restart?force=false&timeout=10 HTTP/1.1",
                "GET /v1/sandboxes/by-name/agent-1 HTTP/1.1",
            ]
        );
    }

    #[tokio::test]
    async fn cloud_restart_without_api_support_is_unsupported() {
        let server = ScriptedCloud::start(vec![
            (200, cloud_response_json(CloudSandboxStatus::Running)),
            (404, String::new()),
        ])
        .await;
        let error = server
            .handle(CloudSandboxStatus::Running)
            .restart()
            .await
            .err()
            .expect("restart must fail");
        assert!(
            matches!(
                error,
                MicrosandboxError::Unsupported {
                    op: Operation::SandboxRestart,
                    reason: UnsupportedReason::NotAvailable(_),
                }
            ),
            "{error:?}"
        );
        assert_eq!(server.finish().await.len(), 2);

        let missing = r#"{"error":{"code":"sandbox_not_found","message":"sandbox not found"}}"#;
        let server = ScriptedCloud::start(vec![
            (200, cloud_response_json(CloudSandboxStatus::Running)),
            (404, missing.to_string()),
        ])
        .await;
        let error = server
            .handle(CloudSandboxStatus::Running)
            .restart()
            .await
            .err()
            .expect("restart must fail");
        assert!(
            matches!(error, MicrosandboxError::SandboxNotFound(_)),
            "{error:?}"
        );
        assert_eq!(server.finish().await.len(), 2);
    }

    #[tokio::test]
    async fn cloud_boot_error_is_absent_until_the_api_exposes_diagnostics() {
        let backend =
            Arc::new(crate::test_support::cloud_backend("http://127.0.0.1:1", "test-key").unwrap());
        let backend_dyn: Arc<dyn Context> = backend.clone();

        let boot_error = backend
            .boot_error(backend_dyn, "cloud-sandbox")
            .await
            .unwrap();

        assert!(boot_error.is_none());
    }

    #[tokio::test]
    async fn cloud_follow_logs_rejects_bounded_filters_before_opening_stream() {
        let backend =
            Arc::new(crate::test_support::cloud_backend("http://127.0.0.1:1", "test-key").unwrap());
        let now = chrono::Utc::now();

        for opts in [
            LogOptions {
                tail: Some(10),
                ..Default::default()
            },
            LogOptions {
                since: Some(now),
                ..Default::default()
            },
            LogOptions {
                until: Some(now),
                ..Default::default()
            },
        ] {
            let backend_dyn: Arc<dyn Context> = backend.clone();
            let error = match backend
                .follow_logs(backend_dyn, "cloud-sandbox", &opts)
                .await
            {
                Ok(_) => panic!("bounded cloud follow should be unsupported"),
                Err(error) => error,
            };

            assert!(matches!(
                error,
                MicrosandboxError::Unsupported {
                    op: Operation::SandboxFollowLogs,
                    reason: UnsupportedReason::NotAvailable(ref reason),
                } if reason == "bounded cloud log follow filters are not yet available"
            ));
        }
    }

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

        let req = CloudCreateBody::try_from(config).unwrap();

        let CloudCreateSandboxRequest::Oci {
            sandbox,
            reference,
            resources,
            ..
        } = &req.spec
        else {
            panic!("expected OCI create request");
        };
        assert_eq!(sandbox.name, "agent-1");
        assert_eq!(reference, "python:3.12");
        assert_eq!(resources.vcpus, 2);
        assert_eq!(resources.memory_mib, 1024);
        assert_eq!(sandbox.env, vec![EnvVar::new("A", "B")]);
        assert_eq!(sandbox.runtime.workdir.as_deref(), Some("/app"));
        assert_eq!(sandbox.runtime.shell.as_deref(), Some("/bin/bash"));
        assert_eq!(
            sandbox.runtime.entrypoint,
            Some(vec!["python".to_string(), "-u".to_string()])
        );
        assert_eq!(req.slug, None);
        assert_eq!(req.registry, None);
    }

    #[test]
    fn cloud_create_request_orders_direct_config_mounts_parent_first() {
        let mut config = base_cloud_config();
        config.spec.mounts = vec![
            VolumeMount::Tmpfs {
                guest: "/workspace/persist".into(),
                size_mib: None,
                options: MountOptions::default(),
            },
            VolumeMount::Tmpfs {
                guest: "/workspace".into(),
                size_mib: None,
                options: MountOptions::default(),
            },
        ];

        let request = CloudCreateBody::try_from(config).unwrap();

        assert_eq!(
            request
                .spec
                .sandbox_spec()
                .mounts
                .iter()
                .map(|mount| match mount {
                    microsandbox_types::CloudVolumeMount::Bind { guest, .. }
                    | microsandbox_types::CloudVolumeMount::Owned { guest, .. }
                    | microsandbox_types::CloudVolumeMount::Named { guest, .. }
                    | microsandbox_types::CloudVolumeMount::Tmpfs { guest, .. }
                    | microsandbox_types::CloudVolumeMount::DiskImage { guest, .. } => {
                        guest.as_str()
                    }
                })
                .collect::<Vec<_>>(),
            vec!["/workspace", "/workspace/persist"]
        );
    }

    #[test]
    fn cloud_create_retains_canonical_mount_config() {
        let mut config = base_cloud_config();
        config.spec.mounts = vec![
            VolumeMount::Tmpfs {
                guest: "/workspace/persist/.".into(),
                size_mib: None,
                options: MountOptions::default(),
            },
            VolumeMount::Tmpfs {
                guest: "/workspace/".into(),
                size_mib: None,
                options: MountOptions::default(),
            },
        ];

        let (request, config) = cloud_create_body_and_config(config, |_| None).unwrap();
        let retained = config
            .spec
            .mounts
            .iter()
            .map(VolumeMount::guest)
            .collect::<Vec<_>>();
        let sent = request
            .spec
            .sandbox_spec()
            .mounts
            .iter()
            .map(|mount| match mount {
                microsandbox_types::CloudVolumeMount::Bind { guest, .. }
                | microsandbox_types::CloudVolumeMount::Owned { guest, .. }
                | microsandbox_types::CloudVolumeMount::Named { guest, .. }
                | microsandbox_types::CloudVolumeMount::Tmpfs { guest, .. }
                | microsandbox_types::CloudVolumeMount::DiskImage { guest, .. } => guest.as_str(),
            })
            .collect::<Vec<_>>();

        assert_eq!(retained, vec!["/workspace", "/workspace/persist"]);
        assert_eq!(retained, sent);
    }

    #[tokio::test]
    async fn remote_compute_type_is_retained_and_overridden_for_new_sandboxes() {
        let source = crate::context::from_options_json(
            r#"{"kind":"remote","apiKey":"test-key","computeType":"shared"}"#,
        )
        .unwrap();
        let retained =
            crate::context::derive_remote_from_options_json(source.as_ref(), "{}").unwrap();
        let standard = crate::context::derive_remote_from_options_json(
            retained.as_ref(),
            r#"{"computeType":"standard"}"#,
        )
        .unwrap();

        for (context, expected) in [
            (&source, "shared"),
            (&retained, "shared"),
            (&standard, "standard"),
        ] {
            for config in [
                base_cloud_config(),
                base_snapshot_cloud_config(SnapshotReference::id(
                    "00000000-0000-0000-0000-000000000003",
                )),
            ] {
                let (request, config) = context
                    .as_cloud()
                    .unwrap()
                    .build_create_request(SandboxBuilder::from(config))
                    .await
                    .unwrap();
                let json = serde_json::to_value(request).unwrap();
                assert_eq!(json["compute"], serde_json::json!({"type": expected}));
                assert!(json["spec"].get("compute").is_none());
                assert!(json["spec"].get("source").is_some());
                assert!(json.get("source").is_none());
                assert!(serde_json::from_value::<CloudCreateSandboxRequest>(json.clone()).is_err());
                assert!(
                    serde_json::to_value(config)
                        .unwrap()
                        .get("compute")
                        .is_none()
                );
            }
        }
    }

    #[test]
    fn cloud_create_body_preserves_flat_production_contract() {
        let mut config = base_cloud_config();
        config.slug = Some("brave-otter".into());
        config.registry_auth = Some(RegistryAuth::Anonymous);

        let req = CloudCreateBody::try_from(config).unwrap();
        let json = serde_json::to_value(&req).unwrap();

        // The deployed API requires source fields at the top level.
        // An anonymous registry_auth converts to the anonymous selection.
        assert_eq!(json["source"], "oci");
        assert_eq!(json["name"], "agent-1");
        assert_eq!(json["reference"], "python:3.12");
        assert!(json.get("image").is_none());
        assert!(json.get("spec").is_none());
        assert_eq!(json["slug"], "brave-otter");
        assert_eq!(json["registry"]["mode"], "anonymous");

        // Verify every sandbox option survives the envelope change, including
        // fields not explicitly asserted above (network, mounts and lifecycle).
        let mut spec = json;
        spec.as_object_mut().unwrap().remove("slug");
        spec.as_object_mut().unwrap().remove("registry");
        assert_eq!(spec, serde_json::to_value(&req.spec).unwrap());
        let decoded: CloudCreateSandboxRequest = serde_json::from_value(spec.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), spec);
    }

    #[tokio::test]
    async fn cloud_release_smoke_sends_flat_create_body() {
        use crate::test_support::fake_server::{FakeServer, respond};

        let server = FakeServer::start(respond(201, None, CLOUD_SANDBOX_RESPONSE_FIXTURE)).await;
        let backend = server.backend();
        let _sandbox = tokio::time::timeout(
            Duration::from_secs(5),
            backend
                .sandboxes()
                .builder("release-smoke-123-1")
                .image("mirror.gcr.io/library/alpine:3.20")
                .cpus(1)
                .memory(512)
                .ephemeral(true)
                .max_duration(Duration::from_secs(600))
                .idle_timeout(Duration::from_secs(120))
                .create(),
        )
        .await
        .unwrap()
        .unwrap();

        // Exercise the HTTP path used by all language bindings, not only the
        // serializer. Pin the same settings as the production release smoke.
        let request = server.only_request();
        assert_eq!(request.method, "POST");
        assert_eq!(
            request.target,
            "/v1/sandboxes?start=true&wait_for=running&wait_timeout=90"
        );
        let body: serde_json::Value = serde_json::from_str(&request.body).unwrap();
        assert!(body.get("spec").is_none());
        assert!(body.get("compute").is_none());
        assert_eq!(body["source"], "oci");
        assert_eq!(body["name"], "release-smoke-123-1");
        assert_eq!(body["reference"], "mirror.gcr.io/library/alpine:3.20");
        assert_eq!(body["resources"]["vcpus"], 1);
        assert_eq!(body["resources"]["memory_mib"], 512);
        assert_eq!(body["lifecycle"]["ephemeral"], true);
        assert_eq!(body["lifecycle"]["max_duration_secs"], 600);
        assert_eq!(body["lifecycle"]["idle_timeout_secs"], 120);
        serde_json::from_value::<CloudCreateSandboxRequest>(body.clone()).unwrap();
    }

    #[test]
    fn cloud_create_body_omits_unset_create_options() {
        let req = CloudCreateBody::try_from(base_cloud_config()).unwrap();
        let json = serde_json::to_value(&req).unwrap();

        assert!(json.get("slug").is_none());
        assert!(json.get("registry").is_none());
    }

    #[test]
    fn cloud_create_body_maps_bare_snapshot_id_to_managed_restore() {
        let config = base_snapshot_cloud_config(SnapshotReference::id(
            "00000000-0000-0000-0000-000000000003",
        ));

        let req = CloudCreateBody::try_from(config).unwrap();
        assert!(matches!(
            req.spec.disk_snapshot_ref().unwrap(),
            CloudSnapshotLocation::Managed { id }
                if id == "00000000-0000-0000-0000-000000000003"
        ));
        let json = serde_json::to_value(req).unwrap();
        assert_eq!(json["source"], "disk_snapshot");
        assert!(json.get("image").is_none());
        assert!(json.get("patches").is_none());
        assert!(json["resources"].get("disk_size_mib").is_none());
    }

    #[test]
    fn cloud_create_body_maps_path_like_snapshot_to_host_volume_restore() {
        for path in ["snapshots/post-setup", "./snapshots/post-setup"] {
            let config = base_snapshot_cloud_config(SnapshotReference::path(path));

            let req = CloudCreateBody::try_from(config).unwrap();
            assert!(matches!(
                req.spec.disk_snapshot_ref().unwrap(),
                CloudSnapshotLocation::HostVolume { path: actual } if actual == path
            ));
        }
    }

    #[test]
    fn cloud_snapshot_restore_rejects_rootfs_overrides_in_manual_configs() {
        let mut image_config = base_cloud_config();
        image_config.snapshot_reference = Some(SnapshotReference::id("snapshot-id"));
        assert_unsupported_config_field(image_config, "rootfs with from_snapshot");

        let mut disk_config = base_cloud_config();
        disk_config.snapshot_reference = Some(SnapshotReference::id("snapshot-id"));
        let RootfsSource::Oci(oci) = &mut disk_config.spec.image else {
            panic!("fixture must use an OCI image");
        };
        oci.reference.clear();
        oci.root_disk = Some(RootDisk::managed(8192));
        assert_unsupported_config_field(disk_config, "rootfs with from_snapshot");
    }

    #[test]
    fn cloud_snapshot_restore_rejects_local_only_restore_choices() {
        let cases: [(&str, ConfigMutation); 5] = [
            ("forked", |config| config.forked = true),
            ("disk_only", |config| {
                config.snapshot_restore_mode =
                    crate::sandbox::config::SnapshotRestoreMode::DiskOnly;
            }),
            ("snapshot_base", |config| {
                config.snapshot_base = Some("base".into())
            }),
            ("inherit_resources", |config| {
                config.restore_resources.inherit = true
            }),
            ("captured resources", |config| {
                config.restore_resources.captured.insert("/data".into());
            }),
        ];
        for (field, mutate) in cases {
            let mut config = base_snapshot_cloud_config(SnapshotReference::id("saved"));
            mutate(&mut config);
            // The request converter is the pre-HTTP boundary, so no cloud
            // destination can be allocated for an unsupported restore choice.
            assert_unsupported_config_field(config, field);
        }
    }

    #[test]
    fn cloud_disk_restore_retains_destination_boot_and_lifecycle_settings() {
        let mut config = base_snapshot_cloud_config(SnapshotReference::id("saved"));
        config.spec.resources.cpus = 2;
        config.spec.resources.max_cpus = 2;
        config.spec.resources.memory_mib = 1024;
        config.spec.resources.max_memory_mib = 1024;
        config.spec.security_profile = microsandbox_types::SecurityProfile::Restricted;
        let mut options = crate::SandboxConfigPatch::new();
        options.spec.security_profile = Some(config.spec.security_profile);
        config.caller_config_overrides = Some(Box::new(options));
        config.spec.lifecycle.max_duration_secs = Some(60);
        config.spec.lifecycle.idle_timeout_secs = Some(10);

        let request = CloudCreateBody::try_from(config).unwrap();
        let json = serde_json::to_value(request).unwrap();
        assert_eq!(json["source"], "disk_snapshot");
        assert_eq!(json["resources"]["vcpus"], 2);
        assert_eq!(json["resources"]["memory_mib"], 1024);
        assert_eq!(json["security_profile"], "restricted");
        assert_eq!(json["lifecycle"]["max_duration_secs"], 60);
        assert_eq!(json["lifecycle"]["idle_timeout_secs"], 10);
    }

    #[tokio::test]
    async fn cloud_create_preserves_remote_root_paths_without_local_resolution() {
        let cloud = test_support::cloud_backend("http://127.0.0.1:1", "test-key").unwrap();
        for (rootfs, source, path) in [
            (
                RootfsSource::Bind {
                    path: "missing-remote-root/../rootfs".into(),
                    follow_root_symlinks: false,
                },
                "bind",
                "missing-remote-root/../rootfs",
            ),
            (
                RootfsSource::DiskImage {
                    path: "remote-disks/rootfs.img".into(),
                    format: crate::sandbox::DiskImageFormat::Raw,
                    fstype: Some("ext4".into()),
                },
                "disk_image",
                "remote-disks/rootfs.img",
            ),
        ] {
            let mut config = base_cloud_config();
            config.spec.image = rootfs;
            let (request, config) = cloud
                .build_create_request(SandboxBuilder::from(config))
                .await
                .unwrap();
            let body = serde_json::to_value(request).unwrap();
            assert_eq!(body["source"], source);
            assert_eq!(body["path"], path);
            match config.spec.image {
                RootfsSource::Bind { path: retained, .. }
                | RootfsSource::DiskImage { path: retained, .. } => {
                    assert_eq!(retained, Path::new(path))
                }
                _ => panic!("remote root source changed"),
            }
        }

        let mut config = base_cloud_config();
        config.spec.image = RootfsSource::Bind {
            path: "rootfs".into(),
            follow_root_symlinks: true,
        };
        assert_unsupported_config_field(config, "rootfs follow_root_symlinks");
    }

    #[test]
    fn cloud_create_request_rejects_flat_root_disk() {
        let mut config = base_cloud_config();
        if let RootfsSource::Oci(oci) = &mut config.spec.image {
            oci.root_disk = Some(RootDisk::Flat {
                size_mib: Some(8192),
                fstype: None,
                clone: microsandbox_types::FlatClone::Auto,
            });
        }

        let err = CloudCreateBody::try_from(config).unwrap_err();
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
                    root_disk: None,
                }),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn base_snapshot_cloud_config(reference: SnapshotReference) -> SandboxConfig {
        let mut config = base_cloud_config();
        let RootfsSource::Oci(oci) = &mut config.spec.image else {
            panic!("fixture must use an OCI image");
        };
        oci.reference.clear();
        config.snapshot_reference = Some(reference);
        config
    }

    #[test]
    fn cloud_create_request_rejects_replace_existing() {
        let mut config = base_cloud_config();
        config.replace_existing = true;
        let err = CloudCreateBody::try_from(config).unwrap_err();
        assert!(matches!(err, MicrosandboxError::Unsupported { .. }));
    }

    #[test]
    fn cloud_create_request_maps_previously_deferred_spec_fields() {
        // These spec fields ride in the create body now; assert they map
        // instead of erroring.
        let mut config = base_cloud_config();
        config.spec.init = Some(crate::sandbox::HandoffInit {
            cmd: "/sbin/init".into(),
            args: Vec::new(),
            env: Vec::new(),
        });
        config.spec.pull_policy = crate::sandbox::PullPolicy::Always;
        config.spec.runtime.cmd = Some(vec!["python".into(), "app.py".into()]);
        config.spec.rlimits.push(crate::sandbox::exec::Rlimit {
            resource: crate::sandbox::exec::RlimitResource::Nofile,
            soft: 1024,
            hard: 2048,
        });
        if let RootfsSource::Oci(oci) = &mut config.spec.image {
            oci.root_disk = Some(RootDisk::managed(8192));
        }

        let req = CloudCreateBody::try_from(config).unwrap();

        let CloudCreateSandboxRequest::Oci {
            sandbox,
            resources,
            pull_policy,
            ..
        } = &req.spec
        else {
            panic!("expected OCI create request");
        };
        assert!(sandbox.init.is_some());
        assert_eq!(*pull_policy, microsandbox_types::CloudPullPolicy::Always);
        assert_eq!(
            sandbox.runtime.cmd,
            Some(vec!["python".to_string(), "app.py".to_string()])
        );
        assert_eq!(sandbox.rlimits.len(), 1);
        assert_eq!(resources.disk_size_mib, Some(8192));
    }

    #[test]
    fn cloud_create_body_maps_basic_registry_auth_to_inline() {
        let mut config = base_cloud_config();
        config.registry_auth = Some(RegistryAuth::Basic {
            username: "u".into(),
            password: "p".into(),
        });
        let req = CloudCreateBody::try_from(config).unwrap();
        let json = serde_json::to_value(&req).unwrap();

        assert_eq!(json["registry"]["mode"], "inline");
        assert_eq!(json["registry"]["username"], "u");
        assert_eq!(json["registry"]["password"], "p");
        // The credentials ride only in the registry section of the body.
        let body = serde_json::to_string(&json).unwrap();
        assert_eq!(body.matches("\"p\"").count(), 1);
    }

    #[test]
    fn cloud_create_request_rejects_insecure() {
        let mut config = base_cloud_config();
        config.insecure = true;
        let err = CloudCreateBody::try_from(config).unwrap_err();
        assert!(matches!(err, MicrosandboxError::Unsupported { .. }));
    }

    #[test]
    fn cloud_create_request_rejects_ca_certs() {
        let mut config = base_cloud_config();
        config
            .ca_certs
            .push(b"-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----".to_vec());
        let err = CloudCreateBody::try_from(config).unwrap_err();
        assert!(matches!(err, MicrosandboxError::Unsupported { .. }));
    }

    #[test]
    fn cloud_create_request_rejects_image_cache_dir() {
        let mut config = base_cloud_config();
        config.image_cache_dir = Some(std::path::PathBuf::from("/tmp/org-cache"));
        let err = CloudCreateBody::try_from(config).unwrap_err();
        assert!(matches!(err, MicrosandboxError::Unsupported { .. }));
    }

    #[test]
    fn cloud_create_translates_previous_version_secret_policies() {
        for raw in [
            include_str!("../../db/fixtures/config-0.6.18-secret-default.json"),
            include_str!("../../db/fixtures/config-0.6.18-global-passthrough.json"),
            // Hand-extended released fixture: inheritance, blocking override, and entry passthrough.
            include_str!("../../db/fixtures/config-0.6.18-global-passthrough-with-entries.json"),
            include_str!("../../db/fixtures/config-0.6.18-secret-passthrough.json"),
        ] {
            let legacy = test_support::fixtures::decode(raw).unwrap();
            let mut config = base_cloud_config();
            let expected = serde_json::to_value(&legacy.spec.network.secrets).unwrap();
            config.spec.network.secrets = legacy.spec.network.secrets;
            let request = CloudCreateBody::try_from(config).unwrap();
            let secrets = &request.spec.sandbox_spec().network.secrets;
            let wire = serde_json::to_value(secrets.as_ref().unwrap()).unwrap();
            let decoded: CloudSecretsConfig = serde_json::from_value(wire).unwrap();
            let domain = SecretsConfig::from(decoded);
            assert_eq!(serde_json::to_value(domain).unwrap(), expected);
        }
    }

    #[test]
    fn cloud_create_request_rejects_fields_missing_from_the_wire() {
        let cases: [(&str, ConfigMutation); 13] = [
            ("max_cpus", |config| config.spec.resources.max_cpus = 2),
            ("max_memory", |config| {
                config.spec.resources.max_memory_mib = 1024
            }),
            ("hostname", |config| {
                config.spec.runtime.hostname = Some("worker".into())
            }),
            ("nested_virt (local-only)", |config| {
                config.spec.resources.nested_virt = Some(true)
            }),
            ("guest_clock", |config| {
                config.spec.runtime.guest_clock = Some(microsandbox_types::GuestClockPolicy::Off)
            }),
            ("metrics_sample_interval", |config| {
                config.spec.runtime.metrics_sample_interval_ms = Some(2500)
            }),
            ("disable_metrics_sample", |config| {
                config.spec.runtime.disable_metrics_sample = true
            }),
            ("network.interface", |config| {
                config.spec.network.interface = Some(microsandbox_types::InterfaceOverrides {
                    mtu: Some(1400),
                    ..Default::default()
                })
            }),
            ("network.nat64_prefixes", |config| {
                config.spec.network.nat64_prefixes = vec!["2001:db8::/96".parse().unwrap()];
            }),
            ("network.nat64_prefixes", |config| {
                config.spec.network.nat64_prefixes.clear();
            }),
            ("network.tls", |config| {
                let mut tls = TlsConfig::default();
                tls.bypass.push("*.internal.example".into());
                config.spec.network.tls = Some(tls);
            }),
            ("from_snapshot", |config| {
                config.snapshot_upper_source = Some("snapshot/upper.ext4".into())
            }),
            ("from_snapshot", |config| {
                config.snapshot_archive_source = Some("snapshot.tar.zst".into())
            }),
        ];

        for (field, mutate) in cases {
            let mut config = base_cloud_config();
            mutate(&mut config);

            assert_unsupported_config_field(config, field);
        }
    }

    #[test]
    fn cloud_create_request_rejects_non_managed_oci_root_disks() {
        for root_disk in [
            RootDisk::tmpfs(256),
            RootDisk::DiskImage {
                path: "upper.raw".into(),
                format: crate::sandbox::DiskImageFormat::Raw,
                fstype: Some("ext4".into()),
            },
        ] {
            let mut config = base_cloud_config();
            let RootfsSource::Oci(oci) = &mut config.spec.image else {
                panic!("fixture must use an OCI image");
            };
            oci.root_disk = Some(root_disk);

            assert_unsupported_config_field(config, "non-managed root_disk");
        }
    }

    #[test]
    fn cloud_create_request_rejects_inline_named_volume_creation() {
        let mut config = base_cloud_config();
        config.spec.mounts.push(VolumeMount::Named {
            name: "cache".into(),
            guest: "/cache".into(),
            create: Some(NamedVolumeCreate {
                mode: NamedVolumeMode::EnsureExists,
                name: "cache".into(),
                kind: VolumeKind::Directory,
                quota_mib: None,
                capacity_mib: None,
                labels: Vec::new(),
            }),
            options: MountOptions::default(),
            stat_virtualization: StatVirtualization::Strict,
            host_permissions: HostPermissions::Private,
            follow_root_symlinks: false,
        });

        assert_unsupported_config_field(config, "named volume inline create");
    }

    #[test]
    fn cloud_create_rejects_owned_storage_before_sending_request() {
        for mount in [
            crate::sandbox::MountBuilder::new("/data")
                .owned()
                .build()
                .unwrap(),
            crate::sandbox::MountBuilder::new("/data")
                .owned_with(|v| v.disk().size(512_u32))
                .build()
                .unwrap(),
        ] {
            let mut config = base_cloud_config();
            config.spec.mounts.push(mount);
            assert_unsupported_config_field(config, "sandbox-owned volumes");
        }
    }

    #[test]
    fn cloud_restore_does_not_silently_drop_missing_resource_opt_out() {
        let mut config = base_cloud_config();
        config.restore_resources.allow_missing = true;
        assert_unsupported_config_field(config, "allow_missing_resources");
    }

    #[test]
    fn cloud_create_request_preserves_mount_owner() {
        let mut config = base_cloud_config();
        config.spec.mounts.push(VolumeMount::Bind {
            host: "/host/data".into(),
            guest: "/data".into(),
            options: MountOptions {
                override_uid: Some(1000),
                override_gid: Some(1000),
                ..MountOptions::default()
            },
            stat_virtualization: StatVirtualization::Strict,
            host_permissions: HostPermissions::Private,
            follow_root_symlinks: false,
            quota_mib: None,
        });

        let request = CloudCreateBody::try_from(config).unwrap();
        let body = serde_json::to_value(request).unwrap();
        assert_eq!(body["mounts"][0]["options"]["override_uid"], 1000);
        assert_eq!(body["mounts"][0]["options"]["override_gid"], 1000);
    }

    #[test]
    fn cloud_create_request_accepts_harmless_omitted_defaults() {
        let mut config = base_cloud_config();
        config.spec.resources.cpus = 2;
        config.spec.resources.max_cpus = 2;
        config.spec.resources.memory_mib = 1024;
        config.spec.resources.max_memory_mib = 1024;
        config.spec.network.interface = Some(Default::default());
        config.spec.network.tls = Some(TlsConfig::default());
        config.spec.mounts.push(VolumeMount::Named {
            name: "cache".into(),
            guest: "/cache".into(),
            create: None,
            options: MountOptions::default(),
            stat_virtualization: StatVirtualization::Strict,
            host_permissions: HostPermissions::Private,
            // Resolution is intentionally selected by the cloud volume
            // service, so this local-only switch must not reject the request.
            follow_root_symlinks: true,
        });

        let req = CloudCreateBody::try_from(config).unwrap();

        let CloudCreateSandboxRequest::Oci {
            sandbox, resources, ..
        } = &req.spec
        else {
            panic!("expected OCI create request");
        };
        assert_eq!(resources.vcpus, 2);
        assert_eq!(resources.memory_mib, 1024);
        assert_eq!(sandbox.mounts.len(), 1);
    }

    #[cfg(feature = "net")]
    #[tokio::test]
    async fn cloud_create_request_accepts_tls_enabled_by_secret_helper() {
        let config = SandboxBuilder::new("agent-1")
            .image("python:3.12")
            .secret_env("API_KEY", "secret", "api.example.com")
            .build()
            .await
            .unwrap();

        let req = CloudCreateBody::try_from(config).unwrap();

        assert_eq!(
            req.spec
                .sandbox_spec()
                .network
                .secrets
                .as_ref()
                .map(|secrets| secrets.entries.len()),
            Some(1),
        );
    }

    #[cfg(feature = "net")]
    #[tokio::test]
    async fn cloud_create_resolves_env_secret_only_in_request() {
        let config = cloud_config_with_secret_source(SecretSource::Env {
            var: "API_KEY_VAR".into(),
        })
        .await;
        let mut resolved_vars = Vec::new();

        let (request, retained) = cloud_create_body_and_config(config, |var| {
            resolved_vars.push(var.to_owned());
            Some(CloudSecretValue::new("material"))
        })
        .unwrap();

        let sent = &request
            .spec
            .sandbox_spec()
            .network
            .secrets
            .as_ref()
            .unwrap()
            .entries[0];
        assert_eq!(sent.value, "material");
        assert!(sent.source.is_none());
        assert_eq!(resolved_vars, vec!["API_KEY_VAR"]);

        let retained = &retained.spec.network.secrets.as_ref().unwrap().secrets[0];
        assert!(retained.value.is_empty());
        assert!(matches!(
            retained.source.as_ref(),
            Some(SecretSource::Env { var }) if var == "API_KEY_VAR"
        ));
    }

    #[cfg(feature = "net")]
    #[tokio::test]
    async fn cloud_create_env_secret_source_wins_over_value() {
        let mut config = cloud_config_with_secret_source(SecretSource::Env {
            var: "API_KEY_VAR".into(),
        })
        .await;
        config.spec.network.secrets.as_mut().unwrap().secrets[0].value =
            Zeroizing::new("inline".into());

        let (request, _) =
            cloud_create_body_and_config(config, |_| Some(CloudSecretValue::new("material")))
                .unwrap();

        let sent = &request
            .spec
            .sandbox_spec()
            .network
            .secrets
            .as_ref()
            .unwrap()
            .entries[0];
        assert_eq!(sent.value, "material");
        assert!(sent.source.is_none());
    }

    #[cfg(feature = "net")]
    #[tokio::test]
    async fn cloud_create_store_secret_source_with_value_is_refused() {
        let mut config = cloud_config_with_secret_source(SecretSource::Store {
            reference: "vault-key".into(),
        })
        .await;
        config.spec.network.secrets.as_mut().unwrap().secrets[0].value =
            Zeroizing::new("inline".into());

        let error = cloud_create_body_and_config(config, |_| {
            panic!("store source must not call the environment resolver")
        })
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("store-backed secret sources are not supported yet")
        );
    }

    #[cfg(feature = "net")]
    #[tokio::test]
    async fn cloud_create_rejects_missing_or_empty_env_secret() {
        for (resolved, expected) in [
            (None, "is not set"),
            (Some(CloudSecretValue::new("")), "is empty"),
        ] {
            let config = cloud_config_with_secret_source(SecretSource::Env {
                var: "API_KEY_VAR".into(),
            })
            .await;

            let error = cloud_create_body_and_config(config, |_| resolved.clone()).unwrap_err();

            assert!(matches!(error, MicrosandboxError::InvalidConfig(_)));
            let message = error.to_string();
            assert!(message.contains("API_KEY_VAR"));
            assert!(message.contains(expected));
        }
    }

    #[cfg(feature = "net")]
    #[tokio::test]
    async fn cloud_create_rejects_store_secret_source() {
        let config = cloud_config_with_secret_source(SecretSource::Store {
            reference: "vault-key".into(),
        })
        .await;

        let error = cloud_create_body_and_config(config, |_| {
            panic!("store source must not call the environment resolver")
        })
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("store-backed secret sources are not supported yet")
        );
    }

    #[cfg(feature = "net")]
    async fn cloud_config_with_secret_source(source: SecretSource) -> SandboxConfig {
        SandboxBuilder::new("agent-1")
            .image("python:3.12")
            .secret(|secret| {
                secret
                    .env("API_KEY")
                    .source(source)
                    .allow("api.example.com")
            })
            .build()
            .await
            .unwrap()
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
        let err = CloudCreateBody::try_from(config).unwrap_err();
        assert!(matches!(err, MicrosandboxError::Unsupported { .. }));
    }

    #[cfg(feature = "net")]
    #[test]
    fn cloud_create_request_rejects_rate_limiters() {
        let mut config = base_cloud_config();
        config.spec.network.rate_limiter = Some(microsandbox_types::NetworkRateLimiterConfig {
            egress: None,
            ingress: Some(microsandbox_types::RateLimiterConfig {
                bandwidth: Some(microsandbox_types::TokenBucketConfig {
                    size: 1024 * 1024,
                    refill_time_ms: 1000,
                    one_time_burst: 0,
                }),
                ops: None,
            }),
        });
        let err = CloudCreateBody::try_from(config).unwrap_err();
        assert!(matches!(err, MicrosandboxError::Unsupported { .. }));
    }

    #[cfg(feature = "net")]
    #[test]
    fn cloud_create_request_rejects_outbound_proxy() {
        let mut config = base_cloud_config();
        config.spec.network.outbound_proxy = Some(microsandbox_types::OutboundProxy::Socks5 {
            address: "127.0.0.1:1080".to_string(),
            credentials: None,
        });

        assert_unsupported_config_field(config, "network.outbound_proxy");
    }

    #[test]
    fn cloud_create_request_rejects_tcp_accept_queue_size() {
        let mut config = base_cloud_config();
        config.spec.network.tcp_accept_queue_size = Some(4096);

        assert_unsupported_config_field(config, "network.tcp_accept_queue_size");
    }

    #[test]
    fn sandbox_config_from_cloud_round_trips_d13_fields() {
        // The cloud response carries the source-tagged create request, which
        // converts back into the shared `SandboxSpec`. Populate a full spec and
        // assert the fields the wire request carries survive the round-trip;
        // fields with no cloud representation (like the runtime hostname) are
        // not carried back.
        let mut spec = SandboxSpec {
            name: "agent-1".into(),
            image: RootfsSource::Oci(OciRootfsSource {
                reference: "python:3.12".into(),
                root_disk: None,
            }),
            env: vec![EnvVar::new("A", "B")],
            ..Default::default()
        };
        spec.resources.cpus = 4;
        spec.resources.memory_mib = 2048;
        spec.runtime.workdir = Some("/app".into());
        spec.runtime.shell = Some("/bin/bash".into());
        spec.runtime.entrypoint = Some(vec!["python".into(), "-u".into()]);
        spec.runtime.hostname = Some("worker".into());
        spec.runtime.user = Some("appuser".into());
        spec.runtime.log_level = Some(SandboxLogLevel::Debug);
        spec.runtime
            .scripts
            .insert("setup".into(), "echo hi".into());
        spec.lifecycle.max_duration_secs = Some(3600);
        spec.lifecycle.idle_timeout_secs = Some(600);

        let cloud = CloudCreateSandboxResponse {
            id: "00000000-0000-0000-0000-000000000002".into(),
            org_id: "00000000-0000-0000-0000-000000000001".into(),
            name: "agent-1".into(),
            slug: "brave-otter".into(),
            status: CloudSandboxStatus::Running,
            status_reason: None,
            spec: Some(serde_json::to_value(CloudCreateSandboxRequest::from(spec)).unwrap()),
            ephemeral: true,
            created_at: chrono::Utc::now(),
            started_at: None,
            stopped_at: None,
            last_failure_message: None,
        };

        let config = sandbox_config_from_cloud(&cloud).unwrap();

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
        assert_eq!(config.spec.runtime.hostname, None);
        assert_eq!(config.spec.runtime.user.as_deref(), Some("appuser"));
        assert_eq!(config.spec.runtime.log_level, Some(SandboxLogLevel::Debug),);
        assert_eq!(
            config.spec.runtime.scripts.get("setup"),
            Some(&"echo hi".to_string())
        );
        assert_eq!(config.spec.lifecycle.max_duration_secs, Some(3600));
        assert_eq!(config.spec.lifecycle.idle_timeout_secs, Some(600));
    }

    #[test]
    fn sandbox_config_from_cloud_keeps_supported_fields_and_ignores_others() {
        let mut cloud = cloud_response(CloudSandboxStatus::Running);
        cloud.spec = Some(serde_json::json!({
            "image": "python:3.12",
            "resources": {
                "vcpus": 4,
                "memory_mib": 2048,
                "disk_size_mib": 8192
            },
            "runtime": {
                "workdir": "/app",
                "shell": "/bin/bash",
                "scripts": { "setup": "echo hi" },
                "entrypoint": ["python", "-u"],
                "cmd": ["main.py"],
                "hostname": "ignored-hostname",
                "user": "appuser",
                "log_level": "debug"
            },
            "env": [{ "key": "A", "value": "B" }],
            "labels": { "tier": "test" },
            "lifecycle": {
                "max_duration_secs": 3600,
                "idle_timeout_secs": 600
            }
        }));

        let config = sandbox_config_from_cloud(&cloud).unwrap();

        assert_eq!(config.spec.name, "agent-1");
        assert!(
            matches!(config.spec.image, RootfsSource::Oci(ref s) if s.reference == "python:3.12")
        );
        assert_eq!(config.spec.resources.cpus, 4);
        assert_eq!(config.spec.resources.max_cpus, 4);
        assert_eq!(config.spec.resources.memory_mib, 2048);
        assert_eq!(config.spec.resources.max_memory_mib, 2048);
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
        assert_eq!(config.spec.runtime.cmd, Some(vec!["main.py".to_string()]));
        assert_eq!(
            config.spec.runtime.hostname.as_deref(),
            Some("ignored-hostname")
        );
        assert_eq!(config.spec.runtime.user.as_deref(), Some("appuser"));
        assert_eq!(config.spec.runtime.log_level, Some(SandboxLogLevel::Debug));
        assert_eq!(
            config.spec.runtime.scripts.get("setup"),
            Some(&"echo hi".to_string())
        );
        assert_eq!(config.spec.lifecycle.max_duration_secs, Some(3600));
        assert_eq!(config.spec.lifecycle.idle_timeout_secs, Some(600));
        assert_eq!(
            config.spec.labels.get("tier").map(String::as_str),
            Some("test")
        );
    }

    #[test]
    fn sandbox_config_from_cloud_decodes_api_spec_projection() {
        let cloud: CloudCreateSandboxResponse =
            serde_json::from_str(CLOUD_SANDBOX_RESPONSE_FIXTURE).unwrap();

        let config = sandbox_config_from_cloud(&cloud).unwrap();

        assert_eq!(config.spec.name, "spec-decode");
        assert!(matches!(
            config.spec.image,
            RootfsSource::Oci(ref image)
                if image.reference == "alpine:3.20"
                    && image.root_disk == Some(RootDisk::managed(4096))
        ));
        assert_eq!(config.spec.resources.cpus, 1);
        assert_eq!(config.spec.resources.memory_mib, 512);
        assert_eq!(
            config.spec.runtime.entrypoint,
            Some(vec!["/bin/sh".to_string(), "-c".to_string()])
        );
        assert_eq!(
            config.spec.runtime.cmd,
            Some(vec!["printf attached".to_string()])
        );
        assert_eq!(config.spec.runtime.workdir.as_deref(), Some("/tmp"));
        assert_eq!(config.spec.runtime.shell.as_deref(), Some("/bin/ash"));
        assert_eq!(config.spec.runtime.user.as_deref(), Some("nobody"));
        assert_eq!(config.spec.env, vec![EnvVar::new("FOO", "bar")]);
        assert_eq!(config.spec.lifecycle.max_duration_secs, Some(900));
    }

    #[test]
    fn sandbox_config_from_cloud_preserves_inspected_runtime_settings() {
        // Inspection is a provider projection, not a source-tagged create request.
        // These values must survive get/connect even though mount sources and
        // private secret material are deliberately absent from that projection.
        let mut cloud = cloud_response(CloudSandboxStatus::Running);
        cloud.spec = Some(serde_json::json!({
            "image": "python",
            "resources": { "vcpus": 2, "memory_mib": 512 },
            "runtime": {
                "shell": "/bin/bash",
                "entrypoint": ["printf"],
                "cmd": ["configured-default"],
                "workdir": "/tmp",
                "user": "1000",
                "scripts": { "check": "printf checked" }
            },
            "env": [{ "key": "CONFIG_TEST", "value": "retained" }],
            "labels": {},
            "rlimits": [],
            "lifecycle": { "ephemeral": false },
            "mounts": [],
            "network": { "enabled": true, "ports": [], "trust_host_cas": false }
        }));

        let config = sandbox_config_from_cloud(&cloud).unwrap();

        assert_eq!(config.spec.runtime.shell.as_deref(), Some("/bin/bash"));
        assert_eq!(config.spec.runtime.workdir.as_deref(), Some("/tmp"));
        assert_eq!(config.spec.runtime.user.as_deref(), Some("1000"));
        assert_eq!(config.spec.runtime.entrypoint, Some(vec!["printf".into()]));
        assert_eq!(
            config.spec.runtime.cmd,
            Some(vec!["configured-default".into()])
        );
        assert_eq!(config.spec.runtime.scripts["check"], "printf checked");
        assert_eq!(
            config.spec.env,
            vec![EnvVar::new("CONFIG_TEST", "retained")]
        );
    }

    #[test]
    fn sandbox_config_from_cloud_rejects_malformed_runtime_settings() {
        for runtime in [
            serde_json::json!({ "shell": 42 }),
            serde_json::json!({ "entrypoint": "printf" }),
            serde_json::json!({ "workdir": [] }),
        ] {
            let mut cloud = cloud_response(CloudSandboxStatus::Running);
            cloud.spec = Some(serde_json::json!({ "image": "python", "runtime": runtime }));
            assert!(sandbox_config_from_cloud(&cloud).is_err());
        }
    }

    #[test]
    fn sandbox_config_from_cloud_does_not_require_spec() {
        let mut cloud = cloud_response(CloudSandboxStatus::Stopped);
        cloud.spec = None;

        let config = sandbox_config_from_cloud(&cloud).unwrap();

        assert_eq!(config.spec.name, cloud.name);
        assert_eq!(config.spec.runtime.shell, None);
    }

    #[test]
    fn sandbox_config_from_cloud_accepts_curated_spec() {
        let mut cloud = cloud_response(CloudSandboxStatus::Stopped);
        cloud.spec = Some(serde_json::json!({
            "image": "alpine:3.19",
            "resources": { "vcpus": 1 }
        }));

        let config = sandbox_config_from_cloud(&cloud).unwrap();

        assert_eq!(config.spec.name, cloud.name);
        assert!(matches!(
            config.spec.image,
            RootfsSource::Oci(ref image) if image.reference == "alpine:3.19"
        ));
        assert_eq!(config.spec.resources.cpus, 1);
        assert_eq!(config.spec.runtime.shell, None);
    }

    #[tokio::test]
    async fn reconnect_exec_uses_spec_returned_by_cloud_api() {
        use microsandbox_protocol::{
            codec,
            core::Ready,
            exec::{ExecExited, ExecRequest, ExecStarted},
            message::{Message, MessageType},
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut requests = Vec::new();

            while requests.len() < 2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut peeked = [0; 4096];
                let request_len = tokio::time::timeout(Duration::from_secs(5), async {
                    loop {
                        let request_len = stream.peek(&mut peeked).await.unwrap();
                        if peeked[..request_len].contains(&b'\n') {
                            break request_len;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                let request_line = std::str::from_utf8(&peeked[..request_len])
                    .unwrap()
                    .lines()
                    .next()
                    .unwrap();

                if request_line == "GET /v1/sandboxes/by-name/spec-decode HTTP/1.1"
                    || request_line
                        == "GET /v1/sandboxes/00000000-0000-0000-0000-0000000000a1 HTTP/1.1"
                {
                    let mut request = Vec::new();
                    while !request.ends_with(b"\r\n\r\n") {
                        request.push(stream.read_u8().await.unwrap());
                    }
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        CLOUD_SANDBOX_RESPONSE_FIXTURE.len(),
                        CLOUD_SANDBOX_RESPONSE_FIXTURE
                    );
                    stream.write_all(response.as_bytes()).await.unwrap();
                    continue;
                }

                assert_eq!(
                    request_line,
                    "GET /v1/sandboxes/00000000-0000-0000-0000-0000000000a1/agent HTTP/1.1"
                );
                let websocket = tokio_tungstenite::accept_async(stream).await.unwrap();
                let mut io = WsByteStream::new(websocket);
                io.write_all(&1u32.to_be_bytes()).await.unwrap();
                io.write_all(&1024u32.to_be_bytes()).await.unwrap();
                let ready =
                    Message::with_payload(MessageType::Ready, 0, &Ready::default()).unwrap();
                codec::write_message(&mut io, &ready).await.unwrap();

                let message = codec::read_message(&mut io).await.unwrap();
                assert_eq!(message.t, MessageType::ExecRequest);
                let request = message.payload::<ExecRequest>().unwrap();
                let started = Message::with_payload(
                    MessageType::ExecStarted,
                    message.id,
                    &ExecStarted { pid: 17 },
                )
                .unwrap();
                codec::write_message(&mut io, &started).await.unwrap();
                let exited = Message::with_payload(
                    MessageType::ExecExited,
                    message.id,
                    &ExecExited { code: 0 },
                )
                .unwrap();
                codec::write_message(&mut io, &exited).await.unwrap();
                requests.push(request);

                // Hold the connection until the client closes it. Closing with unread
                // client frames resets the socket, which can discard the exit event
                // before the client reads it.
                let mut unread = Vec::new();
                let _ = io.read_to_end(&mut unread).await;
            }

            requests
        });

        let backend =
            crate::test_support::cloud_backend(format!("http://{address}"), "test-key").unwrap();
        let operation = async {
            let sandbox = backend.sandboxes().get("spec-decode").await?;
            let default_output = sandbox.exec_default().await?;
            let shell_output = sandbox.shell("pwd").await?;
            Ok::<_, MicrosandboxError>((default_output.status(), shell_output.status()))
        };
        let (default_status, shell_status) =
            tokio::time::timeout(Duration::from_secs(10), operation)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(default_status.code, 0);
        assert_eq!(shell_status.code, 0);

        let requests = tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].cmd, "/bin/sh");
        assert_eq!(
            requests[0].args,
            ["-c".to_string(), "printf attached".to_string()]
        );
        assert_eq!(requests[0].cwd.as_deref(), Some("/tmp"));
        assert_eq!(requests[0].user.as_deref(), Some("nobody"));
        assert!(requests[0].env.iter().any(|value| value == "FOO=bar"));
        assert_eq!(requests[1].cmd, "/bin/ash");
        assert_eq!(requests[1].args, ["-c".to_string(), "pwd".to_string()]);
        assert_eq!(requests[1].cwd.as_deref(), Some("/tmp"));
    }

    #[test]
    fn cloud_status_maps_to_existing_sandbox_states() {
        assert_eq!(
            cloud_status_to_sandbox_status(CloudSandboxStatus::Stopping),
            SandboxStatus::Draining,
        );
        assert_eq!(
            cloud_status_to_sandbox_status(CloudSandboxStatus::SavingState),
            SandboxStatus::Draining,
        );
        assert_eq!(
            cloud_status_to_sandbox_status(CloudSandboxStatus::TemporarilyUnavailable),
            SandboxStatus::Paused,
        );
        assert_eq!(
            cloud_status_to_sandbox_status(CloudSandboxStatus::RecoveryDecisionRequired),
            SandboxStatus::Paused,
        );
        assert_eq!(
            cloud_status_to_sandbox_status(CloudSandboxStatus::Failed),
            SandboxStatus::Crashed,
        );
        assert_eq!(
            cloud_status_to_sandbox_status(CloudSandboxStatus::Unknown),
            SandboxStatus::Paused,
        );
    }

    #[test]
    fn cloud_lifecycle_readiness_accepts_only_running() {
        assert!(ensure_cloud_sandbox_ready(&cloud_response(CloudSandboxStatus::Running)).is_ok());

        for status in [
            CloudSandboxStatus::Created,
            CloudSandboxStatus::Starting,
            CloudSandboxStatus::Stopping,
            CloudSandboxStatus::SavingState,
            CloudSandboxStatus::TemporarilyUnavailable,
            CloudSandboxStatus::RecoveryDecisionRequired,
            CloudSandboxStatus::Stopped,
            CloudSandboxStatus::Failed,
            CloudSandboxStatus::Unknown,
        ] {
            assert!(ensure_cloud_sandbox_ready(&cloud_response(status)).is_err());
        }
    }

    /// Assert that Cloud rejects a create option with a stable typed reason.
    fn assert_unsupported_config_field(config: SandboxConfig, expected: &'static str) {
        let err = CloudCreateBody::try_from(config).unwrap_err();

        assert!(matches!(
            err,
            MicrosandboxError::Unsupported {
                op: Operation::SandboxCreate,
                reason: UnsupportedReason::ConfigField(field),
            } if field == expected
        ));
    }

    struct ScriptedCloud {
        backend: Arc<dyn Context>,
        server: JoinHandle<(Vec<String>, TcpListener)>,
    }

    impl ScriptedCloud {
        async fn start(responses: Vec<(u16, String)>) -> Self {
            use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let mut requests = Vec::new();
                for (status, body) in responses {
                    let (stream, _) = listener.accept().await.unwrap();
                    let mut reader = BufReader::new(stream);
                    let mut request_line = String::new();
                    reader.read_line(&mut request_line).await.unwrap();
                    let mut content_length = 0;
                    loop {
                        let mut line = String::new();
                        assert_ne!(reader.read_line(&mut line).await.unwrap(), 0);
                        if line == "\r\n" {
                            break;
                        }
                        if let Some((name, value)) = line.split_once(':')
                            && name.eq_ignore_ascii_case("content-length")
                        {
                            content_length = value.trim().parse::<usize>().unwrap();
                        }
                    }
                    let mut request_body = vec![0; content_length];
                    reader.read_exact(&mut request_body).await.unwrap();

                    let response = format!(
                        "HTTP/1.1 {status} Scripted\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    reader
                        .get_mut()
                        .write_all(response.as_bytes())
                        .await
                        .unwrap();
                    requests.push(request_line.trim_end().to_string());
                }
                (requests, listener)
            });
            let backend: Arc<dyn Context> =
                Arc::new(test_support::cloud_backend(&url, "test-key").unwrap());

            Self { backend, server }
        }

        fn handle(&self, status: CloudSandboxStatus) -> SandboxRecord {
            SandboxRecord::from_cloud(self.backend.clone(), cloud_response(status)).unwrap()
        }

        async fn finish(self) -> Vec<String> {
            let (requests, listener) = self.server.await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(50), listener.accept())
                    .await
                    .is_err(),
                "unexpected extra request after {requests:?}"
            );
            requests
        }
    }

    fn cloud_response_json(status: CloudSandboxStatus) -> String {
        serde_json::to_string(&cloud_response(status)).unwrap()
    }

    /// Minimal response fixture for create-readiness assertions.
    fn cloud_response(status: CloudSandboxStatus) -> CloudCreateSandboxResponse {
        CloudCreateSandboxResponse {
            id: "00000000-0000-0000-0000-000000000002".into(),
            org_id: "00000000-0000-0000-0000-000000000001".into(),
            name: "agent-1".into(),
            slug: "brave-otter".into(),
            status,
            status_reason: None,
            spec: None,
            ephemeral: true,
            created_at: chrono::Utc::now(),
            started_at: None,
            stopped_at: None,
            last_failure_message: (status == CloudSandboxStatus::Failed)
                .then(|| "image pull failed".into()),
        }
    }
}

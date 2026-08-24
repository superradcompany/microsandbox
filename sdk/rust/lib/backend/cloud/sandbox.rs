//! Cloud sandbox lifecycle: the [`SandboxBackend`] impl for [`CloudBackend`]
//! plus the conversions between the SDK's [`SandboxConfig`] and the cloud's
//! create wire shape.

use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;

use super::CloudBackend;
use crate::backend::{
    Backend,
    sandbox::{LogStream, MetricsStream, SandboxBackend},
};
use crate::error::{Operation, UnsupportedReason};
use crate::logs::{LogEntry, LogOptions, LogStreamOptions};
use crate::sandbox::metrics::SandboxMetrics;
use crate::sandbox::{
    RootfsSource, Sandbox, SandboxConfig, SandboxHandle, SandboxListBuilder, SandboxPage,
    SandboxStatus,
};
use crate::{MicrosandboxError, MicrosandboxResult};
use microsandbox_image::RegistryAuth;
use microsandbox_types::{
    CloudCreateSandboxRequest, CloudCreateSandboxResponse, CloudSandboxStatus, RootDisk,
    SandboxRuntimeOptions, TlsConfig,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Wire body for the cloud's create route: the shared create envelope with
/// the cloud-only fields that ride beside it.
#[derive(Debug, Clone, serde::Serialize)]
pub(in crate::backend) struct CloudCreateBody {
    /// The shared sandbox spec, flattened onto the body.
    #[serde(flatten)]
    pub envelope: CloudCreateSandboxRequest,
    /// Requested globally-unique slug; the cloud assigns one when omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
    /// Registry-credential selection for the image pull, derived from the
    /// config's [`RegistryAuth`]. Omitted (`None`) lets the cloud pick the
    /// stored credential configured for the image's registry host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry: Option<CloudRegistrySelection>,
}

/// Wire shape of the cloud's registry-credential selection.
///
/// `auto` is expressed by omitting the field.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub(in crate::backend) enum CloudRegistrySelection {
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

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl SandboxBackend for CloudBackend {
    fn create<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        config: SandboxConfig,
        start: bool,
    ) -> BoxFuture<'a, MicrosandboxResult<Sandbox>> {
        Box::pin(async move {
            let (req, config) = cloud_create_body_and_config(config)?;
            let cloud = CloudBackend::create_sandbox(self, &req, start).await?;
            if start {
                ensure_cloud_sandbox_ready(&cloud)?;
            }
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
            let (req, config) = cloud_create_body_and_config(config)?;
            let cloud = CloudBackend::create_sandbox(self, &req, true).await?;
            ensure_cloud_sandbox_ready(&cloud)?;
            Ok(Sandbox::from_cloud(backend, cloud, config))
        })
    }

    fn start<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Sandbox>> {
        Box::pin(async move {
            let current = CloudBackend::get_sandbox(self, name).await?;
            let config = sandbox_config_from_cloud(&current);
            let cloud = CloudBackend::start_sandbox(self, name).await?;
            ensure_cloud_sandbox_ready(&cloud)?;
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
            let current = CloudBackend::get_sandbox(self, name).await?;
            let config = sandbox_config_from_cloud(&current);
            let cloud = CloudBackend::start_sandbox(self, name).await?;
            ensure_cloud_sandbox_ready(&cloud)?;
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
        query: SandboxListBuilder,
    ) -> BoxFuture<'a, MicrosandboxResult<SandboxPage>> {
        Box::pin(async move {
            let page = CloudBackend::list_sandboxes(self, &query).await?;
            let sandboxes = page
                .data
                .into_iter()
                .map(|sb| SandboxHandle::from_cloud(backend.clone(), sb))
                .collect::<MicrosandboxResult<Vec<_>>>()?;
            Ok(SandboxPage {
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
            Err(MicrosandboxError::unsupported(
                Operation::SandboxKill,
                UnsupportedReason::UseInstead(Operation::SandboxStop),
            ))
        })
    }

    fn drain<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            Err(MicrosandboxError::unsupported(
                Operation::SandboxDrain,
                UnsupportedReason::UseInstead(Operation::SandboxStop),
            ))
        })
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
        Box::pin(async move { Err(MicrosandboxError::local_only(Operation::SandboxMetrics)) })
    }

    fn metrics_stream(
        &self,
        _backend: Arc<dyn Backend>,
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

impl TryFrom<SandboxConfig> for CloudCreateBody {
    type Error = MicrosandboxError;

    /// Build the cloud create body from an SDK config, rejecting the
    /// create-time options the cloud does not accept.
    fn try_from(mut config: SandboxConfig) -> MicrosandboxResult<Self> {
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

        // Cloud only supports OCI rootfs; reject the local-only rootfs kinds before
        // handing the spec to the control plane. Borrow so the spec isn't moved.
        match &config.spec.image {
            RootfsSource::Oci(oci) => {
                if matches!(
                    oci.root_disk,
                    Some(
                        RootDisk::Tmpfs { .. } | RootDisk::DiskImage { .. } | RootDisk::Flat { .. }
                    )
                ) {
                    return Err(MicrosandboxError::unsupported(
                        Operation::SandboxCreate,
                        UnsupportedReason::ConfigField("non-managed root_disk"),
                    ));
                }
            }
            RootfsSource::Bind { .. } => {
                return Err(MicrosandboxError::unsupported(
                    Operation::SandboxCreate,
                    UnsupportedReason::ConfigField("host-directory rootfs"),
                ));
            }
            RootfsSource::DiskImage { .. } => {
                return Err(MicrosandboxError::unsupported(
                    Operation::SandboxCreate,
                    UnsupportedReason::ConfigField("disk-image rootfs"),
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

        // The cloud request composes the shared spec verbatim plus the cloud-only
        // fields that have no place in it (slug, registry-credential selection).
        Ok(Self {
            slug: config.slug,
            registry,
            envelope: CloudCreateSandboxRequest::from(config.spec),
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn cloud_create_body_and_config(
    mut config: SandboxConfig,
) -> MicrosandboxResult<(CloudCreateBody, SandboxConfig)> {
    // Build the request first to preserve cloud-specific error precedence,
    // then apply the same successful canonicalization to the config retained
    // by Sandbox::config().
    let request = CloudCreateBody::try_from(config.clone())?;
    crate::sandbox::validate_volume_mounts(&mut config.spec.mounts)?;
    Ok((request, config))
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

    if config.spec.resources.max_cpus != config.spec.resources.cpus {
        return Err(unsupported("max_cpus"));
    }
    if config.spec.resources.max_memory_mib != config.spec.resources.memory_mib {
        return Err(unsupported("max_memory"));
    }
    if config.spec.runtime.hostname.is_some() {
        return Err(unsupported("hostname"));
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

    if config
        .spec
        .mounts
        .iter()
        .any(|mount| mount.named_create().is_some())
    {
        return Err(unsupported("named volume inline create"));
    }
    if config.spec.mounts.iter().any(|mount| {
        let options = match mount {
            microsandbox_types::VolumeMount::Bind { options, .. }
            | microsandbox_types::VolumeMount::Named { options, .. }
            | microsandbox_types::VolumeMount::Tmpfs { options, .. }
            | microsandbox_types::VolumeMount::DiskImage { options, .. } => options,
        };
        options.override_uid.is_some() || options.override_gid.is_some()
    }) {
        // Mount ownership is currently a local host-filesystem presentation
        // policy. Until the cloud control plane advertises this capability,
        // sending it would let older servers silently ignore access semantics.
        return Err(unsupported("mount owner"));
    }

    if config.snapshot_upper_source.is_some() {
        return Err(unsupported("from_snapshot"));
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
                .unwrap_or("the cloud control plane reported no failure reason")
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

/// Build the best available runtime config for a sandbox the SDK did not
/// create itself.
///
/// The cloud owns its response projection and may omit `spec` or return a
/// curated shape. A complete shared cloud spec is decoded when available;
/// otherwise agent operations use SDK defaults. Lifecycle start must never
/// depend on the optional inspection projection.
fn sandbox_config_from_cloud(cloud: &CloudCreateSandboxResponse) -> SandboxConfig {
    sandbox_config_from_cloud_spec(&cloud.name, cloud.spec.clone())
}

/// Decode the server-owned spec projection carried by a cloud handle.
///
/// Agent operations only require a best-effort runtime config. The response
/// projection may be absent or curated, so reconnecting must preserve the
/// lifecycle contract without requiring a complete create request.
pub(crate) fn sandbox_config_from_cloud_spec(
    name: &str,
    spec: Option<serde_json::Value>,
) -> SandboxConfig {
    let mut config = spec
        .and_then(|value| {
            serde_json::from_value::<microsandbox_types::CloudSandboxSpec>(value).ok()
        })
        .and_then(|spec| crate::sandbox::SandboxSpec::try_from(spec).ok())
        .map(|spec| SandboxConfig {
            spec,
            ..Default::default()
        })
        .unwrap_or_default();

    // The top-level response name is canonical even when a complete spec was
    // unavailable or carried stale inspection data.
    config.spec.name = name.to_string();
    config
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use microsandbox_types::{
        CloudSandboxSpec, HostPermissions, MountOptions, NamedVolumeCreate, NamedVolumeMode,
        StatVirtualization, VolumeKind, VolumeMount,
    };

    use super::*;
    use crate::sandbox::{EnvVar, OciRootfsSource, RootDisk, SandboxBuilder, SandboxSpec};

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

        // The request carries the cloud wire spec, so assert on `envelope.spec`.
        let spec = &req.envelope.spec;
        assert_eq!(spec.name, "agent-1");
        assert!(
            matches!(spec.image, microsandbox_types::CloudRootfsSource::Oci { ref reference } if reference == "python:3.12")
        );
        assert_eq!(spec.resources.vcpus, 2);
        assert_eq!(spec.resources.memory_mib, 1024);
        assert_eq!(spec.env, vec![EnvVar::new("A", "B")]);
        assert_eq!(spec.runtime.workdir.as_deref(), Some("/app"));
        assert_eq!(spec.runtime.shell.as_deref(), Some("/bin/bash"));
        assert_eq!(
            spec.runtime.entrypoint,
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
                .envelope
                .spec
                .mounts
                .iter()
                .map(|mount| match mount {
                    microsandbox_types::CloudVolumeMount::Bind { guest, .. }
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

        let (request, config) = cloud_create_body_and_config(config).unwrap();
        let retained = config
            .spec
            .mounts
            .iter()
            .map(VolumeMount::guest)
            .collect::<Vec<_>>();
        let sent = request
            .envelope
            .spec
            .mounts
            .iter()
            .map(|mount| match mount {
                microsandbox_types::CloudVolumeMount::Bind { guest, .. }
                | microsandbox_types::CloudVolumeMount::Named { guest, .. }
                | microsandbox_types::CloudVolumeMount::Tmpfs { guest, .. }
                | microsandbox_types::CloudVolumeMount::DiskImage { guest, .. } => guest.as_str(),
            })
            .collect::<Vec<_>>();

        assert_eq!(retained, vec!["/workspace", "/workspace/persist"]);
        assert_eq!(retained, sent);
    }

    #[test]
    fn cloud_create_body_serializes_slug_and_registry_beside_spec() {
        let mut config = base_cloud_config();
        config.slug = Some("brave-otter".into());
        config.registry_auth = Some(microsandbox_image::RegistryAuth::Anonymous);

        let req = CloudCreateBody::try_from(config).unwrap();
        let json = serde_json::to_value(&req).unwrap();

        // The envelope flattens onto the body; slug/registry ride beside it.
        // An anonymous registry_auth converts to the anonymous selection.
        assert_eq!(json["name"], "agent-1");
        assert_eq!(json["image"]["type"], "oci");
        assert_eq!(json["image"]["reference"], "python:3.12");
        assert_eq!(json["slug"], "brave-otter");
        assert_eq!(json["registry"]["mode"], "anonymous");
    }

    #[test]
    fn cloud_create_body_omits_unset_slug_and_registry() {
        let req = CloudCreateBody::try_from(base_cloud_config()).unwrap();
        let json = serde_json::to_value(&req).unwrap();

        assert!(json.get("slug").is_none());
        assert!(json.get("registry").is_none());
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

        let err = CloudCreateBody::try_from(config).unwrap_err();
        assert!(matches!(err, MicrosandboxError::Unsupported { .. }));
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

        let spec = &req.envelope.spec;
        assert!(spec.init.is_some());
        assert_eq!(
            spec.pull_policy,
            microsandbox_types::CloudPullPolicy::Always
        );
        assert_eq!(
            spec.runtime.cmd,
            Some(vec!["python".to_string(), "app.py".to_string()])
        );
        assert_eq!(spec.rlimits.len(), 1);
        assert_eq!(spec.resources.disk_size_mib, Some(8192));
    }

    #[test]
    fn cloud_create_body_maps_basic_registry_auth_to_inline() {
        let mut config = base_cloud_config();
        config.registry_auth = Some(microsandbox_image::RegistryAuth::Basic {
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
    fn cloud_create_request_rejects_fields_missing_from_the_wire() {
        let cases: [(&str, fn(&mut SandboxConfig)); 8] = [
            ("max_cpus", |config| config.spec.resources.max_cpus = 2),
            ("max_memory", |config| {
                config.spec.resources.max_memory_mib = 1024
            }),
            ("hostname", |config| {
                config.spec.runtime.hostname = Some("worker".into())
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
            ("network.tls", |config| {
                let mut tls = TlsConfig::default();
                tls.bypass.push("*.internal.example".into());
                config.spec.network.tls = Some(tls);
            }),
            ("from_snapshot", |config| {
                config.snapshot_upper_source = Some("snapshot/upper.ext4".into())
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
    fn cloud_create_request_rejects_mount_owner_without_capability() {
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

        assert_unsupported_config_field(config, "mount owner");
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

        assert_eq!(req.envelope.spec.resources.vcpus, 2);
        assert_eq!(req.envelope.spec.resources.memory_mib, 1024);
        assert_eq!(req.envelope.spec.mounts.len(), 1);
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
            req.envelope
                .spec
                .network
                .secrets
                .as_ref()
                .map(|secrets| secrets.entries.len()),
            Some(1),
        );
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

    #[test]
    fn sandbox_config_from_cloud_round_trips_d13_fields() {
        // The cloud response carries the wire `CloudSandboxSpec`, which converts
        // back into the shared `SandboxSpec`. Populate a full spec and assert the
        // fields the wire spec carries survive the round-trip; fields with no
        // representation on `CloudSandboxSpec` (like the runtime hostname) are not
        // carried back.
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
        spec.runtime.log_level = Some(microsandbox_types::SandboxLogLevel::Debug);
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
            spec: Some(serde_json::to_value(CloudSandboxSpec::from(spec)).unwrap()),
            ephemeral: true,
            created_at: chrono::Utc::now(),
            started_at: None,
            stopped_at: None,
            last_failure_message: None,
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
        assert_eq!(config.spec.runtime.hostname, None);
        assert_eq!(config.spec.runtime.user.as_deref(), Some("appuser"));
        assert_eq!(
            config.spec.runtime.log_level,
            Some(microsandbox_types::SandboxLogLevel::Debug),
        );
        assert_eq!(
            config.spec.runtime.scripts.get("setup"),
            Some(&"echo hi".to_string())
        );
        assert_eq!(config.spec.lifecycle.max_duration_secs, Some(3600));
        assert_eq!(config.spec.lifecycle.idle_timeout_secs, Some(600));
    }

    #[test]
    fn sandbox_config_from_cloud_does_not_require_spec() {
        let mut cloud = cloud_response(CloudSandboxStatus::Stopped);
        cloud.spec = None;

        let config = sandbox_config_from_cloud(&cloud);

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

        let config = sandbox_config_from_cloud(&cloud);

        assert_eq!(config.spec.name, cloud.name);
        assert_eq!(config.spec.runtime.shell, None);
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

    #[test]
    fn cloud_lifecycle_readiness_accepts_only_running() {
        assert!(ensure_cloud_sandbox_ready(&cloud_response(CloudSandboxStatus::Running)).is_ok());

        for status in [
            CloudSandboxStatus::Created,
            CloudSandboxStatus::Starting,
            CloudSandboxStatus::Stopping,
            CloudSandboxStatus::Stopped,
            CloudSandboxStatus::Failed,
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

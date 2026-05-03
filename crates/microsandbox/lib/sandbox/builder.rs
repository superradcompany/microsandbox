//! Fluent builder for [`SandboxConfig`].

use std::path::PathBuf;

use microsandbox_image::{PullPolicy, PullProgressHandle, RegistryAuth};
#[cfg(feature = "net")]
use microsandbox_network::builder::{NetworkBuilder, SecretBuilder};
#[cfg(feature = "net")]
use microsandbox_network::config::{PortProtocol, PublishedPort};
#[cfg(feature = "net")]
use std::net::{IpAddr, Ipv4Addr};

use super::{
    config::SandboxConfig,
    exec::{Rlimit, RlimitResource},
    types::{
        ImageBuilder, IntoImage, MountBuilder, Patch, PatchBuilder, RootfsSource, VolumeMount,
    },
};
use crate::{LogLevel, MicrosandboxError, MicrosandboxResult, size::Mebibytes};
use std::time::Duration;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Builder for constructing a [`SandboxConfig`] with a fluent API.
pub struct SandboxBuilder {
    config: SandboxConfig,
    build_error: Option<crate::MicrosandboxError>,
    /// Pending snapshot reference (path or bare name) supplied via
    /// [`from_snapshot`]. Resolved during async `create()`.
    pending_snapshot: Option<String>,
}

/// Sub-builder for registry connection settings.
#[derive(Default)]
pub struct RegistryConfigBuilder {
    pub(crate) auth: Option<RegistryAuth>,
    pub(crate) insecure: bool,
    pub(crate) ca_certs: Vec<Vec<u8>>,
}

impl RegistryConfigBuilder {
    /// Set authentication credentials.
    pub fn auth(mut self, auth: RegistryAuth) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Access the registry over plain HTTP instead of HTTPS.
    pub fn insecure(mut self) -> Self {
        self.insecure = true;
        self
    }

    /// Add PEM-encoded CA root certificates to trust.
    pub fn ca_certs(mut self, pem_data: Vec<u8>) -> Self {
        self.ca_certs.push(pem_data);
        self
    }
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SandboxBuilder {
    /// Start building a sandbox configuration. The name must be unique
    /// among existing sandboxes (unless [`replace`](Self::replace) is set).
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            config: SandboxConfig {
                name: name.into(),
                ..Default::default()
            },
            build_error: None,
            pending_snapshot: None,
        }
    }

    /// Set the root filesystem image source.
    ///
    /// - **`&str` / `String`**: Paths starting with `/`, `./`, or `../` are treated as local
    ///   paths. Everything else is treated as an OCI image reference. Disk image extensions
    ///   (`.qcow2`, `.raw`, `.vmdk`) resolve to virtio-blk block device rootfs.
    /// - **`PathBuf`**: Always treated as a local path.
    ///
    /// For explicit disk image configuration, see [`image_with`](Self::image_with).
    ///
    /// ```ignore
    /// .image("python:3.12")       // OCI image
    /// .image("./rootfs")          // local directory (bind mount)
    /// .image("./ubuntu.qcow2")   // disk image (auto-detect fs)
    /// ```
    pub fn image(mut self, image: impl IntoImage) -> Self {
        match image.into_rootfs_source() {
            Ok(rootfs) => self.config.image = rootfs,
            Err(e) => {
                if self.build_error.is_none() {
                    self.build_error = Some(e);
                }
            }
        }
        self
    }

    /// Set the root filesystem image using a builder closure.
    ///
    /// ```ignore
    /// .image_with(|i| i.disk("./ubuntu.qcow2").fstype("ext4"))
    /// ```
    pub fn image_with(mut self, f: impl FnOnce(ImageBuilder) -> ImageBuilder) -> Self {
        match f(ImageBuilder::new()).build() {
            Ok(rootfs) => self.config.image = rootfs,
            Err(e) => {
                if self.build_error.is_none() {
                    self.build_error = Some(e);
                }
            }
        }
        self
    }

    /// Allocate virtual CPUs for this sandbox (default: 1).
    pub fn cpus(mut self, count: u8) -> Self {
        self.config.cpus = count;
        self
    }

    /// Set guest memory size.
    ///
    /// Accepts bare `u32` (interpreted as MiB) or a [`SizeExt`](crate::size::SizeExt) helper:
    /// ```ignore
    /// .memory(512)         // 512 MiB
    /// .memory(512.mib())   // 512 MiB (explicit)
    /// .memory(1.gib())     // 1 GiB = 1024 MiB
    /// ```
    pub fn memory(mut self, size: impl Into<Mebibytes>) -> Self {
        self.config.memory_mib = size.into().as_u32();
        self
    }

    /// Set the runtime log level for the sandbox process.
    ///
    /// This controls the verbosity of the `msb sandbox` process.
    pub fn log_level(mut self, level: LogLevel) -> Self {
        self.config.log_level = Some(level);
        self
    }

    /// Disable runtime logs for this sandbox, even if a global default exists.
    pub fn quiet_logs(mut self) -> Self {
        self.config.log_level = None;
        self
    }

    /// Override the metrics sampling interval for this sandbox.
    pub fn metrics_sample_interval(mut self, interval: Duration) -> Self {
        let ms = interval.as_millis();
        if ms > u128::from(u64::MAX) {
            if self.build_error.is_none() {
                self.build_error = Some(MicrosandboxError::InvalidConfig(format!(
                    "metrics sample interval {interval:?} overflows u64 milliseconds"
                )));
            }
            return self;
        }
        self.config.metrics_sample_interval_ms = ms as u64;
        self
    }

    /// Default working directory for commands executed in this sandbox
    /// (e.g., `/app`). Used by [`exec`](super::Sandbox::exec),
    /// [`shell`](super::Sandbox::shell), and [`attach`](super::Sandbox::attach)
    /// unless overridden per-command.
    pub fn workdir(mut self, path: impl Into<String>) -> Self {
        self.config.workdir = Some(path.into());
        self
    }

    /// Shell used by [`shell()`](super::Sandbox::shell) to interpret
    /// commands (default: `/bin/sh`).
    pub fn shell(mut self, shell: impl Into<String>) -> Self {
        self.config.shell = Some(shell.into());
        self
    }

    /// Configure registry connection settings (auth, TLS, insecure).
    ///
    /// ```rust,ignore
    /// use microsandbox::{RegistryAuth, sandbox::Sandbox};
    ///
    /// let sb = Sandbox::builder("worker")
    ///     .image("localhost:5050/my-app:latest")
    ///     .registry(|r| r
    ///         .auth(RegistryAuth::Basic {
    ///             username: "user".into(),
    ///             password: "pass".into(),
    ///         })
    ///         .insecure()
    ///     )
    ///     .create()
    ///     .await
    ///     .unwrap();
    /// ```
    pub fn registry(
        mut self,
        f: impl FnOnce(RegistryConfigBuilder) -> RegistryConfigBuilder,
    ) -> Self {
        let builder = f(RegistryConfigBuilder::default());
        if let Some(auth) = builder.auth {
            self.config.registry_auth = Some(auth);
        }
        self.config.insecure = builder.insecure;
        self.config.ca_certs = builder.ca_certs;
        self
    }

    /// Replace an existing sandbox with the same name during create.
    ///
    /// If the existing sandbox is still active, microsandbox stops it and
    /// waits for it to exit before recreating it.
    pub fn replace(mut self) -> Self {
        self.config.replace_existing = true;
        self
    }

    /// Override the OCI image entrypoint.
    pub fn entrypoint(mut self, cmd: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.config.entrypoint = Some(cmd.into_iter().map(Into::into).collect());
        self
    }

    /// Set the guest hostname. Defaults to the sandbox name.
    pub fn hostname(mut self, hostname: impl Into<String>) -> Self {
        self.config.hostname = Some(hostname.into());
        self
    }

    /// Override the libkrunfw shared library for this sandbox.
    ///
    /// By default, microsandbox resolves libkrunfw via the global config or
    /// finds it next to the `msb` binary. Use this to point at a specific
    /// libkrunfw build — for example, an unreleased firmware during
    /// development.
    ///
    /// The path is validated at [`build`](Self::build) time.
    pub fn libkrunfw_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.libkrunfw_path = Some(path.into());
        self
    }

    /// Set the user identity inside the sandbox (e.g., `"1000"`, `"appuser"`, `"1000:1000"`).
    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.config.user = Some(user.into());
        self
    }

    /// Set the pull policy for OCI images.
    pub fn pull_policy(mut self, policy: PullPolicy) -> Self {
        self.config.pull_policy = policy;
        self
    }

    /// Disable all network access for this sandbox.
    ///
    /// Disables the network device entirely and sets the policy to
    /// [`NetworkPolicy::none()`](microsandbox_network::policy::NetworkPolicy::none)
    /// so the serialized config also reflects that networking is off.
    ///
    /// ```ignore
    /// .disable_network()
    /// ```
    #[cfg(feature = "net")]
    pub fn disable_network(mut self) -> Self {
        self.config.network.enabled = false;
        self.config.network.policy = microsandbox_network::policy::NetworkPolicy::none();
        self
    }

    /// Configure networking via a closure.
    ///
    /// ```ignore
    /// .network(|n| n
    ///     .port(8080, 80)
    ///     .policy(NetworkPolicy::public_only())
    ///     .tls(|t| t.bypass("*.internal.com"))
    /// )
    /// ```
    #[cfg(feature = "net")]
    pub fn network(mut self, f: impl FnOnce(NetworkBuilder) -> NetworkBuilder) -> Self {
        let network = std::mem::take(&mut self.config.network);
        match f(NetworkBuilder::from_config(network)).build() {
            Ok(net) => self.config.network = net,
            Err(err) => {
                if self.build_error.is_none() {
                    self.build_error = Some(err.into());
                }
            }
        }
        self
    }

    /// Publish a TCP port directly on the sandbox builder.
    ///
    /// Repeatable: call multiple times to expose multiple ports.
    ///
    /// ```ignore
    /// .port(8080, 80)
    /// .port(3000, 3000)
    /// ```
    #[cfg(feature = "net")]
    pub fn port(mut self, host_port: u16, guest_port: u16) -> Self {
        self.config.network.ports.push(PublishedPort {
            host_port,
            guest_port,
            protocol: PortProtocol::Tcp,
            host_bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
        });
        self
    }

    /// Publish a UDP port directly on the sandbox builder.
    ///
    /// Repeatable: call multiple times to expose multiple ports.
    ///
    /// ```ignore
    /// .port_udp(5353, 53)
    /// .port_udp(8125, 8125)
    /// ```
    #[cfg(feature = "net")]
    pub fn port_udp(mut self, host_port: u16, guest_port: u16) -> Self {
        self.config.network.ports.push(PublishedPort {
            host_port,
            guest_port,
            protocol: PortProtocol::Udp,
            host_bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
        });
        self
    }

    /// Add a secret with placeholder-based protection via a closure.
    ///
    /// The sandbox receives a placeholder; the real value is substituted
    /// by the TLS proxy only for allowed hosts.
    ///
    /// ```ignore
    /// .secret(|s| s
    ///     .env("OPENAI_API_KEY")
    ///     .value(api_key)
    ///     .allow_host("api.openai.com")
    /// )
    /// ```
    ///
    /// Automatically enables TLS interception if not already enabled.
    #[cfg(feature = "net")]
    pub fn secret(mut self, f: impl FnOnce(SecretBuilder) -> SecretBuilder) -> Self {
        let entry = f(SecretBuilder::new()).build();
        self.config.network.secrets.secrets.push(entry);
        // Auto-enable TLS when secrets are configured.
        if !self.config.network.tls.enabled {
            self.config.network.tls.enabled = true;
        }
        self
    }

    /// Shorthand: add a secret with env var, value, and allowed host.
    ///
    /// Placeholder is auto-generated as `$MSB_<env_var>`.
    /// Automatically enables TLS interception.
    ///
    /// ```ignore
    /// .secret_env("OPENAI_API_KEY", api_key, "api.openai.com")
    /// ```
    #[cfg(feature = "net")]
    pub fn secret_env(
        self,
        env_var: impl Into<String>,
        value: impl Into<String>,
        allowed_host: impl Into<String>,
    ) -> Self {
        let env_var = env_var.into();
        let value = value.into();
        let allowed_host = allowed_host.into();
        self.secret(|s| s.env(&env_var).value(value).allow_host(allowed_host))
    }

    /// Set an environment variable visible to all commands in this sandbox.
    /// Can be called multiple times. Per-command env vars (on exec/shell)
    /// are merged on top.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.config.env.push((key.into(), value.into()));
        self
    }

    /// Set multiple environment variables at once. See [`env`](Self::env).
    pub fn envs(
        mut self,
        vars: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        for (k, v) in vars {
            self.config.env.push((k.into(), v.into()));
        }
        self
    }

    /// Set a sandbox-wide resource limit inherited by all guest processes.
    ///
    /// This is applied during agentd PID 1 startup, so bootstrap scripts and
    /// long-lived daemons inherit the raised baseline without needing explicit
    /// per-exec rlimits.
    pub fn rlimit(mut self, resource: RlimitResource, limit: u64) -> Self {
        self.config.rlimits.push(Rlimit {
            resource,
            soft: limit,
            hard: limit,
        });
        self
    }

    /// Set a sandbox-wide resource limit with different soft/hard values.
    pub fn rlimit_range(mut self, resource: RlimitResource, soft: u64, hard: u64) -> Self {
        self.config.rlimits.push(Rlimit {
            resource,
            soft,
            hard,
        });
        self
    }

    /// Register a script that will be mounted at `/.msb/scripts/<name>` in
    /// the guest. Scripts are added to `PATH` so they can be invoked by name
    /// via [`exec`](super::Sandbox::exec).
    pub fn script(mut self, name: impl Into<String>, content: impl Into<String>) -> Self {
        self.config.scripts.insert(name.into(), content.into());
        self
    }

    /// Register multiple scripts at once. See [`script`](Self::script).
    pub fn scripts(
        mut self,
        scripts: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        for (name, content) in scripts {
            self.config.scripts.insert(name.into(), content.into());
        }
        self
    }

    /// Set a maximum sandbox lifetime in seconds.
    pub fn max_duration(mut self, secs: u64) -> Self {
        self.config.policy.max_duration_secs = Some(secs);
        self
    }

    /// Auto-stop the sandbox after this many seconds of inactivity.
    /// Inactivity is detected via agentd heartbeat. Omit to disable (default).
    pub fn idle_timeout(mut self, secs: u64) -> Self {
        self.config.policy.idle_timeout_secs = Some(secs);
        self
    }

    /// Add a volume mount using a closure-based builder.
    ///
    /// ```ignore
    /// .volume("/data", |m| m.bind("/host/data"))
    /// .volume("/config", |m| m.bind("/host/config").readonly())
    /// .volume("/cache", |m| m.named("my-cache"))
    /// .volume("/tmp", |m| m.tmpfs().size(100))
    /// ```
    pub fn volume(
        mut self,
        guest_path: impl Into<String>,
        f: impl FnOnce(MountBuilder) -> MountBuilder,
    ) -> Self {
        match f(MountBuilder::new(guest_path)).build() {
            Ok(mount) => self.config.mounts.push(mount),
            Err(e) => {
                if self.build_error.is_none() {
                    self.build_error = Some(e);
                }
            }
        }
        self
    }

    /// Apply rootfs patches using a builder closure.
    ///
    /// Patches are applied before VM start. OCI roots bake patches into
    /// `upper.ext4`; bind roots patch the host directory directly. Returns an
    /// error at create time if used with block device roots (Qcow2, Raw).
    ///
    /// ```ignore
    /// .patch(|p| p
    ///     .text("/etc/app.conf", config_str, None, false)
    ///     .copy_file("./cert.pem", "/etc/ssl/cert.pem", None, false)
    ///     .mkdir("/var/cache/app", None)
    /// )
    /// ```
    pub fn patch(mut self, f: impl FnOnce(PatchBuilder) -> PatchBuilder) -> Self {
        self.config.patches.extend(f(PatchBuilder::new()).build());
        self
    }

    /// Add a single patch directly.
    pub fn add_patch(mut self, patch: Patch) -> Self {
        self.config.patches.push(patch);
        self
    }

    /// Boot a fresh sandbox from a snapshot artifact.
    ///
    /// The snapshot already pins the image reference and digest, so
    /// this method is mutually exclusive with [`image`](Self::image)
    /// and [`image_with`](Self::image_with). The snapshot is opened
    /// (and its integrity verified) at `create()` time, not here.
    ///
    /// `path_or_name` accepts either a path to a snapshot artifact
    /// directory (or a bare name resolved under the default snapshots
    /// directory).
    pub fn from_snapshot(mut self, path_or_name: impl Into<String>) -> Self {
        self.pending_snapshot = Some(path_or_name.into());
        self
    }

    /// Pre-populate the snapshot resolution for callers that opened
    /// the artifact synchronously and don't want the async
    /// [`resolve_pending`](Self::resolve_pending) step.
    ///
    /// Used by the Python SDK helpers, where kwargs-style config
    /// construction has to stay synchronous. Callers that take this
    /// route are expected to also call [`image`](Self::image) with
    /// the snapshot's pinned image reference.
    pub fn snapshot_resolved(
        mut self,
        image_manifest_digest: impl Into<String>,
        upper_source: impl Into<std::path::PathBuf>,
    ) -> Self {
        self.config.manifest_digest = Some(image_manifest_digest.into());
        self.config.snapshot_upper_source = Some(upper_source.into());
        self
    }

    /// Build the configuration without creating the sandbox.
    ///
    /// **Caller responsibility**: if the builder was configured via
    /// [`from_snapshot`](Self::from_snapshot), call
    /// [`resolve_pending`](Self::resolve_pending) first. The async
    /// `create*` methods do this automatically.
    pub fn build(mut self) -> MicrosandboxResult<SandboxConfig> {
        self.validate()?;
        Ok(self.config)
    }

    /// Resolve any pending snapshot reference, mutating the builder
    /// to set `image` and a transient `snapshot_upper_source`.
    ///
    /// Called automatically by the async `create*` methods. Public
    /// for callers that want to drive the builder manually (e.g. the
    /// `msb run --snapshot` path that uses
    /// [`create_with_pull_progress`](Self::create_with_pull_progress)).
    ///
    /// If the user has already called [`image`](Self::image), the
    /// pre-set image must match the snapshot's pinned image
    /// reference; otherwise the call errors.
    pub async fn resolve_pending(&mut self) -> MicrosandboxResult<()> {
        let Some(snapshot_ref) = self.pending_snapshot.take() else {
            return Ok(());
        };

        let snap = crate::snapshot::Snapshot::open(&snapshot_ref).await?;
        let snap_ref = snap.manifest().image.reference.clone();

        let user_image = match &self.config.image {
            RootfsSource::Oci(s) if !s.is_empty() => Some(s.clone()),
            RootfsSource::Bind(p) if !p.as_os_str().is_empty() => {
                return Err(crate::MicrosandboxError::InvalidConfig(
                    "from_snapshot is mutually exclusive with bind/disk image".into(),
                ));
            }
            _ => None,
        };
        if let Some(img) = user_image
            && img != snap_ref
        {
            return Err(crate::MicrosandboxError::InvalidConfig(format!(
                "from_snapshot pins image '{snap_ref}', but builder was set to '{img}'"
            )));
        }

        self.config.image = RootfsSource::Oci(snap_ref);
        self.config.manifest_digest = Some(snap.manifest().image.manifest_digest.clone());
        self.config.snapshot_upper_source = Some(snap.path().join(&snap.manifest().upper.file));
        Ok(())
    }

    /// Create the sandbox. Boots the VM with agentd ready.
    pub async fn create(mut self) -> MicrosandboxResult<super::Sandbox> {
        self.resolve_pending().await?;
        let config = self.build()?;
        super::Sandbox::create(config).await
    }

    /// Create the sandbox for detached/background use.
    pub async fn create_detached(mut self) -> MicrosandboxResult<super::Sandbox> {
        self.resolve_pending().await?;
        let config = self.build()?;
        super::Sandbox::create_detached(config).await
    }

    /// Create the sandbox with pull progress reporting.
    ///
    /// Returns a progress handle for per-layer pull events and a task handle
    /// for the sandbox creation result. Useful for CLI commands that want to
    /// display per-layer download/materialization progress during sandbox creation.
    ///
    /// If the builder was configured via
    /// [`from_snapshot`](Self::from_snapshot), snapshot resolution
    /// happens inside the spawned task so this entry point stays
    /// synchronous.
    pub fn create_with_pull_progress(
        mut self,
    ) -> crate::MicrosandboxResult<(
        PullProgressHandle,
        tokio::task::JoinHandle<crate::MicrosandboxResult<super::Sandbox>>,
    )> {
        let pending = self.pending_snapshot.is_some();
        if !pending {
            let config = self.build()?;
            return Ok(super::Sandbox::create_with_pull_progress(config));
        }

        let (handle, sender) = microsandbox_image::progress_channel();
        let task = tokio::spawn(async move {
            self.resolve_pending().await?;
            let config = self.build()?;
            super::Sandbox::create_with_mode(
                config,
                crate::runtime::SpawnMode::Attached,
                Some(sender),
            )
            .await
        });
        Ok((handle, task))
    }

    /// Like `create_with_pull_progress` but spawns the sandbox process in detached
    /// mode so the sandbox survives after the creating process exits.
    pub fn create_detached_with_pull_progress(
        mut self,
    ) -> crate::MicrosandboxResult<(
        PullProgressHandle,
        tokio::task::JoinHandle<crate::MicrosandboxResult<super::Sandbox>>,
    )> {
        let pending = self.pending_snapshot.is_some();
        if !pending {
            let config = self.build()?;
            return Ok(super::Sandbox::create_detached_with_pull_progress(config));
        }

        let (handle, sender) = microsandbox_image::progress_channel();
        let task = tokio::spawn(async move {
            self.resolve_pending().await?;
            let config = self.build()?;
            super::Sandbox::create_with_mode(
                config,
                crate::runtime::SpawnMode::Detached,
                Some(sender),
            )
            .await
        });
        Ok((handle, task))
    }
}

impl SandboxBuilder {
    /// Validate the configuration before building.
    fn validate(&mut self) -> MicrosandboxResult<()> {
        if let Some(err) = self.build_error.take() {
            return Err(err);
        }

        if self.config.name.is_empty() {
            return Err(crate::MicrosandboxError::InvalidConfig(
                "sandbox name is required".into(),
            ));
        }

        // Check that image is set (non-empty OCI string or Bind path).
        match &self.config.image {
            RootfsSource::Oci(s) if s.is_empty() => {
                return Err(crate::MicrosandboxError::InvalidConfig(
                    "image source is required".into(),
                ));
            }
            RootfsSource::DiskImage { .. } if !self.config.patches.is_empty() => {
                return Err(crate::MicrosandboxError::InvalidConfig(
                    "patches are not compatible with disk image rootfs".into(),
                ));
            }
            _ => {}
        }

        if let Some(path) = &self.config.libkrunfw_path
            && !path.is_file()
        {
            return Err(crate::MicrosandboxError::InvalidConfig(format!(
                "libkrunfw_path does not exist: {}",
                path.display()
            )));
        }

        for rlimit in &self.config.rlimits {
            if rlimit.soft > rlimit.hard {
                return Err(crate::MicrosandboxError::InvalidConfig(format!(
                    "rlimit {}: soft ({}) must not exceed hard ({})",
                    rlimit.resource.as_str(),
                    rlimit.soft,
                    rlimit.hard
                )));
            }
        }

        // Reject any two DiskImage mounts pointing at the same host file.
        // Each virtio-blk device caches independently on the host, so any
        // mix of writable+writable, writable+read-only, or even two
        // read-only mounts of the same image will diverge from the
        // kernel's view (RW invalidates the RO cache; RO+RO doubles the
        // page-cache footprint with no benefit). Compare against the
        // canonical path so symlinks and `./` prefixes don't bypass the
        // check.
        let mut seen: Vec<PathBuf> = Vec::new();
        for mount in &self.config.mounts {
            if let VolumeMount::DiskImage { host, .. } = mount {
                let canonical = std::fs::canonicalize(host).map_err(|e| {
                    crate::MicrosandboxError::InvalidConfig(format!(
                        "disk image host path does not exist: {} ({e})",
                        host.display()
                    ))
                })?;
                if seen.contains(&canonical) {
                    return Err(crate::MicrosandboxError::InvalidConfig(format!(
                        "disk-image volumes cannot share the same host path: {}",
                        canonical.display()
                    )));
                }
                seen.push(canonical);
            }
        }

        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl From<SandboxConfig> for SandboxBuilder {
    fn from(config: SandboxConfig) -> Self {
        Self {
            config,
            build_error: None,
            pending_snapshot: None,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::SandboxBuilder;
    use crate::LogLevel;
    use crate::sandbox::RlimitResource;
    #[cfg(feature = "net")]
    use microsandbox_network::config::PortProtocol;

    #[test]
    fn test_builder_sets_runtime_log_level() {
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .log_level(LogLevel::Debug)
            .build()
            .unwrap();

        assert_eq!(config.log_level, Some(LogLevel::Debug));
    }

    #[test]
    fn test_builder_quiet_logs_clears_runtime_log_level() {
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .log_level(LogLevel::Trace)
            .quiet_logs()
            .build()
            .unwrap();

        assert_eq!(config.log_level, None);
    }

    #[test]
    fn test_builder_metrics_sample_interval_sets_ms() {
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .metrics_sample_interval(std::time::Duration::from_millis(750))
            .build()
            .unwrap();

        assert_eq!(config.metrics_sample_interval_ms, 750);
    }

    #[test]
    fn test_builder_metrics_sample_interval_zero_is_disabled() {
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .metrics_sample_interval(std::time::Duration::ZERO)
            .build()
            .unwrap();

        assert_eq!(config.metrics_sample_interval_ms, 0);
    }

    #[test]
    fn test_builder_replace_sets_replace_existing() {
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .replace()
            .build()
            .unwrap();

        assert!(config.replace_existing);
    }

    #[test]
    fn test_builder_rlimit_sets_sandbox_wide_limit() {
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .rlimit(RlimitResource::Nofile, 65_535)
            .build()
            .unwrap();

        assert_eq!(config.rlimits.len(), 1);
        assert_eq!(config.rlimits[0].resource, RlimitResource::Nofile);
        assert_eq!(config.rlimits[0].soft, 65_535);
        assert_eq!(config.rlimits[0].hard, 65_535);
    }

    #[cfg(feature = "net")]
    #[test]
    fn test_builder_ports_are_repeatable() {
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .port(8080, 80)
            .port(3000, 3000)
            .port_udp(5353, 53)
            .build()
            .unwrap();

        assert_eq!(config.network.ports.len(), 3);
        assert_eq!(config.network.ports[0].host_port, 8080);
        assert_eq!(config.network.ports[0].guest_port, 80);
        assert_eq!(config.network.ports[0].protocol, PortProtocol::Tcp);
        assert_eq!(config.network.ports[1].host_port, 3000);
        assert_eq!(config.network.ports[1].guest_port, 3000);
        assert_eq!(config.network.ports[1].protocol, PortProtocol::Tcp);
        assert_eq!(config.network.ports[2].host_port, 5353);
        assert_eq!(config.network.ports[2].guest_port, 53);
        assert_eq!(config.network.ports[2].protocol, PortProtocol::Udp);
    }

    #[cfg(feature = "net")]
    #[test]
    fn test_builder_disable_network_denies_all() {
        use microsandbox_network::policy::Action;

        let config = SandboxBuilder::new("test")
            .image("alpine")
            .disable_network()
            .build()
            .unwrap();

        assert!(!config.network.enabled);
        // `disable_network()` uses `NetworkPolicy::none()` which is deny-all
        // in both directions with no rules.
        assert_eq!(config.network.policy.default_egress, Action::Deny);
        assert_eq!(config.network.policy.default_ingress, Action::Deny);
        assert!(config.network.policy.rules.is_empty());
    }

    #[cfg(feature = "net")]
    #[test]
    fn test_builder_network_preserves_top_level_settings() {
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .port(8080, 80)
            .secret_env("OPENAI_API_KEY", "secret", "api.openai.com")
            .network(|n| n.max_connections(128))
            .build()
            .unwrap();

        assert_eq!(config.network.ports.len(), 1);
        assert_eq!(config.network.ports[0].host_port, 8080);
        assert_eq!(config.network.ports[0].guest_port, 80);
        assert_eq!(config.network.ports[0].protocol, PortProtocol::Tcp);
        assert_eq!(config.network.secrets.secrets.len(), 1);
        assert_eq!(config.network.max_connections, Some(128));
    }

    //----------------------------------------------------------------------------------------------
    // DiskImage host-path validation
    //----------------------------------------------------------------------------------------------

    /// Helper: stage two files in a tempdir, return absolute paths.
    fn two_disk_files() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.qcow2");
        let b = dir.path().join("b.qcow2");
        std::fs::write(&a, []).unwrap();
        std::fs::write(&b, []).unwrap();
        (dir, a, b)
    }

    #[test]
    fn test_builder_rejects_two_writable_same_host() {
        let (_dir, a, _) = two_disk_files();
        let err = SandboxBuilder::new("test")
            .image("alpine")
            .volume("/x", |v| v.disk(a.clone()))
            .volume("/y", |v| v.disk(a.clone()))
            .build()
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("disk-image volumes cannot share the same host path")
        );
    }

    #[test]
    fn test_builder_rejects_writable_plus_readonly_same_host() {
        // Mixed writable+readonly still corrupts because the writable side's
        // host page cache invalidates the readonly side's view.
        let (_dir, a, _) = two_disk_files();
        let err = SandboxBuilder::new("test")
            .image("alpine")
            .volume("/x", |v| v.disk(a.clone()))
            .volume("/y", |v| v.disk(a.clone()).readonly())
            .build()
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("disk-image volumes cannot share the same host path")
        );
    }

    #[test]
    fn test_builder_rejects_two_readonly_same_host() {
        let (_dir, a, _) = two_disk_files();
        let err = SandboxBuilder::new("test")
            .image("alpine")
            .volume("/x", |v| v.disk(a.clone()).readonly())
            .volume("/y", |v| v.disk(a.clone()).readonly())
            .build()
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("disk-image volumes cannot share the same host path")
        );
    }

    #[test]
    fn test_builder_accepts_two_writable_different_hosts() {
        let (_dir, a, b) = two_disk_files();
        SandboxBuilder::new("test")
            .image("alpine")
            .volume("/x", |v| v.disk(a))
            .volume("/y", |v| v.disk(b))
            .build()
            .unwrap();
    }

    #[test]
    fn test_builder_canonicalizes_host_paths() {
        // /foo/./bar resolves to the same canonical as /foo/bar; the check
        // must catch this even though the byte strings differ.
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.qcow2");
        std::fs::write(&a, []).unwrap();
        let parent = a.parent().unwrap();
        let dotted = parent.join(".").join("a.qcow2");

        let err = SandboxBuilder::new("test")
            .image("alpine")
            .volume("/x", |v| v.disk(a))
            .volume("/y", |v| v.disk(dotted))
            .build()
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("disk-image volumes cannot share the same host path")
        );
    }

    #[test]
    fn test_builder_rejects_missing_disk_host() {
        let dir = tempfile::tempdir().unwrap();
        let nonexistent = dir.path().join("nope.qcow2");
        let err = SandboxBuilder::new("test")
            .image("alpine")
            .volume("/x", |v| v.disk(nonexistent))
            .build()
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("disk image host path does not exist")
        );
    }
}

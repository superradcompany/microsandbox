//! Fluent builder for [`SandboxConfig`].

use std::collections::{BTreeMap, HashSet};
#[cfg(feature = "net")]
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(feature = "local")]
use microsandbox_image::{PullProgressHandle, PullProgressSender, snapshot::SnapshotRootDisk};
#[cfg(feature = "net")]
use microsandbox_network::builder::{NetworkBuilder, SecretBuilder};
#[cfg(feature = "net")]
use microsandbox_network::policy::Rule;
#[cfg(feature = "net")]
use microsandbox_network::{OutboundProxyBuilder, OutboundProxyConfig};
use microsandbox_types::{
    CpuPlacement, EnvVar, PullPolicy, RegistryAuth, SandboxSpecPatch, VsockRouteSpec,
    VsockSocketType,
};
#[cfg(feature = "net")]
use microsandbox_types::{PortProtocol, PublishedPortSpec};

use super::Sandbox;
use super::{
    SandboxSpec,
    config::{
        RestoreOverrideIntent, SandboxConfig, SandboxConfigPatch, SnapshotRestoreMode,
        sandbox_log_level_from_runtime,
    },
    exec::{Rlimit, RlimitResource},
    init::{HandoffInit, InitOptionsBuilder},
    types::{
        DeploymentProfile, ImageBuilder, IntoImage, MountBuilder, Patch, PatchBuilder,
        RootDiskBuilder, RootfsSource, SecurityProfile, VolumeMount,
    },
};
#[cfg(feature = "local")]
use crate::UnsupportedReason;
use crate::backend::default_backend;
use crate::config::layers::BackendConfig;
#[cfg(feature = "local")]
use crate::runtime::SpawnMode;
use crate::snapshot::SnapshotReference;
use crate::{LogLevel, MicrosandboxError, MicrosandboxResult, Operation, size::Mebibytes};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Builder for constructing a [`SandboxConfig`] with a fluent API.
pub struct SandboxBuilder {
    /// Per-sandbox configuration assembled by file, CLI, and SDK inputs.
    pub(crate) config: SandboxConfigPatch,
    detached: bool,
    pub(crate) build_error: Option<crate::MicrosandboxError>,
    /// Raw script snippets supplied through construction patches. They are materialized only when
    /// building so later shell overrides determine their shebang.
    config_scripts: BTreeMap<String, String>,
    /// Pending backend-scoped snapshot reference, resolved during async `build()`.
    pending_snapshot: Option<SnapshotReference>,
    /// Distinguishes a sparse-patch snapshot, which later builder calls may override, from an
    /// explicit restore call that retains the established mutual-exclusion validation.
    pending_snapshot_from_config: bool,
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
    /// Select validation of authorized external filesystem mappings and captured handles.
    /// Strict is the default; relaxed accepts supported mismatches with warnings.
    /// Neither policy grants host access or waives full restore's required-resource checks.
    pub(crate) fn external_mount_policy(
        mut self,
        policy: super::ExternalMountRestorePolicy,
    ) -> Self {
        self.config.external_mount_policy = Some(policy);
        self
    }
    /// Start building a sandbox configuration.
    ///
    /// The name must be unique among existing sandboxes (unless
    /// [`replace`](Self::replace) is set) and no longer than 128 UTF-8 bytes.
    /// Defaults and managed overrides come from the backend active when [`build`](Self::build) runs.
    pub fn new(name: impl Into<String>) -> Self {
        // Builder calls accumulate one patch for final configuration resolution.
        // SDK env() appends preserve order and duplicates; sparse overlays still merge by key.
        let patch = SandboxSpecPatch::new()
            .name(name.into())
            .replace_env(Vec::new());
        let config = SandboxConfigPatch::new().spec(patch);

        Self {
            config,
            detached: false,
            build_error: None,
            config_scripts: BTreeMap::new(),
            pending_snapshot: None,
            pending_snapshot_from_config: false,
        }
    }

    /// Overlay sparse sandbox configuration on the hardcoded and global defaults.
    pub fn overlay(mut self, patch: SandboxConfigPatch) -> Self {
        self.config.overlay_mut(patch);
        self
    }

    /// Seed a builder from a full [`SandboxSpec`] JSON.
    ///
    /// Options chained afterwards override individual fields (last-wins), just as
    /// on a builder from [`new`](Self::new). This is the Rust entry the FFI
    /// `create_from_spec` path calls into, so both share one implementation.
    pub fn from_spec_json(json: &str) -> MicrosandboxResult<Self> {
        let spec: SandboxSpec = serde_json::from_str(json)
            .map_err(|e| MicrosandboxError::InvalidConfig(e.to_string()))?;
        Ok(Self::from(SandboxConfig::from(spec)))
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
        if self.pending_snapshot_from_config {
            self.pending_snapshot = None;
            self.pending_snapshot_from_config = false;
        }
        match image.into_rootfs_source() {
            Ok(rootfs) => {
                self.config.spec.image = Some(rootfs);
            }
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
    /// .image_with(|i| i.oci("python:3.12").root_disk(8.gib()))
    /// .image_with(|i| i.disk("./ubuntu.qcow2").fstype("ext4"))
    /// ```
    pub fn image_with(mut self, f: impl FnOnce(ImageBuilder) -> ImageBuilder) -> Self {
        if self.pending_snapshot_from_config {
            self.pending_snapshot = None;
            self.pending_snapshot_from_config = false;
        }
        match f(ImageBuilder::new()).build() {
            Ok(rootfs) => {
                self.config.spec.image = Some(rootfs);
            }
            Err(e) => {
                if self.build_error.is_none() {
                    self.build_error = Some(e);
                }
            }
        }
        self
    }

    /// Apply a CLI-selected image after discarding a lower-precedence configured snapshot.
    #[doc(hidden)]
    pub fn override_image(mut self, image: impl IntoImage) -> Self {
        self.pending_snapshot = None;
        self.pending_snapshot_from_config = false;
        self.image(image)
    }

    /// Apply a CLI-selected image builder after discarding a configured snapshot.
    #[doc(hidden)]
    pub fn override_image_with(
        mut self,
        configure: impl FnOnce(ImageBuilder) -> ImageBuilder,
    ) -> Self {
        self.pending_snapshot = None;
        self.pending_snapshot_from_config = false;
        self.image_with(configure)
    }

    /// Apply a CLI-selected snapshot after discarding a lower-precedence configured image.
    #[doc(hidden)]
    pub fn override_snapshot(mut self, snapshot: impl Into<String>) -> Self {
        self.config.spec.image = Some(RootfsSource::oci(""));
        self.pending_snapshot = Some(SnapshotReference::auto(snapshot));
        self.pending_snapshot_from_config = false;
        self
    }

    /// Record a deferred configuration error, surfaced at `build()`. Keeps the
    /// first error so the earliest misconfiguration wins.
    pub(super) fn config_error(mut self, message: impl Into<String>) -> Self {
        if self.build_error.is_none() {
            self.build_error = Some(MicrosandboxError::InvalidConfig(message.into()));
        }
        self
    }

    /// Set a managed root disk of the given size for an OCI rootfs.
    ///
    /// Sugar for `root_disk_with(|d| d.size(size))`.
    pub fn root_disk(self, size: impl Into<Mebibytes>) -> Self {
        let size = size.into();
        self.root_disk_with(|d| d.size(size))
    }

    /// Configure the writable rootfs layer (root disk) for an OCI rootfs.
    ///
    /// The root disk is a property of the OCI rootfs source, so this is sugar
    /// over [`image_with`](Self::image_with) and requires an OCI image to be
    /// set first. Prefer `image_with` when configuring the image and root disk
    /// together; this method exists for call sites, such as CLIs, where the
    /// image reference and its options are parsed separately.
    ///
    /// ```ignore
    /// .image("python").root_disk_with(|d| d.tmpfs().size(2.gib()))
    /// .image("python").root_disk_with(|d| d.disk_image("./scratch.img"))
    /// ```
    pub fn root_disk_with(
        mut self,
        configure: impl FnOnce(RootDiskBuilder) -> RootDiskBuilder,
    ) -> Self {
        let root_disk = match configure(RootDiskBuilder::default()).build() {
            Ok(root_disk) => root_disk,
            Err(e) => {
                if self.build_error.is_none() {
                    self.build_error = Some(e);
                }
                return self;
            }
        };
        let mut image = self.config.spec.image.clone().unwrap_or_default();
        match &mut image {
            RootfsSource::Oci(oci) if !oci.reference.is_empty() => {
                oci.root_disk = Some(root_disk);
                self.config.spec.image = Some(image);
            }
            RootfsSource::Oci(_) => {
                if self.build_error.is_none() {
                    self.build_error = Some(crate::MicrosandboxError::InvalidConfig(
                        "root_disk() requires an OCI image to be set first".into(),
                    ));
                }
            }
            _ => {
                if self.build_error.is_none() {
                    self.build_error = Some(crate::MicrosandboxError::InvalidConfig(
                        "root_disk() is only valid for OCI images".into(),
                    ));
                }
            }
        }
        self
    }

    /// Set the writable overlay upper size for an OCI rootfs.
    #[deprecated(since = "0.6.0", note = "use `root_disk` instead")]
    pub fn oci_upper_size(self, size: impl Into<Mebibytes>) -> Self {
        self.root_disk(size)
    }

    /// Allocate virtual CPUs for this sandbox (default: 1).
    pub fn cpus(mut self, count: u8) -> Self {
        let resources = &mut self.config.spec.resources;
        if resources.max_cpus.is_some_and(|max| max < count) {
            resources.max_cpus = Some(count);
        }
        resources.cpus = Some(count);
        self
    }

    /// Set the boot-time maximum possible virtual CPUs.
    ///
    /// This reserves the CPU hotplug capacity the sandbox may use after live
    /// resize support lands. It does not increase the effective vCPU count by
    /// itself; use [`cpus`](Self::cpus) for the initial effective count.
    pub fn max_cpus(mut self, count: u8) -> Self {
        self.config.spec.resources.max_cpus = Some(count);
        self
    }

    /// Select how vCPU threads are placed on host processors.
    pub fn cpu_placement(mut self, policy: CpuPlacement) -> Self {
        self.config.spec.resources.cpu_placement = Some(policy);
        self
    }

    /// Select a host-defined placement profile by name.
    pub fn placement_profile(mut self, profile: impl Into<String>) -> Self {
        self.config.spec.resources.placement_profile = Some(Some(profile.into()));
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
        let memory_mib = size.into().as_u32();
        let resources = &mut self.config.spec.resources;
        if resources.max_memory_mib.is_some_and(|max| max < memory_mib) {
            resources.max_memory_mib = Some(memory_mib);
        }
        resources.memory_mib = Some(memory_mib);
        self
    }

    /// Set the boot-time maximum hotpluggable guest memory.
    ///
    /// This reserves memory hotplug capacity for future live resize support.
    /// It does not increase the effective guest memory by itself; use
    /// [`memory`](Self::memory) for the initial effective memory.
    pub fn max_memory(mut self, size: impl Into<Mebibytes>) -> Self {
        self.config.spec.resources.max_memory_mib = Some(size.into().as_u32());
        self
    }

    /// Select the guest transparent huge-page policy applied at boot.
    ///
    /// `Madvise` is the default and uses huge pages only for mappings that
    /// request them. `Always` can improve large anonymous-memory workloads at
    /// the cost of coarser memory allocation, while `Never` disables THP.
    pub fn thp(mut self, policy: super::TransparentHugePagePolicy) -> Self {
        self.config.spec.resources.thp = Some(policy);
        self
    }

    /// Restore a full snapshot using private copy-on-write memory.
    ///
    /// Clean pages can be shared by children; writes remain private. This requires
    /// a full snapshot and cannot be combined with a fresh boot or disk-only restore.
    pub(crate) fn forked(mut self) -> Self {
        self.config.forked = Some(true);
        self
    }

    /// Set the runtime log level for the sandbox process.
    ///
    /// This controls the verbosity of the `msb machine` process.
    pub fn log_level(mut self, level: LogLevel) -> Self {
        self.config.spec.runtime.log_level = Some(Some(sandbox_log_level_from_runtime(level)));
        self
    }

    /// Disable runtime logs for this sandbox, even if a global default exists.
    pub fn quiet_logs(mut self) -> Self {
        self.config.spec.runtime.log_level = Some(None);
        self
    }

    /// Configure whether the sandbox process is created in detached/background mode.
    ///
    /// Detached sandboxes survive the creating process. Defaults to `false`.
    pub fn detached(mut self, detached: bool) -> Self {
        self.detached = detached;
        self
    }

    /// Force-disable metrics sampling regardless of `metrics_sample_interval`.
    pub fn disable_metrics_sample(mut self) -> Self {
        self.config.spec.runtime.disable_metrics_sample = Some(true);
        self
    }

    /// Override the metrics sampling interval; pass `Duration::ZERO` to disable.
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
        self.config.spec.runtime.metrics_sample_interval_ms =
            Some(std::num::NonZero::new(ms as u64).map(std::num::NonZero::get));
        self
    }

    /// Default working directory for commands executed in this sandbox
    /// (e.g., `/app`). Used by [`exec`](super::Sandbox::exec),
    /// [`shell`](super::Sandbox::shell), and [`attach`](super::Sandbox::attach)
    /// unless overridden per-command.
    pub fn workdir(mut self, path: impl Into<String>) -> Self {
        self.config.spec.runtime.workdir = Some(Some(path.into()));
        self
    }

    /// Shell used by [`shell()`](super::Sandbox::shell) to interpret
    /// commands (default: `/bin/sh`).
    pub fn shell(mut self, shell: impl Into<String>) -> Self {
        self.config.spec.runtime.shell = Some(Some(shell.into()));
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
            self.config.registry_auth = Some(Some(auth));
        }
        self.config.insecure = Some(builder.insecure);
        self.config.ca_certs = Some(builder.ca_certs);
        self
    }

    /// Request a globally-unique slug for the sandbox (cloud backends only).
    ///
    /// Lowercase letters, digits, and single hyphens. When unset, the cloud
    /// assigns one; create fails when the slug is already taken. The local
    /// backend has no slugs and ignores this with a warning.
    pub fn slug(mut self, slug: impl Into<String>) -> Self {
        self.config.slug = Some(Some(slug.into()));
        self
    }

    /// Replace an existing sandbox with the same name during create.
    ///
    /// If a sandbox with this name is already active, microsandbox stops
    /// the prior instance before recreating it: SIGTERM, wait up to ten
    /// seconds for a graceful exit, then SIGKILL. When the prior sandbox
    /// is owned by an in-process `Sandbox` handle, the handle's
    /// underlying child is signalled and reaped directly.
    ///
    /// To override the ten-second timeout, use [`replace_with_timeout`];
    /// pass `Duration::ZERO` to skip SIGTERM and SIGKILL immediately.
    ///
    /// [`replace_with_timeout`]: Self::replace_with_timeout
    pub fn replace(mut self) -> Self {
        self.config.replace_existing = Some(true);
        self
    }

    /// Replace an existing sandbox, overriding the SIGTERM-to-SIGKILL
    /// timeout. Implies [`replace`](Self::replace) — calling this alone
    /// is enough.
    ///
    /// - `timeout > 0`: SIGTERM, wait up to `timeout`, then SIGKILL.
    /// - `timeout == Duration::ZERO`: SIGKILL immediately (skip SIGTERM).
    ///
    /// The default timeout used by [`replace`](Self::replace) is ten
    /// seconds. An expired timeout does not surface an error — the
    /// existing sandbox is force-killed and `create()` proceeds.
    pub fn replace_with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.config.replace_existing = Some(true);
        self.config.replace_with_timeout = Some(timeout);
        self
    }

    /// Override the OCI image entrypoint.
    pub fn entrypoint(mut self, cmd: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.config.spec.runtime.entrypoint = Some(cmd.into_iter().map(Into::into).collect());
        self
    }

    /// Override the OCI image command used by default-workload execution.
    ///
    /// An empty array clears the image CMD. This describes durable configuration and does not
    /// execute the command during sandbox creation.
    pub fn cmd(mut self, cmd: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.config.spec.runtime.cmd = Some(cmd.into_iter().map(Into::into).collect());
        self
    }

    /// Select the foreground command for attached CLI `run`.
    #[doc(hidden)]
    pub fn foreground_command(
        mut self,
        command: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.config
            .set_foreground_command(command.into_iter().map(Into::into).collect());
        self
    }

    /// Select the background command for detached CLI `run`.
    ///
    /// An empty command uses the image's default CMD. A non-empty command replaces CMD while
    /// preserving the effective OCI entrypoint.
    #[doc(hidden)]
    pub fn background_command(
        mut self,
        command: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.config
            .set_background_command(command.into_iter().map(Into::into).collect());
        self
    }

    /// Hand off PID 1 to a guest init binary after agentd's setup.
    ///
    /// `cmd` is either an absolute path inside the guest rootfs or
    /// the literal `"auto"`. Auto first honors a known init path at
    /// the start of the image ENTRYPOINT, preserving attached
    /// init-entrypoint commands when needed, then falls back to
    /// guest-side probing of common distro init paths.
    ///
    /// ```ignore
    /// .init("auto")
    /// .init("/lib/systemd/systemd")
    /// ```
    ///
    /// For init binaries that take argv or extra env (rare in
    /// practice), use [`init_with`](Self::init_with).
    ///
    /// `init` and `entrypoint` are orthogonal: `init` is the guest's
    /// PID 1; `entrypoint` is the user workload that agentd exec's
    /// per request. They can be combined freely.
    pub fn init(mut self, cmd: impl Into<String>) -> Self {
        self.config.spec.init = Some(HandoffInit {
            cmd: cmd.into(),
            args: Vec::new(),
            env: Vec::new(),
        });
        self
    }

    /// Hand off PID 1 with a closure-builder for argv and env. Use this
    /// when the init binary takes flags (e.g. systemd's
    /// `--unit=multi-user.target`) or needs extra env vars.
    ///
    /// ```ignore
    /// .init_with("/lib/systemd/systemd", |i| {
    ///     i.args(["--unit=multi-user.target"])
    ///      .env("container", "microsandbox")
    /// })
    /// ```
    ///
    /// Calling `.init` or `.init_with` more than once overwrites
    /// (different from `.env`, which appends). The init is
    /// pre-boot and one-shot.
    pub fn init_with(
        mut self,
        cmd: impl Into<String>,
        f: impl FnOnce(InitOptionsBuilder) -> InitOptionsBuilder,
    ) -> Self {
        let (args, env) = f(InitOptionsBuilder::default()).build();
        self.config.spec.init = Some(HandoffInit {
            cmd: cmd.into(),
            args,
            env,
        });
        self
    }

    /// Set the guest hostname. Limited to 64 UTF-8 bytes (the Linux UTS
    /// limit). Defaults to a sandbox-name-derived form when unset.
    pub fn hostname(mut self, hostname: impl Into<String>) -> Self {
        self.config.spec.runtime.hostname = Some(hostname.into());
        self
    }

    /// Set the user identity inside the sandbox (e.g., `"1000"`, `"appuser"`, `"1000:1000"`).
    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.config.spec.runtime.user = Some(user.into());
        self
    }

    /// Set the pull policy for OCI images.
    pub fn pull_policy(mut self, policy: PullPolicy) -> Self {
        self.config.spec.pull_policy = Some(policy);
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
        match self.local_network_config() {
            Ok(mut network) => {
                network.enabled = false;
                network.policy = microsandbox_network::policy::NetworkPolicy::none();
                if let Err(err) = self.set_local_network_config(network)
                    && self.build_error.is_none()
                {
                    self.build_error = Some(err);
                }
            }
            Err(err) => {
                if self.build_error.is_none() {
                    self.build_error = Some(err);
                }
            }
        }
        self
    }

    /// Configure networking via a closure.
    ///
    /// ```ignore
    /// .network(|n| n
    ///     .port(8080, 80)
    ///     .policy(NetworkPolicy::default())
    ///     .tls(|t| t.bypass("*.internal.com"))
    /// )
    /// ```
    #[cfg(feature = "net")]
    pub fn network(mut self, f: impl FnOnce(NetworkBuilder) -> NetworkBuilder) -> Self {
        let network = match self.local_network_config() {
            Ok(network) => network,
            Err(err) => {
                if self.build_error.is_none() {
                    self.build_error = Some(err);
                }
                return self;
            }
        };
        match f(NetworkBuilder::from_config(network)).build() {
            Ok(net) => {
                if let Err(err) = self.set_local_network_config(net)
                    && self.build_error.is_none()
                {
                    self.build_error = Some(err);
                }
            }
            Err(err) => {
                if self.build_error.is_none() {
                    self.build_error = Some(err.into());
                }
            }
        }
        self
    }

    /// Configure the single proxy used for outbound sandbox connections.
    ///
    /// Supports SOCKS4 for TCP and SOCKS5 for TCP and non-DNS UDP. The
    /// proxy applies uniformly to TLS-intercepted and bypassed/plain TCP.
    #[cfg(feature = "net")]
    pub fn proxy<P>(mut self, configure: impl FnOnce(OutboundProxyBuilder) -> P) -> Self
    where
        P: OutboundProxyConfig,
    {
        use microsandbox_network::policy::BuildError::InvalidOutboundProxy;

        let proxy = match configure(OutboundProxyBuilder::new()).build() {
            Ok(proxy) => proxy,
            Err(error) => {
                if self.build_error.is_none() {
                    self.build_error = Some(MicrosandboxError::from(InvalidOutboundProxy {
                        reason: error.to_string(),
                    }));
                }
                return self;
            }
        };

        match self.local_network_config() {
            Ok(mut network) => {
                network.outbound_proxy = Some(proxy);
                if let Err(err) = self.set_local_network_config(network)
                    && self.build_error.is_none()
                {
                    self.build_error = Some(err);
                }
            }
            Err(err) => {
                if self.build_error.is_none() {
                    self.build_error = Some(err);
                }
            }
        }
        self
    }

    /// Prepend explicit rules while preserving a configured policy's defaults and existing rules.
    #[cfg(feature = "net")]
    #[doc(hidden)]
    pub fn prepend_network_policy_rules(mut self, mut rules: Vec<Rule>) -> Self {
        match self.local_network_config() {
            Ok(mut network) => {
                rules.append(&mut network.policy.rules);
                network.policy.rules = rules;
                if let Err(error) = self.set_local_network_config(network)
                    && self.build_error.is_none()
                {
                    self.build_error = Some(error);
                }
            }
            Err(error) if self.build_error.is_none() => self.build_error = Some(error),
            Err(_) => {}
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
        self.push_port(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            host_port,
            guest_port,
            PortProtocol::Tcp,
        );
        self
    }

    /// Publish a TCP port on a specific host bind address.
    ///
    /// ```ignore
    /// .port_bind("0.0.0.0".parse().unwrap(), 8080, 80)
    /// ```
    #[cfg(feature = "net")]
    pub fn port_bind(mut self, host_bind: IpAddr, host_port: u16, guest_port: u16) -> Self {
        self.push_port(host_bind, host_port, guest_port, PortProtocol::Tcp);
        self
    }

    #[cfg(feature = "net")]
    fn push_port(
        &mut self,
        host_bind: IpAddr,
        host_port: u16,
        guest_port: u16,
        protocol: PortProtocol,
    ) {
        self.config
            .spec
            .network
            .ports
            .get_or_insert_default()
            .push(PublishedPortSpec {
                host_port,
                guest_port,
                protocol,
                host_bind: host_bind.to_string(),
            });
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
        self.push_port(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            host_port,
            guest_port,
            PortProtocol::Udp,
        );
        self
    }

    /// Publish a UDP port on a specific host bind address.
    #[cfg(feature = "net")]
    pub fn port_udp_bind(mut self, host_bind: IpAddr, host_port: u16, guest_port: u16) -> Self {
        self.push_port(host_bind, host_port, guest_port, PortProtocol::Udp);
        self
    }

    /// Expose a host Unix stream socket or local Windows named pipe on a guest-to-host vsock port.
    ///
    /// Guest applications connect directly to host CID 2 and `port`. No
    /// in-guest proxy or agentd integration is required.
    pub fn vsock(mut self, host_path: impl AsRef<Path>, port: u32) -> Self {
        self.config
            .spec
            .vsock
            .routes
            .get_or_insert_default()
            .push(VsockRouteSpec {
                host_socket: host_path.as_ref().to_path_buf(),
                port,
                socket_type: VsockSocketType::Stream,
            });
        self
    }

    /// Expose a host Unix datagram socket on a guest-to-host vsock port.
    ///
    /// Datagram boundaries are preserved end to end. Delivery remains
    /// best-effort, matching Unix and vsock datagram semantics. Windows does
    /// not support datagram routes.
    pub fn vsock_dgram(mut self, host_path: impl AsRef<Path>, port: u32) -> Self {
        self.config
            .spec
            .vsock
            .routes
            .get_or_insert_default()
            .push(VsockRouteSpec {
                host_socket: host_path.as_ref().to_path_buf(),
                port,
                socket_type: VsockSocketType::Dgram,
            });
        self
    }

    /// Add a fully specified guest-to-host vsock route.
    pub fn vsock_route(mut self, route: VsockRouteSpec) -> Self {
        self.config
            .spec
            .vsock
            .routes
            .get_or_insert_default()
            .push(route);
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
    ///     .allow("api.openai.com")
    /// )
    /// ```
    ///
    /// Automatically enables TLS interception if not already enabled.
    #[cfg(feature = "net")]
    pub fn secret(self, f: impl FnOnce(SecretBuilder) -> SecretBuilder) -> Self {
        self.secret_entry(f(SecretBuilder::new()).build())
    }

    /// Add a materialized secret entry.
    #[cfg(feature = "net")]
    pub fn secret_entry(
        mut self,
        entry: microsandbox_network::secrets::config::SecretEntry,
    ) -> Self {
        match self.local_network_config() {
            Ok(mut network) => {
                network.secrets.secrets.push(entry);
                super::config::ensure_tls_for_secrets(&mut network);
                if let Err(err) = self.set_local_network_config(network)
                    && self.build_error.is_none()
                {
                    self.build_error = Some(err);
                }
            }
            Err(err) => {
                if self.build_error.is_none() {
                    self.build_error = Some(err);
                }
            }
        }
        self
    }

    /// Set the default action for blocked secret placeholders.
    #[cfg(feature = "net")]
    pub fn secret_violation_action(
        mut self,
        action: microsandbox_types::SecretViolationAction,
    ) -> Self {
        match self.local_network_config() {
            Ok(mut network) => {
                network.secrets.violation_action = action;
                if let Err(err) = self.set_local_network_config(network)
                    && self.build_error.is_none()
                {
                    self.build_error = Some(err);
                }
            }
            Err(err) if self.build_error.is_none() => self.build_error = Some(err),
            Err(_) => {}
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
    ///
    /// **Plaintext at rest.** The value is persisted verbatim in the durable
    /// sandbox config and stays there until a later `modify` rotate with a
    /// source reference migrates the entry. This path exists for embedders
    /// who hold only a value (e.g. from their own vault); prefer
    /// `.secret(|s| s.source(..))` when the value can be referenced instead.
    /// Downstream behavior is identical either way: the guest sees only the
    /// placeholder, the proxy injects the value for allowed hosts, and
    /// in-memory copies are zeroized. When a host-side secret store lands,
    /// this method will import the value and store a reference — same
    /// signature, no more raw value at rest.
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
        self.secret(|s| s.env(&env_var).value(value).allow(allowed_host))
    }

    /// Set an environment variable visible to all commands in this sandbox.
    /// Can be called multiple times. Per-command env vars (on exec/shell)
    /// are merged on top.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        let key = key.into();
        if key.starts_with("MSB_") {
            if self.build_error.is_none() {
                self.build_error = Some(crate::MicrosandboxError::InvalidConfig(format!(
                    "environment variable {key:?} uses the reserved MSB_ prefix"
                )));
            }
            return self;
        }
        self.config.spec.get_env_mut().push(EnvVar::new(key, value));
        self
    }

    /// Set multiple environment variables at once. See [`env`](Self::env).
    pub fn envs(
        mut self,
        vars: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        for (k, v) in vars {
            self = self.env(k, v);
        }
        self
    }

    /// Attach a label (`key`/`value`) to the sandbox for attribution.
    pub fn label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.config
            .spec
            .get_labels_mut()
            .insert(key.into(), value.into());
        self
    }

    /// Attach multiple labels at once. See [`label`](Self::label).
    pub fn labels(
        mut self,
        labels: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        for (k, v) in labels {
            self = self.label(k, v);
        }
        self
    }

    /// Set a sandbox-wide resource limit inherited by all guest processes.
    ///
    /// This is applied during agentd PID 1 startup, so bootstrap scripts and
    /// long-lived daemons inherit the raised baseline without needing explicit
    /// per-exec rlimits.
    pub fn rlimit(mut self, resource: RlimitResource, limit: u64) -> Self {
        self.config
            .spec
            .rlimits
            .get_or_insert_default()
            .push(Rlimit {
                resource,
                soft: limit,
                hard: limit,
            });
        self
    }

    /// Set a sandbox-wide resource limit with different soft/hard values.
    pub fn rlimit_range(mut self, resource: RlimitResource, soft: u64, hard: u64) -> Self {
        self.config
            .spec
            .rlimits
            .get_or_insert_default()
            .push(Rlimit {
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
        let name = name.into();
        self.config_scripts.remove(&name);
        self.config
            .spec
            .runtime
            .get_scripts_mut()
            .insert(name, content.into());
        self
    }

    /// Register multiple scripts at once. See [`script`](Self::script).
    pub fn scripts(
        mut self,
        scripts: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        for (name, content) in scripts {
            let name = name.into();
            self.config_scripts.remove(&name);
            self.config
                .spec
                .runtime
                .get_scripts_mut()
                .insert(name, content.into());
        }
        self
    }

    /// Mark the sandbox as ephemeral (or persistent).
    ///
    /// Ephemeral sandboxes are one-off: the host runtime that owns the
    /// process removes the persisted DB row and on-disk state once the VM
    /// reaches a terminal status, and other host runtimes opportunistically
    /// clean up leftovers from runtimes that died first. This sets policy
    /// intent only; enforcement is runtime-owned, never an SDK/CLI reaper.
    /// Defaults to persistent (`false`).
    ///
    /// Note: removing an ephemeral sandbox also drops its logs and captured
    /// output, since those live under the sandbox directory.
    pub fn ephemeral(mut self, ephemeral: bool) -> Self {
        self.config.spec.lifecycle.ephemeral = Some(ephemeral);
        self
    }

    /// Set a maximum sandbox lifetime in seconds.
    pub fn max_duration(mut self, secs: u64) -> Self {
        self.config.spec.lifecycle.max_duration_secs = Some(secs);
        self
    }

    /// Auto-stop the sandbox after this many seconds of inactivity.
    /// Inactivity is detected via agentd heartbeat. Omit to disable (default).
    pub fn idle_timeout(mut self, secs: u64) -> Self {
        self.config.spec.lifecycle.idle_timeout_secs = Some(secs);
        self
    }

    /// Set the in-guest security profile.
    pub fn security(mut self, profile: SecurityProfile) -> Self {
        self.config.spec.security_profile = Some(profile);
        self
    }

    /// Set the host-runtime deployment profile.
    ///
    /// Managed backends may replace this request with a platform-owned profile
    /// before launch. The cloud create wire does not transmit this value.
    pub fn deployment_profile(mut self, profile: DeploymentProfile) -> Self {
        self.config.spec.deployment_profile = Some(profile);
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
            Ok(mount) => {
                self.config.spec.mounts.get_or_insert_default().push(mount);
            }
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
    /// Patches are applied before VM start. Managed OCI roots bake patches into their writable
    /// upper, flat OCI roots bake them into the private complete root disk, and bind roots patch
    /// the host directory directly. User-owned disk-image roots and tmpfs roots reject patches.
    ///
    /// ```ignore
    /// .patch(|p| p
    ///     .text("/etc/app.conf", config_str, None, false)
    ///     .copy_file("./cert.pem", "/etc/ssl/cert.pem", None, false)
    ///     .mkdir("/var/cache/app", None)
    /// )
    /// ```
    pub fn patch(mut self, f: impl FnOnce(PatchBuilder) -> PatchBuilder) -> Self {
        self.config
            .spec
            .patches
            .get_or_insert_default()
            .extend(f(PatchBuilder::new()).build());
        self
    }

    /// Add a single patch directly.
    pub fn add_patch(mut self, patch: Patch) -> Self {
        self.config.spec.patches.get_or_insert_default().push(patch);
        self
    }

    /// Add one already-materialized volume mount.
    #[doc(hidden)]
    pub fn add_volume_mount(mut self, mount: VolumeMount) -> Self {
        self.config.spec.mounts.get_or_insert_default().push(mount);
        self
    }

    /// Cold-boot only the disk state carried by a full snapshot.
    ///
    /// This is a restore policy, not a different artifact kind. It must be combined with
    /// [`with_snapshot_reference`](Self::with_snapshot_reference), and the selected artifact must contain checkpoint
    /// state. Memory, execution, and device state are deliberately ignored.
    pub(crate) fn disk_only(mut self) -> Self {
        self.config.snapshot_restore_mode = Some(SnapshotRestoreMode::DiskOnly);
        self
    }

    /// Supply the base snapshot or standalone archive for omitted disk layers and RAM objects.
    pub(crate) fn snapshot_base(mut self, base: impl Into<String>) -> Self {
        self.config.snapshot_base = Some(base.into());
        self
    }

    /// Defer snapshot resolution to the selected backend.
    ///
    /// References returned by [`crate::snapshot::Snapshot::reference`] and
    /// [`SnapshotHandle::reference`](crate::snapshot::SnapshotHandle::reference)
    /// preserve whether the selected backend resolves the value as an
    /// identifier or a path.
    pub(crate) fn with_snapshot_reference(
        mut self,
        reference: impl Into<SnapshotReference>,
    ) -> Self {
        self.pending_snapshot = Some(reference.into());
        self.pending_snapshot_from_config = false;
        self
    }

    /// Record an already-resolved local snapshot artifact.
    ///
    /// This compatibility helper derives the artifact directory from
    /// `upper_source`; creation still validates that directory's snapshot descriptor.
    /// A loose disk file without a descriptor is not a snapshot and is rejected before
    /// the destination is changed. New code should prefer [`Sandbox::restore_ref`](super::Sandbox::restore_ref),
    /// which lets the selected backend resolve the snapshot without requiring
    /// callers to inspect its storage layout.
    pub fn snapshot_resolved(
        mut self,
        image_manifest_digest: impl Into<String>,
        upper_source: impl Into<std::path::PathBuf>,
    ) -> Self {
        let upper_source = upper_source.into();
        self.config.manifest_digest = Some(Some(image_manifest_digest.into()));
        if let Some(artifact_dir) = upper_source.parent() {
            self.config.snapshot_reference = Some(SnapshotReference::path(
                artifact_dir.to_string_lossy().into_owned(),
            ));
        } else {
            self =
                self.config_error("snapshot upper source must have an artifact parent directory");
        }
        self
    }

    /// Build the configuration without creating the sandbox.
    ///
    /// Snapshot restoration uses [`Sandbox::restore`] instead of the creation builder.
    /// Using the active backend's cached configuration, global defaults, accumulated
    /// CLI/SDK patches, and managed overrides are overlaid in that order, then validated.
    /// A concrete config cannot retain the distinction between an omitted and cleared workdir:
    /// on local creation, `None` inherits global or image defaults. Use [`create`](Self::create)
    /// directly to preserve explicit workdir clears through image resolution.
    pub async fn build(mut self) -> MicrosandboxResult<SandboxConfig> {
        let backend = default_backend();
        #[cfg(feature = "cloud")]
        if let Some(cloud) = backend.as_cloud() {
            return cloud.build_sandbox_config(self).await;
        }
        self.prepare(backend.clone()).await?;
        self.finish(BackendConfig::for_backend(backend.as_ref()), None)
    }

    pub(crate) fn finish(
        mut self,
        backend_config: Option<&BackendConfig>,
        image_defaults: Option<SandboxConfigPatch>,
    ) -> MicrosandboxResult<SandboxConfig> {
        let restore_overrides = self
            .config
            .restore_overrides
            .unwrap_or_else(|| self.restore_override_intent());
        // Snapshot preparation has already fixed the VM geometry and root layout.
        // Policy may reject that state, but must never silently rewrite it.
        let captured_resources = self
            .config
            .resumed_from_full_snapshot
            .unwrap_or_default()
            .then(|| self.config.spec.resources.clone().into_config());
        let captured_root = self
            .config
            .snapshot_parent
            .as_ref()
            .and(self.config.spec.image.as_ref())
            .and_then(RootfsSource::oci_root_disk)
            .cloned();
        let mut sandbox = SandboxConfig::default();
        sandbox.apply_layers(
            backend_config,
            std::mem::take(&mut self.config),
            image_defaults,
        );

        if let Some(captured) = captured_resources {
            let effective = &sandbox.spec.resources;
            if (
                effective.cpus,
                effective.max_cpus,
                effective.memory_mib,
                effective.max_memory_mib,
            ) != (
                captured.cpus,
                captured.max_cpus,
                captured.memory_mib,
                captured.max_memory_mib,
            ) {
                return Err(MicrosandboxError::InvalidConfig(
                    "managed settings conflict with the snapshot's captured CPU and memory geometry".into(),
                ));
            }
        }
        if let Some(captured) = captured_root
            && sandbox.spec.image.oci_root_disk().is_none_or(|effective| {
                std::mem::discriminant(effective) != std::mem::discriminant(&captured)
            })
        {
            return Err(MicrosandboxError::InvalidConfig(
                "managed settings conflict with the snapshot's captured root disk layout".into(),
            ));
        }
        sandbox.restore_overrides = restore_overrides;
        self.materialize_config_scripts(&mut sandbox);
        self.validate(&mut sandbox)?;
        Ok(sandbox)
    }

    #[cfg(feature = "net")]
    fn local_network_config(
        &self,
    ) -> MicrosandboxResult<microsandbox_network::config::NetworkConfig> {
        let mut network = super::NetworkSpec::default();
        self.config.spec.network.clone().apply_to(&mut network);
        super::config::network_config_from_spec(&network)
    }

    #[cfg(feature = "net")]
    fn set_local_network_config(
        &mut self,
        network: microsandbox_network::config::NetworkConfig,
    ) -> MicrosandboxResult<()> {
        let network = super::config::network_spec_from_config(&network)?;
        self.config.spec.network = network.into();
        Ok(())
    }

    /// Apply raw scripts loaded from configuration after the final shell is known.
    #[doc(hidden)]
    pub fn config_scripts(mut self, scripts: BTreeMap<String, String>) -> Self {
        self.config_scripts.extend(scripts);
        self
    }

    fn materialize_config_scripts(&mut self, sandbox: &mut SandboxConfig) {
        let shell = sandbox.spec.runtime.shell.as_deref();
        for (name, body) in std::mem::take(&mut self.config_scripts) {
            if let Err(message) = validate_config_script_name(&name) {
                if self.build_error.is_none() {
                    self.build_error = Some(MicrosandboxError::InvalidConfig(message));
                }
                continue;
            }
            sandbox
                .spec
                .runtime
                .scripts
                .insert(name, wrap_config_script(shell, &body));
        }
    }

    /// Resolve deferred builder inputs without materializing sandbox configuration.
    /// The backend borrows only the pending fields needed before image resolution.
    pub(crate) async fn prepare(
        &mut self,
        backend: std::sync::Arc<dyn crate::Backend>,
    ) -> MicrosandboxResult<&mut SandboxConfigPatch> {
        if let Some(error) = self.build_error.take() {
            return Err(error);
        }
        for name in self.config_scripts.keys() {
            validate_config_script_name(name).map_err(MicrosandboxError::InvalidConfig)?;
        }
        self.resolve_pending(backend).await?;
        Ok(&mut self.config)
    }

    /// Open the deferred snapshot artifact and copy its pinned image
    /// reference, manifest digest, and upper-layer source path into the
    /// config. Driven by build and create preparation.
    async fn resolve_pending(
        &mut self,
        backend: std::sync::Arc<dyn crate::Backend>,
    ) -> MicrosandboxResult<()> {
        let Some(snapshot_ref) = self.pending_snapshot.take() else {
            return Ok(());
        };
        self.pending_snapshot_from_config = false;
        if self.has_explicit_rootfs_source() {
            return Err(MicrosandboxError::InvalidConfig(
                "from_snapshot is mutually exclusive with explicit rootfs configuration".into(),
            ));
        }
        if self
            .config
            .spec
            .patches
            .as_ref()
            .is_some_and(|patches| !patches.is_empty())
        {
            return Err(MicrosandboxError::InvalidConfig(
                "patches cannot be combined with from_snapshot".into(),
            ));
        }
        let overrides = self.restore_override_intent();
        let mut config = SandboxConfig::default();
        config.apply_layers(
            BackendConfig::for_backend(backend.as_ref()),
            std::mem::take(&mut self.config),
            None,
        );
        config.restore_overrides = overrides;
        backend
            .snapshots()
            .prepare_restore(backend.clone(), &mut config, snapshot_ref)
            .await?;
        self.config = SandboxConfigPatch::from_present_fields(config);
        Ok(())
    }

    fn restore_override_intent(&self) -> RestoreOverrideIntent {
        RestoreOverrideIntent {
            cpus: self.config.spec.resources.cpus.is_some(),
            max_cpus: self.config.spec.resources.max_cpus.is_some(),
            memory: self.config.spec.resources.memory_mib.is_some(),
            max_memory: self.config.spec.resources.max_memory_mib.is_some(),
        }
    }

    fn has_explicit_rootfs_source(&self) -> bool {
        match self.config.spec.image.as_ref() {
            Some(RootfsSource::Oci(oci)) => !oci.reference.is_empty() || oci.root_disk.is_some(),
            Some(RootfsSource::Bind { path, .. }) => !path.as_os_str().is_empty(),
            Some(RootfsSource::DiskImage { .. }) => true,
            None => false,
        }
    }

    /// Create the sandbox. Boots the VM with agentd ready.
    pub async fn create(self) -> MicrosandboxResult<Sandbox> {
        let detached = self.detached;
        // Keep configuration and restore state off callers' stacks when they
        // compose multiple creates in a single async task.
        Box::pin(self.create_with_mode(
            detached,
            #[cfg(feature = "local")]
            None,
        ))
        .await
    }

    /// Connect to the persisted sandbox with this name, or create it.
    ///
    /// Existing sandboxes keep their persisted configuration: running ones
    /// are connected and stopped ones are started. Builder configuration is
    /// used only when this call creates the sandbox. A concurrent creator is
    /// handled by connecting to and converging on the winner.
    pub async fn connect_or_create(self) -> MicrosandboxResult<Sandbox> {
        if self.config.replace_existing.unwrap_or(false) {
            return Err(MicrosandboxError::InvalidConfig(
                "connect_or_create cannot be combined with replace_existing".to_string(),
            ));
        }

        let name = self.config.spec.name.clone().unwrap_or_default();
        let detached = self.detached;
        match Sandbox::get(&name).await {
            Ok(handle) => return handle.connect_or_start_with_mode(detached).await,
            Err(MicrosandboxError::SandboxNotFound(_)) => {}
            Err(error) => return Err(error),
        }

        match self.create().await {
            Ok(sandbox) => Ok(sandbox),
            Err(MicrosandboxError::SandboxAlreadyExists(_)) => {
                Sandbox::get(&name)
                    .await?
                    .connect_or_start_with_mode(detached)
                    .await
            }
            Err(error) => Err(error),
        }
    }

    /// Create the sandbox for detached/background use.
    pub async fn create_detached(self) -> MicrosandboxResult<Sandbox> {
        Box::pin(self.create_with_mode(
            true,
            #[cfg(feature = "local")]
            None,
        ))
        .await
    }

    /// Create with image-pull, snapshot-preparation, and activation progress.
    ///
    /// Events are best-effort and never block creation. Await the task for the authoritative
    /// result; dropping the progress receiver does not cancel it. Abort the task to cancel.
    #[cfg(feature = "local")]
    pub fn create_with_progress(
        mut self,
    ) -> crate::MicrosandboxResult<(
        crate::CreationProgressHandle,
        tokio::task::JoinHandle<crate::MicrosandboxResult<super::Sandbox>>,
    )> {
        let (handle, sender) = crate::progress::channel();
        self.config.creation_progress = Some(sender.downgrade());
        let task = tokio::spawn(async move {
            if self.pending_snapshot.is_some() {
                let _ = sender.try_send(crate::CreationProgress::Startup(
                    crate::StartupProgress::phase(crate::StartupPhase::PreparingSnapshot),
                ));
            }
            let (mut pull, pull_sender) = microsandbox_image::progress_channel();
            let detached = self.detached;
            let create = self.create_with_mode(detached, Some(pull_sender));
            let forward = async {
                while let Some(event) = pull.recv().await {
                    let _ = sender.try_send(crate::CreationProgress::Pull(event));
                }
            };
            // No detached forwarding task: cancellation drops both futures together.
            let (result, ()) = tokio::join!(create, forward);
            result
        });
        Ok((handle, task))
    }

    /// Create a detached sandbox with the same creation-progress stream.
    #[cfg(feature = "local")]
    pub fn create_detached_with_progress(
        self,
    ) -> crate::MicrosandboxResult<(
        crate::CreationProgressHandle,
        tokio::task::JoinHandle<crate::MicrosandboxResult<super::Sandbox>>,
    )> {
        self.detached(true).create_with_progress()
    }

    /// Create the sandbox with pull progress reporting.
    ///
    /// Returns a progress handle for per-layer pull events and a task handle
    /// for the sandbox creation result. Useful for CLI commands that want to
    /// display per-layer download/materialization progress during sandbox creation.
    ///
    /// Snapshot restoration has its own `RestoreBuilder::restore_with_progress`
    /// terminal; both operations spawn work without blocking the caller.
    #[cfg(feature = "local")]
    pub fn create_with_pull_progress(
        self,
    ) -> MicrosandboxResult<(
        PullProgressHandle,
        tokio::task::JoinHandle<crate::MicrosandboxResult<Sandbox>>,
    )> {
        let (handle, sender) = microsandbox_image::progress_channel();
        let task = tokio::spawn(async move {
            let detached = self.detached;
            self.create_with_mode(detached, Some(sender)).await
        });
        Ok((handle, task))
    }

    /// Like `create_with_pull_progress` but spawns the sandbox process in detached
    /// mode so the sandbox survives after the creating process exits.
    #[cfg(feature = "local")]
    pub fn create_detached_with_pull_progress(
        self,
    ) -> MicrosandboxResult<(
        PullProgressHandle,
        tokio::task::JoinHandle<crate::MicrosandboxResult<Sandbox>>,
    )> {
        let (handle, sender) = microsandbox_image::progress_channel();
        let task = tokio::spawn(async move { self.create_with_mode(true, Some(sender)).await });
        Ok((handle, task))
    }

    async fn create_with_mode(
        mut self,
        detached: bool,
        #[cfg(feature = "local")] progress: Option<PullProgressSender>,
    ) -> MicrosandboxResult<Sandbox> {
        let backend = default_backend();
        #[cfg(feature = "local")]
        if let Some(local) = backend.as_local() {
            let mode = if detached {
                SpawnMode::Detached
            } else {
                SpawnMode::Attached
            };
            // Keep the local restore future off callers' stacks, including cloud callers.
            return Box::pin(local.create_sandbox(backend.clone(), self, mode, progress)).await;
        }

        // Cloud doesn't transmit progress information yet.
        #[cfg(feature = "local")]
        drop(progress);
        #[cfg(feature = "cloud")]
        if let Some(cloud) = backend.as_cloud() {
            return cloud.create_from_builder(backend.clone(), self, true).await;
        }
        self.prepare(backend.clone()).await?;

        // Custom backends receive a concrete request and own their configuration behavior.
        let sandboxes = backend.sandboxes();
        let config = self.finish(None, None)?;
        if detached || config.resumed_from_full_snapshot() {
            sandboxes.create_detached(backend.clone(), config).await
        } else {
            sandboxes.create(backend.clone(), config, true).await
        }
    }
}
impl SandboxBuilder {
    /// Validate the configuration before building.
    fn validate(&mut self, sandbox: &mut SandboxConfig) -> MicrosandboxResult<()> {
        if let Some(err) = self.build_error.take() {
            return Err(err);
        }

        if sandbox.spec.name.is_empty() {
            return Err(crate::MicrosandboxError::InvalidConfig(
                "sandbox name is required".into(),
            ));
        }
        super::validate_sandbox_name(&sandbox.spec.name)?;
        super::validate_hostname(sandbox.spec.runtime.hostname.as_deref())?;
        if sandbox.spec.resources.cpus == 0 {
            return Err(crate::MicrosandboxError::InvalidConfig(
                "cpus must be greater than 0".into(),
            ));
        }
        if sandbox.spec.resources.memory_mib == 0 {
            return Err(crate::MicrosandboxError::InvalidConfig(
                "memory must be greater than 0".into(),
            ));
        }
        if sandbox.spec.resources.max_cpus == 0 {
            return Err(crate::MicrosandboxError::InvalidConfig(
                "max_cpus must be greater than 0".into(),
            ));
        }
        if sandbox.spec.resources.max_memory_mib == 0 {
            return Err(crate::MicrosandboxError::InvalidConfig(
                "max_memory must be greater than 0".into(),
            ));
        }
        if sandbox.spec.resources.max_cpus < sandbox.spec.resources.cpus {
            return Err(crate::MicrosandboxError::InvalidConfig(format!(
                "max_cpus {} must be greater than or equal to cpus {}",
                sandbox.spec.resources.max_cpus, sandbox.spec.resources.cpus
            )));
        }
        if sandbox.spec.resources.max_memory_mib < sandbox.spec.resources.memory_mib {
            return Err(crate::MicrosandboxError::InvalidConfig(format!(
                "max_memory {} MiB must be greater than or equal to memory {} MiB",
                sandbox.spec.resources.max_memory_mib, sandbox.spec.resources.memory_mib
            )));
        }

        // Check that image is set (non-empty OCI string or Bind path). A direct
        // archive restore resolves its pinned image while the local backend
        // authenticates and streams the archive into child-owned staging. Keep
        // that path single-pass instead of scanning the archive once here and
        // then reading the payload again during creation.
        match &sandbox.spec.image {
            RootfsSource::Oci(oci)
                if oci.reference.is_empty() && sandbox.snapshot_archive_source.is_some() =>
            {
                // The archive source is transient and cloud conversion rejects
                // it explicitly, so only the local backend may defer this field.
            }
            RootfsSource::Oci(oci)
                if oci.reference.is_empty() && sandbox.snapshot_reference.is_none() =>
            {
                return Err(crate::MicrosandboxError::InvalidConfig(
                    "image source is required".into(),
                ));
            }
            RootfsSource::Oci(oci) => {
                Self::validate_root_disk(sandbox, oci.root_disk.as_ref())?;
            }
            RootfsSource::DiskImage { .. } if !sandbox.spec.patches.is_empty() => {
                return Err(crate::MicrosandboxError::InvalidConfig(
                    "patches are not compatible with disk image rootfs".into(),
                ));
            }
            _ => {}
        }
        #[cfg(feature = "local")]
        if sandbox.snapshot_restore_mode == SnapshotRestoreMode::DiskOnly
            && sandbox.snapshot_archive_source.is_none()
            && sandbox.checkpoint_restore.is_none()
        {
            return Err(crate::MicrosandboxError::InvalidConfig(
                "disk_only must be combined with from_snapshot".into(),
            ));
        }
        #[cfg(feature = "local")]
        if sandbox.forked
            && (sandbox.snapshot_restore_mode == SnapshotRestoreMode::DiskOnly
                || (sandbox.checkpoint_restore.is_none()
                    && sandbox.snapshot_archive_source.is_none()))
        {
            return Err(crate::MicrosandboxError::InvalidConfig(
                "forked requires a full snapshot restore and cannot be combined with disk_only"
                    .into(),
            ));
        }
        #[cfg(feature = "local")]
        if sandbox.checkpoint_restore.is_some() && !sandbox.spec.patches.is_empty() {
            return Err(crate::MicrosandboxError::InvalidConfig(
                "patches cannot be combined with full snapshot restore".into(),
            ));
        }
        if sandbox.snapshot_base.is_some() && sandbox.snapshot_archive_source.is_none() {
            return Err(crate::MicrosandboxError::InvalidConfig(
                "snapshot_base requires from_snapshot with an archive path".into(),
            ));
        }

        for rlimit in &sandbox.spec.rlimits {
            if rlimit.soft > rlimit.hard {
                return Err(crate::MicrosandboxError::InvalidConfig(format!(
                    "rlimit {}: soft ({}) must not exceed hard ({})",
                    rlimit.resource.as_str(),
                    rlimit.soft,
                    rlimit.hard
                )));
            }
        }

        super::types::validate_volume_mounts(&mut sandbox.spec.mounts)?;
        super::validate_env(&sandbox.spec.env)?;
        super::validate_labels(&sandbox.spec.labels)?;
        Self::validate_vsock_routes(sandbox)?;

        if let Err(error) = microsandbox_types::resolve_default_command(
            sandbox.spec.runtime.entrypoint.as_deref(),
            sandbox.spec.runtime.cmd.as_deref(),
            None,
        ) && !matches!(
            error,
            microsandbox_types::CommandResolutionError::NoDefaultCommand
        ) {
            return Err(error.into());
        }

        if let Some(spec) = &sandbox.spec.init {
            super::init::validate(spec)?;
        }

        #[cfg(feature = "net")]
        sandbox
            .local_network_config()?
            .secrets
            .validate()
            .map_err(|err| {
                crate::MicrosandboxError::InvalidConfig(format!("invalid network secrets: {err}"))
            })?;

        // Reject any two DiskImage mounts pointing at the same host file.
        // Each virtio-blk device caches independently on the host, so any
        // mix of writable+writable, writable+read-only, or even two
        // read-only mounts of the same image will diverge from the
        // kernel's view (RW invalidates the RO cache; RO+RO doubles the
        // page-cache footprint with no benefit). Compare against the
        // canonical path so symlinks and `./` prefixes don't bypass the
        // check.
        let mut seen: Vec<PathBuf> = Vec::new();
        for mount in &sandbox.spec.mounts {
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

    /// Validate the stable route key and the host resources it references.
    pub(crate) fn validate_vsock_routes(sandbox: &SandboxConfig) -> MicrosandboxResult<()> {
        if sandbox.spec.deployment_profile == DeploymentProfile::MultiTenant
            && !sandbox.spec.vsock.is_empty()
        {
            return Err(MicrosandboxError::InvalidConfig(
                "host vsock routes are disabled for multi-tenant deployments".into(),
            ));
        }

        let mut routes = HashSet::new();

        for route in &sandbox.spec.vsock.routes {
            #[cfg(unix)]
            if !route.host_socket.is_absolute() {
                return Err(crate::MicrosandboxError::InvalidConfig(format!(
                    "vsock host path must be absolute: {}",
                    route.host_socket.display()
                )));
            }
            #[cfg(windows)]
            {
                let path = route.host_socket.as_os_str().to_string_lossy();
                let prefix = r"\\.\pipe\";
                let local = path
                    .get(..prefix.len())
                    .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix));
                let name = path.get(prefix.len()..).unwrap_or_default();
                if !local
                    || name.is_empty()
                    || name
                        .split(['\\', '/'])
                        .any(|part| part.is_empty() || part == "." || part == "..")
                {
                    return Err(crate::MicrosandboxError::InvalidConfig(format!(
                        "vsock host path must be a local Windows named pipe such as \\\\.\\pipe\\api: {}",
                        route.host_socket.display()
                    )));
                }
                if route.socket_type == VsockSocketType::Dgram {
                    return Err(MicrosandboxError::unsupported(
                        Operation::SandboxCreate,
                        crate::UnsupportedReason::RequiresUnixHost,
                    ));
                }
            }
            if route.port == 0 || route.port == u32::MAX {
                return Err(crate::MicrosandboxError::InvalidConfig(format!(
                    "vsock port {} must be between 1 and {}",
                    route.port,
                    u32::MAX - 1
                )));
            }
            // libkrun uses datagram port 123 for host-to-guest clock updates
            // on macOS. Reserving it everywhere keeps configurations portable.
            if route.socket_type == VsockSocketType::Dgram && route.port == 123 {
                return Err(crate::MicrosandboxError::InvalidConfig(
                    "vsock datagram port 123 is reserved for guest clock synchronization".into(),
                ));
            }
            if !routes.insert((route.socket_type, route.port)) {
                return Err(crate::MicrosandboxError::InvalidConfig(format!(
                    "duplicate vsock {:?} route for port {}",
                    route.socket_type, route.port
                )));
            }
        }

        Ok(())
    }

    /// Kind-specific root disk guards for an OCI rootfs.
    fn validate_root_disk(
        sandbox: &SandboxConfig,
        root_disk: Option<&super::types::RootDisk>,
    ) -> MicrosandboxResult<()> {
        use super::types::RootDisk;

        match root_disk {
            None | Some(RootDisk::Managed { size_mib: None }) => Ok(()),
            Some(RootDisk::Managed { size_mib: Some(0) }) => {
                Err(crate::MicrosandboxError::InvalidConfig(
                    "root disk size must be greater than 0".into(),
                ))
            }
            Some(RootDisk::Managed { .. }) => Ok(()),
            Some(RootDisk::Tmpfs { size_mib }) => {
                if *size_mib == Some(0) {
                    return Err(crate::MicrosandboxError::InvalidConfig(
                        "root disk size must be greater than 0".into(),
                    ));
                }
                // tmpfs pages come from guest RAM and the guest has no swap:
                // writes past memory are an OOM kill, not ENOSPC.
                if let Some(size) = size_mib
                    && *size > sandbox.spec.resources.memory_mib
                {
                    return Err(crate::MicrosandboxError::InvalidConfig(format!(
                        "tmpfs root disk size ({size} MiB) must not exceed sandbox memory ({} MiB)",
                        sandbox.spec.resources.memory_mib
                    )));
                }
                if !sandbox.spec.patches.is_empty() {
                    return Err(crate::MicrosandboxError::InvalidConfig(
                        "patches require a managed or flat sandbox-owned root disk".into(),
                    ));
                }
                Ok(())
            }
            Some(RootDisk::DiskImage { path, .. }) => {
                if path.as_os_str().is_empty() {
                    return Err(crate::MicrosandboxError::InvalidConfig(
                        "disk-image root disk path must not be empty".into(),
                    ));
                }
                if !sandbox.spec.patches.is_empty() {
                    return Err(crate::MicrosandboxError::InvalidConfig(
                        "patches require a managed or flat sandbox-owned root disk".into(),
                    ));
                }
                if sandbox.snapshot_upper_source.is_some()
                    || sandbox.snapshot_archive_source.is_some()
                {
                    return Err(crate::MicrosandboxError::InvalidConfig(
                        "from_snapshot requires a managed root disk".into(),
                    ));
                }
                Ok(())
            }
            Some(RootDisk::Flat {
                size_mib, fstype, ..
            }) => {
                if *size_mib == Some(0) {
                    return Err(crate::MicrosandboxError::InvalidConfig(
                        "flat root disk size must be greater than 0".into(),
                    ));
                }
                if fstype.as_deref().unwrap_or("ext4") != "ext4" {
                    return Err(crate::MicrosandboxError::InvalidConfig(
                        "flat root disks currently support only fstype=ext4".into(),
                    ));
                }
                Ok(())
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Populate local restore inputs without changing capture semantics during backend dispatch.
#[cfg(feature = "local")]
pub(crate) fn prepare_local_snapshot_restore(
    config: &mut SandboxConfig,
    snap: &crate::snapshot::Snapshot,
) -> MicrosandboxResult<()> {
    // A security profile is a boot-time guest policy, not a host-side restore override.
    // Validate the caller's explicit intent before preparing any snapshot resources.
    config
        .restore_boot_overrides
        .validate_scope(snap.manifest().scope, config.snapshot_restore_mode)?;
    if config.spec.runtime.user.is_none() {
        config.spec.runtime.user = snap.manifest().restore_defaults()?.user;
    }
    config.snapshot_parent = Some(snap.id().to_string());
    let unsupported = snap.manifest().unsupported_requires();
    if !unsupported.is_empty() {
        return Err(crate::MicrosandboxError::unsupported(
            Operation::SnapshotOps,
            UnsupportedReason::NotAvailable(format!(
                "snapshot requires unsupported runtime capabilities: {}",
                unsupported.join(", ")
            )),
        ));
    }
    let snap_ref = snap.manifest().image.reference.clone();
    config.spec.image = RootfsSource::oci(snap_ref);
    config.manifest_digest = Some(snap.manifest().image.manifest_digest.clone());
    apply_snapshot_root_layout(config, &snap.manifest().root_disk)?;

    let file_state = match &snap.manifest().state {
        crate::snapshot::SnapshotState::File(state) => state,
        crate::snapshot::SnapshotState::Checkpoint(state) => {
            if snap.manifest().scope != crate::snapshot::SnapshotScope::Full {
                return Err(crate::MicrosandboxError::SnapshotIntegrity(
                    "checkpoint state must use full snapshot scope".into(),
                ));
            }
            let expected = microsandbox_image::checkpoint::ObjectId::new(&state.checkpoint_root)
                .map_err(|error| crate::MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
            let closure = snap.path()?.join(crate::snapshot::CHECKPOINT_DIRECTORY);
            let opened = microsandbox_image::checkpoint::CheckpointClosure::inspect_manifest(
                &closure,
                Some(&expected),
            )
            .map_err(|error| crate::MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
            if opened.checkpoint_id != state.checkpoint_id {
                return Err(crate::MicrosandboxError::SnapshotIntegrity(
                    "snapshot and checkpoint closure identities differ".into(),
                ));
            }
            crate::snapshot::validate_checkpoint_owned_inventory(snap.manifest(), &opened)?;
            if config.snapshot_restore_mode == SnapshotRestoreMode::Full {
                if opened.architecture != std::env::consts::ARCH {
                    return Err(crate::MicrosandboxError::SnapshotIntegrity(
                        "checkpoint architecture cannot restore on this host".into(),
                    ));
                }
                let restore_overrides = config.restore_overrides;
                apply_checkpoint_restore_constraints(config, state, &opened, restore_overrides)?;
                config.suppress_launch_for_full_restore();
            }
            config.checkpoint_restore =
                Some(microsandbox_runtime::launch::CheckpointRestoreConfig {
                    memory_descriptor: false,
                    network_gateway_mac: if config.snapshot_restore_mode
                        == SnapshotRestoreMode::Full
                    {
                        microsandbox_runtime::checkpoint::captured_gateway_mac(&opened.resources)
                            .map_err(crate::MicrosandboxError::SnapshotIntegrity)?
                    } else {
                        None
                    },
                    external_mount_policy: config.external_mount_policy,
                    external_mounts: Vec::new(),
                    unavailable_disks: Default::default(),
                    local_branch: false,
                    forked: false,
                    closure,
                    checkpoint_root: state.checkpoint_root.clone(),
                    checkpoint_id: state.checkpoint_id.clone(),
                });
            return Ok(());
        }
    };
    if config.snapshot_restore_mode == SnapshotRestoreMode::DiskOnly {
        return Err(crate::MicrosandboxError::InvalidConfig(
            "disk_only requires a full snapshot with checkpoint state".into(),
        ));
    }
    if snap.manifest().scope != crate::snapshot::SnapshotScope::Disk {
        return Err(crate::MicrosandboxError::SnapshotIntegrity(
            "file state must use disk snapshot scope".into(),
        ));
    }
    if file_state.filesystem != "ext4" {
        return Err(crate::MicrosandboxError::unsupported(
            Operation::SnapshotOps,
            UnsupportedReason::NotAvailable(format!(
                "snapshot file state {:?}/{} is not qualified for restore",
                file_state.disk_format, file_state.filesystem
            )),
        ));
    }
    config.snapshot_root_layer_sources = file_state
        .layers
        .iter()
        .map(|layer| {
            Ok(microsandbox_runtime::launch::RootfsUpperLayerConfig {
                path: snap.layer_path(layer)?,
                format: match layer.format {
                    crate::snapshot::SnapshotFormat::Raw => "raw",
                    crate::snapshot::SnapshotFormat::Qcow2 => "qcow2",
                }
                .into(),
            })
        })
        .collect::<MicrosandboxResult<Vec<_>>>()?;
    config.snapshot_root_virtual_size = Some(file_state.virtual_size);
    let owned = snap.manifest().owned_volumes()?;
    if !owned.is_empty() {
        config.snapshot_owned_source = Some((snap.path()?.to_path_buf(), owned));
    }
    Ok(())
}

#[cfg(feature = "local")]
pub(crate) fn apply_snapshot_root_layout(
    config: &mut SandboxConfig,
    layout: &SnapshotRootDisk,
) -> MicrosandboxResult<()> {
    let RootfsSource::Oci(oci) = &mut config.spec.image else {
        return Err(MicrosandboxError::SnapshotIntegrity(
            "snapshot image did not resolve to an OCI rootfs".into(),
        ));
    };
    oci.root_disk = Some(match layout {
        SnapshotRootDisk::Managed => microsandbox_types::RootDisk::Managed { size_mib: None },
        SnapshotRootDisk::Flat => microsandbox_types::RootDisk::Flat {
            size_mib: None,
            fstype: Some("ext4".into()),
            clone: microsandbox_types::FlatClone::Auto,
        },
        SnapshotRootDisk::Tmpfs { size_mib } => microsandbox_types::RootDisk::Tmpfs {
            size_mib: *size_mib,
        },
    });
    Ok(())
}

fn validate_config_script_name(name: &str) -> Result<(), String> {
    let path = std::path::Path::new(name);
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.as_bytes().contains(&0)
        || name.contains(['/', '\\'])
        || path.file_name().and_then(|part| part.to_str()) != Some(name)
    {
        return Err(format!(
            "script name {name:?} must be a single non-empty filename"
        ));
    }
    Ok(())
}

/// Apply the immutable VM geometry and effective guest network identity carried by a checkpoint.
///
/// Installed snapshots call this while resolving the builder. Archive restores call it after the
/// descriptor and closure have streamed into child staging.
#[cfg(feature = "local")]
pub(crate) fn apply_checkpoint_restore_constraints(
    config: &mut SandboxConfig,
    state: &crate::snapshot::CheckpointSnapshotState,
    checkpoint: &microsandbox_image::checkpoint::CheckpointManifest,
    overrides: RestoreOverrideIntent,
) -> MicrosandboxResult<()> {
    // Keep this guard at the shared boundary as well: archive descriptors are resolved later
    // than installed snapshots, and must not silently discard a requested boot policy.
    config.restore_boot_overrides.validate_scope(
        crate::snapshot::SnapshotScope::Full,
        config.snapshot_restore_mode,
    )?;
    // The summary is for inspection, not an independent source of VM layout.
    // Reject disagreement before applying configuration or preparing child disks.
    let geometry = checkpoint.geometry;
    for (key, expected) in [
        ("vcpus", u64::from(geometry.vcpus)),
        ("max_vcpus", u64::from(geometry.max_vcpus)),
        ("memory_mib", u64::from(geometry.memory_mib)),
        ("max_memory_mib", u64::from(geometry.max_memory_mib)),
    ] {
        if checkpoint_requirement_u64(state, key)? != expected {
            return Err(MicrosandboxError::SnapshotIntegrity(format!(
                "checkpoint restore summary disagrees with captured geometry for {key}"
            )));
        }
    }
    apply_checkpoint_resources(config, state, overrides)?;
    apply_capture_network(config, &checkpoint.resources)
}

#[cfg(feature = "local")]
pub(crate) fn apply_capture_network(
    config: &mut SandboxConfig,
    captured_resources: &[microsandbox_image::checkpoint::ResourceDescriptor],
) -> MicrosandboxResult<()> {
    // Reject missing gateway identity before creating child-owned disk state.
    microsandbox_runtime::checkpoint::captured_gateway_mac(captured_resources)
        .map_err(MicrosandboxError::SnapshotIntegrity)?;
    let mut resources = captured_resources
        .iter()
        .filter(|resource| resource.kind == "network");
    let Some(resource) = resources.next() else {
        if !config.spec.network.ports.is_empty() {
            return Err(MicrosandboxError::InvalidConfig(
                "a checkpoint without a network device cannot restore published ports".into(),
            ));
        }
        config.spec.network.enabled = false;
        config.spec.network.interface = None;
        return Ok(());
    };
    if resources.next().is_some() {
        return Err(MicrosandboxError::SnapshotIntegrity(
            "checkpoint contains more than one guest network resource".into(),
        ));
    }
    if !config.spec.network.enabled {
        return Err(MicrosandboxError::InvalidConfig(
            "a checkpoint with a network device cannot restore with networking disabled".into(),
        ));
    }
    let encoded = resource.binding.get("guest_network").ok_or_else(|| {
        MicrosandboxError::SnapshotIntegrity(
            "checkpoint network resource has no effective guest binding".into(),
        )
    })?;
    let network: microsandbox_protocol::bootstrap::BootstrapNetwork = serde_json::from_str(encoded)
        .map_err(|error| {
            MicrosandboxError::SnapshotIntegrity(format!(
                "checkpoint guest network binding is invalid: {error}"
            ))
        })?;
    if network.interface != "eth0" {
        return Err(MicrosandboxError::SnapshotIntegrity(format!(
            "checkpoint guest network interface {:?} is unsupported",
            network.interface
        )));
    }
    let interface = microsandbox_types::InterfaceOverrides {
        mac: Some(network.mac),
        mtu: Some(network.mtu),
        ipv4_address: network.ipv4.map(|ipv4| ipv4.address),
        ipv4_pool: None,
        ipv6_address: network.ipv6.map(|ipv6| ipv6.address),
        ipv6_pool: None,
    };
    if config
        .spec
        .network
        .interface
        .as_ref()
        .is_some_and(|requested| checkpoint_network_override_conflicts(requested, &interface))
    {
        return Err(MicrosandboxError::InvalidConfig(
            "full snapshot restore cannot change the captured guest network identity".into(),
        ));
    }
    config.spec.network.interface = Some(interface);
    Ok(())
}

/// Return whether an explicitly populated guest-interface field conflicts with the captured
/// effective identity. An empty `InterfaceOverrides` is the normal result of round-tripping local
/// network defaults through the shared spec and must not be mistaken for an explicit override.
#[cfg(feature = "local")]
fn checkpoint_network_override_conflicts(
    requested: &microsandbox_types::InterfaceOverrides,
    captured: &microsandbox_types::InterfaceOverrides,
) -> bool {
    requested.mac.is_some_and(|value| Some(value) != captured.mac)
        || requested
            .mtu
            .is_some_and(|value| Some(value) != captured.mtu)
        || requested
            .ipv4_address
            .is_some_and(|value| Some(value) != captured.ipv4_address)
        || requested
            .ipv6_address
            .is_some_and(|value| Some(value) != captured.ipv6_address)
        // Pools derive an identity from the destination slot, which cannot be substituted for the
        // effective address already present in the restored guest and device state.
        || requested.ipv4_pool.is_some()
        || requested.ipv6_pool.is_some()
}

#[cfg(feature = "local")]
fn apply_checkpoint_resources(
    config: &mut SandboxConfig,
    state: &crate::snapshot::CheckpointSnapshotState,
    overrides: RestoreOverrideIntent,
) -> MicrosandboxResult<()> {
    let vcpus = u8::try_from(checkpoint_requirement_u64(state, "vcpus")?).map_err(|_| {
        MicrosandboxError::SnapshotIntegrity("checkpoint vCPU count exceeds u8".into())
    })?;
    let max_vcpus =
        u8::try_from(checkpoint_requirement_u64(state, "max_vcpus")?).map_err(|_| {
            MicrosandboxError::SnapshotIntegrity("checkpoint maximum vCPU count exceeds u8".into())
        })?;
    let memory_mib =
        u32::try_from(checkpoint_requirement_u64(state, "memory_mib")?).map_err(|_| {
            MicrosandboxError::SnapshotIntegrity("checkpoint memory exceeds u32 MiB".into())
        })?;
    let max_memory_mib = u32::try_from(checkpoint_requirement_u64(state, "max_memory_mib")?)
        .map_err(|_| {
            MicrosandboxError::SnapshotIntegrity("checkpoint maximum memory exceeds u32 MiB".into())
        })?;
    if (overrides.cpus && config.spec.resources.cpus != vcpus)
        || (overrides.max_cpus && config.spec.resources.max_cpus != max_vcpus)
        || (overrides.memory && config.spec.resources.memory_mib != memory_mib)
        || (overrides.max_memory && config.spec.resources.max_memory_mib != max_memory_mib)
    {
        return Err(MicrosandboxError::InvalidConfig(
            "a full snapshot must restore with its captured CPU and memory geometry".into(),
        ));
    }
    config.spec.resources.cpus = vcpus;
    config.spec.resources.max_cpus = max_vcpus;
    config.spec.resources.memory_mib = memory_mib;
    config.spec.resources.max_memory_mib = max_memory_mib;
    Ok(())
}

#[cfg(feature = "local")]
fn checkpoint_requirement_u64(
    state: &crate::snapshot::CheckpointSnapshotState,
    key: &str,
) -> MicrosandboxResult<u64> {
    state
        .requirements_summary
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            MicrosandboxError::SnapshotIntegrity(format!(
                "checkpoint snapshot is missing numeric restore requirement {key:?}"
            ))
        })
}

fn wrap_config_script(shell: Option<&str>, body: &str) -> String {
    let shell = shell.unwrap_or("/bin/sh");
    let mut script = if shell.contains('/') {
        format!("#!{shell}")
    } else {
        format!("#!/usr/bin/env {shell}")
    };
    script.push('\n');
    script.push_str(body);
    if !script.ends_with('\n') {
        script.push('\n');
    }
    script
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl From<SandboxConfig> for SandboxBuilder {
    fn from(mut config: SandboxConfig) -> Self {
        let env = std::mem::take(&mut config.spec.env);
        let shell = config.spec.runtime.shell.take();
        let log_level = config.spec.runtime.log_level.take();
        let metrics_sample_interval_ms = config.spec.runtime.metrics_sample_interval_ms.take();

        let mut patch = SandboxConfigPatch::from_present_fields(config);
        patch.spec.replace_env_mut(env);
        patch.spec.runtime.shell = Some(shell);
        patch.spec.runtime.log_level = Some(log_level);
        patch.spec.runtime.metrics_sample_interval_ms = Some(metrics_sample_interval_ms);

        Self {
            config: patch,
            detached: false,
            build_error: None,
            config_scripts: BTreeMap::new(),
            pending_snapshot: None,
            pending_snapshot_from_config: false,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, feature = "local"))]
mod tests {
    use super::{
        BackendConfig, SandboxBuilder, SandboxConfigPatch, apply_checkpoint_resources,
        checkpoint_network_override_conflicts,
    };
    use crate::LogLevel;
    use crate::config::GlobalConfigPatch;
    use crate::sandbox::config::RestoreOverrideIntent;
    use crate::sandbox::{MAX_HOSTNAME_BYTES, MAX_SANDBOX_NAME_BYTES, RlimitResource};
    use std::collections::BTreeMap;

    #[cfg(feature = "net")]
    #[test]
    fn changing_violation_action_preserves_global_passthrough() {
        let mut builder = SandboxBuilder::new("secrets");
        let mut network = builder.local_network_config().unwrap();
        network.secrets.passthrough_hosts = Some(vec![microsandbox_types::HostPattern::Exact(
            "pass.example".into(),
        )]);
        builder.set_local_network_config(network).unwrap();
        let builder =
            builder.secret_violation_action(microsandbox_types::SecretViolationAction::Block);
        let network = builder.local_network_config().unwrap();
        assert_eq!(
            network.secrets.passthrough_hosts,
            Some(vec![microsandbox_types::HostPattern::Exact(
                "pass.example".into()
            )])
        );
        assert_eq!(
            network.secrets.violation_action,
            microsandbox_types::SecretViolationAction::Block
        );
    }

    #[cfg(feature = "net")]
    use std::net::{IpAddr, Ipv4Addr};

    #[cfg(feature = "net")]
    use microsandbox_network::config::ConnectionLimit;
    #[cfg(feature = "net")]
    use microsandbox_network::secrets::config::{HostPattern, SecretEntry, SecretSubstitution};
    use microsandbox_types::{
        CpuPlacement, DeploymentProfile, SandboxLogLevel, SandboxResourcesPatch, SandboxSpecPatch,
        TransparentHugePagePolicy, VolumeMount, VsockSocketType,
    };
    #[cfg(feature = "net")]
    use microsandbox_types::{PortProtocol, SecretSource};

    #[cfg(feature = "cloud")]
    use crate::backend::with_backend;
    use crate::snapshot::SnapshotReference;

    fn checkpoint_state_with_geometry(
        vcpus: u8,
        max_vcpus: u8,
        memory_mib: u32,
        max_memory_mib: u32,
    ) -> crate::snapshot::CheckpointSnapshotState {
        crate::snapshot::CheckpointSnapshotState {
            checkpoint_id: "checkpoint_test".into(),
            checkpoint_root:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            restore_intents: vec!["clone".into()],
            requirements_summary: BTreeMap::from([
                ("vcpus".into(), serde_json::Value::from(vcpus)),
                ("max_vcpus".into(), serde_json::Value::from(max_vcpus)),
                ("memory_mib".into(), serde_json::Value::from(memory_mib)),
                (
                    "max_memory_mib".into(),
                    serde_json::Value::from(max_memory_mib),
                ),
            ]),
        }
    }

    #[cfg(feature = "cloud")]
    #[tokio::test]
    async fn sandbox_build_uses_the_selected_backends_captured_sources() {
        let local_config = BackendConfig::new(Default::default(), Default::default())
            .prepare_for_local_backend(Default::default())
            .unwrap();
        let local = SandboxBuilder::new("local-defaults")
            .image("alpine")
            .finish(Some(&local_config), None)
            .unwrap();
        assert_eq!(local.spec.runtime.shell.as_deref(), Some("/bin/sh"));

        let managed =
            serde_json::from_str(r#"{"sandbox_defaults":{"cpus":2,"shell":"/bin/admin"}}"#)
                .unwrap();
        let local_backend = crate::LocalBackend::from_backend_config(
            BackendConfig::new(Default::default(), managed)
                .prepare_for_local_backend(Default::default())
                .unwrap(),
            crate::BackendSelectionSource::Programmatic,
            None,
        );
        crate::backend::with_backend(local_backend, async {
            let local = SandboxBuilder::new("local-policy")
                .image("alpine")
                .cpus(4)
                .build()
                .await
                .unwrap();
            assert_eq!(local.spec.resources.cpus, 2);
            let cloud_policy = serde_json::from_str(
                r#"{"sandbox_defaults":{"cpus":3,"shell":"/bin/cloud-policy"}}"#,
            )
            .unwrap();
            let cloud_backend = crate::CloudBackend::builder()
                .url("https://cloud.example")
                .api_key("test-token")
                .config_sources(BackendConfig::new(Default::default(), cloud_policy))
                .build()
                .unwrap();
            let cloud = crate::backend::with_backend(cloud_backend, async {
                SandboxBuilder::new("cloud-defaults")
                    .image("alpine")
                    .cpus(4)
                    .build()
                    .await
                    .unwrap()
            })
            .await;
            assert_eq!(cloud.spec.resources.cpus, 3);
            assert_eq!(
                cloud.spec.runtime.shell.as_deref(),
                Some("/bin/cloud-policy")
            );
        })
        .await;
    }

    #[test]
    fn final_layers_preserve_workdir_presence() {
        use serde_json::json;
        let image = microsandbox_image::ImageConfig {
            working_dir: Some("/image".into()),
            ..Default::default()
        };
        for (global, workdir, managed, expected) in [
            (json!({}), None, json!({}), Some("/image")),
            (
                json!({"workdir": "/global"}),
                None,
                json!({}),
                Some("/global"),
            ),
            (json!({"workdir": null}), None, json!({}), None),
            (
                json!({"workdir": null}),
                Some(Some("/sdk")),
                json!({}),
                Some("/sdk"),
            ),
            (json!({"workdir": "/global"}), Some(None), json!({}), None),
            (
                json!({}),
                Some(None),
                json!({"workdir": "/managed"}),
                Some("/managed"),
            ),
            (
                json!({}),
                Some(Some("/sdk")),
                json!({"workdir": null}),
                None,
            ),
        ] {
            let layers = BackendConfig::new(
                serde_json::from_value(json!({"sandbox_defaults": global})).unwrap(),
                serde_json::from_value(json!({"sandbox_defaults": managed})).unwrap(),
            );
            let mut patch = SandboxConfigPatch::new();
            patch.spec.runtime.workdir = workdir.map(|value| value.map(String::from));
            let config = SandboxBuilder::new("presence")
                .image("alpine")
                .overlay(patch)
                .finish(Some(&layers), Some(SandboxConfigPatch::from_image(&image)))
                .unwrap();
            assert_eq!(config.spec.runtime.workdir.as_deref(), expected);
        }
    }

    #[test]
    fn final_image_layers_keep_env_order_and_resolve_init_with_effective_env() {
        use microsandbox_types::EnvVar;
        let image = microsandbox_image::ImageConfig {
            env: vec!["IMAGE_ONLY=image".into(), "SHARED=image".into()],
            labels: std::collections::HashMap::from([
                ("source".into(), "image".into()),
                ("image-only".into(), "yes".into()),
                ("microsandbox.reserved".into(), "skip".into()),
            ]),
            entrypoint: Some(vec!["/init".into(), "/app/start".into()]),
            cmd: Some(vec!["--serve".into()]),
            ..Default::default()
        };
        let config = SandboxBuilder::new("image-layers")
            .image("alpine")
            .init("auto")
            .env("REMOVED", "earlier")
            .overlay(
                SandboxConfigPatch::new().spec(
                    microsandbox_types::SandboxSpecPatch::new()
                        .replace_env(vec![EnvVar::new("SHARED", "file")]),
                ),
            )
            .env("SHARED", "sdk")
            .label("source", "sdk")
            .finish(
                Some(&BackendConfig::new(Default::default(), Default::default())),
                Some(SandboxConfigPatch::from_image(&image)),
            )
            .unwrap();
        assert_eq!(
            config.spec.env,
            vec![
                EnvVar::new("IMAGE_ONLY", "image"),
                EnvVar::new("SHARED", "file"),
                EnvVar::new("SHARED", "sdk"),
            ]
        );
        assert_eq!(config.spec.labels["source"], "sdk");
        assert_eq!(config.spec.labels["image-only"], "yes");
        assert!(!config.spec.labels.contains_key("microsandbox.reserved"));
        let init = config.spec.init.as_ref().unwrap();
        assert_eq!(init.cmd, "/init");
        assert_eq!(
            init.env,
            vec![
                ("IMAGE_ONLY".into(), "image".into()),
                ("SHARED".into(), "file".into()),
                ("SHARED".into(), "sdk".into()),
            ]
        );
        assert_eq!(
            config.spec.runtime.entrypoint,
            Some(vec!["/app/start".into()])
        );
        assert_eq!(config.spec.runtime.cmd, Some(vec!["--serve".into()]));
        assert!(!config.init_owns_boot_workload());
    }

    #[test]
    fn final_image_resolution_preserves_concrete_launch_behavior() {
        use crate::sandbox::config::LaunchIntent;
        use microsandbox_types::{EnvVar, HandoffInit};
        let image = microsandbox_image::ImageConfig {
            env: vec!["IMAGE_ONLY=image".into(), "SHARED=image".into()],
            entrypoint: Some(vec!["/init".into(), "/app/start".into()]),
            cmd: Some(vec!["--serve".into()]),
            working_dir: Some("/image".into()),
            user: Some("1000:1000".into()),
            ..Default::default()
        };
        for launch_intent in [
            LaunchIntent::None,
            LaunchIntent::Foreground {
                command: Some(vec!["echo".into(), "hello".into()]),
            },
            LaunchIntent::Background,
        ] {
            for entrypoint in [None, Some(vec!["/user-entrypoint".into()])] {
                let mut original = crate::SandboxConfig::default();
                original.spec.name = "existing-config".into();
                original.spec.image = super::RootfsSource::oci("alpine");
                original.spec.env = vec![EnvVar::new("SHARED", "user")];
                original.spec.init = Some(HandoffInit {
                    cmd: "auto".into(),
                    args: vec![],
                    env: vec![],
                });
                original.spec.runtime.entrypoint = entrypoint;
                original.spec.runtime.metrics_sample_interval_ms = None;
                original.launch_intent = launch_intent.clone();
                let mut expected = original.clone();
                expected.merge_image_defaults(&image);
                let actual = SandboxBuilder::from(original)
                    .finish(
                        Some(&BackendConfig::new(Default::default(), Default::default())),
                        Some(SandboxConfigPatch::from_image(&image)),
                    )
                    .unwrap();
                assert_eq!(
                    serde_json::to_value(&actual).unwrap(),
                    serde_json::to_value(&expected).unwrap()
                );
                assert_eq!(
                    actual.init_owns_boot_workload(),
                    expected.init_owns_boot_workload()
                );
                assert_eq!(
                    actual.init_workload_arg_count,
                    expected.init_workload_arg_count
                );
                assert_eq!(actual.launch_intent, expected.launch_intent);
            }
        }
    }

    #[test]
    fn concrete_optional_network_and_placement_values_inherit_or_clear() {
        let user: GlobalConfigPatch = serde_json::from_str(r#"{"sandbox_defaults":{
            "placement_profile":"ordinary", "outbound_proxy":{"protocol":"socks5","address":"127.0.0.1:1080"}
        }}"#).unwrap();
        let layers = BackendConfig::new(user.clone(), Default::default());
        let concrete = SandboxBuilder::new("optional-values")
            .image("alpine")
            .finish(
                Some(&BackendConfig::new(Default::default(), Default::default())),
                None,
            )
            .unwrap();
        let inherited = SandboxBuilder::from(concrete.clone())
            .finish(Some(&layers), None)
            .unwrap();
        assert_eq!(
            inherited.spec.resources.placement_profile.as_deref(),
            Some("ordinary")
        );
        assert!(inherited.spec.network.outbound_proxy.is_some());
        let mut clear = SandboxConfigPatch::new();
        clear.spec.resources.placement_profile = Some(None);
        clear.spec.network.outbound_proxy = Some(None);
        let cleared = SandboxBuilder::from(concrete.clone())
            .overlay(clear)
            .finish(Some(&layers), None)
            .unwrap();
        assert_eq!(cleared.spec.resources.placement_profile, None);
        assert_eq!(cleared.spec.network.outbound_proxy, None);
        let managed = serde_json::from_str(
            r#"{"sandbox_defaults":{"placement_profile":"managed","outbound_proxy":null}}"#,
        )
        .unwrap();
        let enforced = SandboxBuilder::from(concrete)
            .finish(Some(&BackendConfig::new(user, managed)), None)
            .unwrap();
        assert_eq!(
            enforced.spec.resources.placement_profile.as_deref(),
            Some("managed")
        );
        assert_eq!(enforced.spec.network.outbound_proxy, None);
    }

    #[test]
    fn concrete_workdir_uses_normal_precedence() {
        let image = microsandbox_image::ImageConfig {
            working_dir: Some("/image".into()),
            ..Default::default()
        };
        let mut patch = SandboxConfigPatch::new();
        patch.spec.runtime.workdir = Some(None);
        let built = SandboxBuilder::new("concrete-config")
            .image("alpine")
            .overlay(patch)
            .finish(
                Some(&BackendConfig::new(Default::default(), Default::default())),
                None,
            )
            .unwrap();
        assert_eq!(built.spec.runtime.workdir, None);

        for (global, image, expected) in [
            (
                "{}",
                Some(SandboxConfigPatch::from_image(&image)),
                Some("/image"),
            ),
            (
                r#"{"sandbox_defaults":{"workdir":"/global"}}"#,
                Some(SandboxConfigPatch::from_image(&image)),
                Some("/global"),
            ),
            (
                r#"{"sandbox_defaults":{"workdir":"/global"}}"#,
                None,
                Some("/global"),
            ),
            (
                r#"{"sandbox_defaults":{"workdir":null}}"#,
                Some(SandboxConfigPatch::from_image(&image)),
                None,
            ),
        ] {
            let layers =
                BackendConfig::new(serde_json::from_str(global).unwrap(), Default::default());
            let inherited = SandboxBuilder::from(built.clone())
                .finish(Some(&layers), image)
                .unwrap();
            assert_eq!(inherited.spec.runtime.workdir.as_deref(), expected);
        }

        let layers = BackendConfig::new(
            serde_json::from_str(r#"{"sandbox_defaults":{"workdir":"/global"}}"#).unwrap(),
            Default::default(),
        );
        let mut supplied = built.clone();
        supplied.spec.runtime.workdir = Some("/request".into());
        let explicit = SandboxBuilder::from(supplied)
            .finish(Some(&layers), Some(SandboxConfigPatch::from_image(&image)))
            .unwrap();
        assert_eq!(explicit.spec.runtime.workdir.as_deref(), Some("/request"));

        let mut clear = SandboxConfigPatch::new();
        clear.spec.runtime.workdir = Some(None);
        let explicitly_cleared = SandboxBuilder::from(built.clone())
            .overlay(clear)
            .finish(Some(&layers), Some(SandboxConfigPatch::from_image(&image)))
            .unwrap();
        assert_eq!(explicitly_cleared.spec.runtime.workdir, None);
        let enforced = SandboxBuilder::from(built)
            .finish(
                Some(&BackendConfig::new(
                    serde_json::from_str(r#"{"sandbox_defaults":{"workdir":"/global"}}"#).unwrap(),
                    serde_json::from_str(r#"{"sandbox_defaults":{"workdir":null}}"#).unwrap(),
                )),
                Some(SandboxConfigPatch::from_image(&image)),
            )
            .unwrap();
        assert_eq!(enforced.spec.runtime.workdir, None);
    }

    #[test]
    fn full_config_patch_overlays_create_inputs_and_preserves_builder_precedence() {
        let auth = || microsandbox_image::RegistryAuth::Basic {
            username: "builder".into(),
            password: "test-token".into(),
        };
        let lower = SandboxConfigPatch::new()
            .registry_auth(auth())
            .slug("lower".into())
            .replace_existing(true)
            .replace_with_timeout(std::time::Duration::from_secs(30))
            .insecure(true)
            .ca_certs(vec![b"certificate".to_vec()]);
        let higher = SandboxConfigPatch::new()
            .set_registry_auth(None)
            .set_slug(None)
            .replace_existing(false)
            .spec(
                microsandbox_types::SandboxSpecPatch::new()
                    .resources(microsandbox_types::SandboxResourcesPatch::new().cpus(4)),
            );
        let build = || {
            SandboxBuilder::new("full-patch")
                .image("alpine")
                .overlay(lower.clone())
                .overlay(higher.clone())
        };
        let config = build()
            .finish(
                Some(&BackendConfig::new(Default::default(), Default::default())),
                None,
            )
            .unwrap();
        assert_eq!(config.spec.resources.cpus, 4);
        assert!(config.registry_auth.is_none());
        assert!(config.slug.is_none());
        assert!(!config.replace_existing);
        assert_eq!(
            config.replace_with_timeout,
            std::time::Duration::from_secs(30)
        );
        assert!(config.insecure);
        assert_eq!(config.ca_certs, [b"certificate".to_vec()]);

        let config = build()
            .registry(|registry| registry.auth(auth()))
            .slug("final")
            .replace()
            .finish(
                Some(&BackendConfig::new(Default::default(), Default::default())),
                None,
            )
            .unwrap();
        assert!(
            matches!(config.registry_auth, Some(microsandbox_image::RegistryAuth::Basic { ref username, .. }) if username == "builder")
        );
        assert_eq!(config.slug.as_deref(), Some("final"));
        assert!(config.replace_existing);
        assert!(!config.insecure);
        assert!(config.ca_certs.is_empty());
        let serialized = serde_json::to_value(&config).unwrap();
        assert!(serialized.get("spec").is_none());
        assert_eq!(serialized["name"], "full-patch");
        for field in [
            "registry_auth",
            "slug",
            "replace_existing",
            "replace_with_timeout",
            "insecure",
            "ca_certs",
        ] {
            assert!(
                serialized.get(field).is_none(),
                "{field} must remain transient"
            );
        }
    }

    #[test]
    fn rebuilding_config_preserves_snapshot_and_launch_metadata() {
        let mut config = SandboxBuilder::new("snapshot-metadata")
            .image("alpine")
            .snapshot_resolved("sha256:resolved", "/snapshot/upper.ext4")
            .foreground_command(["echo", "ready"])
            .finish(
                Some(&BackendConfig::new(Default::default(), Default::default())),
                None,
            )
            .unwrap();
        config.init_owns_workload = true;
        config.init_workload_arg_count = 2;
        let rebuilt = SandboxBuilder::from(config.clone())
            .finish(
                Some(&BackendConfig::new(Default::default(), Default::default())),
                None,
            )
            .unwrap();
        assert_eq!(rebuilt.manifest_digest, config.manifest_digest);
        assert_eq!(rebuilt.snapshot_upper_source, config.snapshot_upper_source);
        assert_eq!(rebuilt.launch_intent, config.launch_intent);
        assert_eq!(rebuilt.init_owns_workload, config.init_owns_workload);
        assert_eq!(
            rebuilt.init_workload_arg_count,
            config.init_workload_arg_count
        );
        assert_eq!(
            serde_json::to_value(rebuilt).unwrap(),
            serde_json::to_value(config).unwrap()
        );
    }

    #[test]
    fn managed_layer_wins_over_builder_and_sdk_patches_before_validation() {
        use std::collections::BTreeMap;

        use microsandbox_types::SandboxResourcesPatch;

        let managed: GlobalConfigPatch = serde_json::from_str(
            r#"{"sandbox_defaults":{"cpus":2,"workdir":null,"shell":"/bin/bash"}}"#,
        )
        .unwrap();
        let build = || {
            SandboxBuilder::new("managed")
                .image("alpine:latest")
                .cpus(8)
                .workdir("/user")
                .config_scripts(BTreeMap::from([("hello".into(), "echo hello".into())]))
        };
        let config = build()
            .finish(
                Some(&BackendConfig::new(Default::default(), managed.clone())),
                None,
            )
            .unwrap();
        assert_eq!(config.spec.resources.cpus, 2);
        assert_eq!(config.spec.resources.max_cpus, 2);
        assert_eq!(config.spec.runtime.workdir, None);
        assert_eq!(config.spec.runtime.shell.as_deref(), Some("/bin/bash"));
        assert!(config.spec.runtime.scripts["hello"].starts_with("#!/bin/bash"));
        let config = build()
            .overlay(
                SandboxConfigPatch::new().spec(
                    microsandbox_types::SandboxSpecPatch::new()
                        .resources(SandboxResourcesPatch::new().cpus(7).max_cpus(10)),
                ),
            )
            .finish(
                Some(&BackendConfig::new(Default::default(), managed.clone())),
                None,
            )
            .unwrap();
        assert_eq!(config.spec.resources.cpus, 2);
        assert_eq!(config.spec.resources.max_cpus, 10);
        assert!(
            build()
                .max_cpus(1)
                .finish(
                    Some(&BackendConfig::new(Default::default(), managed.clone())),
                    None
                )
                .is_err()
        );
        // A maximum supplied by a patch has the same precedence as the SDK maximum setter.
        let later_setter = build()
            .overlay(
                SandboxConfigPatch::new().spec(
                    microsandbox_types::SandboxSpecPatch::new()
                        .resources(SandboxResourcesPatch::new().max_cpus(10)),
                ),
            )
            .cpus(4);
        assert_eq!(
            later_setter
                .finish(
                    Some(&BackendConfig::new(Default::default(), Default::default())),
                    None
                )
                .unwrap()
                .spec
                .resources
                .max_cpus,
            10
        );
    }

    #[test]
    fn global_sparse_and_managed_inputs_share_patch_precedence() {
        use microsandbox_types::EnvVar;

        let builder = SandboxBuilder::new("layers").image("alpine");
        let global = serde_json::from_str(
            r#"{
            "sandbox_defaults": {"cpus": 3, "memory_mib": 768,
                "shell": "/bin/sh", "workdir": "/global"}
        }"#,
        )
        .unwrap();
        let mut sparse = SandboxConfigPatch::new().spec(
            microsandbox_types::SandboxSpecPatch::new()
                .env(vec![EnvVar::new("SOURCE", "file")])
                .labels(std::collections::BTreeMap::from([
                    ("file".into(), "yes".into()),
                    ("source".into(), "file".into()),
                ])),
        );
        sparse.spec.resources.cpus = Some(4);
        sparse.spec.resources.max_memory_mib = Some(2048);
        sparse.spec.runtime.workdir = Some(None);
        let managed: GlobalConfigPatch = serde_json::from_str(
            r#"{
            "sandbox_defaults": {"cpus": 2, "shell": "/bin/bash"}
        }"#,
        )
        .unwrap();
        let config = builder
            .overlay(sparse)
            .cpus(6)
            .memory(1024_u32)
            .env("SDK", "yes")
            .label("source", "sdk")
            .quiet_logs()
            .metrics_sample_interval(std::time::Duration::ZERO)
            .overlay(
                SandboxConfigPatch::new().spec(
                    microsandbox_types::SandboxSpecPatch::new()
                        .env(vec![EnvVar::new("SOURCE", "last")]),
                ),
            )
            .finish(Some(&BackendConfig::new(global, managed)), None)
            .unwrap();
        assert_eq!(config.spec.resources.cpus, 2);
        assert_eq!(config.spec.resources.max_cpus, 2);
        assert_eq!(config.spec.resources.memory_mib, 1024);
        assert_eq!(config.spec.resources.max_memory_mib, 2048);
        assert_eq!(config.spec.runtime.workdir, None);
        assert_eq!(config.spec.runtime.shell.as_deref(), Some("/bin/bash"));
        assert_eq!(config.spec.runtime.log_level, None);
        assert_eq!(config.spec.runtime.metrics_sample_interval_ms, None);
        assert_eq!(
            config.spec.env,
            vec![EnvVar::new("SOURCE", "last"), EnvVar::new("SDK", "yes")]
        );
        assert_eq!(config.spec.labels["file"], "yes");
        assert_eq!(config.spec.labels["source"], "sdk");
    }

    #[test]
    fn complete_config_survives_patch_normalization() {
        let config = SandboxBuilder::new("complete")
            .image("alpine")
            .max_cpus(8)
            .cpus(2)
            .env("FIRST", "one")
            .env("SECOND", "two")
            .quiet_logs()
            .metrics_sample_interval(std::time::Duration::ZERO)
            .entrypoint(Vec::<String>::new())
            .cmd(["echo", "hello"])
            .label("owner", "test")
            .finish(
                Some(&BackendConfig::new(Default::default(), Default::default())),
                None,
            )
            .unwrap();
        let expected = serde_json::to_value(&config.spec).unwrap();
        let rebuilt = SandboxBuilder::from(config)
            .finish(
                Some(&BackendConfig::new(Default::default(), Default::default())),
                None,
            )
            .unwrap();
        assert_eq!(serde_json::to_value(rebuilt.spec).unwrap(), expected);
    }

    #[test]
    fn env_appends_preserve_duplicates_and_sparse_overlays_merge_by_key() {
        use microsandbox_types::EnvVar;

        let config = SandboxBuilder::new("env-appends")
            .image("alpine")
            .env("KEY", "first")
            .env("KEY", "second")
            .finish(
                Some(&BackendConfig::new(Default::default(), Default::default())),
                None,
            )
            .unwrap();
        assert_eq!(
            config.spec.env,
            vec![EnvVar::new("KEY", "first"), EnvVar::new("KEY", "second")]
        );

        let config = SandboxBuilder::new("env-overlay")
            .image("alpine")
            .env("KEY", "first")
            .overlay(
                SandboxConfigPatch::new().spec(
                    microsandbox_types::SandboxSpecPatch::new()
                        .env(vec![EnvVar::new("KEY", "overlay")]),
                ),
            )
            .env("KEY", "last")
            .finish(
                Some(&BackendConfig::new(Default::default(), Default::default())),
                None,
            )
            .unwrap();
        assert_eq!(
            config.spec.env,
            vec![EnvVar::new("KEY", "overlay"), EnvVar::new("KEY", "last")]
        );
    }

    #[test]
    fn mount_replacement_discards_earlier_appends() {
        let config = SandboxBuilder::new("mount-layers")
            .image("alpine")
            .volume("/first", |mount| mount.tmpfs())
            .overlay(
                SandboxConfigPatch::new()
                    .spec(microsandbox_types::SandboxSpecPatch::new().mounts(Vec::new())),
            )
            .volume("/second", |mount| mount.tmpfs())
            .volume("/third", |mount| mount.tmpfs())
            .finish(
                Some(&BackendConfig::new(Default::default(), Default::default())),
                None,
            )
            .unwrap();
        assert_eq!(
            config
                .spec
                .mounts
                .iter()
                .map(VolumeMount::guest)
                .collect::<Vec<_>>(),
            vec!["/second", "/third"]
        );
    }

    #[cfg(feature = "net")]
    #[test]
    fn network_callbacks_replace_tls_and_preserve_ports() {
        let config = SandboxBuilder::new("network-layers")
            .image("alpine")
            .port(8080, 80)
            .network(|network| {
                network.tls(|tls| {
                    tls.intercept_ca_cert("/test/ca.pem")
                        .intercept_ca_key("/test/ca.key")
                })
            })
            .network(|network| network.tls(|tls| tls.enabled(false)))
            .port(8443, 443)
            .finish(
                Some(&BackendConfig::new(Default::default(), Default::default())),
                None,
            )
            .unwrap();
        let network = config.local_network_config().unwrap();
        assert!(!network.tls.enabled);
        assert!(network.tls.intercept_ca.cert_path.is_none());
        assert!(network.tls.intercept_ca.key_path.is_none());
        assert_eq!(config.spec.network.ports.len(), 2);
    }

    #[test]
    fn managed_root_disk_sizes_are_resolved_after_final_resources() {
        let managed: GlobalConfigPatch = serde_json::from_str(
            r#"{"sandbox_defaults":{"memory_mib":1024,"oci":{"root_disk":{"kind":"tmpfs"}}}}"#,
        )
        .unwrap();
        let mut config = SandboxBuilder::new("root-size")
            .image("alpine")
            .memory(2048_u32)
            .root_disk(4096_u32)
            .finish(
                Some(&BackendConfig::new(Default::default(), managed)),
                Some(Default::default()),
            )
            .unwrap();
        config.apply_rootfs_defaults(&Default::default()).unwrap();
        let super::RootfsSource::Oci(image) = config.spec.image else {
            panic!("expected OCI image");
        };
        assert_eq!(
            image.root_disk,
            Some(microsandbox_types::RootDisk::Tmpfs {
                size_mib: Some(512)
            })
        );
    }

    #[test]
    fn managed_root_disk_preserves_the_selected_image() {
        let managed: GlobalConfigPatch = serde_json::from_str(
            r#"{
            "sandbox_defaults": {"oci": {"root_disk": {"kind": "managed", "size_mib": 2048}}}
        }"#,
        )
        .unwrap();
        let layers = BackendConfig::new(Default::default(), managed);
        let builder = SandboxBuilder::new("root-disk")
            .image("alpine:latest")
            .root_disk(4096_u32);
        let super::RootfsSource::Oci(image_for_pull) = builder.config.resolve_image(&layers) else {
            panic!("expected OCI image");
        };
        let config = builder.finish(Some(&layers), None).unwrap();
        let super::RootfsSource::Oci(image) = config.spec.image else {
            panic!("expected OCI image");
        };
        assert_eq!(image.reference, "alpine:latest");
        assert_eq!(image_for_pull.reference, image.reference);
        assert_eq!(image_for_pull.root_disk, image.root_disk);
        assert_eq!(
            image.root_disk,
            Some(microsandbox_types::RootDisk::Managed {
                size_mib: Some(2048)
            })
        );
    }

    #[test]
    fn managed_root_disk_can_replace_the_deprecated_upper_size() {
        let managed: GlobalConfigPatch = serde_json::from_str(
            r#"{"sandbox_defaults":{"oci":{"upper_size_mib":null,"root_disk":{"kind":"tmpfs","size_mib":128}}}}"#,
        )
        .unwrap();
        let config = SandboxBuilder::new("root-disk-alias")
            .image("alpine")
            .root_disk(4096_u32)
            .finish(
                Some(&BackendConfig::new(Default::default(), managed.clone())),
                None,
            )
            .unwrap();
        let super::RootfsSource::Oci(image) = config.spec.image else {
            panic!("expected OCI image");
        };
        assert_eq!(
            image.root_disk,
            Some(microsandbox_types::RootDisk::Tmpfs {
                size_mib: Some(128)
            })
        );
    }

    #[test]
    fn deployment_profile_sets_sandbox_spec() {
        let builder =
            SandboxBuilder::new("profile-test").deployment_profile(DeploymentProfile::MultiTenant);

        assert_eq!(
            builder.config.spec.deployment_profile.unwrap(),
            DeploymentProfile::MultiTenant
        );
    }

    #[tokio::test]
    async fn test_builder_sets_runtime_log_level() {
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .log_level(LogLevel::Debug)
            .build()
            .await
            .unwrap();

        assert_eq!(config.spec.runtime.log_level, Some(SandboxLogLevel::Debug));
    }

    #[tokio::test]
    async fn test_builder_builds_config_with_shared_spec() {
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .cpus(2)
            .max_cpus(4)
            .cpu_placement(CpuPlacement::Spread)
            .memory(1024)
            .max_memory(4096)
            .thp(TransparentHugePagePolicy::Always)
            .log_level(LogLevel::Info)
            .env("A", "B")
            .script("setup", "echo hi")
            .max_duration(60)
            .build()
            .await
            .unwrap();

        assert_eq!(config.spec.name, "test");
        assert_eq!(config.spec.resources.cpus, 2);
        assert_eq!(config.spec.resources.max_cpus, 4);
        assert_eq!(config.spec.resources.cpu_placement, CpuPlacement::Spread);
        assert_eq!(config.spec.resources.memory_mib, 1024);
        assert_eq!(config.spec.resources.max_memory_mib, 4096);
        assert_eq!(config.spec.resources.thp, TransparentHugePagePolicy::Always);
        assert_eq!(config.spec.runtime.log_level, Some(SandboxLogLevel::Info));
        assert_eq!(config.spec.env.len(), 1);
        assert_eq!(
            config.spec.runtime.scripts.get("setup"),
            Some(&"echo hi".into())
        );
        assert_eq!(config.spec.lifecycle.max_duration_secs, Some(60));
    }

    #[tokio::test]
    async fn test_builder_preserves_cmd_override_and_explicit_clears() {
        let configured = SandboxBuilder::new("test")
            .image("alpine")
            .cmd(["worker.py", "--once"])
            .build()
            .await
            .unwrap();
        assert_eq!(
            configured.spec.runtime.cmd,
            Some(vec!["worker.py".to_string(), "--once".to_string()])
        );

        let cleared = SandboxBuilder::new("test")
            .image("alpine")
            .entrypoint(Vec::<String>::new())
            .cmd(Vec::<String>::new())
            .build()
            .await
            .unwrap();
        assert_eq!(cleared.spec.runtime.entrypoint, Some(Vec::new()));
        assert_eq!(cleared.spec.runtime.cmd, Some(Vec::new()));
    }

    #[tokio::test]
    async fn test_builder_accepts_128_byte_sandbox_name() {
        let name = "x".repeat(MAX_SANDBOX_NAME_BYTES);
        let config = SandboxBuilder::new(name.clone())
            .image("alpine")
            .build()
            .await
            .unwrap();

        assert_eq!(config.spec.name, name);
    }

    #[tokio::test]
    async fn test_builder_rejects_over_128_byte_sandbox_name() {
        let name = "x".repeat(MAX_SANDBOX_NAME_BYTES + 1);
        let err = SandboxBuilder::new(name)
            .image("alpine")
            .build()
            .await
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid config: sandbox name must be at most 128 characters: got 129"
        );
    }

    #[tokio::test]
    async fn test_builder_rejects_zero_cpus() {
        let err = SandboxBuilder::new("test")
            .image("alpine")
            .cpus(0)
            .build()
            .await
            .unwrap_err();

        assert!(err.to_string().contains("cpus must be greater than 0"));
    }

    #[tokio::test]
    async fn test_builder_rejects_zero_memory() {
        let err = SandboxBuilder::new("test")
            .image("alpine")
            .memory(0)
            .build()
            .await
            .unwrap_err();

        assert!(err.to_string().contains("memory must be greater than 0"));
    }

    #[tokio::test]
    async fn test_builder_rejects_max_cpus_below_effective_cpus() {
        let err = SandboxBuilder::new("test")
            .image("alpine")
            .cpus(4)
            .max_cpus(2)
            .build()
            .await
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("max_cpus 2 must be greater than or equal to cpus 4")
        );
    }

    #[tokio::test]
    async fn test_builder_rejects_max_memory_below_effective_memory() {
        let err = SandboxBuilder::new("test")
            .image("alpine")
            .memory(2048)
            .max_memory(1024)
            .build()
            .await
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("max_memory 1024 MiB must be greater than or equal to memory 2048 MiB")
        );
    }

    #[tokio::test]
    async fn test_builder_accepts_64_byte_hostname() {
        let hostname = "y".repeat(MAX_HOSTNAME_BYTES);
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .hostname(hostname.clone())
            .build()
            .await
            .unwrap();

        assert_eq!(
            config.spec.runtime.hostname.as_deref(),
            Some(hostname.as_str())
        );
    }

    #[tokio::test]
    async fn test_builder_rejects_over_64_byte_hostname() {
        let err = SandboxBuilder::new("test")
            .image("alpine")
            .hostname("y".repeat(MAX_HOSTNAME_BYTES + 1))
            .build()
            .await
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid config: hostname is too long: 65 bytes (max 64)"
        );
    }

    #[tokio::test]
    async fn test_builder_rejects_empty_hostname() {
        let err = SandboxBuilder::new("test")
            .image("alpine")
            .hostname("")
            .build()
            .await
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid config: hostname must not be empty"
        );
    }

    #[tokio::test]
    async fn test_builder_image_with_root_disk() {
        let config = SandboxBuilder::new("test")
            .image_with(|i| i.oci("alpine").root_disk(8192u32))
            .build()
            .await
            .unwrap();

        match &config.spec.image {
            super::RootfsSource::Oci(oci) => {
                assert_eq!(oci.reference, "alpine");
                assert_eq!(oci.root_disk, Some(crate::sandbox::RootDisk::managed(8192)));
            }
            other => panic!("expected Oci, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_builder_leaves_backend_root_disk_default_unmaterialized() {
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .build()
            .await
            .unwrap();

        assert!(config.spec.image.oci_root_disk().is_none());
    }

    #[tokio::test]
    async fn test_builder_root_disk_rejects_bind_rootfs() {
        let err = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .root_disk(8192u32)
            .build()
            .await
            .unwrap_err();

        assert!(err.to_string().contains("only valid for OCI images"));
    }

    #[tokio::test]
    async fn test_builder_root_disk_rejects_disk_image_rootfs() {
        let err = SandboxBuilder::new("test")
            .image_with(|i| i.disk("./rootfs.qcow2"))
            .root_disk(8192u32)
            .build()
            .await
            .unwrap_err();

        assert!(err.to_string().contains("only valid for OCI images"));
    }

    #[tokio::test]
    async fn test_builder_tmpfs_root_disk_rejects_size_over_memory() {
        let err = SandboxBuilder::new("test")
            .image("alpine")
            .memory(1024u32)
            .root_disk_with(|d| d.tmpfs().size(2048u32))
            .build()
            .await
            .unwrap_err();

        assert!(err.to_string().contains("must not exceed sandbox memory"));
    }

    #[tokio::test]
    async fn test_builder_tmpfs_root_disk_rejects_patches() {
        let err = SandboxBuilder::new("test")
            .image("alpine")
            .root_disk_with(|d| d.tmpfs())
            .patch(|p| p.text("/etc/motd", "hello", None, true))
            .build()
            .await
            .unwrap_err();

        assert!(err.to_string().contains("sandbox-owned root disk"));
    }

    #[tokio::test]
    async fn test_builder_accepts_flat_root_disk() {
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .root_disk_with(|disk| {
                disk.flat()
                    .size(8192u32)
                    .clone_strategy(crate::sandbox::FlatClone::Copy)
            })
            .build()
            .await
            .unwrap();

        assert_eq!(
            config.spec.image.oci_root_disk(),
            Some(&crate::sandbox::RootDisk::Flat {
                size_mib: Some(8192),
                fstype: None,
                clone: crate::sandbox::FlatClone::Copy,
            })
        );
    }

    #[tokio::test]
    async fn test_builder_flat_root_disk_accepts_patches() {
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .root_disk_with(|disk| disk.flat())
            .patch(|patch| patch.text("/etc/motd", "hello", None, true))
            .build()
            .await
            .unwrap();

        assert!(matches!(
            config.spec.image.oci_root_disk(),
            Some(crate::sandbox::RootDisk::Flat { .. })
        ));
        assert_eq!(config.spec.patches.len(), 1);
    }

    #[tokio::test]
    async fn test_builder_deprecated_oci_upper_size_alias() {
        #[allow(deprecated)]
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .oci_upper_size(8192u32)
            .build()
            .await
            .unwrap();

        assert_eq!(
            config.spec.image.oci_root_disk(),
            Some(&crate::sandbox::RootDisk::managed(8192))
        );
    }

    #[tokio::test]
    async fn test_builder_from_snapshot_rejects_explicit_oci_image() {
        let err = SandboxBuilder::new("test")
            .image("alpine")
            .with_snapshot_reference(SnapshotReference::auto("/tmp/missing-snapshot"))
            .build()
            .await
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("from_snapshot is mutually exclusive")
        );
    }

    #[tokio::test]
    async fn test_builder_from_snapshot_rejects_explicit_root_disk() {
        let err = SandboxBuilder::new("test")
            .image_with(|i| i.oci("").root_disk(8192u32))
            .with_snapshot_reference(SnapshotReference::auto("/tmp/missing-snapshot"))
            .build()
            .await
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("from_snapshot is mutually exclusive")
        );
    }

    #[tokio::test]
    async fn test_builder_from_snapshot_rejects_explicit_disk_image() {
        let err = SandboxBuilder::new("test")
            .image_with(|i| i.disk("./rootfs.raw"))
            .with_snapshot_reference(SnapshotReference::auto("/tmp/missing-snapshot"))
            .build()
            .await
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("from_snapshot is mutually exclusive")
        );
    }

    #[tokio::test]
    async fn test_builder_from_snapshot_rejects_explicit_bind_rootfs() {
        let err = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .with_snapshot_reference(SnapshotReference::auto("/tmp/missing-snapshot"))
            .build()
            .await
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("from_snapshot is mutually exclusive")
        );
    }

    #[tokio::test]
    async fn test_builder_disk_only_requires_snapshot() {
        let err = SandboxBuilder::new("test")
            .image("alpine")
            .disk_only()
            .build()
            .await
            .unwrap_err();

        assert!(err.to_string().contains("disk_only must be combined"));
    }

    #[cfg(feature = "cloud")]
    #[tokio::test]
    async fn test_restore_defers_typed_reference_to_cloud_backend() {
        let cloud =
            crate::test_support::cloud_backend("https://api.example.test", "test-key").unwrap();
        for reference in [
            SnapshotReference::auto("00000000-0000-0000-0000-000000000003"),
            SnapshotReference::id("00000000-0000-0000-0000-000000000003"),
            SnapshotReference::path("snapshots/ready"),
        ] {
            let config = with_backend(cloud.clone(), async {
                crate::Sandbox::restore_ref(reference.clone())
                    .name("test")
                    .inner
                    .build()
                    .await
                    .unwrap()
            })
            .await;
            assert_eq!(config.snapshot_reference, Some(reference));
            // Reference routing must not smuggle creation defaults into host bindings.
            assert!(config.spec.mounts.is_empty());
            assert!(config.spec.network.ports.is_empty());
            assert!(config.spec.vsock.is_empty());
        }
    }

    #[tokio::test]
    async fn test_restore_rejects_patches_before_backend_resolution() {
        let err = SandboxBuilder::new("test")
            .with_snapshot_reference(SnapshotReference::auto("post-setup"))
            .patch(|patch| patch.text("/etc/motd", "hello", None, true))
            .build()
            .await
            .unwrap_err();

        assert!(err.to_string().contains("patches cannot be combined"));
    }

    #[tokio::test]
    async fn test_builder_accepts_archive_as_deferred_image_source() {
        let directory = tempfile::tempdir().unwrap();
        let archive = directory.path().join("snapshot.tar.zst");
        std::fs::write(&archive, b"validated by the local backend").unwrap();

        let config = SandboxBuilder::new("test")
            .with_snapshot_reference(SnapshotReference::path(archive.to_string_lossy()))
            .build()
            .await
            .unwrap();

        assert_eq!(
            config.snapshot_archive_source.as_deref(),
            Some(archive.as_path())
        );
        assert!(matches!(
            config.spec.image,
            crate::sandbox::RootfsSource::Oci(ref image) if image.reference.is_empty()
        ));
    }

    #[test]
    fn restored_geometry_cannot_be_changed_by_managed_layers() {
        let mut captured = SandboxBuilder::new("restore")
            .image("alpine")
            .cpus(4)
            .max_cpus(8)
            .memory(2048)
            .max_memory(4096)
            .config
            .into_config();
        captured.suppress_launch_for_full_restore();
        for (policy, accepted) in [
            (serde_json::json!({}), true),
            (
                serde_json::json!({"sandbox_defaults":{"cpus":4,"memory_mib":2048}}),
                true,
            ),
            (serde_json::json!({"sandbox_defaults":{"cpus":2}}), false),
            (
                serde_json::json!({"sandbox_defaults":{"memory_mib":1024}}),
                false,
            ),
        ] {
            let sources = BackendConfig::new(
                serde_json::from_value(
                    serde_json::json!({"sandbox_defaults":{"cpus":1,"memory_mib":512}}),
                )
                .unwrap(),
                serde_json::from_value(policy).unwrap(),
            );
            let result = SandboxBuilder::from(captured.clone()).finish(Some(&sources), None);
            if accepted {
                let config = result.unwrap();
                assert_eq!(config.spec.resources.cpus, 4);
                assert_eq!(config.spec.resources.max_cpus, 8);
                assert_eq!(config.spec.resources.memory_mib, 2048);
                assert_eq!(config.spec.resources.max_memory_mib, 4096);
            } else {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("captured CPU and memory geometry")
                );
            }
        }
    }

    #[test]
    fn restored_root_layout_cannot_be_changed_by_managed_layers() {
        let mut captured = SandboxBuilder::new("restore")
            .image("alpine")
            .config
            .into_config();
        captured.snapshot_parent = Some("snapshot".into());
        super::apply_snapshot_root_layout(&mut captured, &crate::snapshot::SnapshotRootDisk::Flat)
            .unwrap();
        let sources = BackendConfig::new(
            Default::default(),
            serde_json::from_value(
                serde_json::json!({"sandbox_defaults":{"oci":{"root_disk":{"kind":"managed"}}}}),
            )
            .unwrap(),
        );
        let error = SandboxBuilder::from(captured)
            .finish(Some(&sources), None)
            .unwrap_err();
        assert!(error.to_string().contains("captured root disk layout"));
    }

    #[test]
    fn checkpoint_restore_adopts_captured_vm_geometry() {
        let builder = SandboxBuilder::new("restore");
        let state = checkpoint_state_with_geometry(4, 8, 2048, 4096);

        let mut config = builder.config.clone().into_config();

        apply_checkpoint_resources(&mut config, &state, RestoreOverrideIntent::default()).unwrap();

        assert_eq!(config.spec.resources.cpus, 4);
        assert_eq!(config.spec.resources.max_cpus, 8);
        assert_eq!(config.spec.resources.memory_mib, 2048);
        assert_eq!(config.spec.resources.max_memory_mib, 4096);
    }

    #[test]
    fn checkpoint_restore_rejects_conflicting_explicit_geometry() {
        let builder = SandboxBuilder::new("restore").cpus(2);
        let state = checkpoint_state_with_geometry(4, 8, 2048, 4096);

        let mut config = builder.config.clone().into_config();

        let error = apply_checkpoint_resources(
            &mut config,
            &state,
            RestoreOverrideIntent {
                cpus: true,
                ..RestoreOverrideIntent::default()
            },
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("captured CPU and memory geometry")
        );
    }

    #[test]
    fn checkpoint_restore_checks_each_explicit_patch_resource() {
        let state = checkpoint_state_with_geometry(4, 8, 2048, 4096);
        let cases = [
            ("cpus", SandboxResourcesPatch::new().cpus(4), false),
            ("cpus", SandboxResourcesPatch::new().cpus(2), true),
            ("max_cpus", SandboxResourcesPatch::new().max_cpus(8), false),
            ("max_cpus", SandboxResourcesPatch::new().max_cpus(4), true),
            (
                "memory",
                SandboxResourcesPatch::new().memory_mib(2048),
                false,
            ),
            ("memory", SandboxResourcesPatch::new().memory_mib(512), true),
            (
                "max_memory",
                SandboxResourcesPatch::new().max_memory_mib(4096),
                false,
            ),
            (
                "max_memory",
                SandboxResourcesPatch::new().max_memory_mib(2048),
                true,
            ),
        ];

        for (field, patch, conflicting) in cases {
            let builder = SandboxBuilder::new("restore")
                .overlay(SandboxConfigPatch::new().spec(SandboxSpecPatch::new().resources(patch)));
            let intent = builder.restore_override_intent();
            assert_eq!(intent.cpus, field == "cpus");
            assert_eq!(intent.max_cpus, field == "max_cpus");
            assert_eq!(intent.memory, field == "memory");
            assert_eq!(intent.max_memory, field == "max_memory");
            let mut config = builder.config.clone().into_config();
            let result = apply_checkpoint_resources(&mut config, &state, intent);
            if conflicting {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("captured CPU and memory geometry"),
                    "{field}"
                );
            } else {
                result.unwrap();
                assert_eq!(config.spec.resources.cpus, 4);
                assert_eq!(config.spec.resources.max_cpus, 8);
                assert_eq!(config.spec.resources.memory_mib, 2048);
                assert_eq!(config.spec.resources.max_memory_mib, 4096);
            }
        }
    }

    #[test]
    fn checkpoint_restore_patch_preserves_omission_and_prior_intent() {
        // Clearing a patch field means omission, not resetting a previous builder request.
        let absent = SandboxConfigPatch::new().spec(
            SandboxSpecPatch::new().resources(
                SandboxResourcesPatch::new()
                    .cpus(2)
                    .clear_cpus()
                    .memory_mib(512)
                    .clear_memory_mib(),
            ),
        );
        let omitted = SandboxBuilder::new("restore").overlay(absent.clone());
        let intent = omitted.restore_override_intent();
        assert!(!intent.cpus && !intent.max_cpus && !intent.memory && !intent.max_memory);
        let mut omitted_config = omitted.config.into_config();
        apply_checkpoint_resources(
            &mut omitted_config,
            &checkpoint_state_with_geometry(4, 8, 2048, 4096),
            intent,
        )
        .unwrap();

        let explicit = SandboxBuilder::new("restore")
            .cpus(4)
            .max_cpus(8)
            .memory(2048)
            .max_memory(4096)
            .overlay(absent)
            .overlay(SandboxConfigPatch::new());
        let intent = explicit.restore_override_intent();
        assert!(intent.cpus && intent.max_cpus && intent.memory && intent.max_memory);
        assert_eq!(explicit.config.spec.resources.memory_mib, Some(2048));
    }

    #[test]
    fn checkpoint_restore_patch_tracks_requests_equal_to_defaults() {
        let mut builder = SandboxBuilder::new("restore");
        let default_memory = crate::SandboxConfig::default().spec.resources.memory_mib;
        builder = builder.overlay(
            SandboxConfigPatch::new().spec(
                SandboxSpecPatch::new()
                    .resources(SandboxResourcesPatch::new().memory_mib(default_memory)),
            ),
        );
        let intent = builder.restore_override_intent();
        assert!(intent.memory);
        let state =
            checkpoint_state_with_geometry(4, 8, default_memory + 512, default_memory + 1024);
        let mut config = builder.config.into_config();
        assert!(apply_checkpoint_resources(&mut config, &state, intent).is_err());
    }

    #[tokio::test]
    async fn checkpoint_archive_build_retains_patch_resource_intent() {
        let directory = tempfile::tempdir().unwrap();
        let archive = directory.path().join("saved.msb");
        std::fs::write(&archive, b"archive validation is deferred to the backend").unwrap();
        let config = SandboxBuilder::new("restore")
            .with_snapshot_reference(SnapshotReference::path(archive.to_string_lossy()))
            .overlay(
                SandboxConfigPatch::new().spec(
                    SandboxSpecPatch::new().resources(
                        SandboxResourcesPatch::new()
                            .cpus(2)
                            .max_cpus(4)
                            .memory_mib(512)
                            .max_memory_mib(1024),
                    ),
                ),
            )
            .build()
            .await
            .unwrap();

        // Direct archives cross the builder/backend boundary before geometry is checked.
        // Both routes must carry the same intent into that later validation.
        assert_eq!(
            config.snapshot_archive_source.as_deref(),
            Some(archive.as_path())
        );
        let intent = config.restore_overrides;
        assert!(intent.cpus && intent.max_cpus && intent.memory && intent.max_memory);
    }

    #[test]
    fn checkpoint_restore_accepts_default_and_matching_network_fields() {
        let captured = microsandbox_types::InterfaceOverrides {
            mac: Some([0x02, 0x4d, 0x53, 0x42, 0x00, 0x01]),
            mtu: Some(1500),
            ..Default::default()
        };

        assert!(!checkpoint_network_override_conflicts(
            &microsandbox_types::InterfaceOverrides::default(),
            &captured,
        ));
        assert!(!checkpoint_network_override_conflicts(
            &microsandbox_types::InterfaceOverrides {
                mtu: Some(1500),
                ..Default::default()
            },
            &captured,
        ));
    }

    #[test]
    fn checkpoint_restore_rejects_conflicting_network_fields() {
        let captured = microsandbox_types::InterfaceOverrides {
            mac: Some([0x02, 0x4d, 0x53, 0x42, 0x00, 0x01]),
            mtu: Some(1500),
            ..Default::default()
        };
        let requested = microsandbox_types::InterfaceOverrides {
            mtu: Some(1400),
            ..Default::default()
        };

        assert!(checkpoint_network_override_conflicts(&requested, &captured,));
    }

    #[tokio::test]
    async fn test_builder_quiet_logs_clears_runtime_log_level() {
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .log_level(LogLevel::Trace)
            .quiet_logs()
            .build()
            .await
            .unwrap();

        assert_eq!(config.spec.runtime.log_level, None);
    }

    #[tokio::test]
    async fn test_builder_metrics_sample_interval_sets_ms() {
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .metrics_sample_interval(std::time::Duration::from_millis(750))
            .build()
            .await
            .unwrap();

        assert_eq!(config.spec.runtime.metrics_sample_interval_ms, Some(750));
    }

    #[tokio::test]
    async fn test_builder_metrics_sample_interval_zero_is_disabled() {
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .metrics_sample_interval(std::time::Duration::ZERO)
            .build()
            .await
            .unwrap();

        assert!(config.spec.runtime.metrics_sample_interval_ms.is_none());
        assert!(config.effective_metrics_interval().is_none());
    }

    #[tokio::test]
    async fn test_builder_disable_metrics_sample_overrides_interval() {
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .metrics_sample_interval(std::time::Duration::from_millis(5000))
            .disable_metrics_sample()
            .build()
            .await
            .unwrap();

        assert!(config.spec.runtime.disable_metrics_sample);
        assert_eq!(config.spec.runtime.metrics_sample_interval_ms, Some(5000));
        assert!(config.effective_metrics_interval().is_none());
    }

    #[tokio::test]
    async fn test_builder_replace_sets_replace_existing() {
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .replace()
            .build()
            .await
            .unwrap();

        assert!(config.replace_existing);
    }

    #[tokio::test]
    async fn connect_or_create_rejects_replace_semantics() {
        let result = SandboxBuilder::new("connect-or-replace")
            .replace()
            .connect_or_create()
            .await;

        assert!(matches!(
            result,
            Err(crate::MicrosandboxError::InvalidConfig(_))
        ));
    }

    #[tokio::test]
    async fn test_builder_defaults_to_persistent() {
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .build()
            .await
            .unwrap();

        assert!(!config.spec.lifecycle.ephemeral);
    }

    #[tokio::test]
    async fn test_builder_ephemeral_sets_policy() {
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .ephemeral(true)
            .build()
            .await
            .unwrap();

        assert!(config.spec.lifecycle.ephemeral);
    }

    #[tokio::test]
    async fn test_builder_rlimit_sets_sandbox_wide_limit() {
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .rlimit(RlimitResource::Nofile, 65_535)
            .build()
            .await
            .unwrap();

        assert_eq!(config.spec.rlimits.len(), 1);
        assert_eq!(config.spec.rlimits[0].resource, RlimitResource::Nofile);
        assert_eq!(config.spec.rlimits[0].soft, 65_535);
        assert_eq!(config.spec.rlimits[0].hard, 65_535);
    }

    #[cfg(feature = "net")]
    #[tokio::test]
    async fn test_builder_ports_are_repeatable() {
        let bind = "0.0.0.0".parse().unwrap();
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .port(8080, 80)
            .port(3000, 3000)
            .port_udp(5353, 53)
            .port_bind(bind, 8081, 81)
            .port_udp_bind(bind, 5354, 54)
            .build()
            .await
            .unwrap();

        assert_eq!(config.spec.network.ports.len(), 5);
        assert_eq!(config.spec.network.ports[0].host_port, 8080);
        assert_eq!(config.spec.network.ports[0].guest_port, 80);
        assert_eq!(config.spec.network.ports[0].protocol, PortProtocol::Tcp);
        assert_eq!(
            config.spec.network.ports[0].host_bind,
            IpAddr::V4(Ipv4Addr::LOCALHOST).to_string()
        );
        assert_eq!(config.spec.network.ports[1].host_port, 3000);
        assert_eq!(config.spec.network.ports[1].guest_port, 3000);
        assert_eq!(config.spec.network.ports[1].protocol, PortProtocol::Tcp);
        assert_eq!(config.spec.network.ports[2].host_port, 5353);
        assert_eq!(config.spec.network.ports[2].guest_port, 53);
        assert_eq!(config.spec.network.ports[2].protocol, PortProtocol::Udp);
        assert_eq!(config.spec.network.ports[3].host_bind, bind.to_string());
        assert_eq!(config.spec.network.ports[3].host_port, 8081);
        assert_eq!(config.spec.network.ports[3].guest_port, 81);
        assert_eq!(config.spec.network.ports[3].protocol, PortProtocol::Tcp);
        assert_eq!(config.spec.network.ports[4].host_bind, bind.to_string());
        assert_eq!(config.spec.network.ports[4].host_port, 5354);
        assert_eq!(config.spec.network.ports[4].guest_port, 54);
        assert_eq!(config.spec.network.ports[4].protocol, PortProtocol::Udp);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_builder_vsock_routes_preserve_socket_type() {
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .vsock("/run/host-api.sock", 5000)
            // Stream and datagram namespaces are independent.
            .vsock_dgram("/run/events.sock", 5000)
            .build()
            .await
            .unwrap();

        assert_eq!(config.spec.vsock.routes.len(), 2);
        assert_eq!(
            config.spec.vsock.routes[0].socket_type,
            VsockSocketType::Stream
        );
        assert_eq!(
            config.spec.vsock.routes[1].socket_type,
            VsockSocketType::Dgram
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_builder_rejects_duplicate_vsock_route_key() {
        let err = SandboxBuilder::new("test")
            .image("alpine")
            .vsock("/run/one.sock", 5000)
            .vsock("/run/two.sock", 5000)
            .build()
            .await
            .unwrap_err();

        assert!(err.to_string().contains("duplicate vsock Stream route"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_builder_rejects_reserved_timesync_datagram_port() {
        let err = SandboxBuilder::new("test")
            .image("alpine")
            .vsock_dgram("/run/events.sock", 123)
            .build()
            .await
            .unwrap_err();

        assert!(err.to_string().contains("reserved for guest clock"));
    }

    #[tokio::test]
    async fn test_builder_rejects_vsock_for_multi_tenant_deployments() {
        let err = SandboxBuilder::new("test")
            .image("alpine")
            .deployment_profile(DeploymentProfile::MultiTenant)
            .vsock("/run/host-api.sock", 5000)
            .build()
            .await
            .unwrap_err();

        assert!(err.to_string().contains("multi-tenant"));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn test_builder_accepts_local_named_pipe_stream_route() {
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .vsock(r"\\.\pipe\host-api", 5000)
            .build()
            .await
            .unwrap();

        assert_eq!(config.spec.vsock.routes.len(), 1);
        assert_eq!(
            config.spec.vsock.routes[0].socket_type,
            VsockSocketType::Stream
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn test_builder_rejects_remote_named_pipe_and_datagram() {
        let remote = SandboxBuilder::new("test")
            .image("alpine")
            .vsock(r"\\server\pipe\host-api", 5000)
            .build()
            .await
            .unwrap_err();
        assert!(remote.to_string().contains("local Windows named pipe"));

        let datagram = SandboxBuilder::new("test")
            .image("alpine")
            .vsock_dgram(r"\\.\pipe\events", 5001)
            .build()
            .await
            .unwrap_err();
        assert!(matches!(
            datagram,
            crate::MicrosandboxError::Unsupported {
                op: crate::Operation::SandboxCreate,
                reason: crate::UnsupportedReason::RequiresUnixHost,
            }
        ));
    }

    #[cfg(feature = "net")]
    #[tokio::test]
    async fn test_builder_disable_network_denies_all() {
        use microsandbox_network::policy::Action;

        let config = SandboxBuilder::new("test")
            .image("alpine")
            .disable_network()
            .build()
            .await
            .unwrap();

        let network = config.local_network_config().unwrap();
        assert!(!network.enabled);
        // `disable_network()` uses `NetworkPolicy::none()` which is deny-all
        // in both directions with no rules.
        assert_eq!(network.policy.default_egress, Action::Deny);
        assert_eq!(network.policy.default_ingress, Action::Deny);
        assert!(network.policy.rules.is_empty());
    }

    #[cfg(feature = "net")]
    #[tokio::test]
    async fn test_builder_network_preserves_explicit_unlimited() {
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .network(|n| n.max_tcp_connections(0))
            .build()
            .await
            .unwrap();
        assert_eq!(config.spec.network.max_tcp_connections, Some(0));
        assert_eq!(
            config.local_network_config().unwrap().max_tcp_connections,
            Some(ConnectionLimit::Unlimited)
        );
    }

    #[cfg(feature = "net")]
    #[tokio::test]
    async fn test_builder_network_preserves_explicit_unlimited_udp() {
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .network(|n| n.max_udp_connections(0))
            .build()
            .await
            .unwrap();
        assert_eq!(config.spec.network.max_udp_connections, Some(0));
        assert_eq!(
            config.local_network_config().unwrap().max_udp_connections,
            Some(ConnectionLimit::Unlimited)
        );
    }

    #[cfg(feature = "net")]
    #[tokio::test]
    async fn test_builder_network_preserves_top_level_settings() {
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .port(8080, 80)
            .secret_env("OPENAI_API_KEY", "secret", "api.openai.com")
            .network(|n| n.max_tcp_connections(128).strict(true))
            .build()
            .await
            .unwrap();

        assert_eq!(config.spec.network.ports.len(), 1);
        assert_eq!(config.spec.network.ports[0].host_port, 8080);
        assert_eq!(config.spec.network.ports[0].guest_port, 80);
        assert_eq!(config.spec.network.ports[0].protocol, PortProtocol::Tcp);
        let network = config.local_network_config().unwrap();
        assert_eq!(network.secrets.secrets.len(), 1);
        assert_eq!(
            network.max_tcp_connections,
            Some(ConnectionLimit::from(128))
        );
        assert!(network.strict);
    }

    #[cfg(feature = "net")]
    #[tokio::test]
    async fn global_outbound_proxy_survives_network_options_and_accepts_sdk_override() {
        let global = serde_json::from_str(
            r#"{"sandbox_defaults":{"outbound_proxy":{"protocol":"socks5","address":"127.0.0.1:1080"}}}"#,
        )
        .unwrap();
        let backend = crate::LocalBackend::from_backend_config(
            BackendConfig::new(global, Default::default())
                .prepare_for_local_backend(Default::default())
                .unwrap(),
            crate::BackendSelectionSource::Programmatic,
            None,
        );
        crate::backend::with_backend(backend, async {
            let inherited = SandboxBuilder::new("inherited-proxy")
                .image("alpine")
                .network(|n| n.port(8080, 80))
                .build()
                .await
                .unwrap();
            assert!(matches!(
                inherited.spec.network.outbound_proxy,
                Some(microsandbox_types::OutboundProxy::Socks5 { ref address, .. })
                    if address == "127.0.0.1:1080"
            ));
            assert_eq!(inherited.spec.network.ports.len(), 1);

            let overridden = SandboxBuilder::new("override-proxy")
                .image("alpine")
                .proxy(|p| p.socks4("127.0.0.1:2080"))
                .build()
                .await
                .unwrap();
            assert!(matches!(
                overridden.spec.network.outbound_proxy,
                Some(microsandbox_types::OutboundProxy::Socks4 { ref address, .. })
                    if address == "127.0.0.1:2080"
            ));
        })
        .await;
    }

    #[cfg(feature = "net")]
    #[test]
    fn invalid_proxy_defaults_can_be_overridden_before_network_validation() {
        use microsandbox_network::config::EnvNetworkSecretResolver;

        for proxy in [
            serde_json::json!({"protocol": "socks5", "address": "not-an-address"}),
            serde_json::json!({"protocol": "socks4", "address": "127.0.0.1:1080", "user_id": ""}),
            serde_json::json!({"protocol": "socks5", "address": "127.0.0.1:1080", "credentials": {
                "username": "", "password": {"kind": "env", "var": "PROXY_PASSWORD"}
            }}),
            serde_json::json!({"protocol": "socks5", "address": "127.0.0.1:1080", "credentials": {
                "username": "employee", "password": {"kind": "env", "var": ""}
            }}),
        ] {
            let global = serde_json::from_value(serde_json::json!({
                "sandbox_defaults": {"outbound_proxy": proxy}
            }))
            .unwrap();
            let backend = crate::LocalBackend::from_backend_config(
                BackendConfig::new(global, Default::default())
                    .prepare_for_local_backend(Default::default())
                    .unwrap(),
                crate::BackendSelectionSource::Programmatic,
                None,
            );
            let config = SandboxBuilder::new("override-invalid-proxy")
                .image("alpine")
                .proxy(|p| p.socks5("127.0.0.1:2080"))
                .finish(Some(backend.config_sources()), None)
                .unwrap();
            config
                .local_network_config()
                .unwrap()
                .resolve(&EnvNetworkSecretResolver)
                .unwrap();
        }
    }

    #[cfg(feature = "net")]
    #[test]
    fn invalid_managed_proxy_fails_network_resolution() {
        use microsandbox_network::config::EnvNetworkSecretResolver;

        let managed = serde_json::from_str(
            r#"{"sandbox_defaults":{"outbound_proxy":{"protocol":"socks4","address":"127.0.0.1:1080","user_id":""}}}"#,
        )
        .unwrap();
        let layers = BackendConfig::new(Default::default(), managed)
            .prepare_for_local_backend(Default::default())
            .unwrap();
        let config = SandboxBuilder::new("invalid-managed-proxy")
            .image("alpine")
            .proxy(|p| p.socks5("127.0.0.1:2080"))
            .finish(Some(&layers), None)
            .unwrap();
        let error = config
            .local_network_config()
            .unwrap()
            .resolve(&EnvNetworkSecretResolver)
            .unwrap_err();
        assert!(matches!(
            error,
            microsandbox_network::config::NetworkConfigResolveError::OutboundProxy(
                microsandbox_network::OutboundProxyBuildError::InvalidSocks4UserId { .. }
            )
        ));
    }

    #[cfg(feature = "net")]
    #[test]
    fn managed_outbound_proxy_overrides_sparse_and_sdk_options_and_can_clear() {
        use microsandbox_types::{NetworkSpecPatch, OutboundProxy};

        let build = || {
            SandboxBuilder::new("managed-proxy")
                .image("alpine")
                .overlay(SandboxConfigPatch::new().spec(
                    microsandbox_types::SandboxSpecPatch::new().network(
                        NetworkSpecPatch::new().outbound_proxy(OutboundProxy::Socks4 {
                            address: "127.0.0.1:1080".into(),
                            user_id: Some("sparse-user".into()),
                        }),
                    ),
                ))
                .proxy(|p| {
                    p.socks5("127.0.0.1:2080")
                        .credentials("sdk-user", SecretSource::env("UNUSED_PROXY_PASSWORD"))
                })
                .network(|n| n.port(8080, 80))
        };
        let managed = serde_json::from_str(
            r#"{"sandbox_defaults":{"outbound_proxy":{"protocol":"socks5","address":"127.0.0.1:3080"}}}"#,
        )
        .unwrap();
        let layers = BackendConfig::new(Default::default(), managed);
        let expected = Some(OutboundProxy::Socks5 {
            address: "127.0.0.1:3080".into(),
            credentials: None,
        });
        let config = build().finish(Some(&layers), None).unwrap();
        assert_eq!(config.spec.network.outbound_proxy, expected);
        assert_eq!(config.spec.network.ports.len(), 1);
        assert!(config.spec.network.enabled);

        let disabled = build()
            .disable_network()
            .finish(Some(&layers), None)
            .unwrap();
        assert_eq!(disabled.spec.network.outbound_proxy, expected);
        assert!(!disabled.spec.network.enabled);

        let clear =
            serde_json::from_str(r#"{"sandbox_defaults":{"outbound_proxy":null}}"#).unwrap();
        let layers = BackendConfig::new(Default::default(), clear);
        let config = build()
            .finish(Some(&layers), Some(Default::default()))
            .unwrap();
        assert_eq!(config.spec.network.outbound_proxy, None);
        assert_eq!(config.spec.network.ports.len(), 1);
    }

    #[cfg(feature = "net")]
    #[tokio::test]
    async fn test_builder_sets_outbound_proxy() {
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .proxy(|p| p.socks5("127.0.0.1:1080"))
            .build()
            .await
            .unwrap();

        let network = config.local_network_config().unwrap();
        assert_eq!(
            network.outbound_proxy,
            Some(microsandbox_network::OutboundProxy::Socks5 {
                address: "127.0.0.1:1080".parse().unwrap(),
                credentials: None,
            })
        );
    }

    #[cfg(feature = "net")]
    #[tokio::test]
    async fn test_builder_network_rate_limiters_land_in_the_spec() {
        use std::time::Duration;

        use microsandbox_utils::size::SizeExt;

        let config = SandboxBuilder::new("test")
            .image("alpine")
            .network(|n| {
                n.rate_limiter(|r| {
                    r.egress(|r| {
                        r.bandwidth(1.mib(), Duration::from_secs(1))
                            .bandwidth_burst(512.kib())
                            .ops(1_000, Duration::from_secs(1))
                            .ops_burst(500)
                    })
                })
            })
            .build()
            .await
            .unwrap();

        let rate_limiter = config
            .spec
            .network
            .rate_limiter
            .as_ref()
            .expect("network rate limiter persisted");
        let egress = rate_limiter
            .egress
            .as_ref()
            .expect("egress limiter persisted");
        let bandwidth = egress.bandwidth.as_ref().unwrap();
        assert_eq!(bandwidth.size, 1024 * 1024);
        assert_eq!(bandwidth.refill_time_ms, 1000);
        assert_eq!(bandwidth.one_time_burst, 512 * 1024);
        assert_eq!(egress.ops.as_ref().unwrap().one_time_burst, 500);
        assert!(rate_limiter.ingress.is_none());
    }

    #[cfg(feature = "net")]
    #[tokio::test]
    async fn test_builder_sets_socks5_credentials() {
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .proxy(|p| {
                p.socks5("127.0.0.1:1080").credentials(
                    "sandbox",
                    SecretSource::Env {
                        var: "SOCKS5_PASSWORD".into(),
                    },
                )
            })
            .build()
            .await
            .unwrap();

        let network = config.local_network_config().unwrap();
        let json = serde_json::to_value(network.outbound_proxy).unwrap();
        assert_eq!(json["credentials"]["username"], "sandbox");
        assert_eq!(json["credentials"]["password"]["kind"], "env");
        assert_eq!(json["credentials"]["password"]["var"], "SOCKS5_PASSWORD");
        assert!(json["credentials"].get("value").is_none());
    }

    #[cfg(feature = "net")]
    #[tokio::test]
    async fn test_builder_sets_socks4_outbound_proxy_with_user_id() {
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .proxy(|p| p.socks4("127.0.0.1:1080").user_id("sandbox"))
            .build()
            .await
            .unwrap();

        let network = config.local_network_config().unwrap();
        assert_eq!(
            network.outbound_proxy,
            Some(microsandbox_network::OutboundProxy::Socks4 {
                address: "127.0.0.1:1080".parse().unwrap(),
                user_id: Some("sandbox".to_string()),
            })
        );
    }

    #[cfg(feature = "net")]
    #[tokio::test]
    async fn test_builder_rejects_invalid_outbound_proxy() {
        let error = SandboxBuilder::new("test")
            .image("alpine")
            .proxy(|p| p.socks5("not-an-address"))
            .build()
            .await
            .unwrap_err();

        assert!(error.to_string().contains("invalid SOCKS5 proxy address"));
    }

    #[cfg(feature = "net")]
    #[tokio::test]
    async fn test_builder_rejects_invalid_rate_limiter() {
        let err = SandboxBuilder::new("test")
            .image("alpine")
            .network(|n| n.rate_limiter(|r| r.ingress(|r| r)))
            .build()
            .await
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("rate limiter must configure at least one of bandwidth or ops"),
            "unexpected error: {err}"
        );
    }

    #[cfg(feature = "net")]
    #[tokio::test]
    async fn test_builder_rejects_invalid_secret_config() {
        let err = SandboxBuilder::new("test")
            .image("alpine")
            .secret_entry(SecretEntry {
                env_var: "API\0KEY".into(),
                value: zeroize::Zeroizing::new("secret".into()),
                source: None,
                placeholder: "$MSB_API_KEY".into(),
                allowed_hosts: vec![HostPattern::Exact("api.example.com".into())],
                substitution: SecretSubstitution::default(),
                passthrough_hosts: Vec::new(),
                violation_action: None,
                require_tls_identity: true,
            })
            .build()
            .await
            .unwrap_err();

        assert!(err.to_string().contains("env_var must not contain NUL"));
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

    #[tokio::test]
    async fn test_builder_rejects_two_writable_same_host() {
        let (_dir, a, _) = two_disk_files();
        let err = SandboxBuilder::new("test")
            .image("alpine")
            .volume("/x", |v| v.disk(a.clone()))
            .volume("/y", |v| v.disk(a.clone()))
            .build()
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("disk-image volumes cannot share the same host path")
        );
    }

    #[tokio::test]
    async fn test_builder_rejects_writable_plus_readonly_same_host() {
        // Mixed writable+readonly still corrupts because the writable side's
        // host page cache invalidates the readonly side's view.
        let (_dir, a, _) = two_disk_files();
        let err = SandboxBuilder::new("test")
            .image("alpine")
            .volume("/x", |v| v.disk(a.clone()))
            .volume("/y", |v| v.disk(a.clone()).readonly())
            .build()
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("disk-image volumes cannot share the same host path")
        );
    }

    #[tokio::test]
    async fn test_builder_rejects_two_readonly_same_host() {
        let (_dir, a, _) = two_disk_files();
        let err = SandboxBuilder::new("test")
            .image("alpine")
            .volume("/x", |v| v.disk(a.clone()).readonly())
            .volume("/y", |v| v.disk(a.clone()).readonly())
            .build()
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("disk-image volumes cannot share the same host path")
        );
    }

    #[tokio::test]
    async fn test_builder_accepts_two_writable_different_hosts() {
        let (_dir, a, b) = two_disk_files();
        SandboxBuilder::new("test")
            .image("alpine")
            .volume("/x", |v| v.disk(a))
            .volume("/y", |v| v.disk(b))
            .build()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_builder_canonicalizes_host_paths() {
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
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("disk-image volumes cannot share the same host path")
        );
    }

    #[tokio::test]
    async fn test_builder_rejects_missing_disk_host() {
        let dir = tempfile::tempdir().unwrap();
        let nonexistent = dir.path().join("nope.qcow2");
        let err = SandboxBuilder::new("test")
            .image("alpine")
            .volume("/x", |v| v.disk(nonexistent))
            .build()
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("disk image host path does not exist")
        );
    }

    //----------------------------------------------------------------------------------------------
    // Sandbox name validation
    //----------------------------------------------------------------------------------------------

    #[test]
    fn sandbox_name_accepts_typical() {
        for name in [
            "foo",
            "foo-bar",
            "foo.bar",
            "foo_bar",
            "FooBar",
            "abc123",
            "a",
            "0",
            "agent-1",
            "my.app_2026",
        ] {
            assert!(
                crate::sandbox::validate_sandbox_name(name).is_ok(),
                "expected {name:?} to be accepted"
            );
        }
    }

    #[test]
    fn sandbox_name_rejects_empty() {
        assert!(crate::sandbox::validate_sandbox_name("").is_err());
    }

    #[test]
    fn sandbox_name_rejects_too_long() {
        let long = "a".repeat(MAX_SANDBOX_NAME_BYTES + 1);
        assert!(crate::sandbox::validate_sandbox_name(&long).is_err());
    }

    #[test]
    fn sandbox_name_accepts_at_max_length() {
        let max = "a".repeat(MAX_SANDBOX_NAME_BYTES);
        assert!(crate::sandbox::validate_sandbox_name(&max).is_ok());
    }

    #[test]
    fn sandbox_name_rejects_disallowed_chars() {
        for name in [
            "foo bar", "foo/bar", "foo:bar", "foo!", "foo@bar", "foo#1", "✨",
        ] {
            assert!(
                crate::sandbox::validate_sandbox_name(name).is_err(),
                "expected {name:?} to be rejected"
            );
        }
    }

    #[test]
    fn sandbox_name_rejects_non_alphanumeric_start() {
        for name in [".foo", "-foo", "_foo"] {
            assert!(
                crate::sandbox::validate_sandbox_name(name).is_err(),
                "expected {name:?} to be rejected (non-alphanumeric start)"
            );
        }
    }

    #[tokio::test]
    async fn builder_validate_rejects_bad_name() {
        let err = SandboxBuilder::new("bad name!")
            .image("alpine")
            .build()
            .await
            .unwrap_err();
        assert!(err.to_string().contains("alphanumeric"), "got: {err}");
    }

    #[tokio::test]
    async fn builder_orders_nested_mounts_parent_first() {
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .volume("/workspace/persist", |mount| mount.tmpfs())
            .volume("/workspace", |mount| mount.tmpfs())
            .build()
            .await
            .unwrap();

        assert_eq!(
            config
                .spec
                .mounts
                .iter()
                .map(VolumeMount::guest)
                .collect::<Vec<_>>(),
            vec!["/workspace", "/workspace/persist"]
        );
    }
    #[tokio::test]
    async fn forked_rejects_fresh_boot() {
        let error = SandboxBuilder::new("forked-boot")
            .image("alpine")
            .forked()
            .build()
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("forked requires a full snapshot")
        );
    }

    #[tokio::test]
    async fn forked_restore_is_transient_and_requires_execution() {
        let mut builder = SandboxBuilder::new("forked-child").image("alpine").forked();
        builder.config.checkpoint_restore =
            Some(microsandbox_runtime::launch::CheckpointRestoreConfig {
                memory_descriptor: false,
                network_gateway_mac: None,
                external_mount_policy: Default::default(),
                external_mounts: Vec::new(),
                unavailable_disks: Default::default(),
                local_branch: false,
                forked: false,
                closure: "/owned/checkpoint".into(),
                checkpoint_root: "blake3:captured-root".into(),
                checkpoint_id: "captured".into(),
            });
        let config = builder.config.clone().into_config();
        builder.validate(&mut config.clone()).unwrap();
        assert!(config.forked);
        assert!(!config.clone_for_persistence().forked);
        assert!(
            serde_json::to_value(&config)
                .unwrap()
                .get("forked")
                .is_none()
        );
        builder.config.snapshot_restore_mode =
            Some(crate::sandbox::config::SnapshotRestoreMode::DiskOnly);
        assert!(
            builder
                .build()
                .await
                .unwrap_err()
                .to_string()
                .contains("forked")
        );
    }
}

//! Fluent builder for [`SandboxConfig`].

#[cfg(feature = "net")]
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::Duration;

use microsandbox_image::{PullProgressHandle, RegistryAuth};
#[cfg(feature = "net")]
use microsandbox_network::builder::{NetworkBuilder, SecretBuilder};
use microsandbox_types::{EnvVar, PullPolicy};
#[cfg(feature = "net")]
use microsandbox_types::{PortProtocol, PublishedPortSpec};

use super::{
    config::{SandboxConfig, sandbox_log_level_from_runtime},
    exec::{Rlimit, RlimitResource},
    init::{HandoffInit, InitOptionsBuilder},
    types::{
        ImageBuilder, IntoImage, MountBuilder, Patch, PatchBuilder, RootfsSource, SecurityProfile,
        VolumeMount,
    },
};
use crate::{LogLevel, MicrosandboxError, MicrosandboxResult, size::Mebibytes};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Builder for constructing a [`SandboxConfig`] with a fluent API.
pub struct SandboxBuilder {
    config: SandboxConfig,
    detached: bool,
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
    /// Start building a sandbox configuration.
    ///
    /// The name must be unique among existing sandboxes (unless
    /// [`replace`](Self::replace) is set) and no longer than 128 UTF-8 bytes.
    pub fn new(name: impl Into<String>) -> Self {
        let mut config = SandboxConfig::default();
        config.spec.name = name.into();

        Self {
            config,
            detached: false,
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
            Ok(rootfs) => self.config.spec.image = rootfs,
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
    /// .image_with(|i| i.oci("python:3.12").upper_size(8.gib()))
    /// .image_with(|i| i.disk("./ubuntu.qcow2").fstype("ext4"))
    /// ```
    pub fn image_with(mut self, f: impl FnOnce(ImageBuilder) -> ImageBuilder) -> Self {
        match f(ImageBuilder::new()).build() {
            Ok(rootfs) => self.config.spec.image = rootfs,
            Err(e) => {
                if self.build_error.is_none() {
                    self.build_error = Some(e);
                }
            }
        }
        self
    }

    /// Set the writable overlay upper size for an OCI rootfs.
    ///
    /// Prefer [`image_with`](Self::image_with) when configuring the image and
    /// upper together. This method exists for call sites, such as CLIs, where
    /// the image reference and its options are parsed separately.
    pub fn oci_upper_size(mut self, size: impl Into<Mebibytes>) -> Self {
        let size_mib = size.into().as_u32();
        match &mut self.config.spec.image {
            RootfsSource::Oci(oci) if !oci.reference.is_empty() => {
                oci.upper_size_mib = Some(size_mib);
            }
            RootfsSource::Oci(_) => {
                if self.build_error.is_none() {
                    self.build_error = Some(crate::MicrosandboxError::InvalidConfig(
                        "oci_upper_size() requires an OCI image to be set first".into(),
                    ));
                }
            }
            _ => {
                if self.build_error.is_none() {
                    self.build_error = Some(crate::MicrosandboxError::InvalidConfig(
                        "oci_upper_size() is only valid for OCI images".into(),
                    ));
                }
            }
        }
        self
    }

    /// Allocate virtual CPUs for this sandbox (default: 1).
    pub fn cpus(mut self, count: u8) -> Self {
        self.config.spec.resources.cpus = count;
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
        self.config.spec.resources.memory_mib = size.into().as_u32();
        self
    }

    /// Set the runtime log level for the sandbox process.
    ///
    /// This controls the verbosity of the `msb sandbox` process.
    pub fn log_level(mut self, level: LogLevel) -> Self {
        self.config.spec.runtime.log_level = Some(sandbox_log_level_from_runtime(level));
        self
    }

    /// Disable runtime logs for this sandbox, even if a global default exists.
    pub fn quiet_logs(mut self) -> Self {
        self.config.spec.runtime.log_level = None;
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
        self.config.spec.runtime.disable_metrics_sample = true;
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
            std::num::NonZero::new(ms as u64).map(std::num::NonZero::get);
        self
    }

    /// Default working directory for commands executed in this sandbox
    /// (e.g., `/app`). Used by [`exec`](super::Sandbox::exec),
    /// [`shell`](super::Sandbox::shell), and [`attach`](super::Sandbox::attach)
    /// unless overridden per-command.
    pub fn workdir(mut self, path: impl Into<String>) -> Self {
        self.config.spec.runtime.workdir = Some(path.into());
        self
    }

    /// Shell used by [`shell()`](super::Sandbox::shell) to interpret
    /// commands (default: `/bin/sh`).
    pub fn shell(mut self, shell: impl Into<String>) -> Self {
        self.config.spec.runtime.shell = Some(shell.into());
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
        self.config.replace_existing = true;
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
        self.config.replace_existing = true;
        self.config.replace_with_timeout = timeout;
        self
    }

    /// Override the OCI image entrypoint.
    pub fn entrypoint(mut self, cmd: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.config.spec.runtime.entrypoint = Some(cmd.into_iter().map(Into::into).collect());
        self
    }

    /// Clear detached startup intent for attached CLI `run`.
    #[doc(hidden)]
    pub fn initial_command(mut self, command: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.config
            .set_initial_command(command.into_iter().map(Into::into).collect());
        self
    }

    /// Set the persisted startup command for detached CLI `run`.
    #[doc(hidden)]
    pub fn persistent_initial_command(
        mut self,
        command: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.config
            .set_persistent_initial_command(command.into_iter().map(Into::into).collect());
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
    pub fn init(mut self, cmd: impl Into<PathBuf>) -> Self {
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
        cmd: impl Into<PathBuf>,
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
        self.config.spec.pull_policy = policy;
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
        match self.config.local_network_config() {
            Ok(mut network) => {
                network.enabled = false;
                network.policy = microsandbox_network::policy::NetworkPolicy::none();
                if let Err(err) = self.config.set_local_network_config(network)
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
    ///     .policy(NetworkPolicy::public_only())
    ///     .tls(|t| t.bypass("*.internal.com"))
    /// )
    /// ```
    #[cfg(feature = "net")]
    pub fn network(mut self, f: impl FnOnce(NetworkBuilder) -> NetworkBuilder) -> Self {
        let network = match self.config.local_network_config() {
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
                if let Err(err) = self.config.set_local_network_config(net)
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
        self.config.spec.network.ports.push(PublishedPortSpec {
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
    pub fn secret(self, f: impl FnOnce(SecretBuilder) -> SecretBuilder) -> Self {
        self.secret_entry(f(SecretBuilder::new()).build())
    }

    /// Add a materialized secret entry.
    #[cfg(feature = "net")]
    pub fn secret_entry(
        mut self,
        entry: microsandbox_network::secrets::config::SecretEntry,
    ) -> Self {
        match self.config.local_network_config() {
            Ok(mut network) => {
                network.secrets.secrets.push(entry);
                if !network.tls.enabled {
                    network.tls.enabled = true;
                }
                if let Err(err) = self.config.set_local_network_config(network)
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
        let key = key.into();
        if key.starts_with("MSB_") {
            if self.build_error.is_none() {
                self.build_error = Some(crate::MicrosandboxError::InvalidConfig(format!(
                    "environment variable {key:?} uses the reserved MSB_ prefix"
                )));
            }
            return self;
        }
        self.config.spec.env.push(EnvVar::new(key, value));
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
        self.config.spec.labels.insert(key.into(), value.into());
        self
    }

    /// Attach multiple labels at once. See [`label`](Self::label).
    pub fn labels(
        mut self,
        labels: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        for (k, v) in labels {
            self.config.spec.labels.insert(k.into(), v.into());
        }
        self
    }

    /// Set a sandbox-wide resource limit inherited by all guest processes.
    ///
    /// This is applied during agentd PID 1 startup, so bootstrap scripts and
    /// long-lived daemons inherit the raised baseline without needing explicit
    /// per-exec rlimits.
    pub fn rlimit(mut self, resource: RlimitResource, limit: u64) -> Self {
        self.config.spec.rlimits.push(Rlimit {
            resource,
            soft: limit,
            hard: limit,
        });
        self
    }

    /// Set a sandbox-wide resource limit with different soft/hard values.
    pub fn rlimit_range(mut self, resource: RlimitResource, soft: u64, hard: u64) -> Self {
        self.config.spec.rlimits.push(Rlimit {
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
        self.config
            .spec
            .runtime
            .scripts
            .insert(name.into(), content.into());
        self
    }

    /// Register multiple scripts at once. See [`script`](Self::script).
    pub fn scripts(
        mut self,
        scripts: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        for (name, content) in scripts {
            self.config
                .spec
                .runtime
                .scripts
                .insert(name.into(), content.into());
        }
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
        self.config.spec.security_profile = profile;
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
            Ok(mount) => self.config.spec.mounts.push(mount),
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
        self.config
            .spec
            .patches
            .extend(f(PatchBuilder::new()).build());
        self
    }

    /// Add a single patch directly.
    pub fn add_patch(mut self, patch: Patch) -> Self {
        self.config.spec.patches.push(patch);
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
    /// the artifact synchronously and don't want the async manifest
    /// read that [`build`](Self::build) would otherwise perform.
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
    /// If [`from_snapshot`](Self::from_snapshot) was called, the snapshot
    /// manifest is opened here and its pinned image reference, manifest
    /// digest, and upper-layer source path are populated onto the config.
    /// Backend-owned defaults are applied when the config is created, not here.
    pub async fn build(mut self) -> MicrosandboxResult<SandboxConfig> {
        self.resolve_pending().await?;
        self.validate()?;
        Ok(self.config)
    }

    /// Open the deferred snapshot artifact and copy its pinned image
    /// reference, manifest digest, and upper-layer source path into the
    /// config. Internal — driven by [`build`](Self::build).
    async fn resolve_pending(&mut self) -> MicrosandboxResult<()> {
        let Some(snapshot_ref) = self.pending_snapshot.take() else {
            return Ok(());
        };

        if self.has_explicit_rootfs_source() {
            return Err(crate::MicrosandboxError::InvalidConfig(
                "from_snapshot is mutually exclusive with explicit rootfs configuration".into(),
            ));
        }

        let snap = crate::snapshot::Snapshot::open(&snapshot_ref).await?;
        let snap_ref = snap.manifest().image.reference.clone();

        self.config.spec.image = RootfsSource::oci(snap_ref);
        self.config.manifest_digest = Some(snap.manifest().image.manifest_digest.clone());
        self.config.snapshot_upper_source = Some(snap.path().join(&snap.manifest().upper.file));
        Ok(())
    }

    fn has_explicit_rootfs_source(&self) -> bool {
        match &self.config.spec.image {
            RootfsSource::Oci(oci) => !oci.reference.is_empty() || oci.upper_size_mib.is_some(),
            RootfsSource::Bind(path) => !path.as_os_str().is_empty(),
            RootfsSource::DiskImage { .. } => true,
        }
    }

    /// Create the sandbox. Boots the VM with agentd ready.
    pub async fn create(self) -> MicrosandboxResult<super::Sandbox> {
        if self.detached {
            return self.create_detached().await;
        }
        let config = self.build().await?;
        super::Sandbox::create(config).await
    }

    /// Create the sandbox for detached/background use.
    pub async fn create_detached(self) -> MicrosandboxResult<super::Sandbox> {
        let config = self.build().await?;
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
        self,
    ) -> crate::MicrosandboxResult<(
        PullProgressHandle,
        tokio::task::JoinHandle<crate::MicrosandboxResult<super::Sandbox>>,
    )> {
        let (handle, sender) = microsandbox_image::progress_channel();
        let task = tokio::spawn(async move {
            let detached = self.detached;
            let config = self.build().await?;
            let backend = crate::backend::default_backend();
            match backend.kind() {
                crate::backend::BackendKind::Local => {
                    let mode = if detached {
                        crate::runtime::SpawnMode::Detached
                    } else {
                        crate::runtime::SpawnMode::Attached
                    };
                    crate::sandbox::create_local(backend, config, mode, Some(sender)).await
                }
                crate::backend::BackendKind::Cloud => {
                    drop(sender);
                    if detached {
                        backend
                            .sandboxes()
                            .create_detached(backend.clone(), config)
                            .await
                    } else {
                        backend
                            .sandboxes()
                            .create(backend.clone(), config, true)
                            .await
                    }
                }
            }
        });
        Ok((handle, task))
    }

    /// Like `create_with_pull_progress` but spawns the sandbox process in detached
    /// mode so the sandbox survives after the creating process exits.
    pub fn create_detached_with_pull_progress(
        self,
    ) -> crate::MicrosandboxResult<(
        PullProgressHandle,
        tokio::task::JoinHandle<crate::MicrosandboxResult<super::Sandbox>>,
    )> {
        let (handle, sender) = microsandbox_image::progress_channel();
        let task = tokio::spawn(async move {
            let config = self.build().await?;
            let backend = crate::backend::default_backend();
            match backend.kind() {
                crate::backend::BackendKind::Local => {
                    crate::sandbox::create_local(
                        backend,
                        config,
                        crate::runtime::SpawnMode::Detached,
                        Some(sender),
                    )
                    .await
                }
                crate::backend::BackendKind::Cloud => {
                    drop(sender);
                    backend
                        .sandboxes()
                        .create_detached(backend.clone(), config)
                        .await
                }
            }
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

        if self.config.spec.name.is_empty() {
            return Err(crate::MicrosandboxError::InvalidConfig(
                "sandbox name is required".into(),
            ));
        }
        super::validate_sandbox_name_for_runtime(&self.config.spec.name)?;
        super::validate_hostname(self.config.spec.runtime.hostname.as_deref())?;

        // Check that image is set (non-empty OCI string or Bind path).
        match &self.config.spec.image {
            RootfsSource::Oci(oci) if oci.reference.is_empty() => {
                return Err(crate::MicrosandboxError::InvalidConfig(
                    "image source is required".into(),
                ));
            }
            RootfsSource::Oci(oci) if oci.upper_size_mib == Some(0) => {
                return Err(crate::MicrosandboxError::InvalidConfig(
                    "oci upper_size must be greater than 0".into(),
                ));
            }
            RootfsSource::DiskImage { .. } if !self.config.spec.patches.is_empty() => {
                return Err(crate::MicrosandboxError::InvalidConfig(
                    "patches are not compatible with disk image rootfs".into(),
                ));
            }
            _ => {}
        }

        for rlimit in &self.config.spec.rlimits {
            if rlimit.soft > rlimit.hard {
                return Err(crate::MicrosandboxError::InvalidConfig(format!(
                    "rlimit {}: soft ({}) must not exceed hard ({})",
                    rlimit.resource.as_str(),
                    rlimit.soft,
                    rlimit.hard
                )));
            }
        }

        super::types::validate_volume_mounts(&self.config.spec.mounts)?;
        super::validate_env(&self.config.spec.env)?;
        super::validate_labels(&self.config.spec.labels)?;

        if let Some(spec) = &self.config.spec.init {
            super::init::validate(spec)?;
        }

        #[cfg(feature = "net")]
        self.config
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
        for mount in &self.config.spec.mounts {
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
            detached: false,
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
    use crate::backend::{LocalBackend, with_backend};
    use crate::sandbox::{MAX_HOSTNAME_BYTES, MAX_SANDBOX_NAME_BYTES, RlimitResource};
    #[cfg(feature = "net")]
    use microsandbox_network::secrets::config::{HostPattern, SecretEntry, SecretInjection};
    #[cfg(feature = "net")]
    use microsandbox_types::PortProtocol;
    use microsandbox_types::SandboxLogLevel;
    #[cfg(feature = "net")]
    use std::net::{IpAddr, Ipv4Addr};
    use tempfile::Builder as TempDirBuilder;

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
            .memory(1024)
            .log_level(LogLevel::Info)
            .env("A", "B")
            .script("setup", "echo hi")
            .max_duration(60)
            .build()
            .await
            .unwrap();

        assert_eq!(config.spec.name, "test");
        assert_eq!(config.spec.resources.cpus, 2);
        assert_eq!(config.spec.resources.memory_mib, 1024);
        assert_eq!(config.spec.runtime.log_level, Some(SandboxLogLevel::Info));
        assert_eq!(config.spec.env.len(), 1);
        assert_eq!(
            config.spec.runtime.scripts.get("setup"),
            Some(&"echo hi".into())
        );
        assert_eq!(config.spec.lifecycle.max_duration_secs, Some(60));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_builder_accepts_128_byte_sandbox_name() {
        let temp = TempDirBuilder::new()
            .prefix("msb")
            .tempdir_in("/tmp")
            .unwrap();
        let backend = LocalBackend::builder()
            .home(temp.path())
            .build()
            .await
            .unwrap();
        let name = "x".repeat(MAX_SANDBOX_NAME_BYTES);
        let config = with_backend(backend, async {
            SandboxBuilder::new(name.clone())
                .image("alpine")
                .build()
                .await
                .unwrap()
        })
        .await;

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
    async fn test_builder_image_with_oci_upper_size() {
        let config = SandboxBuilder::new("test")
            .image_with(|i| i.oci("alpine").upper_size(8192u32))
            .build()
            .await
            .unwrap();

        match &config.spec.image {
            super::RootfsSource::Oci(oci) => {
                assert_eq!(oci.reference, "alpine");
                assert_eq!(oci.upper_size_mib, Some(8192));
            }
            other => panic!("expected Oci, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_builder_leaves_backend_oci_upper_default_unmaterialized() {
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .build()
            .await
            .unwrap();

        assert_eq!(config.spec.image.oci_upper_size_mib(), None);
    }

    #[tokio::test]
    async fn test_builder_oci_upper_size_rejects_bind_rootfs() {
        let err = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .oci_upper_size(8192u32)
            .build()
            .await
            .unwrap_err();

        assert!(err.to_string().contains("only valid for OCI images"));
    }

    #[tokio::test]
    async fn test_builder_from_snapshot_rejects_explicit_oci_image() {
        let err = SandboxBuilder::new("test")
            .image("alpine")
            .from_snapshot("/tmp/missing-snapshot")
            .build()
            .await
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("from_snapshot is mutually exclusive")
        );
    }

    #[tokio::test]
    async fn test_builder_from_snapshot_rejects_explicit_oci_upper_size() {
        let err = SandboxBuilder::new("test")
            .image_with(|i| i.oci("").upper_size(8192u32))
            .from_snapshot("/tmp/missing-snapshot")
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
            .from_snapshot("/tmp/missing-snapshot")
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
            .from_snapshot("/tmp/missing-snapshot")
            .build()
            .await
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("from_snapshot is mutually exclusive")
        );
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
    async fn test_builder_network_preserves_top_level_settings() {
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .port(8080, 80)
            .secret_env("OPENAI_API_KEY", "secret", "api.openai.com")
            .network(|n| n.max_connections(128))
            .build()
            .await
            .unwrap();

        assert_eq!(config.spec.network.ports.len(), 1);
        assert_eq!(config.spec.network.ports[0].host_port, 8080);
        assert_eq!(config.spec.network.ports[0].guest_port, 80);
        assert_eq!(config.spec.network.ports[0].protocol, PortProtocol::Tcp);
        let network = config.local_network_config().unwrap();
        assert_eq!(network.secrets.secrets.len(), 1);
        assert_eq!(network.max_connections, Some(128));
    }

    #[cfg(feature = "net")]
    #[tokio::test]
    async fn test_builder_rejects_invalid_secret_config() {
        let err = SandboxBuilder::new("test")
            .image("alpine")
            .secret_entry(SecretEntry {
                env_var: "API\0KEY".into(),
                value: "secret".into(),
                placeholder: "$MSB_API_KEY".into(),
                allowed_hosts: vec![HostPattern::Exact("api.example.com".into())],
                injection: SecretInjection::default(),
                on_violation: None,
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
}

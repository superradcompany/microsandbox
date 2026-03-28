//! Fluent builder for [`SandboxConfig`].

use microsandbox_image::RegistryAuth;
#[cfg(feature = "net")]
use microsandbox_network::builder::{NetworkBuilder, SecretBuilder};
#[cfg(feature = "net")]
use microsandbox_network::config::{PortProtocol, PublishedPort};
#[cfg(feature = "net")]
use std::net::{IpAddr, Ipv4Addr};

use super::{
    config::SandboxConfig,
    types::{IntoImage, MountBuilder, Patch, PatchBuilder, RootfsSource},
};
use crate::{LogLevel, MicrosandboxResult, size::Mebibytes};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Builder for constructing a [`SandboxConfig`] with a fluent API.
pub struct SandboxBuilder {
    config: SandboxConfig,
    build_error: Option<crate::MicrosandboxError>,
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
        }
    }

    /// Set the root filesystem image source.
    ///
    /// Accepts a string, path, or closure:
    /// - **`&str` / `String`**: Paths starting with `/`, `./`, or `../` are treated as local
    ///   paths. Everything else is treated as an OCI image reference. Disk image extensions
    ///   (`.qcow2`, `.raw`, `.vmdk`) resolve to virtio-blk block device rootfs.
    /// - **`PathBuf`**: Always treated as a local path.
    /// - **Closure**: `|i| i.disk("./image.qcow2").fstype("ext4")` for explicit disk image
    ///   configuration.
    ///
    /// ```ignore
    /// .image("python:3.12")                                // OCI image
    /// .image("./rootfs")                                   // local directory (bind mount)
    /// .image("./ubuntu.qcow2")                             // disk image (auto-detect fs)
    /// .image(|i| i.disk("./ubuntu.qcow2").fstype("ext4"))  // disk image (explicit fs)
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

    /// Set registry authentication for private OCI registries.
    pub fn registry_auth(mut self, auth: RegistryAuth) -> Self {
        self.config.registry_auth = Some(auth);
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

    /// Set the user identity inside the sandbox (e.g., `"1000"`, `"appuser"`, `"1000:1000"`).
    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.config.user = Some(user.into());
        self
    }

    /// Set the pull policy for OCI images.
    pub fn pull_policy(mut self, policy: microsandbox_image::PullPolicy) -> Self {
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
    ///     .block_domain("evil.com")
    ///     .tls(|t| t.bypass("*.internal.com"))
    /// )
    /// ```
    #[cfg(feature = "net")]
    pub fn network(mut self, f: impl FnOnce(NetworkBuilder) -> NetworkBuilder) -> Self {
        let network = std::mem::take(&mut self.config.network);
        self.config.network = f(NetworkBuilder::from_config(network)).build();
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
    /// Patches are applied before VM start. Only works with OverlayFs and
    /// PassthroughFs roots. Returns an error at create time if used with
    /// block device roots (Qcow2, Raw).
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

    /// Build the configuration without creating the sandbox.
    pub fn build(mut self) -> MicrosandboxResult<SandboxConfig> {
        self.validate()?;
        Ok(self.config)
    }

    /// Create the sandbox. Boots the VM with agentd ready.
    pub async fn create(self) -> MicrosandboxResult<super::Sandbox> {
        let config = self.build()?;
        super::Sandbox::create(config).await
    }

    /// Create the sandbox for detached/background use.
    pub async fn create_detached(self) -> MicrosandboxResult<super::Sandbox> {
        let config = self.build()?;
        super::Sandbox::create_detached(config).await
    }

    /// Create the sandbox with pull progress reporting.
    ///
    /// Returns a progress handle for per-layer pull events and a task handle
    /// for the sandbox creation result. Useful for CLI commands that want to
    /// display per-layer download/extraction progress during sandbox creation.
    pub fn create_with_pull_progress(
        self,
    ) -> crate::MicrosandboxResult<(
        microsandbox_image::PullProgressHandle,
        tokio::task::JoinHandle<crate::MicrosandboxResult<super::Sandbox>>,
    )> {
        let config = self.build()?;
        Ok(super::Sandbox::create_with_pull_progress(config))
    }

    /// Create a detached sandbox with pull progress reporting.
    ///
    /// Like `create_with_pull_progress` but spawns the sandbox process in detached
    /// mode so the sandbox survives after the creating process exits.
    pub fn create_detached_with_pull_progress(
        self,
    ) -> crate::MicrosandboxResult<(
        microsandbox_image::PullProgressHandle,
        tokio::task::JoinHandle<crate::MicrosandboxResult<super::Sandbox>>,
    )> {
        let config = self.build()?;
        Ok(super::Sandbox::create_detached_with_pull_progress(config))
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
    #[cfg(feature = "net")]
    use microsandbox_network::config::PortProtocol;

    #[test]
    fn test_builder_sets_runtime_log_level() {
        let config = SandboxBuilder::new("test")
            .image("alpine:3.23")
            .log_level(LogLevel::Debug)
            .build()
            .unwrap();

        assert_eq!(config.log_level, Some(LogLevel::Debug));
    }

    #[test]
    fn test_builder_quiet_logs_clears_runtime_log_level() {
        let config = SandboxBuilder::new("test")
            .image("alpine:3.23")
            .log_level(LogLevel::Trace)
            .quiet_logs()
            .build()
            .unwrap();

        assert_eq!(config.log_level, None);
    }

    #[test]
    fn test_builder_replace_sets_replace_existing() {
        let config = SandboxBuilder::new("test")
            .image("alpine:3.23")
            .replace()
            .build()
            .unwrap();

        assert!(config.replace_existing);
    }

    #[cfg(feature = "net")]
    #[test]
    fn test_builder_ports_are_repeatable() {
        let config = SandboxBuilder::new("test")
            .image("alpine:3.23")
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
            .image("alpine:3.23")
            .disable_network()
            .build()
            .unwrap();

        assert!(!config.network.enabled);
        assert_eq!(config.network.policy.default_action, Action::Deny);
        assert!(config.network.policy.rules.is_empty());
    }

    #[cfg(feature = "net")]
    #[test]
    fn test_builder_network_preserves_top_level_settings() {
        let config = SandboxBuilder::new("test")
            .image("alpine:3.23")
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
}

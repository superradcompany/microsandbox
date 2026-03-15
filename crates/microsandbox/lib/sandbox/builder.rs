//! Fluent builder for [`SandboxConfig`].

use microsandbox_runtime::policy::ShutdownMode;

use microsandbox_image::RegistryAuth;

use super::{
    config::SandboxConfig,
    types::{IntoImage, MountBuilder, RootfsSource},
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
    /// Create a new builder with the given sandbox name.
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

    /// Set the number of virtual CPUs.
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

    /// Set the runtime log level for sandbox child processes.
    ///
    /// This controls the verbosity of `msb supervisor` and `msb microvm`
    /// for this sandbox only.
    pub fn log_level(mut self, level: LogLevel) -> Self {
        self.config.log_level = Some(level);
        self
    }

    /// Disable runtime logs for this sandbox, even if a global default exists.
    pub fn quiet_logs(mut self) -> Self {
        self.config.log_level = None;
        self
    }

    /// Set the working directory inside the sandbox.
    pub fn workdir(mut self, path: impl Into<String>) -> Self {
        self.config.workdir = Some(path.into());
        self
    }

    /// Set the default shell.
    pub fn shell(mut self, shell: impl Into<String>) -> Self {
        self.config.shell = Some(shell.into());
        self
    }

    /// Set registry authentication for private OCI registries.
    pub fn registry_auth(mut self, auth: RegistryAuth) -> Self {
        self.config.registry_auth = Some(auth);
        self
    }

    /// Replace an existing stopped sandbox with the same name during create.
    pub fn force(mut self) -> Self {
        self.config.replace_existing = true;
        self
    }

    /// Set a custom init binary path.
    pub fn init(mut self, path: impl Into<String>) -> Self {
        self.config.init = Some(path.into());
        self
    }

    /// Add an environment variable.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.config.env.push((key.into(), value.into()));
        self
    }

    /// Add multiple environment variables.
    pub fn envs(
        mut self,
        vars: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        for (k, v) in vars {
            self.config.env.push((k.into(), v.into()));
        }
        self
    }

    /// Add a named script.
    pub fn script(mut self, name: impl Into<String>, content: impl Into<String>) -> Self {
        self.config.scripts.insert(name.into(), content.into());
        self
    }

    /// Add multiple scripts.
    pub fn scripts(
        mut self,
        scripts: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        for (name, content) in scripts {
            self.config.scripts.insert(name.into(), content.into());
        }
        self
    }

    /// Set the shutdown escalation mode.
    pub fn shutdown_mode(mut self, mode: ShutdownMode) -> Self {
        self.config.supervisor_policy.shutdown_mode = mode;
        self
    }

    /// Set the grace period between escalation steps (in seconds).
    pub fn grace_period(mut self, secs: u64) -> Self {
        self.config.supervisor_policy.grace_secs = secs;
        self
    }

    /// Set a maximum sandbox lifetime in seconds.
    pub fn max_duration(mut self, secs: u64) -> Self {
        self.config.supervisor_policy.max_duration_secs = Some(secs);
        self
    }

    /// Set the idle timeout in seconds.
    pub fn idle_timeout(mut self, secs: u64) -> Self {
        self.config.supervisor_policy.idle_timeout_secs = Some(secs);
        self
    }

    /// Add a volume mount using a closure-based builder.
    ///
    /// ```ignore
    /// .volume("/data", |m| m.bind("/host/data"))
    /// .volume("/config", |m| m.bind("/host/config").readonly())
    /// .volume("/cache", |m| m.named("my-cache"))
    /// .volume("/tmp", |m| m.tmpfs().size(100))
    /// .volume("/watched", |m| m.bind("/host/data").on_read(|_path, data| data.to_vec()))
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
    fn test_builder_force_sets_replace_existing() {
        let config = SandboxBuilder::new("test")
            .image("alpine:3.23")
            .force()
            .build()
            .unwrap();

        assert!(config.replace_existing);
    }
}

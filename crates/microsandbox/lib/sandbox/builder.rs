//! Fluent builder for [`SandboxConfig`].

use microsandbox_runtime::policy::ShutdownMode;

use super::config::SandboxConfig;
use super::types::{MountBuilder, RootfsSource};
use crate::MicrosandboxResult;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Builder for constructing a [`SandboxConfig`] with a fluent API.
pub struct SandboxBuilder {
    config: SandboxConfig,
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
        }
    }

    /// Set the root filesystem source.
    pub fn image(mut self, image: impl Into<RootfsSource>) -> Self {
        self.config.image = image.into();
        self
    }

    /// Set the number of virtual CPUs.
    pub fn cpus(mut self, count: u8) -> Self {
        self.config.cpus = count;
        self
    }

    /// Set guest memory in MiB.
    pub fn memory(mut self, mib: u32) -> Self {
        self.config.memory_mib = mib;
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
    /// .volume("/tmp", |m| m.tmpfs().size_mib(100))
    /// ```
    pub fn volume(
        mut self,
        guest_path: impl Into<String>,
        f: impl FnOnce(MountBuilder) -> MountBuilder,
    ) -> Self {
        let mount = f(MountBuilder::new(guest_path)).build();
        self.config.mounts.push(mount);
        self
    }

    /// Build the configuration without creating the sandbox.
    pub fn build(self) -> MicrosandboxResult<SandboxConfig> {
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
    fn validate(&self) -> MicrosandboxResult<()> {
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
        Self { config }
    }
}

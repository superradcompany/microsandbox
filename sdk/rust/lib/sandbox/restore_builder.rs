//! Dedicated snapshot restoration with explicit destination resource choices.

use super::{ExternalMountRestorePolicy, MountBuilder, Sandbox, SandboxBuilder};
use crate::MicrosandboxResult;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Build a detached sandbox from a snapshot, never an image or replacement startup command.
///
/// ```compile_fail
/// use microsandbox::Sandbox;
/// Sandbox::restore("saved").name("child").memory(128);
/// ```
///
/// ```compile_fail
/// use microsandbox::Sandbox;
/// Sandbox::builder("child").from_snapshot("saved");
/// ```
pub struct RestoreBuilder {
    pub(crate) inner: SandboxBuilder,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Prepare to restore an installed snapshot or archive. No work starts until `restore()`.
    pub fn restore(snapshot: impl Into<String>) -> RestoreBuilder {
        RestoreBuilder::new(snapshot)
    }
}

impl RestoreBuilder {
    fn new(snapshot: impl Into<String>) -> Self {
        let mut inner = SandboxBuilder::new("").with_snapshot_source(snapshot);
        // Global creation defaults must not silently authorize host access or override the
        // captured exec user. Destination bindings come only from this operation's builder.
        inner.config.spec.mounts.clear();
        inner.config.spec.network.ports.clear();
        inner.config.spec.vsock = Default::default();
        inner.config.spec.runtime.user = None;
        Self { inner }
    }

    /// Set the unique destination sandbox name.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.inner.config.spec.name = name.into();
        self
    }

    /// Set host runtime logging for the restored sandbox.
    pub fn log_level(mut self, level: crate::LogLevel) -> Self {
        self.inner = self.inner.log_level(level);
        self
    }

    /// Restore captured RAM with private copy-on-write mappings.
    pub fn forked(mut self) -> Self {
        self.inner = self.inner.forked();
        self
    }

    /// Cold-boot the captured disk instead of resuming captured execution.
    pub fn disk_only(mut self) -> Self {
        self.inner = self.inner.disk_only();
        self
    }

    /// Supply the exact base for a dependent snapshot archive.
    pub fn snapshot_base(mut self, base: impl Into<String>) -> Self {
        self.inner = self.inner.snapshot_base(base);
        self
    }

    /// Restore and return the detached sandbox when it is ready.
    pub async fn restore(self) -> MicrosandboxResult<Sandbox> {
        self.inner.create_detached().await
    }

    /// Restore with the shared image/preparation/activation progress stream.
    #[cfg(feature = "local")]
    pub fn restore_with_progress(
        self,
    ) -> MicrosandboxResult<(
        crate::CreationProgressHandle,
        tokio::task::JoinHandle<MicrosandboxResult<Sandbox>>,
    )> {
        self.inner.create_detached_with_progress()
    }
}

//--------------------------------------------------------------------------------------------------
// Macros
//--------------------------------------------------------------------------------------------------

// Both operations deliberately expose the same resource vocabulary, without exposing image,
// geometry, replacement, init or startup-command setters from the ordinary create builder.
macro_rules! resource_methods {
    ($builder:ty) => {
        impl $builder {
            /// Override the default user for new execs, not credentials of captured processes.
            pub fn user(mut self, user: impl Into<String>) -> Self {
                self.inner = self.inner.user(user);
                self
            }

            /// Select a destination binding or private captured disk at a captured guest path.
            pub fn volume(
                mut self,
                guest: impl Into<String>,
                configure: impl FnOnce(MountBuilder) -> MountBuilder,
            ) -> Self {
                match configure(MountBuilder::new(guest)).build_restore() {
                    Ok(Ok(mount)) => {
                        let guest = mount.guest();
                        self.inner.config.restore_resources.captured.remove(guest);
                        self.inner
                            .config
                            .restore_resources
                            .mapped
                            .insert(guest.into());
                        self.inner
                            .config
                            .spec
                            .mounts
                            .retain(|existing| existing.guest() != guest);
                        self.inner.config.spec.mounts.push(mount);
                    }
                    Ok(Err(guest)) => {
                        self.inner.config.restore_resources.mapped.remove(&guest);
                        self.inner
                            .config
                            .spec
                            .mounts
                            .retain(|existing| existing.guest() != guest);
                        self.inner.config.restore_resources.captured.insert(guest);
                    }
                    Err(error) => {
                        self.inner.build_error = Some(error);
                    }
                }
                self
            }

            /// Bind a host stream socket or local named pipe to a guest-to-host vsock port.
            pub fn vsock(mut self, path: impl AsRef<std::path::Path>, port: u32) -> Self {
                self.inner = self.inner.vsock(path, port);
                self
            }

            /// Bind a host datagram endpoint to a guest-to-host vsock port.
            pub fn vsock_dgram(mut self, path: impl AsRef<std::path::Path>, port: u32) -> Self {
                self.inner = self.inner.vsock_dgram(path, port);
                self
            }

            /// Fill unspecified resources from validated local source records. Explicit choices win.
            pub fn dangerously_inherit_resources(mut self) -> Self {
                self.inner.config.restore_resources.inherit = true;
                self
            }

            /// Choose strict or relaxed compatibility validation for authorized filesystem mappings.
            /// Unmapped filesystems remain unavailable in either mode; this does not inherit resources.
            pub fn external_mount_policy(mut self, policy: ExternalMountRestorePolicy) -> Self {
                self.inner = self.inner.external_mount_policy(policy);
                self
            }

            /// Publish a new TCP listener owned by this child, not the source's listener.
            #[cfg(feature = "net")]
            pub fn port(mut self, host: u16, guest: u16) -> Self {
                self.inner = self.inner.port(host, guest);
                self
            }

            /// Publish a TCP listener on an explicit destination address.
            #[cfg(feature = "net")]
            pub fn port_bind(mut self, bind: std::net::IpAddr, host: u16, guest: u16) -> Self {
                self.inner = self.inner.port_bind(bind, host, guest);
                self
            }

            /// Publish a new UDP listener owned by this child.
            #[cfg(feature = "net")]
            pub fn port_udp(mut self, host: u16, guest: u16) -> Self {
                self.inner = self.inner.port_udp(host, guest);
                self
            }

            /// Publish a UDP listener on an explicit destination address.
            #[cfg(feature = "net")]
            pub fn port_udp_bind(mut self, bind: std::net::IpAddr, host: u16, guest: u16) -> Self {
                self.inner = self.inner.port_udp_bind(bind, host, guest);
                self
            }
        }
    };
}

resource_methods!(RestoreBuilder);
resource_methods!(super::branch::BranchBuilder);
resource_methods!(super::branch::BranchManyBuilder);

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_starts_without_host_bindings() {
        let restore = Sandbox::restore("saved").name("child");
        assert!(restore.inner.config.spec.mounts.is_empty());
        assert!(restore.inner.config.spec.network.ports.is_empty());
        assert!(!restore.inner.config.restore_resources.inherit);
        assert!(restore.inner.config.spec.runtime.user.is_none());
    }

    #[test]
    fn restore_tracks_authorized_and_captured_volumes() {
        let restore = Sandbox::restore("saved")
            .name("child")
            .volume("/data", |v| v.bind("/tmp/explicit-restore-binding"))
            .volume("/private", |v| v.captured());
        assert!(
            restore
                .inner
                .config
                .restore_resources
                .mapped
                .contains("/data")
        );
        assert!(
            restore
                .inner
                .config
                .restore_resources
                .captured
                .contains("/private")
        );
        let restore = restore.volume("/data", |v| v.captured());
        assert!(
            !restore
                .inner
                .config
                .restore_resources
                .mapped
                .contains("/data")
        );
        assert!(restore.inner.config.spec.mounts.is_empty());
    }
}

//! Dedicated snapshot restoration with explicit destination resource choices.

#[cfg(feature = "net")]
use microsandbox_network::policy::NetworkPolicy;

use super::config::SnapshotRestoreMode;
use super::{ExternalMountRestorePolicy, MountBuilder, Sandbox, SandboxBuilder, SecurityProfile};
use crate::size::Mebibytes;
use crate::snapshot::SnapshotReference;
use crate::{MicrosandboxError, MicrosandboxResult, Operation, UnsupportedReason};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Build a detached sandbox from a snapshot, never an image or replacement startup command.
///
/// ```compile_fail
/// use microsandbox::Sandbox;
/// Sandbox::restore("saved").name("child").image("alpine");
/// ```
///
/// ```compile_fail
/// use microsandbox::Sandbox;
/// Sandbox::builder("child").from_snapshot("saved");
/// ```
pub struct RestoreBuilder {
    pub(crate) inner: SandboxBuilder,
}

/// Explicit boot-policy requests must survive deferred source resolution, even when their
/// values equal defaults. Captured execution cannot acquire a different guest security setup.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RestoreBootOverrides {
    pub(crate) security: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RestoreBootOverrides {
    /// Reject unsupported changes while the source is still metadata, before child publication.
    pub(crate) fn validate_scope(
        self,
        scope: crate::snapshot::SnapshotScope,
        mode: SnapshotRestoreMode,
    ) -> MicrosandboxResult<()> {
        if scope != crate::snapshot::SnapshotScope::Full || mode == SnapshotRestoreMode::DiskOnly {
            return Ok(());
        }
        if self.security {
            return Err(MicrosandboxError::unsupported(
                Operation::SnapshotOps,
                UnsupportedReason::NotAvailable(
                    "security profile overrides require a disk snapshot or disk-only restore (disk_only() / --disk-only); full restore resumes the captured guest security profile".into(),
                ),
            ));
        }
        Ok(())
    }
}

impl Sandbox {
    /// Prepare to restore an installed snapshot or archive. No work starts until `restore()`.
    pub fn restore(snapshot: impl Into<String>) -> RestoreBuilder {
        Self::restore_ref(SnapshotReference::auto(snapshot))
    }

    /// Restore an explicit snapshot identifier or backend-scoped artifact path.
    ///
    /// References from `Snapshot::reference()` retain their identifier/path interpretation.
    /// The selected backend resolves the reference; unsupported restore options fail before launch.
    pub fn restore_ref(reference: impl Into<SnapshotReference>) -> RestoreBuilder {
        RestoreBuilder::new(reference.into())
    }
}

impl RestoreBuilder {
    fn new(reference: SnapshotReference) -> Self {
        let mut inner = SandboxBuilder::new("").with_snapshot_reference(reference);
        // Global creation defaults must not silently authorize host access or override the
        // captured exec user. Destination bindings come only from this operation's builder.
        inner.config.spec.mounts = Some(Vec::new());
        inner.config.spec.network.ports = Some(Vec::new());
        inner.config.spec.vsock = Default::default();
        inner.config.spec.runtime.user = None;
        inner
            .config
            .restore_resources
            .get_or_insert_with(Default::default)
            .require_complete = true;
        Self { inner }
    }

    /// Resume even when captured external resources have no destination backing.
    /// Does not inherit host resources or relax validation of supplied objects.
    pub fn allow_missing_resources(mut self) -> Self {
        let resources = self
            .inner
            .config
            .restore_resources
            .get_or_insert_with(Default::default);
        resources.require_complete = false;
        resources.allow_missing = true;
        self
    }

    /// Set the unique destination sandbox name.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.inner.config.spec.name = Some(name.into());
        self
    }

    /// Set guest CPUs for disk boot. Full restore accepts only the captured CPU count.
    pub fn cpus(mut self, count: u8) -> Self {
        self.inner = self.inner.cpus(count);
        self
    }

    /// Set guest memory for disk boot. Full restore accepts only the captured memory size.
    pub fn memory(mut self, size: impl Into<Mebibytes>) -> Self {
        self.inner = self.inner.memory(size);
        self
    }

    /// Set the destination host's network policy before disk boot or captured execution resumes.
    /// This changes traffic admission, not the captured guest interface or TLS trust setup.
    #[cfg(feature = "net")]
    pub fn network_policy(mut self, policy: NetworkPolicy) -> Self {
        self.inner = self.inner.network(|network| network.policy(policy));
        self
    }

    /// Set the destination host's concurrent TCP connection limit; zero explicitly means unlimited.
    /// The limit is applied before disk boot or full-restore network activation.
    #[cfg(feature = "net")]
    pub fn max_tcp_connections(mut self, limit: usize) -> Self {
        self.inner = self
            .inner
            .network(|network| network.max_tcp_connections(limit));
        self
    }

    /// Set the destination host's concurrent UDP session limit; zero explicitly means unlimited.
    /// The limit is applied before disk boot or full-restore network activation.
    #[cfg(feature = "net")]
    pub fn max_udp_connections(mut self, limit: usize) -> Self {
        self.inner = self
            .inner
            .network(|network| network.max_udp_connections(limit));
        self
    }

    /// Deprecated alias for [`Self::max_tcp_connections`].
    #[cfg(feature = "net")]
    #[deprecated(note = "use max_tcp_connections instead")]
    pub fn max_connections(self, limit: usize) -> Self {
        self.max_tcp_connections(limit)
    }

    /// Disable the network device for disk boot. Full restore rejects removal of a captured device.
    #[cfg(feature = "net")]
    pub fn disable_network(mut self) -> Self {
        self.inner = self.inner.disable_network();
        self
    }

    /// Apply the guest security profile at disk boot, before any new workload can execute.
    /// Captured processes cannot be retroactively confined, so full restore rejects this setter.
    pub fn security(mut self, profile: SecurityProfile) -> Self {
        self.inner = self.inner.security(profile);
        self.inner
            .config
            .restore_boot_overrides
            .get_or_insert_with(Default::default)
            .security = true;
        self
    }

    /// Set the destination sandbox's maximum lifetime in seconds, including full restore.
    /// This is runtime-owned enforcement, not a timeout on the restore call.
    pub fn max_duration(mut self, secs: u64) -> Self {
        self.inner = self.inner.max_duration(secs);
        self
    }

    /// Auto-stop the destination sandbox after this many seconds of inactivity, including full restore.
    pub fn idle_timeout(mut self, secs: u64) -> Self {
        self.inner = self.inner.idle_timeout(secs);
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

// Share resource bindings without exposing image, replacement, init or startup-command setters.
// Destination boot controls belong only to RestoreBuilder, not the live branch builders.
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
                let resources = self
                    .inner
                    .config
                    .restore_resources
                    .get_or_insert_with(Default::default);
                let mounts = self.inner.config.spec.mounts.get_or_insert_with(Vec::new);
                match configure(MountBuilder::new(guest)).build_restore() {
                    Ok(Ok(mount)) => {
                        let guest = mount.guest();
                        resources.captured.remove(guest);
                        resources.mapped.insert(guest.into());
                        mounts.retain(|existing| existing.guest() != guest);
                        mounts.push(mount);
                    }
                    Ok(Err(guest)) => {
                        resources.mapped.remove(&guest);
                        mounts.retain(|existing| existing.guest() != guest);
                        resources.captured.insert(guest);
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
                self.inner
                    .config
                    .restore_resources
                    .get_or_insert_with(Default::default)
                    .inherit = true;
                self
            }

            /// Choose strict or relaxed compatibility validation for authorized filesystem mappings.
            /// This does not authorize inheritance or waive restore's required-resource checks.
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

    fn config(builder: &RestoreBuilder) -> crate::SandboxConfig {
        builder.inner.config.clone().into_config()
    }

    #[test]
    fn restore_requires_resources_independently_of_inheritance_and_object_policy() {
        let restore = Sandbox::restore("saved")
            .name("child")
            .dangerously_inherit_resources()
            .external_mount_policy(ExternalMountRestorePolicy::Relaxed);
        assert!(config(&restore).restore_resources.require_complete);
        assert!(!config(&restore).restore_resources.allow_missing);
        let restore = restore.allow_missing_resources();
        assert!(!config(&restore).restore_resources.require_complete);
        assert!(config(&restore).restore_resources.allow_missing);
        assert!(config(&restore).restore_resources.inherit);
        assert_eq!(
            config(&restore).external_mount_policy,
            ExternalMountRestorePolicy::Relaxed
        );
    }

    #[test]
    fn only_explicit_guest_security_changes_are_refused_for_full_execution() {
        use crate::snapshot::SnapshotScope;

        for security in [false, true] {
            let overrides = RestoreBootOverrides { security };
            assert!(
                overrides
                    .validate_scope(SnapshotScope::Disk, SnapshotRestoreMode::Full)
                    .is_ok()
            );
            assert!(
                overrides
                    .validate_scope(SnapshotScope::Full, SnapshotRestoreMode::DiskOnly)
                    .is_ok()
            );
            assert_eq!(
                overrides
                    .validate_scope(SnapshotScope::Full, SnapshotRestoreMode::Full)
                    .is_err(),
                security
            );
        }
    }

    #[test]
    fn security_setter_keeps_explicit_intent_even_for_default_profile() {
        for profile in [SecurityProfile::Default, SecurityProfile::Restricted] {
            let restore = Sandbox::restore("saved").name("child").security(profile);
            assert!(config(&restore).restore_boot_overrides.security);
            assert_eq!(config(&restore).spec.security_profile, profile);
        }
    }

    #[test]
    fn destination_geometry_and_lifecycle_are_not_lost() {
        let restore = Sandbox::restore("saved")
            .name("child")
            .cpus(2)
            .memory(2048)
            .max_duration(600)
            .idle_timeout(120);
        assert_eq!(config(&restore).spec.resources.cpus, 2);
        assert_eq!(config(&restore).spec.resources.memory_mib, 2048);
        assert_eq!(config(&restore).spec.lifecycle.max_duration_secs, Some(600));
        assert_eq!(config(&restore).spec.lifecycle.idle_timeout_secs, Some(120));
        assert!(!config(&restore).restore_boot_overrides.security);
    }

    #[cfg(feature = "net")]
    #[test]
    fn destination_network_controls_apply_without_changing_guest_identity() {
        let restore = Sandbox::restore("saved")
            .name("child")
            .network_policy(NetworkPolicy::none())
            .max_tcp_connections(8)
            .max_udp_connections(4);
        let network = config(&restore).local_network_config().unwrap();
        assert!(network.enabled);
        assert_eq!(
            serde_json::to_value(network.policy).unwrap(),
            serde_json::to_value(NetworkPolicy::none()).unwrap()
        );
        assert_eq!(network.max_tcp_connections, Some(8.into()));
        assert_eq!(network.max_udp_connections, Some(4.into()));
        assert!(network.interface.mac.is_none());
        assert!(!config(&restore).restore_boot_overrides.security);
        let unlimited = Sandbox::restore("saved")
            .name("child")
            .max_tcp_connections(0)
            .max_udp_connections(0);
        assert_eq!(config(&unlimited).spec.network.max_tcp_connections, Some(0));
        assert_eq!(config(&unlimited).spec.network.max_udp_connections, Some(0));
        assert_eq!(
            config(&unlimited)
                .local_network_config()
                .unwrap()
                .max_tcp_connections,
            Some(microsandbox_network::config::ConnectionLimit::Unlimited)
        );
        assert_eq!(
            config(&unlimited)
                .local_network_config()
                .unwrap()
                .max_udp_connections,
            Some(microsandbox_network::config::ConnectionLimit::Unlimited)
        );
        let disabled = Sandbox::restore("saved").name("child").disable_network();
        assert!(!config(&disabled).spec.network.enabled);
    }

    #[cfg(feature = "net")]
    #[test]
    #[allow(deprecated)]
    fn destination_connection_limits_preserve_omission_and_tcp_alias() {
        let defaults = Sandbox::restore("saved");
        assert_eq!(config(&defaults).spec.network.max_tcp_connections, None);
        assert_eq!(config(&defaults).spec.network.max_udp_connections, None);
        let legacy = Sandbox::restore("saved").max_connections(0);
        assert_eq!(config(&legacy).spec.network.max_tcp_connections, Some(0));
        assert_eq!(config(&legacy).spec.network.max_udp_connections, None);
    }

    #[test]
    fn restore_starts_without_host_bindings() {
        let restore = Sandbox::restore("saved").name("child");
        assert!(config(&restore).spec.mounts.is_empty());
        assert!(config(&restore).spec.network.ports.is_empty());
        assert!(!config(&restore).restore_resources.inherit);
        assert!(config(&restore).spec.runtime.user.is_none());
    }

    #[test]
    fn restore_tracks_authorized_and_captured_volumes() {
        let restore = Sandbox::restore("saved")
            .name("child")
            .volume("/data", |v| v.bind("/tmp/explicit-restore-binding"))
            .volume("/private", |v| v.captured());
        assert!(config(&restore).restore_resources.mapped.contains("/data"));
        assert!(
            config(&restore)
                .restore_resources
                .captured
                .contains("/private")
        );
        let restore = restore.volume("/data", |v| v.captured());
        assert!(!config(&restore).restore_resources.mapped.contains("/data"));
        assert!(config(&restore).spec.mounts.is_empty());
    }
}

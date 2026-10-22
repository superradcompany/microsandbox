//! Dedicated snapshot restoration with explicit destination resource choices.

#[cfg(feature = "net")]
use microsandbox_network::policy::NetworkPolicy;
#[cfg(feature = "net")]
use microsandbox_network::{OutboundProxyBuilder, OutboundProxyConfig};

use super::config::SnapshotRestoreMode;
use super::{
    ExternalMountRestorePolicy, InitOptionsBuilder, MountBuilder, PullPolicy, Sandbox,
    SandboxBuilder, SecurityProfile,
};
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
    pub(crate) init: bool,
    pub(crate) hostname: bool,
    pub(crate) thp: bool,
    pub(crate) new_command: bool,
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
        for (requested, label) in [
            (self.new_command, "starting a new command"),
            (self.init, "init replacement"),
            (self.hostname, "hostname replacement"),
            (self.thp, "guest THP policy replacement"),
        ] {
            if requested {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "{label} requires a disk snapshot or disk-only mode; full restore resumes captured execution"
                )));
            }
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

    /// Default guest working directory for new commands, including after full resume.
    pub fn workdir(mut self, path: impl Into<String>) -> Self {
        self.inner = self.inner.workdir(path);
        self
    }

    /// Default shell for new commands; this does not execute it during restoration.
    pub fn shell(mut self, shell: impl Into<String>) -> Self {
        self.inner = self.inner.shell(shell);
        self
    }

    /// Set the entrypoint for future default-workload execution; captured processes are unchanged.
    pub fn entrypoint(mut self, argv: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.inner = self.inner.entrypoint(argv);
        self
    }

    /// Set CMD for future default-workload execution. An empty list explicitly clears CMD.
    /// This never selects a startup command or executes during restoration.
    pub fn cmd(mut self, argv: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.inner = self.inner.cmd(argv);
        self
    }

    /// Add a destination environment default for new commands, not captured processes.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.inner = self.inner.env(key, value);
        self
    }

    /// Add destination environment defaults using the existing SDK append/override semantics.
    pub fn envs(
        mut self,
        env: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        self.inner = self.inner.envs(env);
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

    /// Set the CPU ceiling for disk boot. Full resume requires the captured ceiling.
    pub fn max_cpus(mut self, count: u8) -> Self {
        self.inner = self.inner.max_cpus(count);
        self
    }

    /// Set the memory ceiling for disk boot. Full resume requires the captured ceiling.
    pub fn max_memory(mut self, size: impl Into<Mebibytes>) -> Self {
        self.inner = self.inner.max_memory(size);
        self
    }

    /// Attach a label to the destination sandbox without changing snapshot labels.
    pub fn label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.inner = self.inner.label(key, value);
        self
    }

    /// Attach destination labels, replacing earlier values for the same keys.
    pub fn labels(
        mut self,
        labels: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        self.inner = self.inner.labels(labels);
        self
    }

    /// Select the guest PID 1 for a disk snapshot or disk-only boot.
    /// Full-memory resume rejects this request, including an explicit `auto`.
    pub fn init(self, cmd: impl Into<String>) -> Self {
        self.init_with(cmd, |init| init)
    }

    /// Select guest PID 1 with explicit arguments and environment for a disk boot.
    /// This replaces any earlier init choice. It never changes captured processes on full resume.
    pub fn init_with(
        mut self,
        cmd: impl Into<String>,
        configure: impl FnOnce(InitOptionsBuilder) -> InitOptionsBuilder,
    ) -> Self {
        self.inner = self.inner.init_with(cmd, configure);
        // Preserve intent before deferred metadata resolution, even for default-looking values.
        self.inner
            .config
            .restore_boot_overrides
            .get_or_insert_with(Default::default)
            .init = true;
        self
    }

    /// Set the guest hostname for disk boot; full-memory resume rejects replacement.
    /// The name must be nonempty and fit within Linux's 64-byte hostname limit.
    pub fn hostname(mut self, hostname: impl Into<String>) -> Self {
        self.inner = self.inner.hostname(hostname);
        self.inner
            .config
            .restore_boot_overrides
            .get_or_insert_with(Default::default)
            .hostname = true;
        self
    }

    /// Set the destination host's network policy before disk boot or captured execution resumes.
    /// This changes traffic admission, not the captured guest interface or TLS trust setup.
    #[cfg(feature = "net")]
    pub fn network_policy(mut self, policy: NetworkPolicy) -> Self {
        self.inner = self.inner.network(|network| network.policy(policy));
        self
    }

    /// Control retrieval of the snapshot's digest-pinned base image.
    /// This never selects a different image or updates the saved snapshot.
    pub fn pull_policy(mut self, policy: PullPolicy) -> Self {
        self.inner = self.inner.pull_policy(policy);
        self
    }

    /// Select the destination proxy before disk boot or full-memory resume.
    /// This does not replace the captured guest interface or inject guest trust material.
    /// Proxy credentials use the existing destination secret-source resolution.
    #[cfg(feature = "net")]
    pub fn proxy<P>(mut self, configure: impl FnOnce(OutboundProxyBuilder) -> P) -> Self
    where
        P: OutboundProxyConfig,
    {
        self.inner = self.inner.proxy(configure);
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

    /// Select how the host manages the restored guest's wall clock, including full restore.
    /// Without this call the restore keeps the policy recorded in the snapshot.
    pub fn guest_clock(mut self, policy: super::GuestClockPolicy) -> Self {
        self.inner = self.inner.guest_clock(policy);
        self
    }

    /// Set host runtime logging for the restored sandbox.
    pub fn log_level(mut self, level: crate::LogLevel) -> Self {
        self.inner = self.inner.log_level(level);
        self
    }

    /// Restore captured RAM with private copy-on-write mappings.
    pub fn cow_memory(mut self) -> Self {
        self.inner = self.inner.forked();
        self
    }

    /// Deprecated spelling for copy-on-write memory during full-snapshot restore.
    #[deprecated(note = "use cow_memory instead")]
    pub fn forked(self) -> Self {
        self.cow_memory()
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
                self.inner = self.inner.snapshot_volume(guest, configure);
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

            /// Set inbound tcp connection limits for this child's published ports.
            #[cfg(feature = "net")]
            pub fn max_inbound_tcp_connections(mut self, value: usize) -> Self {
                self.inner = self
                    .inner
                    .network(|network| network.max_inbound_tcp_connections(value));
                self
            }

            /// Set the accept-queue depth of this child's published TCP listeners, `1..=i32::MAX`.
            /// Defaults to 1024; the host kernel clamps it to its own `somaxconn`.
            #[cfg(feature = "net")]
            pub fn tcp_accept_queue_size(mut self, size: u32) -> Self {
                self.inner = self
                    .inner
                    .network(|network| network.tcp_accept_queue_size(size));
                self
            }
        }
    };
}

resource_methods!(RestoreBuilder);
resource_methods!(super::branch::ForkBuilder);
resource_methods!(super::branch::ForkManyBuilder);

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
    fn snapshot_pull_policy_preserves_source_and_full_resume_admission() {
        for policy in [PullPolicy::Always, PullPolicy::IfMissing, PullPolicy::Never] {
            let builder = Sandbox::restore("saved").pull_policy(policy);
            let config = config(&builder);
            assert_eq!(config.spec.pull_policy, policy);
            assert!(builder.inner.build_error.is_none());
            config
                .restore_boot_overrides
                .validate_scope(
                    crate::snapshot::SnapshotScope::Full,
                    SnapshotRestoreMode::Full,
                )
                .unwrap();
        }
    }

    #[cfg(all(feature = "local", feature = "net"))]
    #[test]
    fn destination_proxy_preserves_guest_identity_and_policy() {
        let builder = Sandbox::restore("saved")
            .network_policy(NetworkPolicy::none())
            .proxy(|proxy| {
                proxy.socks5("127.0.0.1:1080").credentials(
                    "destination",
                    crate::sandbox::SecretSource::env("DEST_PROXY_PASSWORD"),
                )
            });
        let config = config(&builder);
        let network = config.local_network_config().unwrap();
        let proxy = serde_json::to_value(network.outbound_proxy.unwrap()).unwrap();
        assert!(proxy.to_string().contains("DEST_PROXY_PASSWORD"));
        assert!(network.interface.mac.is_none());
        assert_eq!(
            serde_json::to_value(network.policy).unwrap(),
            serde_json::to_value(NetworkPolicy::none()).unwrap()
        );
        // A destination host proxy does not ask to replay boot configuration or commands.
        config
            .restore_boot_overrides
            .validate_scope(
                crate::snapshot::SnapshotScope::Full,
                SnapshotRestoreMode::Full,
            )
            .unwrap();
        assert!(builder.inner.build_error.is_none());
    }

    #[test]
    fn destination_labels_do_not_override_guest_boot() {
        let builder = Sandbox::restore("saved")
            .label("team", "before")
            .labels([("team", "after"), ("purpose", "snapshot-child")]);
        let config = config(&builder);
        assert_eq!(config.spec.labels["team"], "after");
        assert_eq!(config.spec.labels["purpose"], "snapshot-child");
        config
            .restore_boot_overrides
            .validate_scope(
                crate::snapshot::SnapshotScope::Full,
                SnapshotRestoreMode::Full,
            )
            .unwrap();
        // Labels use the regular sandbox validation, including reserved keys.
        assert!(
            Sandbox::restore("saved")
                .name("child")
                .label("microsandbox.reserved", "x")
                .inner
                .image("alpine")
                .finish(None, None)
                .is_err()
        );
    }

    #[test]
    fn command_defaults_do_not_request_startup_or_change_captured_execution() {
        let builder = Sandbox::restore("saved")
            .workdir("/root")
            .shell("/bin/ash")
            .entrypoint(["/bin/sh", "-c"])
            .cmd(["printf requested"])
            .env("KEY", "first")
            .envs([("KEY", "last"), ("EMPTY", "")]);
        let config = config(&builder);
        assert_eq!(config.spec.runtime.workdir.as_deref(), Some("/root"));
        assert_eq!(config.spec.runtime.shell.as_deref(), Some("/bin/ash"));
        assert_eq!(
            config.spec.runtime.entrypoint,
            Some(vec!["/bin/sh".into(), "-c".into()])
        );
        assert_eq!(
            config.spec.runtime.cmd,
            Some(vec!["printf requested".into()])
        );
        assert!(!config.should_launch_background_command());
        config
            .restore_boot_overrides
            .validate_scope(
                crate::snapshot::SnapshotScope::Full,
                SnapshotRestoreMode::Full,
            )
            .unwrap();
        assert_eq!(
            config
                .spec
                .env
                .iter()
                .map(|value| (value.key.as_str(), value.value.as_str()))
                .collect::<Vec<_>>(),
            vec![("KEY", "first"), ("KEY", "last"), ("EMPTY", "")]
        );
        let cleared = builder
            .entrypoint(Vec::<String>::new())
            .cmd(Vec::<String>::new());
        let cleared = self::config(&cleared);
        assert_eq!(cleared.spec.runtime.entrypoint, Some(vec![]));
        assert_eq!(cleared.spec.runtime.cmd, Some(vec![]));
    }

    #[test]
    fn resource_ceilings_preserve_explicit_intent_and_validate_zero() {
        let ordinary = Sandbox::restore("saved").name("child");
        assert!(ordinary.inner.config.spec.resources.max_cpus.is_none());
        assert!(
            ordinary
                .inner
                .config
                .spec
                .resources
                .max_memory_mib
                .is_none()
        );
        let explicit = ordinary.cpus(1).memory(128).max_cpus(4).max_memory(512);
        // Inspection keeps caller options sparse until captured-geometry validation.
        assert_eq!(explicit.inner.config.spec.resources.max_cpus, Some(4));
        assert_eq!(
            explicit.inner.config.spec.resources.max_memory_mib,
            Some(512)
        );
        let resolved = explicit
            .inner
            // Source preparation normally supplies the captured image before finish.
            .image("alpine")
            .finish(None, None)
            .unwrap();
        assert_eq!(resolved.spec.resources.max_cpus, 4);
        assert_eq!(resolved.spec.resources.max_memory_mib, 512);
        for builder in [
            Sandbox::restore("saved").name("child").max_cpus(0),
            Sandbox::restore("saved").name("child").max_memory(0),
        ] {
            assert!(
                builder
                    .inner
                    .image("alpine")
                    .finish(None, None)
                    .unwrap_err()
                    .to_string()
                    .contains("must be greater than 0")
            );
        }
    }

    #[test]
    fn explicit_boot_controls_reject_full_resume_even_when_defaults_are_requested() {
        use crate::snapshot::SnapshotScope;

        for builder in [
            Sandbox::restore("saved").init("auto"),
            Sandbox::restore("saved").init_with("/sbin/init", |init| init.arg("--flag")),
            Sandbox::restore("saved").hostname("child"),
        ] {
            let intent = config(&builder).restore_boot_overrides;
            assert!(
                intent
                    .validate_scope(SnapshotScope::Full, SnapshotRestoreMode::Full)
                    .is_err()
            );
            assert!(
                intent
                    .validate_scope(SnapshotScope::Full, SnapshotRestoreMode::DiskOnly)
                    .is_ok()
            );
            assert!(
                intent
                    .validate_scope(SnapshotScope::Disk, SnapshotRestoreMode::Full)
                    .is_ok()
            );
        }
        let ordinary = config(&Sandbox::restore("saved"));
        assert!(
            ordinary
                .restore_boot_overrides
                .validate_scope(SnapshotScope::Full, SnapshotRestoreMode::Full)
                .is_ok()
        );
    }

    #[test]
    fn cow_memory_preserves_the_existing_transient_launch_flag() {
        let ordinary = Sandbox::restore("saved").name("child");
        assert!(!config(&ordinary).forked);
        let cow = ordinary.cow_memory();
        assert!(config(&cow).forked);
        assert!(!config(&cow).clone_for_persistence().forked);
        #[allow(deprecated)]
        let legacy = Sandbox::restore("saved").name("child").forked();
        assert_eq!(config(&legacy).forked, config(&cow).forked);
        assert!(!config(&legacy).clone_for_persistence().forked);
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
            let overrides = RestoreBootOverrides {
                security,
                ..Default::default()
            };
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

    #[cfg(feature = "net")]
    #[test]
    fn destination_accept_queue_size_is_omitted_unless_set_and_validated() {
        let defaults = Sandbox::restore("saved").port(8080, 80);
        assert_eq!(config(&defaults).spec.network.tcp_accept_queue_size, None);
        let tuned = Sandbox::restore("saved")
            .port(8080, 80)
            .tcp_accept_queue_size(4096);
        assert_eq!(
            config(&tuned).spec.network.tcp_accept_queue_size,
            Some(4096)
        );
        assert_eq!(
            config(&tuned)
                .local_network_config()
                .unwrap()
                .tcp_accept_queue_size
                .map(microsandbox_network::config::TcpAcceptQueueSize::get),
            Some(4096)
        );
        let invalid = Sandbox::restore("saved").tcp_accept_queue_size(0);
        assert!(invalid.inner.build_error.is_some());
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

    #[test]
    fn restore_disk_volume_adds_one_disk_image_mount() {
        let restore = Sandbox::restore("saved").volume("/data2", |v| {
            v.disk("/images/seed.img").fstype("ext4").readonly()
        });
        let mounts = &config(&restore).spec.mounts;
        assert_eq!(mounts.len(), 1);
        match &mounts[0] {
            crate::sandbox::VolumeMount::DiskImage {
                host,
                guest,
                fstype,
                options,
                ..
            } => {
                assert_eq!(host, std::path::Path::new("/images/seed.img"));
                assert_eq!(guest, "/data2");
                assert_eq!(fstype.as_deref(), Some("ext4"));
                assert!(options.readonly);
            }
            other => panic!("expected DiskImage, got {other:?}"),
        }
        assert!(config(&restore).restore_resources.mapped.contains("/data2"));
    }
}

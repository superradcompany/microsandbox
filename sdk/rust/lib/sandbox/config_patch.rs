//! Sparse construction-time configuration patches for sandbox builders.

use std::collections::BTreeMap;
use std::path::PathBuf;

use microsandbox_image::RegistryAuth;
#[cfg(feature = "net")]
use microsandbox_network::dns::Nameserver;
#[cfg(feature = "net")]
use microsandbox_network::policy::{Action, NetworkPolicy, Rule};
#[cfg(feature = "net")]
use microsandbox_types::{HostPattern, SecretInjection, SecretSource};
use microsandbox_types::{PullPolicy, Rlimit, SecurityProfile};
#[cfg(feature = "net")]
use zeroize::Zeroizing;

use super::{Patch, SandboxBuilder, VolumeMount};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A sparse, typed patch applied while constructing one sandbox.
///
/// Patches contain no file-loading or interpolation behavior. Callers may build them directly or
/// translate another representation, such as a CLI configuration file, into these SDK types.
#[derive(Clone, Default)]
pub struct SandboxConfigPatch {
    image: Option<SandboxImagePatch>,
    pull_policy: Option<PullPolicy>,
    registry_auth: Option<RegistryAuth>,
    resources: ResourceConfigPatch,
    runtime: RuntimeConfigPatch,
    filesystem: FilesystemConfigPatch,
    scripts: ScriptConfigPatch,
    #[cfg(feature = "net")]
    network: NetworkConfigPatch,
    #[cfg(feature = "net")]
    secrets: SecretConfigPatch,
}

/// A root filesystem selection carried by a [`SandboxConfigPatch`].
#[derive(Debug, Clone)]
pub enum SandboxImagePatch {
    /// A normal image spelling accepted by [`SandboxBuilder::image`].
    Image(String),
    /// An explicit OCI image and optional managed root-disk size in MiB.
    Oci {
        /// OCI image reference.
        reference: String,
        /// Optional managed root-disk size in MiB.
        root_disk_mib: Option<u32>,
    },
    /// A host disk image root filesystem.
    Disk {
        /// Host path to the disk image.
        path: PathBuf,
        /// Optional inner filesystem type.
        fstype: Option<String>,
    },
    /// A host directory root filesystem.
    Bind(PathBuf),
    /// A saved sandbox snapshot.
    Snapshot(String),
}

/// Sparse resource and lifecycle limits.
#[derive(Debug, Clone, Default)]
pub struct ResourceConfigPatch {
    cpus: Option<u8>,
    memory_mib: Option<u32>,
    max_duration_secs: Option<u64>,
    idle_timeout_secs: Option<u64>,
    rlimits: Option<Vec<Rlimit>>,
}

/// Sparse runtime configuration.
#[derive(Debug, Clone, Default)]
pub struct RuntimeConfigPatch {
    workdir: Option<String>,
    shell: Option<String>,
    user: Option<String>,
    hostname: Option<String>,
    security: Option<SecurityProfile>,
    entrypoint: Option<Vec<String>>,
    cmd: Option<Vec<String>>,
    env: Option<BTreeMap<String, String>>,
    labels: Option<BTreeMap<String, String>>,
    init: Option<InitConfigPatch>,
}

/// Sparse guest-init handoff configuration.
#[derive(Debug, Clone, Default)]
pub struct InitConfigPatch {
    cmd: Option<String>,
    args: Option<Vec<String>>,
    env: Option<BTreeMap<String, String>>,
}

/// Sparse filesystem configuration.
#[derive(Debug, Clone, Default)]
pub struct FilesystemConfigPatch {
    mounts: Option<Vec<VolumeMount>>,
    patch_file_operations: Option<Vec<Patch>>,
    patches: Option<Vec<Patch>>,
}

/// Sparse named script configuration.
#[derive(Debug, Clone, Default)]
pub struct ScriptConfigPatch {
    scripts: BTreeMap<String, String>,
}

/// Sparse network configuration.
#[cfg(feature = "net")]
#[derive(Clone, Default)]
pub struct NetworkConfigPatch {
    policy: NetworkPolicyConfigPatch,
    ports: Option<Vec<microsandbox_network::config::PublishedPort>>,
    dns: DnsConfigPatch,
    tls: TlsConfigPatch,
    trust_host_cas: Option<bool>,
    max_connections: Option<usize>,
}

/// Sparse network-policy configuration.
#[cfg(feature = "net")]
#[derive(Debug, Clone, Default)]
pub struct NetworkPolicyConfigPatch {
    base: Option<NetworkPolicy>,
    deny: Option<Vec<Rule>>,
    allow: Option<Vec<Rule>>,
}

/// Sparse DNS configuration.
#[cfg(feature = "net")]
#[derive(Debug, Clone, Default)]
pub struct DnsConfigPatch {
    rebind_protection: Option<bool>,
    nameservers: Option<Vec<Nameserver>>,
    query_timeout_ms: Option<u64>,
}

/// Sparse TLS-interception configuration.
#[cfg(feature = "net")]
#[derive(Debug, Clone, Default)]
pub struct TlsConfigPatch {
    enabled: Option<bool>,
    bypass: Option<Vec<String>>,
    verify_upstream: Option<bool>,
    block_quic: Option<bool>,
}

/// Sparse protected-secret configuration, keyed by guest environment variable name.
#[cfg(feature = "net")]
#[derive(Clone, Default)]
pub struct SecretConfigPatch {
    secrets: BTreeMap<String, SecretEntryConfigPatch>,
}

/// Sparse configuration for one protected secret.
#[cfg(feature = "net")]
#[derive(Clone, Default)]
pub struct SecretEntryConfigPatch {
    material: Option<SecretMaterial>,
    allowed_hosts: Option<Vec<HostPattern>>,
    injection: Option<SecretInjection>,
    require_tls_identity: Option<bool>,
}

#[cfg(feature = "net")]
#[derive(Clone)]
enum SecretMaterial {
    Literal(Zeroizing<String>),
    Source(SecretSource),
}

//--------------------------------------------------------------------------------------------------
// Methods: Root Patch
//--------------------------------------------------------------------------------------------------

impl SandboxConfigPatch {
    /// Create an empty patch.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the image selection in this patch.
    pub fn image(mut self, image: SandboxImagePatch) -> Self {
        self.image = Some(image);
        self
    }

    /// Replace the pull policy in this patch.
    pub fn pull_policy(mut self, policy: PullPolicy) -> Self {
        self.pull_policy = Some(policy);
        self
    }

    /// Replace registry authentication in this patch.
    pub fn registry_auth(mut self, auth: RegistryAuth) -> Self {
        self.registry_auth = Some(auth);
        self
    }

    /// Overlay resource fields into this patch.
    pub fn resources(mut self, patch: ResourceConfigPatch) -> Self {
        self.resources = self.resources.overlay(patch);
        self
    }

    /// Overlay runtime fields into this patch.
    pub fn runtime(mut self, patch: RuntimeConfigPatch) -> Self {
        self.runtime = self.runtime.overlay(patch);
        self
    }

    /// Overlay filesystem fields into this patch.
    pub fn filesystem(mut self, patch: FilesystemConfigPatch) -> Self {
        self.filesystem = self.filesystem.overlay(patch);
        self
    }

    /// Overlay scripts into this patch.
    pub fn scripts(mut self, patch: ScriptConfigPatch) -> Self {
        self.scripts = self.scripts.overlay(patch);
        self
    }

    /// Overlay network fields into this patch.
    #[cfg(feature = "net")]
    pub fn network(mut self, patch: NetworkConfigPatch) -> Self {
        self.network = self.network.overlay(patch);
        self
    }

    /// Overlay protected secrets into this patch.
    #[cfg(feature = "net")]
    pub fn secrets(mut self, patch: SecretConfigPatch) -> Self {
        self.secrets = self.secrets.overlay(patch);
        self
    }

    /// Overlay another root or scoped patch, with the right-hand side taking precedence.
    pub fn overlay<P>(mut self, higher: P) -> Self
    where
        P: Into<SandboxConfigPatch>,
    {
        let higher = higher.into();
        replace(&mut self.image, higher.image);
        replace(&mut self.pull_policy, higher.pull_policy);
        replace(&mut self.registry_auth, higher.registry_auth);
        self.resources = self.resources.overlay(higher.resources);
        self.runtime = self.runtime.overlay(higher.runtime);
        self.filesystem = self.filesystem.overlay(higher.filesystem);
        self.scripts = self.scripts.overlay(higher.scripts);
        #[cfg(feature = "net")]
        {
            self.network = self.network.overlay(higher.network);
            self.secrets = self.secrets.overlay(higher.secrets);
        }
        self
    }

    /// Return the selected image, when this patch supplies one.
    pub fn image_selection(&self) -> Option<&SandboxImagePatch> {
        self.image.as_ref()
    }

    /// Return registry authentication, when this patch supplies it.
    pub fn registry_auth_ref(&self) -> Option<&RegistryAuth> {
        self.registry_auth.as_ref()
    }

    pub(super) fn apply_to(self, mut builder: SandboxBuilder) -> SandboxBuilder {
        if let Some(image) = self.image {
            builder = image.apply(builder);
        }
        if let Some(policy) = self.pull_policy {
            builder = builder.pull_policy(policy);
        }
        if let Some(auth) = self.registry_auth {
            builder = builder.registry(|registry| registry.auth(auth));
        }
        builder = self.resources.apply_to(builder);
        builder = self.runtime.apply_to(builder);
        builder = self.filesystem.apply_to(builder);
        builder = builder.config_scripts(self.scripts.scripts);
        #[cfg(feature = "net")]
        {
            builder = self.network.apply_to(builder);
            builder = self.secrets.apply_to(builder);
        }
        builder
    }
}

impl SandboxBuilder {
    /// Apply a sparse construction patch to this builder.
    ///
    /// Ordinary builder calls chained after `configure` retain last-write-wins precedence.
    pub fn configure(self, patch: SandboxConfigPatch) -> Self {
        patch.apply_to(self)
    }
}

impl SandboxImagePatch {
    /// Human-readable source label suitable for progress output.
    pub fn display(&self) -> String {
        match self {
            Self::Image(value) | Self::Snapshot(value) => value.clone(),
            Self::Oci { reference, .. } => reference.clone(),
            Self::Disk { path, .. } | Self::Bind(path) => path.display().to_string(),
        }
    }

    /// Return an OCI reference suitable for pre-pulling, when applicable.
    pub fn oci_reference(&self) -> Option<&str> {
        match self {
            Self::Image(value) if !microsandbox_utils::looks_like_local_path_text(value) => {
                Some(value)
            }
            Self::Oci { reference, .. } => Some(reference),
            Self::Image(_) | Self::Disk { .. } | Self::Bind(_) | Self::Snapshot(_) => None,
        }
    }

    pub(super) fn apply(self, builder: SandboxBuilder) -> SandboxBuilder {
        match self {
            Self::Image(image) => builder.override_image(image),
            Self::Oci {
                reference,
                root_disk_mib,
            } => match root_disk_mib {
                Some(size) => {
                    builder.override_image_with(|image| image.oci(reference).root_disk(size))
                }
                None => builder.override_image_with(|image| image.oci(reference)),
            },
            Self::Disk { path, fstype } => builder.override_image_with(|mut image| {
                image = image.disk(path);
                if let Some(fstype) = fstype {
                    image = image.fstype(fstype);
                }
                image
            }),
            Self::Bind(path) => builder.override_image_with(|image| image.bind(path)),
            Self::Snapshot(snapshot) => builder.config_snapshot(snapshot),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Scoped Patches
//--------------------------------------------------------------------------------------------------

impl ResourceConfigPatch {
    /// Create an empty resource patch.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the initial vCPU count.
    pub fn cpus(mut self, cpus: u8) -> Self {
        self.cpus = Some(cpus);
        self
    }

    /// Set guest memory in MiB.
    pub fn memory_mib(mut self, memory_mib: u32) -> Self {
        self.memory_mib = Some(memory_mib);
        self
    }

    /// Set the maximum sandbox lifetime in seconds.
    pub fn max_duration_secs(mut self, seconds: u64) -> Self {
        self.max_duration_secs = Some(seconds);
        self
    }

    /// Set the idle timeout in seconds.
    pub fn idle_timeout_secs(mut self, seconds: u64) -> Self {
        self.idle_timeout_secs = Some(seconds);
        self
    }

    /// Replace sandbox-wide resource limits.
    pub fn rlimits(mut self, rlimits: Vec<Rlimit>) -> Self {
        self.rlimits = Some(rlimits);
        self
    }

    /// Overlay another resource patch.
    pub fn overlay(mut self, higher: Self) -> Self {
        replace(&mut self.cpus, higher.cpus);
        replace(&mut self.memory_mib, higher.memory_mib);
        replace(&mut self.max_duration_secs, higher.max_duration_secs);
        replace(&mut self.idle_timeout_secs, higher.idle_timeout_secs);
        replace(&mut self.rlimits, higher.rlimits);
        self
    }

    fn apply_to(self, mut builder: SandboxBuilder) -> SandboxBuilder {
        if let Some(cpus) = self.cpus {
            builder = builder.cpus(cpus);
        }
        if let Some(memory) = self.memory_mib {
            builder = builder.memory(memory);
        }
        if let Some(seconds) = self.max_duration_secs {
            builder = builder.max_duration(seconds);
        }
        if let Some(seconds) = self.idle_timeout_secs {
            builder = builder.idle_timeout(seconds);
        }
        for limit in self.rlimits.unwrap_or_default() {
            builder = builder.rlimit_range(limit.resource, limit.soft, limit.hard);
        }
        builder
    }
}

impl RuntimeConfigPatch {
    /// Create an empty runtime patch.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the default guest working directory.
    pub fn workdir(mut self, value: impl Into<String>) -> Self {
        self.workdir = Some(value.into());
        self
    }

    /// Set the command shell.
    pub fn shell(mut self, value: impl Into<String>) -> Self {
        self.shell = Some(value.into());
        self
    }

    /// Set the guest user.
    pub fn user(mut self, value: impl Into<String>) -> Self {
        self.user = Some(value.into());
        self
    }

    /// Set the guest hostname.
    pub fn hostname(mut self, value: impl Into<String>) -> Self {
        self.hostname = Some(value.into());
        self
    }

    /// Set the in-guest security profile.
    pub fn security(mut self, value: SecurityProfile) -> Self {
        self.security = Some(value);
        self
    }

    /// Replace the image entrypoint override.
    pub fn entrypoint(mut self, value: Vec<String>) -> Self {
        self.entrypoint = Some(value);
        self
    }

    /// Replace the image command override.
    pub fn cmd(mut self, value: Vec<String>) -> Self {
        self.cmd = Some(value);
        self
    }

    /// Overlay environment variables by key.
    pub fn env(mut self, value: BTreeMap<String, String>) -> Self {
        merge_map(&mut self.env, Some(value));
        self
    }

    /// Overlay labels by key.
    pub fn labels(mut self, value: BTreeMap<String, String>) -> Self {
        merge_map(&mut self.labels, Some(value));
        self
    }

    /// Overlay guest-init handoff fields.
    pub fn init(mut self, value: InitConfigPatch) -> Self {
        self.init = Some(match self.init.take() {
            Some(current) => current.overlay(value),
            None => value,
        });
        self
    }

    /// Overlay another runtime patch.
    pub fn overlay(mut self, higher: Self) -> Self {
        replace(&mut self.workdir, higher.workdir);
        replace(&mut self.shell, higher.shell);
        replace(&mut self.user, higher.user);
        replace(&mut self.hostname, higher.hostname);
        replace(&mut self.security, higher.security);
        replace(&mut self.entrypoint, higher.entrypoint);
        replace(&mut self.cmd, higher.cmd);
        merge_map(&mut self.env, higher.env);
        merge_map(&mut self.labels, higher.labels);
        if let Some(init) = higher.init {
            self = self.init(init);
        }
        self
    }

    fn apply_to(self, mut builder: SandboxBuilder) -> SandboxBuilder {
        if let Some(value) = self.workdir {
            builder = builder.workdir(value);
        }
        if let Some(value) = self.shell {
            builder = builder.shell(value);
        }
        if let Some(value) = self.user {
            builder = builder.user(value);
        }
        if let Some(value) = self.hostname {
            builder = builder.hostname(value);
        }
        if let Some(value) = self.security {
            builder = builder.security(value);
        }
        if let Some(value) = self.entrypoint {
            builder = builder.entrypoint(value);
        }
        if let Some(value) = self.cmd {
            builder = builder.cmd(value);
        }
        if let Some(value) = self.env {
            builder = builder.envs(value);
        }
        if let Some(value) = self.labels {
            builder = builder.labels(value);
        }
        if let Some(init) = self.init {
            builder = init.apply_to(builder);
        }
        builder
    }
}

impl InitConfigPatch {
    /// Create an empty init patch.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the guest init command.
    pub fn cmd(mut self, value: impl Into<String>) -> Self {
        self.cmd = Some(value.into());
        self
    }

    /// Replace init arguments.
    pub fn args(mut self, value: Vec<String>) -> Self {
        self.args = Some(value);
        self
    }

    /// Overlay init environment variables by key.
    pub fn env(mut self, value: BTreeMap<String, String>) -> Self {
        merge_map(&mut self.env, Some(value));
        self
    }

    /// Overlay another init patch.
    pub fn overlay(mut self, higher: Self) -> Self {
        replace(&mut self.cmd, higher.cmd);
        replace(&mut self.args, higher.args);
        merge_map(&mut self.env, higher.env);
        self
    }

    fn apply_to(self, mut builder: SandboxBuilder) -> SandboxBuilder {
        let Some(cmd) = self.cmd else {
            return builder.config_error("init.cmd is required when init configuration is present");
        };
        let args = self.args.unwrap_or_default();
        let env = self.env.unwrap_or_default();
        if args.is_empty() && env.is_empty() {
            builder = builder.init(cmd);
        } else {
            builder = builder.init_with(cmd, |init| init.args(args).envs(env));
        }
        builder
    }
}

impl FilesystemConfigPatch {
    /// Create an empty filesystem patch.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace mounts.
    pub fn mounts(mut self, value: Vec<VolumeMount>) -> Self {
        self.mounts = Some(value);
        self
    }

    /// Replace operations loaded from external patch files.
    pub fn patch_file_operations(mut self, value: Vec<Patch>) -> Self {
        self.patch_file_operations = Some(value);
        self
    }

    /// Replace inline root filesystem patches.
    pub fn patches(mut self, value: Vec<Patch>) -> Self {
        self.patches = Some(value);
        self
    }

    /// Overlay another filesystem patch.
    pub fn overlay(mut self, higher: Self) -> Self {
        replace(&mut self.mounts, higher.mounts);
        replace(
            &mut self.patch_file_operations,
            higher.patch_file_operations,
        );
        replace(&mut self.patches, higher.patches);
        self
    }

    fn apply_to(self, mut builder: SandboxBuilder) -> SandboxBuilder {
        for mount in self.mounts.unwrap_or_default() {
            builder = builder.add_volume_mount(mount);
        }
        for patch in self.patch_file_operations.unwrap_or_default() {
            builder = builder.add_patch(patch);
        }
        for patch in self.patches.unwrap_or_default() {
            builder = builder.add_patch(patch);
        }
        builder
    }
}

impl ScriptConfigPatch {
    /// Create an empty script patch.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace one named shell snippet.
    pub fn script(mut self, name: impl Into<String>, body: impl Into<String>) -> Self {
        self.scripts.insert(name.into(), body.into());
        self
    }

    /// Insert or replace several named shell snippets.
    pub fn scripts(
        mut self,
        scripts: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        self.scripts.extend(
            scripts
                .into_iter()
                .map(|(name, body)| (name.into(), body.into())),
        );
        self
    }

    /// Overlay another script patch by name.
    pub fn overlay(mut self, higher: Self) -> Self {
        self.scripts.extend(higher.scripts);
        self
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Network Patches
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "net")]
impl NetworkConfigPatch {
    /// Create an empty network patch.
    pub fn new() -> Self {
        Self::default()
    }

    /// Overlay sparse policy fields.
    pub fn policy(mut self, value: NetworkPolicyConfigPatch) -> Self {
        self.policy = self.policy.overlay(value);
        self
    }

    /// Replace published ports.
    pub fn ports(mut self, value: Vec<microsandbox_network::config::PublishedPort>) -> Self {
        self.ports = Some(value);
        self
    }

    /// Overlay DNS fields.
    pub fn dns(mut self, value: DnsConfigPatch) -> Self {
        self.dns = self.dns.overlay(value);
        self
    }

    /// Overlay TLS fields.
    pub fn tls(mut self, value: TlsConfigPatch) -> Self {
        self.tls = self.tls.overlay(value);
        self
    }

    /// Set whether host certificate authorities are trusted in the guest.
    pub fn trust_host_cas(mut self, enabled: bool) -> Self {
        self.trust_host_cas = Some(enabled);
        self
    }

    /// Set the maximum number of concurrent network connections.
    pub fn max_connections(mut self, value: usize) -> Self {
        self.max_connections = Some(value);
        self
    }

    /// Overlay another network patch.
    pub fn overlay(mut self, higher: Self) -> Self {
        self.policy = self.policy.overlay(higher.policy);
        replace(&mut self.ports, higher.ports);
        self.dns = self.dns.overlay(higher.dns);
        self.tls = self.tls.overlay(higher.tls);
        replace(&mut self.trust_host_cas, higher.trust_host_cas);
        replace(&mut self.max_connections, higher.max_connections);
        self
    }

    fn apply_to(self, mut builder: SandboxBuilder) -> SandboxBuilder {
        let (policy, configured_rules) = self.policy.materialize();
        let ports = self.ports;
        let dns = self.dns;
        let tls = self.tls;
        let trust_host_cas = self.trust_host_cas;
        let max_connections = self.max_connections;

        if policy.is_some() {
            builder = builder.config_network_rules(configured_rules);
        }
        builder = builder.network(move |mut network| {
            if let Some(policy) = policy {
                network = network.policy(policy);
            }
            if let Some(ports) = ports {
                for port in ports {
                    network = match port.protocol {
                        microsandbox_network::config::PortProtocol::Tcp => {
                            network.port_bind(port.host_bind, port.host_port, port.guest_port)
                        }
                        microsandbox_network::config::PortProtocol::Udp => {
                            network.port_udp_bind(port.host_bind, port.host_port, port.guest_port)
                        }
                    };
                }
            }
            if dns.is_present() {
                network = network.dns_overlay(move |mut value| {
                    if let Some(enabled) = dns.rebind_protection {
                        value = value.rebind_protection(enabled);
                    }
                    if let Some(nameservers) = dns.nameservers {
                        value = value.nameservers(nameservers);
                    }
                    if let Some(timeout) = dns.query_timeout_ms {
                        value = value.query_timeout_ms(timeout);
                    }
                    value
                });
            }
            if let Some(enabled) = tls.enabled {
                network = network.tls_overlay(move |mut value| {
                    value = value.enabled(enabled);
                    if let Some(bypass) = tls.bypass {
                        for pattern in bypass {
                            value = value.bypass(pattern);
                        }
                    }
                    if let Some(verify) = tls.verify_upstream {
                        value = value.verify_upstream(verify);
                    }
                    if let Some(block) = tls.block_quic {
                        value = value.block_quic(block);
                    }
                    value
                });
            }
            if let Some(enabled) = trust_host_cas {
                network = network.trust_host_cas(enabled);
            }
            if let Some(max) = max_connections {
                network = network.max_connections(max);
            }
            network
        });
        builder
    }
}

#[cfg(feature = "net")]
impl NetworkPolicyConfigPatch {
    /// Create an empty policy patch.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the base policy expanded before explicit allow and deny rules.
    pub fn base(mut self, value: NetworkPolicy) -> Self {
        self.base = Some(value);
        self
    }

    /// Replace explicit deny rules.
    pub fn deny_rules(mut self, value: Vec<Rule>) -> Self {
        self.deny = Some(value);
        self
    }

    /// Replace explicit allow rules.
    pub fn allow_rules(mut self, value: Vec<Rule>) -> Self {
        self.allow = Some(value);
        self
    }

    /// Overlay another policy patch.
    pub fn overlay(mut self, higher: Self) -> Self {
        replace(&mut self.base, higher.base);
        replace(&mut self.deny, higher.deny);
        replace(&mut self.allow, higher.allow);
        self
    }

    fn materialize(self) -> (Option<NetworkPolicy>, Vec<Rule>) {
        if self.base.is_none() && self.deny.is_none() && self.allow.is_none() {
            return (None, Vec::new());
        }
        let base = self.base.unwrap_or_default();
        let allowlist = self.allow.as_ref().is_some_and(|rules| !rules.is_empty());
        let mut rules = self.deny.unwrap_or_default();
        rules.extend(self.allow.unwrap_or_default());
        let configured_rules = rules.clone();
        if !allowlist {
            rules.extend(base.rules);
        }
        (
            Some(NetworkPolicy {
                default_egress: if allowlist {
                    Action::Deny
                } else {
                    base.default_egress
                },
                default_ingress: base.default_ingress,
                rules,
            }),
            configured_rules,
        )
    }
}

#[cfg(feature = "net")]
impl DnsConfigPatch {
    /// Create an empty DNS patch.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable or disable DNS-rebinding protection.
    pub fn rebind_protection(mut self, enabled: bool) -> Self {
        self.rebind_protection = Some(enabled);
        self
    }

    /// Replace upstream nameservers.
    pub fn nameservers(mut self, values: Vec<Nameserver>) -> Self {
        self.nameservers = Some(values);
        self
    }

    /// Set the DNS query timeout in milliseconds.
    pub fn query_timeout_ms(mut self, value: u64) -> Self {
        self.query_timeout_ms = Some(value);
        self
    }

    /// Overlay another DNS patch.
    pub fn overlay(mut self, higher: Self) -> Self {
        replace(&mut self.rebind_protection, higher.rebind_protection);
        replace(&mut self.nameservers, higher.nameservers);
        replace(&mut self.query_timeout_ms, higher.query_timeout_ms);
        self
    }

    fn is_present(&self) -> bool {
        self.rebind_protection.is_some()
            || self.nameservers.is_some()
            || self.query_timeout_ms.is_some()
    }
}

#[cfg(feature = "net")]
impl TlsConfigPatch {
    /// Create an empty TLS patch.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable or disable TLS interception.
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = Some(enabled);
        self
    }

    /// Replace bypass patterns.
    pub fn bypass(mut self, value: Vec<String>) -> Self {
        self.bypass = Some(value);
        self
    }

    /// Enable or disable upstream certificate verification.
    pub fn verify_upstream(mut self, enabled: bool) -> Self {
        self.verify_upstream = Some(enabled);
        self
    }

    /// Enable or disable QUIC blocking while interception is active.
    pub fn block_quic(mut self, enabled: bool) -> Self {
        self.block_quic = Some(enabled);
        self
    }

    /// Overlay another TLS patch.
    pub fn overlay(mut self, higher: Self) -> Self {
        replace(&mut self.enabled, higher.enabled);
        replace(&mut self.bypass, higher.bypass);
        replace(&mut self.verify_upstream, higher.verify_upstream);
        replace(&mut self.block_quic, higher.block_quic);
        self
    }
}

#[cfg(feature = "net")]
impl SecretConfigPatch {
    /// Create an empty secret patch.
    pub fn new() -> Self {
        Self::default()
    }

    /// Overlay one secret entry by name.
    pub fn secret(mut self, name: impl Into<String>, value: SecretEntryConfigPatch) -> Self {
        let name = name.into();
        match self.secrets.remove(&name) {
            Some(current) => {
                self.secrets.insert(name, current.overlay(value));
            }
            None => {
                self.secrets.insert(name, value);
            }
        }
        self
    }

    /// Overlay another secret patch by name and then by field.
    pub fn overlay(mut self, higher: Self) -> Self {
        for (name, patch) in higher.secrets {
            self = self.secret(name, patch);
        }
        self
    }

    fn apply_to(self, mut builder: SandboxBuilder) -> SandboxBuilder {
        for (name, patch) in self.secrets {
            let (value, source) = match patch.material {
                Some(SecretMaterial::Literal(value)) => (value, None),
                Some(SecretMaterial::Source(source)) => {
                    (Zeroizing::new(String::new()), Some(source))
                }
                None => (
                    Zeroizing::new(String::new()),
                    Some(SecretSource::Env { var: name.clone() }),
                ),
            };
            builder = builder.secret_entry(microsandbox_types::SecretEntry {
                env_var: name.clone(),
                value,
                source,
                placeholder: microsandbox_utils::secret::default_placeholder(&name),
                allowed_hosts: patch.allowed_hosts.unwrap_or_default(),
                injection: patch.injection.unwrap_or(SecretInjection {
                    headers: true,
                    basic_auth: false,
                    query_params: false,
                    body: false,
                }),
                on_violation: None,
                require_tls_identity: patch.require_tls_identity.unwrap_or(true),
            });
        }
        builder
    }
}

#[cfg(feature = "net")]
impl SecretEntryConfigPatch {
    /// Create an empty secret-entry patch.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a literal secret value.
    pub fn literal(mut self, value: impl Into<String>) -> Self {
        self.material = Some(SecretMaterial::Literal(Zeroizing::new(value.into())));
        self
    }

    /// Set a host-side secret source.
    pub fn source(mut self, value: SecretSource) -> Self {
        self.material = Some(SecretMaterial::Source(value));
        self
    }

    /// Replace allowed host patterns.
    pub fn allowed_hosts(mut self, value: Vec<HostPattern>) -> Self {
        self.allowed_hosts = Some(value);
        self
    }

    /// Replace injection locations.
    pub fn injection(mut self, value: SecretInjection) -> Self {
        self.injection = Some(value);
        self
    }

    /// Set whether verified TLS identity is required.
    pub fn require_tls_identity(mut self, value: bool) -> Self {
        self.require_tls_identity = Some(value);
        self
    }

    /// Overlay another secret-entry patch.
    pub fn overlay(mut self, higher: Self) -> Self {
        replace(&mut self.material, higher.material);
        replace(&mut self.allowed_hosts, higher.allowed_hosts);
        replace(&mut self.injection, higher.injection);
        replace(&mut self.require_tls_identity, higher.require_tls_identity);
        self
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl From<ResourceConfigPatch> for SandboxConfigPatch {
    fn from(value: ResourceConfigPatch) -> Self {
        Self::default().resources(value)
    }
}

impl From<RuntimeConfigPatch> for SandboxConfigPatch {
    fn from(value: RuntimeConfigPatch) -> Self {
        Self::default().runtime(value)
    }
}

impl From<FilesystemConfigPatch> for SandboxConfigPatch {
    fn from(value: FilesystemConfigPatch) -> Self {
        Self::default().filesystem(value)
    }
}

impl From<ScriptConfigPatch> for SandboxConfigPatch {
    fn from(value: ScriptConfigPatch) -> Self {
        Self::default().scripts(value)
    }
}

#[cfg(feature = "net")]
impl From<NetworkConfigPatch> for SandboxConfigPatch {
    fn from(value: NetworkConfigPatch) -> Self {
        Self::default().network(value)
    }
}

#[cfg(feature = "net")]
impl From<SecretConfigPatch> for SandboxConfigPatch {
    fn from(value: SecretConfigPatch) -> Self {
        Self::default().secrets(value)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn replace<T>(base: &mut Option<T>, higher: Option<T>) {
    if higher.is_some() {
        *base = higher;
    }
}

fn merge_map<K: Ord, V>(base: &mut Option<BTreeMap<K, V>>, higher: Option<BTreeMap<K, V>>) {
    if let Some(higher) = higher {
        base.get_or_insert_with(BTreeMap::new).extend(higher);
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn scoped_overlays_are_right_hand_wins_and_map_recursive() {
        let root = SandboxConfigPatch::new()
            .image(SandboxImagePatch::Image("alpine".into()))
            .resources(ResourceConfigPatch::new().cpus(2).memory_mib(512))
            .runtime(RuntimeConfigPatch::new().env(BTreeMap::from([
                ("A".into(), "root".into()),
                ("B".into(), "root".into()),
            ])));
        let patch = root.overlay(ResourceConfigPatch::new().cpus(4)).overlay(
            RuntimeConfigPatch::new().env(BTreeMap::from([("A".into(), "scoped".into())])),
        );

        let config = SandboxBuilder::new("patch-test")
            .configure(patch)
            .build()
            .await
            .unwrap();
        assert_eq!(config.spec.resources.cpus, 4);
        assert_eq!(config.spec.resources.memory_mib, 512);
        assert!(
            config
                .spec
                .env
                .iter()
                .any(|value| value.key == "A" && value.value == "scoped")
        );
        assert!(
            config
                .spec
                .env
                .iter()
                .any(|value| value.key == "B" && value.value == "root")
        );
    }

    #[tokio::test]
    async fn explicit_builder_calls_override_configured_scalars() {
        let patch = SandboxConfigPatch::new()
            .image(SandboxImagePatch::Image("alpine".into()))
            .resources(ResourceConfigPatch::new().cpus(2).memory_mib(512));

        let config = SandboxBuilder::new("patch-test")
            .configure(patch)
            .cpus(6)
            .memory(1024)
            .build()
            .await
            .unwrap();
        assert_eq!(config.spec.resources.cpus, 6);
        assert_eq!(config.spec.resources.memory_mib, 1024);
    }

    #[tokio::test]
    async fn configured_scripts_use_the_final_shell() {
        let patch = SandboxConfigPatch::new()
            .image(SandboxImagePatch::Image("alpine".into()))
            .scripts(ScriptConfigPatch::new().script("hello", "echo hello"));

        let config = SandboxBuilder::new("patch-test")
            .configure(patch)
            .shell("bash")
            .build()
            .await
            .unwrap();
        assert_eq!(
            config.spec.runtime.scripts.get("hello").map(String::as_str),
            Some("#!/usr/bin/env bash\necho hello\n")
        );
    }

    #[tokio::test]
    async fn later_image_overrides_only_a_configured_snapshot() {
        let patch =
            SandboxConfigPatch::new().image(SandboxImagePatch::Snapshot("lower-priority".into()));
        let configured = SandboxBuilder::new("patch-test")
            .configure(patch)
            .image("alpine")
            .build()
            .await;
        assert!(configured.is_ok());

        let explicit = SandboxBuilder::new("patch-test")
            .from_snapshot("explicit")
            .image("alpine")
            .build()
            .await
            .unwrap_err();
        assert!(explicit.to_string().contains("mutually exclusive"));
    }
}

use napi_derive::napi;

use crate::types::*;

//--------------------------------------------------------------------------------------------------
// Types: Enums
//--------------------------------------------------------------------------------------------------

/// Image pull policy.
#[napi(string_enum)]
pub enum PullPolicy {
    #[napi(value = "always")]
    Always,
    #[napi(value = "if-missing")]
    IfMissing,
    #[napi(value = "never")]
    Never,
}

/// Supported disk image formats for [`Mount.disk`] and the `disk()` rootfs.
#[napi(string_enum)]
#[derive(Clone, Copy)]
pub enum DiskImageFormat {
    #[napi(value = "qcow2")]
    Qcow2,
    #[napi(value = "raw")]
    Raw,
    #[napi(value = "vmdk")]
    Vmdk,
}

impl From<DiskImageFormat> for microsandbox::sandbox::DiskImageFormat {
    fn from(f: DiskImageFormat) -> Self {
        match f {
            DiskImageFormat::Qcow2 => microsandbox::sandbox::DiskImageFormat::Qcow2,
            DiskImageFormat::Raw => microsandbox::sandbox::DiskImageFormat::Raw,
            DiskImageFormat::Vmdk => microsandbox::sandbox::DiskImageFormat::Vmdk,
        }
    }
}

/// Log level for sandbox process output.
#[napi(string_enum)]
pub enum LogLevel {
    #[napi(value = "trace")]
    Trace,
    #[napi(value = "debug")]
    Debug,
    #[napi(value = "info")]
    Info,
    #[napi(value = "warn")]
    Warn,
    #[napi(value = "error")]
    Error,
}

/// Action to take when a secret is sent to a disallowed host.
#[napi(string_enum)]
pub enum ViolationAction {
    /// Silently block the request.
    #[napi(value = "block")]
    Block,
    /// Block the request and log the violation.
    #[napi(value = "block-and-log")]
    BlockAndLog,
    /// Block the request and terminate the sandbox.
    #[napi(value = "block-and-terminate")]
    BlockAndTerminate,
}

/// Network policy rule action.
#[napi(string_enum)]
pub enum PolicyAction {
    #[napi(value = "allow")]
    Allow,
    #[napi(value = "deny")]
    Deny,
}

/// Network policy rule direction.
#[napi(string_enum)]
pub enum PolicyDirection {
    #[napi(value = "egress")]
    Egress,
    #[napi(value = "ingress")]
    Ingress,
    #[napi(value = "any")]
    Any,
}

/// Network policy rule protocol.
#[napi(string_enum)]
pub enum PolicyProtocol {
    #[napi(value = "tcp")]
    Tcp,
    #[napi(value = "udp")]
    Udp,
    #[napi(value = "icmpv4")]
    Icmpv4,
    #[napi(value = "icmpv6")]
    Icmpv6,
}

/// Sandbox status.
#[napi(string_enum)]
pub enum SandboxStatus {
    #[napi(value = "running")]
    Running,
    #[napi(value = "stopped")]
    Stopped,
    #[napi(value = "crashed")]
    Crashed,
    #[napi(value = "draining")]
    Draining,
}

/// Filesystem entry kind.
#[napi(string_enum)]
pub enum FsEntryKind {
    #[napi(value = "file")]
    File,
    #[napi(value = "directory")]
    Directory,
    #[napi(value = "symlink")]
    Symlink,
    #[napi(value = "other")]
    Other,
}

/// Execution event type.
#[napi(string_enum)]
pub enum ExecEventType {
    #[napi(value = "started")]
    Started,
    #[napi(value = "stdout")]
    Stdout,
    #[napi(value = "stderr")]
    Stderr,
    #[napi(value = "exited")]
    Exited,
}

//--------------------------------------------------------------------------------------------------
// Types: Helper Option Objects
//--------------------------------------------------------------------------------------------------

/// Options for bind and named volume mounts.
#[napi(object)]
pub struct MountOptions {
    /// Read-only mount.
    pub readonly: Option<bool>,
}

/// Options for tmpfs mounts.
#[napi(object)]
pub struct TmpfsOptions {
    /// Size limit in MiB.
    pub size_mib: Option<u32>,
    /// Read-only mount.
    pub readonly: Option<bool>,
}

/// Options for disk-image volume mounts.
#[napi(object)]
pub struct DiskOptions {
    /// Disk image format. When omitted, inferred from the file extension.
    pub format: Option<DiskImageFormat>,
    /// Inner filesystem type the guest should mount (e.g. `"ext4"`). When
    /// omitted, agentd probes `/proc/filesystems`.
    pub fstype: Option<String>,
    /// Read-only mount.
    pub readonly: Option<bool>,
}

/// Options for `Secret.env()`.
#[napi(object)]
pub struct SecretEnvOptions {
    /// The secret value (never enters the sandbox).
    pub value: String,
    /// Allowed hosts (exact match, e.g. `["api.openai.com"]`).
    pub allow_hosts: Option<Vec<String>>,
    /// Allowed host patterns (wildcard, e.g. `["*.openai.com"]`).
    pub allow_host_patterns: Option<Vec<String>>,
    /// Custom placeholder (auto-generated as `$MSB_<ENV_VAR>` if omitted).
    pub placeholder: Option<String>,
    /// Require verified TLS identity before substitution (default: true).
    pub require_tls: Option<bool>,
    /// Violation action: "block", "block-and-log" (default), "block-and-terminate".
    pub on_violation: Option<String>,
    /// Where in the HTTP request the secret can be injected. Defaults to
    /// headers + Basic Auth only; enable `queryParams` or `body` to widen scope.
    pub inject: Option<SecretInjection>,
}

/// Options for `Patch.text()` and `Patch.copyFile()`.
#[napi(object)]
pub struct PatchOptions {
    /// File permissions (e.g. 0o644).
    pub mode: Option<u32>,
    /// Allow replacing existing files.
    pub replace: Option<bool>,
}

/// Options for `Patch.copyDir()` and `Patch.symlink()`.
#[napi(object)]
pub struct PatchReplaceOptions {
    /// Allow replacing existing files/directories.
    pub replace: Option<bool>,
}

//--------------------------------------------------------------------------------------------------
// Types: Helper Classes
//--------------------------------------------------------------------------------------------------

/// Factory for creating volume mount configurations.
///
/// ```js
/// import { Mount, Sandbox } from 'microsandbox'
///
/// const sb = await Sandbox.create({
///     name: "worker",
///     image: "python",
///     volumes: {
///         "/app/src": Mount.bind("./src", { readonly: true }),
///         "/data": Mount.named("my-data"),
///         "/tmp": Mount.tmpfs({ sizeMib: 100 }),
///     },
/// })
/// ```
#[napi]
pub struct Mount;

/// Factory for creating network policy configurations.
///
/// ```js
/// import { NetworkPolicy, Sandbox } from 'microsandbox'
///
/// // legacy preset
/// const sb1 = await Sandbox.create({
///     name: "worker",
///     image: "python",
///     network: NetworkPolicy.publicOnly(),
/// })
///
/// // fluent builder
/// const policy = NetworkPolicy.builder()
///     .defaultDeny()
///     .egress().tcp().port(443).allowPublic().allowPrivate()
///     .any().denyIp("198.51.100.5")
///     .build()
/// ```
#[napi(js_name = "NetworkPolicy")]
pub struct JsNetworkPolicy;

/// Fluent builder for [`NetworkConfig`]-shaped policies. Mirrors the
/// rust `NetworkPolicy::builder()` surface, flattened so the chain
/// stays readable in javascript without nested closures.
///
/// State setters (`.egress() / .ingress() / .any()` for direction,
/// `.tcp() / .udp() / .icmpv4() / .icmpv6()` for the protocols set,
/// `.port(n) / .portRange(lo, hi)` for the ports set) accumulate
/// eagerly. Each rule-adder commits one rule using the closure's
/// current state. State is **not reset** between rule-adders.
///
/// `.build()` returns a [`NetworkConfig`] with `defaultEgress`,
/// `defaultIngress`, and `rules` populated. Pass it through
/// `Sandbox.create({ network: ... })` like any other network config.
#[napi(js_name = "NetworkPolicyBuilder")]
pub struct NetworkPolicyBuilder {
    direction: Option<PolicyDirection>,
    protocols: Vec<PolicyProtocol>,
    ports: Vec<String>,
    rules: Vec<PolicyRule>,
    default_egress: Option<PolicyAction>,
    default_ingress: Option<PolicyAction>,
}

/// Factory for creating secret entries.
///
/// ```js
/// import { Secret, Sandbox } from 'microsandbox'
///
/// const sb = await Sandbox.create({
///     name: "agent",
///     image: "python",
///     secrets: [
///         Secret.env("OPENAI_API_KEY", {
///             value: process.env.OPENAI_API_KEY,
///             allowHosts: ["api.openai.com"],
///         }),
///     ],
/// })
/// ```
#[napi]
pub struct Secret;

/// Factory for creating rootfs patch configurations.
///
/// ```js
/// import { Patch, Sandbox } from 'microsandbox'
///
/// const sb = await Sandbox.create({
///     name: "worker",
///     image: "alpine",
///     patches: [
///         Patch.text("/etc/greeting.txt", "Hello!\n"),
///         Patch.mkdir("/app", { mode: 0o755 }),
///         Patch.append("/etc/hosts", "127.0.0.1 myapp.local\n"),
///         Patch.copyFile("./config.json", "/app/config.json"),
///         Patch.copyDir("./scripts", "/app/scripts"),
///         Patch.symlink("/usr/bin/python3", "/usr/bin/python"),
///         Patch.remove("/etc/motd"),
///     ],
/// })
/// ```
#[napi]
pub struct Patch;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl Mount {
    /// Create a bind mount (host directory → guest path).
    #[napi]
    pub fn bind(path: String, opts: Option<MountOptions>) -> MountConfig {
        let readonly = opts.and_then(|o| o.readonly);
        MountConfig {
            bind: Some(path),
            named: None,
            tmpfs: None,
            disk: None,
            format: None,
            fstype: None,
            readonly,
            size_mib: None,
        }
    }

    /// Create a named volume mount.
    #[napi]
    pub fn named(name: String, opts: Option<MountOptions>) -> MountConfig {
        let readonly = opts.and_then(|o| o.readonly);
        MountConfig {
            bind: None,
            named: Some(name),
            tmpfs: None,
            disk: None,
            format: None,
            fstype: None,
            readonly,
            size_mib: None,
        }
    }

    /// Create a tmpfs (in-memory) mount.
    #[napi]
    pub fn tmpfs(opts: Option<TmpfsOptions>) -> MountConfig {
        let (size_mib, readonly) = opts
            .map(|o| (o.size_mib, o.readonly))
            .unwrap_or((None, None));
        MountConfig {
            bind: None,
            named: None,
            tmpfs: Some(true),
            disk: None,
            format: None,
            fstype: None,
            readonly,
            size_mib,
        }
    }

    /// Mount a host disk image as a virtio-blk device at a guest path.
    ///
    /// Format defaults to the file extension (`.qcow2` → Qcow2, `.vmdk` →
    /// Vmdk, anything else → Raw). Use `opts.format` to override. `fstype`
    /// (e.g. `"ext4"`) is the inner filesystem agentd will mount; when
    /// omitted, agentd probes `/proc/filesystems`.
    #[napi]
    pub fn disk(path: String, opts: Option<DiskOptions>) -> MountConfig {
        let (format, fstype, readonly) = opts
            .map(|o| (o.format, o.fstype, o.readonly))
            .unwrap_or((None, None, None));
        MountConfig {
            bind: None,
            named: None,
            tmpfs: None,
            disk: Some(path),
            format,
            fstype,
            readonly,
            size_mib: None,
        }
    }
}

#[napi]
impl JsNetworkPolicy {
    /// No network access at all.
    #[napi]
    pub fn none() -> NetworkConfig {
        NetworkConfig {
            policy: Some("none".to_string()),
            rules: None,
            default_egress: None,
            default_ingress: None,
            dns: None,
            tls: None,
            max_connections: None,
            trust_host_cas: None,
        }
    }

    /// Public internet only — blocks private ranges (default).
    #[napi]
    pub fn public_only() -> NetworkConfig {
        NetworkConfig {
            policy: Some("public-only".to_string()),
            rules: None,
            default_egress: None,
            default_ingress: None,
            dns: None,
            tls: None,
            max_connections: None,
            trust_host_cas: None,
        }
    }

    /// Unrestricted network access.
    #[napi]
    pub fn allow_all() -> NetworkConfig {
        NetworkConfig {
            policy: Some("allow-all".to_string()),
            rules: None,
            default_egress: None,
            default_ingress: None,
            dns: None,
            tls: None,
            max_connections: None,
            trust_host_cas: None,
        }
    }

    /// Open a fluent [`NetworkPolicyBuilder`] for composing a custom
    /// policy. See the `NetworkPolicyBuilder` class for the full
    /// chainable surface.
    #[napi]
    pub fn builder() -> NetworkPolicyBuilder {
        NetworkPolicyBuilder::new()
    }
}

#[napi]
impl NetworkPolicyBuilder {
    /// Construct an empty builder. Prefer [`JsNetworkPolicy::builder`]
    /// (`NetworkPolicy.builder()` in JS) over calling this directly.
    #[napi(constructor)]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            direction: None,
            protocols: Vec::new(),
            ports: Vec::new(),
            rules: Vec::new(),
            default_egress: None,
            default_ingress: None,
        }
    }

    // -- defaults ----------------------------------------------------

    /// Set both `defaultEgress` and `defaultIngress` to `"allow"`.
    #[napi]
    pub fn default_allow(&mut self) -> &Self {
        self.default_egress = Some(PolicyAction::Allow);
        self.default_ingress = Some(PolicyAction::Allow);
        self
    }

    /// Set both `defaultEgress` and `defaultIngress` to `"deny"`.
    #[napi]
    pub fn default_deny(&mut self) -> &Self {
        self.default_egress = Some(PolicyAction::Deny);
        self.default_ingress = Some(PolicyAction::Deny);
        self
    }

    /// Per-direction override for the egress default action.
    #[napi]
    pub fn default_egress(&mut self, action: PolicyAction) -> &Self {
        self.default_egress = Some(action);
        self
    }

    /// Per-direction override for the ingress default action.
    #[napi]
    pub fn default_ingress(&mut self, action: PolicyAction) -> &Self {
        self.default_ingress = Some(action);
        self
    }

    // -- direction setters ------------------------------------------

    /// Set the direction for subsequent rule-adders to `"egress"`.
    #[napi]
    pub fn egress(&mut self) -> &Self {
        self.direction = Some(PolicyDirection::Egress);
        self
    }

    /// Set the direction for subsequent rule-adders to `"ingress"`.
    #[napi]
    pub fn ingress(&mut self) -> &Self {
        self.direction = Some(PolicyDirection::Ingress);
        self
    }

    /// Set the direction for subsequent rule-adders to `"any"`. Rules
    /// committed with this direction match in either direction.
    #[napi]
    pub fn any(&mut self) -> &Self {
        self.direction = Some(PolicyDirection::Any);
        self
    }

    // -- protocol setters --------------------------------------------

    /// Add `"tcp"` to the protocols set (set semantics; duplicates dedupe).
    #[napi]
    pub fn tcp(&mut self) -> &Self {
        self.add_protocol(PolicyProtocol::Tcp);
        self
    }

    /// Add `"udp"` to the protocols set.
    #[napi]
    pub fn udp(&mut self) -> &Self {
        self.add_protocol(PolicyProtocol::Udp);
        self
    }

    /// Add `"icmpv4"` to the protocols set. Egress-only — committing a
    /// rule with `"icmpv4"` and direction `"ingress"` or `"any"` will
    /// be rejected at sandbox creation.
    #[napi]
    pub fn icmpv4(&mut self) -> &Self {
        self.add_protocol(PolicyProtocol::Icmpv4);
        self
    }

    /// Add `"icmpv6"` to the protocols set. Egress-only.
    #[napi]
    pub fn icmpv6(&mut self) -> &Self {
        self.add_protocol(PolicyProtocol::Icmpv6);
        self
    }

    fn add_protocol(&mut self, p: PolicyProtocol) {
        let already_present = self.protocols.iter().any(|existing| {
            matches!(
                (existing, &p),
                (PolicyProtocol::Tcp, PolicyProtocol::Tcp)
                    | (PolicyProtocol::Udp, PolicyProtocol::Udp)
                    | (PolicyProtocol::Icmpv4, PolicyProtocol::Icmpv4)
                    | (PolicyProtocol::Icmpv6, PolicyProtocol::Icmpv6)
            )
        });
        if !already_present {
            self.protocols.push(p);
        }
    }

    // -- port setters ------------------------------------------------

    /// Add a single port to the ports set.
    #[napi]
    pub fn port(&mut self, port: u16) -> &Self {
        let s = port.to_string();
        if !self.ports.contains(&s) {
            self.ports.push(s);
        }
        self
    }

    /// Add an inclusive port range to the ports set, formatted as
    /// `"<lo>-<hi>"` on the wire. `lo > hi` is rejected at sandbox
    /// creation.
    #[napi]
    pub fn port_range(&mut self, lo: u16, hi: u16) -> &Self {
        let s = format!("{lo}-{hi}");
        if !self.ports.contains(&s) {
            self.ports.push(s);
        }
        self
    }

    // -- atomic group rule-adders ------------------------------------

    /// Allow the `"public"` group (complement of named categories).
    #[napi]
    pub fn allow_public(&mut self) -> &Self {
        self.commit_group(PolicyAction::Allow, "public");
        self
    }

    /// Deny the `"public"` group.
    #[napi]
    pub fn deny_public(&mut self) -> &Self {
        self.commit_group(PolicyAction::Deny, "public");
        self
    }

    /// Allow the `"private"` group (RFC1918 + ULA + CGN).
    #[napi]
    pub fn allow_private(&mut self) -> &Self {
        self.commit_group(PolicyAction::Allow, "private");
        self
    }

    /// Deny the `"private"` group.
    #[napi]
    pub fn deny_private(&mut self) -> &Self {
        self.commit_group(PolicyAction::Deny, "private");
        self
    }

    /// Allow the `"loopback"` group (`127.0.0.0/8`, `::1`) — the
    /// **guest's own** loopback interface. Not the host machine. To
    /// reach a service on the host's localhost, use [`Self::allow_host`].
    #[napi]
    pub fn allow_loopback(&mut self) -> &Self {
        self.commit_group(PolicyAction::Allow, "loopback");
        self
    }

    /// Deny the `"loopback"` group. Useful in `defaultEgress = "allow"`
    /// configurations to block crafted-packet leaks where a process
    /// inside the guest binds a raw socket to eth0 with `dst=127.0.0.1`.
    #[napi]
    pub fn deny_loopback(&mut self) -> &Self {
        self.commit_group(PolicyAction::Deny, "loopback");
        self
    }

    /// Allow the `"link-local"` group (`169.254.0.0/16`, `fe80::/10`).
    /// Excludes the metadata IP (categorized as `"metadata"`).
    #[napi]
    pub fn allow_link_local(&mut self) -> &Self {
        self.commit_group(PolicyAction::Allow, "link-local");
        self
    }

    /// Deny the `"link-local"` group.
    #[napi]
    pub fn deny_link_local(&mut self) -> &Self {
        self.commit_group(PolicyAction::Deny, "link-local");
        self
    }

    /// Allow the `"metadata"` group (`169.254.169.254`). **Dangerous on
    /// cloud hosts** — exposes IAM credentials.
    #[napi]
    pub fn allow_meta(&mut self) -> &Self {
        self.commit_group(PolicyAction::Allow, "metadata");
        self
    }

    /// Deny the `"metadata"` group.
    #[napi]
    pub fn deny_meta(&mut self) -> &Self {
        self.commit_group(PolicyAction::Deny, "metadata");
        self
    }

    /// Allow the `"multicast"` group (`224.0.0.0/4`, `ff00::/8`).
    #[napi]
    pub fn allow_multicast(&mut self) -> &Self {
        self.commit_group(PolicyAction::Allow, "multicast");
        self
    }

    /// Deny the `"multicast"` group.
    #[napi]
    pub fn deny_multicast(&mut self) -> &Self {
        self.commit_group(PolicyAction::Deny, "multicast");
        self
    }

    /// Allow the `"host"` group — the per-sandbox gateway IPs that
    /// back `host.microsandbox.internal`. This is the right shortcut
    /// for "let the sandbox reach my host's localhost", not
    /// [`Self::allow_loopback`].
    #[napi]
    pub fn allow_host(&mut self) -> &Self {
        self.commit_group(PolicyAction::Allow, "host");
        self
    }

    /// Deny the `"host"` group.
    #[napi]
    pub fn deny_host(&mut self) -> &Self {
        self.commit_group(PolicyAction::Deny, "host");
        self
    }

    // -- composite sugar ---------------------------------------------

    /// Allow `"loopback"` + `"link-local"` + `"host"` — the three
    /// "near the sandbox" groups a developer typically wants together
    /// when running locally. Adds **three rules** atomically using
    /// the current state. `"metadata"` is explicitly **not** included.
    #[napi]
    pub fn allow_local(&mut self) -> &Self {
        self.commit_group(PolicyAction::Allow, "loopback");
        self.commit_group(PolicyAction::Allow, "link-local");
        self.commit_group(PolicyAction::Allow, "host");
        self
    }

    /// Deny `"loopback"` + `"link-local"` + `"host"` (no metadata).
    #[napi]
    pub fn deny_local(&mut self) -> &Self {
        self.commit_group(PolicyAction::Deny, "loopback");
        self.commit_group(PolicyAction::Deny, "link-local");
        self.commit_group(PolicyAction::Deny, "host");
        self
    }

    // -- atomic explicit rule-adders ---------------------------------

    /// Allow traffic to a specific IP address (stored as `/32` or
    /// `/128` CIDR on the wire).
    #[napi]
    pub fn allow_ip(&mut self, ip: String) -> &Self {
        self.commit_destination(PolicyAction::Allow, ip);
        self
    }

    /// Deny traffic to a specific IP address.
    #[napi]
    pub fn deny_ip(&mut self, ip: String) -> &Self {
        self.commit_destination(PolicyAction::Deny, ip);
        self
    }

    /// Allow traffic to a CIDR range (e.g. `"10.0.0.0/8"`).
    #[napi]
    pub fn allow_cidr(&mut self, cidr: String) -> &Self {
        self.commit_destination(PolicyAction::Allow, cidr);
        self
    }

    /// Deny traffic to a CIDR range.
    #[napi]
    pub fn deny_cidr(&mut self, cidr: String) -> &Self {
        self.commit_destination(PolicyAction::Deny, cidr);
        self
    }

    /// Allow traffic to an exact domain (e.g. `"api.example.com"`).
    /// Domain rules require the guest to resolve through the
    /// sandbox's DNS interceptor.
    #[napi]
    pub fn allow_domain(&mut self, domain: String) -> &Self {
        self.commit_destination(PolicyAction::Allow, domain);
        self
    }

    /// Deny traffic to an exact domain.
    #[napi]
    pub fn deny_domain(&mut self, domain: String) -> &Self {
        self.commit_destination(PolicyAction::Deny, domain);
        self
    }

    /// Allow traffic to any subdomain matching this suffix. The
    /// suffix should be prefixed with `"."` (e.g.
    /// `".pythonhosted.org"` matches `files.pythonhosted.org`).
    #[napi]
    pub fn allow_domain_suffix(&mut self, suffix: String) -> &Self {
        let s = if suffix.starts_with('.') {
            suffix
        } else {
            format!(".{suffix}")
        };
        self.commit_destination(PolicyAction::Allow, s);
        self
    }

    /// Deny traffic to any subdomain matching this suffix.
    #[napi]
    pub fn deny_domain_suffix(&mut self, suffix: String) -> &Self {
        let s = if suffix.starts_with('.') {
            suffix
        } else {
            format!(".{suffix}")
        };
        self.commit_destination(PolicyAction::Deny, s);
        self
    }

    /// Allow traffic to any destination (`"*"`).
    #[napi]
    pub fn allow_any(&mut self) -> &Self {
        self.commit_destination(PolicyAction::Allow, "*".to_string());
        self
    }

    /// Deny traffic to any destination.
    #[napi]
    pub fn deny_any(&mut self) -> &Self {
        self.commit_destination(PolicyAction::Deny, "*".to_string());
        self
    }

    // -- internal commit helpers ------------------------------------

    fn commit_group(&mut self, action: PolicyAction, group: &str) {
        self.commit_destination(action, group.to_string());
    }

    fn commit_destination(&mut self, action: PolicyAction, destination: String) {
        let action_str = action_ref_to_str(&action).to_string();
        let direction_str = self
            .direction
            .as_ref()
            .map(direction_to_str)
            .map(String::from);
        let protocol_str = self
            .protocols
            .first()
            .map(protocol_to_str)
            .map(String::from);
        let port_str = self.ports.first().cloned();
        self.rules.push(PolicyRule {
            action: action_str,
            direction: direction_str,
            destination: Some(destination),
            protocol: protocol_str,
            port: port_str,
        });
    }

    // -- terminator --------------------------------------------------

    /// Materialize the accumulated state into a [`NetworkConfig`]
    /// suitable for `Sandbox.create({ network: ... })`. Errors in the
    /// rule contents (invalid ip / cidr / domain strings, lo > hi
    /// port range, icmp on a non-egress rule) surface at sandbox
    /// creation, not here.
    #[napi]
    pub fn build(&self) -> NetworkConfig {
        let cloned_rules: Vec<PolicyRule> = self
            .rules
            .iter()
            .map(|r| PolicyRule {
                action: r.action.clone(),
                direction: r.direction.clone(),
                destination: r.destination.clone(),
                protocol: r.protocol.clone(),
                port: r.port.clone(),
            })
            .collect();
        NetworkConfig {
            policy: None,
            rules: Some(cloned_rules),
            default_egress: self
                .default_egress
                .as_ref()
                .map(|a| action_ref_to_str(a).to_string()),
            default_ingress: self
                .default_ingress
                .as_ref()
                .map(|a| action_ref_to_str(a).to_string()),
            dns: None,
            tls: None,
            max_connections: None,
            trust_host_cas: None,
        }
    }
}

fn action_ref_to_str(action: &PolicyAction) -> &'static str {
    match action {
        PolicyAction::Allow => "allow",
        PolicyAction::Deny => "deny",
    }
}

fn direction_to_str(direction: &PolicyDirection) -> &'static str {
    match direction {
        PolicyDirection::Egress => "egress",
        PolicyDirection::Ingress => "ingress",
        PolicyDirection::Any => "any",
    }
}

fn protocol_to_str(protocol: &PolicyProtocol) -> &'static str {
    match protocol {
        PolicyProtocol::Tcp => "tcp",
        PolicyProtocol::Udp => "udp",
        PolicyProtocol::Icmpv4 => "icmpv4",
        PolicyProtocol::Icmpv6 => "icmpv6",
    }
}

#[napi]
impl Secret {
    /// Create a secret bound to an environment variable.
    #[napi]
    pub fn env(env_var: String, opts: SecretEnvOptions) -> SecretEntry {
        SecretEntry {
            env_var,
            value: opts.value,
            allow_hosts: opts.allow_hosts,
            allow_host_patterns: opts.allow_host_patterns,
            placeholder: opts.placeholder,
            require_tls: opts.require_tls,
            on_violation: opts.on_violation,
            inject: opts.inject,
        }
    }
}

#[napi]
impl Patch {
    /// Write text content to a file in the guest filesystem.
    #[napi]
    pub fn text(path: String, content: String, opts: Option<PatchOptions>) -> PatchConfig {
        let (mode, replace) = opts.map(|o| (o.mode, o.replace)).unwrap_or((None, None));
        PatchConfig {
            kind: "text".to_string(),
            path: Some(path),
            content: Some(content),
            src: None,
            dst: None,
            target: None,
            link: None,
            mode,
            replace,
        }
    }

    /// Create a directory in the guest filesystem (idempotent).
    #[napi]
    pub fn mkdir(path: String, opts: Option<PatchOptions>) -> PatchConfig {
        let mode = opts.and_then(|o| o.mode);
        PatchConfig {
            kind: "mkdir".to_string(),
            path: Some(path),
            content: None,
            src: None,
            dst: None,
            target: None,
            link: None,
            mode,
            replace: None,
        }
    }

    /// Append content to an existing file in the guest filesystem.
    #[napi]
    pub fn append(path: String, content: String) -> PatchConfig {
        PatchConfig {
            kind: "append".to_string(),
            path: Some(path),
            content: Some(content),
            src: None,
            dst: None,
            target: None,
            link: None,
            mode: None,
            replace: None,
        }
    }

    /// Copy a file from the host into the guest filesystem.
    #[napi]
    pub fn copy_file(src: String, dst: String, opts: Option<PatchOptions>) -> PatchConfig {
        let (mode, replace) = opts.map(|o| (o.mode, o.replace)).unwrap_or((None, None));
        PatchConfig {
            kind: "copyFile".to_string(),
            path: None,
            content: None,
            src: Some(src),
            dst: Some(dst),
            target: None,
            link: None,
            mode,
            replace,
        }
    }

    /// Copy a directory from the host into the guest filesystem.
    #[napi]
    pub fn copy_dir(src: String, dst: String, opts: Option<PatchReplaceOptions>) -> PatchConfig {
        let replace = opts.and_then(|o| o.replace);
        PatchConfig {
            kind: "copyDir".to_string(),
            path: None,
            content: None,
            src: Some(src),
            dst: Some(dst),
            target: None,
            link: None,
            mode: None,
            replace,
        }
    }

    /// Create a symlink in the guest filesystem.
    #[napi]
    pub fn symlink(target: String, link: String, opts: Option<PatchReplaceOptions>) -> PatchConfig {
        let replace = opts.and_then(|o| o.replace);
        PatchConfig {
            kind: "symlink".to_string(),
            path: None,
            content: None,
            src: None,
            dst: None,
            target: Some(target),
            link: Some(link),
            mode: None,
            replace,
        }
    }

    /// Remove a file or directory from the guest filesystem (idempotent).
    #[napi]
    pub fn remove(path: String) -> PatchConfig {
        PatchConfig {
            kind: "remove".to_string(),
            path: Some(path),
            content: None,
            src: None,
            dst: None,
            target: None,
            link: None,
            mode: None,
            replace: None,
        }
    }
}

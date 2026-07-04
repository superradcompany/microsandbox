//! Common sandbox configuration flags shared between commands.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::Args;
use microsandbox::VolumeKind;
use microsandbox::backend::{Backend, LocalBackend};
use microsandbox::sandbox::{
    DiskImageFormat, MountBuilder, Patch, Sandbox, SandboxBuilder, SandboxFilter, SecurityProfile,
};

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Functions: Backend resolution
//--------------------------------------------------------------------------------------------------

/// Resolve the process-wide local backend exactly once at the CLI entry point.
///
/// CLI commands always operate against the active default backend. Returns
/// an `Arc<dyn Backend>` plus a borrow of the `LocalBackend` inside it so
/// callers can dispatch through either the trait or the local-only APIs.
/// Errors when the resolved default backend isn't a local one (e.g. when
/// the user has installed a cloud profile but is running a local-only
/// command).
pub fn resolve_local_backend() -> anyhow::Result<Arc<dyn Backend>> {
    let backend = microsandbox::backend::default_backend();
    if backend.as_local().is_none() {
        anyhow::bail!(
            "this command requires a local backend, but the active default is a cloud backend"
        );
    }
    Ok(backend)
}

/// Borrow the `LocalBackend` inside the resolved default backend, or error.
pub fn local_backend_ref(backend: &Arc<dyn Backend>) -> anyhow::Result<&LocalBackend> {
    backend
        .as_local()
        .ok_or_else(|| anyhow::anyhow!("this command requires a local backend"))
}

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Common sandbox configuration flags shared between `msb run` and `msb create`.
#[derive(Debug, Default, Args)]
pub struct SandboxOpts {
    /// Name for the sandbox. Auto-generated if omitted. Maximum 128 UTF-8 bytes.
    #[arg(short, long)]
    pub name: Option<String>,

    /// Number of virtual CPUs to allocate.
    #[arg(short = 'c', long)]
    pub cpus: Option<u8>,

    /// Boot-time maximum possible virtual CPUs.
    #[arg(long = "max-cpus")]
    pub max_cpus: Option<u8>,

    /// Amount of memory to allocate (e.g. 512M, 1G).
    #[arg(short, long)]
    pub memory: Option<String>,

    /// Boot-time maximum hotpluggable memory (e.g. 1G, 8G).
    #[arg(long = "max-memory", value_name = "SIZE")]
    pub max_memory: Option<String>,

    /// Mount a host path or named volume into the sandbox (`SOURCE:DEST[:OPTIONS]`).
    #[arg(short, long)]
    pub volume: Vec<String>,

    /// Explicitly mount a host directory into the sandbox (`SOURCE:DEST[:OPTIONS]`).
    #[arg(long = "mount-dir", value_name = "SOURCE:DEST[:OPTIONS]")]
    pub mount_dir: Vec<String>,

    /// Explicitly mount a host file into the sandbox (`SOURCE:DEST[:OPTIONS]`).
    #[arg(long = "mount-file", value_name = "SOURCE:DEST[:OPTIONS]")]
    pub mount_file: Vec<String>,

    /// Explicitly mount a disk image into the sandbox (`SOURCE:DEST[:OPTIONS]`).
    #[arg(long = "mount-disk", value_name = "SOURCE:DEST[:OPTIONS]")]
    pub mount_disk: Vec<String>,

    /// Explicitly mount a named volume into the sandbox (`NAME:DEST[:OPTIONS]`).
    #[arg(long = "mount-named", value_name = "NAME:DEST[:OPTIONS]")]
    pub mount_named: Vec<String>,

    /// Set the default working directory for commands.
    #[arg(short, long)]
    pub workdir: Option<String>,

    /// Shell to use for interactive sessions (default: /bin/sh).
    #[arg(long)]
    pub shell: Option<String>,

    /// Set an environment variable (KEY=value).
    #[arg(short, long)]
    pub env: Vec<String>,

    /// Attach a label to the sandbox for metrics attribution (`KEY=VALUE`, or
    /// bare `KEY` for a valueless marker). Repeatable. Surfaced as attributes on
    /// the sandbox's metrics.
    #[arg(long, value_name = "KEY[=VALUE]")]
    pub label: Vec<String>,

    /// Replace an existing sandbox with the same name.
    #[arg(long)]
    pub replace: bool,

    /// Timeout the existing sandbox gets after SIGTERM before it is
    /// SIGKILLed during a replace. Accepts `0`, `500ms`, `5s`, `2m`.
    /// Implies `--replace`. Default 10s when `--replace` is set on its
    /// own. An expired timeout force-kills the prior sandbox; the
    /// `create` call still proceeds.
    #[arg(long, value_name = "DURATION")]
    pub replace_with_timeout: Option<String>,

    /// Suppress progress output.
    #[arg(short, long)]
    pub quiet: bool,

    // --- Filesystem ---
    /// Mount a temporary in-memory filesystem (PATH, PATH:SIZE, or PATH:SIZE:OPTIONS).
    #[arg(long)]
    pub tmpfs: Vec<String>,

    /// In-guest security profile (default or restricted).
    #[arg(long, value_parser = ["default", "restricted"])]
    pub security: Option<String>,

    /// Register a shell snippet as a named script (NAME=BODY). The body
    /// supports `\n`, `\t`, `\r`, `\\`, `\"`, `\'` escapes; unknown escapes
    /// are preserved verbatim. The snippet is wrapped with a shebang derived
    /// from `--shell` (default `/bin/sh`) and made executable at
    /// `/.msb/scripts/<name>`; the directory is on `PATH`.
    #[arg(long, value_name = "NAME=BODY")]
    pub script: Vec<String>,

    /// Register exact inline script contents (NAME=BODY). No escape decoding
    /// or shebang is added, so the caller must include a `#!` line if the
    /// script should be directly executable.
    #[arg(long, value_name = "NAME=BODY")]
    pub script_raw: Vec<String>,

    /// Register a script from a host file (NAME:PATH). Same destination as
    /// `--script`; the file's contents are read verbatim at launch time.
    #[arg(long, value_name = "NAME:PATH")]
    pub script_path: Vec<String>,

    /// Copy a host file or directory into the guest rootfs before boot (SRC:DST).
    #[arg(long, value_name = "SRC:DST")]
    pub copy: Vec<String>,

    /// Copy a host file into the guest rootfs before boot (SRC:DST).
    #[arg(long, value_name = "SRC:DST")]
    pub copy_file: Vec<String>,

    /// Copy a host directory into the guest rootfs before boot (SRC:DST).
    #[arg(long, value_name = "SRC:DST")]
    pub copy_dir: Vec<String>,

    /// Create a directory in the guest rootfs before boot.
    #[arg(long, value_name = "PATH")]
    pub mkdir: Vec<String>,

    /// Hide/remove a path from the guest rootfs before boot.
    #[arg(long = "rm", value_name = "PATH")]
    pub rm: Vec<String>,

    // --- Image/Runtime overrides ---
    /// Override the image's default entrypoint command.
    #[arg(long)]
    pub entrypoint: Option<String>,

    /// Hand off PID 1 to this init binary inside the guest after agentd
    /// finishes setup. Use `auto` to honor a known init at the start of
    /// the image ENTRYPOINT (for example /init in s6-overlay images),
    /// preserving attached init-entrypoint commands when needed, or to
    /// probe common distro init paths when the image does not declare one.
    #[arg(long, value_name = "PATH|auto")]
    pub init: Option<String>,

    /// Append an argv entry to the handoff init. Repeatable. Defaults
    /// to `[<--init>]` when empty.
    ///
    /// `allow_hyphen_values` lets values like `--unit=multi-user.target`
    /// pass through without clap trying to interpret them as flags.
    #[arg(
        long = "init-arg",
        value_name = "STR",
        allow_hyphen_values = true,
        requires = "init"
    )]
    pub init_arg: Vec<String>,

    /// Set an env var for the handoff init (KEY=VALUE). Repeatable.
    /// Merged on top of the inherited env.
    #[arg(long = "init-env", value_name = "KEY=VALUE", requires = "init")]
    pub init_env: Vec<String>,

    /// Set the guest hostname (defaults to a sandbox-name-derived hostname).
    #[arg(short = 'H', long)]
    pub hostname: Option<String>,

    /// Run commands as the specified user (e.g. nobody, 1000, 1000:1000).
    #[arg(short = 'u', long)]
    pub user: Option<String>,

    /// When to pull the image: always, if-missing (default), never.
    #[arg(long)]
    pub pull: Option<String>,

    /// Writable overlay upper size for OCI images (e.g. 4G, 8192M).
    #[arg(long = "oci-upper-size", value_name = "SIZE")]
    pub oci_upper_size: Option<String>,

    /// Log verbosity for the sandbox runtime (error, warn, info, debug, trace).
    #[arg(long)]
    pub log_level: Option<String>,

    // --- Lifecycle ---
    /// Kill the sandbox after this duration (e.g. 30s, 5m, 1h).
    #[arg(long)]
    pub max_duration: Option<String>,

    /// Stop the sandbox after this period of inactivity (e.g. 30s, 5m, 1h).
    #[arg(long)]
    pub idle_timeout: Option<String>,

    // --- Networking (requires "net" feature) ---
    /// Forward a host port to the sandbox (HOST:GUEST, BIND_ADDR:HOST:GUEST, and /udp variants).
    #[cfg(feature = "net")]
    #[arg(short, long)]
    pub port: Vec<String>,

    /// Disable all network access by default. Sugar for `--net-default deny`.
    /// Combine with `--net-rule allow@<target>` entries to build an
    /// allowlist; without rules, the guest has no network reachability.
    #[cfg(feature = "net")]
    #[arg(
        long = "no-net",
        conflicts_with_all = ["net_default", "net_default_egress", "net_default_ingress"]
    )]
    pub no_net: bool,

    /// Allow DNS responses pointing to private/internal IP addresses.
    #[cfg(feature = "net")]
    #[arg(long)]
    pub no_dns_rebind_protection: bool,

    /// Nameserver to forward DNS queries to (repeatable). Overrides the
    /// nameservers in the host's `/etc/resolv.conf`. Accepts `IP` (port
    /// defaults to 53) or `IP:PORT`.
    #[cfg(feature = "net")]
    #[arg(long, value_name = "ADDR")]
    pub dns_nameserver: Vec<String>,

    /// Per-DNS-query timeout in milliseconds. Default: 5000.
    #[cfg(feature = "net")]
    #[arg(long, value_name = "MS")]
    pub dns_query_timeout_ms: Option<u64>,

    /// IPv4 pool used for per-sandbox /30 guest subnets. Default: 172.16.0.0/12.
    #[cfg(feature = "net")]
    #[arg(long = "net-ipv4-pool", value_name = "CIDR")]
    pub net_ipv4_pool: Option<String>,

    /// IPv6 pool used for per-sandbox /64 guest prefixes. Default: fd42:6d73:62::/48.
    #[cfg(feature = "net")]
    #[arg(long = "net-ipv6-pool", value_name = "CIDR")]
    pub net_ipv6_pool: Option<String>,

    /// Network rule. Repeatable; each value is a comma-separated list of
    /// rule tokens. Token grammar:
    /// `<action>[:<direction>]@<target>[:<proto>[:<ports>]]`.
    ///
    /// Target kinds: IPs/CIDRs, domains (`example.com`), domain suffixes
    /// (`*.example.com` shorthand or `suffix=example.com`), and groups
    /// (`public`, `private`, `multicast`, ...). Suffixes must be at
    /// least two labels (e.g. `*.example.com`, not `*.com`).
    ///
    /// Examples: --net-rule "allow@public"
    /// --net-rule "deny@198.51.100.5,allow@public"
    /// --net-rule "allow:ingress@private"
    /// --net-rule "allow@example.com:tcp:443"
    /// --net-rule "deny@*.ads.example.com"
    #[cfg(feature = "net")]
    #[arg(long = "net-rule", value_name = "TOKENS")]
    pub net_rule: Vec<String>,

    /// Default action for traffic in both directions that doesn't match
    /// any `--net-rule`. Sets egress and ingress symmetrically; use
    /// `--net-default-egress` / `--net-default-ingress` to set them
    /// independently.
    #[cfg(feature = "net")]
    #[arg(
        long = "net-default",
        value_name = "ACTION",
        conflicts_with_all = ["net_default_egress", "net_default_ingress"],
    )]
    pub net_default: Option<String>,

    /// Default action for egress traffic that doesn't match any
    /// `--net-rule`. Default: deny (with an implicit allow@public rule
    /// when no other rules are present).
    #[cfg(feature = "net")]
    #[arg(long = "net-default-egress", value_name = "ACTION")]
    pub net_default_egress: Option<String>,

    /// Default action for ingress traffic that doesn't match any
    /// `--net-rule`. Default: allow (preserves today's unfiltered
    /// published-port behavior when no ingress rules are set).
    #[cfg(feature = "net")]
    #[arg(long = "net-default-ingress", value_name = "ACTION")]
    pub net_default_ingress: Option<String>,

    /// Limit the number of concurrent network connections.
    #[cfg(feature = "net")]
    #[arg(long)]
    pub max_connections: Option<usize>,

    /// Ship the host's trusted root CAs into the guest. Opt in to make
    /// outbound TLS work behind corporate MITM proxies (Warp Zero
    /// Trust, Zscaler, etc.) whose gateway CA is installed on the host
    /// but unknown to the guest's stock Mozilla bundle.
    #[cfg(feature = "net")]
    #[arg(long)]
    pub trust_host_cas: bool,

    // --- TLS interception ---
    /// Intercept and inspect HTTPS traffic via a built-in TLS proxy.
    #[cfg(feature = "net")]
    #[arg(long)]
    pub tls_intercept: bool,

    /// TCP port to apply TLS interception on (default: 443).
    #[cfg(feature = "net")]
    #[arg(long)]
    pub tls_intercept_port: Vec<u16>,

    /// Skip TLS interception for this domain (e.g. *.internal.com).
    #[cfg(feature = "net")]
    #[arg(long)]
    pub tls_bypass: Vec<String>,

    /// Allow QUIC/HTTP3 traffic (blocked by default when TLS interception is on).
    #[cfg(feature = "net")]
    #[arg(long)]
    pub no_block_quic: bool,

    /// Use a custom CA certificate for TLS interception (PEM file).
    #[cfg(feature = "net")]
    #[arg(long)]
    pub tls_intercept_ca_cert: Option<PathBuf>,

    /// Use a custom CA private key for TLS interception (PEM file).
    #[cfg(feature = "net")]
    #[arg(long)]
    pub tls_intercept_ca_key: Option<PathBuf>,

    /// Trust an additional CA certificate for upstream server verification (PEM file).
    /// Can be specified multiple times.
    #[cfg(feature = "net")]
    #[arg(long)]
    pub tls_upstream_ca_cert: Vec<PathBuf>,

    /// Trust an additional CA certificate only for matching upstream hosts (PATTERN=PATH).
    /// Can be specified multiple times.
    #[cfg(feature = "net")]
    #[arg(long, value_name = "PATTERN=PATH")]
    pub tls_upstream_ca_cert_for: Vec<String>,

    /// Disable upstream certificate verification for matching upstream hosts.
    /// Can be specified multiple times.
    #[cfg(feature = "net")]
    #[arg(long, value_name = "PATTERN")]
    pub tls_no_verify_upstream_for: Vec<String>,

    // --- Secrets ---
    /// Inject a secret that is only sent to an allowed host (ENV@HOST). The
    /// value is read from the host environment variable ENV at start time and
    /// stored only as a source reference, never inlined in the sandbox config.
    /// Inline `ENV=VALUE@HOST` is rejected; export the value and use `ENV@HOST`.
    #[cfg(feature = "net")]
    #[arg(long)]
    pub secret: Vec<String>,

    /// Action when a secret is sent to a disallowed host (block, block-and-log, block-and-terminate, passthrough).
    #[cfg(feature = "net")]
    #[arg(long)]
    pub on_secret_violation: Option<String>,
}

/// Parsed public CLI mount options.
#[derive(Debug, Default)]
struct CliMountOptions {
    readonly: bool,
    noexec: bool,
    nosuid: bool,
    nodev: bool,
    stat_virtualization: Option<microsandbox::sandbox::StatVirtualization>,
    host_permissions: Option<microsandbox::sandbox::HostPermissions>,
    size_mib: Option<u32>,
    quota_mib: Option<u32>,
    named_kind: Option<VolumeKind>,
    fstype: Option<String>,
    format: Option<DiskImageFormat>,
}

/// Which keyed options are valid for a public CLI mount flag.
#[derive(Debug, Clone, Copy, Default)]
struct CliMountOptionSupport {
    policies: bool,
    size: bool,
    quota: bool,
    named_kind: bool,
    fstype: bool,
    format: bool,
}

/// Parsed `SOURCE:DEST[:OPTIONS]` mount specification.
struct ParsedCliMountSpec<'a> {
    source: &'a str,
    guest: &'a str,
    options: CliMountOptions,
}

/// Expected host path kind for explicit bind mount flags.
enum HostPathKind {
    Directory,
    File,
}

/// File or directory copy behavior.
#[derive(Debug, Clone, Copy)]
enum CopyKind {
    Infer,
    File,
    Directory,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SandboxOpts {
    /// Returns true if any creation-time configuration flag was set.
    pub fn has_creation_flags(&self) -> bool {
        let base = self.cpus.is_some()
            || self.max_cpus.is_some()
            || self.memory.is_some()
            || self.max_memory.is_some()
            || !self.volume.is_empty()
            || !self.mount_dir.is_empty()
            || !self.mount_file.is_empty()
            || !self.mount_disk.is_empty()
            || !self.mount_named.is_empty()
            || self.workdir.is_some()
            || self.shell.is_some()
            || !self.env.is_empty()
            || !self.tmpfs.is_empty()
            || !self.script.is_empty()
            || !self.script_raw.is_empty()
            || !self.script_path.is_empty()
            || !self.copy.is_empty()
            || !self.copy_file.is_empty()
            || !self.copy_dir.is_empty()
            || !self.mkdir.is_empty()
            || !self.rm.is_empty()
            || self.entrypoint.is_some()
            || self.init.is_some()
            || !self.init_arg.is_empty()
            || !self.init_env.is_empty()
            || self.hostname.is_some()
            || self.user.is_some()
            || self.pull.is_some()
            || self.oci_upper_size.is_some()
            || self.log_level.is_some()
            || self.max_duration.is_some()
            || self.idle_timeout.is_some()
            || self.security.is_some();

        #[cfg(feature = "net")]
        let net = !self.port.is_empty()
            || self.no_net
            || self.no_dns_rebind_protection
            || !self.dns_nameserver.is_empty()
            || self.dns_query_timeout_ms.is_some()
            || !self.net_rule.is_empty()
            || self.net_default.is_some()
            || self.net_default_egress.is_some()
            || self.net_default_ingress.is_some()
            || self.max_connections.is_some()
            || self.trust_host_cas
            || self.tls_intercept
            || !self.tls_intercept_port.is_empty()
            || !self.tls_bypass.is_empty()
            || self.no_block_quic
            || self.tls_intercept_ca_cert.is_some()
            || self.tls_intercept_ca_key.is_some()
            || !self.tls_upstream_ca_cert.is_empty()
            || !self.tls_upstream_ca_cert_for.is_empty()
            || !self.tls_no_verify_upstream_for.is_empty()
            || !self.secret.is_empty()
            || self.on_secret_violation.is_some();

        #[cfg(not(feature = "net"))]
        let net = false;

        base || net
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Apply common sandbox options to a builder.
pub fn apply_sandbox_opts(
    mut builder: SandboxBuilder,
    opts: &SandboxOpts,
) -> anyhow::Result<SandboxBuilder> {
    // --- Basic resources ---
    if let Some(cpus) = opts.cpus {
        builder = builder.cpus(cpus);
    }
    if let Some(max_cpus) = opts.max_cpus {
        builder = builder.max_cpus(max_cpus);
    }
    if let Some(ref mem) = opts.memory {
        builder = builder.memory(ui::parse_size_mib(mem).map_err(anyhow::Error::msg)?);
    }
    if let Some(ref max_memory) = opts.max_memory {
        builder = builder.max_memory(ui::parse_size_mib(max_memory).map_err(anyhow::Error::msg)?);
    }
    if let Some(ref workdir) = opts.workdir {
        builder = builder.workdir(workdir);
    }
    if let Some(ref shell) = opts.shell {
        validate_shell(shell)?;
        builder = builder.shell(shell);
    }
    if let Some(ref timeout) = opts.replace_with_timeout {
        let d =
            parse_duration(timeout).map_err(|e| anyhow::anyhow!("--replace-with-timeout: {e}"))?;
        builder = builder.replace_with_timeout(d);
    } else if opts.replace {
        builder = builder.replace();
    }

    // --- Environment ---
    for env_str in &opts.env {
        let (k, v) = ui::parse_env(env_str).map_err(anyhow::Error::msg)?;
        builder = builder.env(k, v);
    }

    // --- Labels ---
    for label_str in &opts.label {
        let (k, v) = ui::parse_label(label_str);
        builder = builder.label(k, v);
    }

    // --- Volumes ---
    for vol_str in &opts.volume {
        builder = apply_volume(builder, vol_str)?;
    }
    for mount_str in &opts.mount_dir {
        builder = apply_explicit_dir_mount(builder, mount_str)?;
    }
    for mount_str in &opts.mount_file {
        builder = apply_explicit_file_mount(builder, mount_str)?;
    }
    for mount_str in &opts.mount_disk {
        builder = apply_explicit_disk_mount(builder, mount_str)?;
    }
    for mount_str in &opts.mount_named {
        builder = apply_explicit_named_mount(builder, mount_str)?;
    }

    // --- Tmpfs ---
    for tmpfs_str in &opts.tmpfs {
        let (path, size, options) = parse_tmpfs(tmpfs_str)?;
        builder = builder.volume(&path, move |mut m| {
            m = m.tmpfs();
            if let Some(size_mib) = size {
                m = m.size(size_mib);
            }
            if options.readonly {
                m = m.readonly();
            }
            if options.noexec {
                m = m.noexec();
            }
            if options.nosuid {
                m = m.nosuid();
            }
            if options.nodev {
                m = m.nodev();
            }
            m
        });
    }

    // --- Scripts ---
    for (name, content) in collect_scripts(
        opts.shell.as_deref(),
        &opts.script,
        &opts.script_raw,
        &opts.script_path,
    )? {
        builder = builder.script(name, content);
    }

    // --- Rootfs patches ---
    builder = apply_rootfs_patches(builder, opts)?;

    // --- Image/Runtime overrides ---
    if let Some(ref ep) = opts.entrypoint {
        builder = builder.entrypoint(vec![ep.clone()]);
    }
    if let Some(ref hostname) = opts.hostname {
        builder = builder.hostname(hostname);
    }
    if let Some(ref user) = opts.user {
        builder = builder.user(user);
    }
    if let Some(ref pull) = opts.pull {
        builder = builder.pull_policy(parse_pull_policy(pull)?);
    }
    if let Some(ref size) = opts.oci_upper_size {
        let size_mib = ui::parse_size_mib(size).map_err(anyhow::Error::msg)?;
        builder = builder.oci_upper_size(size_mib);
    }
    if let Some(ref security) = opts.security {
        builder = builder.security(parse_security_profile(security)?);
    }

    // --- Handoff init ---
    // clap's `requires = "init"` already enforces that --init-arg /
    // --init-env can't appear without --init, so we don't re-check here.
    if let Some(ref init_path) = opts.init {
        // `auto` is the magic sentinel that asks agentd to probe a
        // candidate list inside the guest rootfs. Anything else must
        // be an absolute path so the eventual execve can find it.
        if init_path != microsandbox_protocol::HANDOFF_INIT_AUTO
            && !std::path::Path::new(init_path).is_absolute()
        {
            anyhow::bail!("--init must be an absolute path or `auto`, got: {init_path}");
        }
        if opts.init_arg.is_empty() && opts.init_env.is_empty() {
            builder = builder.init(init_path);
        } else {
            let mut init_envs = Vec::with_capacity(opts.init_env.len());
            for entry in &opts.init_env {
                let (k, v) = ui::parse_env(entry).map_err(anyhow::Error::msg)?;
                init_envs.push((k, v));
            }
            let init_args = opts.init_arg.clone();
            builder = builder.init_with(init_path, |i| i.args(init_args).envs(init_envs));
        }
    }

    // --- Log level ---
    if let Some(ref level) = opts.log_level {
        builder = builder.log_level(parse_log_level(level)?);
    }

    // --- Lifecycle ---
    if let Some(ref dur) = opts.max_duration {
        builder = builder.max_duration(parse_duration_secs(dur)?);
    }
    if let Some(ref dur) = opts.idle_timeout {
        builder = builder.idle_timeout(parse_duration_secs(dur)?);
    }

    // --- Networking ---
    #[cfg(feature = "net")]
    {
        builder = apply_network_opts(builder, opts)?;
    }

    Ok(builder)
}

/// Apply creation-time rootfs patch options to the builder.
fn apply_rootfs_patches(
    mut builder: SandboxBuilder,
    opts: &SandboxOpts,
) -> anyhow::Result<SandboxBuilder> {
    for spec in &opts.copy {
        builder = builder.add_patch(parse_copy_arg("--copy", spec, CopyKind::Infer)?);
    }
    for spec in &opts.copy_file {
        builder = builder.add_patch(parse_copy_arg("--copy-file", spec, CopyKind::File)?);
    }
    for spec in &opts.copy_dir {
        builder = builder.add_patch(parse_copy_arg("--copy-dir", spec, CopyKind::Directory)?);
    }
    for path in &opts.mkdir {
        validate_guest_path("--mkdir", path)?;
        builder = builder.add_patch(Patch::Mkdir {
            path: path.clone(),
            mode: None,
        });
    }
    for path in &opts.rm {
        validate_guest_path("--rm", path)?;
        builder = builder.add_patch(Patch::Remove { path: path.clone() });
    }

    Ok(builder)
}

/// Parse a CLI copy patch argument.
fn parse_copy_arg(context: &str, spec: &str, kind: CopyKind) -> anyhow::Result<Patch> {
    let (src, dst) = parse_patch_src_dst(context, spec)?;
    build_copy_patch(context, src, dst, kind)
}

/// Parse `SRC:DST` into a host path and guest destination.
fn parse_patch_src_dst(context: &str, spec: &str) -> anyhow::Result<(PathBuf, String)> {
    let (src, dst) = split_source_guest_spec(context, spec)?;
    if src.is_empty() {
        anyhow::bail!("{context} source path cannot be empty");
    }
    validate_guest_path(context, dst)?;
    Ok((PathBuf::from(src), dst.to_string()))
}

/// Build a copy patch, validating host path kind.
fn build_copy_patch(
    context: &str,
    src: PathBuf,
    dst: String,
    kind: CopyKind,
) -> anyhow::Result<Patch> {
    let metadata = std::fs::metadata(&src)
        .map_err(|e| anyhow::anyhow!("{context}: stat {}: {e}", src.display()))?;

    match kind {
        CopyKind::Infer if metadata.is_dir() => Ok(Patch::CopyDir {
            src,
            dst,
            replace: false,
        }),
        CopyKind::Infer | CopyKind::File if metadata.is_file() => Ok(Patch::CopyFile {
            src,
            dst,
            mode: None,
            replace: false,
        }),
        CopyKind::File => anyhow::bail!("{context}: {} is not a file", src.display()),
        CopyKind::Directory if metadata.is_dir() => Ok(Patch::CopyDir {
            src,
            dst,
            replace: false,
        }),
        CopyKind::Directory => anyhow::bail!("{context}: {} is not a directory", src.display()),
        CopyKind::Infer => anyhow::bail!(
            "{context}: {} is not a regular file or directory",
            src.display()
        ),
    }
}

/// Validate a guest patch path.
fn validate_guest_path(context: &str, path: &str) -> anyhow::Result<()> {
    if !path.starts_with('/') {
        anyhow::bail!("{context}: guest path must be absolute: {path}");
    }
    if path.as_bytes().contains(&0) {
        anyhow::bail!("{context}: guest path contains a null byte");
    }
    Ok(())
}

/// Parse a volume spec and apply it to the builder.
///
/// Accepts: `SRC:DST[:ro|rw][,noexec][,nosuid][,nodev][,stat-virt=...][,host-perms=...]`.
pub fn apply_volume(builder: SandboxBuilder, spec: &str) -> anyhow::Result<SandboxBuilder> {
    let parsed = parse_cli_mount_spec(
        "volume",
        spec,
        CliMountOptionSupport {
            policies: true,
            quota: true,
            ..CliMountOptionSupport::default()
        },
    )?;

    let is_path = microsandbox_utils::looks_like_local_path_text(parsed.source);
    let source = parsed.source.to_string();
    let guest = parsed.guest.to_string();
    let options = parsed.options;
    Ok(builder.volume(guest, move |mut m| {
        let quota_mib = options.quota_mib;
        m = if is_path {
            let mut b = m.bind(&source);
            if let Some(q) = quota_mib {
                b = b.quota(q);
            }
            b
        } else {
            // A named volume routes its quota through the named sub-builder
            // rather than the bind-only `.quota()`.
            m.named_with(&source, move |mut v| {
                v = v.ensure_exists();
                if let Some(q) = quota_mib {
                    v = v.quota(q);
                }
                v
            })
        };
        if options.readonly {
            m = m.readonly();
        }
        if options.noexec {
            m = m.noexec();
        }
        if options.nosuid {
            m = m.nosuid();
        }
        if options.nodev {
            m = m.nodev();
        }
        if let Some(sv) = options.stat_virtualization {
            m = m.stat_virtualization(sv);
        }
        if let Some(hp) = options.host_permissions {
            m = m.host_permissions(hp);
        }
        m
    }))
}

/// Validate the public `-v/--volume` syntax without retaining a builder.
pub fn validate_volume_spec(spec: &str) -> anyhow::Result<()> {
    apply_volume(SandboxBuilder::new("__msb_volume_validation__"), spec).map(|_| ())
}

/// Validate an explicit `--mount-dir` syntax without retaining a builder.
pub fn validate_mount_dir_spec(spec: &str) -> anyhow::Result<()> {
    apply_explicit_dir_mount(SandboxBuilder::new("__msb_mount_dir_validation__"), spec).map(|_| ())
}

/// Validate an explicit `--mount-file` syntax without retaining a builder.
pub fn validate_mount_file_spec(spec: &str) -> anyhow::Result<()> {
    apply_explicit_file_mount(SandboxBuilder::new("__msb_mount_file_validation__"), spec)
        .map(|_| ())
}

/// Validate an explicit `--mount-disk` syntax without retaining a builder.
pub fn validate_mount_disk_spec(spec: &str) -> anyhow::Result<()> {
    apply_explicit_disk_mount(SandboxBuilder::new("__msb_mount_disk_validation__"), spec)
        .map(|_| ())
}

/// Validate an explicit `--mount-named` syntax without retaining a builder.
pub fn validate_mount_named_spec(spec: &str) -> anyhow::Result<()> {
    apply_explicit_named_mount(SandboxBuilder::new("__msb_mount_named_validation__"), spec)
        .map(|_| ())
}

/// Apply a `--mount-dir` spec to the builder.
pub fn apply_explicit_dir_mount(
    builder: SandboxBuilder,
    spec: &str,
) -> anyhow::Result<SandboxBuilder> {
    let parsed = parse_cli_mount_spec(
        "mount-dir",
        spec,
        CliMountOptionSupport {
            policies: true,
            quota: true,
            ..CliMountOptionSupport::default()
        },
    )?;
    ensure_host_kind("mount-dir", parsed.source, HostPathKind::Directory)?;

    let source = parsed.source.to_string();
    let guest = parsed.guest.to_string();
    let options = parsed.options;
    Ok(builder.volume(guest, move |m| {
        apply_common_mount_options(m.bind(&source), options)
    }))
}

/// Apply a `--mount-file` spec to the builder.
pub fn apply_explicit_file_mount(
    builder: SandboxBuilder,
    spec: &str,
) -> anyhow::Result<SandboxBuilder> {
    let parsed = parse_cli_mount_spec(
        "mount-file",
        spec,
        CliMountOptionSupport {
            policies: true,
            ..CliMountOptionSupport::default()
        },
    )?;
    ensure_host_kind("mount-file", parsed.source, HostPathKind::File)?;

    let source = parsed.source.to_string();
    let guest = parsed.guest.to_string();
    let options = parsed.options;
    Ok(builder.volume(guest, move |m| {
        apply_common_mount_options(m.bind(&source), options)
    }))
}

/// Apply a `--mount-disk` spec to the builder.
pub fn apply_explicit_disk_mount(
    builder: SandboxBuilder,
    spec: &str,
) -> anyhow::Result<SandboxBuilder> {
    let parsed = parse_cli_mount_spec(
        "mount-disk",
        spec,
        CliMountOptionSupport {
            fstype: true,
            format: true,
            ..CliMountOptionSupport::default()
        },
    )?;

    let source = parsed.source.to_string();
    let guest = parsed.guest.to_string();
    let options = parsed.options;
    Ok(builder.volume(guest, move |mut m| {
        m = m.disk(&source);
        if let Some(format) = options.format {
            m = m.format(format);
        }
        if let Some(fstype) = options.fstype.as_deref() {
            m = m.fstype(fstype);
        }
        apply_common_mount_options(m, options)
    }))
}

/// Apply a `--mount-named` spec to the builder.
pub fn apply_explicit_named_mount(
    builder: SandboxBuilder,
    spec: &str,
) -> anyhow::Result<SandboxBuilder> {
    let parsed = parse_cli_mount_spec(
        "mount-named",
        spec,
        CliMountOptionSupport {
            policies: true,
            size: true,
            quota: true,
            named_kind: true,
            ..CliMountOptionSupport::default()
        },
    )?;
    if microsandbox_utils::looks_like_local_path_text(parsed.source) {
        anyhow::bail!(
            "mount-named source must be a volume name, not a host path: {}",
            parsed.source
        );
    }
    if parsed.options.size_mib.is_some()
        && !matches!(parsed.options.named_kind, Some(VolumeKind::Disk))
    {
        anyhow::bail!("mount-named option `size` requires kind=disk");
    }
    if matches!(parsed.options.named_kind, Some(VolumeKind::Disk))
        && parsed.options.size_mib.is_none()
    {
        anyhow::bail!("mount-named kind=disk requires size=...");
    }
    if matches!(parsed.options.named_kind, Some(VolumeKind::Disk))
        && parsed.options.quota_mib.is_some()
    {
        anyhow::bail!("mount-named kind=disk does not support quota=...");
    }
    if matches!(parsed.options.named_kind, Some(VolumeKind::Disk))
        && (parsed.options.stat_virtualization.is_some()
            || parsed.options.host_permissions.is_some())
    {
        anyhow::bail!("mount-named kind=disk does not support stat-virt=... or host-perms=...");
    }

    let source = parsed.source.to_string();
    let guest = parsed.guest.to_string();
    let options = parsed.options;
    Ok(builder.volume(guest, move |m| {
        let mount = m.named_with(&source, |mut v| {
            v = v.ensure_exists();
            if let Some(kind) = options.named_kind {
                v = match kind {
                    VolumeKind::Directory => v.directory(),
                    VolumeKind::Disk => v.disk(),
                };
            }
            if let Some(size_mib) = options.size_mib {
                v = v.size(size_mib);
            }
            if let Some(quota_mib) = options.quota_mib {
                v = v.quota(quota_mib);
            }
            v
        });
        let mut common_options = options;
        common_options.quota_mib = None;
        apply_common_mount_options(mount, common_options)
    }))
}

/// Apply common read/mount behavior options to a mount builder.
fn apply_common_mount_options(mut mount: MountBuilder, options: CliMountOptions) -> MountBuilder {
    if options.readonly {
        mount = mount.readonly();
    }
    if options.noexec {
        mount = mount.noexec();
    }
    if options.nosuid {
        mount = mount.nosuid();
    }
    if options.nodev {
        mount = mount.nodev();
    }
    if let Some(sv) = options.stat_virtualization {
        mount = mount.stat_virtualization(sv);
    }
    if let Some(hp) = options.host_permissions {
        mount = mount.host_permissions(hp);
    }
    if let Some(quota) = options.quota_mib {
        mount = mount.quota(quota);
    }
    mount
}

/// Parse `SOURCE:DEST[:OPTIONS]` with mount-kind-specific option support.
fn parse_cli_mount_spec<'a>(
    context: &str,
    spec: &'a str,
    support: CliMountOptionSupport,
) -> anyhow::Result<ParsedCliMountSpec<'a>> {
    let (source, guest_and_opts) = split_source_guest_spec(context, spec)?;

    if source.is_empty() {
        anyhow::bail!("{context} source must not be empty");
    }

    let (guest, opts) = match guest_and_opts.split_once(':') {
        Some((g, o)) => (g, Some(o)),
        None => {
            if guest_and_opts.contains(',') {
                let suggestion = guest_and_opts
                    .split_once(',')
                    .map(|(guest, opts)| format!("{source}:{guest}:{opts}"))
                    .unwrap_or_else(|| format!("{source}:{guest_and_opts}:ro"));
                anyhow::bail!(
                    "{context} options must use source:guest:options syntax, \
                     for example {suggestion}"
                );
            }
            (guest_and_opts, None)
        }
    };

    if guest.is_empty() {
        anyhow::bail!("{context} guest path must not be empty");
    }

    Ok(ParsedCliMountSpec {
        source,
        guest,
        options: parse_cli_mount_options(opts, support)?,
    })
}

/// Split a `SOURCE:/guest[:options]` value without mistaking `C:\...` for the separator.
fn split_source_guest_spec<'a>(context: &str, spec: &'a str) -> anyhow::Result<(&'a str, &'a str)> {
    let separator = find_guest_path_separator(spec)
        .ok_or_else(|| anyhow::anyhow!("{context} must be in format source:/guest[:options]"))?;
    Ok((&spec[..separator], &spec[separator + 1..]))
}

/// Find the separator colon immediately before an absolute guest path.
fn find_guest_path_separator(spec: &str) -> Option<usize> {
    for (index, byte) in spec.bytes().enumerate() {
        if byte != b':' {
            continue;
        }
        if is_windows_drive_separator(spec, index) {
            continue;
        }
        if spec[index + 1..].starts_with('/') {
            return Some(index);
        }
    }
    None
}

/// Return true when `index` is the drive colon in a Windows path.
fn is_windows_drive_separator(spec: &str, index: usize) -> bool {
    #[cfg(windows)]
    {
        microsandbox_utils::is_windows_drive_separator_at(spec, index)
    }
    #[cfg(not(windows))]
    {
        let _ = (spec, index);
        false
    }
}

/// Parse public comma-separated mount options.
fn parse_cli_mount_options(
    opts: Option<&str>,
    support: CliMountOptionSupport,
) -> anyhow::Result<CliMountOptions> {
    use microsandbox::sandbox::{HostPermissions, StatVirtualization};

    let mut parsed = CliMountOptions::default();
    let mut seen_access = false;
    let mut seen_noexec = false;
    let mut seen_nosuid = false;
    let mut seen_nodev = false;
    let mut seen_stat_virt = false;
    let mut seen_host_perms = false;
    let mut seen_size = false;
    let mut seen_quota = false;
    let mut seen_named_kind = false;
    let mut seen_fstype = false;
    let mut seen_format = false;

    let Some(opts) = opts else {
        return Ok(parsed);
    };

    for opt in opts.split(',') {
        let opt = opt.trim();
        if opt.is_empty() {
            continue;
        }
        match opt {
            "ro" | "rw" => {
                if seen_access {
                    anyhow::bail!("mount option `ro`/`rw` specified more than once");
                }
                seen_access = true;
                parsed.readonly = opt == "ro";
            }
            "noexec" => {
                if seen_noexec {
                    anyhow::bail!("mount option `noexec` specified more than once");
                }
                seen_noexec = true;
                parsed.noexec = true;
            }
            "nosuid" => {
                if seen_nosuid {
                    anyhow::bail!("mount option `nosuid` specified more than once");
                }
                seen_nosuid = true;
                parsed.nosuid = true;
            }
            "nodev" => {
                if seen_nodev {
                    anyhow::bail!("mount option `nodev` specified more than once");
                }
                seen_nodev = true;
                parsed.nodev = true;
            }
            "suid" | "exec" | "dev" => {
                anyhow::bail!("unsupported mount option {opt:?}");
            }
            _ => {
                let (key, value) = opt.split_once('=').ok_or_else(|| {
                    anyhow::anyhow!("mount option {opt:?} must be a flag or key=value")
                })?;
                match key {
                    "stat-virt" if support.policies => {
                        if seen_stat_virt {
                            anyhow::bail!("mount option `stat-virt` specified more than once");
                        }
                        seen_stat_virt = true;
                        parsed.stat_virtualization = Some(match value {
                            "strict" => StatVirtualization::Strict,
                            "relaxed" => StatVirtualization::Relaxed,
                            "off" => StatVirtualization::Off,
                            other => anyhow::bail!(
                                "invalid stat-virt {other:?} (expected strict|relaxed|off)"
                            ),
                        });
                    }
                    "host-perms" if support.policies => {
                        if seen_host_perms {
                            anyhow::bail!("mount option `host-perms` specified more than once");
                        }
                        seen_host_perms = true;
                        parsed.host_permissions = Some(match value {
                            "private" => HostPermissions::Private,
                            "mirror" => HostPermissions::Mirror,
                            other => anyhow::bail!(
                                "invalid host-perms {other:?} (expected private|mirror)"
                            ),
                        });
                    }
                    "size" if support.size => {
                        if seen_size {
                            anyhow::bail!("mount option `size` specified more than once");
                        }
                        seen_size = true;
                        parsed.size_mib =
                            Some(ui::parse_size_mib(value).map_err(anyhow::Error::msg)?);
                    }
                    "quota" if support.quota => {
                        if seen_quota {
                            anyhow::bail!("mount option `quota` specified more than once");
                        }
                        seen_quota = true;
                        parsed.quota_mib =
                            Some(ui::parse_size_mib(value).map_err(anyhow::Error::msg)?);
                    }
                    "kind" if support.named_kind => {
                        if seen_named_kind {
                            anyhow::bail!("mount option `kind` specified more than once");
                        }
                        seen_named_kind = true;
                        parsed.named_kind = Some(match value {
                            "dir" | "directory" => VolumeKind::Directory,
                            "disk" => VolumeKind::Disk,
                            other => anyhow::bail!(
                                "invalid named volume kind {other:?} (expected dir|disk)"
                            ),
                        });
                    }
                    "fstype" if support.fstype => {
                        if seen_fstype {
                            anyhow::bail!("mount option `fstype` specified more than once");
                        }
                        seen_fstype = true;
                        validate_fstype_option(value)?;
                        parsed.fstype = Some(value.to_string());
                    }
                    "format" if support.format => {
                        if seen_format {
                            anyhow::bail!("mount option `format` specified more than once");
                        }
                        seen_format = true;
                        parsed.format = Some(value.parse::<DiskImageFormat>().map_err(|e| {
                            anyhow::anyhow!("invalid disk image format {value:?}: {e}")
                        })?);
                    }
                    "stat-virt" | "host-perms" | "size" | "quota" | "kind" | "fstype"
                    | "format" => {
                        anyhow::bail!("mount option `{key}` is not valid here");
                    }
                    other => anyhow::bail!("unknown mount option {other:?}"),
                }
            }
        }
    }

    Ok(parsed)
}

/// Validate a disk inner filesystem option before passing it to the SDK builder.
fn validate_fstype_option(value: &str) -> anyhow::Result<()> {
    if value.is_empty() {
        anyhow::bail!("mount option `fstype` must not be empty");
    }
    if value.chars().any(|c| matches!(c, ',' | ';' | ':' | '=')) {
        anyhow::bail!("mount option `fstype` must not contain ',', ';', ':', or '='");
    }
    Ok(())
}

/// Validate that an explicit host bind source has the requested kind.
fn ensure_host_kind(context: &str, source: &str, kind: HostPathKind) -> anyhow::Result<()> {
    let path = Path::new(source);
    let metadata =
        std::fs::metadata(path).map_err(|e| anyhow::anyhow!("{context} source {source:?}: {e}"))?;
    match kind {
        HostPathKind::Directory if metadata.is_dir() => Ok(()),
        HostPathKind::Directory => anyhow::bail!("{context} source is not a directory: {source}"),
        HostPathKind::File if metadata.is_file() => Ok(()),
        HostPathKind::File => anyhow::bail!("{context} source is not a regular file: {source}"),
    }
}

/// Apply network-related options to the builder (requires "net" feature).
#[cfg(feature = "net")]
fn apply_network_opts(
    mut builder: SandboxBuilder,
    opts: &SandboxOpts,
) -> anyhow::Result<SandboxBuilder> {
    use microsandbox_network::dns::Nameserver;

    // Port mappings.
    for port_str in &opts.port {
        let (bind, host, guest, udp) = parse_port_mapping(port_str)?;
        builder = if udp {
            builder.port_udp_bind(bind, host, guest)
        } else {
            builder.port_bind(bind, host, guest)
        };
    }

    // Secrets. `create` persists a host-side source reference, not the raw
    // value: the plaintext is read from the host environment at spawn time so
    // the durable config never stores secret material at rest.
    for secret_str in &opts.secret {
        let (env_var, host) = parse_secret(secret_str, "create")?;
        let source = microsandbox::sandbox::SecretSource::Env {
            var: env_var.clone(),
        };
        builder = builder.secret(|s| s.env(&env_var).source(source).allow_host(host));
    }

    // DNS, TLS, and other network configuration.
    let has_network_config = opts.no_dns_rebind_protection
        || !opts.dns_nameserver.is_empty()
        || opts.dns_query_timeout_ms.is_some()
        || !opts.net_rule.is_empty()
        || opts.no_net
        || opts.net_default.is_some()
        || opts.net_default_egress.is_some()
        || opts.net_default_ingress.is_some()
        || opts.net_ipv4_pool.is_some()
        || opts.net_ipv6_pool.is_some()
        || opts.max_connections.is_some()
        || opts.trust_host_cas
        || opts.tls_intercept
        || !opts.tls_intercept_port.is_empty()
        || !opts.tls_bypass.is_empty()
        || opts.no_block_quic
        || opts.tls_intercept_ca_cert.is_some()
        || opts.tls_intercept_ca_key.is_some()
        || !opts.tls_upstream_ca_cert.is_empty()
        || !opts.tls_upstream_ca_cert_for.is_empty()
        || !opts.tls_no_verify_upstream_for.is_empty()
        || opts.on_secret_violation.is_some();

    if has_network_config {
        let no_dns_rebind = opts.no_dns_rebind_protection;
        let dns_nameservers = opts
            .dns_nameserver
            .iter()
            .map(|s| s.parse::<Nameserver>().map_err(anyhow::Error::from))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let dns_query_timeout_ms = opts.dns_query_timeout_ms;
        let network_policy = build_network_policy(
            &opts.net_rule,
            opts.no_net,
            opts.net_default.as_deref(),
            opts.net_default_egress.as_deref(),
            opts.net_default_ingress.as_deref(),
        )?;
        let max_conn = opts.max_connections;
        let ipv4_pool = opts
            .net_ipv4_pool
            .as_deref()
            .map(|s| {
                s.parse::<ipnetwork::Ipv4Network>()
                    .map_err(anyhow::Error::from)
            })
            .transpose()?;
        let ipv6_pool = opts
            .net_ipv6_pool
            .as_deref()
            .map(|s| {
                s.parse::<ipnetwork::Ipv6Network>()
                    .map_err(anyhow::Error::from)
            })
            .transpose()?;
        let trust_host_cas = opts.trust_host_cas;
        let tls_intercept = opts.tls_intercept;
        let tls_ports = opts.tls_intercept_port.clone();
        let tls_bypass = opts.tls_bypass.clone();
        let no_block_quic = opts.no_block_quic;
        let intercept_ca_cert = opts.tls_intercept_ca_cert.clone();
        let intercept_ca_key = opts.tls_intercept_ca_key.clone();
        let upstream_ca_cert = opts.tls_upstream_ca_cert.clone();
        let scoped_upstream_ca_cert = opts
            .tls_upstream_ca_cert_for
            .iter()
            .map(|spec| parse_scoped_upstream_ca_cert(spec))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let no_verify_upstream_for = opts.tls_no_verify_upstream_for.clone();
        let violation_action = parse_violation_action(&opts.on_secret_violation)?;

        builder = builder.network(move |mut n| {
            n = n.dns(move |mut d| {
                if no_dns_rebind {
                    d = d.rebind_protection(false);
                }
                if !dns_nameservers.is_empty() {
                    d = d.nameservers(dns_nameservers);
                }
                if let Some(ms) = dns_query_timeout_ms {
                    d = d.query_timeout_ms(ms);
                }
                d
            });
            if let Some(policy) = network_policy {
                n = n.policy(policy);
            }
            if let Some(max) = max_conn {
                n = n.max_connections(max);
            }
            if let Some(pool) = ipv4_pool {
                n = n.ipv4_pool(pool);
            }
            if let Some(pool) = ipv6_pool {
                n = n.ipv6_pool(pool);
            }
            if trust_host_cas {
                n = n.trust_host_cas(true);
            }
            if let Some(action) = violation_action {
                n = n.on_secret_violation(|_| {
                    microsandbox_network::builder::ViolationActionBuilder::from_action(action)
                });
            }

            // TLS configuration.
            let has_tls = tls_intercept
                || !tls_ports.is_empty()
                || !tls_bypass.is_empty()
                || no_block_quic
                || intercept_ca_cert.is_some()
                || intercept_ca_key.is_some()
                || !upstream_ca_cert.is_empty()
                || !scoped_upstream_ca_cert.is_empty()
                || !no_verify_upstream_for.is_empty();

            if has_tls {
                let tls_ports = tls_ports.clone();
                let tls_bypass = tls_bypass.clone();
                let intercept_ca_cert = intercept_ca_cert.clone();
                let intercept_ca_key = intercept_ca_key.clone();
                let upstream_ca_cert = upstream_ca_cert.clone();
                let scoped_upstream_ca_cert = scoped_upstream_ca_cert.clone();
                let no_verify_upstream_for = no_verify_upstream_for.clone();
                n = n.tls(move |mut t| {
                    if !tls_ports.is_empty() {
                        t = t.intercepted_ports(tls_ports);
                    }
                    for domain in &tls_bypass {
                        t = t.bypass(domain);
                    }
                    if no_block_quic {
                        t = t.block_quic(false);
                    }
                    if let Some(ref cert) = intercept_ca_cert {
                        t = t.intercept_ca_cert(cert);
                    }
                    if let Some(ref key) = intercept_ca_key {
                        t = t.intercept_ca_key(key);
                    }
                    for path in &upstream_ca_cert {
                        t = t.upstream_ca_cert(path);
                    }
                    for (pattern, path) in &scoped_upstream_ca_cert {
                        t = t.upstream_ca_cert_for(pattern, path);
                    }
                    for pattern in &no_verify_upstream_for {
                        t = t.verify_upstream_for(pattern, false);
                    }
                    t
                });
            }

            n
        });
    }

    Ok(builder)
}

// --- Parsing helpers ---

/// Parse a duration string (e.g., "30s", "5m", "1h") into seconds.
pub fn parse_duration_secs(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    if let Some(n) = s.strip_suffix('s') {
        Ok(n.trim().parse::<u64>()?)
    } else if let Some(n) = s.strip_suffix('m') {
        Ok(n.trim().parse::<u64>()? * 60)
    } else if let Some(n) = s.strip_suffix('h') {
        Ok(n.trim().parse::<u64>()? * 3600)
    } else {
        Ok(s.parse::<u64>()?)
    }
}

/// Parse a duration string with sub-second granularity. Accepts `0`,
/// `500ms`, `5s`, `2m`, `1h`. Bare numbers are treated as seconds for
/// consistency with [`parse_duration_secs`].
pub fn parse_duration(s: &str) -> anyhow::Result<std::time::Duration> {
    let s = s.trim();
    if let Some(n) = s.strip_suffix("ms") {
        Ok(std::time::Duration::from_millis(n.trim().parse::<u64>()?))
    } else if let Some(n) = s.strip_suffix('s') {
        Ok(std::time::Duration::from_secs(n.trim().parse::<u64>()?))
    } else if let Some(n) = s.strip_suffix('m') {
        Ok(std::time::Duration::from_secs(
            n.trim().parse::<u64>()? * 60,
        ))
    } else if let Some(n) = s.strip_suffix('h') {
        Ok(std::time::Duration::from_secs(
            n.trim().parse::<u64>()? * 3600,
        ))
    } else {
        Ok(std::time::Duration::from_secs(s.parse::<u64>()?))
    }
}

/// Assemble a [`NetworkPolicy`] from `--net-rule`, `--net-default*`,
/// and `--no-net`. Returns `None` when no flag is set. Multiple
/// `--net-rule` invocations concatenate in argv order.
///
/// `--no-net` desugars to `--net-default deny`; clap rejects combining
/// it with the explicit defaults, so the four default-source params are
/// mutually exclusive on the caller side.
#[cfg(feature = "net")]
fn build_network_policy(
    rule_args: &[String],
    no_net: bool,
    default_both: Option<&str>,
    default_egress: Option<&str>,
    default_ingress: Option<&str>,
) -> anyhow::Result<Option<microsandbox_network::policy::NetworkPolicy>> {
    use microsandbox_network::policy::{Action, NetworkPolicy};

    use crate::net_rule::parse_rule_list;

    let no_flags = rule_args.is_empty()
        && !no_net
        && default_both.is_none()
        && default_egress.is_none()
        && default_ingress.is_none();
    if no_flags {
        return Ok(None);
    }

    let mut rules = Vec::new();
    for arg in rule_args {
        let parsed = parse_rule_list(arg).map_err(anyhow::Error::from)?;
        rules.extend(parsed);
    }

    let parse_action = |label: &str, raw: &str| -> anyhow::Result<Action> {
        match raw {
            "allow" => Ok(Action::Allow),
            "deny" => Ok(Action::Deny),
            other => anyhow::bail!("unknown {label} value {other:?}; expected `allow` or `deny`"),
        }
    };

    // `--no-net` and `--net-default` are siblings: both set egress and
    // ingress symmetrically. clap enforces they're mutex with each
    // other and with `--net-default-{egress,ingress}`, so at most one
    // source resolves here.
    let symmetric = if no_net {
        Some(Action::Deny)
    } else if let Some(raw) = default_both {
        Some(parse_action("--net-default", raw)?)
    } else {
        None
    };

    // When the user sets no defaults explicitly, fall through to
    // NetworkPolicy::public_only's defaults so behaviour stays in sync
    // with the preset.
    let preset = NetworkPolicy::public_only();
    let default_egress = match (symmetric, default_egress) {
        (_, Some(raw)) => parse_action("--net-default-egress", raw)?,
        (Some(action), None) => action,
        (None, None) => preset.default_egress,
    };
    let default_ingress = match (symmetric, default_ingress) {
        (_, Some(raw)) => parse_action("--net-default-ingress", raw)?,
        (Some(action), None) => action,
        (None, None) => preset.default_ingress,
    };

    Ok(Some(NetworkPolicy {
        default_egress,
        default_ingress,
        rules,
    }))
}

/// Parse a port spec:
/// - `HOST:GUEST`
/// - `BIND_ADDR:HOST:GUEST`
/// - `HOST:GUEST/udp`
/// - `BIND_ADDR:HOST:GUEST/udp`
///
/// IPv6 bind addresses must be bracketed, e.g. `[::]:8080:80`.
#[cfg(feature = "net")]
fn parse_port_mapping(spec: &str) -> anyhow::Result<(std::net::IpAddr, u16, u16, bool)> {
    use std::net::{IpAddr, Ipv4Addr};

    let (port_part, udp) = if let Some(p) = spec.strip_suffix("/udp") {
        (p, true)
    } else if let Some(p) = spec.strip_suffix("/tcp") {
        (p, false)
    } else {
        (spec, false)
    };

    let (bind, host_str, guest_str) = if let Some(rest) = port_part.strip_prefix('[') {
        let (bind_str, after_bracket) = rest.split_once("]:").ok_or_else(|| {
            anyhow::anyhow!("IPv6 port bind must be in format [ADDR]:HOST:GUEST[/udp]")
        })?;
        let (host_str, guest_str) = after_bracket
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("port must be in format [ADDR]:HOST:GUEST[/udp]"))?;
        let bind = bind_str
            .parse::<IpAddr>()
            .map_err(|_| anyhow::anyhow!("invalid bind address: {bind_str}"))?;
        (bind, host_str, guest_str)
    } else {
        let parts: Vec<_> = port_part.split(':').collect();
        match parts.as_slice() {
            [host_str, guest_str] => (IpAddr::V4(Ipv4Addr::LOCALHOST), *host_str, *guest_str),
            [bind_str, host_str, guest_str] => {
                let bind = bind_str
                    .parse::<IpAddr>()
                    .map_err(|_| anyhow::anyhow!("invalid bind address: {bind_str}"))?;
                (bind, *host_str, *guest_str)
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "port must be in format HOST:GUEST[/udp] or BIND_ADDR:HOST:GUEST[/udp]"
                ));
            }
        }
    };

    let host: u16 = host_str
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid host port: {host_str}"))?;
    let guest: u16 = guest_str
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid guest port: {guest_str}"))?;

    Ok((bind, host, guest, udp))
}

/// Parse a `--secret ENV@HOST` spec into `(env_var, host)` for `command`
/// (`create` or `modify`).
///
/// The value is NOT read here: the CLI records a host-side source reference
/// (`{kind: env, var: ENV}`) that is resolved from the host environment when
/// needed, so raw secret material never lands in shell history or process
/// listings.
///
/// The inline `ENV=VALUE@HOST` form is rejected loudly: the shell would leak
/// the value regardless, so the value path is SDK-only. Users are pointed at
/// the `ENV@HOST` env-var form instead.
pub(crate) fn parse_secret(spec: &str, command: &str) -> anyhow::Result<(String, String)> {
    if let Some(eq_pos) = spec.find('=') {
        let env_var = &spec[..eq_pos];
        anyhow::bail!(
            "inline secret values (`{env_var}=VALUE@HOST`) are not supported by `{command}`: \
             the value would be stored in the sandbox config at rest. Export the value as a \
             host environment variable and reference it with `{env_var}@HOST` instead, which \
             is resolved from the environment at start time."
        );
    }

    let at_pos = spec
        .rfind('@')
        .ok_or_else(|| anyhow::anyhow!("secret must be in format ENV@HOST"))?;
    let env_var = spec[..at_pos].to_string();
    let host = spec[at_pos + 1..].to_string();

    if env_var.is_empty() || host.is_empty() {
        anyhow::bail!("secret must be in format ENV@HOST (all parts required)");
    }

    Ok((env_var, host))
}

/// Parse a scoped upstream CA spec: `PATTERN=PATH`.
#[cfg(feature = "net")]
fn parse_scoped_upstream_ca_cert(spec: &str) -> anyhow::Result<(String, PathBuf)> {
    let (pattern, path) = spec
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("scoped upstream CA must be in format PATTERN=PATH"))?;

    if pattern.is_empty() || path.is_empty() {
        anyhow::bail!("scoped upstream CA must be in format PATTERN=PATH (both parts required)");
    }

    Ok((pattern.to_string(), PathBuf::from(path)))
}

/// Parse a violation action string.
#[cfg(feature = "net")]
fn parse_violation_action(
    s: &Option<String>,
) -> anyhow::Result<Option<microsandbox_network::secrets::config::ViolationAction>> {
    use microsandbox_network::secrets::config::{HostPattern, ViolationAction};
    match s.as_deref() {
        None => Ok(None),
        Some("block") => Ok(Some(ViolationAction::Block)),
        Some("block-and-log") => Ok(Some(ViolationAction::BlockAndLog)),
        Some("block-and-terminate") => Ok(Some(ViolationAction::BlockAndTerminate)),
        Some("passthrough") => Ok(Some(ViolationAction::Passthrough(vec![HostPattern::Any]))),
        Some(other) => anyhow::bail!(
            "invalid violation action: {other} (expected: block, block-and-log, block-and-terminate, passthrough)"
        ),
    }
}

/// Parse a tmpfs spec: `PATH`, `PATH:SIZE`, `PATH:OPTIONS`, or `PATH:SIZE:OPTIONS`.
fn parse_tmpfs(spec: &str) -> anyhow::Result<(String, Option<u32>, CliMountOptions)> {
    let mut parts = spec.splitn(3, ':');
    let path = parts.next().unwrap_or_default();
    if path.is_empty() {
        anyhow::bail!("tmpfs path must not be empty");
    }

    let Some(second) = parts.next() else {
        return Ok((path.to_string(), None, CliMountOptions::default()));
    };

    let support = CliMountOptionSupport {
        size: true,
        ..CliMountOptionSupport::default()
    };

    let (positional_size, option_block) = match parts.next() {
        Some(opts) => {
            if second.is_empty() {
                anyhow::bail!("tmpfs size must not be empty before options");
            }
            (
                Some(ui::parse_size_mib(second).map_err(anyhow::Error::msg)?),
                Some(opts),
            )
        }
        None if looks_like_mount_options(second) => (None, Some(second)),
        None => (
            Some(ui::parse_size_mib(second).map_err(anyhow::Error::msg)?),
            None,
        ),
    };

    let options = parse_cli_mount_options(option_block, support)?;
    if positional_size.is_some() && options.size_mib.is_some() {
        anyhow::bail!("tmpfs size specified more than once");
    }
    let size_mib = positional_size.or(options.size_mib);

    Ok((path.to_string(), size_mib, options))
}

/// Returns true when a tmpfs segment is clearly an option block, not a size.
fn looks_like_mount_options(segment: &str) -> bool {
    segment.contains(',')
        || segment.contains('=')
        || matches!(
            segment,
            "ro" | "rw" | "noexec" | "nosuid" | "nodev" | "suid" | "exec" | "dev"
        )
}

fn parse_security_profile(value: &str) -> anyhow::Result<SecurityProfile> {
    match value {
        "default" => Ok(SecurityProfile::Default),
        "restricted" => Ok(SecurityProfile::Restricted),
        other => anyhow::bail!("invalid security profile {other:?}"),
    }
}

/// Resolve `--script` / `--script-raw` / `--script-path` specs into a
/// deduped list of `(name, content)` pairs preserving argv order:
/// inline shell snippets first, then raw inline, then path-backed.
/// Duplicate names across any source are rejected. `shell` is used to
/// generate the shebang for `--script` entries only.
fn collect_scripts(
    shell: Option<&str>,
    scripts: &[String],
    raw_scripts: &[String],
    paths: &[String],
) -> anyhow::Result<Vec<(String, String)>> {
    use std::collections::HashSet;

    let mut out = Vec::with_capacity(scripts.len() + raw_scripts.len() + paths.len());
    let mut seen: HashSet<String> = HashSet::new();

    for spec in scripts {
        let (name, body) = parse_script_spec(spec, "script")?;
        if !seen.insert(name.clone()) {
            anyhow::bail!("script name '{name}' specified more than once");
        }
        let decoded = decode_script_escapes(&body);
        out.push((name, wrap_shell_script(shell, &decoded)));
    }
    for spec in raw_scripts {
        let (name, body) = parse_script_spec(spec, "script-raw")?;
        if !seen.insert(name.clone()) {
            anyhow::bail!("script name '{name}' specified more than once");
        }
        out.push((name, body));
    }
    for spec in paths {
        let (name, content) = parse_script_path(spec)?;
        if !seen.insert(name.clone()) {
            anyhow::bail!("script name '{name}' specified more than once");
        }
        out.push((name, content));
    }
    Ok(out)
}

/// Parse a `NAME=BODY` spec for `--script` / `--script-raw`. Splits on
/// the first `=` so bodies may freely contain `=`. `flag` is used in
/// the error message.
fn parse_script_spec(spec: &str, flag: &str) -> anyhow::Result<(String, String)> {
    let (name, body) = spec
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("{flag} must be in format NAME=BODY"))?;
    if name.is_empty() {
        anyhow::bail!("script name must not be empty (NAME=BODY)");
    }
    Ok((name.to_string(), body.to_string()))
}

/// Reject `--shell` values that would corrupt the generated shebang
/// line or fail to exec interactively. Whitespace (including newlines)
/// and NUL break shebang parsing; an empty string or `/` leave no
/// interpreter for the kernel to run.
fn validate_shell(shell: &str) -> anyhow::Result<()> {
    if shell.is_empty() {
        anyhow::bail!("--shell must not be empty");
    }
    if shell.chars().any(|c| c.is_whitespace() || c == '\0') {
        anyhow::bail!(
            "--shell must not contain whitespace or NUL (got {shell:?}); \
             use --script-raw or --script-path if you need a custom shebang"
        );
    }
    if shell == "/" {
        anyhow::bail!("--shell {shell:?} is not a valid interpreter");
    }
    Ok(())
}

/// Build the shebang line for a `--script` snippet. Absolute paths
/// (`/bin/bash`) are used directly; bare names (`bash`) go through
/// `/usr/bin/env`.
fn script_shebang(shell: Option<&str>) -> String {
    let shell = shell.unwrap_or("/bin/sh");
    if shell.contains('/') {
        format!("#!{shell}")
    } else {
        format!("#!/usr/bin/env {shell}")
    }
}

/// Decode the small set of backslash escapes supported by `--script`.
/// Unknown escapes (e.g. `\d`) are preserved verbatim so regexes and
/// paths survive untouched.
fn decode_script_escapes(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('\\') => out.push('\\'),
            Some('"') => out.push('"'),
            Some('\'') => out.push('\''),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// Wrap a decoded shell snippet with the generated shebang and ensure
/// a trailing newline so the file is well-formed.
fn wrap_shell_script(shell: Option<&str>, body: &str) -> String {
    let mut script = script_shebang(shell);
    script.push('\n');
    script.push_str(body);
    if !script.ends_with('\n') {
        script.push('\n');
    }
    script
}

/// Parse a script-from-file spec: `NAME:PATH` and read file content.
fn parse_script_path(spec: &str) -> anyhow::Result<(String, String)> {
    let (name, path) = spec
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("script-path must be in format NAME:PATH"))?;
    if name.is_empty() {
        anyhow::bail!("script name must not be empty (NAME:PATH)");
    }
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read script file '{path}': {e}"))?;
    Ok((name.to_string(), content))
}

/// Parse a pull policy string.
fn parse_pull_policy(s: &str) -> anyhow::Result<microsandbox::sandbox::PullPolicy> {
    use microsandbox::sandbox::PullPolicy;
    match s {
        "always" => Ok(PullPolicy::Always),
        "if-missing" => Ok(PullPolicy::IfMissing),
        "never" => Ok(PullPolicy::Never),
        _ => anyhow::bail!("invalid pull policy: {s} (expected: always, if-missing, never)"),
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Command resolution
//--------------------------------------------------------------------------------------------------

/// Parse a log level string.
fn parse_log_level(s: &str) -> anyhow::Result<microsandbox::LogLevel> {
    use microsandbox::LogLevel;
    match s {
        "error" => Ok(LogLevel::Error),
        "warn" => Ok(LogLevel::Warn),
        "info" => Ok(LogLevel::Info),
        "debug" => Ok(LogLevel::Debug),
        "trace" => Ok(LogLevel::Trace),
        _ => anyhow::bail!("invalid log level: {s} (expected: error, warn, info, debug, trace)"),
    }
}

/// Return whether this invocation should use the terminal-attached PTY path.
pub(crate) fn use_interactive_tty(stdin_is_terminal: bool, no_tty: bool) -> bool {
    stdin_is_terminal && !no_tty
}

/// Resolve the command to run following OCI semantics.
///
/// Returns `(Some(cmd), args)` or `(None, _)` when no command is available.
///
/// Resolution order when the user supplies no explicit command:
/// 1. Image entrypoint [+ cmd]
/// 2. Image cmd alone
/// 3. `config.spec.runtime.shell` (interactive only)
/// 4. `/bin/sh` (interactive only)
pub fn resolve_command(
    config: &microsandbox::sandbox::SandboxConfig,
    user_command: Vec<String>,
    interactive: bool,
) -> anyhow::Result<(Option<String>, Vec<String>)> {
    // User supplied an explicit command — prepend entrypoint if set.
    if !user_command.is_empty() {
        return match &config.spec.runtime.entrypoint {
            Some(ep) if !ep.is_empty() => {
                let bin = ep[0].clone();
                let args = ep[1..].iter().cloned().chain(user_command).collect();
                Ok((Some(bin), args))
            }
            _ => {
                let mut parts = user_command;
                let cmd = parts.remove(0);
                Ok((Some(cmd), parts))
            }
        };
    }

    // No user command — try the image's entrypoint/cmd.
    if let Some((cmd, cmd_args)) = resolve_image_command(config) {
        return Ok((Some(cmd), cmd_args));
    }

    // Fall back to configured shell (or /bin/sh) in interactive mode.
    if interactive {
        let shell = config.spec.runtime.shell.as_deref().unwrap_or("/bin/sh");
        return Ok((Some(shell.to_string()), vec![]));
    }

    // Non-interactive with nothing to run.
    ui::warn("no command provided and stdin is not a terminal");
    Ok((None, vec![]))
}

/// Resolve the command for `msb exec`.
///
/// Unlike `msb run`, an explicit `msb exec SANDBOX -- CMD ...` should execute
/// `CMD` directly. The sandbox's persisted entrypoint describes the original
/// workload start shape; reapplying it here would turn ordinary maintenance
/// commands like `msb exec app -- date` into `entrypoint date`.
pub fn resolve_exec_command(
    config: &microsandbox::sandbox::SandboxConfig,
    user_command: Vec<String>,
    interactive: bool,
) -> anyhow::Result<(Option<String>, Vec<String>)> {
    if !user_command.is_empty() {
        let mut parts = user_command;
        let cmd = parts.remove(0);
        return Ok((Some(cmd), parts));
    }

    resolve_command(config, user_command, interactive)
}

/// Resolve the default process from OCI image config.
///
/// Follows OCI semantics:
/// - `entrypoint` + `cmd`: entrypoint is the binary, cmd provides default arguments.
/// - `entrypoint` only: entrypoint is the full command.
/// - `cmd` only: cmd[0] is the binary, cmd[1..] are arguments.
/// - Neither set: returns `None`.
fn resolve_image_command(
    config: &microsandbox::sandbox::SandboxConfig,
) -> Option<(String, Vec<String>)> {
    match (&config.spec.runtime.entrypoint, &config.spec.runtime.cmd) {
        (Some(ep), cmd) if !ep.is_empty() => {
            let bin = ep[0].clone();
            let args = ep[1..]
                .iter()
                .chain(cmd.iter().flatten())
                .cloned()
                .collect();
            Some((bin, args))
        }
        (_, Some(cmd)) if !cmd.is_empty() => {
            let bin = cmd[0].clone();
            let args = cmd[1..].to_vec();
            Some((bin, args))
        }
        _ => None,
    }
}

/// Parse an rlimit spec: `RESOURCE=LIMIT` or `RESOURCE=SOFT:HARD`.
pub fn parse_rlimit(
    spec: &str,
) -> anyhow::Result<(microsandbox::sandbox::RlimitResource, u64, u64)> {
    use microsandbox::sandbox::RlimitResource;
    use microsandbox_protocol::exec::ExecRlimit;

    let rlimit = spec.parse::<ExecRlimit>().map_err(anyhow::Error::msg)?;
    let resource =
        RlimitResource::try_from(rlimit.resource.as_str()).map_err(anyhow::Error::msg)?;

    Ok((resource, rlimit.soft, rlimit.hard))
}

/// Parse repeatable `--label KEY[=VALUE]` selector flags into key/value pairs.
/// A bare `KEY` yields an empty value (a valueless marker label).
pub fn parse_label_selectors(labels: &[String]) -> Vec<(String, String)> {
    labels.iter().map(|s| ui::parse_label(s)).collect()
}

/// Build a [`SandboxFilter`] from repeatable `--label KEY[=VALUE]` selector flags.
pub fn label_filter(labels: &[String]) -> SandboxFilter {
    SandboxFilter::new().labels(parse_label_selectors(labels))
}

/// Resolve the set of sandbox names a command should act on, given explicit
/// `names` plus `--label KEY=VALUE` selectors. Label-matched sandboxes are
/// unioned with the explicit names (order-preserving, de-duplicated). Selectors
/// are AND-matched: a sandbox must carry every label to be selected.
pub async fn resolve_selected_sandboxes(
    names: &[String],
    labels: &[String],
) -> anyhow::Result<Vec<String>> {
    let mut seen = std::collections::HashSet::new();
    let mut resolved = Vec::new();

    for name in names {
        if seen.insert(name.clone()) {
            resolved.push(name.clone());
        }
    }

    if !labels.is_empty() {
        for handle in Sandbox::list_with(label_filter(labels)).await? {
            if seen.insert(handle.name().to_string()) {
                resolved.push(handle.name().to_string());
            }
        }
    }

    Ok(resolved)
}

/// Resolve target sandboxes for a bulk command (`stop`/`start`/`remove`),
/// applying the standard guards: error when neither names nor `--label`
/// selectors are given, and emit a notice when selectors matched nothing.
pub async fn resolve_bulk_targets(
    names: &[String],
    labels: &[String],
    quiet: bool,
) -> anyhow::Result<Vec<String>> {
    if names.is_empty() && labels.is_empty() {
        anyhow::bail!("specify one or more sandbox names or --label selectors");
    }

    let resolved = resolve_selected_sandboxes(names, labels).await?;
    if resolved.is_empty() && !quiet {
        ui::warn("no sandboxes matched the given labels");
    }

    Ok(resolved)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use microsandbox::sandbox::{
        HostPermissions, MountOptions, Patch, RootfsSource, SandboxConfig, StatVirtualization,
        VolumeMount,
    };

    use super::*;

    #[test]
    fn parse_secret_returns_env_and_host_reference() {
        // The value is NOT read here: `create` persists a source reference and
        // the spawn resolver reads the host env at start time.
        let (env_var, host) =
            parse_secret("MSB_PARSE_SECRET_TOKEN@api.example.com", "create").unwrap();

        assert_eq!(env_var, "MSB_PARSE_SECRET_TOKEN");
        assert_eq!(host, "api.example.com");
    }

    #[test]
    fn parse_secret_rejects_inline_value_syntax() {
        for command in ["create", "modify"] {
            let err = parse_secret("API_KEY=literal@api.example.com", command)
                .unwrap_err()
                .to_string();

            assert!(
                err.contains("inline secret values"),
                "unexpected error: {err}"
            );
            assert!(
                err.contains(&format!("`{command}`")),
                "unexpected error: {err}"
            );
            assert!(err.contains("API_KEY@HOST"), "unexpected error: {err}");
        }
    }

    #[test]
    fn parse_secret_rejects_missing_parts() {
        assert!(parse_secret("API_KEY", "create").is_err());
        assert!(parse_secret("@api.example.com", "create").is_err());
        assert!(parse_secret("API_KEY@", "create").is_err());
    }

    #[cfg(feature = "net")]
    #[test]
    fn parse_scoped_upstream_ca_cert_accepts_pattern_and_path() {
        let (pattern, path) =
            parse_scoped_upstream_ca_cert("*.internal=/tmp/internal-ca.pem").unwrap();

        assert_eq!(pattern, "*.internal");
        assert_eq!(path, PathBuf::from("/tmp/internal-ca.pem"));
    }

    #[cfg(feature = "net")]
    #[test]
    fn parse_scoped_upstream_ca_cert_rejects_missing_separator() {
        let err = parse_scoped_upstream_ca_cert("*.internal:/tmp/internal-ca.pem")
            .unwrap_err()
            .to_string();

        assert_eq!(err, "scoped upstream CA must be in format PATTERN=PATH");
    }

    #[cfg(feature = "net")]
    #[test]
    fn parse_violation_action_accepts_passthrough() {
        let action = parse_violation_action(&Some("passthrough".to_string()))
            .expect("passthrough should parse")
            .expect("action should be present");

        assert!(matches!(
            action,
            microsandbox_network::secrets::config::ViolationAction::Passthrough(_)
        ));
    }

    #[tokio::test]
    async fn apply_sandbox_opts_sets_oci_upper_size() {
        let opts = SandboxOpts {
            oci_upper_size: Some("8G".to_string()),
            ..Default::default()
        };
        let config = apply_sandbox_opts(SandboxBuilder::new("test").image("alpine"), &opts)
            .unwrap()
            .build()
            .await
            .unwrap();

        match config.spec.image {
            RootfsSource::Oci(oci) => assert_eq!(oci.upper_size_mib, Some(8192)),
            other => panic!("expected Oci, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn apply_sandbox_opts_sets_security_profile() {
        let opts = SandboxOpts {
            security: Some("restricted".to_string()),
            ..Default::default()
        };
        let config = apply_sandbox_opts(SandboxBuilder::new("test").image("alpine"), &opts)
            .unwrap()
            .build()
            .await
            .unwrap();

        assert_eq!(config.spec.security_profile, SecurityProfile::Restricted);
    }

    #[tokio::test]
    async fn apply_sandbox_opts_adds_cli_rootfs_patches() {
        let file = write_temp("config");
        let dir = make_temp_dir("msb-patch-dir");

        let opts = SandboxOpts {
            copy_file: vec![format!("{}:/etc/app/config.toml", file.display())],
            copy_dir: vec![format!("{}:/etc/app/certs", dir.display())],
            mkdir: vec!["/var/cache/app".into()],
            rm: vec!["/etc/motd".into()],
            ..Default::default()
        };
        let config = apply_sandbox_opts(SandboxBuilder::new("test").image("alpine"), &opts)
            .unwrap()
            .build()
            .await
            .unwrap();

        assert!(matches!(
            &config.spec.patches[0],
            Patch::CopyFile { src, dst, .. }
                if src == &file && dst == "/etc/app/config.toml"
        ));
        assert!(matches!(
            &config.spec.patches[1],
            Patch::CopyDir { src, dst, .. }
                if src == &dir && dst == "/etc/app/certs"
        ));
        assert!(matches!(
            &config.spec.patches[2],
            Patch::Mkdir { path, .. } if path == "/var/cache/app"
        ));
        assert!(matches!(
            &config.spec.patches[3],
            Patch::Remove { path } if path == "/etc/motd"
        ));

        let _ = std::fs::remove_file(file);
        let _ = std::fs::remove_dir_all(dir);
    }

    //----------------------------------------------------------------------------------------------
    // Tests: apply_volume / -v parser
    //----------------------------------------------------------------------------------------------

    /// Apply a single `-v` spec to a fresh builder and return the resulting mount.
    async fn build_one(spec: &str) -> VolumeMount {
        let builder = SandboxBuilder::new("test").image("/tmp/rootfs");
        let builder = apply_volume(builder, spec).unwrap();
        let config = builder.build().await.unwrap();
        config.spec.mounts.into_iter().next().unwrap()
    }

    async fn build_explicit(
        spec: &str,
        apply: fn(SandboxBuilder, &str) -> anyhow::Result<SandboxBuilder>,
    ) -> VolumeMount {
        let builder = SandboxBuilder::new("test").image("alpine");
        let config = apply(builder, spec).unwrap().build().await.unwrap();
        config.spec.mounts.into_iter().next().unwrap()
    }

    #[tokio::test]
    async fn test_apply_volume_bind_defaults_to_strict_private() {
        let mount = build_one("/host:/guest").await;
        match mount {
            VolumeMount::Bind {
                stat_virtualization,
                host_permissions,
                options,
                ..
            } => {
                assert!(matches!(stat_virtualization, StatVirtualization::Strict));
                assert!(matches!(host_permissions, HostPermissions::Private));
                assert_eq!(options, MountOptions::default());
            }
            other => panic!("expected Bind, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_apply_volume_ro_flag() {
        let mount = build_one("/host:/guest:ro").await;
        match mount {
            VolumeMount::Bind { options, .. } => assert!(options.readonly),
            other => panic!("expected Bind, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_apply_volume_explicit_security_mount_flags() {
        let mount = build_one("/host:/guest:nosuid,nodev").await;
        match mount {
            VolumeMount::Bind { options, .. } => {
                assert!(!options.readonly);
                assert!(!options.noexec);
                assert!(options.nosuid);
                assert!(options.nodev);
            }
            other => panic!("expected Bind, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_apply_volume_stat_virt_relaxed() {
        let mount = build_one("/host:/guest:ro,noexec,stat-virt=relaxed").await;
        match mount {
            VolumeMount::Bind {
                stat_virtualization,
                options,
                ..
            } => {
                assert!(matches!(stat_virtualization, StatVirtualization::Relaxed));
                assert!(options.readonly);
                assert!(options.noexec);
            }
            other => panic!("expected Bind, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_apply_volume_host_perms_mirror() {
        let mount = build_one("./project:/work:host-perms=mirror").await;
        match mount {
            VolumeMount::Bind {
                host_permissions, ..
            } => {
                assert!(matches!(host_permissions, HostPermissions::Mirror));
            }
            other => panic!("expected Bind, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_apply_volume_combined_policies() {
        // Off + Mirror is rejected at build; use Relaxed + Mirror instead.
        let mount = build_one("/mnt:/host:ro,stat-virt=relaxed,host-perms=mirror").await;
        match mount {
            VolumeMount::Bind {
                stat_virtualization,
                host_permissions,
                options,
                ..
            } => {
                assert!(matches!(stat_virtualization, StatVirtualization::Relaxed));
                assert!(matches!(host_permissions, HostPermissions::Mirror));
                assert!(options.readonly);
            }
            other => panic!("expected Bind, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_apply_volume_rejects_off_plus_mirror_at_sandbox_build() {
        // The Off+Mirror conflict surfaces at SandboxBuilder.build() time
        // because MountBuilder.build() is deferred inside the volume closure.
        let builder = SandboxBuilder::new("test").image("/tmp/rootfs");
        let builder = apply_volume(builder, "/mnt:/host:stat-virt=off,host-perms=mirror")
            .expect("apply_volume defers validation");
        let err = builder.build().await.unwrap_err();
        assert!(
            err.to_string().contains("Off cannot be combined with"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn test_apply_volume_named() {
        let mount = build_one("mycache:/data:stat-virt=relaxed").await;
        match mount {
            VolumeMount::Named {
                name,
                stat_virtualization,
                create,
                ..
            } => {
                assert_eq!(name, "mycache");
                assert!(matches!(stat_virtualization, StatVirtualization::Relaxed));
                assert_eq!(
                    create.as_ref().map(|create| create.mode()),
                    Some(microsandbox::sandbox::NamedVolumeMode::EnsureExists)
                );
            }
            other => panic!("expected Named, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_apply_explicit_dir_mount() {
        let dir = make_temp_dir("msb-mount-dir");
        let spec = format!("{}:/work:ro,host-perms=mirror", dir.display());
        let mount = build_explicit(&spec, apply_explicit_dir_mount).await;
        match mount {
            VolumeMount::Bind {
                host,
                guest,
                host_permissions,
                options,
                ..
            } => {
                assert_eq!(host, dir);
                assert_eq!(guest, "/work");
                assert!(options.readonly);
                assert!(matches!(host_permissions, HostPermissions::Mirror));
            }
            other => panic!("expected Bind, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_apply_explicit_file_mount() {
        let file = write_temp("fixture");
        let spec = format!("{}:/fixture:ro,noexec", file.display());
        let mount = build_explicit(&spec, apply_explicit_file_mount).await;
        match mount {
            VolumeMount::Bind {
                host,
                guest,
                options,
                ..
            } => {
                assert_eq!(host, file);
                assert_eq!(guest, "/fixture");
                assert!(options.readonly);
                assert!(options.noexec);
            }
            other => panic!("expected Bind, got {other:?}"),
        }
    }

    #[tokio::test]
    #[cfg(windows)]
    async fn test_apply_explicit_dir_mount_with_windows_drive_path() {
        let dir = make_temp_dir("msb-mount-dir-drive");
        let spec = format!("{}:/work:ro", dir.display());
        let mount = build_explicit(&spec, apply_explicit_dir_mount).await;
        match mount {
            VolumeMount::Bind {
                host,
                guest,
                options,
                ..
            } => {
                assert_eq!(host, dir);
                assert_eq!(guest, "/work");
                assert!(options.readonly);
            }
            other => panic!("expected Bind, got {other:?}"),
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_parse_copy_patch_with_windows_drive_path() {
        let file = write_temp("fixture");
        let spec = format!("{}:/guest/fixture", file.display());
        let (src, dst) = parse_patch_src_dst("--copy-file", &spec).unwrap();
        assert_eq!(src, file);
        assert_eq!(dst, "/guest/fixture");
    }

    #[tokio::test]
    async fn test_apply_explicit_disk_mount() {
        let disk = write_temp("not a real filesystem, just validating config");
        let spec = format!(
            "{}:/data:format=qcow2,fstype=ext4,ro,noexec",
            disk.display()
        );
        let mount = build_explicit(&spec, apply_explicit_disk_mount).await;
        match mount {
            VolumeMount::DiskImage {
                host,
                guest,
                format,
                fstype,
                options,
            } => {
                assert_eq!(host, disk);
                assert_eq!(guest, "/data");
                assert_eq!(format, DiskImageFormat::Qcow2);
                assert_eq!(fstype.as_deref(), Some("ext4"));
                assert!(options.readonly);
                assert!(options.noexec);
            }
            other => panic!("expected DiskImage, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_apply_explicit_named_mount() {
        let mount =
            build_explicit("cache:/data:stat-virt=relaxed", apply_explicit_named_mount).await;
        match mount {
            VolumeMount::Named {
                name,
                guest,
                stat_virtualization,
                create,
                ..
            } => {
                assert_eq!(name, "cache");
                assert_eq!(guest, "/data");
                assert!(matches!(stat_virtualization, StatVirtualization::Relaxed));
                assert_eq!(
                    create.as_ref().map(|create| create.mode()),
                    Some(microsandbox::sandbox::NamedVolumeMode::EnsureExists)
                );
            }
            other => panic!("expected Named, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_apply_explicit_named_mount_disk_ensure_options() {
        let mount = build_explicit(
            "cache-disk:/data:kind=disk,size=2G",
            apply_explicit_named_mount,
        )
        .await;
        match mount {
            VolumeMount::Named { create, .. } => {
                let create = create.expect("mount-named should ensure the named volume");
                assert_eq!(
                    create.mode(),
                    microsandbox::sandbox::NamedVolumeMode::EnsureExists
                );
                assert_eq!(create.kind(), VolumeKind::Disk);
                assert_eq!(create.capacity_mib(), Some(2048));
            }
            other => panic!("expected Named, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_apply_explicit_named_mount_directory_quota() {
        let mount = build_explicit("cache:/data:quota=1G", apply_explicit_named_mount).await;
        match mount {
            VolumeMount::Named { create, .. } => {
                let create = create.expect("mount-named should ensure the named volume");
                assert_eq!(
                    create.mode(),
                    microsandbox::sandbox::NamedVolumeMode::EnsureExists
                );
                assert_eq!(create.kind(), VolumeKind::Directory);
                assert_eq!(create.quota_mib(), Some(1024));
            }
            other => panic!("expected Named, got {other:?}"),
        }
    }

    #[test]
    fn test_apply_explicit_named_mount_disk_rejects_policy_options() {
        let err = match apply_explicit_named_mount(
            SandboxBuilder::new("test").image("alpine"),
            "cache-disk:/data:kind=disk,size=2G,stat-virt=relaxed",
        ) {
            Ok(_) => panic!("expected mount-named disk to reject stat-virt"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("does not support stat-virt"));

        let err = match apply_explicit_named_mount(
            SandboxBuilder::new("test").image("alpine"),
            "cache-disk:/data:kind=disk,size=2G,host-perms=mirror",
        ) {
            Ok(_) => panic!("expected mount-named disk to reject host-perms"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("does not support stat-virt"));
    }

    #[test]
    fn test_apply_explicit_disk_rejects_policy_option() {
        let err = match apply_explicit_disk_mount(
            SandboxBuilder::new("test").image("alpine"),
            "/tmp/disk.raw:/data:stat-virt=relaxed",
        ) {
            Ok(_) => panic!("expected mount-disk to reject stat-virt"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("not valid here"), "got: {err}");
    }

    #[test]
    fn test_apply_explicit_file_rejects_disk_option() {
        let file = write_temp("fixture");
        let spec = format!("{}:/fixture:fstype=ext4", file.display());
        let err =
            match apply_explicit_file_mount(SandboxBuilder::new("test").image("alpine"), &spec) {
                Ok(_) => panic!("expected mount-file to reject fstype"),
                Err(err) => err,
            };
        assert!(err.to_string().contains("not valid here"), "got: {err}");
    }

    fn expect_apply_volume_err(spec: &str) -> String {
        let builder = SandboxBuilder::new("test").image("/tmp/rootfs");
        match apply_volume(builder, spec) {
            Ok(_) => panic!("expected error for spec {spec:?}"),
            Err(err) => err.to_string(),
        }
    }

    #[test]
    fn test_apply_volume_rejects_unknown_stat_virt() {
        let err = expect_apply_volume_err("/host:/guest:stat-virt=bogus");
        assert!(err.contains("invalid stat-virt"), "got: {err}");
    }

    #[test]
    fn test_apply_volume_rejects_unknown_host_perms() {
        let err = expect_apply_volume_err("/host:/guest:host-perms=public");
        assert!(err.contains("invalid host-perms"), "got: {err}");
    }

    #[test]
    fn test_apply_volume_rejects_unknown_option_key() {
        let err = expect_apply_volume_err("/host:/guest:bogus=1");
        assert!(err.contains("unknown mount option"), "got: {err}");
    }

    #[test]
    fn test_apply_volume_rejects_duplicate_stat_virt() {
        let err = expect_apply_volume_err("/host:/guest:stat-virt=strict,stat-virt=off");
        assert!(err.contains("more than once"), "got: {err}");
    }

    #[test]
    fn test_apply_volume_rejects_legacy_comma_options() {
        let err = expect_apply_volume_err("/host:/guest,ro");
        assert!(err.contains("source:guest:options"), "got: {err}");
        assert!(err.contains("/host:/guest:ro"), "got: {err}");
    }

    #[test]
    fn test_validate_volume_spec_rejects_legacy_comma_options() {
        let err = validate_volume_spec("/host:/guest,ro").unwrap_err();
        assert!(err.to_string().contains("source:guest:options"));
    }

    #[test]
    fn test_apply_volume_rejects_unsupported_flags() {
        let err = expect_apply_volume_err("/host:/guest:exec");
        assert!(err.contains("unsupported mount option"), "got: {err}");
    }

    #[test]
    fn test_parse_tmpfs_accepts_size_and_noexec() {
        let (path, size, options) = parse_tmpfs("/tmp:1G:noexec").unwrap();
        assert_eq!(path, "/tmp");
        assert_eq!(size, Some(1024));
        assert!(options.noexec);
    }

    #[test]
    fn test_parse_tmpfs_accepts_keyed_size_and_flags() {
        let (path, size, options) = parse_tmpfs("/seed:size=64,ro,noexec,nosuid,nodev").unwrap();
        assert_eq!(path, "/seed");
        assert_eq!(size, Some(64));
        assert!(options.readonly);
        assert!(options.noexec);
        assert!(options.nosuid);
        assert!(options.nodev);
    }

    #[tokio::test]
    async fn test_apply_volume_rejects_comma_in_source_path() {
        // Embedded commas in host paths could silently inject mount options
        // through the spawn → VM wire format. The SDK rejects them at build
        // time with a clear error; the CLI surfaces that error verbatim.
        let builder = SandboxBuilder::new("test").image("/tmp/rootfs");
        // apply_volume itself defers to MountBuilder which only validates at
        // SandboxBuilder::build() — so the parse step succeeds and the
        // rejection comes from the subsequent build.
        let builder =
            apply_volume(builder, "/path/with,comma:/dst").expect("apply_volume defers validation");
        let err = builder.build().await.unwrap_err();
        assert!(
            err.to_string().contains("must not contain ','"),
            "got: {err}"
        );
    }

    /// Write a temp file with unique name, return its path.
    fn write_temp(content: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("msb-script-test-{}-{}.sh", std::process::id(), n));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    fn make_temp_dir(prefix: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("{prefix}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    async fn build_volume(spec: &str) -> VolumeMount {
        let builder = SandboxBuilder::new("test").image("alpine");
        let config = apply_volume(builder, spec).unwrap().build().await.unwrap();
        config.spec.mounts.into_iter().next().unwrap()
    }

    fn command_config(entrypoint: Option<&[&str]>, cmd: Option<&[&str]>) -> SandboxConfig {
        let mut config = SandboxConfig::default();
        config.spec.runtime.entrypoint = entrypoint.map(|items| {
            items
                .iter()
                .map(|item| (*item).to_string())
                .collect::<Vec<_>>()
        });
        config.spec.runtime.cmd = cmd.map(|items| {
            items
                .iter()
                .map(|item| (*item).to_string())
                .collect::<Vec<_>>()
        });
        config
    }

    // --- resolve_command / resolve_exec_command ---

    #[test]
    fn resolve_command_prepends_entrypoint_to_explicit_run_command() {
        let config = command_config(Some(&["start"]), None);
        let (cmd, args) =
            resolve_command(&config, vec!["date".to_string()], false).expect("resolve command");

        assert_eq!(cmd.as_deref(), Some("start"));
        assert_eq!(args, vec!["date".to_string()]);
    }

    #[test]
    fn resolve_exec_command_runs_explicit_command_directly() {
        let config = command_config(Some(&["start"]), None);
        let (cmd, args) = resolve_exec_command(&config, vec!["date".to_string()], false)
            .expect("resolve exec command");

        assert_eq!(cmd.as_deref(), Some("date"));
        assert!(args.is_empty());
    }

    #[test]
    fn resolve_exec_command_keeps_explicit_command_args() {
        let config = command_config(Some(&["start"]), None);
        let (cmd, args) = resolve_exec_command(
            &config,
            vec!["sh".to_string(), "-lc".to_string(), "echo ok".to_string()],
            false,
        )
        .expect("resolve exec command");

        assert_eq!(cmd.as_deref(), Some("sh"));
        assert_eq!(args, vec!["-lc".to_string(), "echo ok".to_string()]);
    }

    #[test]
    fn resolve_exec_command_without_explicit_command_uses_image_defaults() {
        let config = command_config(Some(&["start"]), Some(&["default"]));
        let (cmd, args) =
            resolve_exec_command(&config, Vec::new(), false).expect("resolve exec command");

        assert_eq!(cmd.as_deref(), Some("start"));
        assert_eq!(args, vec!["default".to_string()]);
    }

    // --- apply_volume ---

    #[tokio::test]
    async fn apply_volume_dot_source_is_bind_mount() {
        match build_volume(".:/mnt").await {
            VolumeMount::Bind { host, guest, .. } => {
                assert_eq!(host, PathBuf::from("."));
                assert_eq!(guest, "/mnt");
            }
            other => panic!("expected bind mount, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn apply_volume_dot_dot_source_is_bind_mount() {
        match build_volume("..:/mnt").await {
            VolumeMount::Bind { host, guest, .. } => {
                assert_eq!(host, PathBuf::from(".."));
                assert_eq!(guest, "/mnt");
            }
            other => panic!("expected bind mount, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn apply_volume_plain_source_is_named_mount() {
        match build_volume("data:/mnt").await {
            VolumeMount::Named { name, guest, .. } => {
                assert_eq!(name, "data");
                assert_eq!(guest, "/mnt");
            }
            other => panic!("expected named mount, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn apply_volume_rejects_path_like_named_source() {
        let builder = SandboxBuilder::new("test").image("alpine");
        let err = apply_volume(builder, "data/../../secrets:/mnt")
            .unwrap()
            .build()
            .await
            .unwrap_err();

        assert!(err.to_string().contains("volume name"));
    }

    // --- parse_script_spec ---

    #[test]
    fn spec_basic() {
        let (name, body) = parse_script_spec("greet=echo hi", "script").unwrap();
        assert_eq!(name, "greet");
        assert_eq!(body, "echo hi");
    }

    #[test]
    fn spec_body_may_contain_equals() {
        let (name, body) = parse_script_spec("kv=K=V test: a=b=c", "script").unwrap();
        assert_eq!(name, "kv");
        assert_eq!(body, "K=V test: a=b=c");
    }

    #[test]
    fn spec_empty_body_is_allowed() {
        let (name, body) = parse_script_spec("noop=", "script").unwrap();
        assert_eq!(name, "noop");
        assert_eq!(body, "");
    }

    #[test]
    fn spec_missing_equals_errors() {
        let err = parse_script_spec("noequals", "script").unwrap_err();
        assert!(err.to_string().contains("NAME=BODY"), "got: {err}");
        assert!(err.to_string().starts_with("script "), "got: {err}");
    }

    #[test]
    fn spec_empty_name_errors() {
        let err = parse_script_spec("=echo hi", "script").unwrap_err();
        assert!(err.to_string().contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn spec_flag_label_propagates() {
        let err = parse_script_spec("noequals", "script-raw").unwrap_err();
        assert!(err.to_string().starts_with("script-raw "), "got: {err}");
    }

    // --- escape decoding / shebang / wrapping ---

    #[test]
    fn decode_known_escapes() {
        assert_eq!(decode_script_escapes(r"a\nb"), "a\nb");
        assert_eq!(decode_script_escapes(r"a\tb"), "a\tb");
        assert_eq!(decode_script_escapes(r"a\rb"), "a\rb");
        assert_eq!(decode_script_escapes(r"a\\b"), "a\\b");
        assert_eq!(decode_script_escapes(r#"a\"b"#), "a\"b");
        assert_eq!(decode_script_escapes(r"a\'b"), "a'b");
    }

    #[test]
    fn decode_unknown_escapes_preserved() {
        assert_eq!(decode_script_escapes(r"a\db"), r"a\db");
        assert_eq!(decode_script_escapes(r"\x \y \z"), r"\x \y \z");
    }

    #[test]
    fn decode_trailing_backslash_preserved() {
        assert_eq!(decode_script_escapes(r"foo\"), r"foo\");
    }

    #[test]
    fn shebang_absolute_path_used_directly() {
        assert_eq!(script_shebang(Some("/bin/bash")), "#!/bin/bash");
        assert_eq!(
            script_shebang(Some("/usr/local/bin/zsh")),
            "#!/usr/local/bin/zsh"
        );
    }

    #[test]
    fn shebang_bare_name_goes_through_env() {
        assert_eq!(script_shebang(Some("bash")), "#!/usr/bin/env bash");
        assert_eq!(script_shebang(Some("zsh")), "#!/usr/bin/env zsh");
    }

    #[test]
    fn shebang_defaults_to_bin_sh() {
        assert_eq!(script_shebang(None), "#!/bin/sh");
    }

    #[test]
    fn wrap_appends_trailing_newline() {
        assert_eq!(
            wrap_shell_script(None, "echo hello"),
            "#!/bin/sh\necho hello\n"
        );
    }

    #[test]
    fn validate_shell_rejects_bad_shapes() {
        assert!(validate_shell("").is_err());
        assert!(validate_shell("/").is_err());
        assert!(validate_shell("bash -x").is_err());
        assert!(validate_shell("bash\nrm -rf /").is_err());
        assert!(validate_shell("bash\trm").is_err());
        assert!(validate_shell("bash\0").is_err());
        assert!(validate_shell(" bash").is_err());
        assert!(validate_shell("bash ").is_err());
    }

    #[test]
    fn validate_shell_accepts_valid_shapes() {
        assert!(validate_shell("bash").is_ok());
        assert!(validate_shell("sh").is_ok());
        assert!(validate_shell("/bin/sh").is_ok());
        assert!(validate_shell("/bin/bash").is_ok());
        assert!(validate_shell("/usr/local/bin/zsh").is_ok());
    }

    #[test]
    fn wrap_does_not_double_trailing_newline() {
        assert_eq!(
            wrap_shell_script(None, "echo hello\n"),
            "#!/bin/sh\necho hello\n"
        );
    }

    // --- collect_scripts (duplicate logic) ---

    // --- parse_port_mapping ---

    #[cfg(feature = "net")]
    #[test]
    fn port_without_bind_defaults_to_loopback() {
        let (bind, host, guest, udp) = parse_port_mapping("8080:80").unwrap();
        assert_eq!(bind, std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        assert_eq!(host, 8080);
        assert_eq!(guest, 80);
        assert!(!udp);
    }

    #[cfg(feature = "net")]
    #[test]
    fn port_with_explicit_loopback_stays_loopback() {
        let (bind, host, guest, udp) = parse_port_mapping("127.0.0.1:8080:80").unwrap();
        assert_eq!(bind, std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        assert_eq!(host, 8080);
        assert_eq!(guest, 80);
        assert!(!udp);
    }

    #[cfg(feature = "net")]
    #[test]
    fn port_with_ipv4_bind() {
        let (bind, host, guest, udp) = parse_port_mapping("0.0.0.0:8080:80/udp").unwrap();
        assert_eq!(bind, "0.0.0.0".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(host, 8080);
        assert_eq!(guest, 80);
        assert!(udp);
    }

    #[cfg(feature = "net")]
    #[test]
    fn port_with_bracketed_ipv6_bind() {
        let (bind, host, guest, udp) = parse_port_mapping("[::]:8080:80/tcp").unwrap();
        assert_eq!(bind, "::".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(host, 8080);
        assert_eq!(guest, 80);
        assert!(!udp);
    }

    // --- parse_script_path ---

    #[test]
    fn path_basic() {
        let p = write_temp("#!/bin/sh\necho hi\n");
        let spec = format!("hello:{}", p.display());
        let (name, body) = parse_script_path(&spec).unwrap();
        assert_eq!(name, "hello");
        assert_eq!(body, "#!/bin/sh\necho hi\n");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn path_missing_colon_errors() {
        let err = parse_script_path("nocolons").unwrap_err();
        assert!(err.to_string().contains("NAME:PATH"), "got: {err}");
    }

    #[test]
    fn path_empty_name_errors() {
        let err = parse_script_path(":/tmp/whatever").unwrap_err();
        assert!(err.to_string().contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn path_missing_file_errors() {
        let err = parse_script_path("foo:/no/such/file-msb.sh").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("failed to read script file"), "got: {msg}");
        assert!(msg.contains("/no/such/file-msb.sh"), "got: {msg}");
    }

    // --- collect_scripts (duplicate logic) ---

    #[test]
    fn collect_script_wraps_with_default_shebang() {
        let scripts = vec!["start=echo hello".to_string()];
        let out = collect_scripts(None, &scripts, &[], &[]).unwrap();
        assert_eq!(
            out,
            vec![("start".to_string(), "#!/bin/sh\necho hello\n".to_string())]
        );
    }

    #[test]
    fn collect_script_decodes_newlines_in_body() {
        let scripts = vec![r#"start=echo hello\npython -c "print(123)""#.to_string()];
        let out = collect_scripts(None, &scripts, &[], &[]).unwrap();
        assert_eq!(
            out[0].1,
            "#!/bin/sh\necho hello\npython -c \"print(123)\"\n"
        );
    }

    #[test]
    fn collect_script_uses_absolute_shell_path() {
        let scripts = vec!["start=echo hi".to_string()];
        let out = collect_scripts(Some("/bin/bash"), &scripts, &[], &[]).unwrap();
        assert_eq!(out[0].1, "#!/bin/bash\necho hi\n");
    }

    #[test]
    fn collect_script_uses_env_for_bare_shell() {
        let scripts = vec!["start=echo $BASH_VERSION".to_string()];
        let out = collect_scripts(Some("bash"), &scripts, &[], &[]).unwrap();
        assert_eq!(out[0].1, "#!/usr/bin/env bash\necho $BASH_VERSION\n");
    }

    #[test]
    fn collect_script_raw_is_exact() {
        let raw = vec!["start=echo hello".to_string()];
        let out = collect_scripts(None, &[], &raw, &[]).unwrap();
        assert_eq!(out, vec![("start".to_string(), "echo hello".to_string())]);
    }

    #[test]
    fn collect_script_raw_preserves_escapes_literally() {
        let raw = vec![r"start=echo hello\nworld".to_string()];
        let out = collect_scripts(None, &[], &raw, &[]).unwrap();
        assert_eq!(out[0].1, r"echo hello\nworld");
    }

    #[test]
    fn collect_script_path_is_exact_file_contents() {
        let p = write_temp("#!/bin/sh\necho from-file\n");
        let paths = vec![format!("start:{}", p.display())];
        let out = collect_scripts(None, &[], &[], &paths).unwrap();
        assert_eq!(out[0].1, "#!/bin/sh\necho from-file\n");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn collect_script_preserves_unknown_escapes() {
        let scripts = vec![r"re=grep '\d\+' file".to_string()];
        let out = collect_scripts(None, &scripts, &[], &[]).unwrap();
        assert_eq!(out[0].1, "#!/bin/sh\ngrep '\\d\\+' file\n");
    }

    #[test]
    fn collect_script_always_ends_with_newline() {
        let scripts = vec!["start=echo hello".to_string()];
        let out = collect_scripts(None, &scripts, &[], &[]).unwrap();
        assert!(out[0].1.ends_with('\n'));
    }

    #[test]
    fn collect_preserves_order_across_all_three_sources() {
        let p = write_temp("from-file");
        let scripts = vec!["a=echo a".to_string()];
        let raw = vec!["b=echo b".to_string()];
        let paths = vec![format!("c:{}", p.display())];
        let out = collect_scripts(None, &scripts, &raw, &paths).unwrap();
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].0, "a");
        assert_eq!(out[1], ("b".to_string(), "echo b".to_string()));
        assert_eq!(out[2], ("c".to_string(), "from-file".to_string()));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn collect_rejects_duplicate_within_script() {
        let scripts = vec!["foo=echo a".to_string(), "foo=echo b".to_string()];
        let err = collect_scripts(None, &scripts, &[], &[]).unwrap_err();
        assert!(
            err.to_string().contains("'foo' specified more than once"),
            "got: {err}"
        );
    }

    #[test]
    fn collect_rejects_duplicate_within_path() {
        let p = write_temp("x");
        let paths = vec![
            format!("foo:{}", p.display()),
            format!("foo:{}", p.display()),
        ];
        let err = collect_scripts(None, &[], &[], &paths).unwrap_err();
        assert!(
            err.to_string().contains("'foo' specified more than once"),
            "got: {err}"
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn collect_rejects_duplicate_across_all_three_sources() {
        let p = write_temp("x");
        let scripts = vec!["foo=echo a".to_string()];
        let raw = vec!["foo=echo b".to_string()];
        let paths = vec![format!("foo:{}", p.display())];

        let err = collect_scripts(None, &scripts, &raw, &[]).unwrap_err();
        assert!(
            err.to_string().contains("'foo' specified more than once"),
            "script vs script-raw: {err}"
        );

        let err = collect_scripts(None, &scripts, &[], &paths).unwrap_err();
        assert!(
            err.to_string().contains("'foo' specified more than once"),
            "script vs script-path: {err}"
        );

        let err = collect_scripts(None, &[], &raw, &paths).unwrap_err();
        assert!(
            err.to_string().contains("'foo' specified more than once"),
            "script-raw vs script-path: {err}"
        );

        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn collect_empty_inputs_ok() {
        let out = collect_scripts(None, &[], &[], &[]).unwrap();
        assert!(out.is_empty());
    }

    // --- build_network_policy: --net-default / --no-net ---

    #[cfg(feature = "net")]
    use microsandbox_network::policy::Action;

    #[cfg(feature = "net")]
    #[test]
    fn build_policy_no_flags_returns_none() {
        let p = build_network_policy(&[], false, None, None, None).unwrap();
        assert!(p.is_none());
    }

    #[cfg(feature = "net")]
    #[test]
    fn build_policy_net_default_deny_sets_both_directions() {
        let p = build_network_policy(&[], false, Some("deny"), None, None)
            .unwrap()
            .expect("policy");
        assert_eq!(p.default_egress, Action::Deny);
        assert_eq!(p.default_ingress, Action::Deny);
        assert!(p.rules.is_empty());
    }

    #[cfg(feature = "net")]
    #[test]
    fn build_policy_net_default_allow_sets_both_directions() {
        let p = build_network_policy(&[], false, Some("allow"), None, None)
            .unwrap()
            .expect("policy");
        assert_eq!(p.default_egress, Action::Allow);
        assert_eq!(p.default_ingress, Action::Allow);
    }

    #[cfg(feature = "net")]
    #[test]
    fn build_policy_no_net_desugars_to_deny_both() {
        let p = build_network_policy(&[], true, None, None, None)
            .unwrap()
            .expect("policy");
        assert_eq!(p.default_egress, Action::Deny);
        assert_eq!(p.default_ingress, Action::Deny);
    }

    #[cfg(feature = "net")]
    #[test]
    fn build_policy_no_net_with_allow_rule_yields_allowlist() {
        let rules = vec!["allow@example.com".to_string()];
        let p = build_network_policy(&rules, true, None, None, None)
            .unwrap()
            .expect("policy");
        assert_eq!(p.default_egress, Action::Deny);
        assert_eq!(p.default_ingress, Action::Deny);
        assert_eq!(p.rules.len(), 1);
        assert_eq!(p.rules[0].action, Action::Allow);
    }

    #[cfg(feature = "net")]
    #[test]
    fn build_policy_net_default_rejects_unknown_action() {
        let err = build_network_policy(&[], false, Some("maybe"), None, None).unwrap_err();
        assert!(
            err.to_string().contains("--net-default"),
            "expected --net-default in error, got: {err}"
        );
    }

    #[cfg(feature = "net")]
    #[test]
    fn build_policy_rule_only_uses_preset_defaults() {
        // Without any --net-default* flag, rules apply on top of the
        // public_only preset (deny egress, allow ingress). Verifies the
        // "rules alone keep the preset's defaults" path now that the
        // --deny-domain* flip-to-allow exception is gone.
        let rules = vec!["allow@example.com".to_string()];
        let p = build_network_policy(&rules, false, None, None, None)
            .unwrap()
            .expect("policy");
        let preset = microsandbox_network::policy::NetworkPolicy::public_only();
        assert_eq!(p.default_egress, preset.default_egress);
        assert_eq!(p.default_ingress, preset.default_ingress);
    }
}

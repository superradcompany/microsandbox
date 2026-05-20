//! Common sandbox configuration flags shared between commands.

use std::path::PathBuf;

use clap::Args;
use microsandbox::sandbox::SandboxBuilder;

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Common sandbox configuration flags shared between `msb run` and `msb create`.
#[derive(Debug, Args)]
pub struct SandboxOpts {
    /// Name for the sandbox. Auto-generated if omitted.
    #[arg(short, long)]
    pub name: Option<String>,

    /// Number of virtual CPUs to allocate.
    #[arg(short = 'c', long)]
    pub cpus: Option<u8>,

    /// Amount of memory to allocate (e.g. 512M, 1G).
    #[arg(short, long)]
    pub memory: Option<String>,

    /// Mount a host path or named volume into the sandbox (SOURCE:DEST).
    #[arg(short, long)]
    pub volume: Vec<String>,

    /// Set the default working directory for commands.
    #[arg(short, long)]
    pub workdir: Option<String>,

    /// Shell to use for interactive sessions (default: /bin/sh).
    #[arg(long)]
    pub shell: Option<String>,

    /// Set an environment variable (KEY=value).
    #[arg(short, long)]
    pub env: Vec<String>,

    /// Replace an existing sandbox with the same name.
    #[arg(long)]
    pub replace: bool,

    /// Grace period the existing sandbox gets after SIGTERM before it
    /// is SIGKILLed during a replace. Accepts `0`, `500ms`, `5s`, `2m`.
    /// Implies `--replace`. Default 10s when `--replace` is set on its own.
    #[arg(long, value_name = "DURATION")]
    pub replace_with_grace: Option<String>,

    /// Suppress progress output.
    #[arg(short, long)]
    pub quiet: bool,

    // --- Filesystem ---
    /// Mount a temporary in-memory filesystem (PATH or PATH:SIZE, e.g. /tmp:100M).
    #[arg(long)]
    pub tmpfs: Vec<String>,

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

    // --- Image/Runtime overrides ---
    /// Override the image's default entrypoint command.
    #[arg(long)]
    pub entrypoint: Option<String>,

    /// Hand off PID 1 to this init binary inside the guest after agentd
    /// finishes setup. Use `auto` to probe `/sbin/init`,
    /// `/lib/systemd/systemd`, `/usr/lib/systemd/systemd` (first hit
    /// wins), or supply an explicit absolute path.
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

    /// Set the guest hostname (defaults to sandbox name).
    #[arg(short = 'H', long)]
    pub hostname: Option<String>,

    /// Run commands as the specified user (e.g. nobody, 1000, 1000:1000).
    #[arg(short = 'u', long)]
    pub user: Option<String>,

    /// When to pull the image: always, if-missing (default), never.
    #[arg(long)]
    pub pull: Option<String>,

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

    /// Disable all network access. Sugar for `--net-default-egress deny`
    /// with no rules.
    #[cfg(feature = "net")]
    #[arg(long = "no-net")]
    pub no_net: bool,

    /// Deny egress to a domain. Equivalent to a `deny Domain("...")`
    /// policy rule appended after any `--net-rule` entries.
    #[cfg(feature = "net")]
    #[arg(long = "deny-domain", value_name = "NAME")]
    pub deny_domain: Vec<String>,

    /// Deny egress to all subdomains of a suffix (e.g. `.ads.example`).
    /// Equivalent to a `deny DomainSuffix("...")` rule appended after
    /// any `--net-rule` entries.
    #[cfg(feature = "net")]
    #[arg(long = "deny-domain-suffix", value_name = "SUFFIX")]
    pub deny_domain_suffix: Vec<String>,

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
    /// Examples:
    ///   --net-rule "allow@public"
    ///   --net-rule "deny@198.51.100.5,allow@public"
    ///   --net-rule "allow:ingress@private"
    ///   --net-rule "allow@example.com:tcp:443"
    #[cfg(feature = "net")]
    #[arg(long = "net-rule", value_name = "TOKENS")]
    pub net_rule: Vec<String>,

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

    // --- Secrets ---
    /// Inject a secret that is only sent to an allowed host (ENV=VALUE@HOST).
    #[cfg(feature = "net")]
    #[arg(long)]
    pub secret: Vec<String>,

    /// Action when a secret is sent to a disallowed host (block, block-and-log, block-and-terminate).
    #[cfg(feature = "net")]
    #[arg(long)]
    pub on_secret_violation: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SandboxOpts {
    /// Returns true if any creation-time configuration flag was set.
    pub fn has_creation_flags(&self) -> bool {
        let base = self.cpus.is_some()
            || self.memory.is_some()
            || !self.volume.is_empty()
            || self.workdir.is_some()
            || self.shell.is_some()
            || !self.env.is_empty()
            || !self.tmpfs.is_empty()
            || !self.script.is_empty()
            || !self.script_raw.is_empty()
            || !self.script_path.is_empty()
            || self.entrypoint.is_some()
            || self.init.is_some()
            || !self.init_arg.is_empty()
            || !self.init_env.is_empty()
            || self.hostname.is_some()
            || self.user.is_some()
            || self.pull.is_some()
            || self.log_level.is_some()
            || self.max_duration.is_some()
            || self.idle_timeout.is_some();

        #[cfg(feature = "net")]
        let net = !self.port.is_empty()
            || self.no_net
            || !self.deny_domain.is_empty()
            || !self.deny_domain_suffix.is_empty()
            || self.no_dns_rebind_protection
            || !self.dns_nameserver.is_empty()
            || self.dns_query_timeout_ms.is_some()
            || !self.net_rule.is_empty()
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
    if let Some(ref mem) = opts.memory {
        builder = builder.memory(ui::parse_size_mib(mem).map_err(anyhow::Error::msg)?);
    }
    if let Some(ref workdir) = opts.workdir {
        builder = builder.workdir(workdir);
    }
    if let Some(ref shell) = opts.shell {
        validate_shell(shell)?;
        builder = builder.shell(shell);
    }
    if let Some(ref grace) = opts.replace_with_grace {
        let d = parse_duration(grace).map_err(|e| anyhow::anyhow!("--replace-with-grace: {e}"))?;
        builder = builder.replace_with_grace(d);
    } else if opts.replace {
        builder = builder.replace();
    }

    // --- Environment ---
    for env_str in &opts.env {
        let (k, v) = ui::parse_env(env_str).map_err(anyhow::Error::msg)?;
        builder = builder.env(k, v);
    }

    // --- Volumes ---
    for vol_str in &opts.volume {
        builder = apply_volume(builder, vol_str)?;
    }

    // --- Tmpfs ---
    for tmpfs_str in &opts.tmpfs {
        let (path, size) = parse_tmpfs(tmpfs_str)?;
        builder = if let Some(size_mib) = size {
            builder.volume(&path, |m| m.tmpfs().size(size_mib))
        } else {
            builder.volume(&path, |m| m.tmpfs())
        };
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

/// Parse a volume spec and apply it to the builder.
pub fn apply_volume(builder: SandboxBuilder, spec: &str) -> anyhow::Result<SandboxBuilder> {
    let (source, guest) = spec
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("volume must be in format source:guest"))?;

    if microsandbox_utils::looks_like_local_path_text(source) {
        Ok(builder.volume(guest, |m| m.bind(source)))
    } else {
        Ok(builder.volume(guest, |m| m.named(source)))
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

    // Disable networking. `--no-net` is mutually exclusive with the
    // policy-shaping flags: it kills the guest's network interface
    // entirely, so any rule or default action would be dead code and
    // is almost certainly a user mistake. Reject the combination at
    // parse time with a helpful migration hint.
    if opts.no_net {
        let mut conflicts: Vec<&'static str> = Vec::new();
        if !opts.net_rule.is_empty() {
            conflicts.push("--net-rule");
        }
        if opts.net_default_egress.is_some() {
            conflicts.push("--net-default-egress");
        }
        if opts.net_default_ingress.is_some() {
            conflicts.push("--net-default-ingress");
        }
        if opts.net_ipv4_pool.is_some() {
            conflicts.push("--net-ipv4-pool");
        }
        if opts.net_ipv6_pool.is_some() {
            conflicts.push("--net-ipv6-pool");
        }
        if !conflicts.is_empty() {
            anyhow::bail!(
                "--no-net cannot be combined with {}; \
                 --no-net disables the guest network entirely, so rules and defaults are dead code. \
                 Drop --no-net to apply rules, or drop the rule flags to keep the network off.",
                conflicts.join(" / "),
            );
        }
        builder = builder.disable_network();
    }

    // Secrets.
    for secret_str in &opts.secret {
        let (env_var, value, host) = parse_secret(secret_str)?;
        builder = builder.secret_env(env_var, value, host);
    }

    // DNS, TLS, and other network configuration.
    let has_network_config = !opts.deny_domain.is_empty()
        || !opts.deny_domain_suffix.is_empty()
        || opts.no_dns_rebind_protection
        || !opts.dns_nameserver.is_empty()
        || opts.dns_query_timeout_ms.is_some()
        || !opts.net_rule.is_empty()
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
            opts.net_default_egress.as_deref(),
            opts.net_default_ingress.as_deref(),
            &opts.deny_domain,
            &opts.deny_domain_suffix,
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
                n = n.on_secret_violation(action);
            }

            // TLS configuration.
            let has_tls = tls_intercept
                || !tls_ports.is_empty()
                || !tls_bypass.is_empty()
                || no_block_quic
                || intercept_ca_cert.is_some()
                || intercept_ca_key.is_some()
                || !upstream_ca_cert.is_empty();

            if has_tls {
                let tls_ports = tls_ports.clone();
                let tls_bypass = tls_bypass.clone();
                let intercept_ca_cert = intercept_ca_cert.clone();
                let intercept_ca_key = intercept_ca_key.clone();
                let upstream_ca_cert = upstream_ca_cert.clone();
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

/// Assemble a [`NetworkPolicy`] from `--net-rule` / `--net-default-*`
/// and the bulk-deny flags. Returns `None` when no flag is set.
/// Multiple `--net-rule` invocations concatenate in argv order.
#[cfg(feature = "net")]
fn build_network_policy(
    rule_args: &[String],
    default_egress: Option<&str>,
    default_ingress: Option<&str>,
    deny_domains: &[String],
    deny_domain_suffixes: &[String],
) -> anyhow::Result<Option<microsandbox_network::policy::NetworkPolicy>> {
    use anyhow::Context;
    use microsandbox_network::policy::{Action, Destination, DomainName, NetworkPolicy, Rule};

    use crate::net_rule::parse_rule_list;

    let no_rule_flags =
        rule_args.is_empty() && default_egress.is_none() && default_ingress.is_none();
    let no_block_flags = deny_domains.is_empty() && deny_domain_suffixes.is_empty();
    if no_rule_flags && no_block_flags {
        return Ok(None);
    }

    let mut rules = Vec::new();

    // Prepend bulk-deny flags so they outrank later allow rules.
    for d in deny_domains {
        let domain: DomainName = d.parse().with_context(|| format!("--deny-domain {d:?}"))?;
        rules.push(Rule::deny_egress(Destination::Domain(domain)));
    }
    for s in deny_domain_suffixes {
        let suffix: DomainName = s
            .parse()
            .with_context(|| format!("--deny-domain-suffix {s:?}"))?;
        rules.push(Rule::deny_egress(Destination::DomainSuffix(suffix)));
    }

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

    // When the user sets no defaults explicitly, fall through to
    // NetworkPolicy::public_only's defaults so behaviour stays in sync
    // with the preset.
    //
    // Exception: if only --deny-domain / --deny-domain-suffix were set
    // (no --net-rule, no --net-default-*), default egress flips to
    // Allow so the rest of the network keeps working — these flags
    // add deny entries on top of permissive defaults.
    let preset = NetworkPolicy::public_only();
    let default_egress = match default_egress {
        Some(raw) => parse_action("--net-default-egress", raw)?,
        None if no_rule_flags => Action::Allow,
        None => preset.default_egress,
    };
    let default_ingress = match default_ingress {
        Some(raw) => parse_action("--net-default-ingress", raw)?,
        None => preset.default_ingress,
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

/// Parse a secret spec: `ENV=VALUE@HOST`.
#[cfg(feature = "net")]
fn parse_secret(spec: &str) -> anyhow::Result<(String, String, String)> {
    let eq_pos = spec
        .find('=')
        .ok_or_else(|| anyhow::anyhow!("secret must be in format ENV=VALUE@HOST"))?;
    let env_var = spec[..eq_pos].to_string();
    let rest = &spec[eq_pos + 1..];

    let at_pos = rest
        .rfind('@')
        .ok_or_else(|| anyhow::anyhow!("secret must be in format ENV=VALUE@HOST"))?;
    let value = rest[..at_pos].to_string();
    let host = rest[at_pos + 1..].to_string();

    if env_var.is_empty() || value.is_empty() || host.is_empty() {
        anyhow::bail!("secret must be in format ENV=VALUE@HOST (all parts required)");
    }

    Ok((env_var, value, host))
}

/// Parse a violation action string.
#[cfg(feature = "net")]
fn parse_violation_action(
    s: &Option<String>,
) -> anyhow::Result<Option<microsandbox_network::secrets::config::ViolationAction>> {
    use microsandbox_network::secrets::config::ViolationAction;
    match s.as_deref() {
        None => Ok(None),
        Some("block") => Ok(Some(ViolationAction::Block)),
        Some("block-and-log") => Ok(Some(ViolationAction::BlockAndLog)),
        Some("block-and-terminate") => Ok(Some(ViolationAction::BlockAndTerminate)),
        Some(other) => anyhow::bail!(
            "invalid violation action: {other} (expected: block, block-and-log, block-and-terminate)"
        ),
    }
}

/// Parse a tmpfs spec: `PATH` or `PATH:SIZE`.
fn parse_tmpfs(spec: &str) -> anyhow::Result<(String, Option<u32>)> {
    if let Some((path, size_str)) = spec.split_once(':') {
        let size_mib = ui::parse_size_mib(size_str).map_err(anyhow::Error::msg)?;
        Ok((path.to_string(), Some(size_mib)))
    } else {
        Ok((spec.to_string(), None))
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
// Trait Implementations
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

/// Resolve the command to run following OCI semantics.
///
/// Returns `(Some(cmd), args)` or `(None, _)` when no command is available.
///
/// Resolution order when the user supplies no explicit command:
/// 1. Image entrypoint [+ cmd]
/// 2. Image cmd alone
/// 3. `config.shell` (interactive only)
/// 4. `/bin/sh` (interactive only)
pub fn resolve_command(
    config: &microsandbox::sandbox::SandboxConfig,
    user_command: Vec<String>,
    interactive: bool,
) -> anyhow::Result<(Option<String>, Vec<String>)> {
    // User supplied an explicit command — prepend entrypoint if set.
    if !user_command.is_empty() {
        return match &config.entrypoint {
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
        let shell = config.shell.as_deref().unwrap_or("/bin/sh");
        return Ok((Some(shell.to_string()), vec![]));
    }

    // Non-interactive with nothing to run.
    ui::warn("no command provided and stdin is not a terminal");
    Ok((None, vec![]))
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
    match (&config.entrypoint, &config.cmd) {
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

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use microsandbox::sandbox::VolumeMount;

    use super::*;

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

    async fn build_volume(spec: &str) -> VolumeMount {
        let builder = SandboxBuilder::new("test").image("alpine");
        let config = apply_volume(builder, spec).unwrap().build().await.unwrap();
        config.mounts.into_iter().next().unwrap()
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
}

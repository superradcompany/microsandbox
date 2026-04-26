use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use microsandbox::sandbox::{NetworkPolicy, PullPolicy, SandboxConfig as RustSandboxConfig};
use microsandbox::{LogLevel, RegistryAuth as RustRegistryAuth};
use microsandbox_network::dns::Nameserver;
use microsandbox_network::policy::{
    Action, Destination, DestinationGroup, Direction, PortRange, Protocol, Rule,
};
use microsandbox_network::secrets::config::ViolationAction;
use napi::bindgen_prelude::*;
use napi_derive::napi;
use tokio::sync::Mutex;

use crate::error::to_napi_error;
use crate::exec::{ExecOutput, JsExecHandle, convert_exec_config};
use crate::fs::JsSandboxFs;
use crate::sandbox_handle::JsSandboxHandle;
use crate::types::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A running sandbox instance.
///
/// Created via `Sandbox.create()` or `Sandbox.start()`. Holds a live connection
/// to the guest VM and can execute commands, access the filesystem, and query metrics.
#[napi]
pub struct Sandbox {
    inner: Arc<Mutex<Option<microsandbox::sandbox::Sandbox>>>,
}

/// A streaming subscription for sandbox metrics at a regular interval.
///
/// Supports both manual `recv()` calls and `for await...of` iteration:
/// ```js
/// const stream = await sb.metricsStream(1000);
/// for await (const m of stream) {
///   console.log(`CPU: ${m.cpuPercent.toFixed(1)}%`);
/// }
/// ```
#[napi(async_iterator, js_name = "MetricsStream")]
pub struct JsMetricsStream {
    rx: Arc<Mutex<tokio::sync::mpsc::Receiver<napi::Result<SandboxMetrics>>>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    pub fn from_rust(inner: microsandbox::sandbox::Sandbox) -> Self {
        Sandbox {
            inner: Arc::new(Mutex::new(Some(inner))),
        }
    }
}

#[napi]
impl Sandbox {
    //----------------------------------------------------------------------------------------------
    // Static Methods — Creation
    //----------------------------------------------------------------------------------------------

    /// Create a sandbox from configuration (attached mode — stops on GC/process exit).
    #[napi(factory)]
    pub async fn create(config: SandboxConfig) -> Result<Sandbox> {
        let rust_config = convert_config(config).await?;
        let inner = microsandbox::sandbox::Sandbox::create(rust_config)
            .await
            .map_err(to_napi_error)?;
        Ok(Sandbox {
            inner: Arc::new(Mutex::new(Some(inner))),
        })
    }

    /// Create a sandbox that survives the parent process (detached mode).
    #[napi(factory)]
    pub async fn create_detached(config: SandboxConfig) -> Result<Sandbox> {
        let rust_config = convert_config(config).await?;
        let inner = microsandbox::sandbox::Sandbox::create_detached(rust_config)
            .await
            .map_err(to_napi_error)?;
        Ok(Sandbox {
            inner: Arc::new(Mutex::new(Some(inner))),
        })
    }

    /// Start an existing stopped sandbox (attached mode).
    #[napi(factory)]
    pub async fn start(name: String) -> Result<Sandbox> {
        let inner = microsandbox::sandbox::Sandbox::start(&name)
            .await
            .map_err(to_napi_error)?;
        Ok(Sandbox {
            inner: Arc::new(Mutex::new(Some(inner))),
        })
    }

    /// Start an existing stopped sandbox (detached mode).
    #[napi(factory)]
    pub async fn start_detached(name: String) -> Result<Sandbox> {
        let inner = microsandbox::sandbox::Sandbox::start_detached(&name)
            .await
            .map_err(to_napi_error)?;
        Ok(Sandbox {
            inner: Arc::new(Mutex::new(Some(inner))),
        })
    }

    //----------------------------------------------------------------------------------------------
    // Static Methods — Lookup
    //----------------------------------------------------------------------------------------------

    /// Get a lightweight handle to an existing sandbox.
    #[napi]
    pub async fn get(name: String) -> Result<JsSandboxHandle> {
        let handle = microsandbox::sandbox::Sandbox::get(&name)
            .await
            .map_err(to_napi_error)?;
        Ok(JsSandboxHandle::from_rust(handle))
    }

    /// List all sandboxes.
    #[napi]
    pub async fn list() -> Result<Vec<SandboxInfo>> {
        let handles = microsandbox::sandbox::Sandbox::list()
            .await
            .map_err(to_napi_error)?;
        Ok(handles.iter().map(sandbox_handle_to_info).collect())
    }

    /// Remove a stopped sandbox from the database.
    #[napi(js_name = "remove")]
    pub async fn remove_static(name: String) -> Result<()> {
        microsandbox::sandbox::Sandbox::remove(&name)
            .await
            .map_err(to_napi_error)
    }

    //----------------------------------------------------------------------------------------------
    // Properties
    //----------------------------------------------------------------------------------------------

    /// Sandbox name.
    #[napi(getter)]
    pub async fn name(&self) -> Result<String> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        Ok(sb.name().to_string())
    }

    /// Whether this handle owns the sandbox lifecycle (attached mode).
    #[napi(getter)]
    pub async fn owns_lifecycle(&self) -> Result<bool> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        Ok(sb.owns_lifecycle())
    }

    //----------------------------------------------------------------------------------------------
    // Execution
    //----------------------------------------------------------------------------------------------

    /// Execute a command and wait for completion.
    #[napi]
    pub async fn exec(&self, cmd: String, args: Option<Vec<String>>) -> Result<ExecOutput> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        let args_owned = args.unwrap_or_default();
        let output = sb.exec(&cmd, args_owned).await.map_err(to_napi_error)?;
        Ok(ExecOutput::from_rust(output))
    }

    /// Execute a command with full configuration and wait for completion.
    #[napi(js_name = "execWithConfig")]
    pub async fn exec_with_config(&self, config: ExecConfig) -> Result<ExecOutput> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        let f = convert_exec_config(&config);
        let output = sb.exec_with(&config.cmd, f).await.map_err(to_napi_error)?;
        Ok(ExecOutput::from_rust(output))
    }

    /// Execute a command with streaming I/O.
    #[napi]
    pub async fn exec_stream(
        &self,
        cmd: String,
        args: Option<Vec<String>>,
    ) -> Result<JsExecHandle> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        let args_owned = args.unwrap_or_default();
        let handle = sb
            .exec_stream(&cmd, args_owned)
            .await
            .map_err(to_napi_error)?;
        Ok(JsExecHandle::from_rust(handle))
    }

    /// Execute a command with streaming I/O and full configuration.
    ///
    /// Unlike `execStream`, this accepts an `ExecConfig` so callers can enable
    /// a piped stdin (`stdin: "pipe"`), set a TTY, pass env vars, etc. Required
    /// for bidirectional streaming protocols where the host writes to the
    /// running process's stdin via `ExecHandle.takeStdin()` while concurrently
    /// reading events via `ExecHandle.recv()`.
    #[napi(js_name = "execStreamWithConfig")]
    pub async fn exec_stream_with_config(&self, config: ExecConfig) -> Result<JsExecHandle> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        let f = convert_exec_config(&config);
        let handle = sb
            .exec_stream_with(&config.cmd, f)
            .await
            .map_err(to_napi_error)?;
        Ok(JsExecHandle::from_rust(handle))
    }

    /// Execute a shell command using the sandbox's configured shell.
    #[napi]
    pub async fn shell(&self, script: String) -> Result<ExecOutput> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        let output = sb.shell(&script).await.map_err(to_napi_error)?;
        Ok(ExecOutput::from_rust(output))
    }

    /// Execute a shell command with streaming I/O.
    #[napi]
    pub async fn shell_stream(&self, script: String) -> Result<JsExecHandle> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        let handle = sb.shell_stream(&script).await.map_err(to_napi_error)?;
        Ok(JsExecHandle::from_rust(handle))
    }

    //----------------------------------------------------------------------------------------------
    // Filesystem
    //----------------------------------------------------------------------------------------------

    /// Get a filesystem handle for operations on the running sandbox.
    #[napi]
    pub fn fs(&self) -> JsSandboxFs {
        JsSandboxFs::new(self.inner.clone())
    }

    //----------------------------------------------------------------------------------------------
    // Metrics
    //----------------------------------------------------------------------------------------------

    /// Get point-in-time resource metrics.
    #[napi]
    pub async fn metrics(&self) -> Result<SandboxMetrics> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        let m = sb.metrics().await.map_err(to_napi_error)?;
        Ok(metrics_to_js(&m))
    }

    /// Stream metrics snapshots at the requested interval (in milliseconds).
    #[napi]
    pub async fn metrics_stream(&self, interval_ms: f64) -> Result<JsMetricsStream> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        let interval = Duration::from_millis(interval_ms as u64);
        let mut stream = Box::pin(sb.metrics_stream(interval));

        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            while let Some(result) = stream.next().await {
                let item = result.map(|m| metrics_to_js(&m)).map_err(to_napi_error);
                if tx.send(item).await.is_err() {
                    break;
                }
            }
        });

        Ok(JsMetricsStream {
            rx: Arc::new(Mutex::new(rx)),
        })
    }

    //----------------------------------------------------------------------------------------------
    // Attach
    //----------------------------------------------------------------------------------------------

    /// Attach to an interactive PTY session inside the sandbox.
    ///
    /// Bridges the host terminal to the guest process. Returns the exit code.
    #[napi]
    pub async fn attach(&self, cmd: String, args: Option<Vec<String>>) -> Result<i32> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        let args_owned = args.unwrap_or_default();
        sb.attach(&cmd, args_owned).await.map_err(to_napi_error)
    }

    /// Attach with full configuration options.
    #[napi(js_name = "attachWithConfig")]
    pub async fn attach_with_config(&self, config: AttachConfig) -> Result<i32> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        sb.attach_with(&config.cmd, |mut b| {
            if let Some(ref args) = config.args {
                b = b.args(args.clone());
            }
            if let Some(ref cwd) = config.cwd {
                b = b.cwd(cwd);
            }
            if let Some(ref user) = config.user {
                b = b.user(user);
            }
            if let Some(ref env) = config.env {
                for (k, v) in env {
                    b = b.env(k, v);
                }
            }
            if let Some(ref keys) = config.detach_keys {
                b = b.detach_keys(keys);
            }
            b
        })
        .await
        .map_err(to_napi_error)
    }

    /// Attach to the sandbox's default shell.
    #[napi]
    pub async fn attach_shell(&self) -> Result<i32> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        sb.attach_shell().await.map_err(to_napi_error)
    }

    //----------------------------------------------------------------------------------------------
    // Lifecycle
    //----------------------------------------------------------------------------------------------

    /// Stop the sandbox gracefully (SIGTERM).
    #[napi]
    pub async fn stop(&self) -> Result<()> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        sb.stop().await.map_err(to_napi_error)
    }

    /// Stop and wait for exit, returning the exit status.
    #[napi]
    pub async fn stop_and_wait(&self) -> Result<ExitStatus> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        let status = sb.stop_and_wait().await.map_err(to_napi_error)?;
        Ok(exit_status_to_js(status))
    }

    /// Kill the sandbox immediately (SIGKILL).
    #[napi]
    pub async fn kill(&self) -> Result<()> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        sb.kill().await.map_err(to_napi_error)
    }

    /// Graceful drain (SIGUSR1 — for load balancing).
    #[napi]
    pub async fn drain(&self) -> Result<()> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        sb.drain().await.map_err(to_napi_error)
    }

    /// Wait for the sandbox process to exit.
    #[napi(js_name = "wait")]
    pub async fn wait_for_exit(&self) -> Result<ExitStatus> {
        let guard = self.inner.lock().await;
        let sb = guard.as_ref().ok_or_else(consumed_error)?;
        let status = sb.wait().await.map_err(to_napi_error)?;
        Ok(exit_status_to_js(status))
    }

    /// Detach from the sandbox — it will continue running after this handle is dropped.
    #[napi]
    pub async fn detach(&self) -> Result<()> {
        let mut guard = self.inner.lock().await;
        if let Some(sb) = guard.take() {
            sb.detach().await;
        }
        Ok(())
    }

    /// Remove the persisted database record after stopping.
    #[napi]
    pub async fn remove_persisted(&self) -> Result<()> {
        let mut guard = self.inner.lock().await;
        let sb = guard.take().ok_or_else(consumed_error)?;
        sb.remove_persisted().await.map_err(to_napi_error)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsMetricsStream {
    /// Receive the next metrics snapshot. Returns `null` when the stream ends.
    #[napi]
    pub async fn recv(&self) -> Result<Option<SandboxMetrics>> {
        let mut guard = self.rx.lock().await;
        match guard.recv().await {
            Some(result) => Ok(Some(result?)),
            None => Ok(None),
        }
    }
}

#[napi]
impl AsyncGenerator for JsMetricsStream {
    type Yield = SandboxMetrics;
    type Next = ();
    type Return = ();

    fn next(
        &mut self,
        _value: Option<Self::Next>,
    ) -> impl std::future::Future<Output = Result<Option<Self::Yield>>> + Send + 'static {
        let rx = Arc::clone(&self.rx);
        async move {
            let mut guard = rx.lock().await;
            match guard.recv().await {
                Some(result) => Ok(Some(result?)),
                None => Ok(None),
            }
        }
    }
}

/// Convert a JS `SandboxConfig` to the Rust `SandboxConfig` via the builder pattern.
async fn convert_config(config: SandboxConfig) -> Result<RustSandboxConfig> {
    let mut builder =
        microsandbox::sandbox::Sandbox::builder(&config.name).image(config.image.as_str());

    if let Some(mem) = config.memory_mib {
        builder = builder.memory(mem);
    }
    if let Some(cpus) = config.cpus {
        builder = builder.cpus(cpus);
    }
    if let Some(ref workdir) = config.workdir {
        builder = builder.workdir(workdir);
    }
    if let Some(ref shell) = config.shell {
        builder = builder.shell(shell);
    }
    if let Some(ref entrypoint) = config.entrypoint {
        builder = builder.entrypoint(entrypoint.clone());
    }
    if let Some(ref hostname) = config.hostname {
        builder = builder.hostname(hostname);
    }
    if let Some(ref libkrunfw_path) = config.libkrunfw_path {
        builder = builder.libkrunfw_path(libkrunfw_path);
    }
    if let Some(ref user) = config.user {
        builder = builder.user(user);
    }
    if let Some(ref env) = config.env {
        for (k, v) in env {
            builder = builder.env(k, v);
        }
    }
    if let Some(ref scripts) = config.scripts {
        for (k, v) in scripts {
            builder = builder.script(k, v);
        }
    }
    if let Some(ref volumes) = config.volumes {
        for (guest_path, mount) in volumes {
            builder = builder.volume(guest_path, |b| convert_mount(b, mount));
        }
    }
    if let Some(ref patches) = config.patches {
        for patch in patches {
            let rust_patch = convert_patch(patch)?;
            builder = builder.add_patch(rust_patch);
        }
    }
    if let Some(ref pull_policy) = config.pull_policy {
        let policy = match pull_policy.as_str() {
            "always" => PullPolicy::Always,
            "never" => PullPolicy::Never,
            _ => PullPolicy::IfMissing,
        };
        builder = builder.pull_policy(policy);
    }
    if let Some(ref log_level) = config.log_level {
        let level = match log_level.as_str() {
            "trace" => LogLevel::Trace,
            "debug" => LogLevel::Debug,
            "warn" => LogLevel::Warn,
            "error" => LogLevel::Error,
            _ => LogLevel::Info,
        };
        builder = builder.log_level(level);
    }
    if config.replace.unwrap_or(false) {
        builder = builder.replace();
    }
    if config.quiet_logs.unwrap_or(false) {
        builder = builder.quiet_logs();
    }
    if let Some(ref registry) = config.registry {
        let auth = registry.auth.as_ref().map(|a| RustRegistryAuth::Basic {
            username: a.username.clone(),
            password: a.password.clone(),
        });
        let insecure = registry.insecure.unwrap_or(false);
        let ca_certs = match &registry.ca_certs_path {
            Some(path) => Some(tokio::fs::read(path).await.map_err(|e| {
                napi::Error::from_reason(format!("failed to read CA certs from `{path}`: {e}"))
            })?),
            None => None,
        };

        builder = builder.registry(|mut r| {
            if let Some(auth) = auth {
                r = r.auth(auth);
            }
            if insecure {
                r = r.insecure();
            }
            if let Some(data) = ca_certs {
                r = r.ca_certs(data);
            }
            r
        });
    }
    if let Some(ref ports) = config.ports {
        for (host_str, guest) in ports {
            let host: u16 = host_str.parse().map_err(|_| {
                napi::Error::from_reason(format!("invalid port number: {host_str}"))
            })?;
            builder = builder.port(host, *guest as u16);
        }
    }
    if let Some(ref network) = config.network {
        let dns_nameservers = if let Some(ref dns) = network.dns
            && let Some(ref nameservers) = dns.nameservers
        {
            parse_nameservers(nameservers)?
        } else {
            Vec::new()
        };

        builder = builder.network(|mut n| {
            // Policy: preset or custom rules
            if let Some(ref rules) = network.rules {
                let default_action = match network.default_action.as_deref() {
                    Some("deny") => Action::Deny,
                    _ => Action::Allow,
                };
                // The TS-side `rules` array carries direction per rule, matching
                // the new single-list NetworkPolicy schema. A single TS-side
                // `default_action` maps to both direction defaults for backwards
                // compatibility. Proper 0.4 TS API replaces this shim
                // (see sdk/node-ts redesign, phase 7).
                let parsed_rules: Vec<_> = rules.iter().filter_map(convert_policy_rule).collect();
                n = n.policy(NetworkPolicy {
                    default_egress: default_action,
                    default_ingress: default_action,
                    rules: parsed_rules,
                });
            } else if let Some(ref policy) = network.policy {
                n = n.policy(match policy.as_str() {
                    "allow-all" => NetworkPolicy::allow_all(),
                    "none" => NetworkPolicy::none(),
                    _ => NetworkPolicy::public_only(),
                });
            }
            // DNS
            if let Some(ref dns) = network.dns {
                let block_domains = dns.block_domains.clone();
                let block_domain_suffixes = dns.block_domain_suffixes.clone();
                let rebind_protection = dns.rebind_protection;
                let query_timeout_ms = dns.query_timeout_ms;
                n = n.dns(move |mut d| {
                    if let Some(domains) = block_domains {
                        for domain in &domains {
                            d = d.block_domain(domain);
                        }
                    }
                    if let Some(suffixes) = block_domain_suffixes {
                        for suffix in &suffixes {
                            d = d.block_domain_suffix(suffix);
                        }
                    }
                    if let Some(rebind) = rebind_protection {
                        d = d.rebind_protection(rebind);
                    }
                    if !dns_nameservers.is_empty() {
                        d = d.nameservers(dns_nameservers);
                    }
                    if let Some(ms) = query_timeout_ms {
                        d = d.query_timeout_ms(u64::from(ms));
                    }
                    d
                });
            }
            // TLS
            if let Some(ref tls) = network.tls {
                n = n.tls(|mut t| {
                    if let Some(ref bypass) = tls.bypass {
                        for pattern in bypass {
                            t = t.bypass(pattern);
                        }
                    }
                    if let Some(verify) = tls.verify_upstream {
                        t = t.verify_upstream(verify);
                    }
                    if let Some(ref ports) = tls.intercepted_ports {
                        t = t.intercepted_ports(ports.iter().map(|&p| p as u16).collect());
                    }
                    if let Some(block) = tls.block_quic {
                        t = t.block_quic(block);
                    }
                    if let Some(ref path) = tls.intercept_ca_cert {
                        t = t.intercept_ca_cert(path);
                    }
                    if let Some(ref path) = tls.intercept_ca_key {
                        t = t.intercept_ca_key(path);
                    }
                    if let Some(ref paths) = tls.upstream_ca_cert {
                        for path in paths {
                            t = t.upstream_ca_cert(path);
                        }
                    }
                    t
                });
            }
            // Max connections
            if let Some(max) = network.max_connections {
                n = n.max_connections(max as usize);
            }
            if let Some(trust) = network.trust_host_cas {
                n = n.trust_host_cas(trust);
            }
            n
        });
    }
    // Secrets — via Secret.env().
    if let Some(ref secrets) = config.secrets {
        for entry in secrets {
            let env_var = entry.env_var.clone();
            let value = entry.value.clone();
            let allow_hosts = entry.allow_hosts.clone();
            let allow_host_patterns = entry.allow_host_patterns.clone();
            let placeholder = entry.placeholder.clone();
            let require_tls = entry.require_tls;
            let inject_headers = entry.inject.as_ref().and_then(|i| i.headers);
            let inject_basic_auth = entry.inject.as_ref().and_then(|i| i.basic_auth);
            let inject_query = entry.inject.as_ref().and_then(|i| i.query_params);
            let inject_body = entry.inject.as_ref().and_then(|i| i.body);
            builder = builder.secret(move |mut s| {
                s = s.env(&env_var).value(value);
                if let Some(hosts) = allow_hosts {
                    for host in hosts {
                        s = s.allow_host(host);
                    }
                }
                if let Some(patterns) = allow_host_patterns {
                    for pattern in patterns {
                        s = s.allow_host_pattern(pattern);
                    }
                }
                if let Some(p) = placeholder {
                    s = s.placeholder(p);
                }
                if let Some(require) = require_tls {
                    s = s.require_tls_identity(require);
                }
                if let Some(enabled) = inject_headers {
                    s = s.inject_headers(enabled);
                }
                if let Some(enabled) = inject_basic_auth {
                    s = s.inject_basic_auth(enabled);
                }
                if let Some(enabled) = inject_query {
                    s = s.inject_query(enabled);
                }
                if let Some(enabled) = inject_body {
                    s = s.inject_body(enabled);
                }
                s
            });
            if let Some(ref action_str) = entry.on_violation {
                builder = builder.network(|n| {
                    n.on_secret_violation(match action_str.as_str() {
                        "block" => ViolationAction::Block,
                        "block-and-terminate" => ViolationAction::BlockAndTerminate,
                        _ => ViolationAction::BlockAndLog,
                    })
                });
            }
        }
    }

    builder.build().map_err(to_napi_error)
}

/// Parse user-supplied nameserver strings into [`Nameserver`]s, wrapping any
/// parse error in a napi `Error` so it surfaces as a JS exception.
fn parse_nameservers(nameservers: &[String]) -> Result<Vec<Nameserver>> {
    nameservers
        .iter()
        .map(|s| {
            s.parse::<Nameserver>()
                .map_err(|e| napi::Error::from_reason(e.to_string()))
        })
        .collect()
}

fn convert_mount(
    builder: microsandbox::sandbox::MountBuilder,
    mount: &MountConfig,
) -> microsandbox::sandbox::MountBuilder {
    let mut b = builder;
    if let Some(ref bind_path) = mount.bind {
        b = b.bind(PathBuf::from(bind_path));
    } else if let Some(ref vol_name) = mount.named {
        b = b.named(vol_name);
    } else if mount.tmpfs.unwrap_or(false) {
        b = b.tmpfs();
    }
    if mount.readonly.unwrap_or(false) {
        b = b.readonly();
    }
    if let Some(size) = mount.size_mib {
        b = b.size(size);
    }
    b
}

fn convert_patch(patch: &PatchConfig) -> Result<microsandbox::sandbox::Patch> {
    use microsandbox::sandbox::Patch;
    match patch.kind.as_str() {
        "text" => Ok(Patch::Text {
            path: patch.path.clone().unwrap_or_default(),
            content: patch.content.clone().unwrap_or_default(),
            mode: patch.mode,
            replace: patch.replace.unwrap_or(false),
        }),
        "copyFile" => Ok(Patch::CopyFile {
            src: PathBuf::from(patch.src.clone().unwrap_or_default()),
            dst: patch.dst.clone().unwrap_or_default(),
            mode: patch.mode,
            replace: patch.replace.unwrap_or(false),
        }),
        "copyDir" => Ok(Patch::CopyDir {
            src: PathBuf::from(patch.src.clone().unwrap_or_default()),
            dst: patch.dst.clone().unwrap_or_default(),
            replace: patch.replace.unwrap_or(false),
        }),
        "symlink" => Ok(Patch::Symlink {
            target: patch.target.clone().unwrap_or_default(),
            link: patch.link.clone().unwrap_or_default(),
            replace: patch.replace.unwrap_or(false),
        }),
        "mkdir" => Ok(Patch::Mkdir {
            path: patch.path.clone().unwrap_or_default(),
            mode: patch.mode,
        }),
        "remove" => Ok(Patch::Remove {
            path: patch.path.clone().unwrap_or_default(),
        }),
        "append" => Ok(Patch::Append {
            path: patch.path.clone().unwrap_or_default(),
            content: patch.content.clone().unwrap_or_default(),
        }),
        other => Err(napi::Error::from_reason(format!(
            "unknown patch kind: {other}"
        ))),
    }
}

pub fn metrics_to_js(m: &microsandbox::sandbox::SandboxMetrics) -> SandboxMetrics {
    SandboxMetrics {
        cpu_percent: m.cpu_percent as f64,
        memory_bytes: m.memory_bytes as f64,
        memory_limit_bytes: m.memory_limit_bytes as f64,
        disk_read_bytes: m.disk_read_bytes as f64,
        disk_write_bytes: m.disk_write_bytes as f64,
        net_rx_bytes: m.net_rx_bytes as f64,
        net_tx_bytes: m.net_tx_bytes as f64,
        uptime_ms: m.uptime.as_millis() as f64,
        timestamp_ms: datetime_to_ms(&m.timestamp),
    }
}

fn sandbox_handle_to_info(handle: &microsandbox::sandbox::SandboxHandle) -> SandboxInfo {
    SandboxInfo {
        name: handle.name().to_string(),
        status: format!("{:?}", handle.status()).to_lowercase(),
        config_json: handle.config_json().to_string(),
        created_at: opt_datetime_to_ms(&handle.created_at()),
        updated_at: opt_datetime_to_ms(&handle.updated_at()),
    }
}

/// Convert a TS-side rule into the new single-list `Rule` shape with
/// per-rule direction. The TS-side `direction` field accepts `"egress"`,
/// `"ingress"`, `"any"`, or the legacy `"outbound"` / `"inbound"` aliases.
fn convert_policy_rule(rule: &PolicyRule) -> Option<Rule> {
    let action = match rule.action.as_str() {
        "deny" => Action::Deny,
        _ => Action::Allow,
    };
    let direction = match rule.direction.as_deref() {
        Some("ingress") | Some("inbound") => Direction::Ingress,
        Some("any") => Direction::Any,
        // Default and "egress" / "outbound" map to Egress.
        _ => Direction::Egress,
    };
    let destination = match rule.destination.as_deref() {
        Some("*") | None => Destination::Any,
        Some("loopback") => Destination::Group(DestinationGroup::Loopback),
        Some("private") => Destination::Group(DestinationGroup::Private),
        Some("link-local") => Destination::Group(DestinationGroup::LinkLocal),
        Some("metadata") => Destination::Group(DestinationGroup::Metadata),
        Some("multicast") => Destination::Group(DestinationGroup::Multicast),
        Some("host") => Destination::Group(DestinationGroup::Host),
        Some("public") => Destination::Group(DestinationGroup::Public),
        Some(s) if s.starts_with('.') => Destination::DomainSuffix(s.parse().ok()?),
        Some(s) if s.contains('/') => {
            // CIDR notation
            match s.parse() {
                Ok(cidr) => Destination::Cidr(cidr),
                Err(_) => return None,
            }
        }
        Some(s) => Destination::Domain(s.parse().ok()?),
    };
    let protocols = match rule.protocol.as_deref() {
        Some(p) => vec![match p {
            "udp" => Protocol::Udp,
            "icmpv4" => Protocol::Icmpv4,
            "icmpv6" => Protocol::Icmpv6,
            _ => Protocol::Tcp,
        }],
        None => Vec::new(),
    };
    let ports = match rule.port.as_deref() {
        Some(p) => {
            if let Some((start, end)) = p.split_once('-') {
                vec![PortRange::range(start.parse().ok()?, end.parse().ok()?)]
            } else {
                vec![PortRange::single(p.parse().ok()?)]
            }
        }
        None => Vec::new(),
    };

    Some(Rule {
        direction,
        destination,
        protocols,
        ports,
        action,
    })
}

fn exit_status_to_js(status: std::process::ExitStatus) -> ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    let code = status.code().unwrap_or_else(|| {
        // If no code, the process was killed by a signal.
        status.signal().map(|s| 128 + s).unwrap_or(-1)
    });
    ExitStatus {
        code,
        success: status.success(),
    }
}

fn consumed_error() -> napi::Error {
    napi::Error::from_reason("Sandbox handle has been consumed (detached or removed)")
}

//! Destination-only snapshot spawning and independently consumable progress for Ruby.

use std::{cell::RefCell, sync::Arc};

use magnus::{
    Error, RArray, RHash, RModule, Ruby, Value, method, prelude::*, scan_args::scan_args,
    typed_data,
};
use microsandbox_core::{
    CreationProgressHandle, MicrosandboxError, MicrosandboxResult,
    sandbox::{
        ExternalMountRestorePolicy, GuestClockPolicy, PullPolicy, RestoreBuilder, Sandbox,
        SecurityProfile,
    },
};
use tokio::{
    sync::Mutex,
    task::{AbortHandle, JoinHandle},
};

use super::snapshot_group::RubyGroup;
use super::{
    RubyOutboundProxy, RubyOutboundProxyConfig, RubySandbox, RubySnapshot, argument_error, keyword,
    reject_unknown_keywords, run, string_array, string_map, string_value, symbol,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

type SpawnTask = JoinHandle<MicrosandboxResult<Sandbox>>;

/// Progress and completion have separate locks: waiting for one never prevents cancellation or
/// consumption of the other. No Ruby objects are retained by native asynchronous work.
#[magnus::wrap(class = "Microsandbox::PullSession", free_immediately, size)]
pub(super) struct RubyPullSession {
    pid: u32,
    abort: AbortHandle,
    progress: Arc<Mutex<CreationProgressHandle>>,
    task: Arc<Mutex<Option<SpawnTask>>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RubyPullSession {
    fn new((progress, task): (CreationProgressHandle, SpawnTask)) -> Self {
        Self {
            pid: std::process::id(),
            abort: task.abort_handle(),
            progress: Arc::new(Mutex::new(progress)),
            task: Arc::new(Mutex::new(Some(task))),
        }
    }

    fn check_process(&self, ruby: &Ruby) -> Result<(), Error> {
        if self.pid != std::process::id() {
            return Err(argument_error(
                ruby,
                "a creation session cannot be used after fork; start a new operation in this process",
            ));
        }
        Ok(())
    }

    fn cancel(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<(), Error> {
        this.check_process(ruby)?;
        this.abort.abort();
        Ok(())
    }

    fn next_event(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<Option<RHash>, Error> {
        this.check_process(ruby)?;
        let progress = this.progress.clone();
        let event = run(ruby, async move { Ok(progress.lock().await.recv().await) })?;
        // Serialization and Ruby allocation happen only after reacquiring the interpreter lock.
        event
            .map(|event| {
                ruby.require("json")?;
                let json: RModule = ruby.class_object().const_get("JSON")?;
                let payload = serde_json::to_string(&event)
                    .map_err(|e| argument_error(ruby, e.to_string()))?;
                json.funcall("parse", (payload,))
            })
            .transpose()
    }

    fn result(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<RubySandbox, Error> {
        this.check_process(ruby)?;
        let task = this.task.clone();
        let sandbox = run(ruby, async move {
            let task = task.lock().await.take().ok_or_else(|| {
                MicrosandboxError::InvalidConfig("result already consumed".into())
            })?;
            task.await.map_err(|error| {
                MicrosandboxError::Runtime(format!("sandbox creation task failed: {error}"))
            })?
        })?;
        Ok(RubySandbox {
            inner: RefCell::new(Some(sandbox)),
        })
    }
}

impl RubyGroup {
    fn spawn_sandbox(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        args: &[Value],
    ) -> Result<RubySandbox, Error> {
        let builder = destination(ruby, args, true)?;
        let group = this.inner.clone();
        let sandbox = run(
            ruby,
            async move { group.spawn_sandbox_with(|_| builder).await },
        )?;
        Ok(RubySandbox {
            inner: RefCell::new(Some(sandbox)),
        })
    }

    fn spawn_sandbox_with_progress(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        args: &[Value],
    ) -> Result<RubyPullSession, Error> {
        let builder = destination(ruby, args, true)?;
        let group = this.inner.clone();
        Ok(RubyPullSession::new(run(ruby, async move {
            group.spawn_sandbox_with_progress_with(|_| builder).await
        })?))
    }
}

impl RubySnapshot {
    fn spawn_sandbox(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        args: &[Value],
    ) -> Result<RubySandbox, Error> {
        let builder = destination(ruby, args, this.inner.path().is_ok())?;
        let checkpoint = this.inner.clone();
        let sandbox = run(ruby, async move {
            checkpoint.spawn_sandbox_with(|_| builder).await
        })?;
        Ok(RubySandbox {
            inner: RefCell::new(Some(sandbox)),
        })
    }

    fn spawn_sandbox_with_progress(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        args: &[Value],
    ) -> Result<RubyPullSession, Error> {
        let builder = destination(ruby, args, this.inner.path().is_ok())?;
        let checkpoint = this.inner.clone();
        Ok(RubyPullSession::new(run(ruby, async move {
            checkpoint
                .spawn_sandbox_with_progress_with(|_| builder)
                .await
        })?))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn choice(options: RHash, name: &str) -> Result<Option<String>, Error> {
    options
        .get(symbol(name))
        .filter(|value| !value.is_nil())
        .map(|value| string_value(value, name))
        .transpose()
}

/// Capture local host paths while Ruby still holds the GVL. A cloud receiver's paths belong to
/// its backend and must never be resolved against the SDK client's working directory.
fn host_path(ruby: &Ruby, value: String, local: bool) -> Result<String, Error> {
    if !local {
        return Ok(value);
    }
    let path =
        std::path::absolute(value).map_err(|error| argument_error(ruby, error.to_string()))?;
    path.into_os_string()
        .into_string()
        .map_err(|_| argument_error(ruby, "host path is not valid UTF-8"))
}

/// Parse only destination controls. The receiver supplies the source and owning backend; callers
/// cannot smuggle a replacement source, image or fresh-boot execution defaults into full resume.
fn destination(ruby: &Ruby, args: &[Value], local: bool) -> Result<RestoreBuilder, Error> {
    let parsed = scan_args::<(), (), (), (), RHash, ()>(args)?;
    let options = parsed.keywords;
    reject_unknown_keywords(
        ruby,
        options,
        &[
            "name",
            "cpus",
            "memory",
            "max_cpus",
            "max_memory",
            "labels",
            "workdir",
            "shell",
            "entrypoint",
            "cmd",
            "env",
            "network",
            "pull_policy",
            "proxy",
            "disable_network",
            "security",
            "max_duration",
            "idle_timeout",
            "max_tcp_connections",
            "max_udp_connections",
            "cow_memory",
            "disk_only",
            "snapshot_base",
            "log_level",
            "user",
            "volumes",
            "captured_volumes",
            "ports",
            "vsock",
            "max_inbound_tcp_connections",
            "tcp_accept_queue_size",
            "external_mount_policy",
            "dangerously_inherit_resources",
            "allow_missing_resources",
            "guest_clock",
            "init",
            "hostname",
        ],
    )?;
    let mut builder = Sandbox::restore_ref(microsandbox_core::SnapshotReference::auto(""));
    if let Some(v) = keyword::<String>(options, "name")? {
        builder = builder.name(v);
    }
    if let Some(v) = keyword::<String>(options, "pull_policy")? {
        let p = match v.to_ascii_lowercase().as_str() {
            "if_missing" | "if-missing" => PullPolicy::IfMissing,
            "always" => PullPolicy::Always,
            "never" => PullPolicy::Never,
            other => {
                return Err(argument_error(
                    ruby,
                    format!("pull_policy must be if_missing, always, or never; got {other}"),
                ));
            }
        };
        builder = builder.pull_policy(p);
    }
    if let Some(proxy) = keyword::<&RubyOutboundProxy>(options, "proxy")? {
        builder = match proxy.inner.borrow().clone() {
            RubyOutboundProxyConfig::HttpConnect { address } => {
                builder.proxy(|proxy| proxy.http_connect(address))
            }
            RubyOutboundProxyConfig::Socks4 {
                address,
                user_id: Some(user_id),
            } => builder.proxy(|proxy| proxy.socks4(address).user_id(user_id)),
            RubyOutboundProxyConfig::Socks4 {
                address,
                user_id: None,
            } => builder.proxy(|proxy| proxy.socks4(address)),
            RubyOutboundProxyConfig::Socks5 {
                address,
                credentials: Some((username, password)),
            } => builder.proxy(|proxy| proxy.socks5(address).credentials(username, password)),
            RubyOutboundProxyConfig::Socks5 {
                address,
                credentials: None,
            } => builder.proxy(|proxy| proxy.socks5(address)),
        };
    }
    if let Some(v) = keyword::<u8>(options, "cpus")? {
        builder = builder.cpus(v);
    }
    if let Some(v) = keyword::<u32>(options, "memory")? {
        builder = builder.memory(v);
    }
    if let Some(v) = keyword::<u8>(options, "max_cpus")? {
        builder = builder.max_cpus(v);
    }
    if let Some(v) = keyword::<u32>(options, "max_memory")? {
        builder = builder.max_memory(v);
    }
    if let Some(v) = options.get(symbol("labels")).filter(|v| !v.is_nil()) {
        builder = builder.labels(string_map(v, "labels")?);
    }
    if let Some(v) = keyword::<String>(options, "workdir")? {
        builder = builder.workdir(v);
    }
    if let Some(v) = keyword::<String>(options, "shell")? {
        builder = builder.shell(v);
    }
    if let Some(v) = options.get(symbol("entrypoint")).filter(|v| !v.is_nil()) {
        builder = builder.entrypoint(string_array(v, "entrypoint")?);
    }
    if let Some(v) = options.get(symbol("cmd")).filter(|v| !v.is_nil()) {
        builder = builder.cmd(string_array(v, "cmd")?);
    }
    if let Some(v) = options.get(symbol("env")).filter(|v| !v.is_nil()) {
        builder = builder.envs(string_map(v, "env")?);
    }
    if let Some(v) = keyword::<String>(options, "init")? {
        builder = builder.init(v);
    }
    if let Some(v) = keyword::<String>(options, "hostname")? {
        builder = builder.hostname(v);
    }
    if let Some(v) = keyword::<u64>(options, "max_duration")? {
        builder = builder.max_duration(v);
    }
    if let Some(v) = keyword::<u64>(options, "idle_timeout")? {
        builder = builder.idle_timeout(v);
    }
    if let Some(v) = keyword::<usize>(options, "max_tcp_connections")? {
        builder = builder.max_tcp_connections(v);
    }
    if let Some(v) = keyword::<usize>(options, "max_udp_connections")? {
        builder = builder.max_udp_connections(v);
    }
    if let Some(v) = keyword::<usize>(options, "max_inbound_tcp_connections")? {
        builder = builder.max_inbound_tcp_connections(v);
    }
    if let Some(v) = keyword::<u32>(options, "tcp_accept_queue_size")? {
        builder = builder.tcp_accept_queue_size(v);
    }
    if let Some(v) = keyword::<String>(options, "snapshot_base")? {
        let path_like = v.contains('/')
            || v.starts_with(['.', '~'])
            || std::path::Path::new(&v).is_file()
            || (cfg!(windows) && (v.contains('\\') || v.as_bytes().get(1) == Some(&b':')));
        builder = builder.snapshot_base(host_path(ruby, v, local && path_like)?);
    }
    if let Some(v) = keyword::<String>(options, "user")? {
        builder = builder.user(v);
    }
    if keyword::<bool>(options, "disable_network")?.unwrap_or(false) {
        builder = builder.disable_network();
    }
    if keyword::<bool>(options, "cow_memory")?.unwrap_or(false) {
        builder = builder.cow_memory();
    }
    if keyword::<bool>(options, "disk_only")?.unwrap_or(false) {
        builder = builder.disk_only();
    }
    if keyword::<bool>(options, "allow_missing_resources")?.unwrap_or(false) {
        builder = builder.allow_missing_resources();
    }
    if keyword::<bool>(options, "dangerously_inherit_resources")?.unwrap_or(false) {
        builder = builder.dangerously_inherit_resources();
    }
    if let Some(network) = options.get(symbol("network")).filter(|v| !v.is_nil()) {
        if let Some(value) = magnus::Symbol::from_value(network) {
            if value.name()?.as_ref() != "none" {
                return Err(argument_error(
                    ruby,
                    "network must be :none or a policy Hash",
                ));
            }
            builder = builder.disable_network();
        } else {
            builder = builder.network_policy(super::restricted_network_policy(ruby, network)?);
        }
    }
    if let Some(v) = choice(options, "security")? {
        builder = builder.security(match v.as_str() {
            "default" => SecurityProfile::Default,
            "restricted" => SecurityProfile::Restricted,
            _ => {
                return Err(argument_error(
                    ruby,
                    "security must be default or restricted",
                ));
            }
        });
    }
    if let Some(v) = choice(options, "guest_clock")? {
        builder = builder.guest_clock(match v.as_str() {
            "sync" => GuestClockPolicy::Sync,
            "off" => GuestClockPolicy::Off,
            _ => return Err(argument_error(ruby, "guest_clock must be sync or off")),
        });
    }
    if let Some(v) = choice(options, "log_level")? {
        builder = builder.log_level(match v.as_str() {
            "trace" => microsandbox_core::LogLevel::Trace,
            "debug" => microsandbox_core::LogLevel::Debug,
            "info" => microsandbox_core::LogLevel::Info,
            "warn" => microsandbox_core::LogLevel::Warn,
            "error" => microsandbox_core::LogLevel::Error,
            _ => return Err(argument_error(ruby, "invalid log_level")),
        });
    }
    if let Some(v) = choice(options, "external_mount_policy")? {
        builder = builder.external_mount_policy(match v.as_str() {
            "strict" => ExternalMountRestorePolicy::Strict,
            "relaxed" => ExternalMountRestorePolicy::Relaxed,
            _ => {
                return Err(argument_error(
                    ruby,
                    "external_mount_policy must be strict or relaxed",
                ));
            }
        });
    }
    // Explicit mappings are data, never evaluated Ruby callbacks on the native worker.
    if let Some(volumes) = keyword::<RHash>(options, "volumes")? {
        let mut bindings = Vec::new();
        volumes.foreach(|guest: String, config: RHash| {
            reject_unknown_keywords(ruby, config, &["bind", "named", "disk", "readonly"])?;
            let bind = keyword::<String>(config, "bind")?
                .map(|v| host_path(ruby, v, local))
                .transpose()?;
            let named = keyword::<String>(config, "named")?;
            let disk = keyword::<String>(config, "disk")?
                .map(|v| host_path(ruby, v, local))
                .transpose()?;
            if usize::from(bind.is_some())
                + usize::from(named.is_some())
                + usize::from(disk.is_some())
                != 1
            {
                return Err(argument_error(
                    ruby,
                    "each volume requires exactly one of bind, named or disk",
                ));
            }
            bindings.push((
                guest,
                bind,
                named,
                disk,
                keyword::<bool>(config, "readonly")?.unwrap_or(false),
            ));
            Ok(magnus::r_hash::ForEach::Continue)
        })?;
        for (guest, bind, named, disk, readonly) in bindings {
            builder = builder.volume(guest, |mut mount| {
                if let Some(path) = bind {
                    mount = mount.bind(path);
                }
                if let Some(name) = named {
                    mount = mount.named(name);
                }
                if let Some(path) = disk {
                    mount = mount.disk(path);
                }
                if readonly {
                    mount = mount.readonly();
                }
                mount
            });
        }
    }
    if let Some(paths) = keyword::<Vec<String>>(options, "captured_volumes")? {
        for guest in paths {
            builder = builder.volume(guest, |mount| mount.captured());
        }
    }
    if let Some(ports) = keyword::<RArray>(options, "ports")? {
        for index in 0..ports.len() {
            let port: RHash = ports.entry(index as isize)?;
            reject_unknown_keywords(ruby, port, &["host", "guest", "bind", "protocol"])?;
            let host = super::required_keyword::<u16>(port, "host", ruby)?;
            let guest = super::required_keyword::<u16>(port, "guest", ruby)?;
            let bind = keyword::<String>(port, "bind")?
                .map(|v| {
                    v.parse::<std::net::IpAddr>()
                        .map_err(|e| argument_error(ruby, e.to_string()))
                })
                .transpose()?;
            builder = match (choice(port, "protocol")?.as_deref().unwrap_or("tcp"), bind) {
                ("tcp", None) => builder.port(host, guest),
                ("tcp", Some(bind)) => builder.port_bind(bind, host, guest),
                ("udp", None) => builder.port_udp(host, guest),
                ("udp", Some(bind)) => builder.port_udp_bind(bind, host, guest),
                _ => return Err(argument_error(ruby, "port protocol must be tcp or udp")),
            };
        }
    }
    if let Some(routes) = keyword::<RArray>(options, "vsock")? {
        for index in 0..routes.len() {
            let route: RHash = routes.entry(index as isize)?;
            reject_unknown_keywords(ruby, route, &["path", "port", "datagram"])?;
            let path = host_path(
                ruby,
                super::required_keyword::<String>(route, "path", ruby)?,
                local,
            )?;
            let port = super::required_keyword::<u32>(route, "port", ruby)?;
            builder = if keyword::<bool>(route, "datagram")?.unwrap_or(false) {
                builder.vsock_dgram(path, port)
            } else {
                builder.vsock(path, port)
            };
        }
    }
    Ok(builder)
}

pub(super) fn register(ruby: &Ruby, module: RModule) -> Result<(), Error> {
    let group: magnus::RClass = module.const_get("Snapshot")?;
    group.define_method("spawn_sandbox", method!(RubyGroup::spawn_sandbox, -1))?;
    group.define_method(
        "spawn_sandbox_with_progress",
        method!(RubyGroup::spawn_sandbox_with_progress, -1),
    )?;
    let checkpoint: magnus::RClass = module.const_get("Checkpoint")?;
    checkpoint.define_method("spawn_sandbox", method!(RubySnapshot::spawn_sandbox, -1))?;
    checkpoint.define_method(
        "spawn_sandbox_with_progress",
        method!(RubySnapshot::spawn_sandbox_with_progress, -1),
    )?;
    let session = module.define_class("PullSession", ruby.class_object())?;
    session.define_method("next_event", method!(RubyPullSession::next_event, 0))?;
    session.define_method("result", method!(RubyPullSession::result, 0))?;
    session.define_method("cancel", method!(RubyPullSession::cancel, 0))?;
    Ok(())
}

use std::{fmt::Display, future::Future, sync::OnceLock, time::Duration};

use magnus::{
    Error, ExceptionClass, RArray, RHash, RString, Ruby, Symbol, TryConvert, Value, function,
    method, prelude::*, r_hash::ForEach, scan_args::scan_args, typed_data,
};
use microsandbox_core::{
    MicrosandboxResult,
    sandbox::{
        ExecOptionsBuilder, ExecOutput, NetworkPolicy, PullPolicy, RlimitResource,
        Sandbox as CoreSandbox, SandboxBuilder, SandboxHandle as CoreSandboxHandle, SandboxPage,
        SandboxStatus, SandboxStopResult,
    },
};

//--------------------------------------------------------------------------------------------------
// Runtime
//--------------------------------------------------------------------------------------------------

static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fn current_ruby() -> Ruby {
    Ruby::get().expect("Ruby VM is not available")
}

fn runtime() -> Result<&'static tokio::runtime::Runtime, Error> {
    if let Some(runtime) = RUNTIME.get() {
        return Ok(runtime);
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| Error::new(current_ruby().exception_runtime_error(), error.to_string()))?;
    let _ = RUNTIME.set(runtime);
    Ok(RUNTIME
        .get()
        .expect("Tokio runtime disappeared after initialization"))
}

fn native_error(ruby: &Ruby, error: impl Display) -> Error {
    let message = error.to_string();
    let exception = ruby
        .define_module("Microsandbox")
        .and_then(|module| module.const_get::<_, ExceptionClass>("Error"))
        .unwrap_or_else(|_| ruby.exception_runtime_error());
    Error::new(exception, message)
}

fn run<F, T>(ruby: &Ruby, future: F) -> Result<T, Error>
where
    F: Future<Output = MicrosandboxResult<T>>,
{
    runtime()?
        .block_on(future)
        .map_err(|error| native_error(ruby, error))
}

fn symbol(name: &str) -> Symbol {
    current_ruby().to_symbol(name)
}

fn argument_error(ruby: &Ruby, message: impl Into<String>) -> Error {
    Error::new(ruby.exception_arg_error(), message.into())
}

fn keyword_names(kwargs: RHash) -> Result<Vec<String>, Error> {
    let mut names = Vec::with_capacity(kwargs.len());
    kwargs.foreach(|key: Symbol, _value: Value| {
        names.push(key.name()?.into_owned());
        Ok(ForEach::Continue)
    })?;
    Ok(names)
}

fn reject_unknown_keywords(ruby: &Ruby, kwargs: RHash, allowed: &[&str]) -> Result<(), Error> {
    for key in keyword_names(kwargs)? {
        if !allowed.contains(&key.as_str()) {
            return Err(argument_error(ruby, format!("unknown keyword: :{key}")));
        }
    }
    Ok(())
}

fn keyword<T: TryConvert>(kwargs: RHash, name: &str) -> Result<Option<T>, Error> {
    kwargs
        .get(current_ruby().to_symbol(name))
        .filter(|value| !value.is_nil())
        .map(TryConvert::try_convert)
        .transpose()
}

fn string_value(value: Value, name: &str) -> Result<String, Error> {
    if let Some(symbol) = Symbol::from_value(value) {
        return Ok(symbol.name()?.into_owned());
    }
    RString::try_convert(value)
        .and_then(|string| string.to_string())
        .map_err(|_| {
            Error::new(
                current_ruby().exception_type_error(),
                format!("{name} must be a String or Symbol"),
            )
        })
}

fn string_map(value: Value, name: &str) -> Result<Vec<(String, String)>, Error> {
    let hash = RHash::try_convert(value).map_err(|_| {
        Error::new(
            current_ruby().exception_type_error(),
            format!("{name} must be a Hash"),
        )
    })?;
    let mut values = Vec::with_capacity(hash.len());
    hash.foreach(|key: Value, value: Value| {
        let key = string_value(key, name)?;
        let value = String::try_convert(value).map_err(|_| {
            Error::new(
                current_ruby().exception_type_error(),
                format!("{name} values must be Strings"),
            )
        })?;
        values.push((key, value));
        Ok(ForEach::Continue)
    })?;
    Ok(values)
}

fn string_array(value: Value, name: &str) -> Result<Vec<String>, Error> {
    let array = RArray::try_convert(value).map_err(|_| {
        Error::new(
            current_ruby().exception_type_error(),
            format!("{name} must be an Array"),
        )
    })?;
    array.to_vec::<String>().map_err(|_| {
        Error::new(
            current_ruby().exception_type_error(),
            format!("{name} must contain only Strings"),
        )
    })
}
fn required_keyword<T: TryConvert>(hash: RHash, name: &str, ruby: &Ruby) -> Result<T, Error> {
    keyword(hash, name)?.ok_or_else(|| argument_error(ruby, format!("missing keyword: :{name}")))
}

fn restricted_network_policy(ruby: &Ruby, value: Value) -> Result<NetworkPolicy, Error> {
    let hash = RHash::try_convert(value)
        .map_err(|_| argument_error(ruby, "network must be :none or a Hash"))?;
    reject_unknown_keywords(ruby, hash, &["allowed_hosts", "allowed_ports"])?;
    let hosts = required_keyword::<RArray>(hash, "allowed_hosts", ruby)?
        .to_vec::<String>()
        .map_err(|_| argument_error(ruby, "allowed_hosts must contain only Strings"))?;
    let ports = required_keyword::<RArray>(hash, "allowed_ports", ruby)?
        .to_vec::<u16>()
        .map_err(|_| argument_error(ruby, "allowed_ports must contain integers"))?;

    NetworkPolicy::builder()
        .default_deny()
        .egress(|egress| egress.tcp().ports(ports).allow_domains(hosts))
        .build()
        .map_err(|error| native_error(ruby, error))
}

fn apply_secret_options(
    ruby: &Ruby,
    mut builder: SandboxBuilder,
    value: Value,
) -> Result<SandboxBuilder, Error> {
    let secrets = RArray::try_convert(value)
        .map_err(|_| argument_error(ruby, "secrets must be an Array of Hashes"))?;
    for index in 0..secrets.len() {
        let spec: RHash = secrets.entry(index as isize)?;
        let env = required_keyword::<String>(spec, "env", ruby)?;
        let secret = required_keyword::<String>(spec, "value", ruby)?;
        let host = required_keyword::<String>(spec, "allowed_host", ruby)?;
        builder = builder.secret_env(env, secret, host);
    }
    Ok(builder)
}

fn duration(ruby: &Ruby, seconds: f64, name: &str) -> Result<Duration, Error> {
    if !seconds.is_finite() || seconds < 0.0 {
        return Err(argument_error(
            ruby,
            format!("{name} must be a finite, non-negative number"),
        ));
    }
    Duration::try_from_secs_f64(seconds)
        .map_err(|_| argument_error(ruby, format!("{name} is too large")))
}
fn parse_timeout(
    ruby: &Ruby,
    positional: Option<f64>,
    kwargs: RHash,
    method: &str,
) -> Result<Option<Duration>, Error> {
    reject_unknown_keywords(ruby, kwargs, &["timeout"])?;
    let keyword = keyword::<f64>(kwargs, "timeout")?;
    if positional.is_some() && keyword.is_some() {
        return Err(argument_error(
            ruby,
            format!("{method} accepts timeout once"),
        ));
    }
    positional
        .or(keyword)
        .map(|seconds| duration(ruby, seconds, "timeout"))
        .transpose()
}

fn parse_resource(value: Value, ruby: &Ruby) -> Result<RlimitResource, Error> {
    let resource = string_value(value, "resource")?;
    match resource.as_str() {
        "cpu" => Ok(RlimitResource::Cpu),
        "fsize" => Ok(RlimitResource::Fsize),
        "data" => Ok(RlimitResource::Data),
        "stack" => Ok(RlimitResource::Stack),
        "core" => Ok(RlimitResource::Core),
        "rss" => Ok(RlimitResource::Rss),
        "nproc" => Ok(RlimitResource::Nproc),
        "nofile" => Ok(RlimitResource::Nofile),
        "memlock" => Ok(RlimitResource::Memlock),
        "as" => Ok(RlimitResource::As),
        "locks" => Ok(RlimitResource::Locks),
        "sigpending" => Ok(RlimitResource::Sigpending),
        "msgqueue" => Ok(RlimitResource::Msgqueue),
        "nice" => Ok(RlimitResource::Nice),
        "rtprio" => Ok(RlimitResource::Rtprio),
        "rttime" => Ok(RlimitResource::Rttime),
        other => Err(argument_error(
            ruby,
            format!("unknown rlimit resource: {other}"),
        )),
    }
}

fn apply_builder_options(
    ruby: &Ruby,
    mut builder: SandboxBuilder,
    kwargs: RHash,
) -> Result<SandboxBuilder, Error> {
    const ALLOWED: &[&str] = &[
        "image",
        "cpus",
        "max_cpus",
        "memory",
        "max_memory",
        "detached",
        "workdir",
        "shell",
        "hostname",
        "user",
        "env",
        "labels",
        "ephemeral",
        "max_duration",
        "idle_timeout",
        "replace",
        "replace_timeout",
        "root_disk",
        "disable_network",
        "network",
        "secrets",
        "quiet_logs",
        "entrypoint",
        "init",
        "pull_policy",
        "scripts",
        "slug",
    ];
    reject_unknown_keywords(ruby, kwargs, ALLOWED)?;

    if let Some(image) = keyword::<String>(kwargs, "image")? {
        builder = builder.image(image);
    }
    if let Some(cpus) = keyword::<u8>(kwargs, "cpus")? {
        builder = builder.cpus(cpus);
    }
    if let Some(max_cpus) = keyword::<u8>(kwargs, "max_cpus")? {
        builder = builder.max_cpus(max_cpus);
    }
    if let Some(memory) = keyword::<u32>(kwargs, "memory")? {
        builder = builder.memory(memory);
    }
    if let Some(max_memory) = keyword::<u32>(kwargs, "max_memory")? {
        builder = builder.max_memory(max_memory);
    }
    if let Some(detached) = keyword::<bool>(kwargs, "detached")? {
        builder = builder.detached(detached);
    }
    if let Some(workdir) = keyword::<String>(kwargs, "workdir")? {
        builder = builder.workdir(workdir);
    }
    if let Some(shell) = keyword::<String>(kwargs, "shell")? {
        builder = builder.shell(shell);
    }
    if let Some(hostname) = keyword::<String>(kwargs, "hostname")? {
        builder = builder.hostname(hostname);
    }
    if let Some(user) = keyword::<String>(kwargs, "user")? {
        builder = builder.user(user);
    }
    if let Some(env) = kwargs.get(symbol("env")) {
        builder = builder.envs(string_map(env, "env")?);
    }
    if let Some(labels) = kwargs.get(symbol("labels")) {
        builder = builder.labels(string_map(labels, "labels")?);
    }
    if let Some(ephemeral) = keyword::<bool>(kwargs, "ephemeral")? {
        builder = builder.ephemeral(ephemeral);
    }
    if let Some(max_duration) = keyword::<u64>(kwargs, "max_duration")? {
        builder = builder.max_duration(max_duration);
    }
    if let Some(idle_timeout) = keyword::<u64>(kwargs, "idle_timeout")? {
        builder = builder.idle_timeout(idle_timeout);
    }
    if keyword::<bool>(kwargs, "replace")?.unwrap_or(false) {
        builder = builder.replace();
    }
    if let Some(replace_timeout) = keyword::<f64>(kwargs, "replace_timeout")? {
        builder = builder.replace_with_timeout(duration(ruby, replace_timeout, "replace_timeout")?);
    }
    if let Some(root_disk) = keyword::<u32>(kwargs, "root_disk")? {
        builder = builder.root_disk(root_disk);
    }
    if keyword::<bool>(kwargs, "disable_network")?.unwrap_or(false) {
        builder = builder.disable_network();
    }
    if let Some(network) = kwargs.get(symbol("network")) {
        if let Some(network) = Symbol::from_value(network) {
            if network.name()?.as_ref() != "none" {
                return Err(argument_error(ruby, "network must be :none or a Hash"));
            }
            builder = builder.disable_network();
        } else {
            let policy = restricted_network_policy(ruby, network)?;
            builder = builder.network(|network| network.policy(policy));
        }
    }
    if let Some(secrets) = kwargs.get(symbol("secrets")) {
        builder = apply_secret_options(ruby, builder, secrets)?;
    }
    if keyword::<bool>(kwargs, "quiet_logs")?.unwrap_or(false) {
        builder = builder.quiet_logs();
    }
    if let Some(entrypoint) = kwargs.get(symbol("entrypoint")) {
        builder = builder.entrypoint(string_array(entrypoint, "entrypoint")?);
    }
    if let Some(init) = keyword::<String>(kwargs, "init")? {
        builder = builder.init(init);
    }
    if let Some(policy) = keyword::<String>(kwargs, "pull_policy")? {
        let policy = match policy.to_ascii_lowercase().as_str() {
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
        builder = builder.pull_policy(policy);
    }
    if let Some(scripts) = kwargs.get(symbol("scripts")) {
        builder = builder.scripts(string_map(scripts, "scripts")?);
    }
    if let Some(slug) = keyword::<String>(kwargs, "slug")? {
        builder = builder.slug(slug);
    }

    Ok(builder)
}

fn apply_exec_options(
    ruby: &Ruby,
    mut builder: ExecOptionsBuilder,
    kwargs: RHash,
) -> Result<ExecOptionsBuilder, Error> {
    const ALLOWED: &[&str] = &["cwd", "user", "env", "timeout", "stdin", "tty", "rlimits"];
    reject_unknown_keywords(ruby, kwargs, ALLOWED)?;

    if let Some(cwd) = keyword::<String>(kwargs, "cwd")? {
        builder = builder.cwd(cwd);
    }
    if let Some(user) = keyword::<String>(kwargs, "user")? {
        builder = builder.user(user);
    }
    if let Some(env) = kwargs.get(symbol("env")) {
        builder = builder.envs(string_map(env, "env")?);
    }
    if let Some(timeout) = keyword::<f64>(kwargs, "timeout")? {
        builder = builder.timeout(duration(ruby, timeout, "timeout")?);
    }
    if let Some(tty) = keyword::<bool>(kwargs, "tty")? {
        builder = builder.tty(tty);
    }
    if let Some(stdin) = kwargs.get(symbol("stdin")) {
        if let Some(symbol) = Symbol::from_value(stdin) {
            match symbol.name()?.as_ref() {
                "null" => builder = builder.stdin_null(),
                "pipe" => builder = builder.stdin_pipe(),
                value => {
                    return Err(argument_error(
                        ruby,
                        format!("stdin must be :null, :pipe, or a String; got :{value}"),
                    ));
                }
            }
            let string = RString::try_convert(stdin)?;
            // Copy immediately; no Ruby call can invalidate the borrowed bytes.
            let data = unsafe { string.as_slice() }.to_vec();
            builder = builder.stdin_bytes(data);
        }
    }
    if let Some(rlimits) = kwargs.get(symbol("rlimits")) {
        let limits = RHash::try_convert(rlimits).map_err(|_| {
            argument_error(ruby, "rlimits must be a Hash of resource names to limits")
        })?;
        let mut parsed_limits = Vec::with_capacity(limits.len());
        limits.foreach(|resource: Value, value: Value| {
            let resource = parse_resource(resource, ruby)?;
            let limit = u64::try_convert(value)
                .map_err(|_| argument_error(ruby, "rlimit values must be non-negative integers"))?;
            parsed_limits.push((resource, limit));
            Ok(ForEach::Continue)
        })?;
        for (resource, limit) in parsed_limits {
            builder = builder.rlimit(resource, limit);
        }
    }
    Ok(builder)
}

fn args_and_kwargs(args: &[Value]) -> Result<(String, RArray, RHash), Error> {
    let parsed = scan_args::<(String,), (Option<RArray>,), (), (), RHash, ()>(args)?;
    Ok((
        parsed.required.0,
        parsed
            .optional
            .0
            .unwrap_or_else(|| current_ruby().ary_new()),
        parsed.keywords,
    ))
}

fn exec_args_and_kwargs(args: &[Value]) -> Result<(String, Vec<String>, RHash), Error> {
    let (command, array, kwargs) = args_and_kwargs(args)?;
    Ok((command, array.to_vec::<String>()?, kwargs))
}

//--------------------------------------------------------------------------------------------------
// Wrapped types
//--------------------------------------------------------------------------------------------------

#[magnus::wrap(class = "Microsandbox::Sandbox", free_immediately, size)]
struct RubySandbox {
    inner: std::cell::RefCell<Option<CoreSandbox>>,
}

#[magnus::wrap(class = "Microsandbox::SandboxHandle", free_immediately, size)]
struct RubySandboxHandle {
    inner: CoreSandboxHandle,
}

#[magnus::wrap(class = "Microsandbox::SandboxBuilder", free_immediately, size)]
struct RubySandboxBuilder {
    inner: std::cell::RefCell<Option<SandboxBuilder>>,
}

#[magnus::wrap(class = "Microsandbox::ExecOutput", free_immediately, size)]
struct RubyExecOutput {
    inner: ExecOutput,
}

//--------------------------------------------------------------------------------------------------
// Builder methods
//--------------------------------------------------------------------------------------------------

fn take_builder(this: &RubySandboxBuilder) -> Result<SandboxBuilder, Error> {
    this.inner.borrow_mut().take().ok_or_else(|| {
        Error::new(
            current_ruby().exception_runtime_error(),
            "builder has been consumed",
        )
    })
}

fn put_builder<F>(this: &RubySandboxBuilder, update: F) -> Result<(), Error>
where
    F: FnOnce(SandboxBuilder) -> SandboxBuilder,
{
    let builder = take_builder(this)?;
    *this.inner.borrow_mut() = Some(update(builder));
    Ok(())
}

impl RubySandboxBuilder {
    fn image(this: typed_data::Obj<Self>, image: String) -> Result<(), Error> {
        put_builder(&this, |builder| builder.image(image))
    }

    fn cpus(this: typed_data::Obj<Self>, cpus: u8) -> Result<(), Error> {
        put_builder(&this, |builder| builder.cpus(cpus))
    }

    fn max_cpus(this: typed_data::Obj<Self>, cpus: u8) -> Result<(), Error> {
        put_builder(&this, |builder| builder.max_cpus(cpus))
    }

    fn memory(this: typed_data::Obj<Self>, memory: u32) -> Result<(), Error> {
        put_builder(&this, |builder| builder.memory(memory))
    }

    fn max_memory(this: typed_data::Obj<Self>, memory: u32) -> Result<(), Error> {
        put_builder(&this, |builder| builder.max_memory(memory))
    }

    fn env(this: typed_data::Obj<Self>, key: String, value: String) -> Result<(), Error> {
        put_builder(&this, |builder| builder.env(key, value))
    }

    fn label(this: typed_data::Obj<Self>, key: String, value: String) -> Result<(), Error> {
        put_builder(&this, |builder| builder.label(key, value))
    }

    fn workdir(this: typed_data::Obj<Self>, path: String) -> Result<(), Error> {
        put_builder(&this, |builder| builder.workdir(path))
    }

    fn shell(this: typed_data::Obj<Self>, shell: String) -> Result<(), Error> {
        put_builder(&this, |builder| builder.shell(shell))
    }

    fn hostname(this: typed_data::Obj<Self>, hostname: String) -> Result<(), Error> {
        put_builder(&this, |builder| builder.hostname(hostname))
    }

    fn user(this: typed_data::Obj<Self>, user: String) -> Result<(), Error> {
        put_builder(&this, |builder| builder.user(user))
    }

    fn detached(this: typed_data::Obj<Self>, detached: bool) -> Result<(), Error> {
        put_builder(&this, |builder| builder.detached(detached))
    }

    fn ephemeral(this: typed_data::Obj<Self>, ephemeral: bool) -> Result<(), Error> {
        put_builder(&this, |builder| builder.ephemeral(ephemeral))
    }

    fn max_duration(this: typed_data::Obj<Self>, seconds: u64) -> Result<(), Error> {
        put_builder(&this, |builder| builder.max_duration(seconds))
    }

    fn idle_timeout(this: typed_data::Obj<Self>, seconds: u64) -> Result<(), Error> {
        put_builder(&this, |builder| builder.idle_timeout(seconds))
    }

    fn replace(this: typed_data::Obj<Self>) -> Result<(), Error> {
        put_builder(&this, SandboxBuilder::replace)
    }

    fn replace_with_timeout(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        seconds: f64,
    ) -> Result<(), Error> {
        let timeout = duration(ruby, seconds, "replace_timeout")?;
        put_builder(&this, |builder| builder.replace_with_timeout(timeout))
    }

    fn root_disk(this: typed_data::Obj<Self>, memory: u32) -> Result<(), Error> {
        put_builder(&this, |builder| builder.root_disk(memory))
    }

    fn disable_network(this: typed_data::Obj<Self>) -> Result<(), Error> {
        put_builder(&this, SandboxBuilder::disable_network)
    }

    fn quiet_logs(this: typed_data::Obj<Self>) -> Result<(), Error> {
        put_builder(&this, SandboxBuilder::quiet_logs)
    }

    fn entrypoint(this: typed_data::Obj<Self>, command: RArray) -> Result<(), Error> {
        put_builder(&this, |builder| {
            builder.entrypoint(command.to_vec::<String>().unwrap_or_default())
        })
    }

    fn init(this: typed_data::Obj<Self>, command: String) -> Result<(), Error> {
        put_builder(&this, |builder| builder.init(command))
    }

    fn create(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<RubySandbox, Error> {
        let builder = take_builder(&this)?;
        let sandbox = run(ruby, builder.create())?;
        Ok(RubySandbox {
            inner: std::cell::RefCell::new(Some(sandbox)),
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Sandbox methods
//--------------------------------------------------------------------------------------------------

impl RubySandbox {
    fn inner_clone(&self) -> Result<CoreSandbox, Error> {
        self.inner.borrow().as_ref().cloned().ok_or_else(|| {
            Error::new(
                current_ruby().exception_runtime_error(),
                "sandbox handle has been detached",
            )
        })
    }

    fn name(&self) -> Result<String, Error> {
        Ok(self.inner_clone()?.name().to_owned())
    }

    fn owns_lifecycle(&self) -> Result<bool, Error> {
        Ok(self.inner_clone()?.owns_lifecycle())
    }

    fn backend(&self) -> Result<String, Error> {
        Ok(match self.inner_clone()?.backend_kind() {
            microsandbox_core::BackendKind::Local => "local",
            microsandbox_core::BackendKind::Cloud => "cloud",
        }
        .to_owned())
    }

    fn exec(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        args: &[Value],
    ) -> Result<RubyExecOutput, Error> {
        let (command, command_args, kwargs) = exec_args_and_kwargs(args)?;
        let sandbox = this.inner_clone()?;
        let options = apply_exec_options(ruby, ExecOptionsBuilder::default(), kwargs)?;
        let output = run(
            ruby,
            sandbox.exec_with(command, |_| options.args(command_args)),
        )?;
        Ok(RubyExecOutput { inner: output })
    }

    fn shell(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        args: &[Value],
    ) -> Result<RubyExecOutput, Error> {
        let parsed = scan_args::<(String,), (), (), (), RHash, ()>(args)?;
        let script = parsed.required.0;
        let sandbox = this.inner_clone()?;
        let options = apply_exec_options(ruby, ExecOptionsBuilder::default(), parsed.keywords)?;
        let output = run(ruby, sandbox.shell_with(script, |_| options))?;
        Ok(RubyExecOutput { inner: output })
    }
    fn stop(ruby: &Ruby, this: typed_data::Obj<Self>, args: &[Value]) -> Result<(), Error> {
        let parsed = scan_args::<(), (Option<f64>,), (), (), RHash, ()>(args)?;
        let timeout = parse_timeout(ruby, parsed.optional.0, parsed.keywords, "stop")?;
        let sandbox = this.inner_clone()?;
        run(ruby, async move {
            match timeout {
                Some(timeout) => sandbox.stop_with_timeout(timeout).await,
                None => sandbox.stop().await,
            }
        })
    }

    fn kill(ruby: &Ruby, this: typed_data::Obj<Self>, args: &[Value]) -> Result<(), Error> {
        let parsed = scan_args::<(), (Option<f64>,), (), (), RHash, ()>(args)?;
        let timeout = parse_timeout(ruby, parsed.optional.0, parsed.keywords, "kill")?;
        let sandbox = this.inner_clone()?;
        run(ruby, async move {
            match timeout {
                Some(timeout) => sandbox.kill_with_timeout(timeout).await,
                None => sandbox.kill().await,
            }
        })
    }

    fn request_stop(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<(), Error> {
        run(ruby, this.inner_clone()?.request_stop())
    }

    fn request_kill(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<(), Error> {
        run(ruby, this.inner_clone()?.request_kill())
    }

    fn wait_until_stopped(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<RHash, Error> {
        let result = run(ruby, this.inner_clone()?.wait_until_stopped())?;
        stop_result_hash(result)
    }

    fn detach(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<(), Error> {
        let sandbox = this.inner.borrow_mut().take().ok_or_else(|| {
            Error::new(
                ruby.exception_runtime_error(),
                "sandbox handle has been detached",
            )
        })?;
        runtime()?.block_on(sandbox.detach());
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Handle methods
//--------------------------------------------------------------------------------------------------

impl RubySandboxHandle {
    fn name(&self) -> String {
        self.inner.name().to_owned()
    }

    fn status(&self) -> String {
        status_name(self.inner.status_snapshot()).to_owned()
    }

    fn config_json(&self) -> String {
        self.inner.config_json().to_owned()
    }

    fn active_config_json(&self) -> Option<String> {
        self.inner.active_config_json().map(str::to_owned)
    }

    fn last_failure_message(&self) -> Option<String> {
        self.inner.last_failure_message_snapshot()
    }

    fn refresh(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<RubySandboxHandle, Error> {
        Ok(RubySandboxHandle {
            inner: run(ruby, this.inner.refresh())?,
        })
    }

    fn connect(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<RubySandbox, Error> {
        Ok(RubySandbox {
            inner: std::cell::RefCell::new(Some(run(ruby, this.inner.connect())?)),
        })
    }

    fn start(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        args: &[Value],
    ) -> Result<RubySandbox, Error> {
        let parsed = scan_args::<(), (), (), (), RHash, ()>(args)?;
        reject_unknown_keywords(ruby, parsed.keywords, &["detached"])?;
        let detached = keyword::<bool>(parsed.keywords, "detached")?.unwrap_or(false);
        let sandbox = if detached {
            run(ruby, this.inner.start_detached())?
        } else {
            run(ruby, this.inner.start())?
        };
        Ok(RubySandbox {
            inner: std::cell::RefCell::new(Some(sandbox)),
        })
    }

    fn stop(ruby: &Ruby, this: typed_data::Obj<Self>, args: &[Value]) -> Result<(), Error> {
        let parsed = scan_args::<(), (Option<f64>,), (), (), RHash, ()>(args)?;
        let timeout = parse_timeout(ruby, parsed.optional.0, parsed.keywords, "stop")?;
        run(ruby, async move {
            match timeout {
                Some(timeout) => this.inner.stop_with_timeout(timeout).await,
                None => this.inner.stop().await,
            }
        })
    }

    fn kill(ruby: &Ruby, this: typed_data::Obj<Self>, args: &[Value]) -> Result<(), Error> {
        let parsed = scan_args::<(), (Option<f64>,), (), (), RHash, ()>(args)?;
        let timeout = parse_timeout(ruby, parsed.optional.0, parsed.keywords, "kill")?;
        run(ruby, async move {
            match timeout {
                Some(timeout) => this.inner.kill_with_timeout(timeout).await,
                None => this.inner.kill().await,
            }
        })
    }

    fn remove(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<(), Error> {
        run(ruby, this.inner.remove())
    }

    fn wait_until_stopped(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<RHash, Error> {
        stop_result_hash(run(ruby, this.inner.wait_until_stopped())?)
    }
}

//--------------------------------------------------------------------------------------------------
// Exec output methods
//--------------------------------------------------------------------------------------------------

impl RubyExecOutput {
    fn stdout(&self) -> RString {
        current_ruby().str_from_slice(self.inner.stdout_bytes())
    }

    fn stderr(&self) -> RString {
        current_ruby().str_from_slice(self.inner.stderr_bytes())
    }

    fn stdout_bytes(&self) -> RString {
        current_ruby().str_from_slice(self.inner.stdout_bytes())
    }

    fn stderr_bytes(&self) -> RString {
        current_ruby().str_from_slice(self.inner.stderr_bytes())
    }

    fn exit_code(&self) -> i32 {
        self.inner.status().code
    }

    fn success(&self) -> bool {
        self.inner.status().success
    }

    fn to_h(&self) -> RHash {
        let hash = current_ruby().hash_new();
        hash.aset("stdout", self.stdout()).unwrap();
        hash.aset("stderr", self.stderr()).unwrap();
        hash.aset("exit_code", self.exit_code()).unwrap();
        hash.aset("success", self.success()).unwrap();
        hash
    }
}

//--------------------------------------------------------------------------------------------------
// Module functions and static methods
//--------------------------------------------------------------------------------------------------

fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn installed() -> bool {
    microsandbox_core::setup::is_installed()
}

fn install(ruby: &Ruby) -> Result<(), Error> {
    run(ruby, microsandbox_core::setup::install())
}

fn set_runtime_msb_path(path: String) {
    microsandbox_core::config::set_sdk_msb_path(path);
}

fn set_runtime_libkrunfw_path(path: String) {
    microsandbox_core::config::set_sdk_libkrunfw_path(path);
}

fn sandbox_builder(name: String) -> RubySandboxBuilder {
    RubySandboxBuilder {
        inner: std::cell::RefCell::new(Some(SandboxBuilder::new(name))),
    }
}

fn sandbox_create(ruby: &Ruby, args: &[Value]) -> Result<RubySandbox, Error> {
    let parsed = scan_args::<(String,), (), (), (), RHash, ()>(args)?;
    let builder = apply_builder_options(
        ruby,
        SandboxBuilder::new(parsed.required.0),
        parsed.keywords,
    )?;
    Ok(RubySandbox {
        inner: std::cell::RefCell::new(Some(run(ruby, builder.create())?)),
    })
}

fn sandbox_start(ruby: &Ruby, args: &[Value]) -> Result<RubySandbox, Error> {
    let parsed = scan_args::<(String,), (), (), (), RHash, ()>(args)?;
    reject_unknown_keywords(ruby, parsed.keywords, &["detached"])?;
    let name = parsed.required.0;
    let detached = keyword::<bool>(parsed.keywords, "detached")?.unwrap_or(false);
    let sandbox = if detached {
        run(ruby, CoreSandbox::start_detached(&name))?
    } else {
        run(ruby, CoreSandbox::start(&name))?
    };
    Ok(RubySandbox {
        inner: std::cell::RefCell::new(Some(sandbox)),
    })
}

fn sandbox_get(ruby: &Ruby, args: &[Value]) -> Result<RubySandboxHandle, Error> {
    let parsed = scan_args::<(String,), (), (), (), RHash, ()>(args)?;
    if !parsed.keywords.is_empty() {
        return Err(argument_error(ruby, "get does not accept keywords"));
    }
    Ok(RubySandboxHandle {
        inner: run(ruby, CoreSandbox::get(&parsed.required.0))?,
    })
}

fn sandbox_remove(ruby: &Ruby, args: &[Value]) -> Result<(), Error> {
    let parsed = scan_args::<(String,), (), (), (), RHash, ()>(args)?;
    if !parsed.keywords.is_empty() {
        return Err(argument_error(ruby, "remove does not accept keywords"));
    }
    run(ruby, CoreSandbox::remove(&parsed.required.0))
}

fn sandbox_list(ruby: &Ruby, args: &[Value]) -> Result<RHash, Error> {
    let parsed = scan_args::<(), (), (), (), RHash, ()>(args)?;
    reject_unknown_keywords(ruby, parsed.keywords, &["cursor", "limit", "labels"])?;
    let cursor = keyword::<String>(parsed.keywords, "cursor")?;
    let limit = keyword::<u32>(parsed.keywords, "limit")?;
    let labels = match parsed.keywords.get(symbol("labels")) {
        Some(value) => Some(string_map(value, "labels")?),
        None => None,
    };
    let page = run(
        ruby,
        CoreSandbox::list_with(|mut builder| {
            if let Some(limit) = limit {
                builder = builder.limit(limit);
            }
            if let Some(cursor) = cursor {
                builder = builder.cursor(cursor);
            }
            if let Some(labels) = labels {
                builder = builder.labels(labels);
            }
            builder
        }),
    )?;
    page_hash(page)
}

//--------------------------------------------------------------------------------------------------
// Conversion helpers
//--------------------------------------------------------------------------------------------------

fn status_name(status: SandboxStatus) -> &'static str {
    match status {
        SandboxStatus::Created => "created",
        SandboxStatus::Starting => "starting",
        SandboxStatus::Running => "running",
        SandboxStatus::Draining => "draining",
        SandboxStatus::Paused => "paused",
        SandboxStatus::Stopped => "stopped",
        SandboxStatus::Crashed => "crashed",
    }
}

fn stop_result_hash(result: SandboxStopResult) -> Result<RHash, Error> {
    let hash = current_ruby().hash_new();
    hash.aset("name", result.name)?;
    hash.aset("status", status_name(result.status))?;
    hash.aset("exit_code", result.exit_code)?;
    hash.aset("signal", result.signal)?;
    hash.aset("observed_at", result.observed_at.to_rfc3339())?;
    hash.aset("source", result.source)?;
    Ok(hash)
}

fn page_hash(page: SandboxPage) -> Result<RHash, Error> {
    let handles = page
        .sandboxes
        .into_iter()
        .map(|inner| RubySandboxHandle { inner });
    let sandboxes = current_ruby().ary_new();
    for handle in handles {
        sandboxes.push(handle)?;
    }
    let hash = current_ruby().hash_new();
    hash.aset("sandboxes", sandboxes)?;
    hash.aset("next_cursor", page.next_cursor)?;
    Ok(hash)
}

//--------------------------------------------------------------------------------------------------
// Ruby initialization
//--------------------------------------------------------------------------------------------------

#[magnus::init(name = "microsandbox")]
fn init(ruby: &Ruby) -> Result<(), Error> {
    let module = ruby.define_module("Microsandbox")?;
    module.define_error("Error", ruby.exception_standard_error())?;
    module.define_module_function("version", function!(version, 0))?;
    module.define_module_function("installed?", function!(installed, 0))?;
    module.define_module_function("install", function!(install, 0))?;
    module.define_module_function("set_runtime_msb_path", function!(set_runtime_msb_path, 1))?;
    module.define_module_function(
        "set_runtime_libkrunfw_path",
        function!(set_runtime_libkrunfw_path, 1),
    )?;

    let sandbox = module.define_class("Sandbox", ruby.class_object())?;
    sandbox.define_singleton_method("builder", function!(sandbox_builder, 1))?;
    sandbox.define_singleton_method("create", function!(sandbox_create, -1))?;
    sandbox.define_singleton_method("start", function!(sandbox_start, -1))?;
    sandbox.define_singleton_method("get", function!(sandbox_get, -1))?;
    sandbox.define_singleton_method("list", function!(sandbox_list, -1))?;
    sandbox.define_singleton_method("remove", function!(sandbox_remove, -1))?;
    sandbox.define_method("name", method!(RubySandbox::name, 0))?;
    sandbox.define_method("owns_lifecycle?", method!(RubySandbox::owns_lifecycle, 0))?;
    sandbox.define_method("backend", method!(RubySandbox::backend, 0))?;
    sandbox.define_method("exec", method!(RubySandbox::exec, -1))?;
    sandbox.define_method("shell", method!(RubySandbox::shell, -1))?;
    sandbox.define_method("stop", method!(RubySandbox::stop, -1))?;
    sandbox.define_method("kill", method!(RubySandbox::kill, -1))?;
    sandbox.define_method("request_stop", method!(RubySandbox::request_stop, 0))?;
    sandbox.define_method("request_kill", method!(RubySandbox::request_kill, 0))?;
    sandbox.define_method(
        "wait_until_stopped",
        method!(RubySandbox::wait_until_stopped, 0),
    )?;
    sandbox.define_method("detach", method!(RubySandbox::detach, 0))?;

    let handle = module.define_class("SandboxHandle", ruby.class_object())?;
    handle.define_method("name", method!(RubySandboxHandle::name, 0))?;
    handle.define_method("status", method!(RubySandboxHandle::status, 0))?;
    handle.define_method("config_json", method!(RubySandboxHandle::config_json, 0))?;
    handle.define_method(
        "active_config_json",
        method!(RubySandboxHandle::active_config_json, 0),
    )?;
    handle.define_method(
        "last_failure_message",
        method!(RubySandboxHandle::last_failure_message, 0),
    )?;
    handle.define_method("refresh", method!(RubySandboxHandle::refresh, 0))?;
    handle.define_method("connect", method!(RubySandboxHandle::connect, 0))?;
    handle.define_method("start", method!(RubySandboxHandle::start, -1))?;
    handle.define_method("stop", method!(RubySandboxHandle::stop, -1))?;
    handle.define_method("kill", method!(RubySandboxHandle::kill, -1))?;
    handle.define_method("remove", method!(RubySandboxHandle::remove, 0))?;
    handle.define_method(
        "wait_until_stopped",
        method!(RubySandboxHandle::wait_until_stopped, 0),
    )?;

    let builder = module.define_class("SandboxBuilder", ruby.class_object())?;
    builder.define_method("image!", method!(RubySandboxBuilder::image, 1))?;
    builder.define_method("cpus!", method!(RubySandboxBuilder::cpus, 1))?;
    builder.define_method("max_cpus!", method!(RubySandboxBuilder::max_cpus, 1))?;
    builder.define_method("memory!", method!(RubySandboxBuilder::memory, 1))?;
    builder.define_method("max_memory!", method!(RubySandboxBuilder::max_memory, 1))?;
    builder.define_method("env!", method!(RubySandboxBuilder::env, 2))?;
    builder.define_method("label!", method!(RubySandboxBuilder::label, 2))?;
    builder.define_method("workdir!", method!(RubySandboxBuilder::workdir, 1))?;
    builder.define_method("shell!", method!(RubySandboxBuilder::shell, 1))?;
    builder.define_method("hostname!", method!(RubySandboxBuilder::hostname, 1))?;
    builder.define_method("user!", method!(RubySandboxBuilder::user, 1))?;
    builder.define_method("detached!", method!(RubySandboxBuilder::detached, 1))?;
    builder.define_method("ephemeral!", method!(RubySandboxBuilder::ephemeral, 1))?;
    builder.define_method(
        "max_duration!",
        method!(RubySandboxBuilder::max_duration, 1),
    )?;
    builder.define_method(
        "idle_timeout!",
        method!(RubySandboxBuilder::idle_timeout, 1),
    )?;
    builder.define_method("replace!", method!(RubySandboxBuilder::replace, 0))?;
    builder.define_method(
        "replace_with_timeout!",
        method!(RubySandboxBuilder::replace_with_timeout, 1),
    )?;
    builder.define_method("root_disk!", method!(RubySandboxBuilder::root_disk, 1))?;
    builder.define_method(
        "disable_network!",
        method!(RubySandboxBuilder::disable_network, 0),
    )?;
    builder.define_method("quiet_logs!", method!(RubySandboxBuilder::quiet_logs, 0))?;
    builder.define_method("entrypoint!", method!(RubySandboxBuilder::entrypoint, 1))?;
    builder.define_method("init!", method!(RubySandboxBuilder::init, 1))?;
    builder.define_method("create", method!(RubySandboxBuilder::create, 0))?;

    let output = module.define_class("ExecOutput", ruby.class_object())?;
    output.define_method("stdout", method!(RubyExecOutput::stdout, 0))?;
    output.define_method("stderr", method!(RubyExecOutput::stderr, 0))?;
    output.define_method("stdout_bytes", method!(RubyExecOutput::stdout_bytes, 0))?;
    output.define_method("stderr_bytes", method!(RubyExecOutput::stderr_bytes, 0))?;
    output.define_method("exit_code", method!(RubyExecOutput::exit_code, 0))?;
    output.define_method("success?", method!(RubyExecOutput::success, 0))?;
    output.define_method("to_h", method!(RubyExecOutput::to_h, 0))?;

    Ok(())
}

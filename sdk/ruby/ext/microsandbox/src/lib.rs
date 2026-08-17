use std::{
    ffi::c_void,
    fmt::Display,
    future::Future,
    mem::ManuallyDrop,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicPtr, AtomicU32, Ordering},
    },
    time::Duration,
};

use magnus::{
    Error, ExceptionClass, RArray, RHash, RString, Ruby, Symbol, TryConvert, Value, function,
    method, prelude::*, r_hash::ForEach, scan_args::scan_args, typed_data,
};
use microsandbox_core::{
    BackendKind, MicrosandboxResult,
    backend::{
        CloudBackend, LocalBackend, default_backend, resolve_default_backend, set_default_backend,
    },
    image::{Image, ImageHandle},
    logs::{LogEntry, LogOptions, LogSource},
    sandbox::{
        ExecOptionsBuilder, ExecOutput, FsEntry, FsEntryKind, FsMetadata, NetworkPolicy,
        PullPolicy, RlimitResource, Sandbox as CoreSandbox, SandboxBuilder, SandboxFsOps,
        SandboxHandle as CoreSandboxHandle, SandboxMetrics, SandboxPage, SandboxPingResult,
        SandboxStatus, SandboxStopResult, SandboxTouchResult,
    },
    snapshot::{Snapshot, SnapshotHandle},
    volume::{Volume, VolumeHandle, VolumeKind},
};

// -------------------------------------------------------------------------------------------------
// GVL release — FFI
// -------------------------------------------------------------------------------------------------

unsafe extern "C" {
    fn rb_thread_call_without_gvl(
        func: unsafe extern "C" fn(*mut c_void) -> *mut c_void,
        data: *mut c_void,
        ubf: Option<unsafe extern "C" fn(*mut c_void) -> std::ffi::c_int>,
        ubf_data: *mut c_void,
    ) -> *mut c_void;
}

/// Per-call completion state created in the process that starts the operation.
///
/// Tokio's blocking oneshot receiver caches a thread parker. Reusing that
/// inherited cache after `fork(2)` can dereference stale synchronization state,
/// so the Ruby extension waits on a fresh condition variable instead.
struct BlockingState<T> {
    result: Mutex<Option<T>>,
    ready: Condvar,
}

impl<T> BlockingState<T> {
    fn new() -> Self {
        Self {
            result: Mutex::new(None),
            ready: Condvar::new(),
        }
    }

    fn complete(&self, value: T) {
        let mut result = self
            .result
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *result = Some(value);
        self.ready.notify_one();
    }

    fn wait(&self) -> T {
        let mut result = self
            .result
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        loop {
            if let Some(value) = result.take() {
                return value;
            }
            result = self
                .ready
                .wait(result)
                .unwrap_or_else(|error| error.into_inner());
        }
    }
}

/// Carrier accessed from the C callback inside `rb_thread_call_without_gvl`.
struct BlockingRecv<T> {
    state: Arc<BlockingState<Result<T, tokio::task::JoinError>>>,
    result: Option<std::thread::Result<Result<T, tokio::task::JoinError>>>,
}

fn catch_callback<F, T>(callback: F) -> std::thread::Result<T>
where
    F: FnOnce() -> T,
{
    catch_unwind(AssertUnwindSafe(callback))
}

fn panic_message(panic: &(dyn std::any::Any + Send)) -> &str {
    if let Some(message) = panic.downcast_ref::<&str>() {
        message
    } else if let Some(message) = panic.downcast_ref::<String>() {
        message.as_str()
    } else {
        "unknown panic payload"
    }
}

unsafe extern "C" fn do_blocking_recv<T>(data: *mut c_void) -> *mut c_void {
    let carrier = unsafe { &mut *(data as *mut BlockingRecv<T>) };
    carrier.result = Some(catch_callback(|| carrier.state.wait()));
    std::ptr::null_mut()
}

// -------------------------------------------------------------------------------------------------
// Runtime
// -------------------------------------------------------------------------------------------------

// A tokio runtime cannot survive fork(2): only the calling thread exists in
// the child, while the inherited runtime points at worker and I/O threads that
// disappeared. Tag each leaked runtime with the process that created it and
// build a fresh one after fork. The stale parent runtime is intentionally
// leaked; dropping it in the child can block forever joining vanished threads.
static RUNTIME_PTR: AtomicPtr<tokio::runtime::Runtime> = AtomicPtr::new(std::ptr::null_mut());
static RUNTIME_PID: AtomicU32 = AtomicU32::new(0);
static RUNTIME_SLOT: Mutex<RuntimeSlot> = Mutex::new(RuntimeSlot { runtime: None });

struct RuntimeSlot {
    runtime: Option<ManuallyDrop<tokio::runtime::Runtime>>,
}

fn current_ruby() -> Ruby {
    Ruby::get().expect("Ruby VM is not available")
}

#[derive(Clone)]
enum BackendSelection {
    Ambient,
    Local,
    Cloud {
        api_key: String,
        url: Option<String>,
    },
    CloudProfile(String),
}

static BACKEND_SELECTION: Mutex<BackendSelection> = Mutex::new(BackendSelection::Ambient);

fn reset_backend_after_fork(ruby: &Ruby) -> Result<(), Error> {
    let selection = BACKEND_SELECTION
        .lock()
        .map_err(|_| {
            Error::new(
                ruby.exception_runtime_error(),
                "backend selection lock is poisoned",
            )
        })?
        .clone();
    match selection {
        BackendSelection::Ambient => {
            let backend = resolve_default_backend().map_err(|error| native_error(ruby, error))?;
            set_default_backend(backend);
        }
        BackendSelection::Local => set_default_backend(LocalBackend::lazy()),
        BackendSelection::Cloud { api_key, url } => {
            let backend = match url {
                Some(url) => CloudBackend::new(url, api_key),
                None => CloudBackend::with_api_key(api_key),
            }
            .map_err(|error| native_error(ruby, error))?;
            set_default_backend(backend);
        }
        BackendSelection::CloudProfile(name) => {
            let backend =
                CloudBackend::from_profile(&name).map_err(|error| native_error(ruby, error))?;
            set_default_backend(backend);
        }
    }
    Ok(())
}

fn runtime() -> Result<&'static tokio::runtime::Runtime, Error> {
    let process_id = std::process::id();
    let runtime_ptr = RUNTIME_PTR.load(Ordering::Acquire);
    if !runtime_ptr.is_null() && RUNTIME_PID.load(Ordering::Acquire) == process_id {
        return Ok(unsafe { &*runtime_ptr });
    }

    let mut slot = RUNTIME_SLOT.lock().map_err(|_| {
        Error::new(
            current_ruby().exception_runtime_error(),
            "Tokio runtime lock is poisoned",
        )
    })?;
    let runtime_ptr = RUNTIME_PTR.load(Ordering::Acquire);
    if !runtime_ptr.is_null() && RUNTIME_PID.load(Ordering::Acquire) == process_id {
        return Ok(unsafe { &*runtime_ptr });
    }

    if RUNTIME_PID.load(Ordering::Acquire) != 0 {
        reset_backend_after_fork(&current_ruby())?;
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("microsandbox-ruby")
        .build()
        .map_err(|error| Error::new(current_ruby().exception_runtime_error(), error.to_string()))?;
    // Assignment deliberately does not drop an inherited runtime. Its worker
    // threads vanished at fork and Tokio may hang trying to join them.
    slot.runtime = Some(ManuallyDrop::new(runtime));
    let runtime_ptr = slot
        .runtime
        .as_ref()
        .map(|runtime| &**runtime as *const _ as *mut _)
        .expect("runtime slot was just initialized");
    RUNTIME_PTR.store(runtime_ptr, Ordering::Release);
    RUNTIME_PID.store(process_id, Ordering::Release);
    Ok(unsafe { &*runtime_ptr })
}

fn native_error(ruby: &Ruby, error: impl Display) -> Error {
    let msg = error.to_string();
    let exc = ruby
        .define_module("Microsandbox")
        .and_then(|m| m.const_get::<_, ExceptionClass>("Error"))
        .unwrap_or_else(|_| ruby.exception_runtime_error());
    Error::new(exc, msg)
}

/// Spawn `future` on the tokio runtime and block the Ruby thread **without the
/// GVL** until the result arrives. Other Ruby threads remain schedulable during
/// sandbox operations.
fn block_without_gvl<F, T>(ruby: &Ruby, future: F) -> Result<T, Error>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let runtime = runtime()?;
    let state = Arc::new(BlockingState::new());
    let task = runtime.spawn(future);
    let completion = Arc::clone(&state);
    runtime.spawn(async move {
        completion.complete(task.await);
    });
    let mut carrier = BlockingRecv {
        state,
        result: None,
    };
    unsafe {
        rb_thread_call_without_gvl(
            do_blocking_recv::<T>,
            &mut carrier as *mut _ as *mut c_void,
            None,
            std::ptr::null_mut(),
        );
    }
    match carrier.result.take() {
        Some(Ok(Ok(value))) => Ok(value),
        Some(Ok(Err(error))) if error.is_cancelled() => Err(Error::new(
            ruby.exception_runtime_error(),
            "sandbox operation was canceled",
        )),
        Some(Ok(Err(error))) => {
            let message = if error.is_panic() {
                let panic = error.into_panic();
                panic_message(panic.as_ref()).to_owned()
            } else {
                error.to_string()
            };
            Err(Error::new(
                ruby.exception_runtime_error(),
                format!("native operation panicked while the Ruby GVL was released: {message}"),
            ))
        }
        Some(Err(panic)) => Err(Error::new(
            ruby.exception_runtime_error(),
            format!(
                "native operation panicked while the Ruby GVL was released: {}",
                panic_message(panic.as_ref())
            ),
        )),
        None => unreachable!("GVL callback did not run"),
    }
}

/// Run an SDK future to completion (GVL released) and convert errors.
fn run<F, T>(ruby: &Ruby, future: F) -> Result<T, Error>
where
    F: Future<Output = MicrosandboxResult<T>> + Send + 'static,
    T: Send + 'static,
{
    block_without_gvl(ruby, future)?.map_err(|e| native_error(ruby, e))
}

// -------------------------------------------------------------------------------------------------
// Argument helpers
// -------------------------------------------------------------------------------------------------

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
        .get(symbol(name))
        .filter(|v| !v.is_nil())
        .map(TryConvert::try_convert)
        .transpose()
}

fn string_value(value: Value, name: &str) -> Result<String, Error> {
    if let Some(sym) = Symbol::from_value(value) {
        return Ok(sym.name()?.into_owned());
    }
    RString::try_convert(value)
        .and_then(|s| s.to_string())
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
    let mut out = Vec::with_capacity(hash.len());
    hash.foreach(|k: Value, v: Value| {
        let k = string_value(k, name)?;
        let v = String::try_convert(v).map_err(|_| {
            Error::new(
                current_ruby().exception_type_error(),
                format!("{name} values must be Strings"),
            )
        })?;
        out.push((k, v));
        Ok(ForEach::Continue)
    })?;
    Ok(out)
}

fn string_array(value: Value, name: &str) -> Result<Vec<String>, Error> {
    let ary = RArray::try_convert(value).map_err(|_| {
        Error::new(
            current_ruby().exception_type_error(),
            format!("{name} must be an Array"),
        )
    })?;
    ary.to_vec::<String>().map_err(|_| {
        Error::new(
            current_ruby().exception_type_error(),
            format!("{name} must contain only Strings"),
        )
    })
}

fn required_keyword<T: TryConvert>(hash: RHash, name: &str, ruby: &Ruby) -> Result<T, Error> {
    keyword(hash, name)?.ok_or_else(|| argument_error(ruby, format!("missing keyword: :{name}")))
}

// -------------------------------------------------------------------------------------------------
// Network / secrets
// -------------------------------------------------------------------------------------------------

fn restricted_network_policy(ruby: &Ruby, value: Value) -> Result<NetworkPolicy, Error> {
    let hash = RHash::try_convert(value)
        .map_err(|_| argument_error(ruby, "network must be :none or a Hash"))?;
    reject_unknown_keywords(ruby, hash, &["allowed_hosts", "allowed_ports"])?;
    let hosts: Vec<String> = required_keyword::<RArray>(hash, "allowed_hosts", ruby)?
        .to_vec::<String>()
        .map_err(|_| argument_error(ruby, "allowed_hosts must contain only Strings"))?;
    let ports: Vec<u16> = required_keyword::<RArray>(hash, "allowed_ports", ruby)?
        .to_vec::<u16>()
        .map_err(|_| argument_error(ruby, "allowed_ports must contain integers"))?;
    NetworkPolicy::builder()
        .default_deny()
        .egress(|eg| eg.tcp().ports(ports).allow_domains(hosts))
        .build()
        .map_err(|e| native_error(ruby, e))
}

fn apply_secret_options(
    ruby: &Ruby,
    mut builder: SandboxBuilder,
    value: Value,
) -> Result<SandboxBuilder, Error> {
    let secrets = RArray::try_convert(value)
        .map_err(|_| argument_error(ruby, "secrets must be an Array of Hashes"))?;
    for i in 0..secrets.len() {
        let spec: RHash = secrets.entry(i as isize)?;
        let env = required_keyword::<String>(spec, "env", ruby)?;
        let secret = required_keyword::<String>(spec, "value", ruby)?;
        let host = required_keyword::<String>(spec, "allowed_host", ruby)?;
        builder = builder.secret_env(env, secret, host);
    }
    Ok(builder)
}

// -------------------------------------------------------------------------------------------------
// Duration / timeout
// -------------------------------------------------------------------------------------------------

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
    let kw = keyword::<f64>(kwargs, "timeout")?;
    if positional.is_some() && kw.is_some() {
        return Err(argument_error(
            ruby,
            format!("{method} accepts timeout once"),
        ));
    }
    positional
        .or(kw)
        .map(|s| duration(ruby, s, "timeout"))
        .transpose()
}

// -------------------------------------------------------------------------------------------------
// Rlimit parsing
// -------------------------------------------------------------------------------------------------

fn parse_resource(value: Value, ruby: &Ruby) -> Result<RlimitResource, Error> {
    match string_value(value, "resource")?.as_str() {
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

// -------------------------------------------------------------------------------------------------
// Builder / exec option parsing
// -------------------------------------------------------------------------------------------------

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

    if let Some(v) = keyword::<String>(kwargs, "image")? {
        builder = builder.image(v);
    }
    if let Some(v) = keyword::<u8>(kwargs, "cpus")? {
        builder = builder.cpus(v);
    }
    if let Some(v) = keyword::<u8>(kwargs, "max_cpus")? {
        builder = builder.max_cpus(v);
    }
    if let Some(v) = keyword::<u32>(kwargs, "memory")? {
        builder = builder.memory(v);
    }
    if let Some(v) = keyword::<u32>(kwargs, "max_memory")? {
        builder = builder.max_memory(v);
    }
    if let Some(v) = keyword::<bool>(kwargs, "detached")? {
        builder = builder.detached(v);
    }
    if let Some(v) = keyword::<String>(kwargs, "workdir")? {
        builder = builder.workdir(v);
    }
    if let Some(v) = keyword::<String>(kwargs, "shell")? {
        builder = builder.shell(v);
    }
    if let Some(v) = keyword::<String>(kwargs, "hostname")? {
        builder = builder.hostname(v);
    }
    if let Some(v) = keyword::<String>(kwargs, "user")? {
        builder = builder.user(v);
    }
    if let Some(v) = kwargs.get(symbol("env")) {
        builder = builder.envs(string_map(v, "env")?);
    }
    if let Some(v) = kwargs.get(symbol("labels")) {
        builder = builder.labels(string_map(v, "labels")?);
    }
    if let Some(v) = keyword::<bool>(kwargs, "ephemeral")? {
        builder = builder.ephemeral(v);
    }
    if let Some(v) = keyword::<u64>(kwargs, "max_duration")? {
        builder = builder.max_duration(v);
    }
    if let Some(v) = keyword::<u64>(kwargs, "idle_timeout")? {
        builder = builder.idle_timeout(v);
    }
    if keyword::<bool>(kwargs, "replace")?.unwrap_or(false) {
        builder = builder.replace();
    }
    if let Some(v) = keyword::<f64>(kwargs, "replace_timeout")? {
        builder = builder.replace_with_timeout(duration(ruby, v, "replace_timeout")?);
    }
    if let Some(v) = keyword::<u32>(kwargs, "root_disk")? {
        builder = builder.root_disk(v);
    }
    if keyword::<bool>(kwargs, "disable_network")?.unwrap_or(false) {
        builder = builder.disable_network();
    }
    if let Some(net) = kwargs.get(symbol("network")) {
        if let Some(sym) = Symbol::from_value(net) {
            if sym.name()?.as_ref() != "none" {
                return Err(argument_error(ruby, "network must be :none or a Hash"));
            }
            builder = builder.disable_network();
        } else {
            let policy = restricted_network_policy(ruby, net)?;
            builder = builder.network(|n| n.policy(policy));
        }
    }
    if let Some(v) = kwargs.get(symbol("secrets")) {
        builder = apply_secret_options(ruby, builder, v)?;
    }
    if keyword::<bool>(kwargs, "quiet_logs")?.unwrap_or(false) {
        builder = builder.quiet_logs();
    }
    if let Some(v) = kwargs.get(symbol("entrypoint")) {
        let parts = string_array(v, "entrypoint")?;
        builder = builder.entrypoint(parts);
    }
    if let Some(v) = keyword::<String>(kwargs, "init")? {
        builder = builder.init(v);
    }
    if let Some(v) = keyword::<String>(kwargs, "pull_policy")? {
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
    if let Some(v) = kwargs.get(symbol("scripts")) {
        builder = builder.scripts(string_map(v, "scripts")?);
    }
    if let Some(v) = keyword::<String>(kwargs, "slug")? {
        builder = builder.slug(v);
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

    if let Some(v) = keyword::<String>(kwargs, "cwd")? {
        builder = builder.cwd(v);
    }
    if let Some(v) = keyword::<String>(kwargs, "user")? {
        builder = builder.user(v);
    }
    if let Some(v) = kwargs.get(symbol("env")) {
        builder = builder.envs(string_map(v, "env")?);
    }
    if let Some(v) = keyword::<f64>(kwargs, "timeout")? {
        builder = builder.timeout(duration(ruby, v, "timeout")?);
    }
    if let Some(v) = keyword::<bool>(kwargs, "tty")? {
        builder = builder.tty(v);
    }
    if let Some(v) = kwargs.get(symbol("stdin")) {
        if let Some(sym) = Symbol::from_value(v) {
            match sym.name()?.as_ref() {
                "null" => builder = builder.stdin_null(),
                "pipe" => builder = builder.stdin_pipe(),
                val => {
                    return Err(argument_error(
                        ruby,
                        format!("stdin must be :null, :pipe, or a String; got :{val}"),
                    ));
                }
            }
        } else {
            let s = RString::try_convert(v)?;
            let data = unsafe { s.as_slice() }.to_vec();
            builder = builder.stdin_bytes(data);
        }
    }
    if let Some(v) = kwargs.get(symbol("rlimits")) {
        let limits = RHash::try_convert(v).map_err(|_| {
            argument_error(ruby, "rlimits must be a Hash of resource names to limits")
        })?;
        let mut parsed = Vec::with_capacity(limits.len());
        limits.foreach(|res: Value, val: Value| {
            let res = parse_resource(res, ruby)?;
            let lim = u64::try_convert(val)
                .map_err(|_| argument_error(ruby, "rlimit values must be non-negative integers"))?;
            parsed.push((res, lim));
            Ok(ForEach::Continue)
        })?;
        for (res, lim) in parsed {
            builder = builder.rlimit(res, lim);
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
    let (cmd, ary, kw) = args_and_kwargs(args)?;
    Ok((cmd, ary.to_vec::<String>()?, kw))
}

// -------------------------------------------------------------------------------------------------
// Wrapped types
// -------------------------------------------------------------------------------------------------

#[magnus::wrap(class = "Microsandbox::Sandbox", size)]
struct RubySandbox {
    inner: std::cell::RefCell<Option<CoreSandbox>>,
}

#[magnus::wrap(class = "Microsandbox::SandboxHandle", free_immediately, size)]
struct RubySandboxHandle {
    inner: Arc<CoreSandboxHandle>,
}

#[magnus::wrap(class = "Microsandbox::SandboxBuilder", free_immediately, size)]
struct RubySandboxBuilder {
    inner: std::cell::RefCell<Option<SandboxBuilder>>,
}

#[magnus::wrap(class = "Microsandbox::ExecOutput", free_immediately, size)]
struct RubyExecOutput {
    inner: ExecOutput,
}

#[magnus::wrap(class = "Microsandbox::SandboxMetrics", free_immediately, size)]
struct RubySandboxMetrics {
    inner: SandboxMetrics,
}

#[magnus::wrap(class = "Microsandbox::LogEntry", free_immediately, size)]
struct RubyLogEntry {
    inner: LogEntry,
}

#[magnus::wrap(class = "Microsandbox::ImageHandle", free_immediately, size)]
struct RubyImageHandle {
    inner: ImageHandle,
}

#[magnus::wrap(class = "Microsandbox::VolumeHandle", free_immediately, size)]
struct RubyVolumeHandle {
    inner: VolumeHandle,
}

#[magnus::wrap(class = "Microsandbox::SnapshotHandle", free_immediately, size)]
struct RubySnapshotHandle {
    inner: SnapshotHandle,
}

// -------------------------------------------------------------------------------------------------
// Builder methods
// -------------------------------------------------------------------------------------------------

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
    let b = take_builder(this)?;
    *this.inner.borrow_mut() = Some(update(b));
    Ok(())
}

impl RubySandboxBuilder {
    fn image(this: typed_data::Obj<Self>, v: String) -> Result<(), Error> {
        put_builder(&this, |b| b.image(v))
    }
    fn cpus(this: typed_data::Obj<Self>, v: u8) -> Result<(), Error> {
        put_builder(&this, |b| b.cpus(v))
    }
    fn max_cpus(this: typed_data::Obj<Self>, v: u8) -> Result<(), Error> {
        put_builder(&this, |b| b.max_cpus(v))
    }
    fn memory(this: typed_data::Obj<Self>, v: u32) -> Result<(), Error> {
        put_builder(&this, |b| b.memory(v))
    }
    fn max_memory(this: typed_data::Obj<Self>, v: u32) -> Result<(), Error> {
        put_builder(&this, |b| b.max_memory(v))
    }
    fn env(this: typed_data::Obj<Self>, k: String, v: String) -> Result<(), Error> {
        put_builder(&this, |b| b.env(k, v))
    }
    fn label(this: typed_data::Obj<Self>, k: String, v: String) -> Result<(), Error> {
        put_builder(&this, |b| b.label(k, v))
    }
    fn workdir(this: typed_data::Obj<Self>, v: String) -> Result<(), Error> {
        put_builder(&this, |b| b.workdir(v))
    }
    fn shell(this: typed_data::Obj<Self>, v: String) -> Result<(), Error> {
        put_builder(&this, |b| b.shell(v))
    }
    fn hostname(this: typed_data::Obj<Self>, v: String) -> Result<(), Error> {
        put_builder(&this, |b| b.hostname(v))
    }
    fn user(this: typed_data::Obj<Self>, v: String) -> Result<(), Error> {
        put_builder(&this, |b| b.user(v))
    }
    fn detached(this: typed_data::Obj<Self>, v: bool) -> Result<(), Error> {
        put_builder(&this, |b| b.detached(v))
    }
    fn ephemeral(this: typed_data::Obj<Self>, v: bool) -> Result<(), Error> {
        put_builder(&this, |b| b.ephemeral(v))
    }
    fn max_duration(this: typed_data::Obj<Self>, v: u64) -> Result<(), Error> {
        put_builder(&this, |b| b.max_duration(v))
    }
    fn idle_timeout(this: typed_data::Obj<Self>, v: u64) -> Result<(), Error> {
        put_builder(&this, |b| b.idle_timeout(v))
    }
    fn replace(this: typed_data::Obj<Self>) -> Result<(), Error> {
        put_builder(&this, SandboxBuilder::replace)
    }
    fn replace_with_timeout(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        secs: f64,
    ) -> Result<(), Error> {
        let d = duration(ruby, secs, "replace_timeout")?;
        put_builder(&this, |b| b.replace_with_timeout(d))
    }
    fn root_disk(this: typed_data::Obj<Self>, v: u32) -> Result<(), Error> {
        put_builder(&this, |b| b.root_disk(v))
    }
    fn disable_network(this: typed_data::Obj<Self>) -> Result<(), Error> {
        put_builder(&this, SandboxBuilder::disable_network)
    }
    fn quiet_logs(this: typed_data::Obj<Self>) -> Result<(), Error> {
        put_builder(&this, SandboxBuilder::quiet_logs)
    }
    fn entrypoint(this: typed_data::Obj<Self>, cmd: RArray) -> Result<(), Error> {
        let parts = cmd.to_vec::<String>().map_err(|_| {
            Error::new(
                current_ruby().exception_type_error(),
                "entrypoint must contain only Strings",
            )
        })?;
        put_builder(&this, |b| b.entrypoint(parts))
    }
    fn init(this: typed_data::Obj<Self>, v: String) -> Result<(), Error> {
        put_builder(&this, |b| b.init(v))
    }
    fn vsock(this: typed_data::Obj<Self>, host_path: String, port: u32) -> Result<(), Error> {
        put_builder(&this, |b| b.vsock(host_path, port))
    }
    fn vsock_dgram(this: typed_data::Obj<Self>, host_path: String, port: u32) -> Result<(), Error> {
        put_builder(&this, |b| b.vsock_dgram(host_path, port))
    }
    fn create(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<RubySandbox, Error> {
        let b = take_builder(&this)?;
        let sb = run(ruby, b.create())?;
        Ok(RubySandbox {
            inner: std::cell::RefCell::new(Some(sb)),
        })
    }
}

// -------------------------------------------------------------------------------------------------
// Sandbox methods
// -------------------------------------------------------------------------------------------------

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
            BackendKind::Local => "local",
            BackendKind::Cloud => "cloud",
        }
        .to_owned())
    }

    fn status(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<String, Error> {
        let sb = this.inner_clone()?;
        let status = run(ruby, async move { sb.status().await })?;
        Ok(status_name(status).to_owned())
    }

    fn last_failure_message(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
    ) -> Result<Option<String>, Error> {
        let sb = this.inner_clone()?;
        run(ruby, async move { sb.last_failure_message().await })
    }

    fn exec(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        args: &[Value],
    ) -> Result<RubyExecOutput, Error> {
        let (cmd, cmd_args, kw) = exec_args_and_kwargs(args)?;
        let sb = this.inner_clone()?;
        let opts = apply_exec_options(ruby, ExecOptionsBuilder::default(), kw)?;
        let output = run(ruby, async move {
            sb.exec_with(cmd, move |_| opts.args(cmd_args)).await
        })?;
        Ok(RubyExecOutput { inner: output })
    }

    fn shell(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        args: &[Value],
    ) -> Result<RubyExecOutput, Error> {
        let parsed = scan_args::<(String,), (), (), (), RHash, ()>(args)?;
        let script = parsed.required.0;
        let sb = this.inner_clone()?;
        let opts = apply_exec_options(ruby, ExecOptionsBuilder::default(), parsed.keywords)?;
        let output = run(
            ruby,
            async move { sb.shell_with(script, move |_| opts).await },
        )?;
        Ok(RubyExecOutput { inner: output })
    }

    fn stop(ruby: &Ruby, this: typed_data::Obj<Self>, args: &[Value]) -> Result<(), Error> {
        let parsed = scan_args::<(), (Option<f64>,), (), (), RHash, ()>(args)?;
        let timeout = parse_timeout(ruby, parsed.optional.0, parsed.keywords, "stop")?;
        let sb = this.inner_clone()?;
        run(ruby, async move {
            match timeout {
                Some(timeout) => sb.stop_with_timeout(timeout).await,
                None => sb.stop().await,
            }
        })
    }

    fn kill(ruby: &Ruby, this: typed_data::Obj<Self>, args: &[Value]) -> Result<(), Error> {
        let parsed = scan_args::<(), (Option<f64>,), (), (), RHash, ()>(args)?;
        let timeout = parse_timeout(ruby, parsed.optional.0, parsed.keywords, "kill")?;
        let sb = this.inner_clone()?;
        run(ruby, async move {
            match timeout {
                Some(timeout) => sb.kill_with_timeout(timeout).await,
                None => sb.kill().await,
            }
        })
    }

    fn request_stop(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<(), Error> {
        let sb = this.inner_clone()?;
        run(ruby, async move { sb.request_stop().await })
    }

    fn request_kill(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<(), Error> {
        let sb = this.inner_clone()?;
        run(ruby, async move { sb.request_kill().await })
    }

    fn wait_until_stopped(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<RHash, Error> {
        let sb = this.inner_clone()?;
        stop_result_hash(run(ruby, async move { sb.wait_until_stopped().await })?)
    }

    fn ping(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<RHash, Error> {
        let sb = this.inner_clone()?;
        ping_result_hash(run(ruby, async move { sb.ping().await })?)
    }

    fn touch(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<RHash, Error> {
        let sb = this.inner_clone()?;
        touch_result_hash(run(ruby, async move { sb.touch().await })?)
    }

    fn metrics(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<RubySandboxMetrics, Error> {
        let sb = this.inner_clone()?;
        let inner = run(ruby, async move { sb.metrics().await })?;
        Ok(RubySandboxMetrics { inner })
    }

    fn logs(ruby: &Ruby, this: typed_data::Obj<Self>, args: &[Value]) -> Result<RArray, Error> {
        let parsed = scan_args::<(), (), (), (), RHash, ()>(args)?;
        reject_unknown_keywords(ruby, parsed.keywords, &["tail", "sources"])?;
        let mut opts = LogOptions::default();
        if let Some(tail) = keyword::<usize>(parsed.keywords, "tail")? {
            opts.tail = Some(tail);
        }
        if let Some(value) = parsed.keywords.get(symbol("sources")) {
            let sources = RArray::try_convert(value).map_err(|_| {
                argument_error(ruby, "sources must be an Array of symbols or strings")
            })?;
            for index in 0..sources.len() {
                let value: Value = sources.entry(index as isize)?;
                let name = string_value(value, "sources")?;
                opts.sources.push(parse_log_source(ruby, &name)?);
            }
        }
        let sb = this.inner_clone()?;
        let entries = run(ruby, async move { sb.logs(&opts).await })?;
        let array = current_ruby().ary_new();
        for entry in entries {
            array.push(RubyLogEntry { inner: entry })?;
        }
        Ok(array)
    }
    fn ssh_exec(ruby: &Ruby, this: typed_data::Obj<Self>, args: &[Value]) -> Result<RHash, Error> {
        let parsed = scan_args::<(String,), (), (), (), RHash, ()>(args)?;
        reject_unknown_keywords(ruby, parsed.keywords, &["inactivity_timeout"])?;
        let inactivity_timeout = keyword::<f64>(parsed.keywords, "inactivity_timeout")?
            .map(|seconds| duration(ruby, seconds, "inactivity_timeout"))
            .transpose()?;
        let command = parsed.required.0;
        let sb = this.inner_clone()?;
        let output = run(ruby, async move {
            let client = sb
                .ssh()
                .connect_with(|builder| match inactivity_timeout {
                    Some(timeout) => builder.inactivity_timeout(timeout),
                    None => builder,
                })
                .await?;
            client.exec(command).await
        })?;
        let hash = current_ruby().hash_new();
        hash.aset("stdout", current_ruby().str_from_slice(&output.stdout))?;
        hash.aset("stderr", current_ruby().str_from_slice(&output.stderr))?;
        hash.aset("exit_code", output.status)?;
        hash.aset("success", output.status == 0)?;
        Ok(hash)
    }

    // -- filesystem ----------------------------------------------------------

    fn fs_read(ruby: &Ruby, this: typed_data::Obj<Self>, path: String) -> Result<RString, Error> {
        let sb = this.inner_clone()?;
        let backend = sb.backend().clone();
        let name = sb.name().to_owned();
        let data = run(ruby, async move {
            SandboxFsOps::with_backend(backend, &name).read(&path).await
        })?;
        Ok(current_ruby().str_from_slice(&data))
    }

    fn fs_write(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        path: String,
        data: RString,
    ) -> Result<(), Error> {
        let sb = this.inner_clone()?;
        let backend = sb.backend().clone();
        let name = sb.name().to_owned();
        let bytes = unsafe { data.as_slice() }.to_vec();
        run(ruby, async move {
            SandboxFsOps::with_backend(backend, &name)
                .write(&path, bytes)
                .await
        })
    }

    fn fs_mkdir(ruby: &Ruby, this: typed_data::Obj<Self>, path: String) -> Result<(), Error> {
        let sb = this.inner_clone()?;
        let backend = sb.backend().clone();
        let name = sb.name().to_owned();
        run(ruby, async move {
            SandboxFsOps::with_backend(backend, &name)
                .mkdir(&path)
                .await
        })
    }

    fn fs_list(ruby: &Ruby, this: typed_data::Obj<Self>, path: String) -> Result<RArray, Error> {
        let sb = this.inner_clone()?;
        let backend = sb.backend().clone();
        let name = sb.name().to_owned();
        let entries = run(ruby, async move {
            SandboxFsOps::with_backend(backend, &name).list(&path).await
        })?;
        let ary = current_ruby().ary_new();
        for e in entries {
            ary.push(fs_entry_hash(e)?)?;
        }
        Ok(ary)
    }

    fn fs_stat(ruby: &Ruby, this: typed_data::Obj<Self>, path: String) -> Result<RHash, Error> {
        let sb = this.inner_clone()?;
        let backend = sb.backend().clone();
        let name = sb.name().to_owned();
        let md = run(ruby, async move {
            SandboxFsOps::with_backend(backend, &name).stat(&path).await
        })?;
        fs_metadata_hash(md)
    }

    fn fs_exists(ruby: &Ruby, this: typed_data::Obj<Self>, path: String) -> Result<bool, Error> {
        let sb = this.inner_clone()?;
        let backend = sb.backend().clone();
        let name = sb.name().to_owned();
        run(ruby, async move {
            SandboxFsOps::with_backend(backend, &name)
                .exists(&path)
                .await
        })
    }

    fn fs_copy(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        from: String,
        to: String,
    ) -> Result<(), Error> {
        let sb = this.inner_clone()?;
        let backend = sb.backend().clone();
        let name = sb.name().to_owned();
        run(ruby, async move {
            SandboxFsOps::with_backend(backend, &name)
                .copy(&from, &to)
                .await
        })
    }

    fn fs_rename(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        from: String,
        to: String,
    ) -> Result<(), Error> {
        let sb = this.inner_clone()?;
        let backend = sb.backend().clone();
        let name = sb.name().to_owned();
        run(ruby, async move {
            SandboxFsOps::with_backend(backend, &name)
                .rename(&from, &to)
                .await
        })
    }

    fn fs_remove(ruby: &Ruby, this: typed_data::Obj<Self>, path: String) -> Result<(), Error> {
        let sb = this.inner_clone()?;
        let backend = sb.backend().clone();
        let name = sb.name().to_owned();
        run(ruby, async move {
            SandboxFsOps::with_backend(backend, &name)
                .remove(&path)
                .await
        })
    }

    fn fs_remove_dir(ruby: &Ruby, this: typed_data::Obj<Self>, path: String) -> Result<(), Error> {
        let sb = this.inner_clone()?;
        let backend = sb.backend().clone();
        let name = sb.name().to_owned();
        run(ruby, async move {
            SandboxFsOps::with_backend(backend, &name)
                .remove_dir(&path)
                .await
        })
    }

    fn fs_copy_from_host(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        host_path: String,
        guest_path: String,
    ) -> Result<(), Error> {
        let sb = this.inner_clone()?;
        let backend = sb.backend().clone();
        let name = sb.name().to_owned();
        run(ruby, async move {
            SandboxFsOps::with_backend(backend, &name)
                .copy_from_host(&host_path, &guest_path)
                .await
        })
    }

    fn fs_copy_to_host(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        guest_path: String,
        host_path: String,
    ) -> Result<(), Error> {
        let sb = this.inner_clone()?;
        let backend = sb.backend().clone();
        let name = sb.name().to_owned();
        run(ruby, async move {
            SandboxFsOps::with_backend(backend, &name)
                .copy_to_host(&guest_path, &host_path)
                .await
        })
    }

    // -- lifecycle -----------------------------------------------------------

    fn detach(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<(), Error> {
        let sb = this.inner.borrow_mut().take().ok_or_else(|| {
            Error::new(
                ruby.exception_runtime_error(),
                "sandbox handle has been detached",
            )
        })?;
        block_without_gvl(ruby, sb.detach())?;
        Ok(())
    }
}

// -------------------------------------------------------------------------------------------------
// Handle methods
// -------------------------------------------------------------------------------------------------

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
        let handle = Arc::clone(&this.inner);
        let inner = run(ruby, async move { handle.refresh().await })?;
        Ok(RubySandboxHandle {
            inner: Arc::new(inner),
        })
    }

    fn connect(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<RubySandbox, Error> {
        let handle = Arc::clone(&this.inner);
        let inner = run(ruby, async move { handle.connect().await })?;
        Ok(RubySandbox {
            inner: std::cell::RefCell::new(Some(inner)),
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
        let handle = Arc::clone(&this.inner);
        let inner = run(ruby, async move {
            if detached {
                handle.start_detached().await
            } else {
                handle.start().await
            }
        })?;
        Ok(RubySandbox {
            inner: std::cell::RefCell::new(Some(inner)),
        })
    }

    fn stop(ruby: &Ruby, this: typed_data::Obj<Self>, args: &[Value]) -> Result<(), Error> {
        let parsed = scan_args::<(), (Option<f64>,), (), (), RHash, ()>(args)?;
        let timeout = parse_timeout(ruby, parsed.optional.0, parsed.keywords, "stop")?;
        let handle = Arc::clone(&this.inner);
        run(ruby, async move {
            match timeout {
                Some(timeout) => handle.stop_with_timeout(timeout).await,
                None => handle.stop().await,
            }
        })
    }

    fn kill(ruby: &Ruby, this: typed_data::Obj<Self>, args: &[Value]) -> Result<(), Error> {
        let parsed = scan_args::<(), (Option<f64>,), (), (), RHash, ()>(args)?;
        let timeout = parse_timeout(ruby, parsed.optional.0, parsed.keywords, "kill")?;
        let handle = Arc::clone(&this.inner);
        run(ruby, async move {
            match timeout {
                Some(timeout) => handle.kill_with_timeout(timeout).await,
                None => handle.kill().await,
            }
        })
    }

    fn remove(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<(), Error> {
        let handle = Arc::clone(&this.inner);
        run(ruby, async move { handle.remove().await })
    }

    fn wait_until_stopped(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<RHash, Error> {
        let handle = Arc::clone(&this.inner);
        stop_result_hash(run(ruby, async move { handle.wait_until_stopped().await })?)
    }

    fn snapshot(ruby: &Ruby, this: typed_data::Obj<Self>, name: String) -> Result<RHash, Error> {
        let handle = Arc::clone(&this.inner);
        snapshot_hash(run(ruby, async move { handle.snapshot(&name).await })?)
    }

    fn metrics(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<RubySandboxMetrics, Error> {
        let handle = Arc::clone(&this.inner);
        let inner = run(ruby, async move { handle.metrics().await })?;
        Ok(RubySandboxMetrics { inner })
    }

    fn ping(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<RHash, Error> {
        let handle = Arc::clone(&this.inner);
        ping_result_hash(run(ruby, async move { handle.ping().await })?)
    }

    fn touch(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<RHash, Error> {
        let handle = Arc::clone(&this.inner);
        touch_result_hash(run(ruby, async move { handle.touch().await })?)
    }
}

// -------------------------------------------------------------------------------------------------
// ExecOutput methods
// -------------------------------------------------------------------------------------------------

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
    fn to_h(&self) -> Result<RHash, Error> {
        let hash = current_ruby().hash_new();
        hash.aset("stdout", self.stdout())?;
        hash.aset("stderr", self.stderr())?;
        hash.aset("exit_code", self.exit_code())?;
        hash.aset("success", self.success())?;
        Ok(hash)
    }
}

// -------------------------------------------------------------------------------------------------
// Metrics methods
// -------------------------------------------------------------------------------------------------

impl RubySandboxMetrics {
    fn to_h(&self) -> Result<RHash, Error> {
        let metrics = &self.inner;
        let hash = current_ruby().hash_new();
        hash.aset("cpu_percent", metrics.cpu_percent as f64)?;
        hash.aset("vcpu_time_ns", metrics.vcpu_time_ns)?;
        hash.aset("memory_bytes", metrics.memory_bytes)?;
        hash.aset("memory_limit_bytes", metrics.memory_limit_bytes)?;
        hash.aset("disk_read_bytes", metrics.disk_read_bytes)?;
        hash.aset("disk_write_bytes", metrics.disk_write_bytes)?;
        hash.aset("net_rx_bytes", metrics.net_rx_bytes)?;
        hash.aset("net_tx_bytes", metrics.net_tx_bytes)?;
        hash.aset("uptime_ms", metrics.uptime.as_millis() as u64)?;
        hash.aset("timestamp", metrics.timestamp.to_rfc3339())?;
        Ok(hash)
    }
}

// -------------------------------------------------------------------------------------------------
// LogEntry methods
// -------------------------------------------------------------------------------------------------

impl RubyLogEntry {
    fn timestamp(&self) -> String {
        self.inner.timestamp.to_rfc3339()
    }
    fn source(&self) -> String {
        log_source_name(&self.inner.source).to_owned()
    }
    fn data(&self) -> RString {
        current_ruby().str_from_slice(&self.inner.data)
    }
    fn to_h(&self) -> Result<RHash, Error> {
        let hash = current_ruby().hash_new();
        hash.aset("timestamp", self.timestamp())?;
        hash.aset("source", self.source())?;
        hash.aset("data", self.data())?;
        Ok(hash)
    }
}

// -------------------------------------------------------------------------------------------------
// ImageHandle methods
// -------------------------------------------------------------------------------------------------

impl RubyImageHandle {
    fn reference(&self) -> String {
        self.inner.reference().to_owned()
    }
    fn size_bytes(&self) -> Option<i64> {
        self.inner.size_bytes()
    }
    fn manifest_digest(&self) -> Option<String> {
        self.inner.manifest_digest().map(str::to_owned)
    }
    fn architecture(&self) -> Option<String> {
        self.inner.architecture().map(str::to_owned)
    }
    fn os(&self) -> Option<String> {
        self.inner.os().map(str::to_owned)
    }
    fn layer_count(&self) -> usize {
        self.inner.layer_count()
    }
    fn created_at(&self) -> Option<String> {
        self.inner.created_at().map(|dt| dt.to_rfc3339())
    }
}

// -------------------------------------------------------------------------------------------------
// VolumeHandle methods
// -------------------------------------------------------------------------------------------------

impl RubyVolumeHandle {
    fn name(&self) -> String {
        self.inner.name().to_owned()
    }
    fn kind(&self) -> String {
        volume_kind_name(self.inner.kind()).to_owned()
    }
    fn quota_mib(&self) -> Option<u32> {
        self.inner.quota_mib()
    }
    fn used_bytes(&self) -> u64 {
        self.inner.used_bytes()
    }
    fn capacity_bytes(&self) -> Option<u64> {
        self.inner.capacity_bytes()
    }
    fn labels(&self) -> Result<RHash, Error> {
        let hash = current_ruby().hash_new();
        for (key, value) in self.inner.labels() {
            hash.aset(key.as_str(), value.as_str())?;
        }
        Ok(hash)
    }
    fn created_at(&self) -> Option<String> {
        self.inner.created_at().map(|dt| dt.to_rfc3339())
    }
    fn remove(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<(), Error> {
        let handle = this.inner.clone();
        run(ruby, async move { handle.remove().await })
    }
}

// -------------------------------------------------------------------------------------------------
// SnapshotHandle methods
// -------------------------------------------------------------------------------------------------

impl RubySnapshotHandle {
    fn digest(&self) -> String {
        self.inner.digest().to_owned()
    }
    fn name(&self) -> Option<String> {
        self.inner.name().map(str::to_owned)
    }
    fn size_bytes(&self) -> Option<u64> {
        self.inner.size_bytes()
    }
    fn image_ref(&self) -> String {
        self.inner.image_ref().to_owned()
    }
    fn state_kind(&self) -> String {
        self.inner.state_kind().to_owned()
    }
    fn path(&self) -> String {
        self.inner.path().to_string_lossy().into_owned()
    }
    fn remove(ruby: &Ruby, this: typed_data::Obj<Self>, force: bool) -> Result<(), Error> {
        let handle = this.inner.clone();
        run(ruby, async move { handle.remove(force).await })
    }
}

// -------------------------------------------------------------------------------------------------
// Module functions
// -------------------------------------------------------------------------------------------------

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

fn default_backend_kind_str() -> String {
    match default_backend().kind() {
        BackendKind::Local => "local",
        BackendKind::Cloud => "cloud",
    }
    .to_owned()
}

fn remember_backend_selection(ruby: &Ruby, selection: BackendSelection) -> Result<(), Error> {
    *BACKEND_SELECTION.lock().map_err(|_| {
        Error::new(
            ruby.exception_runtime_error(),
            "backend selection lock is poisoned",
        )
    })? = selection;
    Ok(())
}

fn set_default_backend_local(ruby: &Ruby) -> Result<(), Error> {
    set_default_backend(LocalBackend::lazy());
    remember_backend_selection(ruby, BackendSelection::Local)
}

fn set_default_backend_cloud(ruby: &Ruby, args: &[Value]) -> Result<(), Error> {
    let parsed = scan_args::<(String,), (), (), (), RHash, ()>(args)?;
    reject_unknown_keywords(ruby, parsed.keywords, &["url"])?;
    let api_key = parsed.required.0;
    let url = keyword::<String>(parsed.keywords, "url")?;
    let backend = match &url {
        Some(url) => CloudBackend::new(url, &api_key),
        None => CloudBackend::with_api_key(&api_key),
    }
    .map_err(|error| native_error(ruby, error))?;
    set_default_backend(backend);
    remember_backend_selection(ruby, BackendSelection::Cloud { api_key, url })
}

fn set_default_backend_profile(ruby: &Ruby, name: String) -> Result<(), Error> {
    let backend = CloudBackend::from_profile(&name).map_err(|error| native_error(ruby, error))?;
    set_default_backend(backend);
    remember_backend_selection(ruby, BackendSelection::CloudProfile(name))
}
// -- Sandbox statics ---------------------------------------------------------

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
    let inner = run(ruby, builder.create())?;
    Ok(RubySandbox {
        inner: std::cell::RefCell::new(Some(inner)),
    })
}

fn sandbox_start(ruby: &Ruby, args: &[Value]) -> Result<RubySandbox, Error> {
    let parsed = scan_args::<(String,), (), (), (), RHash, ()>(args)?;
    reject_unknown_keywords(ruby, parsed.keywords, &["detached"])?;
    let name = parsed.required.0;
    let detached = keyword::<bool>(parsed.keywords, "detached")?.unwrap_or(false);
    let inner = run(ruby, async move {
        if detached {
            CoreSandbox::start_detached(&name).await
        } else {
            CoreSandbox::start(&name).await
        }
    })?;
    Ok(RubySandbox {
        inner: std::cell::RefCell::new(Some(inner)),
    })
}

fn sandbox_get(ruby: &Ruby, args: &[Value]) -> Result<RubySandboxHandle, Error> {
    let parsed = scan_args::<(String,), (), (), (), RHash, ()>(args)?;
    if !parsed.keywords.is_empty() {
        return Err(argument_error(ruby, "get does not accept keywords"));
    }
    let name = parsed.required.0;
    let inner = run(ruby, async move { CoreSandbox::get(&name).await })?;
    Ok(RubySandboxHandle {
        inner: Arc::new(inner),
    })
}

fn sandbox_remove(ruby: &Ruby, args: &[Value]) -> Result<(), Error> {
    let parsed = scan_args::<(String,), (), (), (), RHash, ()>(args)?;
    if !parsed.keywords.is_empty() {
        return Err(argument_error(ruby, "remove does not accept keywords"));
    }
    let name = parsed.required.0;
    run(ruby, async move { CoreSandbox::remove(&name).await })
}

fn sandbox_list(ruby: &Ruby, args: &[Value]) -> Result<RHash, Error> {
    let parsed = scan_args::<(), (), (), (), RHash, ()>(args)?;
    reject_unknown_keywords(ruby, parsed.keywords, &["cursor", "limit", "labels"])?;
    let cursor = keyword::<String>(parsed.keywords, "cursor")?;
    let limit = keyword::<u32>(parsed.keywords, "limit")?;
    let labels = parsed
        .keywords
        .get(symbol("labels"))
        .map(|value| string_map(value, "labels"))
        .transpose()?;
    let page = run(
        ruby,
        CoreSandbox::list_with(move |mut builder| {
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

// -- Volume statics ----------------------------------------------------------

fn volume_get(ruby: &Ruby, args: &[Value]) -> Result<RubyVolumeHandle, Error> {
    let parsed = scan_args::<(String,), (), (), (), RHash, ()>(args)?;
    if !parsed.keywords.is_empty() {
        return Err(argument_error(ruby, "get does not accept keywords"));
    }
    let name = parsed.required.0;
    let inner = run(ruby, async move { Volume::get(&name).await })?;
    Ok(RubyVolumeHandle { inner })
}

fn volume_list(ruby: &Ruby, args: &[Value]) -> Result<RArray, Error> {
    let parsed = scan_args::<(), (), (), (), RHash, ()>(args)?;
    if !parsed.keywords.is_empty() {
        return Err(argument_error(ruby, "list does not accept keywords"));
    }
    let handles = run(ruby, Volume::list())?;
    let array = current_ruby().ary_new();
    for inner in handles {
        array.push(RubyVolumeHandle { inner })?;
    }
    Ok(array)
}

fn volume_remove(ruby: &Ruby, args: &[Value]) -> Result<(), Error> {
    let parsed = scan_args::<(String,), (), (), (), RHash, ()>(args)?;
    if !parsed.keywords.is_empty() {
        return Err(argument_error(ruby, "remove does not accept keywords"));
    }
    let name = parsed.required.0;
    run(ruby, async move { Volume::remove(&name).await })
}

fn volume_builder(name: String) -> RubyVolumeBuilder {
    RubyVolumeBuilder {
        inner: std::cell::RefCell::new(Some(Volume::builder(name))),
    }
}

// -- Snapshot statics --------------------------------------------------------

fn snapshot_get(ruby: &Ruby, args: &[Value]) -> Result<RubySnapshotHandle, Error> {
    let parsed = scan_args::<(String,), (), (), (), RHash, ()>(args)?;
    if !parsed.keywords.is_empty() {
        return Err(argument_error(ruby, "get does not accept keywords"));
    }
    let name = parsed.required.0;
    let inner = run(ruby, async move { Snapshot::get(&name).await })?;
    Ok(RubySnapshotHandle { inner })
}

fn snapshot_list(ruby: &Ruby, args: &[Value]) -> Result<RArray, Error> {
    let parsed = scan_args::<(), (), (), (), RHash, ()>(args)?;
    if !parsed.keywords.is_empty() {
        return Err(argument_error(ruby, "list does not accept keywords"));
    }
    let handles = run(ruby, Snapshot::list())?;
    let array = current_ruby().ary_new();
    for inner in handles {
        array.push(RubySnapshotHandle { inner })?;
    }
    Ok(array)
}

fn snapshot_remove(ruby: &Ruby, args: &[Value]) -> Result<(), Error> {
    let parsed = scan_args::<(String,), (Option<bool>,), (), (), RHash, ()>(args)?;
    if !parsed.keywords.is_empty() {
        return Err(argument_error(ruby, "remove does not accept keywords"));
    }
    let name = parsed.required.0;
    let force = parsed.optional.0.unwrap_or(false);
    run(ruby, async move { Snapshot::remove(&name, force).await })
}

// -- Image statics -----------------------------------------------------------

fn image_get(ruby: &Ruby, args: &[Value]) -> Result<RubyImageHandle, Error> {
    let parsed = scan_args::<(String,), (), (), (), RHash, ()>(args)?;
    if !parsed.keywords.is_empty() {
        return Err(argument_error(ruby, "get does not accept keywords"));
    }
    let reference = parsed.required.0;
    let inner = run(ruby, async move { Image::get(&reference).await })?;
    Ok(RubyImageHandle { inner })
}

fn image_list(ruby: &Ruby, args: &[Value]) -> Result<RArray, Error> {
    let parsed = scan_args::<(), (), (), (), RHash, ()>(args)?;
    if !parsed.keywords.is_empty() {
        return Err(argument_error(ruby, "list does not accept keywords"));
    }
    let handles = run(ruby, Image::list())?;
    let array = current_ruby().ary_new();
    for inner in handles {
        array.push(RubyImageHandle { inner })?;
    }
    Ok(array)
}

fn image_remove(ruby: &Ruby, args: &[Value]) -> Result<(), Error> {
    let parsed = scan_args::<(String,), (Option<bool>,), (), (), RHash, ()>(args)?;
    if !parsed.keywords.is_empty() {
        return Err(argument_error(ruby, "remove does not accept keywords"));
    }
    let reference = parsed.required.0;
    let force = parsed.optional.0.unwrap_or(false);
    run(ruby, async move { Image::remove(&reference, force).await })
}

fn image_prune(ruby: &Ruby, args: &[Value]) -> Result<RHash, Error> {
    let parsed = scan_args::<(), (), (), (), RHash, ()>(args)?;
    if !parsed.keywords.is_empty() {
        return Err(argument_error(ruby, "prune does not accept keywords"));
    }
    let report = run(ruby, Image::prune())?;
    let hash = current_ruby().hash_new();
    hash.aset("image_refs_removed", report.image_refs_removed)?;
    hash.aset("manifests_removed", report.manifests_removed)?;
    hash.aset("layers_removed", report.layers_removed)?;
    hash.aset("bytes_reclaimed", report.bytes_reclaimed)?;
    Ok(hash)
}

// -------------------------------------------------------------------------------------------------
// VolumeBuilder (lightweight — not a typed_data object, just a Ruby wrapper)
// -------------------------------------------------------------------------------------------------

#[magnus::wrap(class = "Microsandbox::VolumeBuilder", size)]
struct RubyVolumeBuilder {
    inner: std::cell::RefCell<Option<microsandbox_core::volume::VolumeBuilder>>,
}

fn take_volume_builder(
    this: &RubyVolumeBuilder,
) -> Result<microsandbox_core::volume::VolumeBuilder, Error> {
    this.inner.borrow_mut().take().ok_or_else(|| {
        Error::new(
            current_ruby().exception_runtime_error(),
            "volume builder has been consumed",
        )
    })
}

fn put_volume_builder<F>(this: &RubyVolumeBuilder, update: F) -> Result<(), Error>
where
    F: FnOnce(microsandbox_core::volume::VolumeBuilder) -> microsandbox_core::volume::VolumeBuilder,
{
    let builder = take_volume_builder(this)?;
    *this.inner.borrow_mut() = Some(update(builder));
    Ok(())
}

impl RubyVolumeBuilder {
    fn directory(this: typed_data::Obj<Self>) -> Result<typed_data::Obj<Self>, Error> {
        put_volume_builder(&this, |builder| builder.directory())?;
        Ok(this)
    }

    fn disk(this: typed_data::Obj<Self>) -> Result<typed_data::Obj<Self>, Error> {
        put_volume_builder(&this, |builder| builder.disk())?;
        Ok(this)
    }

    fn quota(this: typed_data::Obj<Self>, mib: u32) -> Result<typed_data::Obj<Self>, Error> {
        put_volume_builder(&this, |builder| builder.quota(mib))?;
        Ok(this)
    }

    fn size(this: typed_data::Obj<Self>, mib: u32) -> Result<typed_data::Obj<Self>, Error> {
        put_volume_builder(&this, |builder| builder.size(mib))?;
        Ok(this)
    }

    fn label(
        this: typed_data::Obj<Self>,
        key: String,
        value: String,
    ) -> Result<typed_data::Obj<Self>, Error> {
        put_volume_builder(&this, |builder| builder.label(key, value))?;
        Ok(this)
    }

    fn create(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<RubyVolumeHandle, Error> {
        let config = take_volume_builder(&this)?.build();
        let inner = run(ruby, async move {
            let volume = Volume::create(config).await?;
            Volume::get(volume.name()).await
        })?;
        Ok(RubyVolumeHandle { inner })
    }
}

// -------------------------------------------------------------------------------------------------
// Conversion helpers
// -------------------------------------------------------------------------------------------------

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

fn volume_kind_name(kind: VolumeKind) -> &'static str {
    match kind {
        VolumeKind::Directory => "dir",
        VolumeKind::Disk => "disk",
    }
}

fn log_source_name(src: &LogSource) -> &'static str {
    match src {
        LogSource::Stdout => "stdout",
        LogSource::Stderr => "stderr",
        LogSource::Output => "output",
        LogSource::System => "system",
    }
}

fn parse_log_source(ruby: &Ruby, name: &str) -> Result<LogSource, Error> {
    match name {
        "stdout" => Ok(LogSource::Stdout),
        "stderr" => Ok(LogSource::Stderr),
        "output" => Ok(LogSource::Output),
        "system" => Ok(LogSource::System),
        other => Err(argument_error(ruby, format!("unknown log source: {other}"))),
    }
}

fn stop_result_hash(r: SandboxStopResult) -> Result<RHash, Error> {
    let h = current_ruby().hash_new();
    h.aset("name", r.name)?;
    h.aset("status", status_name(r.status))?;
    h.aset("exit_code", r.exit_code)?;
    h.aset("signal", r.signal)?;
    h.aset("observed_at", r.observed_at.to_rfc3339())?;
    h.aset("source", r.source)?;
    Ok(h)
}

fn ping_result_hash(r: SandboxPingResult) -> Result<RHash, Error> {
    let h = current_ruby().hash_new();
    h.aset("name", r.name)?;
    h.aset("latency_ms", r.latency.as_millis() as u64)?;
    Ok(h)
}

fn touch_result_hash(r: SandboxTouchResult) -> Result<RHash, Error> {
    let h = current_ruby().hash_new();
    h.aset("name", r.name)?;
    h.aset("activity_seq", r.activity_seq)?;
    Ok(h)
}

fn page_hash(page: SandboxPage) -> Result<RHash, Error> {
    let array = current_ruby().ary_new();
    for inner in page.sandboxes {
        array.push(RubySandboxHandle {
            inner: Arc::new(inner),
        })?;
    }
    let hash = current_ruby().hash_new();
    hash.aset("sandboxes", array)?;
    hash.aset("next_cursor", page.next_cursor)?;
    Ok(hash)
}

fn fs_entry_kind_name(kind: FsEntryKind) -> &'static str {
    match kind {
        FsEntryKind::File => "file",
        FsEntryKind::Directory => "directory",
        FsEntryKind::Symlink => "symlink",
        FsEntryKind::Other => "other",
    }
}

fn fs_entry_hash(e: FsEntry) -> Result<RHash, Error> {
    let h = current_ruby().hash_new();
    h.aset("path", e.path)?;
    h.aset("kind", fs_entry_kind_name(e.kind))?;
    h.aset("size", e.size)?;
    h.aset("mode", e.mode)?;
    h.aset("uid", e.uid)?;
    h.aset("gid", e.gid)?;
    if let Some(m) = e.modified {
        h.aset("modified", m.to_rfc3339())?;
    }
    if let Some(a) = e.accessed {
        h.aset("accessed", a.to_rfc3339())?;
    }
    Ok(h)
}

fn fs_metadata_hash(md: FsMetadata) -> Result<RHash, Error> {
    let h = current_ruby().hash_new();
    h.aset("kind", fs_entry_kind_name(md.kind))?;
    h.aset("size", md.size)?;
    h.aset("mode", md.mode)?;
    h.aset("uid", md.uid)?;
    h.aset("gid", md.gid)?;
    h.aset("readonly", md.readonly)?;
    if let Some(m) = md.modified {
        h.aset("modified", m.to_rfc3339())?;
    }
    if let Some(a) = md.accessed {
        h.aset("accessed", a.to_rfc3339())?;
    }
    if let Some(c) = md.created {
        h.aset("created", c.to_rfc3339())?;
    }
    Ok(h)
}

fn snapshot_hash(snapshot: Snapshot) -> Result<RHash, Error> {
    let hash = current_ruby().hash_new();
    hash.aset("digest", snapshot.digest())?;
    hash.aset("path", snapshot.path().to_string_lossy().into_owned())?;
    hash.aset("size_bytes", snapshot.size_bytes())?;
    Ok(hash)
}

// -------------------------------------------------------------------------------------------------
// Ruby initialization
// -------------------------------------------------------------------------------------------------

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
    module.define_module_function(
        "default_backend_kind",
        function!(default_backend_kind_str, 0),
    )?;
    module.define_module_function(
        "use_local_backend!",
        function!(set_default_backend_local, 0),
    )?;
    module.define_module_function(
        "use_cloud_backend!",
        function!(set_default_backend_cloud, -1),
    )?;
    module.define_module_function(
        "use_cloud_profile!",
        function!(set_default_backend_profile, 1),
    )?;

    // -- Sandbox -------------------------------------------------------------
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
    sandbox.define_method("status", method!(RubySandbox::status, 0))?;
    sandbox.define_method(
        "last_failure_message",
        method!(RubySandbox::last_failure_message, 0),
    )?;
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
    sandbox.define_method("ping", method!(RubySandbox::ping, 0))?;
    sandbox.define_method("touch", method!(RubySandbox::touch, 0))?;
    sandbox.define_method("metrics", method!(RubySandbox::metrics, 0))?;
    sandbox.define_method("logs", method!(RubySandbox::logs, -1))?;
    sandbox.define_method("ssh_exec", method!(RubySandbox::ssh_exec, -1))?;
    // filesystem
    sandbox.define_method("fs_read", method!(RubySandbox::fs_read, 1))?;
    sandbox.define_method("fs_write", method!(RubySandbox::fs_write, 2))?;
    sandbox.define_method("fs_mkdir", method!(RubySandbox::fs_mkdir, 1))?;
    sandbox.define_method("fs_list", method!(RubySandbox::fs_list, 1))?;
    sandbox.define_method("fs_stat", method!(RubySandbox::fs_stat, 1))?;
    sandbox.define_method("fs_exists?", method!(RubySandbox::fs_exists, 1))?;
    sandbox.define_method("fs_copy", method!(RubySandbox::fs_copy, 2))?;
    sandbox.define_method("fs_rename", method!(RubySandbox::fs_rename, 2))?;
    sandbox.define_method("fs_remove", method!(RubySandbox::fs_remove, 1))?;
    sandbox.define_method("fs_remove_dir", method!(RubySandbox::fs_remove_dir, 1))?;
    sandbox.define_method(
        "fs_copy_from_host",
        method!(RubySandbox::fs_copy_from_host, 2),
    )?;
    sandbox.define_method("fs_copy_to_host", method!(RubySandbox::fs_copy_to_host, 2))?;

    // -- SandboxHandle -------------------------------------------------------
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
    handle.define_method("snapshot", method!(RubySandboxHandle::snapshot, 1))?;
    handle.define_method("metrics", method!(RubySandboxHandle::metrics, 0))?;
    handle.define_method("ping", method!(RubySandboxHandle::ping, 0))?;
    handle.define_method("touch", method!(RubySandboxHandle::touch, 0))?;

    // -- SandboxBuilder ------------------------------------------------------
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
    builder.define_method("vsock!", method!(RubySandboxBuilder::vsock, 2))?;
    builder.define_method("vsock_dgram!", method!(RubySandboxBuilder::vsock_dgram, 2))?;
    builder.define_method("create", method!(RubySandboxBuilder::create, 0))?;

    // -- ExecOutput ----------------------------------------------------------
    let output = module.define_class("ExecOutput", ruby.class_object())?;
    output.define_method("stdout", method!(RubyExecOutput::stdout, 0))?;
    output.define_method("stderr", method!(RubyExecOutput::stderr, 0))?;
    output.define_method("stdout_bytes", method!(RubyExecOutput::stdout_bytes, 0))?;
    output.define_method("stderr_bytes", method!(RubyExecOutput::stderr_bytes, 0))?;
    output.define_method("exit_code", method!(RubyExecOutput::exit_code, 0))?;
    output.define_method("success?", method!(RubyExecOutput::success, 0))?;
    output.define_method("to_h", method!(RubyExecOutput::to_h, 0))?;

    // -- SandboxMetrics ------------------------------------------------------
    let metrics = module.define_class("SandboxMetrics", ruby.class_object())?;
    metrics.define_method("to_h", method!(RubySandboxMetrics::to_h, 0))?;

    // -- LogEntry ------------------------------------------------------------
    let log_entry = module.define_class("LogEntry", ruby.class_object())?;
    log_entry.define_method("timestamp", method!(RubyLogEntry::timestamp, 0))?;
    log_entry.define_method("source", method!(RubyLogEntry::source, 0))?;
    log_entry.define_method("data", method!(RubyLogEntry::data, 0))?;
    log_entry.define_method("to_h", method!(RubyLogEntry::to_h, 0))?;

    // -- ImageHandle ---------------------------------------------------------
    let image_handle = module.define_class("ImageHandle", ruby.class_object())?;
    image_handle.define_method("reference", method!(RubyImageHandle::reference, 0))?;
    image_handle.define_method("size_bytes", method!(RubyImageHandle::size_bytes, 0))?;
    image_handle.define_method(
        "manifest_digest",
        method!(RubyImageHandle::manifest_digest, 0),
    )?;
    image_handle.define_method("architecture", method!(RubyImageHandle::architecture, 0))?;
    image_handle.define_method("os", method!(RubyImageHandle::os, 0))?;
    image_handle.define_method("layer_count", method!(RubyImageHandle::layer_count, 0))?;
    image_handle.define_method("created_at", method!(RubyImageHandle::created_at, 0))?;

    let image = module.define_class("Image", ruby.class_object())?;
    image.define_singleton_method("get", function!(image_get, -1))?;
    image.define_singleton_method("list", function!(image_list, -1))?;
    image.define_singleton_method("remove", function!(image_remove, -1))?;
    image.define_singleton_method("prune", function!(image_prune, -1))?;

    // -- Volume --------------------------------------------------------------
    let volume = module.define_class("Volume", ruby.class_object())?;
    volume.define_singleton_method("builder", function!(volume_builder, 1))?;
    volume.define_singleton_method("get", function!(volume_get, -1))?;
    volume.define_singleton_method("list", function!(volume_list, -1))?;
    volume.define_singleton_method("remove", function!(volume_remove, -1))?;

    let vol_builder = module.define_class("VolumeBuilder", ruby.class_object())?;
    vol_builder.define_method("directory", method!(RubyVolumeBuilder::directory, 0))?;
    vol_builder.define_method("disk", method!(RubyVolumeBuilder::disk, 0))?;
    vol_builder.define_method("quota", method!(RubyVolumeBuilder::quota, 1))?;
    vol_builder.define_method("size", method!(RubyVolumeBuilder::size, 1))?;
    vol_builder.define_method("label", method!(RubyVolumeBuilder::label, 2))?;
    vol_builder.define_method("create", method!(RubyVolumeBuilder::create, 0))?;

    let vol_handle = module.define_class("VolumeHandle", ruby.class_object())?;
    vol_handle.define_method("name", method!(RubyVolumeHandle::name, 0))?;
    vol_handle.define_method("kind", method!(RubyVolumeHandle::kind, 0))?;
    vol_handle.define_method("quota_mib", method!(RubyVolumeHandle::quota_mib, 0))?;
    vol_handle.define_method("used_bytes", method!(RubyVolumeHandle::used_bytes, 0))?;
    vol_handle.define_method(
        "capacity_bytes",
        method!(RubyVolumeHandle::capacity_bytes, 0),
    )?;
    vol_handle.define_method("labels", method!(RubyVolumeHandle::labels, 0))?;
    vol_handle.define_method("created_at", method!(RubyVolumeHandle::created_at, 0))?;
    vol_handle.define_method("remove", method!(RubyVolumeHandle::remove, 0))?;

    // -- Snapshot ------------------------------------------------------------
    let snapshot = module.define_class("Snapshot", ruby.class_object())?;
    snapshot.define_singleton_method("get", function!(snapshot_get, -1))?;
    snapshot.define_singleton_method("list", function!(snapshot_list, -1))?;
    snapshot.define_singleton_method("remove", function!(snapshot_remove, -1))?;

    let snap_handle = module.define_class("SnapshotHandle", ruby.class_object())?;
    snap_handle.define_method("digest", method!(RubySnapshotHandle::digest, 0))?;
    snap_handle.define_method("name", method!(RubySnapshotHandle::name, 0))?;
    snap_handle.define_method("size_bytes", method!(RubySnapshotHandle::size_bytes, 0))?;
    snap_handle.define_method("image_ref", method!(RubySnapshotHandle::image_ref, 0))?;
    snap_handle.define_method("state_kind", method!(RubySnapshotHandle::state_kind, 0))?;
    snap_handle.define_method("path", method!(RubySnapshotHandle::path, 0))?;
    snap_handle.define_method("remove", method!(RubySnapshotHandle::remove, 1))?;

    Ok(())
}

#[cfg(test)]
mod runtime_tests {
    use std::{sync::Arc, thread};

    use super::{BlockingState, catch_callback, panic_message};

    #[test]
    fn blocking_state_waits_for_completion() {
        let state = Arc::new(BlockingState::new());
        let completion = Arc::clone(&state);
        let worker = thread::spawn(move || completion.complete(42));

        assert_eq!(state.wait(), 42);
        worker.join().unwrap();
    }

    #[test]
    fn no_gvl_callback_panics_are_captured() {
        let result = catch_callback(|| panic!("callback panic"));
        let panic = result.expect_err("callback panic should be captured");
        assert_eq!(panic_message(panic.as_ref()), "callback panic");
    }
}

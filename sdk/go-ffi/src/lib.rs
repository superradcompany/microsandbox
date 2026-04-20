//! C-ABI FFI layer for the microsandbox Go SDK.
//!
//! # Calling convention
//!
//! Every exported `msb_*` function takes a caller-provided output buffer
//! (`*mut u8`, `size_t`) into which a null-terminated UTF-8 JSON document is
//! written on success. The return value is:
//!
//!   - `NULL` on success.
//!   - A heap-allocated, null-terminated C string containing a JSON-encoded
//!     error on failure. The Go side MUST free this with `msb_free_string`.
//!
//! The error JSON shape is `{"kind":"<kind>","message":"<text>"}` where
//! `<kind>` is one of the strings listed in [`error_kind`]. This lets the Go
//! side map back to a typed `microsandbox.Error`.
//!
//! # Handles
//!
//! Sandboxes crossing the boundary are identified by opaque `u64` handles.
//! The Rust side owns the underlying resources in a global registry; the Go
//! side stores the `u64` and must call `msb_sandbox_close` when done.
//! Volumes are referenced by name only (they're persistent disk state, not
//! running processes).
//!
//! # Threading
//!
//! A single multi-threaded Tokio runtime is created lazily the first time an
//! async operation is invoked (`OnceLock`). The runtime outlives the process.
//! The handle registry is protected by an `RwLock` — concurrent calls from Go
//! goroutines are safe.

use std::{
    collections::HashMap,
    ffi::{CStr, CString},
    os::raw::{c_char, c_uchar},
    sync::{
        OnceLock, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use base64::Engine;
use tokio_stream::StreamExt as _;
use microsandbox::{
    MicrosandboxError, Sandbox,
    sandbox::{
        FsEntryKind,
        all_sandbox_metrics,
        exec::{ExecEvent, ExecHandle, ExecSink},
        fs::{FsReadStream, FsWriteSink},
    },
    volume::Volume,
};
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// Runtime singleton
// ---------------------------------------------------------------------------

fn rt() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime")
    })
}

// ---------------------------------------------------------------------------
// Handle registry
//
// A live `Sandbox` (the Rust type, post-`connect()`) is stored behind an
// `Arc` so FFI calls can borrow it without holding the registry lock for
// the duration of an async operation.
// ---------------------------------------------------------------------------

type Handle = u64;

// Each ID namespace gets its own counter. This keeps sandbox handles, exec
// handles, and cancel ids numerically distinguishable in logs and avoids
// surprising readers who assume a single namespace.
static NEXT_SANDBOX_HANDLE: AtomicU64 = AtomicU64::new(1);
static NEXT_EXEC_HANDLE: AtomicU64 = AtomicU64::new(1);
static NEXT_CANCEL_ID: AtomicU64 = AtomicU64::new(1);

fn registry() -> &'static RwLock<HashMap<Handle, std::sync::Arc<Sandbox>>> {
    static REG: OnceLock<RwLock<HashMap<Handle, std::sync::Arc<Sandbox>>>> = OnceLock::new();
    REG.get_or_init(|| RwLock::new(HashMap::new()))
}

fn register(sandbox: Sandbox) -> Result<Handle, FfiError> {
    let h = NEXT_SANDBOX_HANDLE.fetch_add(1, Ordering::Relaxed);
    registry()
        .write()
        .map_err(|_| FfiError::internal("sandbox registry lock poisoned"))?
        .insert(h, std::sync::Arc::new(sandbox));
    Ok(h)
}

fn get(handle: Handle) -> Result<std::sync::Arc<Sandbox>, FfiError> {
    registry()
        .read()
        .map_err(|_| FfiError::internal("sandbox registry lock poisoned"))?
        .get(&handle)
        .cloned()
        .ok_or_else(|| FfiError::invalid_handle(handle))
}

fn remove(handle: Handle) -> Result<Option<std::sync::Arc<Sandbox>>, FfiError> {
    Ok(registry()
        .write()
        .map_err(|_| FfiError::internal("sandbox registry lock poisoned"))?
        .remove(&handle))
}

// ---------------------------------------------------------------------------
// Exec handle registry
//
// Streaming exec sessions are stored by u64 handle so Go can call
// msb_exec_recv / msb_exec_close without holding a Sandbox reference.
// ExecHandle is !Send because of the UnboundedReceiver, so we wrap it in
// a Mutex to satisfy the RwLock<HashMap<…>> bound.
// ---------------------------------------------------------------------------

// Exec handles are stored behind `Arc<Mutex<…>>`. The Arc lets callers
// (`msb_exec_recv`, `msb_exec_signal`) clone a reference out of the registry
// and drop the RwLock read guard before entering a potentially long-running
// `block_on(eh.recv())`. Holding the read guard across that await would block
// any goroutine trying to acquire the write lock (`register_exec` / `remove_exec`).
type ExecEntry = std::sync::Arc<std::sync::Mutex<ExecHandle>>;

fn exec_registry() -> &'static RwLock<HashMap<Handle, ExecEntry>> {
    static EXEC_REG: OnceLock<RwLock<HashMap<Handle, ExecEntry>>> = OnceLock::new();
    EXEC_REG.get_or_init(|| RwLock::new(HashMap::new()))
}

// Stdin sinks keyed by the same exec_handle u64. ExecSink.write/close are &self,
// so Arc suffices — no Mutex needed for concurrent writes.
type StdinEntry = std::sync::Arc<ExecSink>;

fn stdin_registry() -> &'static RwLock<HashMap<Handle, StdinEntry>> {
    static STDIN_REG: OnceLock<RwLock<HashMap<Handle, StdinEntry>>> = OnceLock::new();
    STDIN_REG.get_or_init(|| RwLock::new(HashMap::new()))
}

fn register_stdin(handle: Handle, sink: ExecSink) -> Result<(), FfiError> {
    stdin_registry()
        .write()
        .map_err(|_| FfiError::internal("stdin registry lock poisoned"))?
        .insert(handle, std::sync::Arc::new(sink));
    Ok(())
}

fn get_stdin(handle: Handle) -> Result<StdinEntry, FfiError> {
    stdin_registry()
        .read()
        .map_err(|_| FfiError::internal("stdin registry lock poisoned"))?
        .get(&handle)
        .cloned()
        .ok_or_else(|| FfiError::invalid_argument("exec session has no stdin pipe (start with stdin_pipe=true)"))
}

fn remove_stdin(handle: Handle) {
    let _ = stdin_registry().write().map(|mut r| r.remove(&handle));
}

fn register_exec(handle: ExecHandle) -> Result<Handle, FfiError> {
    let h = NEXT_EXEC_HANDLE.fetch_add(1, Ordering::Relaxed);
    exec_registry()
        .write()
        .map_err(|_| FfiError::internal("exec registry lock poisoned"))?
        .insert(h, std::sync::Arc::new(std::sync::Mutex::new(handle)));
    Ok(h)
}

fn get_exec(handle: Handle) -> Result<ExecEntry, FfiError> {
    exec_registry()
        .read()
        .map_err(|_| FfiError::internal("exec registry lock poisoned"))?
        .get(&handle)
        .cloned()
        .ok_or_else(|| FfiError::invalid_handle(handle))
}

fn remove_exec(handle: Handle) -> Result<Option<ExecEntry>, FfiError> {
    Ok(exec_registry()
        .write()
        .map_err(|_| FfiError::internal("exec registry lock poisoned"))?
        .remove(&handle))
}

// ---------------------------------------------------------------------------
// Cancellation token registry
//
// Go allocates a cancel_id before each blocking call and registers a
// CancellationToken here. When the Go context is cancelled, Go calls
// msb_cancel_trigger(id) which fires the token, causing the in-flight
// Rust async op to abort via tokio::select!. After the goroutine completes
// (whether by cancellation or normal return) Go calls msb_cancel_unregister.
// ---------------------------------------------------------------------------

fn cancel_registry() -> &'static RwLock<HashMap<u64, CancellationToken>> {
    static CANCEL_REG: OnceLock<RwLock<HashMap<u64, CancellationToken>>> = OnceLock::new();
    CANCEL_REG.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Register a new CancellationToken for a call identified by `id`.
fn cancel_register(id: u64) {
    let token = CancellationToken::new();
    if let Ok(mut reg) = cancel_registry().write() {
        reg.insert(id, token);
    }
}

/// Fire the token for `id`. No-op if the id is not registered (already
/// unregistered) or if the lock is poisoned.
fn cancel_trigger(id: u64) {
    if let Ok(reg) = cancel_registry().read() {
        if let Some(token) = reg.get(&id) {
            token.cancel();
        }
    }
}

/// Remove and drop the token for `id`. No-op if the lock is poisoned.
fn cancel_unregister(id: u64) {
    if let Ok(mut reg) = cancel_registry().write() {
        reg.remove(&id);
    }
}

/// Look up the cancellation token for `id`. Returns an internal error if the
/// token is not registered (caller race with msb_cancel_unregister) or if the
/// lock is poisoned.
fn lookup_cancel_token(id: u64) -> Result<CancellationToken, FfiError> {
    cancel_registry()
        .read()
        .map_err(|_| FfiError::internal("cancel registry lock poisoned"))?
        .get(&id)
        .cloned()
        .ok_or_else(|| FfiError::internal("cancel token not found"))
}

/// Run an async future, aborting if the given CancellationToken is fired.
/// Returns FfiError with kind=internal and message="cancelled" on cancellation.
async fn run_cancellable<F, T>(token: CancellationToken, fut: F) -> Result<T, FfiError>
where
    F: std::future::Future<Output = Result<T, FfiError>>,
{
    tokio::select! {
        result = fut => result,
        _ = token.cancelled() => Err(FfiError::new(error_kind::CANCELLED, "cancelled")),
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Stable string tags for error kinds sent across the FFI. The Go side maps
/// these to `microsandbox.ErrorKind`. Keep in sync with Go's `errors.go`.
mod error_kind {
    pub const SANDBOX_NOT_FOUND: &str = "sandbox_not_found";
    pub const SANDBOX_STILL_RUNNING: &str = "sandbox_still_running";
    pub const VOLUME_NOT_FOUND: &str = "volume_not_found";
    pub const VOLUME_ALREADY_EXISTS: &str = "volume_already_exists";
    pub const EXEC_TIMEOUT: &str = "exec_timeout";
    pub const INVALID_CONFIG: &str = "invalid_config";
    pub const INVALID_ARGUMENT: &str = "invalid_argument";
    pub const INVALID_HANDLE: &str = "invalid_handle";
    pub const BUFFER_TOO_SMALL: &str = "buffer_too_small";
    pub const CANCELLED: &str = "cancelled";
    pub const INTERNAL: &str = "internal";
    pub const FILESYSTEM: &str = "filesystem";
    pub const IMAGE_NOT_FOUND: &str = "image_not_found";
    pub const IMAGE_IN_USE: &str = "image_in_use";
    pub const PATCH_FAILED: &str = "patch_failed";
    pub const IO: &str = "io";
}

struct FfiError {
    kind: &'static str,
    message: String,
}

impl FfiError {
    fn new(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(error_kind::INVALID_ARGUMENT, message)
    }

    fn invalid_handle(handle: Handle) -> Self {
        Self::new(
            error_kind::INVALID_HANDLE,
            format!("unknown sandbox handle: {handle}"),
        )
    }

    fn internal(message: impl Into<String>) -> Self {
        Self::new(error_kind::INTERNAL, message)
    }

    /// Serialize to the JSON payload returned by the error C string.
    fn to_json(&self) -> String {
        // Message is escaped via serde_json so it's safe to embed arbitrary text.
        let msg = serde_json::to_string(&self.message).unwrap_or_else(|_| "\"\"".into());
        format!(r#"{{"kind":"{}","message":{}}}"#, self.kind, msg)
    }
}

impl From<MicrosandboxError> for FfiError {
    fn from(e: MicrosandboxError) -> Self {
        let kind = match &e {
            MicrosandboxError::SandboxNotFound(_) => error_kind::SANDBOX_NOT_FOUND,
            MicrosandboxError::SandboxStillRunning(_) => error_kind::SANDBOX_STILL_RUNNING,
            MicrosandboxError::VolumeNotFound(_) => error_kind::VOLUME_NOT_FOUND,
            MicrosandboxError::VolumeAlreadyExists(_) => error_kind::VOLUME_ALREADY_EXISTS,
            MicrosandboxError::ExecTimeout(_) => error_kind::EXEC_TIMEOUT,
            MicrosandboxError::InvalidConfig(_) => error_kind::INVALID_CONFIG,
            MicrosandboxError::SandboxFs(_) => error_kind::FILESYSTEM,
            MicrosandboxError::ImageNotFound(_) => error_kind::IMAGE_NOT_FOUND,
            MicrosandboxError::ImageInUse(_) => error_kind::IMAGE_IN_USE,
            MicrosandboxError::PatchFailed(_) => error_kind::PATCH_FAILED,
            MicrosandboxError::Io(_) => error_kind::IO,
            _ => error_kind::INTERNAL,
        };
        Self {
            kind,
            message: e.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers: C <-> Rust string/buffer marshaling
// ---------------------------------------------------------------------------

/// SAFETY: `ptr` must either be null or a valid null-terminated C string
/// owned by the caller and live for the duration of this call.
unsafe fn cstr(ptr: *const c_char) -> Result<String, FfiError> {
    if ptr.is_null() {
        return Err(FfiError::invalid_argument("null pointer argument"));
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map(|s| s.to_owned())
        .map_err(|e| FfiError::invalid_argument(format!("invalid UTF-8: {e}")))
}

/// Copy `json` (plus a trailing NUL) into the caller-provided buffer.
/// Returns an `FfiError` if the buffer is too small so the caller can grow.
fn write_output(buf: *mut c_uchar, buf_len: usize, json: &str) -> Result<(), FfiError> {
    let bytes = json.as_bytes();
    if bytes.len() + 1 > buf_len {
        return Err(FfiError::new(
            error_kind::BUFFER_TOO_SMALL,
            format!(
                "output buffer too small: need {}, have {buf_len}",
                bytes.len() + 1
            ),
        ));
    }
    // SAFETY: caller promises `buf` points to `buf_len` writable bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len());
        *buf.add(bytes.len()) = 0;
    }
    Ok(())
}

/// Heap-allocate an error as a null-terminated C string. Ownership transfers
/// to the Go caller, which MUST free via `msb_free_string`.
///
/// NUL bytes in the serialized JSON (which can only originate from the error
/// message, since `kind` is always an ASCII tag) are stripped before building
/// the CString so the conversion is infallible and never loses context.
fn err_ptr(err: FfiError) -> *mut c_char {
    let mut json = err.to_json().into_bytes();
    json.retain(|b| *b != 0);
    // SAFETY: NULs have been stripped, so `CString::new` cannot fail.
    CString::new(json)
        .expect("NULs were stripped; CString::new cannot fail")
        .into_raw()
}

/// Run a fallible closure, writing its successful JSON to `buf` or returning
/// an error C string. Consolidates the success/error branching.
fn run(
    buf: *mut c_uchar,
    buf_len: usize,
    f: impl FnOnce() -> Result<String, FfiError>,
) -> *mut c_char {
    match f().and_then(|json| write_output(buf, buf_len, &json)) {
        Ok(()) => std::ptr::null_mut(),
        Err(e) => err_ptr(e),
    }
}

/// Like `run`, but wraps the async work in a CancellationToken looked up by
/// `cancel_id`. The closure returns a boxed future; this helper looks up the
/// token, drives the future with `block_on(run_cancellable(...))`, and writes
/// the result.
///
/// If the token is triggered before the future completes, the call returns a
/// `cancelled` error immediately. The Tokio task is dropped (aborted) at the
/// select! boundary — side effects that completed before cancellation may have
/// already landed, but no further work is done.
///
/// `run_c` is the single owner of `cancel_unregister` for the blocking-call
/// path: it always unregisters on return, regardless of success or error, so
/// call sites must not unregister themselves.
fn run_c(
    cancel_id: u64,
    buf: *mut c_uchar,
    buf_len: usize,
    f: impl FnOnce() -> Result<std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, FfiError>> + Send>>, FfiError>,
) -> *mut c_char {
    let result = (|| -> Result<(), FfiError> {
        let token = lookup_cancel_token(cancel_id)?;
        let fut = f()?;
        let json = rt().block_on(run_cancellable(token, fut))?;
        write_output(buf, buf_len, &json)
    })();
    cancel_unregister(cancel_id);
    match result {
        Ok(()) => std::ptr::null_mut(),
        Err(e) => err_ptr(e),
    }
}

// ---------------------------------------------------------------------------
// msb_free_string
// ---------------------------------------------------------------------------

/// Free a C string previously returned as an error from any `msb_*` function.
/// Safe to call with a null pointer (no-op).
///
/// # Safety
/// `ptr` must be either null or a pointer returned by this library's
/// `CString::into_raw` — callers from Go produce this via error returns only.
#[unsafe(no_mangle)]
pub extern "C" fn msb_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        // SAFETY: We only ever return pointers built via `CString::into_raw`.
        unsafe { drop(CString::from_raw(ptr)) };
    }
}

// ---------------------------------------------------------------------------
// Cancellation entry points
//
// Usage from Go (in call()):
//   1. Before spawning the CGO goroutine: id = msb_cancel_alloc()
//   2. If ctx.Done() fires:              msb_cancel_trigger(id)
//   3. After the goroutine returns:      msb_cancel_unregister(id)
//
// Every blocking msb_* function accepts a cancel_id as its first argument
// and passes the token into run_c / run_cancellable.
// ---------------------------------------------------------------------------

/// Allocate and register a new CancellationToken. Returns the opaque id that
/// must be passed to the corresponding blocking msb_* call and later freed
/// with msb_cancel_unregister.
#[unsafe(no_mangle)]
pub extern "C" fn msb_cancel_alloc() -> u64 {
    let id = NEXT_CANCEL_ID.fetch_add(1, Ordering::Relaxed);
    cancel_register(id);
    id
}

/// Trigger cancellation for the given id. Safe to call multiple times or
/// after msb_cancel_unregister (no-op in those cases).
#[unsafe(no_mangle)]
pub extern "C" fn msb_cancel_trigger(id: u64) {
    cancel_trigger(id);
}

/// Remove the token for `id`. Called by Go after the blocking goroutine
/// returns, regardless of whether cancellation was triggered.
#[unsafe(no_mangle)]
pub extern "C" fn msb_cancel_unregister(id: u64) {
    cancel_unregister(id);
}

// ---------------------------------------------------------------------------
// Sandbox — create
//
// Input:
//   name: null-terminated C string, owned by caller (Go), borrowed for call.
//   opts_json: JSON object with optional fields (image, memory_mib, cpus,
//     workdir, env). Owned by caller, borrowed for call.
// Output on success: {"handle": <u64>}
// The caller MUST eventually call `msb_sandbox_close(handle)` to release.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Sandbox create — deserialized option types
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize, Default)]
struct NetworkPolicyRule {
    action: String,
    #[serde(default = "default_egress")]
    direction: String,
    destination: Option<String>,
    protocol: Option<String>,
    port: Option<serde_json::Value>,
}

fn default_egress() -> String {
    "egress".into()
}

#[derive(serde::Deserialize)]
struct CustomNetworkPolicy {
    #[serde(default = "default_allow")]
    default_action: String,
    #[serde(default)]
    rules: Vec<NetworkPolicyRule>,
}

fn default_allow() -> String {
    "allow".into()
}

#[derive(serde::Deserialize, Default)]
struct TlsOpts {
    #[serde(default)]
    bypass: Vec<String>,
    verify_upstream: Option<bool>,
    intercepted_ports: Option<Vec<u16>>,
    block_quic: Option<bool>,
    ca_cert: Option<String>,
    ca_key: Option<String>,
}

#[derive(serde::Deserialize, Default)]
struct NetworkOpts {
    policy: Option<String>,
    custom_policy: Option<CustomNetworkPolicy>,
    #[serde(default)]
    block_domains: Vec<String>,
    #[serde(default)]
    block_domain_suffixes: Vec<String>,
    dns_rebind_protection: Option<bool>,
    tls: Option<TlsOpts>,
    /// Ports nested inside network: {host_port: guest_port}.
    #[serde(default)]
    ports: HashMap<u16, u16>,
}

#[derive(serde::Deserialize)]
struct SecretOpts {
    env_var: String,
    value: String,
    #[serde(default)]
    allow_hosts: Vec<String>,
    #[serde(default)]
    allow_host_patterns: Vec<String>,
    placeholder: Option<String>,
    require_tls: Option<bool>,
}

#[derive(serde::Deserialize)]
struct PatchOpts {
    kind: String,
    // text / append / mkdir / remove / symlink / copy_file / copy_dir
    path: Option<String>,
    content: Option<String>,
    mode: Option<u32>,
    #[serde(default)]
    replace: bool,
    src: Option<String>,
    dst: Option<String>,
    target: Option<String>,
    link: Option<String>,
}

#[derive(serde::Deserialize)]
struct SandboxCreateOpts {
    image: Option<String>,
    memory_mib: Option<u32>,
    cpus: Option<u8>,
    workdir: Option<String>,
    env: Option<HashMap<String, String>>,
    #[serde(default)]
    detached: bool,
    hostname: Option<String>,
    user: Option<String>,
    #[serde(default)]
    replace: bool,
    network: Option<NetworkOpts>,
    /// Top-level ports shorthand: {host_port: guest_port}.
    #[serde(default)]
    ports: HashMap<u16, u16>,
    #[serde(default)]
    secrets: Vec<SecretOpts>,
    #[serde(default)]
    patches: Vec<PatchOpts>,
    /// Volume mounts: guest_path → MountSpec.
    #[serde(default)]
    volumes: HashMap<String, MountSpec>,
}

#[derive(serde::Deserialize, Default)]
struct MountSpec {
    bind: Option<String>,
    named: Option<String>,
    #[serde(default)]
    tmpfs: bool,
    #[serde(default)]
    readonly: bool,
    size_mib: Option<u32>,
}

// ---------------------------------------------------------------------------
// Sandbox create — helpers
// ---------------------------------------------------------------------------

fn apply_network(
    mut builder: microsandbox::sandbox::SandboxBuilder,
    net: &NetworkOpts,
) -> Result<microsandbox::sandbox::SandboxBuilder, FfiError> {
    use microsandbox_network::policy::{
        Destination, DestinationGroup, Direction, NetworkPolicy, PortRange, Rule,
    };

    // Preset policy string.
    if let Some(ref preset) = net.policy {
        let policy = match preset.as_str() {
            "none" => NetworkPolicy::none(),
            "public_only" | "public-only" => NetworkPolicy::public_only(),
            "allow_all" | "allow-all" => NetworkPolicy::allow_all(),
            other => {
                return Err(FfiError::invalid_argument(format!(
                    "unknown network policy preset: {other}"
                )));
            }
        };
        builder = builder.network(|n| n.policy(policy));
    }

    // Custom policy.
    if let Some(ref cp) = net.custom_policy {
        let default_action = parse_action(&cp.default_action)?;
        let mut rules = Vec::new();
        for r in &cp.rules {
            let action = parse_action(&r.action)?;
            let direction = match r.direction.as_str() {
                "egress" => Direction::Outbound,
                "ingress" => Direction::Inbound,
                other => {
                    return Err(FfiError::invalid_argument(format!(
                        "unknown direction: {other}"
                    )));
                }
            };
            let destination = match r.destination.as_deref() {
                None | Some("*") => Destination::Any,
                Some("loopback") => Destination::Group(DestinationGroup::Loopback),
                Some("private") => Destination::Group(DestinationGroup::Private),
                Some("link-local") => Destination::Group(DestinationGroup::LinkLocal),
                Some("metadata") => Destination::Group(DestinationGroup::Metadata),
                Some("multicast") => Destination::Group(DestinationGroup::Multicast),
                Some(s) if s.starts_with('.') => Destination::DomainSuffix(s.to_string()),
                Some(s) if s.contains('/') => {
                    let cidr: ipnetwork::IpNetwork = s.parse().map_err(|e| {
                        FfiError::invalid_argument(format!("invalid CIDR {s}: {e}"))
                    })?;
                    Destination::Cidr(cidr)
                }
                Some(s) => Destination::Domain(s.to_string()),
            };
            let protocol = r.protocol.as_deref().map(parse_protocol).transpose()?;
            let ports = r.port.as_ref().and_then(|v| {
                let p: u16 = match v {
                    serde_json::Value::Number(n) => n.as_u64()? as u16,
                    serde_json::Value::String(s) => s.parse().ok()?,
                    _ => return None,
                };
                Some(PortRange { start: p, end: p })
            });
            rules.push(Rule { action, direction, destination, protocol, ports });
        }
        builder =
            builder.network(|n| n.policy(NetworkPolicy { default_action, rules }));
    }

    // Block domains.
    for d in &net.block_domains {
        let d = d.clone();
        builder = builder.network(move |n| n.block_domain(d));
    }
    // Block domain suffixes.
    for s in &net.block_domain_suffixes {
        let s = s.clone();
        builder = builder.network(move |n| n.block_domain_suffix(s));
    }
    // DNS rebind protection.
    if let Some(rebind) = net.dns_rebind_protection {
        builder = builder.network(move |n| n.dns_rebind_protection(rebind));
    }

    // TLS.
    if let Some(ref tls) = net.tls {
        let bypass = tls.bypass.clone();
        let verify_upstream = tls.verify_upstream;
        let intercepted_ports = tls.intercepted_ports.clone();
        let block_quic = tls.block_quic;
        let ca_cert = tls.ca_cert.clone();
        let ca_key = tls.ca_key.clone();
        builder = builder.network(move |n| {
            n.tls(move |mut t| {
                for domain in &bypass {
                    t = t.bypass(domain);
                }
                if let Some(v) = verify_upstream {
                    t = t.verify_upstream(v);
                }
                if let Some(ports) = intercepted_ports {
                    t = t.intercepted_ports(ports);
                }
                if let Some(b) = block_quic {
                    t = t.block_quic(b);
                }
                if let Some(ref cert) = ca_cert {
                    t = t.intercept_ca_cert(cert);
                }
                if let Some(ref key) = ca_key {
                    t = t.intercept_ca_key(key);
                }
                t
            })
        });
    }

    // Ports nested inside network object.
    for (host, guest) in &net.ports {
        builder = builder.port(*host, *guest);
    }

    Ok(builder)
}

fn apply_secret(
    builder: microsandbox::sandbox::SandboxBuilder,
    s: &SecretOpts,
) -> microsandbox::sandbox::SandboxBuilder {
    let env_var = s.env_var.clone();
    let value = s.value.clone();
    let allow_hosts = s.allow_hosts.clone();
    let allow_host_patterns = s.allow_host_patterns.clone();
    let placeholder = s.placeholder.clone();
    let require_tls = s.require_tls;
    builder.secret(move |mut sb| {
        sb = sb.env(&env_var).value(value.clone());
        for h in &allow_hosts {
            sb = sb.allow_host(h);
        }
        for p in &allow_host_patterns {
            sb = sb.allow_host_pattern(p);
        }
        if let Some(ref ph) = placeholder {
            sb = sb.placeholder(ph);
        }
        if let Some(req) = require_tls {
            sb = sb.require_tls_identity(req);
        }
        sb
    })
}

fn apply_patch(
    builder: microsandbox::sandbox::SandboxBuilder,
    p: &PatchOpts,
) -> Result<microsandbox::sandbox::SandboxBuilder, FfiError> {
    use microsandbox::sandbox::Patch;

    let require_path = || {
        p.path
            .clone()
            .ok_or_else(|| FfiError::invalid_argument("patch.path required"))
    };

    let patch = match p.kind.as_str() {
        "text" => Patch::Text {
            path: require_path()?,
            content: p.content.clone().unwrap_or_default(),
            mode: p.mode,
            replace: p.replace,
        },
        "append" => Patch::Append {
            path: require_path()?,
            content: p.content.clone().unwrap_or_default(),
        },
        "mkdir" => Patch::Mkdir { path: require_path()?, mode: p.mode },
        "remove" => Patch::Remove { path: require_path()? },
        "symlink" => Patch::Symlink {
            target: p
                .target
                .clone()
                .ok_or_else(|| FfiError::invalid_argument("patch.target required"))?,
            link: p
                .link
                .clone()
                .ok_or_else(|| FfiError::invalid_argument("patch.link required"))?,
            replace: p.replace,
        },
        "copy_file" => Patch::CopyFile {
            src: p
                .src
                .clone()
                .ok_or_else(|| FfiError::invalid_argument("patch.src required"))?
                .into(),
            dst: p
                .dst
                .clone()
                .ok_or_else(|| FfiError::invalid_argument("patch.dst required"))?,
            mode: p.mode,
            replace: p.replace,
        },
        "copy_dir" => Patch::CopyDir {
            src: p
                .src
                .clone()
                .ok_or_else(|| FfiError::invalid_argument("patch.src required"))?
                .into(),
            dst: p
                .dst
                .clone()
                .ok_or_else(|| FfiError::invalid_argument("patch.dst required"))?,
            replace: p.replace,
        },
        other => {
            return Err(FfiError::invalid_argument(format!(
                "unknown patch kind: {other}"
            )));
        }
    };
    Ok(builder.add_patch(patch))
}

fn apply_volume(
    builder: microsandbox::sandbox::SandboxBuilder,
    guest_path: &str,
    m: &MountSpec,
) -> Result<microsandbox::sandbox::SandboxBuilder, FfiError> {
    Ok(builder.volume(guest_path, |mb| {
        let mb = if let Some(ref host) = m.bind {
            mb.bind(host)
        } else if let Some(ref name) = m.named {
            mb.named(name)
        } else if m.tmpfs {
            mb.tmpfs()
        } else {
            mb
        };
        let mb = if m.readonly { mb.readonly() } else { mb };
        if let Some(siz) = m.size_mib {
            mb.size(siz)
        } else {
            mb
        }
    }))
}

fn parse_action(
    s: &str,
) -> Result<microsandbox_network::policy::Action, FfiError> {
    match s {
        "allow" => Ok(microsandbox_network::policy::Action::Allow),
        "deny" => Ok(microsandbox_network::policy::Action::Deny),
        other => Err(FfiError::invalid_argument(format!("unknown action: {other}"))),
    }
}

fn parse_protocol(
    s: &str,
) -> Result<microsandbox_network::policy::Protocol, FfiError> {
    match s {
        "tcp" => Ok(microsandbox_network::policy::Protocol::Tcp),
        "udp" => Ok(microsandbox_network::policy::Protocol::Udp),
        "icmpv4" => Ok(microsandbox_network::policy::Protocol::Icmpv4),
        "icmpv6" => Ok(microsandbox_network::policy::Protocol::Icmpv6),
        other => Err(FfiError::invalid_argument(format!("unknown protocol: {other}"))),
    }
}

// ---------------------------------------------------------------------------
// Sandbox — create
//
// Input:
//   name: null-terminated C string, owned by caller (Go), borrowed for call.
//   opts_json: JSON object. Owned by caller, borrowed for call.
// Output on success: {"handle": <u64>}
// The caller MUST eventually call `msb_sandbox_close(handle)` to release.
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn msb_sandbox_create(
    cancel_id: u64,
    name: *const c_char,
    opts_json: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let name = unsafe { cstr(name) }?;
        let opts_raw = unsafe { cstr(opts_json) }?;
        let opts: SandboxCreateOpts = serde_json::from_str(&opts_raw)
            .map_err(|e| FfiError::invalid_argument(format!("invalid opts JSON: {e}")))?;

        Ok(Box::pin(async move {
            let mut builder = Sandbox::builder(&name);
            if let Some(img) = opts.image {
                builder = builder.image(img.as_str());
            }
            if let Some(m) = opts.memory_mib {
                builder = builder.memory(m);
            }
            if let Some(c) = opts.cpus {
                builder = builder.cpus(c);
            }
            if let Some(w) = opts.workdir {
                builder = builder.workdir(w);
            }
            if let Some(h) = opts.hostname {
                builder = builder.hostname(h);
            }
            if let Some(u) = opts.user {
                builder = builder.user(u);
            }
            if opts.replace {
                builder = builder.replace();
            }
            for (k, v) in opts.env.unwrap_or_default() {
                builder = builder.env(k, v);
            }
            // Top-level ports.
            for (host, guest) in &opts.ports {
                builder = builder.port(*host, *guest);
            }
            // Network (policy, DNS, TLS, ports-in-network).
            if let Some(ref net) = opts.network {
                builder = apply_network(builder, net)?;
            }
            // Secrets.
            for s in &opts.secrets {
                builder = apply_secret(builder, s);
            }
            // Patches.
            for p in &opts.patches {
                builder = apply_patch(builder, p)?;
            }
            // Volume mounts.
            for (guest_path, mount) in &opts.volumes {
                builder = apply_volume(builder, guest_path, mount)?;
            }

            let config = builder.build()?;
            let sandbox = if opts.detached {
                Sandbox::create_detached(config).await?
            } else {
                Sandbox::create(config).await?
            };
            let handle = register(sandbox)?;
            Ok(format!(r#"{{"handle":{handle}}}"#))
        }))
    })
}

// ---------------------------------------------------------------------------
// Sandbox — lookup (name-addressed SandboxHandle metadata)
//
// Returns the persisted DB record for a sandbox without connecting. If you want a
// live `Sandbox`, call `msb_sandbox_connect(name)` instead.
// Output: {"name","status","config_json","created_at_unix","updated_at_unix","pid"}
// ---------------------------------------------------------------------------

fn sandbox_status_str(s: microsandbox::sandbox::SandboxStatus) -> &'static str {
    use microsandbox::sandbox::SandboxStatus::*;
    match s {
        Running => "running",
        Draining => "draining",
        Paused => "paused",
        Stopped => "stopped",
        Crashed => "crashed",
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn msb_sandbox_lookup(
    cancel_id: u64,
    name: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let name = unsafe { cstr(name) }?;
        Ok(Box::pin(async move {
            let h = Sandbox::get(&name).await.map_err(FfiError::from)?;
            Ok(serde_json::json!({
                "name": h.name(),
                "status": sandbox_status_str(h.status()),
                "config_json": h.config_json(),
                "created_at_unix": h.created_at().map(|t| t.timestamp()),
                "updated_at_unix": h.updated_at().map(|t| t.timestamp()),
            })
            .to_string())
        }))
    })
}

// ---------------------------------------------------------------------------
// Sandbox — connect (name → live handle)
//
// Looks up the sandbox by name and connects to its running agent, returning
// a freshly registered u64 handle.
// Output: {"handle": <u64>}
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn msb_sandbox_connect(
    cancel_id: u64,
    name: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let name = unsafe { cstr(name) }?;
        Ok(Box::pin(async move {
            let sb = Sandbox::get(&name).await?.connect().await?;
            let handle = register(sb)?;
            Ok(format!(r#"{{"handle":{handle}}}"#))
        }))
    })
}

// ---------------------------------------------------------------------------
// Sandbox — start from a DB record
//
// Boots a sandbox that is persisted but not running. `detached` controls
// whether the lifecycle is owned by this handle (detached=true leaves the
// VM alive when the handle drops).
// Output: {"handle": <u64>}
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn msb_sandbox_start(
    cancel_id: u64,
    name: *const c_char,
    detached: bool,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let name = unsafe { cstr(name) }?;
        Ok(Box::pin(async move {
            let h = Sandbox::get(&name).await.map_err(FfiError::from)?;
            let sb = if detached {
                h.start_detached().await.map_err(FfiError::from)?
            } else {
                h.start().await.map_err(FfiError::from)?
            };
            let handle = register(sb)?;
            Ok(format!(r#"{{"handle":{handle}}}"#))
        }))
    })
}

// ---------------------------------------------------------------------------
// Sandbox — stop / kill by name (no live handle required)
//
// Operates on the DB
// record directly; does not require the caller to hold a live Sandbox.
// Output: {"ok":true}
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn msb_sandbox_handle_stop(
    cancel_id: u64,
    name: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let name = unsafe { cstr(name) }?;
        Ok(Box::pin(async move {
            let h = Sandbox::get(&name).await.map_err(FfiError::from)?;
            h.stop().await.map_err(FfiError::from)?;
            Ok(r#"{"ok":true}"#.into())
        }))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn msb_sandbox_handle_kill(
    cancel_id: u64,
    name: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let name = unsafe { cstr(name) }?;
        Ok(Box::pin(async move {
            let mut h = Sandbox::get(&name).await.map_err(FfiError::from)?;
            h.kill().await.map_err(FfiError::from)?;
            Ok(r#"{"ok":true}"#.into())
        }))
    })
}

// ---------------------------------------------------------------------------
// Sandbox — close
//
// Drop the Rust-side Sandbox for this handle. This releases connections and,
// if this handle owned the lifecycle, stops the VM. After this call the
// handle is invalid and any further FFI call with it returns `invalid_handle`.
// Output: {"ok":true}
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn msb_sandbox_close(
    cancel_id: u64,
    handle: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    cancel_unregister(cancel_id);
    run(buf, buf_len, || {
        let sb = remove(handle)?.ok_or_else(|| FfiError::invalid_handle(handle))?;
        drop(sb);
        Ok(r#"{"ok":true}"#.into())
    })
}

// ---------------------------------------------------------------------------
// Sandbox — detach
//
// Disarm the SIGTERM safety net so the sandbox keeps running after the
// handle is released. This is the counterpart to `close` for sandboxes
// created with `detached: true`: the caller calls `detach` before dropping
// the handle so the VM survives. After this call the handle is invalid.
// Output: {"ok":true}
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn msb_sandbox_detach(
    cancel_id: u64,
    handle: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let arc = remove(handle)?.ok_or_else(|| FfiError::invalid_handle(handle))?;
        // Unwrap the Arc so we can call `detach(self)`. This fails only if
        // another caller is still holding a clone (e.g. a concurrent FFI
        // call that cloned the Arc out of the registry). Detaching while
        // another op is in flight is a misuse — the SIGTERM safety net
        // would still fire when the last clone drops.
        Ok(Box::pin(async move {
            let sb = std::sync::Arc::try_unwrap(arc).map_err(|_| {
                FfiError::internal(
                    "detach while another sandbox operation is in flight on the same handle",
                )
            })?;
            sb.detach().await;
            Ok(r#"{"ok":true}"#.into())
        }))
    })
}

// ---------------------------------------------------------------------------
// Sandbox — stop (graceful) and stop_and_wait
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn msb_sandbox_stop(
    cancel_id: u64,
    handle: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let sb = get(handle)?;
        Ok(Box::pin(async move {
            sb.stop().await.map_err(FfiError::from)?;
            Ok(r#"{"ok":true}"#.into())
        }))
    })
}

/// Stop and wait for full shutdown. Returns `{"exit_code": <int|null>}`.
#[unsafe(no_mangle)]
pub extern "C" fn msb_sandbox_stop_and_wait(
    cancel_id: u64,
    handle: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let sb = get(handle)?;
        Ok(Box::pin(async move {
            let status = sb.stop_and_wait().await.map_err(FfiError::from)?;
            let code = status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "null".into());
            Ok(format!(r#"{{"exit_code":{code}}}"#))
        }))
    })
}

/// Kill the sandbox immediately (SIGKILL on the VM process).
#[unsafe(no_mangle)]
pub extern "C" fn msb_sandbox_kill(
    cancel_id: u64,
    handle: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let sb = get(handle)?;
        Ok(Box::pin(async move {
            sb.kill().await.map_err(FfiError::from)?;
            Ok(r#"{"ok":true}"#.into())
        }))
    })
}

// ---------------------------------------------------------------------------
// Sandbox — drain, wait, owns_lifecycle
// ---------------------------------------------------------------------------

/// Trigger graceful drain (SIGUSR1). Returns `{"ok":true}`.
#[unsafe(no_mangle)]
pub extern "C" fn msb_sandbox_drain(
    cancel_id: u64,
    handle: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let sb = get(handle)?;
        Ok(Box::pin(async move {
            sb.drain().await.map_err(FfiError::from)?;
            Ok(r#"{"ok":true}"#.into())
        }))
    })
}

/// Wait for the sandbox process to exit. Returns `{"exit_code": <int|null>}`.
#[unsafe(no_mangle)]
pub extern "C" fn msb_sandbox_wait(
    cancel_id: u64,
    handle: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let sb = get(handle)?;
        Ok(Box::pin(async move {
            let status = sb.wait().await.map_err(FfiError::from)?;
            let code = status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "null".into());
            Ok(format!(r#"{{"exit_code":{code}}}"#))
        }))
    })
}

/// Reports whether this handle owns the sandbox lifecycle (synchronous).
/// Returns `{"owns":true}` or `{"owns":false}`.
#[unsafe(no_mangle)]
pub extern "C" fn msb_sandbox_owns_lifecycle(
    handle: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run(buf, buf_len, || {
        let owns = registry()
            .read()
            .map(|r| r.get(&handle).map(|sb| sb.owns_lifecycle()).unwrap_or(false))
            .unwrap_or(false);
        let json = if owns { r#"{"owns":true}"# } else { r#"{"owns":false}"# };
        Ok(json.into())
    })
}

// ---------------------------------------------------------------------------
// Sandbox — list (by name; no handles are allocated here)
// Output: ["name1","name2",...]
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn msb_sandbox_list(cancel_id: u64, buf: *mut c_uchar, buf_len: usize) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        Ok(Box::pin(async move {
            let handles = Sandbox::list().await.map_err(FfiError::from)?;
            let names: Vec<&str> = handles.iter().map(|h| h.name()).collect();
            serde_json::to_string(&names).map_err(|e| FfiError::internal(e.to_string()))
        }))
    })
}

// ---------------------------------------------------------------------------
// Sandbox — remove (by name; persisted state)
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn msb_sandbox_remove(
    cancel_id: u64,
    name: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let name = unsafe { cstr(name) }?;
        Ok(Box::pin(async move {
            Sandbox::remove(&name).await.map_err(FfiError::from)?;
            Ok(r#"{"ok":true}"#.into())
        }))
    })
}

// ---------------------------------------------------------------------------
// Sandbox — exec (blocking, collected output)
//
// exec_opts_json: {"args":[...],"cwd":"...","timeout_secs":<int>}
// Output: {"stdout":"...","stderr":"...","exit_code":<int|null>}
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct ExecOpts {
    args: Option<Vec<String>>,
    cwd: Option<String>,
    timeout_secs: Option<u64>,
    stdin_pipe: Option<bool>,
    user: Option<String>,
    #[serde(default)]
    env: HashMap<String, String>,
}

#[unsafe(no_mangle)]
pub extern "C" fn msb_sandbox_exec(
    cancel_id: u64,
    handle: Handle,
    cmd: *const c_char,
    exec_opts_json: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let sb = get(handle)?;
        let cmd = unsafe { cstr(cmd) }?;
        let opts_raw = unsafe { cstr(exec_opts_json) }?;
        let opts: ExecOpts = serde_json::from_str(&opts_raw)
            .map_err(|e| FfiError::invalid_argument(format!("invalid exec opts: {e}")))?;
        Ok(Box::pin(async move {
            let output = sb
                .exec_with(&cmd, |mut b| {
                    if let Some(args) = opts.args {
                        b = b.args(args);
                    }
                    if let Some(cwd) = opts.cwd {
                        b = b.cwd(cwd);
                    }
                    if let Some(secs) = opts.timeout_secs {
                        b = b.timeout(Duration::from_secs(secs));
                    }
                    if let Some(u) = opts.user {
                        b = b.user(u);
                    }
                    for (k, v) in opts.env {
                        b = b.env(k, v);
                    }
                    b
                })
                .await
                .map_err(FfiError::from)?;

            let stdout = output.stdout().unwrap_or_default();
            let stderr = output.stderr().unwrap_or_default();
            let exit_code = output.status().code;
            Ok(serde_json::json!({
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": exit_code,
            })
            .to_string())
        }))
    })
}

// ---------------------------------------------------------------------------
// Sandbox — metrics
// Output: {cpu_percent,memory_bytes,memory_limit_bytes,disk_*,net_*,uptime_secs}
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn msb_sandbox_metrics(
    cancel_id: u64,
    handle: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let sb = get(handle)?;
        Ok(Box::pin(async move {
            let m = sb.metrics().await.map_err(FfiError::from)?;
            Ok(serde_json::json!({
                "cpu_percent": m.cpu_percent,
                "memory_bytes": m.memory_bytes,
                "memory_limit_bytes": m.memory_limit_bytes,
                "disk_read_bytes": m.disk_read_bytes,
                "disk_write_bytes": m.disk_write_bytes,
                "net_rx_bytes": m.net_rx_bytes,
                "net_tx_bytes": m.net_tx_bytes,
                "uptime_secs": m.uptime.as_secs(),
            })
            .to_string())
        }))
    })
}

// ---------------------------------------------------------------------------
// Filesystem
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn msb_fs_read(
    cancel_id: u64,
    handle: Handle,
    path: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let sb = get(handle)?;
        let path = unsafe { cstr(path) }?;
        Ok(Box::pin(async move {
            let bytes = sb.fs().read(&path).await.map_err(FfiError::from)?;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
            Ok(format!(r#"{{"data":"{b64}"}}"#))
        }))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn msb_fs_write(
    cancel_id: u64,
    handle: Handle,
    path: *const c_char,
    data_b64: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let sb = get(handle)?;
        let path = unsafe { cstr(path) }?;
        let data_b64 = unsafe { cstr(data_b64) }?;
        let data = base64::engine::general_purpose::STANDARD
            .decode(data_b64.as_bytes())
            .map_err(|e| FfiError::invalid_argument(format!("base64 decode: {e}")))?;
        Ok(Box::pin(async move {
            sb.fs().write(&path, data).await.map_err(FfiError::from)?;
            Ok(r#"{"ok":true}"#.into())
        }))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn msb_fs_list(
    cancel_id: u64,
    handle: Handle,
    path: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let sb = get(handle)?;
        let path = unsafe { cstr(path) }?;
        Ok(Box::pin(async move {
            let entries = sb.fs().list(&path).await.map_err(FfiError::from)?;
            let out: Vec<_> = entries
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "path": e.path,
                        "kind": kind_str(e.kind),
                        "size": e.size,
                        "mode": e.mode,
                    })
                })
                .collect();
            Ok(serde_json::to_string(&out).unwrap_or_else(|_| "[]".into()))
        }))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn msb_fs_stat(
    cancel_id: u64,
    handle: Handle,
    path: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let sb = get(handle)?;
        let path = unsafe { cstr(path) }?;
        Ok(Box::pin(async move {
            let m = sb.fs().stat(&path).await.map_err(FfiError::from)?;
            Ok(serde_json::json!({
                "kind": kind_str(m.kind),
                "size": m.size,
                "mode": m.mode,
                "readonly": m.readonly,
                "modified_unix": m.modified.map(|t| t.timestamp()),
            })
            .to_string())
        }))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn msb_fs_copy_from_host(
    cancel_id: u64,
    handle: Handle,
    host_path: *const c_char,
    guest_path: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let sb = get(handle)?;
        let host_path = unsafe { cstr(host_path) }?;
        let guest_path = unsafe { cstr(guest_path) }?;
        Ok(Box::pin(async move {
            sb.fs()
                .copy_from_host(&host_path, &guest_path)
                .await
                .map_err(FfiError::from)?;
            Ok(r#"{"ok":true}"#.into())
        }))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn msb_fs_copy_to_host(
    cancel_id: u64,
    handle: Handle,
    guest_path: *const c_char,
    host_path: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let sb = get(handle)?;
        let guest_path = unsafe { cstr(guest_path) }?;
        let host_path = unsafe { cstr(host_path) }?;
        Ok(Box::pin(async move {
            sb.fs()
                .copy_to_host(&guest_path, &host_path)
                .await
                .map_err(FfiError::from)?;
            Ok(r#"{"ok":true}"#.into())
        }))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn msb_fs_mkdir(
    cancel_id: u64,
    handle: Handle,
    path: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let sb = get(handle)?;
        let path = unsafe { cstr(path) }?;
        Ok(Box::pin(async move {
            sb.fs().mkdir(&path).await.map_err(FfiError::from)?;
            Ok(r#"{"ok":true}"#.into())
        }))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn msb_fs_remove(
    cancel_id: u64,
    handle: Handle,
    path: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let sb = get(handle)?;
        let path = unsafe { cstr(path) }?;
        Ok(Box::pin(async move {
            sb.fs().remove(&path).await.map_err(FfiError::from)?;
            Ok(r#"{"ok":true}"#.into())
        }))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn msb_fs_remove_dir(
    cancel_id: u64,
    handle: Handle,
    path: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let sb = get(handle)?;
        let path = unsafe { cstr(path) }?;
        Ok(Box::pin(async move {
            sb.fs().remove_dir(&path).await.map_err(FfiError::from)?;
            Ok(r#"{"ok":true}"#.into())
        }))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn msb_fs_copy(
    cancel_id: u64,
    handle: Handle,
    src: *const c_char,
    dst: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let sb = get(handle)?;
        let src = unsafe { cstr(src) }?;
        let dst = unsafe { cstr(dst) }?;
        Ok(Box::pin(async move {
            sb.fs().copy(&src, &dst).await.map_err(FfiError::from)?;
            Ok(r#"{"ok":true}"#.into())
        }))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn msb_fs_rename(
    cancel_id: u64,
    handle: Handle,
    src: *const c_char,
    dst: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let sb = get(handle)?;
        let src = unsafe { cstr(src) }?;
        let dst = unsafe { cstr(dst) }?;
        Ok(Box::pin(async move {
            sb.fs().rename(&src, &dst).await.map_err(FfiError::from)?;
            Ok(r#"{"ok":true}"#.into())
        }))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn msb_fs_exists(
    cancel_id: u64,
    handle: Handle,
    path: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let sb = get(handle)?;
        let path = unsafe { cstr(path) }?;
        Ok(Box::pin(async move {
            let exists = sb.fs().exists(&path).await.map_err(FfiError::from)?;
            Ok(format!(r#"{{"exists":{exists}}}"#))
        }))
    })
}

// ---------------------------------------------------------------------------
// Volumes — name-addressed; no handles.
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn msb_volume_create(
    cancel_id: u64,
    name: *const c_char,
    quota_mib: u32,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let name = unsafe { cstr(name) }?;
        Ok(Box::pin(async move {
            let mut b = Volume::builder(&name);
            if quota_mib > 0 {
                b = b.quota(quota_mib);
            }
            b.create().await.map_err(FfiError::from)?;
            Ok(r#"{"ok":true}"#.into())
        }))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn msb_volume_remove(
    cancel_id: u64,
    name: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let name = unsafe { cstr(name) }?;
        Ok(Box::pin(async move {
            Volume::remove(&name).await.map_err(FfiError::from)?;
            Ok(r#"{"ok":true}"#.into())
        }))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn msb_volume_list(cancel_id: u64, buf: *mut c_uchar, buf_len: usize) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        Ok(Box::pin(async move {
            let handles = Volume::list().await.map_err(FfiError::from)?;
            let names: Vec<&str> = handles.iter().map(|h| h.name()).collect();
            serde_json::to_string(&names).map_err(|e| FfiError::internal(e.to_string()))
        }))
    })
}

// ---------------------------------------------------------------------------
// Metrics streaming
//
// msb_sandbox_metrics_stream  — start; returns a stream_handle u64
// msb_metrics_recv            — poll for the next snapshot (blocks up to interval)
// msb_metrics_close           — drop the stream
// ---------------------------------------------------------------------------

static NEXT_METRICS_HANDLE: AtomicU64 = AtomicU64::new(1);

// Metrics stream: the driver task runs in the Tokio runtime and sends results
// through an unbounded channel. The Go side calls msb_metrics_recv to receive
// the next snapshot, blocking until one arrives or the context is cancelled.
type MetricsItem = Result<microsandbox::sandbox::SandboxMetrics, microsandbox::MicrosandboxError>;
type MetricsStreamEntry = std::sync::Arc<tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<MetricsItem>>>;

fn metrics_registry() -> &'static RwLock<HashMap<Handle, MetricsStreamEntry>> {
    static REG: OnceLock<RwLock<HashMap<Handle, MetricsStreamEntry>>> = OnceLock::new();
    REG.get_or_init(|| RwLock::new(HashMap::new()))
}

fn register_metrics(rx: tokio::sync::mpsc::UnboundedReceiver<MetricsItem>) -> Result<Handle, FfiError> {
    let h = NEXT_METRICS_HANDLE.fetch_add(1, Ordering::Relaxed);
    metrics_registry()
        .write()
        .map_err(|_| FfiError::internal("metrics registry lock poisoned"))?
        .insert(h, std::sync::Arc::new(tokio::sync::Mutex::new(rx)));
    Ok(h)
}

fn get_metrics(handle: Handle) -> Result<MetricsStreamEntry, FfiError> {
    metrics_registry()
        .read()
        .map_err(|_| FfiError::internal("metrics registry lock poisoned"))?
        .get(&handle)
        .cloned()
        .ok_or_else(|| FfiError::invalid_handle(handle))
}

fn remove_metrics(handle: Handle) {
    let _ = metrics_registry().write().map(|mut r| r.remove(&handle));
}

/// Start a metrics stream. Returns `{"stream_handle":<u64>}`.
/// interval_ms: polling interval in milliseconds (0 → 1 ms minimum).
#[unsafe(no_mangle)]
pub extern "C" fn msb_sandbox_metrics_stream(
    cancel_id: u64,
    handle: Handle,
    interval_ms: u64,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let sb = get(handle)?;
        Ok(Box::pin(async move {
            let interval = Duration::from_millis(if interval_ms == 0 { 1 } else { interval_ms });
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<MetricsItem>();
            // Spawn a task that drives the stream and forwards items to the channel.
            // The task stops naturally when the receiver is dropped (msb_metrics_close).
            tokio::spawn(async move {
                let mut stream = std::pin::pin!(sb.metrics_stream(interval));
                while let Some(item) = stream.next().await {
                    if tx.send(item).is_err() {
                        break; // receiver dropped
                    }
                }
            });
            let sh = register_metrics(rx)?;
            Ok(format!(r#"{{"stream_handle":{sh}}}"#))
        }))
    })
}

/// Poll for the next metrics snapshot. Blocks until the next interval fires.
/// Returns a JSON metrics object, or `{"done":true}` if the stream ended.
#[unsafe(no_mangle)]
pub extern "C" fn msb_metrics_recv(
    cancel_id: u64,
    stream_handle: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    let result: Result<(), FfiError> = (|| -> Result<(), FfiError> {
        let token = lookup_cancel_token(cancel_id)?;
        let entry = get_metrics(stream_handle)?;
        let mut recv = entry
            .try_lock()
            .map_err(|_| FfiError::internal("metrics stream mutex busy"))?;
        let json = rt().block_on(async {
            tokio::select! {
                item = recv.recv() => {
                    match item {
                        None => Ok(r#"{"done":true}"#.to_string()),
                        Some(Ok(m)) => Ok(format!(
                            r#"{{"cpu_percent":{cpu},"memory_bytes":{mem},"memory_limit_bytes":{lim},"disk_read_bytes":{dr},"disk_write_bytes":{dw},"net_rx_bytes":{net_rx},"net_tx_bytes":{net_tx},"uptime_secs":{up}}}"#,
                            cpu = m.cpu_percent,
                            mem = m.memory_bytes,
                            lim = m.memory_limit_bytes,
                            dr = m.disk_read_bytes,
                            dw = m.disk_write_bytes,
                            net_rx = m.net_rx_bytes,
                            net_tx = m.net_tx_bytes,
                            up = m.uptime.as_secs(),
                        )),
                        Some(Err(e)) => Err(FfiError::from(e)),
                    }
                }
                _ = token.cancelled() => Err(FfiError::new(error_kind::CANCELLED, "cancelled")),
            }
        })?;
        write_output(buf, buf_len, &json)
    })();
    cancel_unregister(cancel_id);
    match result {
        Ok(()) => std::ptr::null_mut(),
        Err(e) => err_ptr(e),
    }
}

/// Close (drop) a metrics stream. The background driver task exits when the
/// channel receiver is dropped.
#[unsafe(no_mangle)]
pub extern "C" fn msb_metrics_close(
    stream_handle: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run(buf, buf_len, || {
        remove_metrics(stream_handle);
        Ok(r#"{"ok":true}"#.into())
    })
}

// ---------------------------------------------------------------------------
// Exec streaming
//
// msb_sandbox_exec_stream — starts a streaming exec, returns an exec handle.
// msb_exec_recv           — receive the next event (blocks until one arrives
//                           or the stream ends). Returns {"done":true} when
//                           the process has exited and all events are drained.
// msb_exec_close          — drop the exec handle (does not kill the process).
//
// Event JSON shapes:
//   {"event":"started","pid":<u32>}
//   {"event":"stdout","data":"<base64>"}
//   {"event":"stderr","data":"<base64>"}
//   {"event":"exited","code":<i32>}
//   {"event":"done"}   — returned by msb_exec_recv when stream has ended
// ---------------------------------------------------------------------------

/// Start a streaming exec session. Returns {"exec_handle":<u64>}.
/// The exec handle MUST be released with msb_exec_close when done.
///
/// exec_opts_json: same schema as msb_sandbox_exec (args, cwd, timeout_secs).
#[unsafe(no_mangle)]
pub extern "C" fn msb_sandbox_exec_stream(
    cancel_id: u64,
    handle: Handle,
    cmd: *const c_char,
    exec_opts_json: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let sb = get(handle)?;
        let cmd = unsafe { cstr(cmd) }?;
        let opts_raw = unsafe { cstr(exec_opts_json) }?;
        let opts: ExecOpts = serde_json::from_str(&opts_raw)
            .map_err(|e| FfiError::invalid_argument(format!("invalid exec opts: {e}")))?;
        Ok(Box::pin(async move {
            let stdin_pipe = opts.stdin_pipe.unwrap_or(false);
            let exec_handle = sb
                .exec_stream_with(&cmd, |mut b| {
                    if let Some(args) = opts.args {
                        b = b.args(args);
                    }
                    if stdin_pipe {
                        b = b.stdin_pipe();
                    }
                    if let Some(cwd) = opts.cwd {
                        b = b.cwd(cwd);
                    }
                    if let Some(secs) = opts.timeout_secs {
                        b = b.timeout(Duration::from_secs(secs));
                    }
                    if let Some(u) = opts.user {
                        b = b.user(u);
                    }
                    for (k, v) in opts.env {
                        b = b.env(k, v);
                    }
                    b
                })
                .await
                .map_err(FfiError::from)?;
            let exec_h = register_exec(exec_handle)?;
            if stdin_pipe {
                if let Ok(eh) = get_exec(exec_h) {
                    if let Ok(mut guard) = eh.lock() {
                        if let Some(sink) = guard.take_stdin() {
                            let _ = register_stdin(exec_h, sink);
                        }
                    }
                }
            }
            Ok(format!(r#"{{"exec_handle":{exec_h}}}"#))
        }))
    })
}

/// Receive the next event from a streaming exec session.
/// Blocks until an event is available or the stream ends.
/// Returns {"event":"done"} when all events have been consumed.
/// The exec handle remains valid after "done" until msb_exec_close is called.
#[unsafe(no_mangle)]
pub extern "C" fn msb_exec_recv(
    cancel_id: u64,
    exec_handle: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    // This function can't use run_c because it must hold the exec-handle
    // Mutex guard across the await. Instead it replicates the cancel-id
    // unregister contract inline: always unregister on return.
    let result: Result<(), FfiError> = (|| -> Result<(), FfiError> {
        let token = lookup_cancel_token(cancel_id)?;
        // Clone the Arc out so the read guard is dropped before block_on —
        // otherwise any register/remove of another exec handle would deadlock
        // while this recv blocks waiting for data.
        let entry = get_exec(exec_handle)?;
        let mut eh = entry
            .lock()
            .map_err(|_| FfiError::internal("exec handle mutex poisoned"))?;
        let json = rt().block_on(async {
            tokio::select! {
                event = eh.recv() => {
                    let json = match event {
                        None => r#"{"event":"done"}"#.to_string(),
                        Some(ExecEvent::Started { pid }) => format!(r#"{{"event":"started","pid":{pid}}}"#),
                        Some(ExecEvent::Stdout(data)) => {
                            let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
                            format!(r#"{{"event":"stdout","data":"{b64}"}}"#)
                        }
                        Some(ExecEvent::Stderr(data)) => {
                            let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
                            format!(r#"{{"event":"stderr","data":"{b64}"}}"#)
                        }
                        Some(ExecEvent::Exited { code }) => format!(r#"{{"event":"exited","code":{code}}}"#),
                    };
                    Ok::<_, FfiError>(json)
                }
                _ = token.cancelled() => Err(FfiError::new(error_kind::CANCELLED, "cancelled")),
            }
        })?;
        write_output(buf, buf_len, &json)
    })();
    cancel_unregister(cancel_id);
    match result {
        Ok(()) => std::ptr::null_mut(),
        Err(e) => err_ptr(e),
    }
}

/// Release the exec handle. Does not kill the running process; use
/// msb_sandbox_exec_stream then msb_exec_close after the process exits,
/// or msb_exec_signal/kill to terminate it first.
#[unsafe(no_mangle)]
pub extern "C" fn msb_exec_close(
    cancel_id: u64,
    exec_handle: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    cancel_unregister(cancel_id);
    run(buf, buf_len, || {
        remove_exec(exec_handle)?
            .ok_or_else(|| FfiError::invalid_handle(exec_handle))?;
        remove_stdin(exec_handle);
        Ok(r#"{"ok":true}"#.into())
    })
}

/// Return the internal protocol ID for an exec session. Synchronous.
/// Returns `{"id":"<string>"}`.
#[unsafe(no_mangle)]
pub extern "C" fn msb_exec_id(
    exec_handle: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run(buf, buf_len, || {
        let entry = get_exec(exec_handle)?;
        let eh = entry
            .lock()
            .map_err(|_| FfiError::internal("exec handle mutex poisoned"))?;
        let id = eh.id();
        Ok(format!(r#"{{"id":"{id}"}}"#))
    })
}

/// Send a Unix signal to the running process.
/// signal: standard Unix signal number (e.g. 15 = SIGTERM, 9 = SIGKILL).
#[unsafe(no_mangle)]
pub extern "C" fn msb_exec_signal(
    cancel_id: u64,
    exec_handle: Handle,
    signal: i32,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    let result: Result<(), FfiError> = (|| -> Result<(), FfiError> {
        let token = lookup_cancel_token(cancel_id)?;
        let entry = get_exec(exec_handle)?;
        let eh = entry
            .lock()
            .map_err(|_| FfiError::internal("exec handle mutex poisoned"))?;
        rt().block_on(async {
            tokio::select! {
                r = eh.signal(signal) => r.map_err(FfiError::from),
                _ = token.cancelled() => Err(FfiError::new(error_kind::CANCELLED, "cancelled")),
            }
        })?;
        write_output(buf, buf_len, r#"{"ok":true}"#)
    })();
    cancel_unregister(cancel_id);
    match result {
        Ok(()) => std::ptr::null_mut(),
        Err(e) => err_ptr(e),
    }
}

// ---------------------------------------------------------------------------
// Exec stdin (write / close)
//
// Only valid when the exec session was started with stdin_pipe=true.
// data_b64 is standard base64-encoded bytes.
// ---------------------------------------------------------------------------

/// Write data to the stdin pipe of a running exec session.
/// data_b64 is standard base64. Returns `{"ok":true}` on success.
#[unsafe(no_mangle)]
pub extern "C" fn msb_exec_stdin_write(
    cancel_id: u64,
    exec_handle: Handle,
    data_b64: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    let result: Result<(), FfiError> = (|| -> Result<(), FfiError> {
        let token = lookup_cancel_token(cancel_id)?;
        let data_str = unsafe { cstr(data_b64) }?;
        let data = base64::engine::general_purpose::STANDARD
            .decode(data_str.as_bytes())
            .map_err(|e| FfiError::invalid_argument(format!("base64 decode: {e}")))?;
        let sink = get_stdin(exec_handle)?;
        rt().block_on(async {
            tokio::select! {
                r = sink.write(&data) => r.map_err(FfiError::from),
                _ = token.cancelled() => Err(FfiError::new(error_kind::CANCELLED, "cancelled")),
            }
        })?;
        write_output(buf, buf_len, r#"{"ok":true}"#)
    })();
    cancel_unregister(cancel_id);
    match result {
        Ok(()) => std::ptr::null_mut(),
        Err(e) => err_ptr(e),
    }
}

/// Close the stdin pipe of a running exec session. Returns `{"ok":true}` on success.
#[unsafe(no_mangle)]
pub extern "C" fn msb_exec_stdin_close(
    cancel_id: u64,
    exec_handle: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    let result: Result<(), FfiError> = (|| -> Result<(), FfiError> {
        let token = lookup_cancel_token(cancel_id)?;
        let sink = get_stdin(exec_handle)?;
        rt().block_on(async {
            tokio::select! {
                r = sink.close() => r.map_err(FfiError::from),
                _ = token.cancelled() => Err(FfiError::new(error_kind::CANCELLED, "cancelled")),
            }
        })?;
        remove_stdin(exec_handle);
        write_output(buf, buf_len, r#"{"ok":true}"#)
    })();
    cancel_unregister(cancel_id);
    match result {
        Ok(()) => std::ptr::null_mut(),
        Err(e) => err_ptr(e),
    }
}

// ---------------------------------------------------------------------------
// ExecHandle — collect / wait / kill
// ---------------------------------------------------------------------------

/// Collect all remaining stdout/stderr from a streaming exec and return ExecOutput.
/// Returns `{"stdout_b64":"...","stderr_b64":"...","exit_code":<int>}`.
#[unsafe(no_mangle)]
pub extern "C" fn msb_exec_collect(
    cancel_id: u64,
    exec_handle: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    let result: Result<(), FfiError> = (|| -> Result<(), FfiError> {
        let token = lookup_cancel_token(cancel_id)?;
        let entry = get_exec(exec_handle)?;
        let mut eh = entry
            .lock()
            .map_err(|_| FfiError::internal("exec handle mutex poisoned"))?;
        let output = rt().block_on(async {
            tokio::select! {
                r = eh.collect() => r.map_err(FfiError::from),
                _ = token.cancelled() => Err(FfiError::new(error_kind::CANCELLED, "cancelled")),
            }
        })?;
        let stdout_b64 = base64::engine::general_purpose::STANDARD.encode(output.stdout_bytes());
        let stderr_b64 = base64::engine::general_purpose::STANDARD.encode(output.stderr_bytes());
        let json = format!(
            r#"{{"stdout_b64":"{stdout_b64}","stderr_b64":"{stderr_b64}","exit_code":{code}}}"#,
            code = output.status().code,
        );
        write_output(buf, buf_len, &json)
    })();
    cancel_unregister(cancel_id);
    match result {
        Ok(()) => std::ptr::null_mut(),
        Err(e) => err_ptr(e),
    }
}

/// Wait for the exec session to exit. Returns `{"exit_code":<int>}`.
#[unsafe(no_mangle)]
pub extern "C" fn msb_exec_wait(
    cancel_id: u64,
    exec_handle: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    let result: Result<(), FfiError> = (|| -> Result<(), FfiError> {
        let token = lookup_cancel_token(cancel_id)?;
        let entry = get_exec(exec_handle)?;
        let mut eh = entry
            .lock()
            .map_err(|_| FfiError::internal("exec handle mutex poisoned"))?;
        let status = rt().block_on(async {
            tokio::select! {
                r = eh.wait() => r.map_err(FfiError::from),
                _ = token.cancelled() => Err(FfiError::new(error_kind::CANCELLED, "cancelled")),
            }
        })?;
        let json = format!(r#"{{"exit_code":{}}}"#, status.code);
        write_output(buf, buf_len, &json)
    })();
    cancel_unregister(cancel_id);
    match result {
        Ok(()) => std::ptr::null_mut(),
        Err(e) => err_ptr(e),
    }
}

/// Send SIGKILL to the running exec process. Returns `{"ok":true}`.
#[unsafe(no_mangle)]
pub extern "C" fn msb_exec_kill(
    cancel_id: u64,
    exec_handle: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    let result: Result<(), FfiError> = (|| -> Result<(), FfiError> {
        let token = lookup_cancel_token(cancel_id)?;
        let entry = get_exec(exec_handle)?;
        let eh = entry
            .lock()
            .map_err(|_| FfiError::internal("exec handle mutex poisoned"))?;
        rt().block_on(async {
            tokio::select! {
                r = eh.kill() => r.map_err(FfiError::from),
                _ = token.cancelled() => Err(FfiError::new(error_kind::CANCELLED, "cancelled")),
            }
        })?;
        write_output(buf, buf_len, r#"{"ok":true}"#)
    })();
    cancel_unregister(cancel_id);
    match result {
        Ok(()) => std::ptr::null_mut(),
        Err(e) => err_ptr(e),
    }
}

// ---------------------------------------------------------------------------
// All-sandbox metrics
// ---------------------------------------------------------------------------

/// Return metrics for all running sandboxes.
/// Returns `{"sandboxes":{"<name>":{...metrics...},...}}`.
#[unsafe(no_mangle)]
pub extern "C" fn msb_all_sandbox_metrics(
    cancel_id: u64,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        Ok(Box::pin(async move {
            let map = all_sandbox_metrics().await.map_err(FfiError::from)?;
            let mut entries = String::new();
            for (name, m) in &map {
                if !entries.is_empty() { entries.push(','); }
                entries.push_str(&format!(
                    r#""{name}":{{"cpu_percent":{cpu},"memory_bytes":{mem},"memory_limit_bytes":{lim},"disk_read_bytes":{dr},"disk_write_bytes":{dw},"net_rx_bytes":{rx},"net_tx_bytes":{tx},"uptime_secs":{up}}}"#,
                    cpu = m.cpu_percent,
                    mem = m.memory_bytes,
                    lim = m.memory_limit_bytes,
                    dr  = m.disk_read_bytes,
                    dw  = m.disk_write_bytes,
                    rx  = m.net_rx_bytes,
                    tx  = m.net_tx_bytes,
                    up  = m.uptime.as_secs(),
                ));
            }
            Ok(format!(r#"{{"sandboxes":{{{entries}}}}}"#))
        }))
    })
}

// ---------------------------------------------------------------------------
// SandboxHandle metrics (by name, no live sandbox handle required)
// ---------------------------------------------------------------------------

/// Return metrics for a specific sandbox by name.
/// Returns the same metrics JSON shape as msb_sandbox_metrics.
#[unsafe(no_mangle)]
pub extern "C" fn msb_sandbox_handle_metrics(
    cancel_id: u64,
    name: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let name_str = unsafe { cstr(name) }?.to_owned();
        Ok(Box::pin(async move {
            let handle = Sandbox::get(&name_str).await.map_err(FfiError::from)?;
            let m = handle.metrics().await.map_err(FfiError::from)?;
            Ok(format!(
                r#"{{"cpu_percent":{cpu},"memory_bytes":{mem},"memory_limit_bytes":{lim},"disk_read_bytes":{dr},"disk_write_bytes":{dw},"net_rx_bytes":{rx},"net_tx_bytes":{tx},"uptime_secs":{up}}}"#,
                cpu = m.cpu_percent,
                mem = m.memory_bytes,
                lim = m.memory_limit_bytes,
                dr  = m.disk_read_bytes,
                dw  = m.disk_write_bytes,
                rx  = m.net_rx_bytes,
                tx  = m.net_tx_bytes,
                up  = m.uptime.as_secs(),
            ))
        }))
    })
}

// ---------------------------------------------------------------------------
// Sandbox.removePersisted
// ---------------------------------------------------------------------------

/// Remove the sandbox's persisted filesystem + database state.
/// The sandbox must be stopped. Consumes the live handle.
/// Returns `{"ok":true}`.
#[unsafe(no_mangle)]
pub extern "C" fn msb_sandbox_remove_persisted(
    cancel_id: u64,
    handle: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let sb = remove(handle)?.ok_or_else(|| FfiError::invalid_handle(handle))?;
        let owned = std::sync::Arc::try_unwrap(sb)
            .map_err(|_| FfiError::internal("sandbox handle still referenced"))?;
        Ok(Box::pin(async move {
            owned.remove_persisted().await.map_err(FfiError::from)?;
            Ok(r#"{"ok":true}"#.to_string())
        }))
    })
}

// ---------------------------------------------------------------------------
// Volume.get
// ---------------------------------------------------------------------------

/// Look up a volume by name and return its metadata.
/// Returns `{"name":"...","quota_mib":<int|null>,"used_bytes":<int>,
///           "labels":{"k":"v",...},"created_at_unix":<int|null>}`.
#[unsafe(no_mangle)]
pub extern "C" fn msb_volume_get(
    cancel_id: u64,
    name: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let name_str = unsafe { cstr(name) }?.to_owned();
        Ok(Box::pin(async move {
            let vh = Volume::get(&name_str).await.map_err(FfiError::from)?;
            let quota = match vh.quota_mib() {
                Some(q) => format!("{q}"),
                None => "null".to_string(),
            };
            let created = match vh.created_at() {
                Some(dt) => format!("{}", dt.timestamp()),
                None => "null".to_string(),
            };
            let labels_json: String = {
                let mut s = String::from("{");
                for (i, (k, v)) in vh.labels().iter().enumerate() {
                    if i > 0 { s.push(','); }
                    s.push_str(&format!(r#""{k}":"{v}""#));
                }
                s.push('}');
                s
            };
            let path = microsandbox::config::config()
                .volumes_dir()
                .join(vh.name())
                .to_string_lossy()
                .into_owned();
            Ok(format!(
                r#"{{"name":"{name}","path":"{path}","quota_mib":{quota},"used_bytes":{used},"labels":{labels},"created_at_unix":{created}}}"#,
                name = vh.name(),
                used = vh.used_bytes(),
                labels = labels_json,
            ))
        }))
    })
}

// ---------------------------------------------------------------------------
// Filesystem streaming — FsReadStream / FsWriteSink
// ---------------------------------------------------------------------------

static NEXT_FS_READ_HANDLE: AtomicU64 = AtomicU64::new(1);
static NEXT_FS_WRITE_HANDLE: AtomicU64 = AtomicU64::new(1);

type FsReadEntry = std::sync::Arc<tokio::sync::Mutex<FsReadStream>>;
type FsWriteEntry = std::sync::Arc<tokio::sync::Mutex<Option<FsWriteSink>>>;

fn fs_read_registry() -> &'static RwLock<HashMap<Handle, FsReadEntry>> {
    static REG: OnceLock<RwLock<HashMap<Handle, FsReadEntry>>> = OnceLock::new();
    REG.get_or_init(|| RwLock::new(HashMap::new()))
}

fn fs_write_registry() -> &'static RwLock<HashMap<Handle, FsWriteEntry>> {
    static REG: OnceLock<RwLock<HashMap<Handle, FsWriteEntry>>> = OnceLock::new();
    REG.get_or_init(|| RwLock::new(HashMap::new()))
}

fn register_fs_read(stream: FsReadStream) -> Result<Handle, FfiError> {
    let h = NEXT_FS_READ_HANDLE.fetch_add(1, Ordering::Relaxed);
    fs_read_registry()
        .write()
        .map_err(|_| FfiError::internal("fs_read registry poisoned"))?
        .insert(h, std::sync::Arc::new(tokio::sync::Mutex::new(stream)));
    Ok(h)
}

fn get_fs_read(handle: Handle) -> Result<FsReadEntry, FfiError> {
    fs_read_registry()
        .read()
        .map_err(|_| FfiError::internal("fs_read registry poisoned"))?
        .get(&handle)
        .cloned()
        .ok_or_else(|| FfiError::invalid_handle(handle))
}

fn remove_fs_read(handle: Handle) {
    let _ = fs_read_registry().write().map(|mut r| r.remove(&handle));
}

fn register_fs_write(sink: FsWriteSink) -> Result<Handle, FfiError> {
    let h = NEXT_FS_WRITE_HANDLE.fetch_add(1, Ordering::Relaxed);
    fs_write_registry()
        .write()
        .map_err(|_| FfiError::internal("fs_write registry poisoned"))?
        .insert(h, std::sync::Arc::new(tokio::sync::Mutex::new(Some(sink))));
    Ok(h)
}

fn get_fs_write(handle: Handle) -> Result<FsWriteEntry, FfiError> {
    fs_write_registry()
        .read()
        .map_err(|_| FfiError::internal("fs_write registry poisoned"))?
        .get(&handle)
        .cloned()
        .ok_or_else(|| FfiError::invalid_handle(handle))
}

fn remove_fs_write(handle: Handle) {
    let _ = fs_write_registry().write().map(|mut r| r.remove(&handle));
}

/// Open a streaming read from a guest file.
/// Returns `{"stream_handle":<u64>}`.
#[unsafe(no_mangle)]
pub extern "C" fn msb_fs_read_stream(
    cancel_id: u64,
    handle: Handle,
    path: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let sb = get(handle)?;
        let path_str = unsafe { cstr(path) }?.to_owned();
        Ok(Box::pin(async move {
            let stream = sb.fs().read_stream(&path_str).await.map_err(FfiError::from)?;
            let sh = register_fs_read(stream)?;
            Ok(format!(r#"{{"stream_handle":{sh}}}"#))
        }))
    })
}

/// Receive the next chunk from a read stream.
/// Returns `{"done":true}` at EOF, or `{"chunk_b64":"..."}` with data.
#[unsafe(no_mangle)]
pub extern "C" fn msb_fs_read_stream_recv(
    cancel_id: u64,
    stream_handle: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    let result: Result<(), FfiError> = (|| -> Result<(), FfiError> {
        let token = lookup_cancel_token(cancel_id)?;
        let entry = get_fs_read(stream_handle)?;
        let mut stream = entry
            .try_lock()
            .map_err(|_| FfiError::internal("fs_read stream mutex busy"))?;
        let json = rt().block_on(async {
            tokio::select! {
                r = stream.recv() => {
                    match r.map_err(FfiError::from)? {
                        None => Ok(r#"{"done":true}"#.to_string()),
                        Some(chunk) => {
                            let b64 = base64::engine::general_purpose::STANDARD.encode(&chunk);
                            Ok(format!(r#"{{"chunk_b64":"{b64}"}}"#))
                        }
                    }
                },
                _ = token.cancelled() => Err(FfiError::new(error_kind::CANCELLED, "cancelled")),
            }
        })?;
        write_output(buf, buf_len, &json)
    })();
    cancel_unregister(cancel_id);
    match result {
        Ok(()) => std::ptr::null_mut(),
        Err(e) => err_ptr(e),
    }
}

/// Close (drop) a read stream. Synchronous. Returns `{"ok":true}`.
#[unsafe(no_mangle)]
pub extern "C" fn msb_fs_read_stream_close(
    stream_handle: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run(buf, buf_len, || {
        remove_fs_read(stream_handle);
        Ok(r#"{"ok":true}"#.to_string())
    })
}

/// Open a streaming write to a guest file.
/// Returns `{"stream_handle":<u64>}`.
#[unsafe(no_mangle)]
pub extern "C" fn msb_fs_write_stream(
    cancel_id: u64,
    handle: Handle,
    path: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let sb = get(handle)?;
        let path_str = unsafe { cstr(path) }?.to_owned();
        Ok(Box::pin(async move {
            let sink = sb.fs().write_stream(&path_str).await.map_err(FfiError::from)?;
            let sh = register_fs_write(sink)?;
            Ok(format!(r#"{{"stream_handle":{sh}}}"#))
        }))
    })
}

/// Write a base64-encoded chunk to a write stream. Returns `{"ok":true}`.
#[unsafe(no_mangle)]
pub extern "C" fn msb_fs_write_stream_write(
    cancel_id: u64,
    stream_handle: Handle,
    data_b64: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    let result: Result<(), FfiError> = (|| -> Result<(), FfiError> {
        let token = lookup_cancel_token(cancel_id)?;
        let data_str = unsafe { cstr(data_b64) }?;
        let data = base64::engine::general_purpose::STANDARD
            .decode(data_str.as_bytes())
            .map_err(|e| FfiError::invalid_argument(format!("base64 decode: {e}")))?;
        let entry = get_fs_write(stream_handle)?;
        let guard = entry
            .try_lock()
            .map_err(|_| FfiError::internal("fs_write stream mutex busy"))?;
        let sink = guard.as_ref().ok_or_else(|| FfiError::internal("write stream already closed"))?;
        rt().block_on(async {
            tokio::select! {
                r = sink.write(&data) => r.map_err(FfiError::from),
                _ = token.cancelled() => Err(FfiError::new(error_kind::CANCELLED, "cancelled")),
            }
        })?;
        write_output(buf, buf_len, r#"{"ok":true}"#)
    })();
    cancel_unregister(cancel_id);
    match result {
        Ok(()) => std::ptr::null_mut(),
        Err(e) => err_ptr(e),
    }
}

/// Close a write stream (sends EOF, waits for confirmation). Returns `{"ok":true}`.
#[unsafe(no_mangle)]
pub extern "C" fn msb_fs_write_stream_close(
    cancel_id: u64,
    stream_handle: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    let result: Result<(), FfiError> = (|| -> Result<(), FfiError> {
        let token = lookup_cancel_token(cancel_id)?;
        let entry = get_fs_write(stream_handle)?;
        let mut guard = entry
            .try_lock()
            .map_err(|_| FfiError::internal("fs_write stream mutex busy"))?;
        let sink = guard.take().ok_or_else(|| FfiError::internal("write stream already closed"))?;
        drop(guard);
        remove_fs_write(stream_handle);
        rt().block_on(async {
            tokio::select! {
                r = sink.close() => r.map_err(FfiError::from),
                _ = token.cancelled() => Err(FfiError::new(error_kind::CANCELLED, "cancelled")),
            }
        })?;
        write_output(buf, buf_len, r#"{"ok":true}"#)
    })();
    cancel_unregister(cancel_id);
    match result {
        Ok(()) => std::ptr::null_mut(),
        Err(e) => err_ptr(e),
    }
}

// ---------------------------------------------------------------------------
// Attach / AttachShell — interactive PTY sessions
//
// These block the calling thread until the guest process exits.
// opts_json is `{"args":["..."]}` (args is optional).
// Returns `{"exit_code":<int>}`.
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize, Default)]
struct AttachOpts {
    #[serde(default)]
    args: Vec<String>,
}

/// Attach to a sandbox with an interactive PTY session.
/// Returns `{"exit_code":<int>}` when the process exits.
#[unsafe(no_mangle)]
pub extern "C" fn msb_sandbox_attach(
    cancel_id: u64,
    handle: Handle,
    cmd: *const c_char,
    opts_json: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    let result: Result<(), FfiError> = (|| -> Result<(), FfiError> {
        let token = lookup_cancel_token(cancel_id)?;
        let sb = get(handle)?;
        let cmd_str = unsafe { cstr(cmd) }?.to_owned();
        let opts: AttachOpts = if opts_json.is_null() {
            AttachOpts::default()
        } else {
            let s = unsafe { cstr(opts_json) }?;
            serde_json::from_str(&s).map_err(|e| FfiError::invalid_argument(format!("attach opts: {e}")))?
        };
        let exit_code = rt().block_on(async {
            tokio::select! {
                r = sb.attach(&cmd_str, opts.args) => r.map_err(FfiError::from),
                _ = token.cancelled() => Err(FfiError::new(error_kind::CANCELLED, "cancelled")),
            }
        })?;
        let out = format!(r#"{{"exit_code":{exit_code}}}"#);
        write_output(buf, buf_len, &out)
    })();
    cancel_unregister(cancel_id);
    match result {
        Ok(()) => std::ptr::null_mut(),
        Err(e) => err_ptr(e),
    }
}

/// Attach to the sandbox's default shell.
/// Returns `{"exit_code":<int>}` when the shell exits.
#[unsafe(no_mangle)]
pub extern "C" fn msb_sandbox_attach_shell(
    cancel_id: u64,
    handle: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    let result: Result<(), FfiError> = (|| -> Result<(), FfiError> {
        let token = lookup_cancel_token(cancel_id)?;
        let sb = get(handle)?;
        let exit_code = rt().block_on(async {
            tokio::select! {
                r = sb.attach_shell() => r.map_err(FfiError::from),
                _ = token.cancelled() => Err(FfiError::new(error_kind::CANCELLED, "cancelled")),
            }
        })?;
        let out = format!(r#"{{"exit_code":{exit_code}}}"#);
        write_output(buf, buf_len, &out)
    })();
    cancel_unregister(cancel_id);
    match result {
        Ok(()) => std::ptr::null_mut(),
        Err(e) => err_ptr(e),
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn kind_str(kind: FsEntryKind) -> &'static str {
    match kind {
        FsEntryKind::File => "file",
        FsEntryKind::Directory => "directory",
        FsEntryKind::Symlink => "symlink",
        FsEntryKind::Other => "other",
    }
}

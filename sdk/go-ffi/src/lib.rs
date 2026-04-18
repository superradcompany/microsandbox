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
use microsandbox::{
    MicrosandboxError, Sandbox,
    sandbox::{FsEntryKind, exec::{ExecEvent, ExecHandle}},
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
    network: Option<NetworkOpts>,
    /// Top-level ports shorthand: {host_port: guest_port}.
    #[serde(default)]
    ports: HashMap<u16, u16>,
    #[serde(default)]
    secrets: Vec<SecretOpts>,
    #[serde(default)]
    patches: Vec<PatchOpts>,
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
// Sandbox — get
//
// Reattach to an existing sandbox by name and return a fresh handle. Used
// after `msb_sandbox_close` has dropped a local handle, or for sandboxes
// created by another process.
// Output: {"handle": <u64>}
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn msb_sandbox_get(
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
            let exec_handle = sb
                .exec_stream_with(&cmd, |mut b| {
                    if let Some(args) = opts.args {
                        b = b.args(args);
                    }
                    if let Some(cwd) = opts.cwd {
                        b = b.cwd(cwd);
                    }
                    if let Some(secs) = opts.timeout_secs {
                        b = b.timeout(Duration::from_secs(secs));
                    }
                    b
                })
                .await
                .map_err(FfiError::from)?;
            let exec_h = register_exec(exec_handle)?;
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
        Ok(r#"{"ok":true}"#.into())
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
// Private helpers
// ---------------------------------------------------------------------------

fn kind_str(kind: FsEntryKind) -> &'static str {
    match kind {
        FsEntryKind::File => "file",
        FsEntryKind::Directory => "dir",
        FsEntryKind::Symlink => "symlink",
        FsEntryKind::Other => "other",
    }
}

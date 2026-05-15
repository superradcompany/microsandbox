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
//! `<kind>` is one of the strings listed in `error_kind`. This lets the Go
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

// Every `pub unsafe extern "C"` boundary function carries the same implicit
// contract (caller-provided buffer, valid C strings, owned handles) covered
// once in the module-level docs above; per-function `# Safety` blocks would
// be repetitive without adding signal.
#![allow(clippy::missing_safety_doc)]

use std::{
    collections::HashMap,
    ffi::{CStr, CString},
    os::raw::{c_char, c_uchar},
    path::PathBuf,
    sync::{
        OnceLock, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use base64::Engine;
use microsandbox::{
    LogLevel, MicrosandboxError, RegistryAuth, Sandbox, Snapshot, UpperVerifyStatus,
    sandbox::{
        FsEntryKind, LogOptions, LogSource, PullPolicy, all_sandbox_metrics,
        exec::{ExecEvent, ExecHandle, ExecSink},
        fs::{FsReadStream, FsWriteSink},
        logs,
    },
    snapshot::{ExportOpts, SnapshotDestination, SnapshotFormat},
    volume::{Volume, VolumeBuilder, VolumeHandle},
};
use microsandbox_network::secrets::config::ViolationAction;
use tokio::runtime::Runtime;
use tokio_stream::StreamExt as _;
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
        .ok_or_else(|| {
            FfiError::invalid_argument(
                "exec session has no stdin pipe (start with stdin_pipe=true)",
            )
        })
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
    if let Ok(reg) = cancel_registry().read()
        && let Some(token) = reg.get(&id)
    {
        token.cancel();
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
    pub const SNAPSHOT_NOT_FOUND: &str = "snapshot_not_found";
    pub const SNAPSHOT_ALREADY_EXISTS: &str = "snapshot_already_exists";
    pub const SNAPSHOT_SANDBOX_RUNNING: &str = "snapshot_sandbox_running";
    pub const SNAPSHOT_IMAGE_MISSING: &str = "snapshot_image_missing";
    pub const SNAPSHOT_INTEGRITY: &str = "snapshot_integrity";
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
            MicrosandboxError::SnapshotNotFound(_) => error_kind::SNAPSHOT_NOT_FOUND,
            MicrosandboxError::SnapshotAlreadyExists(_) => error_kind::SNAPSHOT_ALREADY_EXISTS,
            MicrosandboxError::SnapshotSandboxRunning(_) => error_kind::SNAPSHOT_SANDBOX_RUNNING,
            MicrosandboxError::SnapshotImageMissing(_) => error_kind::SNAPSHOT_IMAGE_MISSING,
            MicrosandboxError::SnapshotIntegrity(_) => error_kind::SNAPSHOT_INTEGRITY,
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
    f: impl FnOnce() -> Result<
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, FfiError>> + Send>>,
        FfiError,
    >,
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
pub unsafe extern "C" fn msb_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        // SAFETY: We only ever return pointers built via `CString::into_raw`.
        unsafe { drop(CString::from_raw(ptr)) };
    }
}

// ---------------------------------------------------------------------------
// msb_set_sdk_msb_path
// ---------------------------------------------------------------------------

/// Push the SDK-resolved msb binary path into the Rust resolver's tier 2.
/// Called once from setup.EnsureInstalled after the install dir is known.
/// Set-once: subsequent calls are ignored (matches the OnceLock in
/// microsandbox::config). Null or invalid-UTF-8 paths are silently ignored
/// since the resolver's lower tiers (~/.microsandbox/bin/msb, PATH) still
/// work as fallbacks.
///
/// # Safety
/// `path` must be either null or a valid null-terminated UTF-8 C string
/// owned by the caller for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_set_sdk_msb_path(path: *const c_char) {
    if path.is_null() {
        return;
    }
    if let Ok(s) = unsafe { CStr::from_ptr(path) }.to_str() {
        microsandbox::config::set_sdk_msb_path(s);
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
pub unsafe extern "C" fn msb_cancel_alloc() -> u64 {
    let id = NEXT_CANCEL_ID.fetch_add(1, Ordering::Relaxed);
    cancel_register(id);
    id
}

/// Trigger cancellation for the given id. Safe to call multiple times or
/// after msb_cancel_unregister (no-op in those cases).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_cancel_trigger(id: u64) {
    cancel_trigger(id);
}

/// Remove the token for `id`. Called by Go after the blocking goroutine
/// returns, regardless of whether cancellation was triggered.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_cancel_unregister(id: u64) {
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
    /// Single protocol shorthand. Mutually compatible with `protocols`;
    /// when both are set the union is used.
    protocol: Option<String>,
    /// Multi-protocol list. Empty matches any protocol.
    #[serde(default)]
    protocols: Vec<String>,
    /// Single port or range as a string ("443" or "8000-9000").
    /// Numeric is also accepted for backward compatibility.
    port: Option<serde_json::Value>,
    /// Multi-port list. Each entry may be a single port or a range.
    #[serde(default)]
    ports: Vec<serde_json::Value>,
}

fn default_egress() -> String {
    "egress".into()
}

/// Custom policy. Parity-aligned with Node/Python: `default_egress` and
/// `default_ingress` are the asymmetric default actions. Empty defaults to
/// deny egress / allow ingress (matching upstream `public_only`).
#[derive(serde::Deserialize, Default)]
struct CustomNetworkPolicy {
    default_egress: Option<String>,
    default_ingress: Option<String>,
    #[serde(default)]
    rules: Vec<NetworkPolicyRule>,
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
    /// Extra CA certificates to trust for upstream verification.
    #[serde(default)]
    upstream_ca_certs: Vec<String>,
}

#[derive(serde::Deserialize, Default)]
struct DnsOpts {
    rebind_protection: Option<bool>,
    #[serde(default)]
    nameservers: Vec<String>,
    query_timeout_ms: Option<u64>,
}

#[derive(serde::Deserialize, Default)]
struct NetworkOpts {
    policy: Option<String>,
    custom_policy: Option<CustomNetworkPolicy>,
    /// DNS configuration. Replaces the legacy flat `dns_rebind_protection`.
    dns: Option<DnsOpts>,
    /// Legacy alias kept for back-compat with older Go callers; merged into
    /// `dns.rebind_protection` if both are set, with `dns` winning.
    dns_rebind_protection: Option<bool>,
    /// Convenience: deny these exact domains (DNS-level).
    #[serde(default)]
    deny_domains: Vec<String>,
    /// Convenience: deny these domain suffixes (DNS-level).
    #[serde(default)]
    deny_domain_suffixes: Vec<String>,
    tls: Option<TlsOpts>,
    /// Ports nested inside network: {host_port: guest_port}.
    #[serde(default)]
    ports: HashMap<u16, u16>,
    max_connections: Option<usize>,
    /// Sandbox-wide secret violation action: "block", "block-and-log",
    /// "block-and-terminate".
    on_secret_violation: Option<String>,
    /// Trust the host's extra CA certificates inside the guest.
    trust_host_cas: Option<bool>,
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
    /// Per-network (sandbox-wide) violation action override. The Node/Python
    /// SDKs accept this as a per-secret field on `SecretEntry`; it ends up
    /// applied at the network builder level. We honour it the same way:
    /// the last seen non-null value wins.
    on_violation: Option<String>,
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

#[derive(serde::Deserialize, Default)]
struct InitOpts {
    cmd: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: Vec<(String, String)>,
}

#[derive(serde::Deserialize, Default)]
struct RegistryAuthOpts {
    username: String,
    password: String,
}

#[derive(serde::Deserialize)]
struct SandboxCreateOpts {
    image: Option<String>,
    image_fstype: Option<String>,
    snapshot: Option<String>,
    memory_mib: Option<u32>,
    cpus: Option<u8>,
    workdir: Option<String>,
    shell: Option<String>,
    env: Option<HashMap<String, String>>,
    #[serde(default)]
    detached: bool,
    hostname: Option<String>,
    user: Option<String>,
    #[serde(default)]
    replace: bool,
    /// Grace period in milliseconds between SIGTERM and SIGKILL when
    /// replacing an existing sandbox. `Some(0)` skips SIGTERM. `None`
    /// uses the Rust SDK default when `replace` is set.
    replace_with_grace_ms: Option<u64>,
    /// User-workload entrypoint override (separate from `init`, which is
    /// guest PID 1). Sent across as an array of strings.
    #[serde(default)]
    entrypoint: Vec<String>,
    /// PID-1 init handoff. Either a bare cmd string or {cmd, args, env}.
    init: Option<InitOpts>,
    /// Sandbox log level: trace/debug/info/warn/error.
    log_level: Option<String>,
    #[serde(default)]
    quiet_logs: bool,
    /// Named scripts that can be invoked via the agent.
    #[serde(default)]
    scripts: HashMap<String, String>,
    /// Image pull policy: "always", "if-missing", "never".
    pull_policy: Option<String>,
    /// Maximum sandbox lifetime in seconds (0 = unlimited).
    max_duration_secs: Option<u64>,
    /// Idle timeout in seconds (0 = unlimited).
    idle_timeout_secs: Option<u64>,
    /// Registry credentials for pulling private images.
    registry_auth: Option<RegistryAuthOpts>,
    network: Option<NetworkOpts>,
    /// Top-level ports shorthand: {host_port: guest_port} (TCP).
    #[serde(default)]
    ports: HashMap<u16, u16>,
    /// Top-level UDP ports shorthand: {host_port: guest_port}.
    #[serde(default)]
    ports_udp: HashMap<u16, u16>,
    #[serde(default)]
    secrets: Vec<SecretOpts>,
    #[serde(default)]
    patches: Vec<PatchOpts>,
    /// Volume mounts: guest_path → MountSpec.
    #[serde(default)]
    volumes: HashMap<String, MountSpec>,
}

#[derive(serde::Deserialize, Default)]
struct LogReadOpts {
    tail: Option<usize>,
    since_ms: Option<i64>,
    until_ms: Option<i64>,
    #[serde(default)]
    sources: Vec<String>,
}

#[derive(serde::Deserialize, Default)]
struct SnapshotCreateOpts {
    name: Option<String>,
    path: Option<String>,
    #[serde(default)]
    labels: HashMap<String, String>,
    #[serde(default)]
    force: bool,
    #[serde(default)]
    record_integrity: bool,
}

#[derive(serde::Deserialize, Default)]
struct SnapshotExportOpts {
    #[serde(default)]
    with_parents: bool,
    #[serde(default)]
    with_image: bool,
    #[serde(default)]
    plain_tar: bool,
}

#[derive(serde::Deserialize, Default)]
struct MountSpec {
    bind: Option<String>,
    named: Option<String>,
    #[serde(default)]
    tmpfs: bool,
    /// Mount a host disk image (.img/.qcow2/etc.).
    disk: Option<String>,
    /// Disk image format hint ("raw", "qcow2") for `disk` mounts.
    format: Option<String>,
    /// Filesystem hint ("ext4", "xfs") for `disk` mounts.
    fstype: Option<String>,
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
    use microsandbox_network::policy::{Action, Destination, Direction, NetworkPolicy, Rule};

    // Bulk DNS-level deny rules (composed up-front so any error short-
    // circuits before we touch the builder).
    let mut bulk_deny: Vec<Rule> = Vec::new();
    for d in &net.deny_domains {
        let domain = d
            .parse()
            .map_err(|e| FfiError::invalid_argument(format!("deny_domains[{d:?}]: {e}")))?;
        bulk_deny.push(Rule::deny_egress(Destination::Domain(domain)));
    }
    for s in &net.deny_domain_suffixes {
        let suffix = s
            .parse()
            .map_err(|e| FfiError::invalid_argument(format!("deny_domain_suffixes[{s:?}]: {e}")))?;
        bulk_deny.push(Rule::deny_egress(Destination::DomainSuffix(suffix)));
    }

    let mut policy_set = false;

    // Preset policy string.
    if let Some(ref preset) = net.policy {
        let mut policy = match preset.as_str() {
            "none" => NetworkPolicy::none(),
            "public_only" | "public-only" => NetworkPolicy::public_only(),
            "allow_all" | "allow-all" => NetworkPolicy::allow_all(),
            "non_local" | "non-local" => NetworkPolicy::non_local(),
            other => {
                return Err(FfiError::invalid_argument(format!(
                    "unknown network policy preset: {other}"
                )));
            }
        };
        let mut combined = bulk_deny.clone();
        combined.extend(policy.rules);
        policy.rules = combined;
        builder = builder.network(|n| n.policy(policy));
        policy_set = true;
    }

    // Custom policy.
    if let Some(ref cp) = net.custom_policy {
        let default_egress = match cp.default_egress.as_deref() {
            Some(s) => parse_action(s)?,
            None => Action::Deny,
        };
        let default_ingress = match cp.default_ingress.as_deref() {
            Some(s) => parse_action(s)?,
            None => Action::Allow,
        };

        let mut rules = bulk_deny.clone();
        for r in &cp.rules {
            let action = parse_action(&r.action)?;
            let direction = match r.direction.as_str() {
                "egress" | "outbound" => Direction::Egress,
                "ingress" | "inbound" => Direction::Ingress,
                "any" | "both" => Direction::Any,
                other => {
                    return Err(FfiError::invalid_argument(format!(
                        "unknown direction: {other}"
                    )));
                }
            };
            let destination = parse_destination(r.destination.as_deref())?;
            let protocols = parse_protocols(r.protocol.as_deref(), &r.protocols)?;
            let ports = parse_ports(r.port.as_ref(), &r.ports)?;
            rules.push(Rule {
                action,
                direction,
                destination,
                protocols,
                ports,
            });
        }
        builder = builder.network(|n| {
            n.policy(NetworkPolicy {
                default_egress,
                default_ingress,
                rules,
            })
        });
        policy_set = true;
    }

    // No preset / custom policy was specified, but legacy DNS deny entries
    // were. Use permissive defaults so the rest of the network keeps
    // working — preserves the legacy "full network minus blocked domains"
    // semantics.
    if !policy_set && !bulk_deny.is_empty() {
        let policy = NetworkPolicy {
            default_egress: Action::Allow,
            default_ingress: Action::Allow,
            rules: bulk_deny,
        };
        builder = builder.network(|n| n.policy(policy));
    }

    // DNS configuration. Either nested `dns: {...}` or the legacy flat
    // `dns_rebind_protection` field. The nested form wins.
    let dns_rebind = net
        .dns
        .as_ref()
        .and_then(|d| d.rebind_protection)
        .or(net.dns_rebind_protection);
    let dns_nameservers: Vec<String> = net
        .dns
        .as_ref()
        .map(|d| d.nameservers.clone())
        .unwrap_or_default();
    let dns_query_timeout = net.dns.as_ref().and_then(|d| d.query_timeout_ms);
    if dns_rebind.is_some() || !dns_nameservers.is_empty() || dns_query_timeout.is_some() {
        // Resolve nameservers eagerly so a parse error surfaces here, not
        // inside the builder closure.
        let nameservers: Vec<microsandbox_network::dns::Nameserver> = dns_nameservers
            .iter()
            .map(|s| s.parse::<microsandbox_network::dns::Nameserver>())
            .collect::<Result<_, _>>()
            .map_err(|e| FfiError::invalid_argument(format!("invalid nameserver: {e}")))?;
        builder = builder.network(move |n| {
            n.dns(move |mut d| {
                if let Some(r) = dns_rebind {
                    d = d.rebind_protection(r);
                }
                if !nameservers.is_empty() {
                    d = d.nameservers(nameservers);
                }
                if let Some(ms) = dns_query_timeout {
                    d = d.query_timeout_ms(ms);
                }
                d
            })
        });
    }

    // TLS.
    if let Some(ref tls) = net.tls {
        let bypass = tls.bypass.clone();
        let verify_upstream = tls.verify_upstream;
        let intercepted_ports = tls.intercepted_ports.clone();
        let block_quic = tls.block_quic;
        let ca_cert = tls.ca_cert.clone();
        let ca_key = tls.ca_key.clone();
        let upstream_ca = tls.upstream_ca_certs.clone();
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
                for path in &upstream_ca {
                    t = t.upstream_ca_cert(path);
                }
                t
            })
        });
    }

    // Connection ceiling.
    if let Some(max) = net.max_connections {
        builder = builder.network(move |n| n.max_connections(max));
    }

    // Trust host CA bundles inside the guest.
    if let Some(trust) = net.trust_host_cas {
        builder = builder.network(move |n| n.trust_host_cas(trust));
    }

    // Sandbox-wide secret violation action.
    if let Some(ref violation) = net.on_secret_violation {
        let action = parse_violation_action(violation)?;
        builder = builder.network(move |n| n.on_secret_violation(action));
    }

    // Ports nested inside network object.
    for (host, guest) in &net.ports {
        builder = builder.port(*host, *guest);
    }

    Ok(builder)
}

/// Resolve a JSON destination string into the typed enum. Supports the
/// same forms as the Node and Python SDKs.
fn parse_destination(
    s: Option<&str>,
) -> Result<microsandbox_network::policy::Destination, FfiError> {
    use microsandbox_network::policy::{Destination, DestinationGroup};
    Ok(match s {
        None | Some("*") => Destination::Any,
        Some("public") => Destination::Group(DestinationGroup::Public),
        Some("loopback") => Destination::Group(DestinationGroup::Loopback),
        Some("private") => Destination::Group(DestinationGroup::Private),
        Some("link-local") | Some("link_local") => Destination::Group(DestinationGroup::LinkLocal),
        Some("metadata") => Destination::Group(DestinationGroup::Metadata),
        Some("multicast") => Destination::Group(DestinationGroup::Multicast),
        Some("host") => Destination::Group(DestinationGroup::Host),
        Some(s) if s.starts_with('.') => {
            let name = s.parse().map_err(|e| {
                FfiError::invalid_argument(format!("invalid domain suffix {s:?}: {e}"))
            })?;
            Destination::DomainSuffix(name)
        }
        Some(s) if s.contains('/') => {
            let cidr: ipnetwork::IpNetwork = s
                .parse()
                .map_err(|e| FfiError::invalid_argument(format!("invalid CIDR {s:?}: {e}")))?;
            Destination::Cidr(cidr)
        }
        Some(s) => {
            let name = s
                .parse()
                .map_err(|e| FfiError::invalid_argument(format!("invalid domain {s:?}: {e}")))?;
            Destination::Domain(name)
        }
    })
}

/// Merge a single `protocol` shorthand and a `protocols` list into a
/// dedup'd Vec (empty = any).
fn parse_protocols(
    single: Option<&str>,
    list: &[String],
) -> Result<Vec<microsandbox_network::policy::Protocol>, FfiError> {
    let mut out: Vec<microsandbox_network::policy::Protocol> = Vec::new();
    if let Some(s) = single {
        out.push(parse_protocol(s)?);
    }
    for s in list {
        let p = parse_protocol(s)?;
        if !out.contains(&p) {
            out.push(p);
        }
    }
    Ok(out)
}

/// Parse a single port or port range into the typed Vec representation.
/// Accepts numbers, `"443"`, or `"8000-9000"`. Empty Vec = any.
fn parse_ports(
    single: Option<&serde_json::Value>,
    list: &[serde_json::Value],
) -> Result<Vec<microsandbox_network::policy::PortRange>, FfiError> {
    let mut out: Vec<microsandbox_network::policy::PortRange> = Vec::new();
    if let Some(v) = single {
        out.push(parse_port_value(v)?);
    }
    for v in list {
        out.push(parse_port_value(v)?);
    }
    Ok(out)
}

fn parse_port_value(
    v: &serde_json::Value,
) -> Result<microsandbox_network::policy::PortRange, FfiError> {
    use microsandbox_network::policy::PortRange;
    match v {
        serde_json::Value::Number(n) => {
            let p = n
                .as_u64()
                .and_then(|p| u16::try_from(p).ok())
                .ok_or_else(|| FfiError::invalid_argument(format!("port out of range: {n}")))?;
            Ok(PortRange { start: p, end: p })
        }
        serde_json::Value::String(s) => parse_port_string(s),
        other => Err(FfiError::invalid_argument(format!(
            "port must be number or string, got {other}"
        ))),
    }
}

fn parse_port_string(s: &str) -> Result<microsandbox_network::policy::PortRange, FfiError> {
    use microsandbox_network::policy::PortRange;
    if let Some((lo, hi)) = s.split_once('-') {
        let start: u16 = lo
            .trim()
            .parse()
            .map_err(|e| FfiError::invalid_argument(format!("invalid port range {s:?}: {e}")))?;
        let end: u16 = hi
            .trim()
            .parse()
            .map_err(|e| FfiError::invalid_argument(format!("invalid port range {s:?}: {e}")))?;
        if start > end {
            return Err(FfiError::invalid_argument(format!(
                "port range start > end: {s:?}"
            )));
        }
        Ok(PortRange { start, end })
    } else {
        let p: u16 = s
            .trim()
            .parse()
            .map_err(|e| FfiError::invalid_argument(format!("invalid port {s:?}: {e}")))?;
        Ok(PortRange { start: p, end: p })
    }
}

fn parse_violation_action(s: &str) -> Result<ViolationAction, FfiError> {
    match s {
        "block" => Ok(ViolationAction::Block),
        "block-and-log" | "block_and_log" => Ok(ViolationAction::BlockAndLog),
        "block-and-terminate" | "block_and_terminate" => Ok(ViolationAction::BlockAndTerminate),
        other => Err(FfiError::invalid_argument(format!(
            "unknown violation action: {other}"
        ))),
    }
}

fn parse_log_level(s: &str) -> Result<LogLevel, FfiError> {
    match s.to_ascii_lowercase().as_str() {
        "trace" => Ok(LogLevel::Trace),
        "debug" => Ok(LogLevel::Debug),
        "info" => Ok(LogLevel::Info),
        "warn" => Ok(LogLevel::Warn),
        "error" => Ok(LogLevel::Error),
        other => Err(FfiError::invalid_argument(format!(
            "unknown log level: {other}"
        ))),
    }
}

fn parse_pull_policy(s: &str) -> Result<PullPolicy, FfiError> {
    match s {
        "always" => Ok(PullPolicy::Always),
        "if-missing" | "if_missing" => Ok(PullPolicy::IfMissing),
        "never" => Ok(PullPolicy::Never),
        other => Err(FfiError::invalid_argument(format!(
            "unknown pull policy: {other}"
        ))),
    }
}

fn apply_secret(
    mut builder: microsandbox::sandbox::SandboxBuilder,
    s: &SecretOpts,
) -> Result<microsandbox::sandbox::SandboxBuilder, FfiError> {
    let env_var = s.env_var.clone();
    let value = s.value.clone();
    let allow_hosts = s.allow_hosts.clone();
    let allow_host_patterns = s.allow_host_patterns.clone();
    let placeholder = s.placeholder.clone();
    let require_tls = s.require_tls;
    builder = builder.secret(move |mut sb| {
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
    });
    if let Some(ref violation) = s.on_violation {
        let action = parse_violation_action(violation)?;
        builder = builder.network(move |n| n.on_secret_violation(action));
    }
    Ok(builder)
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
        "mkdir" => Patch::Mkdir {
            path: require_path()?,
            mode: p.mode,
        },
        "remove" => Patch::Remove {
            path: require_path()?,
        },
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
    // Disk mounts have additional fields that need to be parsed before
    // entering the closure (so `?` works cleanly on the format string).
    let disk_format = if let Some(ref f) = m.format {
        Some(
            f.parse::<microsandbox::sandbox::DiskImageFormat>()
                .map_err(|e| {
                    FfiError::invalid_argument(format!("invalid disk format {f:?}: {e}"))
                })?,
        )
    } else {
        None
    };

    let bind = m.bind.clone();
    let named = m.named.clone();
    let tmpfs = m.tmpfs;
    let disk = m.disk.clone();
    let fstype = m.fstype.clone();
    let readonly = m.readonly;
    let size_mib = m.size_mib;

    let kinds_set: u8 =
        bind.is_some() as u8 + named.is_some() as u8 + tmpfs as u8 + disk.is_some() as u8;
    if kinds_set > 1 {
        return Err(FfiError::invalid_argument(
            "mount must specify exactly one of: bind, named, tmpfs, disk",
        ));
    }

    Ok(builder.volume(guest_path, move |mb| {
        let mut mb = if let Some(ref host) = bind {
            mb.bind(host)
        } else if let Some(ref name) = named {
            mb.named(name)
        } else if tmpfs {
            mb.tmpfs()
        } else if let Some(ref host) = disk {
            mb.disk(host)
        } else {
            mb
        };
        if let Some(format) = disk_format {
            mb = mb.format(format);
        }
        if let Some(ref ft) = fstype {
            mb = mb.fstype(ft);
        }
        if readonly {
            mb = mb.readonly();
        }
        if let Some(siz) = size_mib {
            mb = mb.size(siz);
        }
        mb
    }))
}

fn parse_action(s: &str) -> Result<microsandbox_network::policy::Action, FfiError> {
    match s {
        "allow" => Ok(microsandbox_network::policy::Action::Allow),
        "deny" => Ok(microsandbox_network::policy::Action::Deny),
        other => Err(FfiError::invalid_argument(format!(
            "unknown action: {other}"
        ))),
    }
}

fn parse_protocol(s: &str) -> Result<microsandbox_network::policy::Protocol, FfiError> {
    match s {
        "tcp" => Ok(microsandbox_network::policy::Protocol::Tcp),
        "udp" => Ok(microsandbox_network::policy::Protocol::Udp),
        "icmpv4" => Ok(microsandbox_network::policy::Protocol::Icmpv4),
        "icmpv6" => Ok(microsandbox_network::policy::Protocol::Icmpv6),
        other => Err(FfiError::invalid_argument(format!(
            "unknown protocol: {other}"
        ))),
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
pub unsafe extern "C" fn msb_sandbox_create(
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

        // Pre-parse pull policy / log level / violation action so any error
        // surfaces from the synchronous prologue, not inside the async block.
        let pull_policy = match opts.pull_policy.as_deref() {
            Some(s) => Some(parse_pull_policy(s)?),
            None => None,
        };
        let log_level = match opts.log_level.as_deref() {
            Some(s) => Some(parse_log_level(s)?),
            None => None,
        };

        Ok(Box::pin(async move {
            let mut builder = Sandbox::builder(&name);
            if opts.image.is_some() && opts.snapshot.is_some() {
                return Err(FfiError::invalid_argument(
                    "image and snapshot are mutually exclusive",
                ));
            }
            if let Some(img) = opts.image {
                if let Some(fstype) = opts.image_fstype {
                    builder = builder.image_with(|i| i.disk(img).fstype(fstype));
                } else {
                    builder = builder.image(img.as_str());
                }
            }
            if let Some(snapshot) = opts.snapshot {
                builder = builder.from_snapshot(snapshot);
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
            if let Some(s) = opts.shell {
                builder = builder.shell(s);
            }
            if let Some(h) = opts.hostname {
                builder = builder.hostname(h);
            }
            if let Some(u) = opts.user {
                builder = builder.user(u);
            }
            if let Some(grace_ms) = opts.replace_with_grace_ms {
                builder = builder.replace_with_grace(std::time::Duration::from_millis(grace_ms));
            } else if opts.replace {
                builder = builder.replace();
            }
            if !opts.entrypoint.is_empty() {
                builder = builder.entrypoint(opts.entrypoint);
            }
            if let Some(init) = opts.init {
                let args = init.args;
                let env = init.env;
                builder = builder.init_with(init.cmd, |i| i.args(args).envs(env));
            }
            if let Some(level) = log_level {
                builder = builder.log_level(level);
            }
            if opts.quiet_logs {
                builder = builder.quiet_logs();
            }
            for (k, v) in opts.scripts {
                builder = builder.script(k, v);
            }
            if let Some(policy) = pull_policy {
                builder = builder.pull_policy(policy);
            }
            if let Some(secs) = opts.max_duration_secs
                && secs > 0
            {
                builder = builder.max_duration(secs);
            }
            if let Some(secs) = opts.idle_timeout_secs
                && secs > 0
            {
                builder = builder.idle_timeout(secs);
            }
            if let Some(auth) = opts.registry_auth {
                builder = builder.registry(|r| {
                    r.auth(RegistryAuth::Basic {
                        username: auth.username,
                        password: auth.password,
                    })
                });
            }
            for (k, v) in opts.env.unwrap_or_default() {
                builder = builder.env(k, v);
            }
            // Top-level ports.
            for (host, guest) in &opts.ports {
                builder = builder.port(*host, *guest);
            }
            for (host, guest) in &opts.ports_udp {
                builder = builder.port_udp(*host, *guest);
            }
            // Network (policy, DNS, TLS, ports-in-network).
            if let Some(ref net) = opts.network {
                builder = apply_network(builder, net)?;
            }
            // Secrets.
            for s in &opts.secrets {
                builder = apply_secret(builder, s)?;
            }
            // Patches.
            for p in &opts.patches {
                builder = apply_patch(builder, p)?;
            }
            // Volume mounts.
            for (guest_path, mount) in &opts.volumes {
                builder = apply_volume(builder, guest_path, mount)?;
            }

            let sandbox = if opts.detached {
                builder.create_detached().await?
            } else {
                builder.create().await?
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
pub unsafe extern "C" fn msb_sandbox_lookup(
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
pub unsafe extern "C" fn msb_sandbox_connect(
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
pub unsafe extern "C" fn msb_sandbox_start(
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
pub unsafe extern "C" fn msb_sandbox_handle_stop(
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
pub unsafe extern "C" fn msb_sandbox_handle_kill(
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
pub unsafe extern "C" fn msb_sandbox_close(
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
pub unsafe extern "C" fn msb_sandbox_detach(
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
pub unsafe extern "C" fn msb_sandbox_stop(
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
pub unsafe extern "C" fn msb_sandbox_stop_and_wait(
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
pub unsafe extern "C" fn msb_sandbox_kill(
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
pub unsafe extern "C" fn msb_sandbox_drain(
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
pub unsafe extern "C" fn msb_sandbox_wait(
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
pub unsafe extern "C" fn msb_sandbox_owns_lifecycle(
    handle: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run(buf, buf_len, || {
        let owns = registry()
            .read()
            .map(|r| {
                r.get(&handle)
                    .map(|sb| sb.owns_lifecycle())
                    .unwrap_or(false)
            })
            .unwrap_or(false);
        let json = if owns {
            r#"{"owns":true}"#
        } else {
            r#"{"owns":false}"#
        };
        Ok(json.into())
    })
}

// ---------------------------------------------------------------------------
// Sandbox — list (by name; no handles are allocated here)
// Output: ["name1","name2",...]
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_sandbox_list(
    cancel_id: u64,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        Ok(Box::pin(async move {
            let handles = Sandbox::list().await.map_err(FfiError::from)?;
            let mut out = String::from("[");
            for (i, h) in handles.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&sandbox_handle_json(h));
            }
            out.push(']');
            Ok(out)
        }))
    })
}

/// Serialise a `SandboxHandle` into the public JSON shape, matching what
/// `msb_sandbox_lookup` returns for a single handle.
fn sandbox_handle_json(h: &microsandbox::sandbox::SandboxHandle) -> String {
    let name_json = serde_json::to_string(h.name()).unwrap_or_else(|_| "\"\"".into());
    let cfg_json = serde_json::to_string(h.config_json()).unwrap_or_else(|_| "\"\"".into());
    let created = match h.created_at() {
        Some(dt) => format!("{}", dt.timestamp()),
        None => "null".to_string(),
    };
    let updated = match h.updated_at() {
        Some(dt) => format!("{}", dt.timestamp()),
        None => "null".to_string(),
    };
    format!(
        r#"{{"name":{name},"status":"{status}","config_json":{config},"created_at_unix":{created},"updated_at_unix":{updated}}}"#,
        name = name_json,
        status = sandbox_status_str(h.status()),
        config = cfg_json,
    )
}

fn parse_log_source(s: &str) -> Result<LogSource, FfiError> {
    match s {
        "stdout" => Ok(LogSource::Stdout),
        "stderr" => Ok(LogSource::Stderr),
        "output" => Ok(LogSource::Output),
        "system" => Ok(LogSource::System),
        other => Err(FfiError::invalid_argument(format!(
            "invalid log source: {other}"
        ))),
    }
}

fn log_source_str(source: LogSource) -> &'static str {
    match source {
        LogSource::Stdout => "stdout",
        LogSource::Stderr => "stderr",
        LogSource::Output => "output",
        LogSource::System => "system",
    }
}

fn parse_log_options(opts_json: *const c_char) -> Result<LogOptions, FfiError> {
    let raw = if opts_json.is_null() {
        "{}".to_string()
    } else {
        unsafe { cstr(opts_json) }?.to_string()
    };
    let opts: LogReadOpts = serde_json::from_str(&raw)
        .map_err(|e| FfiError::invalid_argument(format!("invalid log opts JSON: {e}")))?;
    let since = opts
        .since_ms
        .map(|ms| {
            chrono::DateTime::from_timestamp_millis(ms).ok_or_else(|| {
                FfiError::invalid_argument(format!("invalid since_ms timestamp: {ms}"))
            })
        })
        .transpose()?;
    let until = opts
        .until_ms
        .map(|ms| {
            chrono::DateTime::from_timestamp_millis(ms).ok_or_else(|| {
                FfiError::invalid_argument(format!("invalid until_ms timestamp: {ms}"))
            })
        })
        .transpose()?;
    let sources = opts
        .sources
        .iter()
        .map(|s| parse_log_source(s))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(LogOptions {
        tail: opts.tail,
        since,
        until,
        sources,
    })
}

fn log_entries_json(entries: Vec<microsandbox::sandbox::LogEntry>) -> Result<String, FfiError> {
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        out.push(serde_json::json!({
            "source": log_source_str(entry.source),
            "session_id": entry.session_id,
            "timestamp_ms": entry.timestamp.timestamp_millis(),
            "data_b64": base64::engine::general_purpose::STANDARD.encode(entry.data),
        }));
    }
    serde_json::to_string(&out).map_err(|e| FfiError::internal(format!("serialise logs: {e}")))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_sandbox_logs(
    cancel_id: u64,
    handle: Handle,
    opts_json: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let opts = parse_log_options(opts_json)?;
        Ok(Box::pin(async move {
            let sb = get(handle)?;
            let entries = sb.logs(&opts).map_err(FfiError::from)?;
            log_entries_json(entries)
        }))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_sandbox_handle_logs(
    cancel_id: u64,
    name: *const c_char,
    opts_json: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let name = unsafe { cstr(name) }?.to_owned();
        let opts = parse_log_options(opts_json)?;
        Ok(Box::pin(async move {
            let entries = logs::read_logs(&name, &opts).map_err(FfiError::from)?;
            log_entries_json(entries)
        }))
    })
}

// ---------------------------------------------------------------------------
// Sandbox — remove (by name; persisted state)
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_sandbox_remove(
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
pub unsafe extern "C" fn msb_sandbox_exec(
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
pub unsafe extern "C" fn msb_sandbox_metrics(
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
pub unsafe extern "C" fn msb_fs_read(
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
pub unsafe extern "C" fn msb_fs_write(
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
pub unsafe extern "C" fn msb_fs_list(
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
pub unsafe extern "C" fn msb_fs_stat(
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
pub unsafe extern "C" fn msb_fs_copy_from_host(
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
pub unsafe extern "C" fn msb_fs_copy_to_host(
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
pub unsafe extern "C" fn msb_fs_mkdir(
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
pub unsafe extern "C" fn msb_fs_remove(
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
pub unsafe extern "C" fn msb_fs_remove_dir(
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
pub unsafe extern "C" fn msb_fs_copy(
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
pub unsafe extern "C" fn msb_fs_rename(
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
pub unsafe extern "C" fn msb_fs_exists(
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

/// Volume create options. `quota_mib == 0` means unlimited.
#[derive(serde::Deserialize, Default)]
struct VolumeCreateOpts {
    #[serde(default)]
    quota_mib: u32,
    /// Optional key-value labels.
    #[serde(default)]
    labels: HashMap<String, String>,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_volume_create(
    cancel_id: u64,
    name: *const c_char,
    opts_json: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let name = unsafe { cstr(name) }?;
        let opts: VolumeCreateOpts = if opts_json.is_null() {
            VolumeCreateOpts::default()
        } else {
            let s = unsafe { cstr(opts_json) }?;
            if s.is_empty() {
                VolumeCreateOpts::default()
            } else {
                serde_json::from_str(&s)
                    .map_err(|e| FfiError::invalid_argument(format!("invalid volume opts: {e}")))?
            }
        };
        Ok(Box::pin(async move {
            let mut b: VolumeBuilder = Volume::builder(&name);
            if opts.quota_mib > 0 {
                b = b.quota(opts.quota_mib);
            }
            for (k, v) in &opts.labels {
                b = b.label(k, v);
            }
            b.create().await.map_err(FfiError::from)?;
            Ok(volume_handle_json(
                &Volume::get(&name).await.map_err(FfiError::from)?,
            ))
        }))
    })
}

/// Serialise a `VolumeHandle` into the public JSON shape.
fn volume_handle_json(vh: &VolumeHandle) -> String {
    let quota = match vh.quota_mib() {
        Some(q) => format!("{q}"),
        None => "null".to_string(),
    };
    let created = match vh.created_at() {
        Some(dt) => format!("{}", dt.timestamp()),
        None => "null".to_string(),
    };
    // Use serde_json for the labels object so escaping is correct.
    let labels_map: HashMap<&str, &str> = vh
        .labels()
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let labels_json = serde_json::to_string(&labels_map).unwrap_or_else(|_| "{}".into());
    let path = microsandbox::config::config()
        .volumes_dir()
        .join(vh.name())
        .to_string_lossy()
        .into_owned();
    let name_json = serde_json::to_string(vh.name()).unwrap_or_else(|_| "\"\"".into());
    let path_json = serde_json::to_string(&path).unwrap_or_else(|_| "\"\"".into());
    format!(
        r#"{{"name":{name},"path":{path},"quota_mib":{quota},"used_bytes":{used},"labels":{labels},"created_at_unix":{created}}}"#,
        name = name_json,
        path = path_json,
        used = vh.used_bytes(),
        labels = labels_json,
    )
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_volume_remove(
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
pub unsafe extern "C" fn msb_volume_list(
    cancel_id: u64,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        Ok(Box::pin(async move {
            let handles = Volume::list().await.map_err(FfiError::from)?;
            let mut out = String::from("[");
            for (i, vh) in handles.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&volume_handle_json(vh));
            }
            out.push(']');
            Ok(out)
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
type MetricsStreamEntry =
    std::sync::Arc<tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<MetricsItem>>>;

fn metrics_registry() -> &'static RwLock<HashMap<Handle, MetricsStreamEntry>> {
    static REG: OnceLock<RwLock<HashMap<Handle, MetricsStreamEntry>>> = OnceLock::new();
    REG.get_or_init(|| RwLock::new(HashMap::new()))
}

fn register_metrics(
    rx: tokio::sync::mpsc::UnboundedReceiver<MetricsItem>,
) -> Result<Handle, FfiError> {
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
pub unsafe extern "C" fn msb_sandbox_metrics_stream(
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
pub unsafe extern "C" fn msb_metrics_recv(
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
pub unsafe extern "C" fn msb_metrics_close(
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

/// Start a streaming exec session. Returns `{"exec_handle":<u64>}`.
/// The exec handle MUST be released with msb_exec_close when done.
///
/// exec_opts_json: same schema as msb_sandbox_exec (args, cwd, timeout_secs).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_sandbox_exec_stream(
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
            if stdin_pipe
                && let Ok(eh) = get_exec(exec_h)
                && let Ok(mut guard) = eh.lock()
                && let Some(sink) = guard.take_stdin()
            {
                let _ = register_stdin(exec_h, sink);
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
pub unsafe extern "C" fn msb_exec_recv(
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
                        Some(ExecEvent::Failed(failure)) => {
                            // ExecFailed is a typed payload (errno/path/etc.) on
                            // upstream main; serialise it through serde so the
                            // Go side gets a stable {"event":"failed","error":...}
                            // shape. Falls back to the structured `message` field
                            // on serialisation failure so we never lose the signal.
                            let payload = serde_json::to_value(&failure).unwrap_or_else(|_| {
                                serde_json::json!({"message": failure.message})
                            });
                            serde_json::json!({"event":"failed","error":payload}).to_string()
                        }
                        Some(ExecEvent::StdinError(error)) => {
                            let payload = serde_json::to_value(&error).unwrap_or_else(|_| {
                                serde_json::json!({"message": error.message})
                            });
                            serde_json::json!({"event":"stdin_error","error":payload}).to_string()
                        }
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
pub unsafe extern "C" fn msb_exec_close(
    cancel_id: u64,
    exec_handle: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    cancel_unregister(cancel_id);
    run(buf, buf_len, || {
        remove_exec(exec_handle)?.ok_or_else(|| FfiError::invalid_handle(exec_handle))?;
        remove_stdin(exec_handle);
        Ok(r#"{"ok":true}"#.into())
    })
}

/// Return the internal protocol ID for an exec session. Synchronous.
/// Returns `{"id":"<string>"}`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_exec_id(
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
pub unsafe extern "C" fn msb_exec_signal(
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
pub unsafe extern "C" fn msb_exec_stdin_write(
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
pub unsafe extern "C" fn msb_exec_stdin_close(
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
pub unsafe extern "C" fn msb_exec_collect(
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
pub unsafe extern "C" fn msb_exec_wait(
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
pub unsafe extern "C" fn msb_exec_kill(
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
pub unsafe extern "C" fn msb_all_sandbox_metrics(
    cancel_id: u64,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        Ok(Box::pin(async move {
            let map = all_sandbox_metrics().await.map_err(FfiError::from)?;
            let mut entries = String::new();
            for (name, m) in &map {
                if !entries.is_empty() {
                    entries.push(',');
                }
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
pub unsafe extern "C" fn msb_sandbox_handle_metrics(
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
                dr = m.disk_read_bytes,
                dw = m.disk_write_bytes,
                rx = m.net_rx_bytes,
                tx = m.net_tx_bytes,
                up = m.uptime.as_secs(),
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
pub unsafe extern "C" fn msb_sandbox_remove_persisted(
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
pub unsafe extern "C" fn msb_volume_get(
    cancel_id: u64,
    name: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let name_str = unsafe { cstr(name) }?.to_owned();
        Ok(Box::pin(async move {
            let vh = Volume::get(&name_str).await.map_err(FfiError::from)?;
            Ok(volume_handle_json(&vh))
        }))
    })
}

/// Returns the upstream `microsandbox` crate version this FFI was built against.
/// Synchronous; no Rust-side state is touched. The Go SDK exposes this so callers
/// can verify the loaded library matches the expected runtime.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_version(buf: *mut c_uchar, buf_len: usize) -> *mut c_char {
    run(buf, buf_len, || {
        let v = env!("CARGO_PKG_VERSION");
        Ok(format!(r#"{{"version":"{v}"}}"#))
    })
}

// ---------------------------------------------------------------------------
// Image cache
// ---------------------------------------------------------------------------

/// Serialise an `ImageHandle` to the public JSON shape used by the Go SDK.
fn image_handle_json(h: &microsandbox::image::ImageHandle) -> serde_json::Value {
    serde_json::json!({
        "reference": h.reference(),
        "manifest_digest": h.manifest_digest(),
        "architecture": h.architecture(),
        "os": h.os(),
        "layer_count": h.layer_count(),
        "size_bytes": h.size_bytes(),
        "created_at_unix": h.created_at().map(|t| t.timestamp()),
        "last_used_at_unix": h.last_used_at().map(|t| t.timestamp()),
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_image_get(
    cancel_id: u64,
    reference: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let reference = unsafe { cstr(reference) }?;
        Ok(Box::pin(async move {
            let h = microsandbox::image::Image::get(&reference)
                .await
                .map_err(FfiError::from)?;
            Ok(image_handle_json(&h).to_string())
        }))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_image_list(
    cancel_id: u64,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        Ok(Box::pin(async move {
            let handles = microsandbox::image::Image::list()
                .await
                .map_err(FfiError::from)?;
            let arr: Vec<serde_json::Value> = handles.iter().map(image_handle_json).collect();
            Ok(serde_json::Value::Array(arr).to_string())
        }))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_image_inspect(
    cancel_id: u64,
    reference: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let reference = unsafe { cstr(reference) }?;
        Ok(Box::pin(async move {
            let detail = microsandbox::image::Image::inspect(&reference)
                .await
                .map_err(FfiError::from)?;
            let config = detail.config.as_ref().map(|c| {
                serde_json::json!({
                    "digest": c.digest,
                    "env": c.env,
                    "cmd": c.cmd,
                    "entrypoint": c.entrypoint,
                    "working_dir": c.working_dir,
                    "user": c.user,
                    "labels": c.labels,
                    "stop_signal": c.stop_signal,
                })
            });
            let layers: Vec<serde_json::Value> = detail
                .layers
                .iter()
                .map(|l| {
                    serde_json::json!({
                        "diff_id": l.diff_id,
                        "blob_digest": l.blob_digest,
                        "media_type": l.media_type,
                        "compressed_size_bytes": l.compressed_size_bytes,
                        "erofs_size_bytes": l.erofs_size_bytes,
                        "position": l.position,
                    })
                })
                .collect();
            let mut obj = image_handle_json(&detail.handle);
            if let serde_json::Value::Object(ref mut map) = obj {
                map.insert(
                    "config".to_string(),
                    config.unwrap_or(serde_json::Value::Null),
                );
                map.insert("layers".to_string(), serde_json::Value::Array(layers));
            }
            Ok(obj.to_string())
        }))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_image_remove(
    cancel_id: u64,
    reference: *const c_char,
    force: bool,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let reference = unsafe { cstr(reference) }?;
        Ok(Box::pin(async move {
            microsandbox::image::Image::remove(&reference, force)
                .await
                .map_err(FfiError::from)?;
            Ok(r#"{"ok":true}"#.into())
        }))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_image_gc_layers(
    cancel_id: u64,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        Ok(Box::pin(async move {
            let removed = microsandbox::image::Image::gc_layers()
                .await
                .map_err(FfiError::from)?;
            Ok(format!(r#"{{"removed":{removed}}}"#))
        }))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_image_gc(
    cancel_id: u64,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        Ok(Box::pin(async move {
            let removed = microsandbox::image::Image::gc()
                .await
                .map_err(FfiError::from)?;
            Ok(format!(r#"{{"removed":{removed}}}"#))
        }))
    })
}

// ---------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------

fn snapshot_format_str(f: SnapshotFormat) -> &'static str {
    match f {
        SnapshotFormat::Raw => "raw",
        SnapshotFormat::Qcow2 => "qcow2",
    }
}

fn snapshot_json(s: &Snapshot) -> serde_json::Value {
    let manifest = s.manifest();
    let labels: HashMap<String, String> = manifest
        .labels
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    serde_json::json!({
        "path": s.path().display().to_string(),
        "digest": s.digest(),
        "size_bytes": s.size_bytes(),
        "image_ref": manifest.image.reference,
        "image_manifest_digest": manifest.image.manifest_digest,
        "format": snapshot_format_str(manifest.format),
        "fstype": manifest.fstype,
        "parent": manifest.parent,
        "created_at": manifest.created_at,
        "labels": labels,
        "source_sandbox": manifest.source_sandbox,
    })
}

fn snapshot_handle_json(h: &microsandbox::SnapshotHandle) -> serde_json::Value {
    serde_json::json!({
        "digest": h.digest(),
        "name": h.name(),
        "parent_digest": h.parent_digest(),
        "image_ref": h.image_ref(),
        "format": snapshot_format_str(h.format()),
        "size_bytes": h.size_bytes(),
        "created_at_unix": h.created_at().and_utc().timestamp(),
        "path": h.path().display().to_string(),
    })
}

fn verify_report_json(report: microsandbox::snapshot::SnapshotVerifyReport) -> serde_json::Value {
    let upper = match report.upper {
        UpperVerifyStatus::NotRecorded => serde_json::json!({"kind":"not_recorded"}),
        UpperVerifyStatus::Verified { algorithm, digest } => {
            serde_json::json!({"kind":"verified","algorithm":algorithm,"digest":digest})
        }
    };
    serde_json::json!({
        "digest": report.digest,
        "path": report.path.display().to_string(),
        "upper": upper,
    })
}

fn apply_snapshot_create_opts(
    mut builder: microsandbox::SnapshotBuilder,
    opts: SnapshotCreateOpts,
) -> Result<microsandbox::SnapshotBuilder, FfiError> {
    match (opts.name, opts.path) {
        (Some(name), None) => {
            builder = builder.destination(SnapshotDestination::Name(name));
        }
        (None, Some(path)) => {
            builder = builder.destination(SnapshotDestination::Path(PathBuf::from(path)));
        }
        (Some(_), Some(_)) => {
            return Err(FfiError::invalid_argument(
                "snapshot create accepts either name or path, not both",
            ));
        }
        (None, None) => {
            return Err(FfiError::invalid_argument(
                "snapshot create requires name or path",
            ));
        }
    }
    for (k, v) in opts.labels {
        builder = builder.label(k, v);
    }
    if opts.force {
        builder = builder.force();
    }
    if opts.record_integrity {
        builder = builder.record_integrity();
    }
    Ok(builder)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_sandbox_handle_snapshot(
    cancel_id: u64,
    sandbox_name: *const c_char,
    snapshot_name: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let sandbox_name = unsafe { cstr(sandbox_name) }?;
        let snapshot_name = unsafe { cstr(snapshot_name) }?;
        Ok(Box::pin(async move {
            let h = Sandbox::get(&sandbox_name).await.map_err(FfiError::from)?;
            let snap = h.snapshot(&snapshot_name).await.map_err(FfiError::from)?;
            Ok(snapshot_json(&snap).to_string())
        }))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_sandbox_handle_snapshot_to(
    cancel_id: u64,
    sandbox_name: *const c_char,
    path: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let sandbox_name = unsafe { cstr(sandbox_name) }?;
        let path = unsafe { cstr(path) }?;
        Ok(Box::pin(async move {
            let h = Sandbox::get(&sandbox_name).await.map_err(FfiError::from)?;
            let snap = h
                .snapshot_to(PathBuf::from(path))
                .await
                .map_err(FfiError::from)?;
            Ok(snapshot_json(&snap).to_string())
        }))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_snapshot_create(
    cancel_id: u64,
    source_sandbox: *const c_char,
    opts_json: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let source_sandbox = unsafe { cstr(source_sandbox) }?;
        let opts_raw = unsafe { cstr(opts_json) }?;
        let opts: SnapshotCreateOpts = serde_json::from_str(&opts_raw)
            .map_err(|e| FfiError::invalid_argument(format!("invalid opts JSON: {e}")))?;
        let builder = apply_snapshot_create_opts(Snapshot::builder(&source_sandbox), opts)?;
        Ok(Box::pin(async move {
            let snap = builder.create().await.map_err(FfiError::from)?;
            Ok(snapshot_json(&snap).to_string())
        }))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_snapshot_open(
    cancel_id: u64,
    path_or_name: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let path_or_name = unsafe { cstr(path_or_name) }?;
        Ok(Box::pin(async move {
            let snap = Snapshot::open(&path_or_name)
                .await
                .map_err(FfiError::from)?;
            Ok(snapshot_json(&snap).to_string())
        }))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_snapshot_verify(
    cancel_id: u64,
    path_or_name: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let path_or_name = unsafe { cstr(path_or_name) }?;
        Ok(Box::pin(async move {
            let snap = Snapshot::open(&path_or_name)
                .await
                .map_err(FfiError::from)?;
            let report = snap.verify().await.map_err(FfiError::from)?;
            Ok(verify_report_json(report).to_string())
        }))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_snapshot_get(
    cancel_id: u64,
    name_or_digest: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let name_or_digest = unsafe { cstr(name_or_digest) }?;
        Ok(Box::pin(async move {
            let h = Snapshot::get(&name_or_digest)
                .await
                .map_err(FfiError::from)?;
            Ok(snapshot_handle_json(&h).to_string())
        }))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_snapshot_list(
    cancel_id: u64,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        Ok(Box::pin(async move {
            let handles = Snapshot::list().await.map_err(FfiError::from)?;
            let arr: Vec<serde_json::Value> = handles.iter().map(snapshot_handle_json).collect();
            Ok(serde_json::Value::Array(arr).to_string())
        }))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_snapshot_list_dir(
    cancel_id: u64,
    dir: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let dir = unsafe { cstr(dir) }?;
        Ok(Box::pin(async move {
            let snaps = Snapshot::list_dir(PathBuf::from(dir))
                .await
                .map_err(FfiError::from)?;
            let arr: Vec<serde_json::Value> = snaps.iter().map(snapshot_json).collect();
            Ok(serde_json::Value::Array(arr).to_string())
        }))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_snapshot_remove(
    cancel_id: u64,
    path_or_name: *const c_char,
    force: bool,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let path_or_name = unsafe { cstr(path_or_name) }?;
        Ok(Box::pin(async move {
            Snapshot::remove(&path_or_name, force)
                .await
                .map_err(FfiError::from)?;
            Ok(r#"{"ok":true}"#.into())
        }))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_snapshot_reindex(
    cancel_id: u64,
    dir: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let dir = unsafe { cstr(dir) }?;
        Ok(Box::pin(async move {
            let indexed = Snapshot::reindex(PathBuf::from(dir))
                .await
                .map_err(FfiError::from)?;
            Ok(format!(r#"{{"indexed":{indexed}}}"#))
        }))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_snapshot_export(
    cancel_id: u64,
    name_or_path: *const c_char,
    out: *const c_char,
    opts_json: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let name_or_path = unsafe { cstr(name_or_path) }?;
        let out = unsafe { cstr(out) }?;
        let opts_raw = unsafe { cstr(opts_json) }?;
        let opts: SnapshotExportOpts = serde_json::from_str(&opts_raw)
            .map_err(|e| FfiError::invalid_argument(format!("invalid opts JSON: {e}")))?;
        Ok(Box::pin(async move {
            Snapshot::export(
                &name_or_path,
                &PathBuf::from(out),
                ExportOpts {
                    with_parents: opts.with_parents,
                    with_image: opts.with_image,
                    plain_tar: opts.plain_tar,
                },
            )
            .await
            .map_err(FfiError::from)?;
            Ok(r#"{"ok":true}"#.into())
        }))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_snapshot_import(
    cancel_id: u64,
    archive: *const c_char,
    dest: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let archive = unsafe { cstr(archive) }?;
        let dest = unsafe { cstr(dest) }?;
        let dest = if dest.is_empty() {
            None
        } else {
            Some(PathBuf::from(dest))
        };
        Ok(Box::pin(async move {
            let h = Snapshot::import(&PathBuf::from(archive), dest.as_deref())
                .await
                .map_err(FfiError::from)?;
            Ok(snapshot_handle_json(&h).to_string())
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
pub unsafe extern "C" fn msb_fs_read_stream(
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
            let stream = sb
                .fs()
                .read_stream(&path_str)
                .await
                .map_err(FfiError::from)?;
            let sh = register_fs_read(stream)?;
            Ok(format!(r#"{{"stream_handle":{sh}}}"#))
        }))
    })
}

/// Receive the next chunk from a read stream.
/// Returns `{"done":true}` at EOF, or `{"chunk_b64":"..."}` with data.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_fs_read_stream_recv(
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
pub unsafe extern "C" fn msb_fs_read_stream_close(
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
pub unsafe extern "C" fn msb_fs_write_stream(
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
            let sink = sb
                .fs()
                .write_stream(&path_str)
                .await
                .map_err(FfiError::from)?;
            let sh = register_fs_write(sink)?;
            Ok(format!(r#"{{"stream_handle":{sh}}}"#))
        }))
    })
}

/// Write a base64-encoded chunk to a write stream. Returns `{"ok":true}`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_fs_write_stream_write(
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
        let sink = guard
            .as_ref()
            .ok_or_else(|| FfiError::internal("write stream already closed"))?;
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
pub unsafe extern "C" fn msb_fs_write_stream_close(
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
        let sink = guard
            .take()
            .ok_or_else(|| FfiError::internal("write stream already closed"))?;
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
pub unsafe extern "C" fn msb_sandbox_attach(
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
            serde_json::from_str(&s)
                .map_err(|e| FfiError::invalid_argument(format!("attach opts: {e}")))?
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
pub unsafe extern "C" fn msb_sandbox_attach_shell(
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

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
use microsandbox::{MicrosandboxError, Sandbox, sandbox::FsEntryKind, volume::Volume};
use tokio::runtime::Runtime;

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

static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

fn registry() -> &'static RwLock<HashMap<Handle, std::sync::Arc<Sandbox>>> {
    static REG: OnceLock<RwLock<HashMap<Handle, std::sync::Arc<Sandbox>>>> = OnceLock::new();
    REG.get_or_init(|| RwLock::new(HashMap::new()))
}

fn register(sandbox: Sandbox) -> Handle {
    let h = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    registry()
        .write()
        .expect("registry poisoned")
        .insert(h, std::sync::Arc::new(sandbox));
    h
}

fn get(handle: Handle) -> Result<std::sync::Arc<Sandbox>, FfiError> {
    registry()
        .read()
        .expect("registry poisoned")
        .get(&handle)
        .cloned()
        .ok_or_else(|| FfiError::invalid_handle(handle))
}

fn remove(handle: Handle) -> Option<std::sync::Arc<Sandbox>> {
    registry()
        .write()
        .expect("registry poisoned")
        .remove(&handle)
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
fn err_ptr(err: FfiError) -> *mut c_char {
    let json = err.to_json();
    CString::new(json)
        .unwrap_or_else(|_| CString::new(r#"{"kind":"internal","message":"malformed error"}"#).unwrap())
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
// Sandbox — create
//
// Input:
//   name: null-terminated C string, owned by caller (Go), borrowed for call.
//   opts_json: JSON object with optional fields (image, memory_mib, cpus,
//     workdir, env). Owned by caller, borrowed for call.
// Output on success: {"handle": <u64>}
// The caller MUST eventually call `msb_sandbox_close(handle)` to release.
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct SandboxCreateOpts {
    image: Option<String>,
    memory_mib: Option<u32>,
    cpus: Option<u8>,
    workdir: Option<String>,
    env: Option<HashMap<String, String>>,
}

#[unsafe(no_mangle)]
pub extern "C" fn msb_sandbox_create(
    name: *const c_char,
    opts_json: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run(buf, buf_len, || {
        let name = unsafe { cstr(name) }?;
        let opts_raw = unsafe { cstr(opts_json) }?;
        let opts: SandboxCreateOpts = serde_json::from_str(&opts_raw)
            .map_err(|e| FfiError::invalid_argument(format!("invalid opts JSON: {e}")))?;

        let handle = rt().block_on(async move {
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
            let config = builder.build()?;
            let sandbox = Sandbox::create(config).await?;
            Ok::<_, FfiError>(register(sandbox))
        })?;

        Ok(format!(r#"{{"handle":{handle}}}"#))
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
    name: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run(buf, buf_len, || {
        let name = unsafe { cstr(name) }?;
        let handle = rt().block_on(async move {
            let sb = Sandbox::get(&name).await?.connect().await?;
            Ok::<_, FfiError>(register(sb))
        })?;
        Ok(format!(r#"{{"handle":{handle}}}"#))
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
    handle: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run(buf, buf_len, || {
        let sb = remove(handle).ok_or_else(|| FfiError::invalid_handle(handle))?;
        // Ensure the Arc is uniquely held so the Drop side-effects (if any)
        // run synchronously here; if another FFI call is in-flight with the
        // same handle the drop happens when that call finishes.
        drop(sb);
        Ok(r#"{"ok":true}"#.into())
    })
}

// ---------------------------------------------------------------------------
// Sandbox — stop (graceful) and stop_and_wait
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn msb_sandbox_stop(
    handle: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run(buf, buf_len, || {
        let sb = get(handle)?;
        rt().block_on(async move { sb.stop().await.map_err(FfiError::from) })?;
        Ok(r#"{"ok":true}"#.into())
    })
}

/// Stop and wait for full shutdown. Returns `{"exit_code": <int|null>}`.
#[unsafe(no_mangle)]
pub extern "C" fn msb_sandbox_stop_and_wait(
    handle: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run(buf, buf_len, || {
        let sb = get(handle)?;
        let status =
            rt().block_on(async move { sb.stop_and_wait().await.map_err(FfiError::from) })?;
        let code = status
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "null".into());
        Ok(format!(r#"{{"exit_code":{code}}}"#))
    })
}

/// Kill the sandbox immediately (SIGKILL on the VM process).
#[unsafe(no_mangle)]
pub extern "C" fn msb_sandbox_kill(
    handle: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run(buf, buf_len, || {
        let sb = get(handle)?;
        rt().block_on(async move {
            // kill() takes &self on Sandbox (we Arc-wrapped it).
            sb.kill().await.map_err(FfiError::from)
        })?;
        Ok(r#"{"ok":true}"#.into())
    })
}

// ---------------------------------------------------------------------------
// Sandbox — list (by name; no handles are allocated here)
// Output: ["name1","name2",...]
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn msb_sandbox_list(buf: *mut c_uchar, buf_len: usize) -> *mut c_char {
    run(buf, buf_len, || {
        let handles = rt().block_on(async { Sandbox::list().await.map_err(FfiError::from) })?;
        let names: Vec<&str> = handles.iter().map(|h| h.name()).collect();
        serde_json::to_string(&names).map_err(|e| FfiError::internal(e.to_string()))
    })
}

// ---------------------------------------------------------------------------
// Sandbox — remove (by name; persisted state)
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn msb_sandbox_remove(
    name: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run(buf, buf_len, || {
        let name = unsafe { cstr(name) }?;
        rt().block_on(async move { Sandbox::remove(&name).await.map_err(FfiError::from) })?;
        Ok(r#"{"ok":true}"#.into())
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
    handle: Handle,
    cmd: *const c_char,
    exec_opts_json: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run(buf, buf_len, || {
        let sb = get(handle)?;
        let cmd = unsafe { cstr(cmd) }?;
        let opts_raw = unsafe { cstr(exec_opts_json) }?;
        let opts: ExecOpts = serde_json::from_str(&opts_raw)
            .map_err(|e| FfiError::invalid_argument(format!("invalid exec opts: {e}")))?;

        let output = rt().block_on(async move {
            sb.exec_with(&cmd, |mut b| {
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
            .map_err(FfiError::from)
        })?;

        let stdout = output.stdout().unwrap_or_default();
        let stderr = output.stderr().unwrap_or_default();
        let exit_code = output.status().code;
        Ok(serde_json::json!({
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
        })
        .to_string())
    })
}

// ---------------------------------------------------------------------------
// Sandbox — metrics
// Output: {cpu_percent,memory_bytes,memory_limit_bytes,disk_*,net_*,uptime_secs}
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn msb_sandbox_metrics(
    handle: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run(buf, buf_len, || {
        let sb = get(handle)?;
        // Metrics live on SandboxHandle, reachable via name().
        let name = sb.name().to_string();
        let m = rt().block_on(async move {
            let h = Sandbox::get(&name).await?;
            h.metrics().await.map_err(FfiError::from)
        })?;
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
    })
}

// ---------------------------------------------------------------------------
// Filesystem
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn msb_fs_read(
    handle: Handle,
    path: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run(buf, buf_len, || {
        let sb = get(handle)?;
        let path = unsafe { cstr(path) }?;
        let bytes = rt().block_on(async move { sb.fs().read(&path).await.map_err(FfiError::from) })?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
        Ok(format!(r#"{{"data":"{b64}"}}"#))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn msb_fs_write(
    handle: Handle,
    path: *const c_char,
    data_b64: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run(buf, buf_len, || {
        let sb = get(handle)?;
        let path = unsafe { cstr(path) }?;
        let data_b64 = unsafe { cstr(data_b64) }?;
        let data = base64::engine::general_purpose::STANDARD
            .decode(data_b64.as_bytes())
            .map_err(|e| FfiError::invalid_argument(format!("base64 decode: {e}")))?;
        rt().block_on(async move {
            sb.fs().write(&path, data).await.map_err(FfiError::from)
        })?;
        Ok(r#"{"ok":true}"#.into())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn msb_fs_list(
    handle: Handle,
    path: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run(buf, buf_len, || {
        let sb = get(handle)?;
        let path = unsafe { cstr(path) }?;
        let entries =
            rt().block_on(async move { sb.fs().list(&path).await.map_err(FfiError::from) })?;
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
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn msb_fs_stat(
    handle: Handle,
    path: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run(buf, buf_len, || {
        let sb = get(handle)?;
        let path = unsafe { cstr(path) }?;
        let m = rt().block_on(async move { sb.fs().stat(&path).await.map_err(FfiError::from) })?;
        Ok(serde_json::json!({
            "kind": kind_str(m.kind),
            "size": m.size,
            "mode": m.mode,
            "readonly": m.readonly,
            "modified_unix": m.modified.map(|t| t.timestamp()),
        })
        .to_string())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn msb_fs_copy_from_host(
    handle: Handle,
    host_path: *const c_char,
    guest_path: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run(buf, buf_len, || {
        let sb = get(handle)?;
        let host_path = unsafe { cstr(host_path) }?;
        let guest_path = unsafe { cstr(guest_path) }?;
        rt().block_on(async move {
            sb.fs()
                .copy_from_host(&host_path, &guest_path)
                .await
                .map_err(FfiError::from)
        })?;
        Ok(r#"{"ok":true}"#.into())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn msb_fs_copy_to_host(
    handle: Handle,
    guest_path: *const c_char,
    host_path: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run(buf, buf_len, || {
        let sb = get(handle)?;
        let guest_path = unsafe { cstr(guest_path) }?;
        let host_path = unsafe { cstr(host_path) }?;
        rt().block_on(async move {
            sb.fs()
                .copy_to_host(&guest_path, &host_path)
                .await
                .map_err(FfiError::from)
        })?;
        Ok(r#"{"ok":true}"#.into())
    })
}

// ---------------------------------------------------------------------------
// Volumes — name-addressed; no handles.
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn msb_volume_create(
    name: *const c_char,
    quota_mib: u32,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run(buf, buf_len, || {
        let name = unsafe { cstr(name) }?;
        rt().block_on(async move {
            let mut b = Volume::builder(&name);
            if quota_mib > 0 {
                b = b.quota(quota_mib);
            }
            b.create().await.map_err(FfiError::from)
        })?;
        Ok(r#"{"ok":true}"#.into())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn msb_volume_remove(
    name: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run(buf, buf_len, || {
        let name = unsafe { cstr(name) }?;
        rt().block_on(async move { Volume::remove(&name).await.map_err(FfiError::from) })?;
        Ok(r#"{"ok":true}"#.into())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn msb_volume_list(buf: *mut c_uchar, buf_len: usize) -> *mut c_char {
    run(buf, buf_len, || {
        let handles = rt().block_on(async { Volume::list().await.map_err(FfiError::from) })?;
        let names: Vec<&str> = handles.iter().map(|h| h.name()).collect();
        serde_json::to_string(&names).map_err(|e| FfiError::internal(e.to_string()))
    })
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

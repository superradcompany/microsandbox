// Package ffi is the CGO bridge from the Go SDK to the microsandbox Rust
// library. It is NOT stable and must not be imported from outside this module.
//
// # Architecture
//
// The library is loaded at runtime via dlopen/dlsym rather than linked at
// build time. This means `go build` succeeds with no Rust toolchain or
// pre-built library on disk — the library is downloaded on first use by
// microsandbox.EnsureInstalled.
//
// Layout of this file:
//   - C preamble: typedefs, function-pointer globals, load_microsandbox(),
//     is_microsandbox_loaded(), and call_msb_* trampolines.
//   - Go loader: Load(), IsLoaded(), ensureLoaded() — wiring the C loader
//     into idiomatic Go with sync.Once.
//   - Go FFI wrappers: one exported function per msb_* entry point.
//
// # Boundary contract
//
// Every msb_* call returns:
//   - NULL on success, writing a JSON document into the caller's buffer.
//   - A heap-allocated C string (JSON {kind,message}) on failure. The Go
//     side MUST free it with call_msb_free_string immediately after reading.
//
// Sandboxes are identified across the boundary by opaque uint64 handles
// allocated by the Rust side. Call (*Sandbox).Close to release.
//
// # Pointer ownership at the FFI boundary
//
// Go-allocated C strings (C.CString) are freed by Go with `defer C.free`.
// Rust MUST copy any string it needs before returning — it must not retain
// Go pointers across calls. Error strings returned by Rust are heap-allocated
// by Rust and freed by Go via call_msb_free_string. Output JSON is written
// into a Go-owned buffer; Rust does not retain that pointer.
//
// # Thread safety
//
// All msb_* entry points are safe to call from multiple goroutines
// concurrently. The Rust side uses an RwLock-protected handle registry and
// a multi-threaded Tokio runtime.
package ffi

/*
#cgo linux LDFLAGS: -ldl
#cgo darwin LDFLAGS:
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>

// ---------------------------------------------------------------------------
// Function pointer typedefs — one per Rust extern "C" function.
// Keep in sync with sdk/go-ffi/src/lib.rs and microsandbox_go_ffi.h.
// ---------------------------------------------------------------------------
typedef void     (*msb_free_string_fn)(char *ptr);
typedef uint64_t (*msb_cancel_alloc_fn)(void);
typedef void     (*msb_cancel_trigger_fn)(uint64_t id);
typedef void     (*msb_cancel_unregister_fn)(uint64_t id);

typedef char *(*msb_sandbox_create_fn)(uint64_t cancel_id, const char *name, const char *opts_json, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_get_fn)(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_close_fn)(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_detach_fn)(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_stop_fn)(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_stop_and_wait_fn)(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_kill_fn)(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_list_fn)(uint64_t cancel_id, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_remove_fn)(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_exec_fn)(uint64_t cancel_id, uint64_t handle, const char *cmd, const char *exec_opts_json, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_exec_stream_fn)(uint64_t cancel_id, uint64_t handle, const char *cmd, const char *exec_opts_json, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_metrics_fn)(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len);

typedef char *(*msb_exec_recv_fn)(uint64_t cancel_id, uint64_t exec_handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_exec_close_fn)(uint64_t cancel_id, uint64_t exec_handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_exec_signal_fn)(uint64_t cancel_id, uint64_t exec_handle, int32_t signal, uint8_t *buf, size_t buf_len);

typedef char *(*msb_fs_read_fn)(uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len);
typedef char *(*msb_fs_write_fn)(uint64_t cancel_id, uint64_t handle, const char *path, const char *data_b64, uint8_t *buf, size_t buf_len);
typedef char *(*msb_fs_list_fn)(uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len);
typedef char *(*msb_fs_stat_fn)(uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len);
typedef char *(*msb_fs_copy_from_host_fn)(uint64_t cancel_id, uint64_t handle, const char *host_path, const char *guest_path, uint8_t *buf, size_t buf_len);
typedef char *(*msb_fs_copy_to_host_fn)(uint64_t cancel_id, uint64_t handle, const char *guest_path, const char *host_path, uint8_t *buf, size_t buf_len);

typedef char *(*msb_volume_create_fn)(uint64_t cancel_id, const char *name, uint32_t quota_mib, uint8_t *buf, size_t buf_len);
typedef char *(*msb_volume_remove_fn)(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len);
typedef char *(*msb_volume_list_fn)(uint64_t cancel_id, uint8_t *buf, size_t buf_len);

// ---------------------------------------------------------------------------
// Function pointer globals — NULL until load_microsandbox() succeeds.
// ---------------------------------------------------------------------------
static msb_free_string_fn        ptr_msb_free_string        = NULL;
static msb_cancel_alloc_fn       ptr_msb_cancel_alloc       = NULL;
static msb_cancel_trigger_fn     ptr_msb_cancel_trigger     = NULL;
static msb_cancel_unregister_fn  ptr_msb_cancel_unregister  = NULL;
static msb_sandbox_create_fn     ptr_msb_sandbox_create     = NULL;
static msb_sandbox_get_fn        ptr_msb_sandbox_get        = NULL;
static msb_sandbox_close_fn      ptr_msb_sandbox_close      = NULL;
static msb_sandbox_detach_fn     ptr_msb_sandbox_detach     = NULL;
static msb_sandbox_stop_fn       ptr_msb_sandbox_stop       = NULL;
static msb_sandbox_stop_and_wait_fn ptr_msb_sandbox_stop_and_wait = NULL;
static msb_sandbox_kill_fn       ptr_msb_sandbox_kill       = NULL;
static msb_sandbox_list_fn       ptr_msb_sandbox_list       = NULL;
static msb_sandbox_remove_fn     ptr_msb_sandbox_remove     = NULL;
static msb_sandbox_exec_fn       ptr_msb_sandbox_exec       = NULL;
static msb_sandbox_exec_stream_fn ptr_msb_sandbox_exec_stream = NULL;
static msb_sandbox_metrics_fn    ptr_msb_sandbox_metrics    = NULL;
static msb_exec_recv_fn          ptr_msb_exec_recv          = NULL;
static msb_exec_close_fn         ptr_msb_exec_close         = NULL;
static msb_exec_signal_fn        ptr_msb_exec_signal        = NULL;
static msb_fs_read_fn            ptr_msb_fs_read            = NULL;
static msb_fs_write_fn           ptr_msb_fs_write           = NULL;
static msb_fs_list_fn            ptr_msb_fs_list            = NULL;
static msb_fs_stat_fn            ptr_msb_fs_stat            = NULL;
static msb_fs_copy_from_host_fn  ptr_msb_fs_copy_from_host  = NULL;
static msb_fs_copy_to_host_fn    ptr_msb_fs_copy_to_host    = NULL;
static msb_volume_create_fn      ptr_msb_volume_create      = NULL;
static msb_volume_remove_fn      ptr_msb_volume_remove      = NULL;
static msb_volume_list_fn        ptr_msb_volume_list        = NULL;

// dlopen handle — set once by load_microsandbox, never closed.
static void *lib_handle = NULL;

// load_error holds a static error string on dlopen/dlsym failure.
// Not freed by callers — it lives for the process lifetime.
static char load_error[1024] = {0};

// RESOLVE dlsym's one symbol into its ptr_* global and stores an error
// message (returning it) if the symbol is absent.
#define RESOLVE(name) \
	do { \
		ptr_##name = (name##_fn)dlsym(lib_handle, #name); \
		if (!ptr_##name) { \
			snprintf(load_error, sizeof(load_error), \
				"dlsym '%s': %s", #name, dlerror()); \
			return load_error; \
		} \
	} while (0)

// load_microsandbox opens the shared library at path and resolves every
// msb_* symbol. Returns NULL on success or a static error string on failure.
// Idempotent: returns NULL immediately if already loaded.
// Ownership: path is borrowed for the duration of the call only.
const char *load_microsandbox(const char *path) {
	if (lib_handle) {
		return NULL;
	}
	lib_handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
	if (!lib_handle) {
		snprintf(load_error, sizeof(load_error), "dlopen '%s': %s", path, dlerror());
		return load_error;
	}
	RESOLVE(msb_free_string);
	RESOLVE(msb_cancel_alloc);
	RESOLVE(msb_cancel_trigger);
	RESOLVE(msb_cancel_unregister);
	RESOLVE(msb_sandbox_create);
	RESOLVE(msb_sandbox_get);
	RESOLVE(msb_sandbox_close);
	RESOLVE(msb_sandbox_detach);
	RESOLVE(msb_sandbox_stop);
	RESOLVE(msb_sandbox_stop_and_wait);
	RESOLVE(msb_sandbox_kill);
	RESOLVE(msb_sandbox_list);
	RESOLVE(msb_sandbox_remove);
	RESOLVE(msb_sandbox_exec);
	RESOLVE(msb_sandbox_exec_stream);
	RESOLVE(msb_sandbox_metrics);
	RESOLVE(msb_exec_recv);
	RESOLVE(msb_exec_close);
	RESOLVE(msb_exec_signal);
	RESOLVE(msb_fs_read);
	RESOLVE(msb_fs_write);
	RESOLVE(msb_fs_list);
	RESOLVE(msb_fs_stat);
	RESOLVE(msb_fs_copy_from_host);
	RESOLVE(msb_fs_copy_to_host);
	RESOLVE(msb_volume_create);
	RESOLVE(msb_volume_remove);
	RESOLVE(msb_volume_list);
	return NULL;
}

// is_microsandbox_loaded returns 1 after a successful load_microsandbox call.
int is_microsandbox_loaded() {
	return lib_handle != NULL ? 1 : 0;
}

// ---------------------------------------------------------------------------
// Trampolines — thin wrappers that call through the function-pointer globals.
// Calling a NULL pointer is UB; callers must check IsLoaded() (ensureLoaded)
// before reaching these. The NULL guards here are a last-resort safety net.
// ---------------------------------------------------------------------------
void call_msb_free_string(char *ptr) {
	if (ptr_msb_free_string) ptr_msb_free_string(ptr);
}
uint64_t call_msb_cancel_alloc(void) {
	return ptr_msb_cancel_alloc ? ptr_msb_cancel_alloc() : 0;
}
void call_msb_cancel_trigger(uint64_t id) {
	if (ptr_msb_cancel_trigger) ptr_msb_cancel_trigger(id);
}
void call_msb_cancel_unregister(uint64_t id) {
	if (ptr_msb_cancel_unregister) ptr_msb_cancel_unregister(id);
}
char *call_msb_sandbox_create(uint64_t cancel_id, const char *name, const char *opts_json, uint8_t *buf, size_t buf_len) {
	return ptr_msb_sandbox_create ? ptr_msb_sandbox_create(cancel_id, name, opts_json, buf, buf_len) : NULL;
}
char *call_msb_sandbox_get(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) {
	return ptr_msb_sandbox_get ? ptr_msb_sandbox_get(cancel_id, name, buf, buf_len) : NULL;
}
char *call_msb_sandbox_close(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) {
	return ptr_msb_sandbox_close ? ptr_msb_sandbox_close(cancel_id, handle, buf, buf_len) : NULL;
}
char *call_msb_sandbox_detach(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) {
	return ptr_msb_sandbox_detach ? ptr_msb_sandbox_detach(cancel_id, handle, buf, buf_len) : NULL;
}
char *call_msb_sandbox_stop(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) {
	return ptr_msb_sandbox_stop ? ptr_msb_sandbox_stop(cancel_id, handle, buf, buf_len) : NULL;
}
char *call_msb_sandbox_stop_and_wait(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) {
	return ptr_msb_sandbox_stop_and_wait ? ptr_msb_sandbox_stop_and_wait(cancel_id, handle, buf, buf_len) : NULL;
}
char *call_msb_sandbox_kill(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) {
	return ptr_msb_sandbox_kill ? ptr_msb_sandbox_kill(cancel_id, handle, buf, buf_len) : NULL;
}
char *call_msb_sandbox_list(uint64_t cancel_id, uint8_t *buf, size_t buf_len) {
	return ptr_msb_sandbox_list ? ptr_msb_sandbox_list(cancel_id, buf, buf_len) : NULL;
}
char *call_msb_sandbox_remove(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) {
	return ptr_msb_sandbox_remove ? ptr_msb_sandbox_remove(cancel_id, name, buf, buf_len) : NULL;
}
char *call_msb_sandbox_exec(uint64_t cancel_id, uint64_t handle, const char *cmd, const char *opts, uint8_t *buf, size_t buf_len) {
	return ptr_msb_sandbox_exec ? ptr_msb_sandbox_exec(cancel_id, handle, cmd, opts, buf, buf_len) : NULL;
}
char *call_msb_sandbox_exec_stream(uint64_t cancel_id, uint64_t handle, const char *cmd, const char *opts, uint8_t *buf, size_t buf_len) {
	return ptr_msb_sandbox_exec_stream ? ptr_msb_sandbox_exec_stream(cancel_id, handle, cmd, opts, buf, buf_len) : NULL;
}
char *call_msb_sandbox_metrics(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) {
	return ptr_msb_sandbox_metrics ? ptr_msb_sandbox_metrics(cancel_id, handle, buf, buf_len) : NULL;
}
char *call_msb_exec_recv(uint64_t cancel_id, uint64_t exec_handle, uint8_t *buf, size_t buf_len) {
	return ptr_msb_exec_recv ? ptr_msb_exec_recv(cancel_id, exec_handle, buf, buf_len) : NULL;
}
char *call_msb_exec_close(uint64_t cancel_id, uint64_t exec_handle, uint8_t *buf, size_t buf_len) {
	return ptr_msb_exec_close ? ptr_msb_exec_close(cancel_id, exec_handle, buf, buf_len) : NULL;
}
char *call_msb_exec_signal(uint64_t cancel_id, uint64_t exec_handle, int32_t signal, uint8_t *buf, size_t buf_len) {
	return ptr_msb_exec_signal ? ptr_msb_exec_signal(cancel_id, exec_handle, signal, buf, buf_len) : NULL;
}
char *call_msb_fs_read(uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len) {
	return ptr_msb_fs_read ? ptr_msb_fs_read(cancel_id, handle, path, buf, buf_len) : NULL;
}
char *call_msb_fs_write(uint64_t cancel_id, uint64_t handle, const char *path, const char *data_b64, uint8_t *buf, size_t buf_len) {
	return ptr_msb_fs_write ? ptr_msb_fs_write(cancel_id, handle, path, data_b64, buf, buf_len) : NULL;
}
char *call_msb_fs_list(uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len) {
	return ptr_msb_fs_list ? ptr_msb_fs_list(cancel_id, handle, path, buf, buf_len) : NULL;
}
char *call_msb_fs_stat(uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len) {
	return ptr_msb_fs_stat ? ptr_msb_fs_stat(cancel_id, handle, path, buf, buf_len) : NULL;
}
char *call_msb_fs_copy_from_host(uint64_t cancel_id, uint64_t handle, const char *host_path, const char *guest_path, uint8_t *buf, size_t buf_len) {
	return ptr_msb_fs_copy_from_host ? ptr_msb_fs_copy_from_host(cancel_id, handle, host_path, guest_path, buf, buf_len) : NULL;
}
char *call_msb_fs_copy_to_host(uint64_t cancel_id, uint64_t handle, const char *guest_path, const char *host_path, uint8_t *buf, size_t buf_len) {
	return ptr_msb_fs_copy_to_host ? ptr_msb_fs_copy_to_host(cancel_id, handle, guest_path, host_path, buf, buf_len) : NULL;
}
char *call_msb_volume_create(uint64_t cancel_id, const char *name, uint32_t quota_mib, uint8_t *buf, size_t buf_len) {
	return ptr_msb_volume_create ? ptr_msb_volume_create(cancel_id, name, quota_mib, buf, buf_len) : NULL;
}
char *call_msb_volume_remove(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) {
	return ptr_msb_volume_remove ? ptr_msb_volume_remove(cancel_id, name, buf, buf_len) : NULL;
}
char *call_msb_volume_list(uint64_t cancel_id, uint8_t *buf, size_t buf_len) {
	return ptr_msb_volume_list ? ptr_msb_volume_list(cancel_id, buf, buf_len) : NULL;
}
*/
import "C"

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
	"unsafe"
)

// =============================================================================
// Loader
// =============================================================================

// KindLibraryNotLoaded is returned when any FFI function is called before
// the library has been loaded. The public SDK surfaces this as ErrLibraryNotLoaded.
const KindLibraryNotLoaded = "library_not_loaded"

// libraryPathEnv overrides the default library path. Set it to a local
// target/debug build path for development without running EnsureInstalled.
const libraryPathEnv = "MICROSANDBOX_LIB_PATH"

var (
	loadOnce    sync.Once
	loadErr     error
	libraryPath string
)

func init() {
	if envPath := os.Getenv(libraryPathEnv); envPath != "" {
		libraryPath = envPath
	} else {
		if home, err := os.UserHomeDir(); err == nil {
			libraryPath = filepath.Join(home, ".microsandbox", "lib", defaultLibName())
		}
	}
}

// defaultLibName returns the platform-specific filename of the Go FFI cdylib.
func defaultLibName() string {
	if runtime.GOOS == "darwin" {
		return "libmicrosandbox_go_ffi.dylib"
	}
	return "libmicrosandbox_go_ffi.so"
}

// Load opens the shared library at path (or the default ~/.microsandbox/lib/
// location when path is empty) and resolves every msb_* symbol. Safe to call
// multiple times — only the first call does work.
func Load(path string) error {
	if path == "" {
		path = libraryPath
	}
	loadOnce.Do(func() {
		cPath := C.CString(path)
		defer C.free(unsafe.Pointer(cPath))
		if errMsg := C.load_microsandbox(cPath); errMsg != nil {
			loadErr = fmt.Errorf("%s", C.GoString(errMsg))
		}
	})
	return loadErr
}

// IsLoaded reports whether the library has been successfully loaded.
func IsLoaded() bool {
	return C.is_microsandbox_loaded() == 1
}

// ensureLoaded is called at the top of every exported FFI function. It returns
// a typed error when the library has not been loaded, so the caller gets a
// clear message rather than a nil-pointer crash.
func ensureLoaded() error {
	if !IsLoaded() {
		return &Error{
			Kind:    KindLibraryNotLoaded,
			Message: "microsandbox library not loaded; call microsandbox.EnsureInstalled() first",
		}
	}
	return nil
}

// =============================================================================
// Types and helpers
// =============================================================================

// defaultBufSize is the output buffer allocated for each FFI call. 1 MiB
// covers JSON metadata and small file reads. FSRead on larger files returns
// KindBufferTooSmall; streaming is a follow-up.
const defaultBufSize = 1 << 20

// Error is the typed error surfaced across the FFI boundary. The Rust side
// serialises {kind, message} JSON; this type unmarshals it. The public SDK
// maps Kind back into microsandbox.ErrorKind.
type Error struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Message }

// Error kind strings. Keep in sync with sdk/go-ffi/src/lib.rs FfiError::kind.
const (
	KindSandboxNotFound     = "sandbox_not_found"
	KindSandboxStillRunning = "sandbox_still_running"
	KindVolumeNotFound      = "volume_not_found"
	KindVolumeAlreadyExists = "volume_already_exists"
	KindExecTimeout         = "exec_timeout"
	KindInvalidConfig       = "invalid_config"
	KindInvalidArgument     = "invalid_argument"
	KindInvalidHandle       = "invalid_handle"
	KindBufferTooSmall      = "buffer_too_small"
	KindCancelled           = "cancelled"
	KindInternal            = "internal"
)

// Sandbox is an opaque handle to a Rust-side sandbox. Call Close to release.
// Safe for concurrent use from multiple goroutines.
type Sandbox struct {
	handle C.uint64_t
	name   string
}

// Handle returns the underlying integer handle (for debugging only).
func (s *Sandbox) Handle() uint64 { return uint64(s.handle) }

// Name returns the sandbox name supplied at creation time.
func (s *Sandbox) Name() string { return s.name }

// call invokes fn with a fresh 1 MiB buffer and a Rust-side cancellation
// token. It runs fn on a goroutine and selects on ctx.Done; if the context
// fires first, it triggers the Rust cancel token and waits for the goroutine
// before returning — this prevents the caller's `defer C.free` on any C
// strings from racing with Rust still reading them.
//
// Rust's run_c helper (and the close/exec_close/exec_recv/exec_signal paths)
// call msb_cancel_unregister themselves; nothing to do here.
func call(ctx context.Context, fn func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char) (string, error) {
	type res struct {
		out string
		err error
	}
	done := make(chan res, 1)
	buf := make([]byte, defaultBufSize)
	cancelID := C.call_msb_cancel_alloc()

	go func() {
		errPtr := fn(cancelID, (*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
		if errPtr != nil {
			msg := C.GoString(errPtr)
			C.call_msb_free_string(errPtr)
			var e Error
			if jerr := json.Unmarshal([]byte(msg), &e); jerr != nil {
				e = Error{Kind: KindInternal, Message: msg}
			}
			done <- res{err: &e}
			return
		}
		end := 0
		for end < len(buf) && buf[end] != 0 {
			end++
		}
		done <- res{out: string(buf[:end])}
	}()

	select {
	case r := <-done:
		return r.out, r.err
	case <-ctx.Done():
		C.call_msb_cancel_trigger(cancelID)
		<-done // wait so caller's deferred C.free doesn't race Rust
		return "", ctx.Err()
	}
}

// =============================================================================
// Sandbox lifecycle
// =============================================================================

// CreateOptions mirrors the JSON schema expected by msb_sandbox_create.
// Zero-valued fields are omitted; the Rust side applies defaults.
type CreateOptions struct {
	Image     string            `json:"image,omitempty"`
	MemoryMiB uint32            `json:"memory_mib,omitempty"`
	CPUs      uint8             `json:"cpus,omitempty"`
	Workdir   string            `json:"workdir,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	Detached  bool              `json:"detached,omitempty"`
	Ports     map[uint16]uint16 `json:"ports,omitempty"`
	Network   *NetworkOptions   `json:"network,omitempty"`
	Secrets   []SecretOptions   `json:"secrets,omitempty"`
	Patches   []PatchOptions    `json:"patches,omitempty"`
}

// NetworkOptions is the JSON representation of the network config block.
type NetworkOptions struct {
	Policy              string               `json:"policy,omitempty"`
	CustomPolicy        *CustomNetworkPolicy `json:"custom_policy,omitempty"`
	BlockDomains        []string             `json:"block_domains,omitempty"`
	BlockDomainSuffixes []string             `json:"block_domain_suffixes,omitempty"`
	DNSRebindProtection *bool                `json:"dns_rebind_protection,omitempty"`
	TLS                 *TLSOptions          `json:"tls,omitempty"`
	Ports               map[uint16]uint16    `json:"ports,omitempty"`
}

// CustomNetworkPolicy is an explicit allow/deny rule set.
type CustomNetworkPolicy struct {
	DefaultAction string        `json:"default_action,omitempty"`
	Rules         []NetworkRule `json:"rules,omitempty"`
}

// NetworkRule is a single firewall rule.
type NetworkRule struct {
	Action      string `json:"action"`
	Direction   string `json:"direction,omitempty"`
	Destination string `json:"destination,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	Port        uint16 `json:"port,omitempty"`
}

// TLSOptions configures the transparent HTTPS interception proxy.
type TLSOptions struct {
	Bypass           []string `json:"bypass,omitempty"`
	VerifyUpstream   *bool    `json:"verify_upstream,omitempty"`
	InterceptedPorts []uint16 `json:"intercepted_ports,omitempty"`
	BlockQUIC        *bool    `json:"block_quic,omitempty"`
	CACert           string   `json:"ca_cert,omitempty"`
	CAKey            string   `json:"ca_key,omitempty"`
}

// SecretOptions is the JSON representation of a single credential.
type SecretOptions struct {
	EnvVar            string   `json:"env_var"`
	Value             string   `json:"value"`
	AllowHosts        []string `json:"allow_hosts,omitempty"`
	AllowHostPatterns []string `json:"allow_host_patterns,omitempty"`
	Placeholder       string   `json:"placeholder,omitempty"`
	RequireTLS        *bool    `json:"require_tls,omitempty"`
}

// PatchOptions is the JSON representation of a single rootfs patch.
type PatchOptions struct {
	Kind    string  `json:"kind"`
	Path    string  `json:"path,omitempty"`
	Content string  `json:"content,omitempty"`
	Mode    *uint32 `json:"mode,omitempty"`
	Replace bool    `json:"replace,omitempty"`
	Src     string  `json:"src,omitempty"`
	Dst     string  `json:"dst,omitempty"`
	Target  string  `json:"target,omitempty"`
	Link    string  `json:"link,omitempty"`
}

// CreateSandbox creates and boots a sandbox, returning a handle the caller
// must Close when done.
//
// Ownership: cName and cOpts are Go-allocated C strings borrowed by Rust for
// the duration of the call. Rust copies any strings it retains before returning.
func CreateSandbox(ctx context.Context, name string, opts CreateOptions) (*Sandbox, error) {
	if err := ensureLoaded(); err != nil {
		return nil, err
	}
	optsJSON, err := json.Marshal(opts)
	if err != nil {
		return nil, fmt.Errorf("marshal opts: %w", err)
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	cOpts := C.CString(string(optsJSON))
	defer C.free(unsafe.Pointer(cOpts))

	out, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_sandbox_create(cancelID, cName, cOpts, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Handle uint64 `json:"handle"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return nil, fmt.Errorf("parse create response: %w", err)
	}
	return &Sandbox{handle: C.uint64_t(resp.Handle), name: name}, nil
}

// GetSandbox reattaches to an existing sandbox by name. Returns an Error with
// Kind==KindSandboxNotFound if no such sandbox exists.
func GetSandbox(ctx context.Context, name string) (*Sandbox, error) {
	if err := ensureLoaded(); err != nil {
		return nil, err
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	out, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_sandbox_get(cancelID, cName, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Handle uint64 `json:"handle"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return nil, fmt.Errorf("parse get response: %w", err)
	}
	return &Sandbox{handle: C.uint64_t(resp.Handle), name: name}, nil
}

// Close releases the Rust-side sandbox resources for this handle. Safe to
// call multiple times — the second returns KindInvalidHandle.
// Uses context.Background so cleanup cannot be cancelled; use CloseCtx for
// a caller-controlled timeout.
func (s *Sandbox) Close() error {
	return s.CloseCtx(context.Background())
}

// CloseCtx is Close with a caller-controlled context.
func (s *Sandbox) CloseCtx(ctx context.Context) error {
	if err := ensureLoaded(); err != nil {
		return err
	}
	_, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_sandbox_close(cancelID, s.handle, buf, bufLen)
	})
	return err
}

// Detach releases the handle without stopping the VM. Use on sandboxes
// created with Detached==true when the caller is done but the VM should
// keep running. After Detach the handle is invalid.
func (s *Sandbox) Detach(ctx context.Context) error {
	if err := ensureLoaded(); err != nil {
		return err
	}
	_, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_sandbox_detach(cancelID, s.handle, buf, bufLen)
	})
	return err
}

// Stop gracefully stops the sandbox without waiting for exit.
func (s *Sandbox) Stop(ctx context.Context) error {
	if err := ensureLoaded(); err != nil {
		return err
	}
	_, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_sandbox_stop(cancelID, s.handle, buf, bufLen)
	})
	return err
}

// StopAndWait stops the sandbox and waits for its process to exit.
// Returns the exit code, or -1 if the guest did not report one.
func (s *Sandbox) StopAndWait(ctx context.Context) (int, error) {
	if err := ensureLoaded(); err != nil {
		return 0, err
	}
	out, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_sandbox_stop_and_wait(cancelID, s.handle, buf, bufLen)
	})
	if err != nil {
		return 0, err
	}
	var resp struct {
		ExitCode *int `json:"exit_code"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return 0, fmt.Errorf("parse stop_and_wait response: %w", err)
	}
	if resp.ExitCode == nil {
		return -1, nil
	}
	return *resp.ExitCode, nil
}

// Kill terminates the sandbox immediately (SIGKILL).
func (s *Sandbox) Kill(ctx context.Context) error {
	if err := ensureLoaded(); err != nil {
		return err
	}
	_, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_sandbox_kill(cancelID, s.handle, buf, bufLen)
	})
	return err
}

// ListSandboxes returns the names of all known sandboxes (running or stopped).
func ListSandboxes(ctx context.Context) ([]string, error) {
	if err := ensureLoaded(); err != nil {
		return nil, err
	}
	out, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_sandbox_list(cancelID, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var names []string
	if err := json.Unmarshal([]byte(out), &names); err != nil {
		return nil, fmt.Errorf("parse sandbox list: %w", err)
	}
	return names, nil
}

// RemoveSandbox removes a stopped sandbox's persisted state by name.
func RemoveSandbox(ctx context.Context, name string) error {
	if err := ensureLoaded(); err != nil {
		return err
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	_, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_sandbox_remove(cancelID, cName, buf, bufLen)
	})
	return err
}

// =============================================================================
// Exec (collected output)
// =============================================================================

// ExecOptions configures a single Exec call.
type ExecOptions struct {
	Args        []string `json:"args,omitempty"`
	Cwd         string   `json:"cwd,omitempty"`
	TimeoutSecs uint64   `json:"timeout_secs,omitempty"`
}

// ExecResult is the collected output of a completed command.
type ExecResult struct {
	Stdout   string
	Stderr   string
	ExitCode int // -1 if the guest did not report a code
}

// Exec runs cmd in the sandbox and collects its output.
func (s *Sandbox) Exec(ctx context.Context, cmd string, opts ExecOptions) (*ExecResult, error) {
	if err := ensureLoaded(); err != nil {
		return nil, err
	}
	optsJSON, err := json.Marshal(opts)
	if err != nil {
		return nil, fmt.Errorf("marshal exec opts: %w", err)
	}
	cCmd := C.CString(cmd)
	defer C.free(unsafe.Pointer(cCmd))
	cOpts := C.CString(string(optsJSON))
	defer C.free(unsafe.Pointer(cOpts))

	out, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_sandbox_exec(cancelID, s.handle, cCmd, cOpts, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var raw struct {
		Stdout   string `json:"stdout"`
		Stderr   string `json:"stderr"`
		ExitCode *int   `json:"exit_code"`
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, fmt.Errorf("parse exec response: %w", err)
	}
	code := -1
	if raw.ExitCode != nil {
		code = *raw.ExitCode
	}
	return &ExecResult{Stdout: raw.Stdout, Stderr: raw.Stderr, ExitCode: code}, nil
}

// =============================================================================
// Exec (streaming)
// =============================================================================

// ExecStreamHandle is an opaque reference to a running streaming exec session.
// Go owns the u64 token; Rust owns the channel resources until Close is called.
// Not safe for concurrent use from multiple goroutines.
type ExecStreamHandle struct {
	handle C.uint64_t
}

// ExecEventKind identifies what an ExecStreamEvent carries.
type ExecEventKind int

const (
	ExecEventStarted ExecEventKind = iota
	ExecEventStdout
	ExecEventStderr
	ExecEventExited
	ExecEventDone // all events consumed; no further Recv calls needed
)

// ExecStreamEvent is one event from a streaming exec session.
type ExecStreamEvent struct {
	Kind     ExecEventKind
	PID      uint32 // ExecEventStarted
	Data     []byte // ExecEventStdout / ExecEventStderr
	ExitCode int    // ExecEventExited
}

// ExecStream starts a streaming exec session. The returned handle MUST be
// closed with Close when the stream ends or is no longer needed.
func (s *Sandbox) ExecStream(ctx context.Context, cmd string, opts ExecOptions) (*ExecStreamHandle, error) {
	if err := ensureLoaded(); err != nil {
		return nil, err
	}
	optsJSON, err := json.Marshal(opts)
	if err != nil {
		return nil, fmt.Errorf("marshal exec opts: %w", err)
	}
	cCmd := C.CString(cmd)
	defer C.free(unsafe.Pointer(cCmd))
	cOpts := C.CString(string(optsJSON))
	defer C.free(unsafe.Pointer(cOpts))

	out, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_sandbox_exec_stream(cancelID, s.handle, cCmd, cOpts, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var resp struct {
		ExecHandle uint64 `json:"exec_handle"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return nil, fmt.Errorf("parse exec_stream response: %w", err)
	}
	return &ExecStreamHandle{handle: C.uint64_t(resp.ExecHandle)}, nil
}

// Recv blocks until the next event arrives or the stream ends. Returns
// ExecEventDone when all events have been consumed. ctx cancellation returns
// ctx.Err() immediately; the underlying Rust work continues in background.
func (h *ExecStreamHandle) Recv(ctx context.Context) (*ExecStreamEvent, error) {
	if err := ensureLoaded(); err != nil {
		return nil, err
	}
	out, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_exec_recv(cancelID, h.handle, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var raw struct {
		Event string `json:"event"`
		PID   uint32 `json:"pid"`
		Data  string `json:"data"` // base64
		Code  int    `json:"code"`
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, fmt.Errorf("parse exec event: %w", err)
	}
	ev := &ExecStreamEvent{}
	switch raw.Event {
	case "started":
		ev.Kind = ExecEventStarted
		ev.PID = raw.PID
	case "stdout":
		ev.Kind = ExecEventStdout
		ev.Data, err = base64.StdEncoding.DecodeString(raw.Data)
		if err != nil {
			return nil, fmt.Errorf("decode stdout: %w", err)
		}
	case "stderr":
		ev.Kind = ExecEventStderr
		ev.Data, err = base64.StdEncoding.DecodeString(raw.Data)
		if err != nil {
			return nil, fmt.Errorf("decode stderr: %w", err)
		}
	case "exited":
		ev.Kind = ExecEventExited
		ev.ExitCode = raw.Code
	case "done":
		ev.Kind = ExecEventDone
	default:
		return nil, fmt.Errorf("unknown exec event: %q", raw.Event)
	}
	return ev, nil
}

// Signal sends a Unix signal number to the running process (e.g. 15=SIGTERM).
func (h *ExecStreamHandle) Signal(ctx context.Context, signal int) error {
	if err := ensureLoaded(); err != nil {
		return err
	}
	_, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_exec_signal(cancelID, h.handle, C.int32_t(signal), buf, bufLen)
	})
	return err
}

// Close releases the Rust-side exec handle. Does not kill the process; call
// Signal(ctx, 9) first if needed. Uses context.Background so cleanup cannot
// be cancelled.
func (h *ExecStreamHandle) Close() error {
	if err := ensureLoaded(); err != nil {
		return err
	}
	_, err := call(context.Background(), func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_exec_close(cancelID, h.handle, buf, bufLen)
	})
	return err
}

// =============================================================================
// Metrics
// =============================================================================

// Metrics is the resource-usage snapshot reported by Rust.
type Metrics struct {
	CPUPercent       float64       `json:"cpu_percent"`
	MemoryBytes      uint64        `json:"memory_bytes"`
	MemoryLimitBytes uint64        `json:"memory_limit_bytes"`
	DiskReadBytes    uint64        `json:"disk_read_bytes"`
	DiskWriteBytes   uint64        `json:"disk_write_bytes"`
	NetRxBytes       uint64        `json:"net_rx_bytes"`
	NetTxBytes       uint64        `json:"net_tx_bytes"`
	UptimeSecs       uint64        `json:"uptime_secs"`
	Uptime           time.Duration `json:"-"`
}

// Metrics fetches a resource-usage snapshot for this sandbox.
func (s *Sandbox) Metrics(ctx context.Context) (*Metrics, error) {
	if err := ensureLoaded(); err != nil {
		return nil, err
	}
	out, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_sandbox_metrics(cancelID, s.handle, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var m Metrics
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		return nil, fmt.Errorf("parse metrics: %w", err)
	}
	m.Uptime = time.Duration(m.UptimeSecs) * time.Second
	return &m, nil
}

// =============================================================================
// Filesystem
// =============================================================================

// FsEntry is a single directory listing entry.
type FsEntry struct {
	Path string `json:"path"`
	Kind string `json:"kind"` // "file" | "dir" | "symlink" | "other"
	Size int64  `json:"size"`
	Mode uint32 `json:"mode"`
}

// FsStat is file or directory metadata.
type FsStat struct {
	Kind         string `json:"kind"`
	Size         int64  `json:"size"`
	Mode         uint32 `json:"mode"`
	Readonly     bool   `json:"readonly"`
	ModifiedUnix *int64 `json:"modified_unix"`
}

// IsDir reports whether the entry is a directory.
func (s *FsStat) IsDir() bool { return s.Kind == "dir" }

// ModTime returns the modified timestamp, or the zero value if absent.
func (s *FsStat) ModTime() time.Time {
	if s.ModifiedUnix == nil {
		return time.Time{}
	}
	return time.Unix(*s.ModifiedUnix, 0)
}

// FsRead reads a file from the sandbox. Files larger than ~750 KiB may
// exceed the buffer and return KindBufferTooSmall.
func (s *Sandbox) FsRead(ctx context.Context, path string) ([]byte, error) {
	if err := ensureLoaded(); err != nil {
		return nil, err
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	out, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_fs_read(cancelID, s.handle, cPath, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var payload struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		return nil, fmt.Errorf("parse fs_read: %w", err)
	}
	return base64.StdEncoding.DecodeString(payload.Data)
}

// FsWrite writes data to a file in the sandbox.
func (s *Sandbox) FsWrite(ctx context.Context, path string, data []byte) error {
	if err := ensureLoaded(); err != nil {
		return err
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	cData := C.CString(base64.StdEncoding.EncodeToString(data))
	defer C.free(unsafe.Pointer(cData))

	_, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_fs_write(cancelID, s.handle, cPath, cData, buf, bufLen)
	})
	return err
}

// FsList lists the entries in a directory.
func (s *Sandbox) FsList(ctx context.Context, path string) ([]FsEntry, error) {
	if err := ensureLoaded(); err != nil {
		return nil, err
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	out, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_fs_list(cancelID, s.handle, cPath, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var entries []FsEntry
	if err := json.Unmarshal([]byte(out), &entries); err != nil {
		return nil, fmt.Errorf("parse fs_list: %w", err)
	}
	return entries, nil
}

// FsStat returns metadata for a file or directory.
func (s *Sandbox) FsStat(ctx context.Context, path string) (*FsStat, error) {
	if err := ensureLoaded(); err != nil {
		return nil, err
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	out, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_fs_stat(cancelID, s.handle, cPath, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var stat FsStat
	if err := json.Unmarshal([]byte(out), &stat); err != nil {
		return nil, fmt.Errorf("parse fs_stat: %w", err)
	}
	return &stat, nil
}

// FsCopyFromHost copies a host file into the sandbox.
func (s *Sandbox) FsCopyFromHost(ctx context.Context, hostPath, guestPath string) error {
	if err := ensureLoaded(); err != nil {
		return err
	}
	cHost := C.CString(hostPath)
	defer C.free(unsafe.Pointer(cHost))
	cGuest := C.CString(guestPath)
	defer C.free(unsafe.Pointer(cGuest))

	_, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_fs_copy_from_host(cancelID, s.handle, cHost, cGuest, buf, bufLen)
	})
	return err
}

// FsCopyToHost copies a file from the sandbox to the host.
func (s *Sandbox) FsCopyToHost(ctx context.Context, guestPath, hostPath string) error {
	if err := ensureLoaded(); err != nil {
		return err
	}
	cGuest := C.CString(guestPath)
	defer C.free(unsafe.Pointer(cGuest))
	cHost := C.CString(hostPath)
	defer C.free(unsafe.Pointer(cHost))

	_, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_fs_copy_to_host(cancelID, s.handle, cGuest, cHost, buf, bufLen)
	})
	return err
}

// =============================================================================
// Volumes
// =============================================================================

// CreateVolume creates a named persistent volume. quotaMiB==0 means unlimited.
func CreateVolume(ctx context.Context, name string, quotaMiB uint32) error {
	if err := ensureLoaded(); err != nil {
		return err
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	_, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_volume_create(cancelID, cName, C.uint32_t(quotaMiB), buf, bufLen)
	})
	return err
}

// RemoveVolume removes a named volume.
func RemoveVolume(ctx context.Context, name string) error {
	if err := ensureLoaded(); err != nil {
		return err
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	_, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_volume_remove(cancelID, cName, buf, bufLen)
	})
	return err
}

// ListVolumes returns the names of all volumes.
func ListVolumes(ctx context.Context) ([]string, error) {
	if err := ensureLoaded(); err != nil {
		return nil, err
	}
	out, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_volume_list(cancelID, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var names []string
	if err := json.Unmarshal([]byte(out), &names); err != nil {
		return nil, fmt.Errorf("parse volume list: %w", err)
	}
	return names, nil
}

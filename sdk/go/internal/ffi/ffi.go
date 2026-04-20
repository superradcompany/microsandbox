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
typedef char *(*msb_sandbox_lookup_fn)(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_connect_fn)(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_start_fn)(uint64_t cancel_id, const char *name, bool detached, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_handle_stop_fn)(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_handle_kill_fn)(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len);
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
typedef char *(*msb_exec_collect_fn)(uint64_t cancel_id, uint64_t exec_handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_exec_wait_fn)(uint64_t cancel_id, uint64_t exec_handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_exec_kill_fn)(uint64_t cancel_id, uint64_t exec_handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_exec_id_fn)(uint64_t exec_handle, uint8_t *buf, size_t buf_len);

typedef char *(*msb_fs_read_fn)(uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len);
typedef char *(*msb_fs_write_fn)(uint64_t cancel_id, uint64_t handle, const char *path, const char *data_b64, uint8_t *buf, size_t buf_len);
typedef char *(*msb_fs_list_fn)(uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len);
typedef char *(*msb_fs_stat_fn)(uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len);
typedef char *(*msb_fs_copy_from_host_fn)(uint64_t cancel_id, uint64_t handle, const char *host_path, const char *guest_path, uint8_t *buf, size_t buf_len);
typedef char *(*msb_fs_copy_to_host_fn)(uint64_t cancel_id, uint64_t handle, const char *guest_path, const char *host_path, uint8_t *buf, size_t buf_len);
typedef char *(*msb_fs_mkdir_fn)(uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len);
typedef char *(*msb_fs_remove_fn)(uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len);
typedef char *(*msb_fs_remove_dir_fn)(uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len);
typedef char *(*msb_fs_copy_fn)(uint64_t cancel_id, uint64_t handle, const char *src, const char *dst, uint8_t *buf, size_t buf_len);
typedef char *(*msb_fs_rename_fn)(uint64_t cancel_id, uint64_t handle, const char *src, const char *dst, uint8_t *buf, size_t buf_len);
typedef char *(*msb_fs_exists_fn)(uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len);

typedef char *(*msb_sandbox_metrics_stream_fn)(uint64_t cancel_id, uint64_t handle, uint64_t interval_ms, uint8_t *buf, size_t buf_len);
typedef char *(*msb_metrics_recv_fn)(uint64_t cancel_id, uint64_t stream_handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_metrics_close_fn)(uint64_t stream_handle, uint8_t *buf, size_t buf_len);

typedef char *(*msb_exec_stdin_write_fn)(uint64_t cancel_id, uint64_t exec_handle, const char *data_b64, uint8_t *buf, size_t buf_len);
typedef char *(*msb_exec_stdin_close_fn)(uint64_t cancel_id, uint64_t exec_handle, uint8_t *buf, size_t buf_len);

typedef char *(*msb_sandbox_drain_fn)(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_wait_fn)(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_owns_lifecycle_fn)(uint64_t handle, uint8_t *buf, size_t buf_len);

typedef char *(*msb_sandbox_attach_fn)(uint64_t cancel_id, uint64_t handle, const char *cmd, const char *opts_json, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_attach_shell_fn)(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_remove_persisted_fn)(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_all_sandbox_metrics_fn)(uint64_t cancel_id, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_handle_metrics_fn)(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len);

typedef char *(*msb_volume_create_fn)(uint64_t cancel_id, const char *name, uint32_t quota_mib, uint8_t *buf, size_t buf_len);
typedef char *(*msb_volume_remove_fn)(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len);
typedef char *(*msb_volume_list_fn)(uint64_t cancel_id, uint8_t *buf, size_t buf_len);
typedef char *(*msb_volume_get_fn)(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len);

typedef char *(*msb_fs_read_stream_fn)(uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len);
typedef char *(*msb_fs_read_stream_recv_fn)(uint64_t cancel_id, uint64_t stream_handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_fs_read_stream_close_fn)(uint64_t stream_handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_fs_write_stream_fn)(uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len);
typedef char *(*msb_fs_write_stream_write_fn)(uint64_t cancel_id, uint64_t stream_handle, const char *data_b64, uint8_t *buf, size_t buf_len);
typedef char *(*msb_fs_write_stream_close_fn)(uint64_t cancel_id, uint64_t stream_handle, uint8_t *buf, size_t buf_len);

// ---------------------------------------------------------------------------
// Function pointer globals — NULL until load_microsandbox() succeeds.
// ---------------------------------------------------------------------------
static msb_free_string_fn        ptr_msb_free_string        = NULL;
static msb_cancel_alloc_fn       ptr_msb_cancel_alloc       = NULL;
static msb_cancel_trigger_fn     ptr_msb_cancel_trigger     = NULL;
static msb_cancel_unregister_fn  ptr_msb_cancel_unregister  = NULL;
static msb_sandbox_create_fn     ptr_msb_sandbox_create     = NULL;
static msb_sandbox_lookup_fn     ptr_msb_sandbox_lookup     = NULL;
static msb_sandbox_connect_fn    ptr_msb_sandbox_connect    = NULL;
static msb_sandbox_start_fn      ptr_msb_sandbox_start      = NULL;
static msb_sandbox_handle_stop_fn ptr_msb_sandbox_handle_stop = NULL;
static msb_sandbox_handle_kill_fn ptr_msb_sandbox_handle_kill = NULL;
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
static msb_fs_mkdir_fn           ptr_msb_fs_mkdir           = NULL;
static msb_fs_remove_fn          ptr_msb_fs_remove          = NULL;
static msb_fs_remove_dir_fn      ptr_msb_fs_remove_dir      = NULL;
static msb_fs_copy_fn            ptr_msb_fs_copy            = NULL;
static msb_fs_rename_fn          ptr_msb_fs_rename          = NULL;
static msb_fs_exists_fn          ptr_msb_fs_exists          = NULL;
static msb_sandbox_metrics_stream_fn ptr_msb_sandbox_metrics_stream = NULL;
static msb_metrics_recv_fn        ptr_msb_metrics_recv        = NULL;
static msb_metrics_close_fn       ptr_msb_metrics_close       = NULL;
static msb_exec_stdin_write_fn    ptr_msb_exec_stdin_write    = NULL;
static msb_exec_stdin_close_fn   ptr_msb_exec_stdin_close   = NULL;
static msb_sandbox_drain_fn       ptr_msb_sandbox_drain       = NULL;
static msb_sandbox_wait_fn        ptr_msb_sandbox_wait        = NULL;
static msb_sandbox_owns_lifecycle_fn ptr_msb_sandbox_owns_lifecycle = NULL;
static msb_exec_collect_fn         ptr_msb_exec_collect         = NULL;
static msb_exec_wait_fn            ptr_msb_exec_wait            = NULL;
static msb_exec_kill_fn            ptr_msb_exec_kill            = NULL;
static msb_exec_id_fn              ptr_msb_exec_id              = NULL;
static msb_sandbox_attach_fn      ptr_msb_sandbox_attach      = NULL;
static msb_sandbox_attach_shell_fn ptr_msb_sandbox_attach_shell = NULL;
static msb_sandbox_remove_persisted_fn ptr_msb_sandbox_remove_persisted = NULL;
static msb_all_sandbox_metrics_fn  ptr_msb_all_sandbox_metrics  = NULL;
static msb_sandbox_handle_metrics_fn ptr_msb_sandbox_handle_metrics = NULL;
static msb_volume_create_fn       ptr_msb_volume_create       = NULL;
static msb_volume_remove_fn       ptr_msb_volume_remove       = NULL;
static msb_volume_list_fn         ptr_msb_volume_list         = NULL;
static msb_volume_get_fn          ptr_msb_volume_get          = NULL;
static msb_fs_read_stream_fn       ptr_msb_fs_read_stream       = NULL;
static msb_fs_read_stream_recv_fn  ptr_msb_fs_read_stream_recv  = NULL;
static msb_fs_read_stream_close_fn ptr_msb_fs_read_stream_close = NULL;
static msb_fs_write_stream_fn      ptr_msb_fs_write_stream      = NULL;
static msb_fs_write_stream_write_fn ptr_msb_fs_write_stream_write = NULL;
static msb_fs_write_stream_close_fn ptr_msb_fs_write_stream_close = NULL;

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
	RESOLVE(msb_sandbox_lookup);
	RESOLVE(msb_sandbox_connect);
	RESOLVE(msb_sandbox_start);
	RESOLVE(msb_sandbox_handle_stop);
	RESOLVE(msb_sandbox_handle_kill);
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
	RESOLVE(msb_fs_mkdir);
	RESOLVE(msb_fs_remove);
	RESOLVE(msb_fs_remove_dir);
	RESOLVE(msb_fs_copy);
	RESOLVE(msb_fs_rename);
	RESOLVE(msb_fs_exists);
	RESOLVE(msb_sandbox_metrics_stream);
	RESOLVE(msb_metrics_recv);
	RESOLVE(msb_metrics_close);
	RESOLVE(msb_exec_stdin_write);
	RESOLVE(msb_exec_stdin_close);
	RESOLVE(msb_sandbox_drain);
	RESOLVE(msb_sandbox_wait);
	RESOLVE(msb_sandbox_owns_lifecycle);
	RESOLVE(msb_exec_collect);
	RESOLVE(msb_exec_wait);
	RESOLVE(msb_exec_kill);
	RESOLVE(msb_exec_id);
	RESOLVE(msb_sandbox_attach);
	RESOLVE(msb_sandbox_attach_shell);
	RESOLVE(msb_sandbox_remove_persisted);
	RESOLVE(msb_all_sandbox_metrics);
	RESOLVE(msb_sandbox_handle_metrics);
	RESOLVE(msb_volume_create);
	RESOLVE(msb_volume_remove);
	RESOLVE(msb_volume_list);
	RESOLVE(msb_volume_get);
	RESOLVE(msb_fs_read_stream);
	RESOLVE(msb_fs_read_stream_recv);
	RESOLVE(msb_fs_read_stream_close);
	RESOLVE(msb_fs_write_stream);
	RESOLVE(msb_fs_write_stream_write);
	RESOLVE(msb_fs_write_stream_close);
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
char *call_msb_sandbox_lookup(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) {
	return ptr_msb_sandbox_lookup ? ptr_msb_sandbox_lookup(cancel_id, name, buf, buf_len) : NULL;
}
char *call_msb_sandbox_connect(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) {
	return ptr_msb_sandbox_connect ? ptr_msb_sandbox_connect(cancel_id, name, buf, buf_len) : NULL;
}
char *call_msb_sandbox_start(uint64_t cancel_id, const char *name, bool detached, uint8_t *buf, size_t buf_len) {
	return ptr_msb_sandbox_start ? ptr_msb_sandbox_start(cancel_id, name, detached, buf, buf_len) : NULL;
}
char *call_msb_sandbox_handle_stop(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) {
	return ptr_msb_sandbox_handle_stop ? ptr_msb_sandbox_handle_stop(cancel_id, name, buf, buf_len) : NULL;
}
char *call_msb_sandbox_handle_kill(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) {
	return ptr_msb_sandbox_handle_kill ? ptr_msb_sandbox_handle_kill(cancel_id, name, buf, buf_len) : NULL;
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
char *call_msb_fs_mkdir(uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len) {
	return ptr_msb_fs_mkdir ? ptr_msb_fs_mkdir(cancel_id, handle, path, buf, buf_len) : NULL;
}
char *call_msb_fs_remove(uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len) {
	return ptr_msb_fs_remove ? ptr_msb_fs_remove(cancel_id, handle, path, buf, buf_len) : NULL;
}
char *call_msb_fs_remove_dir(uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len) {
	return ptr_msb_fs_remove_dir ? ptr_msb_fs_remove_dir(cancel_id, handle, path, buf, buf_len) : NULL;
}
char *call_msb_fs_copy(uint64_t cancel_id, uint64_t handle, const char *src, const char *dst, uint8_t *buf, size_t buf_len) {
	return ptr_msb_fs_copy ? ptr_msb_fs_copy(cancel_id, handle, src, dst, buf, buf_len) : NULL;
}
char *call_msb_fs_rename(uint64_t cancel_id, uint64_t handle, const char *src, const char *dst, uint8_t *buf, size_t buf_len) {
	return ptr_msb_fs_rename ? ptr_msb_fs_rename(cancel_id, handle, src, dst, buf, buf_len) : NULL;
}
char *call_msb_fs_exists(uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len) {
	return ptr_msb_fs_exists ? ptr_msb_fs_exists(cancel_id, handle, path, buf, buf_len) : NULL;
}
char *call_msb_sandbox_metrics_stream(uint64_t cancel_id, uint64_t handle, uint64_t interval_ms, uint8_t *buf, size_t buf_len) {
	return ptr_msb_sandbox_metrics_stream ? ptr_msb_sandbox_metrics_stream(cancel_id, handle, interval_ms, buf, buf_len) : NULL;
}
char *call_msb_metrics_recv(uint64_t cancel_id, uint64_t stream_handle, uint8_t *buf, size_t buf_len) {
	return ptr_msb_metrics_recv ? ptr_msb_metrics_recv(cancel_id, stream_handle, buf, buf_len) : NULL;
}
char *call_msb_metrics_close(uint64_t stream_handle, uint8_t *buf, size_t buf_len) {
	return ptr_msb_metrics_close ? ptr_msb_metrics_close(stream_handle, buf, buf_len) : NULL;
}
char *call_msb_exec_stdin_write(uint64_t cancel_id, uint64_t exec_handle, const char *data_b64, uint8_t *buf, size_t buf_len) {
	return ptr_msb_exec_stdin_write ? ptr_msb_exec_stdin_write(cancel_id, exec_handle, data_b64, buf, buf_len) : NULL;
}
char *call_msb_exec_stdin_close(uint64_t cancel_id, uint64_t exec_handle, uint8_t *buf, size_t buf_len) {
	return ptr_msb_exec_stdin_close ? ptr_msb_exec_stdin_close(cancel_id, exec_handle, buf, buf_len) : NULL;
}
char *call_msb_sandbox_drain(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) {
	return ptr_msb_sandbox_drain ? ptr_msb_sandbox_drain(cancel_id, handle, buf, buf_len) : NULL;
}
char *call_msb_sandbox_wait(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) {
	return ptr_msb_sandbox_wait ? ptr_msb_sandbox_wait(cancel_id, handle, buf, buf_len) : NULL;
}
char *call_msb_sandbox_owns_lifecycle(uint64_t handle, uint8_t *buf, size_t buf_len) {
	return ptr_msb_sandbox_owns_lifecycle ? ptr_msb_sandbox_owns_lifecycle(handle, buf, buf_len) : NULL;
}
char *call_msb_exec_collect(uint64_t cancel_id, uint64_t exec_handle, uint8_t *buf, size_t buf_len) {
	return ptr_msb_exec_collect ? ptr_msb_exec_collect(cancel_id, exec_handle, buf, buf_len) : NULL;
}
char *call_msb_exec_wait(uint64_t cancel_id, uint64_t exec_handle, uint8_t *buf, size_t buf_len) {
	return ptr_msb_exec_wait ? ptr_msb_exec_wait(cancel_id, exec_handle, buf, buf_len) : NULL;
}
char *call_msb_exec_kill(uint64_t cancel_id, uint64_t exec_handle, uint8_t *buf, size_t buf_len) {
	return ptr_msb_exec_kill ? ptr_msb_exec_kill(cancel_id, exec_handle, buf, buf_len) : NULL;
}
char *call_msb_exec_id(uint64_t exec_handle, uint8_t *buf, size_t buf_len) {
	return ptr_msb_exec_id ? ptr_msb_exec_id(exec_handle, buf, buf_len) : NULL;
}
char *call_msb_sandbox_attach(uint64_t cancel_id, uint64_t handle, const char *cmd, const char *opts_json, uint8_t *buf, size_t buf_len) {
	return ptr_msb_sandbox_attach ? ptr_msb_sandbox_attach(cancel_id, handle, cmd, opts_json, buf, buf_len) : NULL;
}
char *call_msb_sandbox_attach_shell(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) {
	return ptr_msb_sandbox_attach_shell ? ptr_msb_sandbox_attach_shell(cancel_id, handle, buf, buf_len) : NULL;
}
char *call_msb_sandbox_remove_persisted(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) {
	return ptr_msb_sandbox_remove_persisted ? ptr_msb_sandbox_remove_persisted(cancel_id, handle, buf, buf_len) : NULL;
}
char *call_msb_all_sandbox_metrics(uint64_t cancel_id, uint8_t *buf, size_t buf_len) {
	return ptr_msb_all_sandbox_metrics ? ptr_msb_all_sandbox_metrics(cancel_id, buf, buf_len) : NULL;
}
char *call_msb_sandbox_handle_metrics(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) {
	return ptr_msb_sandbox_handle_metrics ? ptr_msb_sandbox_handle_metrics(cancel_id, name, buf, buf_len) : NULL;
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
char *call_msb_volume_get(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) {
	return ptr_msb_volume_get ? ptr_msb_volume_get(cancel_id, name, buf, buf_len) : NULL;
}
char *call_msb_fs_read_stream(uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len) {
	return ptr_msb_fs_read_stream ? ptr_msb_fs_read_stream(cancel_id, handle, path, buf, buf_len) : NULL;
}
char *call_msb_fs_read_stream_recv(uint64_t cancel_id, uint64_t stream_handle, uint8_t *buf, size_t buf_len) {
	return ptr_msb_fs_read_stream_recv ? ptr_msb_fs_read_stream_recv(cancel_id, stream_handle, buf, buf_len) : NULL;
}
char *call_msb_fs_read_stream_close(uint64_t stream_handle, uint8_t *buf, size_t buf_len) {
	return ptr_msb_fs_read_stream_close ? ptr_msb_fs_read_stream_close(stream_handle, buf, buf_len) : NULL;
}
char *call_msb_fs_write_stream(uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len) {
	return ptr_msb_fs_write_stream ? ptr_msb_fs_write_stream(cancel_id, handle, path, buf, buf_len) : NULL;
}
char *call_msb_fs_write_stream_write(uint64_t cancel_id, uint64_t stream_handle, const char *data_b64, uint8_t *buf, size_t buf_len) {
	return ptr_msb_fs_write_stream_write ? ptr_msb_fs_write_stream_write(cancel_id, stream_handle, data_b64, buf, buf_len) : NULL;
}
char *call_msb_fs_write_stream_close(uint64_t cancel_id, uint64_t stream_handle, uint8_t *buf, size_t buf_len) {
	return ptr_msb_fs_write_stream_close ? ptr_msb_fs_write_stream_close(cancel_id, stream_handle, buf, buf_len) : NULL;
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
	"sync/atomic"
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
	KindFilesystem          = "filesystem"
	KindImageNotFound       = "image_not_found"
	KindImageInUse          = "image_in_use"
	KindPatchFailed         = "patch_failed"
	KindIO                  = "io"
)

// Sandbox is an opaque handle to a Rust-side sandbox. Call Close to release.
// Safe for concurrent use from multiple goroutines; Close uses an atomic
// swap so concurrent Close calls produce exactly one Rust-side release.
type Sandbox struct {
	handle atomic.Uint64
	name   string
}

// Handle returns the underlying integer handle (for debugging only). Returns
// 0 after Close.
func (s *Sandbox) Handle() uint64 { return s.handle.Load() }

// h returns the handle as C.uint64_t for passing to Rust. Callers that must
// distinguish "handle already closed" from "Rust-side not found" should check
// for zero before invoking the FFI; otherwise Rust will return InvalidHandle.
func (s *Sandbox) h() C.uint64_t { return C.uint64_t(s.handle.Load()) }

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

// salvageHandle attempts a best-effort recovery of the `handle` field from a
// create/connect response body when strict unmarshalling failed. Returns 0
// if the handle cannot be recovered. Used to avoid leaking Rust-side state
// in pathological cases where the Rust response is non-empty but malformed.
func salvageHandle(body string) uint64 {
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return 0
	}
	switch v := m["handle"].(type) {
	case float64:
		if v <= 0 {
			return 0
		}
		return uint64(v)
	case json.Number:
		n, err := v.Int64()
		if err != nil || n <= 0 {
			return 0
		}
		return uint64(n)
	default:
		return 0
	}
}

// releaseHandle best-effort closes a Rust-side sandbox handle without going
// through a *Sandbox wrapper. Used to clean up after a create/connect
// response that could not be decoded. Uses context.Background so the
// caller's cancelled ctx cannot prevent cleanup.
func releaseHandle(handle uint64) {
	_, _ = call(context.Background(), func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_sandbox_close(cancelID, C.uint64_t(handle), buf, bufLen)
	})
}

// =============================================================================
// Sandbox lifecycle
// =============================================================================

// CreateOptions matches the JSON payload shape expected by msb_sandbox_create.
// Zero-valued fields are omitted; the Rust side applies defaults.
type CreateOptions struct {
	Image     string               `json:"image,omitempty"`
	MemoryMiB uint32               `json:"memory_mib,omitempty"`
	CPUs      uint8                `json:"cpus,omitempty"`
	Workdir   string               `json:"workdir,omitempty"`
	Hostname  string               `json:"hostname,omitempty"`
	User      string               `json:"user,omitempty"`
	Replace   bool                 `json:"replace,omitempty"`
	Env       map[string]string    `json:"env,omitempty"`
	Detached  bool                 `json:"detached,omitempty"`
	Ports     map[uint16]uint16    `json:"ports,omitempty"`
	Network   *NetworkOptions      `json:"network,omitempty"`
	Secrets   []SecretOptions      `json:"secrets,omitempty"`
	Patches   []PatchOptions       `json:"patches,omitempty"`
	Volumes   map[string]MountSpec `json:"volumes,omitempty"`
}

// MountSpec describes a volume mount for a sandbox.
type MountSpec struct {
	Bind     string `json:"bind,omitempty"`
	Named    string `json:"named,omitempty"`
	Tmpfs    bool   `json:"tmpfs,omitempty"`
	Readonly bool   `json:"readonly,omitempty"`
	SizeMiB  uint32 `json:"size_mib,omitempty"`
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
		// Rust has allocated a handle we can no longer trust. Best-effort
		// recover the handle from the response so we can release it;
		// otherwise the VM and registry entry would leak.
		if h := salvageHandle(out); h != 0 {
			releaseHandle(h)
		}
		return nil, fmt.Errorf("parse create response: %w", err)
	}
	s := &Sandbox{name: name}
	s.handle.Store(resp.Handle)
	return s, nil
}

// ConnectSandbox reattaches to an existing sandbox by name and returns a
// live Sandbox. Returns an Error with Kind==KindSandboxNotFound if no such
// sandbox exists.
func ConnectSandbox(ctx context.Context, name string) (*Sandbox, error) {
	if err := ensureLoaded(); err != nil {
		return nil, err
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	out, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_sandbox_connect(cancelID, cName, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Handle uint64 `json:"handle"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		if h := salvageHandle(out); h != 0 {
			releaseHandle(h)
		}
		return nil, fmt.Errorf("parse connect response: %w", err)
	}
	s := &Sandbox{name: name}
	s.handle.Store(resp.Handle)
	return s, nil
}

// SandboxHandleInfo is the JSON payload returned by LookupSandbox.
type SandboxHandleInfo struct {
	Name          string `json:"name"`
	Status        string `json:"status"`
	ConfigJSON    string `json:"config_json"`
	CreatedAtUnix *int64 `json:"created_at_unix"`
	UpdatedAtUnix *int64 `json:"updated_at_unix"`
}

// LookupSandbox fetches the persisted metadata for a sandbox by name without
// connecting.
func LookupSandbox(ctx context.Context, name string) (*SandboxHandleInfo, error) {
	if err := ensureLoaded(); err != nil {
		return nil, err
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	out, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_sandbox_lookup(cancelID, cName, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var info SandboxHandleInfo
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		return nil, fmt.Errorf("parse lookup response: %w", err)
	}
	return &info, nil
}

// StartSandbox boots a persisted sandbox and returns a live Sandbox.
// `detached==true` leaves the VM running after the handle is released.
func StartSandbox(ctx context.Context, name string, detached bool) (*Sandbox, error) {
	if err := ensureLoaded(); err != nil {
		return nil, err
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	out, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_sandbox_start(cancelID, cName, C.bool(detached), buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Handle uint64 `json:"handle"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		if h := salvageHandle(out); h != 0 {
			releaseHandle(h)
		}
		return nil, fmt.Errorf("parse start response: %w", err)
	}
	s := &Sandbox{name: name}
	s.handle.Store(resp.Handle)
	return s, nil
}

// StopSandboxByName gracefully stops a sandbox identified by name.
func StopSandboxByName(ctx context.Context, name string) error {
	if err := ensureLoaded(); err != nil {
		return err
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	_, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_sandbox_handle_stop(cancelID, cName, buf, bufLen)
	})
	return err
}

// KillSandboxByName terminates a sandbox identified by name.
func KillSandboxByName(ctx context.Context, name string) error {
	if err := ensureLoaded(); err != nil {
		return err
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	_, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_sandbox_handle_kill(cancelID, cName, buf, bufLen)
	})
	return err
}

// Drain triggers graceful drain (SIGUSR1) on the sandbox.
func (s *Sandbox) Drain(ctx context.Context) error {
	if err := ensureLoaded(); err != nil {
		return err
	}
	_, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_sandbox_drain(cancelID, s.h(), buf, bufLen)
	})
	return err
}

// Wait blocks until the sandbox process exits. Returns the exit code or -1.
func (s *Sandbox) Wait(ctx context.Context) (int, error) {
	if err := ensureLoaded(); err != nil {
		return 0, err
	}
	out, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_sandbox_wait(cancelID, s.h(), buf, bufLen)
	})
	if err != nil {
		return 0, err
	}
	var resp struct {
		ExitCode *int `json:"exit_code"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return 0, fmt.Errorf("parse wait response: %w", err)
	}
	if resp.ExitCode == nil {
		return -1, nil
	}
	return *resp.ExitCode, nil
}

// OwnsLifecycle reports whether this handle owns the sandbox VM lifecycle.
// When true, closing or stopping the handle terminates the sandbox.
func (s *Sandbox) OwnsLifecycle() (bool, error) {
	if err := ensureLoaded(); err != nil {
		return false, err
	}
	buf := make([]byte, defaultBufSize)
	errPtr := C.call_msb_sandbox_owns_lifecycle(s.h(), (*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if errPtr != nil {
		msg := C.GoString(errPtr)
		C.call_msb_free_string(errPtr)
		var e Error
		if jerr := json.Unmarshal([]byte(msg), &e); jerr != nil {
			e = Error{Kind: KindInternal, Message: msg}
		}
		return false, &e
	}
	end := 0
	for end < len(buf) && buf[end] != 0 {
		end++
	}
	var resp struct {
		Owns bool `json:"owns"`
	}
	if err := json.Unmarshal(buf[:end], &resp); err != nil {
		return false, fmt.Errorf("parse owns_lifecycle response: %w", err)
	}
	return resp.Owns, nil
}

// Close releases the Rust-side sandbox resources for this handle. Safe to
// call multiple times and from multiple goroutines — the atomic swap below
// guarantees exactly one Rust-side release; all other callers get a
// synthetic KindInvalidHandle without touching Rust. Uses context.Background
// so cleanup cannot be cancelled; use CloseCtx for a caller-controlled
// timeout.
func (s *Sandbox) Close() error {
	return s.CloseCtx(context.Background())
}

// CloseCtx is Close with a caller-controlled context.
func (s *Sandbox) CloseCtx(ctx context.Context) error {
	if err := ensureLoaded(); err != nil {
		return err
	}
	// Atomically claim the handle: only the goroutine that observes a
	// non-zero prior value is allowed to call the Rust destructor.
	h := s.handle.Swap(0)
	if h == 0 {
		return &Error{Kind: KindInvalidHandle, Message: "sandbox handle already closed"}
	}
	_, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_sandbox_close(cancelID, C.uint64_t(h), buf, bufLen)
	})
	return err
}

// Detach releases the handle without stopping the VM. Use on sandboxes
// created with Detached==true when the caller is done but the VM should
// keep running. After Detach the handle is invalid. Safe for concurrent
// use — the atomic swap ensures exactly one call reaches Rust.
func (s *Sandbox) Detach(ctx context.Context) error {
	if err := ensureLoaded(); err != nil {
		return err
	}
	h := s.handle.Swap(0)
	if h == 0 {
		return &Error{Kind: KindInvalidHandle, Message: "sandbox handle already closed"}
	}
	_, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_sandbox_detach(cancelID, C.uint64_t(h), buf, bufLen)
	})
	return err
}

// Stop gracefully stops the sandbox without waiting for exit.
func (s *Sandbox) Stop(ctx context.Context) error {
	if err := ensureLoaded(); err != nil {
		return err
	}
	_, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_sandbox_stop(cancelID, s.h(), buf, bufLen)
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
		return C.call_msb_sandbox_stop_and_wait(cancelID, s.h(), buf, bufLen)
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
		return C.call_msb_sandbox_kill(cancelID, s.h(), buf, bufLen)
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
	Args        []string          `json:"args,omitempty"`
	Cwd         string            `json:"cwd,omitempty"`
	TimeoutSecs uint64            `json:"timeout_secs,omitempty"`
	StdinPipe   bool              `json:"stdin_pipe,omitempty"`
	User        string            `json:"user,omitempty"`
	Env         map[string]string `json:"env,omitempty"`
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
		return C.call_msb_sandbox_exec(cancelID, s.h(), cCmd, cOpts, buf, bufLen)
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

// ExecSink is a write-only sink for sending data to a running process's stdin.
// Obtain via ExecStreamHandle.TakeStdin. Implements io.WriteCloser.
type ExecSink struct {
	execHandle C.uint64_t
}

// Write sends data to the process stdin. Implements io.Writer.
func (sk *ExecSink) Write(p []byte) (int, error) {
	if err := ensureLoaded(); err != nil {
		return 0, err
	}
	encoded := base64.StdEncoding.EncodeToString(p)
	cData := C.CString(encoded)
	defer C.free(unsafe.Pointer(cData))

	_, err := call(context.Background(), func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_exec_stdin_write(cancelID, sk.execHandle, cData, buf, bufLen)
	})
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// WriteCtx is Write with a caller-controlled context.
func (sk *ExecSink) WriteCtx(ctx context.Context, p []byte) (int, error) {
	if err := ensureLoaded(); err != nil {
		return 0, err
	}
	encoded := base64.StdEncoding.EncodeToString(p)
	cData := C.CString(encoded)
	defer C.free(unsafe.Pointer(cData))

	_, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_exec_stdin_write(cancelID, sk.execHandle, cData, buf, bufLen)
	})
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close closes the stdin pipe. Implements io.Closer.
func (sk *ExecSink) Close() error {
	if err := ensureLoaded(); err != nil {
		return err
	}
	_, err := call(context.Background(), func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_exec_stdin_close(cancelID, sk.execHandle, buf, bufLen)
	})
	return err
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
		return C.call_msb_sandbox_exec_stream(cancelID, s.h(), cCmd, cOpts, buf, bufLen)
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

// TakeStdin returns a sink for writing to the process's stdin. Only valid when
// the exec session was started with StdinPipe==true. Returns nil otherwise.
// The sink is valid until the exec session is closed.
func (h *ExecStreamHandle) TakeStdin() *ExecSink {
	return &ExecSink{execHandle: h.handle}
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
		return C.call_msb_sandbox_metrics(cancelID, s.h(), buf, bufLen)
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
// Metrics streaming
// =============================================================================

// MetricsStreamHandle is an opaque reference to a running metrics stream.
// Call Close to release Rust-side resources and stop the background task.
type MetricsStreamHandle struct {
	handle C.uint64_t
}

// MetricsStreamSandbox starts a metrics stream that emits a snapshot every interval.
// intervalMs==0 uses the minimum interval (1ms). Returns a handle that must be
// closed with MetricsStreamHandle.Close.
func (s *Sandbox) MetricsStream(ctx context.Context, intervalMs uint64) (*MetricsStreamHandle, error) {
	if err := ensureLoaded(); err != nil {
		return nil, err
	}
	out, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_sandbox_metrics_stream(cancelID, s.h(), C.uint64_t(intervalMs), buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var resp struct {
		StreamHandle uint64 `json:"stream_handle"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return nil, fmt.Errorf("parse metrics_stream response: %w", err)
	}
	return &MetricsStreamHandle{handle: C.uint64_t(resp.StreamHandle)}, nil
}

// Recv blocks until the next metrics snapshot is available or the context is cancelled.
// Returns nil when the stream has ended (the sandbox exited).
func (h *MetricsStreamHandle) Recv(ctx context.Context) (*Metrics, error) {
	if err := ensureLoaded(); err != nil {
		return nil, err
	}
	out, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_metrics_recv(cancelID, h.handle, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var raw struct {
		Done             bool    `json:"done"`
		CPUPercent       float64 `json:"cpu_percent"`
		MemoryBytes      uint64  `json:"memory_bytes"`
		MemoryLimitBytes uint64  `json:"memory_limit_bytes"`
		DiskReadBytes    uint64  `json:"disk_read_bytes"`
		DiskWriteBytes   uint64  `json:"disk_write_bytes"`
		NetRxBytes       uint64  `json:"net_rx_bytes"`
		NetTxBytes       uint64  `json:"net_tx_bytes"`
		UptimeSecs       uint64  `json:"uptime_secs"`
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, fmt.Errorf("parse metrics_recv: %w", err)
	}
	if raw.Done {
		return nil, nil
	}
	m := &Metrics{
		CPUPercent:       raw.CPUPercent,
		MemoryBytes:      raw.MemoryBytes,
		MemoryLimitBytes: raw.MemoryLimitBytes,
		DiskReadBytes:    raw.DiskReadBytes,
		DiskWriteBytes:   raw.DiskWriteBytes,
		NetRxBytes:       raw.NetRxBytes,
		NetTxBytes:       raw.NetTxBytes,
		UptimeSecs:       raw.UptimeSecs,
		Uptime:           time.Duration(raw.UptimeSecs) * time.Second,
	}
	return m, nil
}

// Close drops the stream handle. The background Rust task stops when the
// channel is closed.
func (h *MetricsStreamHandle) Close() error {
	if err := ensureLoaded(); err != nil {
		return err
	}
	buf := make([]byte, defaultBufSize)
	errPtr := C.call_msb_metrics_close(h.handle, (*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if errPtr != nil {
		msg := C.GoString(errPtr)
		C.call_msb_free_string(errPtr)
		var e Error
		if jerr := json.Unmarshal([]byte(msg), &e); jerr != nil {
			e = Error{Kind: KindInternal, Message: msg}
		}
		return &e
	}
	return nil
}

// =============================================================================
// Exec — collect / wait / kill

// Collect drains a streaming exec session and returns its full output.
func (h *ExecStreamHandle) Collect(ctx context.Context) (*ExecResult, error) {
	if err := ensureLoaded(); err != nil {
		return nil, err
	}
	out, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_exec_collect(cancelID, h.handle, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var resp struct {
		StdoutB64 string `json:"stdout_b64"`
		StderrB64 string `json:"stderr_b64"`
		ExitCode  int    `json:"exit_code"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return nil, fmt.Errorf("parse exec_collect: %w", err)
	}
	stdout, _ := base64.StdEncoding.DecodeString(resp.StdoutB64)
	stderr, _ := base64.StdEncoding.DecodeString(resp.StderrB64)
	return &ExecResult{Stdout: string(stdout), Stderr: string(stderr), ExitCode: resp.ExitCode}, nil
}

// Wait blocks until the exec process exits and returns its exit code.
func (h *ExecStreamHandle) Wait(ctx context.Context) (int, error) {
	if err := ensureLoaded(); err != nil {
		return -1, err
	}
	out, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_exec_wait(cancelID, h.handle, buf, bufLen)
	})
	if err != nil {
		return -1, err
	}
	var resp struct {
		ExitCode int `json:"exit_code"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return -1, fmt.Errorf("parse exec_wait: %w", err)
	}
	return resp.ExitCode, nil
}

// ID returns the internal protocol ID for this exec session.
func (h *ExecStreamHandle) ID() (string, error) {
	if err := ensureLoaded(); err != nil {
		return "", err
	}
	buf := make([]byte, defaultBufSize)
	errPtr := C.call_msb_exec_id(h.handle, (*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if errPtr != nil {
		msg := C.GoString(errPtr)
		C.call_msb_free_string(errPtr)
		var e Error
		if jerr := json.Unmarshal([]byte(msg), &e); jerr != nil {
			e = Error{Kind: KindInternal, Message: msg}
		}
		return "", &e
	}
	out := C.GoString((*C.char)(unsafe.Pointer(&buf[0])))
	var resp struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return "", fmt.Errorf("parse exec_id: %w", err)
	}
	return resp.ID, nil
}

// Kill sends SIGKILL to the running exec process.
func (h *ExecStreamHandle) Kill(ctx context.Context) error {
	if err := ensureLoaded(); err != nil {
		return err
	}
	_, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_exec_kill(cancelID, h.handle, buf, bufLen)
	})
	return err
}

// =============================================================================
// Attach

// Attach starts an interactive PTY session running cmd with args.
// It blocks until the process exits and returns the exit code.
func (s *Sandbox) Attach(ctx context.Context, cmd string, args []string) (int, error) {
	if err := ensureLoaded(); err != nil {
		return -1, err
	}
	type optsJSON struct {
		Args []string `json:"args,omitempty"`
	}
	optsBytes, err := json.Marshal(optsJSON{Args: args})
	if err != nil {
		return -1, fmt.Errorf("marshal attach opts: %w", err)
	}
	cCmd := C.CString(cmd)
	defer C.free(unsafe.Pointer(cCmd))
	cOpts := C.CString(string(optsBytes))
	defer C.free(unsafe.Pointer(cOpts))
	out, err2 := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_sandbox_attach(cancelID, s.h(), cCmd, cOpts, buf, bufLen)
	})
	if err2 != nil {
		return -1, err2
	}
	var resp struct {
		ExitCode int `json:"exit_code"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return -1, fmt.Errorf("parse attach response: %w", err)
	}
	return resp.ExitCode, nil
}

// AttachShell starts an interactive PTY session in the sandbox's default shell.
// It blocks until the shell exits and returns the exit code.
func (s *Sandbox) AttachShell(ctx context.Context) (int, error) {
	if err := ensureLoaded(); err != nil {
		return -1, err
	}
	out, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_sandbox_attach_shell(cancelID, s.h(), buf, bufLen)
	})
	if err != nil {
		return -1, err
	}
	var resp struct {
		ExitCode int `json:"exit_code"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return -1, fmt.Errorf("parse attach_shell response: %w", err)
	}
	return resp.ExitCode, nil
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
func (s *FsStat) IsDir() bool { return s.Kind == "directory" }

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
		return C.call_msb_fs_read(cancelID, s.h(), cPath, buf, bufLen)
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
		return C.call_msb_fs_write(cancelID, s.h(), cPath, cData, buf, bufLen)
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
		return C.call_msb_fs_list(cancelID, s.h(), cPath, buf, bufLen)
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
		return C.call_msb_fs_stat(cancelID, s.h(), cPath, buf, bufLen)
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
		return C.call_msb_fs_copy_from_host(cancelID, s.h(), cHost, cGuest, buf, bufLen)
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
		return C.call_msb_fs_copy_to_host(cancelID, s.h(), cGuest, cHost, buf, bufLen)
	})
	return err
}

// FsMkdir creates a directory (and any missing parents) inside the sandbox.
func (s *Sandbox) FsMkdir(ctx context.Context, path string) error {
	if err := ensureLoaded(); err != nil {
		return err
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	_, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_fs_mkdir(cancelID, s.h(), cPath, buf, bufLen)
	})
	return err
}

// FsRemove deletes a single file from the sandbox. Use FsRemoveDir for directories.
func (s *Sandbox) FsRemove(ctx context.Context, path string) error {
	if err := ensureLoaded(); err != nil {
		return err
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	_, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_fs_remove(cancelID, s.h(), cPath, buf, bufLen)
	})
	return err
}

// FsRemoveDir removes a directory recursively.
func (s *Sandbox) FsRemoveDir(ctx context.Context, path string) error {
	if err := ensureLoaded(); err != nil {
		return err
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	_, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_fs_remove_dir(cancelID, s.h(), cPath, buf, bufLen)
	})
	return err
}

// FsCopy copies a file within the sandbox.
func (s *Sandbox) FsCopy(ctx context.Context, src, dst string) error {
	if err := ensureLoaded(); err != nil {
		return err
	}
	cSrc := C.CString(src)
	defer C.free(unsafe.Pointer(cSrc))
	cDst := C.CString(dst)
	defer C.free(unsafe.Pointer(cDst))

	_, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_fs_copy(cancelID, s.h(), cSrc, cDst, buf, bufLen)
	})
	return err
}

// FsRename renames (or moves) a file or directory within the sandbox.
func (s *Sandbox) FsRename(ctx context.Context, src, dst string) error {
	if err := ensureLoaded(); err != nil {
		return err
	}
	cSrc := C.CString(src)
	defer C.free(unsafe.Pointer(cSrc))
	cDst := C.CString(dst)
	defer C.free(unsafe.Pointer(cDst))

	_, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_fs_rename(cancelID, s.h(), cSrc, cDst, buf, bufLen)
	})
	return err
}

// FsExists reports whether a file or directory exists at the given path.
func (s *Sandbox) FsExists(ctx context.Context, path string) (bool, error) {
	if err := ensureLoaded(); err != nil {
		return false, err
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	out, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_fs_exists(cancelID, s.h(), cPath, buf, bufLen)
	})
	if err != nil {
		return false, err
	}
	var resp struct {
		Exists bool `json:"exists"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return false, fmt.Errorf("parse fs_exists: %w", err)
	}
	return resp.Exists, nil
}

// =============================================================================
// Sandbox extras — RemovePersisted, AllSandboxMetrics, SandboxHandleMetrics
// =============================================================================

// RemovePersisted removes the sandbox's persisted state (DB record + filesystem).
// The sandbox must be stopped. The live handle is consumed.
func (s *Sandbox) RemovePersisted(ctx context.Context) error {
	if err := ensureLoaded(); err != nil {
		return err
	}
	_, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_sandbox_remove_persisted(cancelID, s.h(), buf, bufLen)
	})
	return err
}

// AllSandboxMetrics returns a snapshot of resource usage for every running sandbox.
func AllSandboxMetrics(ctx context.Context) (map[string]*Metrics, error) {
	if err := ensureLoaded(); err != nil {
		return nil, err
	}
	out, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_all_sandbox_metrics(cancelID, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Sandboxes map[string]*Metrics `json:"sandboxes"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return nil, fmt.Errorf("parse all_sandbox_metrics: %w", err)
	}
	return resp.Sandboxes, nil
}

// SandboxHandleMetrics returns a point-in-time metrics snapshot for a sandbox
// identified by name. The sandbox must be running or draining.
func SandboxHandleMetrics(ctx context.Context, name string) (*Metrics, error) {
	if err := ensureLoaded(); err != nil {
		return nil, err
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	out, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_sandbox_handle_metrics(cancelID, cName, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var raw struct {
		CPUPercent       float64 `json:"cpu_percent"`
		MemoryBytes      uint64  `json:"memory_bytes"`
		MemoryLimitBytes uint64  `json:"memory_limit_bytes"`
		DiskReadBytes    uint64  `json:"disk_read_bytes"`
		DiskWriteBytes   uint64  `json:"disk_write_bytes"`
		NetRxBytes       uint64  `json:"net_rx_bytes"`
		NetTxBytes       uint64  `json:"net_tx_bytes"`
		UptimeSecs       uint64  `json:"uptime_secs"`
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, fmt.Errorf("parse sandbox_handle_metrics: %w", err)
	}
	return &Metrics{
		CPUPercent:       raw.CPUPercent,
		MemoryBytes:      raw.MemoryBytes,
		MemoryLimitBytes: raw.MemoryLimitBytes,
		DiskReadBytes:    raw.DiskReadBytes,
		DiskWriteBytes:   raw.DiskWriteBytes,
		NetRxBytes:       raw.NetRxBytes,
		NetTxBytes:       raw.NetTxBytes,
		UptimeSecs:       raw.UptimeSecs,
		Uptime:           time.Duration(raw.UptimeSecs) * time.Second,
	}, nil
}

// =============================================================================
// Filesystem streaming — FsReadStreamHandle / FsWriteStreamHandle
// =============================================================================

// FsReadStreamHandle is an open read stream from a guest file.
type FsReadStreamHandle struct {
	handle C.uint64_t
}

// Recv returns the next chunk, or nil when EOF.
func (h *FsReadStreamHandle) Recv(ctx context.Context) ([]byte, error) {
	if err := ensureLoaded(); err != nil {
		return nil, err
	}
	out, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_fs_read_stream_recv(cancelID, h.handle, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Done    bool   `json:"done"`
		ChunkB64 string `json:"chunk_b64"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return nil, fmt.Errorf("parse fs_read_stream_recv: %w", err)
	}
	if resp.Done {
		return nil, nil
	}
	chunk, err := base64.StdEncoding.DecodeString(resp.ChunkB64)
	if err != nil {
		return nil, fmt.Errorf("decode fs chunk: %w", err)
	}
	return chunk, nil
}

// Close releases the read stream handle.
func (h *FsReadStreamHandle) Close() error {
	if err := ensureLoaded(); err != nil {
		return err
	}
	buf := make([]byte, defaultBufSize)
	errPtr := C.call_msb_fs_read_stream_close(h.handle, (*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if errPtr != nil {
		msg := C.GoString(errPtr)
		C.call_msb_free_string(errPtr)
		var e Error
		if jerr := json.Unmarshal([]byte(msg), &e); jerr != nil {
			e = Error{Kind: KindInternal, Message: msg}
		}
		return &e
	}
	return nil
}

// FsReadStream opens a streaming read from a guest file.
func (s *Sandbox) FsReadStream(ctx context.Context, path string) (*FsReadStreamHandle, error) {
	if err := ensureLoaded(); err != nil {
		return nil, err
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	out, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_fs_read_stream(cancelID, s.h(), cPath, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var resp struct {
		StreamHandle uint64 `json:"stream_handle"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return nil, fmt.Errorf("parse fs_read_stream: %w", err)
	}
	return &FsReadStreamHandle{handle: C.uint64_t(resp.StreamHandle)}, nil
}

// FsWriteStreamHandle is an open write stream to a guest file.
type FsWriteStreamHandle struct {
	handle C.uint64_t
}

// Write sends a chunk of data to the guest file.
func (h *FsWriteStreamHandle) Write(ctx context.Context, data []byte) error {
	if err := ensureLoaded(); err != nil {
		return err
	}
	b64 := base64.StdEncoding.EncodeToString(data)
	cData := C.CString(b64)
	defer C.free(unsafe.Pointer(cData))
	_, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_fs_write_stream_write(cancelID, h.handle, cData, buf, bufLen)
	})
	return err
}

// Close finalises the write (sends EOF) and waits for confirmation.
func (h *FsWriteStreamHandle) Close(ctx context.Context) error {
	if err := ensureLoaded(); err != nil {
		return err
	}
	_, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_fs_write_stream_close(cancelID, h.handle, buf, bufLen)
	})
	return err
}

// FsWriteStream opens a streaming write to a guest file.
func (s *Sandbox) FsWriteStream(ctx context.Context, path string) (*FsWriteStreamHandle, error) {
	if err := ensureLoaded(); err != nil {
		return nil, err
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	out, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_fs_write_stream(cancelID, s.h(), cPath, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var resp struct {
		StreamHandle uint64 `json:"stream_handle"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return nil, fmt.Errorf("parse fs_write_stream: %w", err)
	}
	return &FsWriteStreamHandle{handle: C.uint64_t(resp.StreamHandle)}, nil
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

// VolumeHandleInfo carries metadata for a volume returned by GetVolume.
type VolumeHandleInfo struct {
	Name          string
	Path          string
	QuotaMiB      *uint32
	UsedBytes     uint64
	Labels        map[string]string
	CreatedAtUnix *int64
}

// GetVolume looks up a volume by name and returns its metadata.
func GetVolume(ctx context.Context, name string) (*VolumeHandleInfo, error) {
	if err := ensureLoaded(); err != nil {
		return nil, err
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	out, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_volume_get(cancelID, cName, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var raw struct {
		Name          string            `json:"name"`
		Path          string            `json:"path"`
		QuotaMiB      *uint32           `json:"quota_mib"`
		UsedBytes     uint64            `json:"used_bytes"`
		Labels        map[string]string `json:"labels"`
		CreatedAtUnix *int64            `json:"created_at_unix"`
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, fmt.Errorf("parse volume_get: %w", err)
	}
	return &VolumeHandleInfo{
		Name:          raw.Name,
		Path:          raw.Path,
		QuotaMiB:      raw.QuotaMiB,
		UsedBytes:     raw.UsedBytes,
		Labels:        raw.Labels,
		CreatedAtUnix: raw.CreatedAtUnix,
	}, nil
}

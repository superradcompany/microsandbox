// Package ffi is the CGO bridge from the Go SDK to the microsandbox Rust
// library. It is NOT stable and must not be imported from outside this module.
//
// # Architecture
//
// The library is loaded at runtime via dlopen/dlsym rather than linked at
// build time. This means `go build` succeeds with no Rust toolchain on the
// host — the library bytes are embedded in the SDK (see internal/bundle)
// and extracted to disk automatically before the first dlopen.
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
// Most msb_* calls return:
//   - NULL on success, writing a JSON document into the caller's buffer.
//   - A heap-allocated C string (JSON {kind,message}) on failure. The Go
//     side MUST free it with call_msb_free_string immediately after reading.
//
// Raw agent calls (`msb_agent_*`) return scalars and allocated CBOR bodies.
// Snapshot-object owned calls return allocated JSON. Go MUST copy both kinds
// of allocated byte buffer and release them with call_msb_agent_free_bytes.
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
// into a Go-owned buffer; Rust does not retain that pointer. Raw agent byte
// outputs and snapshot-object owned responses are allocated by Rust, copied
// by Go, then released through call_msb_agent_free_bytes.
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
#include <stdbool.h>
#ifdef _WIN32
// Windows has no dlfcn.h: provide dlopen/dlsym/dlerror equivalents via
// LoadLibrary/GetProcAddress (only the subset this file uses: dlopen/dlsym/dlerror
// plus RTLD_NOW/RTLD_LOCAL; no dlclose).
#include <windows.h>
static void *dlopen(const char *path, int mode) {
	(void)mode;
	// path arrives as UTF-8 from Go (it contains the user's home dir, so
	// non-ASCII is routine). LoadLibraryA would decode it in the legacy
	// ANSI codepage and fail on such paths; convert and use the wide API.
	wchar_t wpath[4096];
	if (MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, 4096) == 0) {
		return NULL;
	}
	return (void *)LoadLibraryW(wpath);
}
static void *dlsym(void *handle, const char *symbol) {
	return (void *)(intptr_t)GetProcAddress((HMODULE)handle, symbol);
}
static const char *dlerror(void) {
	static char buf[256];
	DWORD e = GetLastError();
	if (e == 0) {
		return NULL;
	}
	snprintf(buf, sizeof(buf), "windows loader error %lu", (unsigned long)e);
	return buf;
}
#ifndef RTLD_NOW
#define RTLD_NOW 0
#endif
#ifndef RTLD_LOCAL
#define RTLD_LOCAL 0
#endif
#else
#include <dlfcn.h>
#endif
#include <string.h>
#include "provider.h"

// ---------------------------------------------------------------------------
// Function pointer typedefs — one per Rust extern "C" function.
// Keep in sync with sdk/go/native/src/lib.rs and microsandbox_go_ffi.h.
// ---------------------------------------------------------------------------
typedef void     (*msb_free_string_fn)(char *ptr);
typedef void     (*msb_set_sdk_msb_path_fn)(const char *path);
typedef char *(*msb_jobs_fn)(uint64_t cancel_id, uint64_t sandbox, const char *request, uint8_t *buf, size_t buf_len);

typedef uint64_t (*msb_cancel_alloc_fn)(void);
typedef void     (*msb_cancel_trigger_fn)(uint64_t id);
typedef void     (*msb_cancel_unregister_fn)(uint64_t id);
typedef char *(*msb_runtime_setup_fn)(uint64_t cancel_id, const char *operation, const char *config_json, const char *options_json, uint8_t *buf, size_t buf_len);
typedef char *(*msb_default_backend_info_fn)(uint8_t *buf, size_t buf_len);

typedef char *(*msb_sandbox_create_fn)(uint64_t cancel_id, const char *name, const char *opts_json, bool connect_or_create, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_handle_lifecycle_fn)(uint64_t cancel_id, const char *name, const char *expected_id, const char *operation, const char *opts_json, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_lookup_fn)(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_connect_fn)(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_start_fn)(uint64_t cancel_id, const char *name, bool detached, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_handle_stop_fn)(uint64_t cancel_id, const char *name, uint64_t timeout_ms, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_handle_request_stop_fn)(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_handle_kill_fn)(uint64_t cancel_id, const char *name, uint64_t timeout_ms, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_handle_request_kill_fn)(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_handle_request_drain_fn)(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_handle_wait_until_stopped_fn)(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_handle_ping_fn)(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_handle_touch_fn)(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_handle_modify_fn)(uint64_t cancel_id, const char *name, const char *opts_json, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_handle_resize_status_fn)(uint64_t cancel_id, const char *name, const char *expected_id, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_handle_wait_until_resized_fn)(uint64_t cancel_id, const char *name, const char *expected_id, uint64_t timeout_ms, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_close_fn)(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_detach_fn)(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_stop_fn)(uint64_t cancel_id, uint64_t handle, uint64_t timeout_ms, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_stop_gracefully_fn)(uint64_t cancel_id, uint64_t handle, uint8_t has_timeout, uint64_t timeout_ms, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_request_stop_fn)(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_restore_warnings_fn)(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_pause_fn)(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_pause_with_guest_flush_fn)(uint64_t cancel_id, uint64_t handle, const char *source, const char *expected_id, const char *policy, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_branch_fn)(uint64_t cancel_id, uint64_t handle, const char *source, const char *child, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_branch_with_options_fn)(uint64_t cancel_id, uint64_t handle, const char *source, const char *child, bool record_integrity, uint8_t *buf, size_t buf_len);
typedef msb_sandbox_branch_with_options_fn msb_sandbox_branch_many_fn;
typedef char *(*msb_sandbox_resume_fn)(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_handle_pause_fn)(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_handle_resume_fn)(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_kill_fn)(uint64_t cancel_id, uint64_t handle, uint64_t timeout_ms, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_request_kill_fn)(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_list_fn)(uint64_t cancel_id, const char *filter_json, uint8_t *buf, size_t buf_len);
typedef msb_sandbox_list_fn msb_context_create_fn;
typedef char *(*msb_context_operation_fn)(uint64_t, uint64_t, const char *, uint8_t *, size_t);
typedef void (*msb_context_release_fn)(uint64_t);
typedef msb_context_operation_fn msb_resource_operation_fn;
typedef msb_context_release_fn msb_resource_release_fn;
typedef msb_sandbox_list_fn msb_sandbox_resource_list_fn;
typedef char *(*msb_sandbox_resource_operation_fn)(uint64_t, uint64_t, const char *, uint8_t *, size_t);
typedef msb_sandbox_resource_operation_fn msb_sandbox_resource_wait_for_status_fn;
typedef char *(*msb_sandbox_remove_fn)(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_exec_fn)(uint64_t cancel_id, uint64_t handle, const char *cmd, const char *exec_opts_json, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_exec_default_fn)(uint64_t cancel_id, uint64_t handle, const char *exec_opts_json, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_exec_stream_fn)(uint64_t cancel_id, uint64_t handle, const char *cmd, const char *exec_opts_json, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_exec_default_stream_fn)(uint64_t cancel_id, uint64_t handle, const char *exec_opts_json, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_metrics_fn)(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_ssh_connect_fn)(uint64_t cancel_id, uint64_t handle, const char *opts_json, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_ssh_server_fn)(uint64_t cancel_id, uint64_t handle, const char *opts_json, uint8_t *buf, size_t buf_len);
typedef char *(*msb_ssh_server_close_fn)(uint64_t cancel_id, uint64_t server_handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_ssh_server_serve_connection_fn)(uint64_t cancel_id, uint64_t server_handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_ssh_client_exec_fn)(uint64_t cancel_id, uint64_t client_handle, const char *command, const char *opts_json, uint8_t *buf, size_t buf_len);
typedef char *(*msb_ssh_client_attach_fn)(uint64_t cancel_id, uint64_t client_handle, const char *opts_json, uint8_t *buf, size_t buf_len);
typedef char *(*msb_ssh_client_close_fn)(uint64_t cancel_id, uint64_t client_handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_ssh_client_sftp_fn)(uint64_t cancel_id, uint64_t client_handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sftp_read_fn)(uint64_t cancel_id, uint64_t sftp_handle, const char *path, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sftp_write_fn)(uint64_t cancel_id, uint64_t sftp_handle, const char *path, const char *data_b64, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sftp_mkdir_fn)(uint64_t cancel_id, uint64_t sftp_handle, const char *path, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sftp_remove_file_fn)(uint64_t cancel_id, uint64_t sftp_handle, const char *path, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sftp_remove_dir_fn)(uint64_t cancel_id, uint64_t sftp_handle, const char *path, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sftp_rename_fn)(uint64_t cancel_id, uint64_t sftp_handle, const char *old_path, const char *new_path, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sftp_real_path_fn)(uint64_t cancel_id, uint64_t sftp_handle, const char *path, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sftp_read_link_fn)(uint64_t cancel_id, uint64_t sftp_handle, const char *path, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sftp_symlink_fn)(uint64_t cancel_id, uint64_t sftp_handle, const char *target, const char *link_path, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sftp_close_fn)(uint64_t cancel_id, uint64_t sftp_handle, uint8_t *buf, size_t buf_len);

typedef char *(*msb_exec_recv_fn)(uint64_t cancel_id, uint64_t exec_handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_exec_close_fn)(uint64_t cancel_id, uint64_t exec_handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_exec_signal_fn)(uint64_t cancel_id, uint64_t exec_handle, int32_t signal, uint8_t *buf, size_t buf_len);
typedef char *(*msb_exec_resize_fn)(uint64_t cancel_id, uint64_t exec_handle, uint16_t rows, uint16_t cols, uint8_t *buf, size_t buf_len);
typedef char *(*msb_execution_result_fn)(uint64_t, uint64_t, const char *, const char *, const char *, uint8_t **, size_t *);
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

typedef char *(*msb_sandbox_request_drain_fn)(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_wait_until_stopped_fn)(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_owns_lifecycle_fn)(uint64_t handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_ping_fn)(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_touch_fn)(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_modify_fn)(uint64_t cancel_id, uint64_t handle, const char *opts_json, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_resize_operations_fn)(uint64_t cancel_id, uint64_t handle, const char *name, const char *expected_id, const char *request_json, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_resize_status_fn)(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_wait_until_resized_fn)(uint64_t cancel_id, uint64_t handle, uint64_t timeout_ms, uint8_t *buf, size_t buf_len);

typedef char *(*msb_sandbox_attach_fn)(uint64_t cancel_id, uint64_t handle, const char *cmd, const char *opts_json, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_attach_default_fn)(uint64_t cancel_id, uint64_t handle, const char *opts_json, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_shell_path_fn)(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_attach_shell_fn)(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_all_sandbox_metrics_fn)(uint64_t cancel_id, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_handle_metrics_fn)(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_logs_fn)(uint64_t cancel_id, uint64_t handle, const char *opts_json, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_handle_logs_fn)(uint64_t cancel_id, const char *name, const char *opts_json, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_log_stream_fn)(uint64_t cancel_id, uint64_t handle, const char *opts_json, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_handle_log_stream_fn)(uint64_t cancel_id, const char *name, const char *opts_json, uint8_t *buf, size_t buf_len);
typedef char *(*msb_log_recv_fn)(uint64_t cancel_id, uint64_t stream_handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_log_close_fn)(uint64_t stream_handle, uint8_t *buf, size_t buf_len);

typedef char *(*msb_volume_create_fn)(uint64_t cancel_id, const char *name, const char *opts_json, uint8_t *buf, size_t buf_len);
typedef char *(*msb_volume_remove_fn)(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len);
typedef char *(*msb_volume_list_fn)(uint64_t cancel_id, uint8_t *buf, size_t buf_len);
typedef char *(*msb_volume_get_fn)(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len);
typedef char *(*msb_volume_get_default_fn)(uint64_t cancel_id, uint8_t *buf, size_t buf_len);
typedef char *(*msb_volume_fs_op_fn)(uint64_t cancel_id, const char *name, const char *op, const char *args_json, uint8_t *buf, size_t buf_len);
typedef char *(*msb_version_fn)(uint8_t *buf, size_t buf_len);
typedef char *(*msb_agent_socket_path_fn)(const char *name, uint8_t *buf, size_t buf_len);

typedef char *(*msb_image_get_fn)(uint64_t cancel_id, const char *reference, uint8_t *buf, size_t buf_len);
typedef char *(*msb_image_list_fn)(uint64_t cancel_id, uint8_t *buf, size_t buf_len);
typedef char *(*msb_image_inspect_fn)(uint64_t cancel_id, const char *reference, uint8_t *buf, size_t buf_len);
typedef char *(*msb_image_remove_fn)(uint64_t cancel_id, const char *reference, bool force, uint8_t *buf, size_t buf_len);
typedef char *(*msb_image_prune_fn)(uint64_t cancel_id, uint8_t *buf, size_t buf_len);
typedef char *(*msb_snapshot_object_fn)(uint64_t, uint64_t, const char *, uint8_t *, size_t);
typedef char *(*msb_snapshot_object_owned_fn)(uint64_t, uint64_t, const char *, uint8_t **, size_t *);
typedef void (*msb_snapshot_object_close_fn)(uint64_t);
typedef char *(*msb_storage_usage_fn)(uint64_t cancel_id, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_storage_usage_fn)(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_storage_prune_fn)(uint64_t cancel_id, const char *options_json, uint8_t *buf, size_t buf_len);
typedef char *(*msb_service_create_fn)(uint64_t cancel_id, const char *request_json, uint8_t *buf, size_t buf_len);
typedef char *(*msb_service_get_fn)(uint64_t cancel_id, const char *slug, uint8_t *buf, size_t buf_len);
typedef char *(*msb_service_list_fn)(uint64_t cancel_id, const char *options_json, uint8_t *buf, size_t buf_len);
typedef char *(*msb_service_update_fn)(uint64_t cancel_id, uint64_t handle, const char *request_json, uint8_t *buf, size_t buf_len);
typedef char *(*msb_service_enable_fn)(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_service_disable_fn)(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_service_remove_fn)(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_service_refresh_fn)(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_service_close_fn)(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_image_load_fn)(uint64_t cancel_id, const char *input_path, const char *tags_json, uint8_t *buf, size_t buf_len);
typedef char *(*msb_image_save_fn)(uint64_t cancel_id, const char *references_json, const char *output_path, const char *format, uint8_t *buf, size_t buf_len);

typedef char *(*msb_sandbox_handle_snapshot_fn)(uint64_t cancel_id, const char *sandbox_name, const char *snapshot_name, uint8_t *buf, size_t buf_len);
typedef char *(*msb_snapshot_create_fn)(uint64_t cancel_id, const char *source_sandbox, const char *opts_json, uint8_t *buf, size_t buf_len);
typedef char *(*msb_snapshot_create_archive_fn)(uint64_t cancel_id, const char *source_sandbox, const char *archive_path, const char *opts_json, bool plain_tar, uint8_t *buf, size_t buf_len);
typedef char *(*msb_snapshot_open_fn)(uint64_t cancel_id, const char *reference, const char *reference_kind, uint8_t *buf, size_t buf_len);
typedef char *(*msb_snapshot_verify_fn)(uint64_t cancel_id, const char *reference, const char *reference_kind, uint8_t *buf, size_t buf_len);
typedef char *(*msb_snapshot_get_fn)(uint64_t cancel_id, const char *name_or_digest, uint8_t *buf, size_t buf_len);
typedef char *(*msb_snapshot_list_fn)(uint64_t cancel_id, uint8_t *buf, size_t buf_len);
typedef char *(*msb_snapshot_list_dir_fn)(uint64_t cancel_id, const char *dir, uint8_t *buf, size_t buf_len);
typedef char *(*msb_snapshot_remove_fn)(uint64_t cancel_id, const char *reference, const char *reference_kind, bool force, uint8_t *buf, size_t buf_len);
typedef char *(*msb_snapshot_reindex_fn)(uint64_t cancel_id, const char *dir, uint8_t *buf, size_t buf_len);
typedef char *(*msb_snapshot_export_fn)(uint64_t cancel_id, const char *reference, const char *reference_kind, const char *out, const char *opts_json, uint8_t *buf, size_t buf_len);
typedef char *(*msb_snapshot_copy_fn)(uint64_t cancel_id, const char *reference, const char *reference_kind, const char *output_archive_path, const char *opts_json, uint8_t *buf, size_t buf_len);
typedef char *(*msb_snapshot_import_fn)(uint64_t cancel_id, const char *archive, const char *dest, uint8_t *buf, size_t buf_len);
typedef char *(*msb_snapshot_import_with_base_fn)(uint64_t cancel_id, const char *archive, const char *dest, const char *base, uint8_t *buf, size_t buf_len);
typedef char *(*msb_snapshot_import_with_options_fn)(uint64_t cancel_id, const char *archive, const char *opts_json, uint8_t *buf, size_t buf_len);
typedef char *(*msb_snapshot_import_many_fn)(uint64_t cancel_id, const char *archives_json, const char *opts_json, uint8_t *buf, size_t buf_len);
typedef char *(*msb_snapshot_group_head_fn)(uint64_t cancel_id, const char *selector, uint8_t *buf, size_t buf_len);
typedef char *(*msb_sandbox_compact_fn)(uint64_t cancel_id, uint64_t handle, const char *name, const char *opts, uint8_t *buf, size_t buf_len);

typedef char *(*msb_fs_read_stream_fn)(uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len);
typedef char *(*msb_fs_read_stream_recv_fn)(uint64_t cancel_id, uint64_t stream_handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_fs_read_stream_close_fn)(uint64_t stream_handle, uint8_t *buf, size_t buf_len);
typedef char *(*msb_fs_write_stream_fn)(uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len);
typedef char *(*msb_fs_write_stream_write_fn)(uint64_t cancel_id, uint64_t stream_handle, const char *data_b64, uint8_t *buf, size_t buf_len);
typedef char *(*msb_fs_write_stream_close_fn)(uint64_t cancel_id, uint64_t stream_handle, uint8_t *buf, size_t buf_len);

typedef char *(*msb_agent_open_sandbox_fn)(uint64_t cancel_id, const char *name, uint64_t timeout_ms, uint64_t *out_handle);
typedef char *(*msb_agent_open_path_fn)(uint64_t cancel_id, const char *path, uint64_t timeout_ms, uint64_t *out_handle);
typedef char *(*msb_agent_request_fn)(uint64_t cancel_id, uint64_t agent_handle, uint8_t flags, const uint8_t *body_ptr, size_t body_len, uint32_t *out_id, uint8_t *out_flags, uint8_t **out_body_ptr, size_t *out_body_len);
typedef char *(*msb_agent_stream_open_fn)(uint64_t cancel_id, uint64_t agent_handle, uint8_t flags, const uint8_t *body_ptr, size_t body_len, uint32_t *out_id, uint64_t *out_stream_handle);
typedef char *(*msb_agent_stream_next_fn)(uint64_t cancel_id, uint64_t agent_handle, uint64_t stream_handle, bool *out_present, uint32_t *out_id, uint8_t *out_flags, uint8_t **out_body_ptr, size_t *out_body_len);
typedef char *(*msb_agent_stream_close_fn)(uint64_t cancel_id, uint64_t agent_handle, uint64_t stream_handle);
typedef char *(*msb_agent_send_fn)(uint64_t cancel_id, uint64_t agent_handle, uint32_t id, uint8_t flags, const uint8_t *body_ptr, size_t body_len);
typedef char *(*msb_agent_ready_bytes_fn)(uint64_t agent_handle, uint8_t **out_body_ptr, size_t *out_body_len);
typedef char *(*msb_agent_close_fn)(uint64_t cancel_id, uint64_t agent_handle);
typedef void (*msb_agent_free_bytes_fn)(uint8_t *ptr, size_t len);

// ---------------------------------------------------------------------------
// Function pointer globals — NULL until load_microsandbox() succeeds.
// ---------------------------------------------------------------------------
typedef char *(*msb_sandbox_restore_fn)(uint64_t, const char *, const char *, uint8_t *, size_t);
typedef char *(*msb_creation_progress_open_fn)(uint8_t *, size_t);
typedef char *(*msb_creation_progress_recv_fn)(uint64_t, uint64_t, uint8_t *, size_t);
typedef char *(*msb_creation_progress_close_fn)(uint64_t, uint8_t *, size_t);

// A library owns one immutable function table for its entire process lifetime.
struct msb_library {
    msb_sandbox_handle_resize_status_fn ptr_msb_sandbox_handle_resize_status;
    msb_sandbox_handle_wait_until_resized_fn ptr_msb_sandbox_handle_wait_until_resized;
    msb_sandbox_resize_status_fn ptr_msb_sandbox_resize_status;
    msb_sandbox_resize_operations_fn ptr_msb_sandbox_resize_operations;
    msb_sandbox_wait_until_resized_fn ptr_msb_sandbox_wait_until_resized;
    msb_snapshot_object_fn ptr_msb_snapshot_object;
    msb_snapshot_object_owned_fn ptr_msb_snapshot_object_owned;
    msb_snapshot_object_close_fn ptr_msb_snapshot_object_close;

    msb_creation_progress_open_fn ptr_msb_creation_progress_open;
    msb_creation_progress_recv_fn ptr_msb_creation_progress_recv;
    msb_creation_progress_close_fn ptr_msb_creation_progress_close;
    void *handle;
    bool ready;
    char load_error[1024];
    msb_jobs_fn ptr_msb_jobs;
    msb_free_string_fn ptr_msb_free_string;
    msb_set_sdk_msb_path_fn ptr_msb_set_sdk_msb_path;
    msb_cancel_alloc_fn ptr_msb_cancel_alloc;
    msb_cancel_trigger_fn ptr_msb_cancel_trigger;
    msb_cancel_unregister_fn ptr_msb_cancel_unregister;
    msb_sandbox_create_fn ptr_msb_sandbox_create;
    msb_sandbox_restore_fn ptr_msb_sandbox_restore;
    msb_sandbox_handle_lifecycle_fn ptr_msb_sandbox_handle_lifecycle;
    msb_sandbox_lookup_fn ptr_msb_sandbox_lookup;
    msb_runtime_setup_fn ptr_msb_runtime_setup;
    msb_default_backend_info_fn ptr_msb_default_backend_info;
    msb_sandbox_connect_fn ptr_msb_sandbox_connect;
    msb_sandbox_start_fn ptr_msb_sandbox_start;
    msb_sandbox_handle_stop_fn ptr_msb_sandbox_handle_stop;
    msb_sandbox_handle_request_stop_fn ptr_msb_sandbox_handle_request_stop;
    msb_sandbox_handle_kill_fn ptr_msb_sandbox_handle_kill;
    msb_sandbox_handle_request_kill_fn ptr_msb_sandbox_handle_request_kill;
    msb_sandbox_handle_request_drain_fn ptr_msb_sandbox_handle_request_drain;
    msb_sandbox_handle_wait_until_stopped_fn ptr_msb_sandbox_handle_wait_until_stopped;
    msb_sandbox_handle_ping_fn ptr_msb_sandbox_handle_ping;
    msb_sandbox_handle_touch_fn ptr_msb_sandbox_handle_touch;
    msb_sandbox_handle_modify_fn ptr_msb_sandbox_handle_modify;
    msb_sandbox_close_fn ptr_msb_sandbox_close;
    msb_sandbox_detach_fn ptr_msb_sandbox_detach;
    msb_sandbox_stop_fn ptr_msb_sandbox_stop;
    msb_sandbox_stop_gracefully_fn ptr_msb_sandbox_stop_gracefully;
    msb_sandbox_request_stop_fn ptr_msb_sandbox_request_stop;
    msb_sandbox_restore_warnings_fn ptr_msb_sandbox_restore_warnings;
    msb_sandbox_pause_fn ptr_msb_sandbox_pause;
    msb_sandbox_pause_with_guest_flush_fn ptr_msb_sandbox_pause_with_guest_flush;
    msb_sandbox_branch_fn ptr_msb_sandbox_branch;
    msb_sandbox_branch_with_options_fn ptr_msb_sandbox_branch_with_options;
    msb_sandbox_branch_with_options_fn ptr_msb_sandbox_branch_many;
    msb_sandbox_resume_fn ptr_msb_sandbox_resume;
    msb_sandbox_handle_pause_fn ptr_msb_sandbox_handle_pause;
    msb_sandbox_handle_resume_fn ptr_msb_sandbox_handle_resume;
    msb_sandbox_kill_fn ptr_msb_sandbox_kill;
    msb_sandbox_request_kill_fn ptr_msb_sandbox_request_kill;
    msb_sandbox_list_fn ptr_msb_sandbox_list;
    msb_resource_operation_fn ptr_msb_resource_operation;
    msb_resource_release_fn ptr_msb_resource_release;
    msb_context_create_fn ptr_msb_context_create;
    msb_context_operation_fn ptr_msb_context_operation;
    msb_context_release_fn ptr_msb_context_release;
    msb_sandbox_list_fn ptr_msb_sandbox_resource_list;
    msb_sandbox_resource_operation_fn ptr_msb_sandbox_resource_operation;
    msb_sandbox_resource_operation_fn ptr_msb_sandbox_resource_wait_for_status;
    msb_sandbox_remove_fn ptr_msb_sandbox_remove;
    msb_sandbox_exec_fn ptr_msb_sandbox_exec;
    msb_sandbox_exec_default_fn ptr_msb_sandbox_exec_default;
    msb_sandbox_exec_stream_fn ptr_msb_sandbox_exec_stream;
    msb_sandbox_exec_default_stream_fn ptr_msb_sandbox_exec_default_stream;
    msb_sandbox_metrics_fn ptr_msb_sandbox_metrics;
    msb_sandbox_ssh_connect_fn ptr_msb_sandbox_ssh_connect;
    msb_sandbox_ssh_server_fn ptr_msb_sandbox_ssh_server;
    msb_ssh_server_close_fn ptr_msb_ssh_server_close;
    msb_ssh_server_serve_connection_fn ptr_msb_ssh_server_serve_connection;
    msb_ssh_client_exec_fn ptr_msb_ssh_client_exec;
    msb_ssh_client_attach_fn ptr_msb_ssh_client_attach;
    msb_ssh_client_close_fn ptr_msb_ssh_client_close;
    msb_ssh_client_sftp_fn ptr_msb_ssh_client_sftp;
    msb_sftp_read_fn ptr_msb_sftp_read;
    msb_sftp_write_fn ptr_msb_sftp_write;
    msb_sftp_mkdir_fn ptr_msb_sftp_mkdir;
    msb_sftp_remove_file_fn ptr_msb_sftp_remove_file;
    msb_sftp_remove_dir_fn ptr_msb_sftp_remove_dir;
    msb_sftp_rename_fn ptr_msb_sftp_rename;
    msb_sftp_real_path_fn ptr_msb_sftp_real_path;
    msb_sftp_read_link_fn ptr_msb_sftp_read_link;
    msb_sftp_symlink_fn ptr_msb_sftp_symlink;
    msb_sftp_close_fn ptr_msb_sftp_close;
    msb_exec_recv_fn ptr_msb_exec_recv;
    msb_exec_close_fn ptr_msb_exec_close;
    msb_exec_signal_fn ptr_msb_exec_signal;
    msb_exec_resize_fn ptr_msb_exec_resize;
    msb_fs_read_fn ptr_msb_fs_read;
    msb_fs_write_fn ptr_msb_fs_write;
    msb_fs_list_fn ptr_msb_fs_list;
    msb_fs_stat_fn ptr_msb_fs_stat;
    msb_fs_copy_from_host_fn ptr_msb_fs_copy_from_host;
    msb_fs_copy_to_host_fn ptr_msb_fs_copy_to_host;
    msb_fs_mkdir_fn ptr_msb_fs_mkdir;
    msb_fs_remove_fn ptr_msb_fs_remove;
    msb_fs_remove_dir_fn ptr_msb_fs_remove_dir;
    msb_fs_copy_fn ptr_msb_fs_copy;
    msb_fs_rename_fn ptr_msb_fs_rename;
    msb_fs_exists_fn ptr_msb_fs_exists;
    msb_sandbox_metrics_stream_fn ptr_msb_sandbox_metrics_stream;
    msb_metrics_recv_fn ptr_msb_metrics_recv;
    msb_metrics_close_fn ptr_msb_metrics_close;
    msb_exec_stdin_write_fn ptr_msb_exec_stdin_write;
    msb_exec_stdin_close_fn ptr_msb_exec_stdin_close;
    msb_sandbox_request_drain_fn ptr_msb_sandbox_request_drain;
    msb_sandbox_wait_until_stopped_fn ptr_msb_sandbox_wait_until_stopped;
    msb_sandbox_owns_lifecycle_fn ptr_msb_sandbox_owns_lifecycle;
    msb_sandbox_ping_fn ptr_msb_sandbox_ping;
    msb_sandbox_touch_fn ptr_msb_sandbox_touch;
    msb_sandbox_modify_fn ptr_msb_sandbox_modify;
    msb_execution_result_fn ptr_msb_execution_result;
    msb_exec_collect_fn ptr_msb_exec_collect;
    msb_exec_wait_fn ptr_msb_exec_wait;
    msb_exec_kill_fn ptr_msb_exec_kill;
    msb_exec_id_fn ptr_msb_exec_id;
    msb_sandbox_attach_fn ptr_msb_sandbox_attach;
    msb_sandbox_attach_default_fn ptr_msb_sandbox_attach_default;
    msb_sandbox_attach_shell_fn ptr_msb_sandbox_attach_shell;
    msb_sandbox_shell_path_fn ptr_msb_sandbox_shell_path;
    msb_all_sandbox_metrics_fn ptr_msb_all_sandbox_metrics;
    msb_sandbox_handle_metrics_fn ptr_msb_sandbox_handle_metrics;
    msb_sandbox_logs_fn ptr_msb_sandbox_logs;
    msb_sandbox_handle_logs_fn ptr_msb_sandbox_handle_logs;
    msb_sandbox_log_stream_fn ptr_msb_sandbox_log_stream;
    msb_sandbox_handle_log_stream_fn ptr_msb_sandbox_handle_log_stream;
    msb_log_recv_fn ptr_msb_log_recv;
    msb_log_close_fn ptr_msb_log_close;
    msb_volume_create_fn ptr_msb_volume_create;
    msb_volume_remove_fn ptr_msb_volume_remove;
    msb_volume_list_fn ptr_msb_volume_list;
    msb_volume_get_fn ptr_msb_volume_get;
    msb_volume_get_default_fn ptr_msb_volume_get_default;
    msb_volume_fs_op_fn ptr_msb_volume_fs_op;
    msb_fs_read_stream_fn ptr_msb_fs_read_stream;
    msb_fs_read_stream_recv_fn ptr_msb_fs_read_stream_recv;
    msb_fs_read_stream_close_fn ptr_msb_fs_read_stream_close;
    msb_fs_write_stream_fn ptr_msb_fs_write_stream;
    msb_fs_write_stream_write_fn ptr_msb_fs_write_stream_write;
    msb_fs_write_stream_close_fn ptr_msb_fs_write_stream_close;
    msb_agent_open_sandbox_fn ptr_msb_agent_open_sandbox;
    msb_agent_open_path_fn ptr_msb_agent_open_path;
    msb_agent_request_fn ptr_msb_agent_request;
    msb_agent_stream_open_fn ptr_msb_agent_stream_open;
    msb_agent_stream_next_fn ptr_msb_agent_stream_next;
    msb_agent_stream_close_fn ptr_msb_agent_stream_close;
    msb_agent_send_fn ptr_msb_agent_send;
    msb_agent_ready_bytes_fn ptr_msb_agent_ready_bytes;
    msb_agent_close_fn ptr_msb_agent_close;
    msb_agent_free_bytes_fn ptr_msb_agent_free_bytes;
    msb_version_fn ptr_msb_version;
    msb_agent_socket_path_fn ptr_msb_agent_socket_path;
    msb_image_get_fn ptr_msb_image_get;
    msb_image_list_fn ptr_msb_image_list;
    msb_image_inspect_fn ptr_msb_image_inspect;
    msb_image_remove_fn ptr_msb_image_remove;
    msb_image_prune_fn ptr_msb_image_prune;
    msb_service_create_fn ptr_msb_service_create;
    msb_service_get_fn ptr_msb_service_get;
    msb_service_list_fn ptr_msb_service_list;
    msb_service_update_fn ptr_msb_service_update;
    msb_service_enable_fn ptr_msb_service_enable;
    msb_service_disable_fn ptr_msb_service_disable;
    msb_service_remove_fn ptr_msb_service_remove;
    msb_service_refresh_fn ptr_msb_service_refresh;
    msb_service_close_fn ptr_msb_service_close;
    msb_storage_usage_fn ptr_msb_storage_usage;
    msb_sandbox_storage_usage_fn ptr_msb_sandbox_storage_usage;
    msb_storage_prune_fn ptr_msb_storage_prune;
    msb_image_load_fn ptr_msb_image_load;
    msb_image_save_fn ptr_msb_image_save;
    msb_sandbox_handle_snapshot_fn ptr_msb_sandbox_handle_snapshot;
    msb_snapshot_create_fn ptr_msb_snapshot_create;
    msb_snapshot_create_archive_fn ptr_msb_snapshot_create_archive;
    msb_snapshot_open_fn ptr_msb_snapshot_open;
    msb_snapshot_verify_fn ptr_msb_snapshot_verify;
    msb_snapshot_get_fn ptr_msb_snapshot_get;
    msb_snapshot_list_fn ptr_msb_snapshot_list;
    msb_snapshot_list_dir_fn ptr_msb_snapshot_list_dir;
    msb_snapshot_remove_fn ptr_msb_snapshot_remove;
    msb_snapshot_reindex_fn ptr_msb_snapshot_reindex;
    msb_snapshot_export_fn ptr_msb_snapshot_export;
    msb_snapshot_copy_fn ptr_msb_snapshot_copy;
    msb_snapshot_import_fn ptr_msb_snapshot_import;
    msb_snapshot_import_with_base_fn ptr_msb_snapshot_import_with_base;
    msb_snapshot_import_with_options_fn ptr_msb_snapshot_import_with_options;
    msb_snapshot_import_many_fn ptr_msb_snapshot_import_many;
    msb_snapshot_group_head_fn ptr_msb_snapshot_group_head;
    msb_sandbox_compact_fn ptr_msb_sandbox_compact;
};
static msb_library default_library = {0};

bool provider_has_port_modification(msb_library *library) {
    return library->handle && dlsym(library->handle, "msb_supports_port_modification") != NULL;
}
bool has_port_modification(void) { return provider_has_port_modification(&default_library); }

bool provider_has_secret_policy_modification(msb_library *library) {
    return library->handle && dlsym(library->handle, "msb_supports_secret_policy_modification") != NULL;
}
bool has_secret_policy_modification(void) { return provider_has_secret_policy_modification(&default_library); }

bool provider_has_resize_operations(msb_library *library) { return library->ptr_msb_sandbox_resize_operations != NULL; }
bool has_resize_operations(void) { return provider_has_resize_operations(&default_library); }
char *provider_call_msb_sandbox_resize_operations(msb_library *library, uint64_t cancel_id, uint64_t handle, const char *name, const char *expected_id, const char *request_json, uint8_t *buf, size_t buf_len) {
    return library->ptr_msb_sandbox_resize_operations ? library->ptr_msb_sandbox_resize_operations(cancel_id, handle, name, expected_id, request_json, buf, buf_len) : NULL;
}
char *call_msb_sandbox_resize_operations(uint64_t cancel_id, uint64_t handle, const char *name, const char *expected_id, const char *request_json, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_resize_operations(&default_library, cancel_id, handle, name, expected_id, request_json, buf, buf_len); }
bool provider_has_resize_wait(msb_library *library) {
	return library->ptr_msb_sandbox_handle_resize_status && library->ptr_msb_sandbox_handle_wait_until_resized
		&& library->ptr_msb_sandbox_resize_status && library->ptr_msb_sandbox_wait_until_resized;
}
bool has_resize_wait(void) { return provider_has_resize_wait(&default_library); }
char *provider_call_msb_sandbox_handle_resize_status(msb_library *library, uint64_t cancel_id, const char *name, const char *expected_id, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_handle_resize_status ? library->ptr_msb_sandbox_handle_resize_status(cancel_id, name, expected_id, buf, buf_len) : NULL;
}
char *call_msb_sandbox_handle_resize_status(uint64_t cancel_id, const char *name, const char *expected_id, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_handle_resize_status(&default_library, cancel_id, name, expected_id, buf, buf_len); }
char *provider_call_msb_sandbox_handle_wait_until_resized(msb_library *library, uint64_t cancel_id, const char *name, const char *expected_id, uint64_t timeout_ms, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_handle_wait_until_resized ? library->ptr_msb_sandbox_handle_wait_until_resized(cancel_id, name, expected_id, timeout_ms, buf, buf_len) : NULL;
}
char *call_msb_sandbox_handle_wait_until_resized(uint64_t cancel_id, const char *name, const char *expected_id, uint64_t timeout_ms, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_handle_wait_until_resized(&default_library, cancel_id, name, expected_id, timeout_ms, buf, buf_len); }
char *provider_call_msb_sandbox_resize_status(msb_library *library, uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_resize_status ? library->ptr_msb_sandbox_resize_status(cancel_id, handle, buf, buf_len) : NULL;
}
char *call_msb_sandbox_resize_status(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_resize_status(&default_library, cancel_id, handle, buf, buf_len); }
char *provider_call_msb_sandbox_wait_until_resized(msb_library *library, uint64_t cancel_id, uint64_t handle, uint64_t timeout_ms, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_wait_until_resized ? library->ptr_msb_sandbox_wait_until_resized(cancel_id, handle, timeout_ms, buf, buf_len) : NULL;
}
char *call_msb_sandbox_wait_until_resized(uint64_t cancel_id, uint64_t handle, uint64_t timeout_ms, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_wait_until_resized(&default_library, cancel_id, handle, timeout_ms, buf, buf_len); }
bool provider_has_snapshot_import_budget(msb_library *library) {
    return library->handle && dlsym(library->handle, "msb_supports_snapshot_import_budget") != NULL;
}
bool provider_has_msb_snapshot_objects(msb_library *library) { return library->ptr_msb_snapshot_object && library->ptr_msb_snapshot_object_close; }
bool has_msb_snapshot_objects(void) { return provider_has_msb_snapshot_objects(&default_library); }
bool provider_has_context_snapshot_objects(msb_library *library) {
    return provider_has_msb_snapshot_objects(library) && library->handle && dlsym(library->handle, "msb_supports_context_snapshot_objects") != NULL;
}
bool provider_has_msb_snapshot_group_paths(msb_library *library) {
    return provider_has_msb_snapshot_objects(library) && library->handle &&
        dlsym(library->handle, "msb_supports_snapshot_group_paths") != NULL;
}
bool has_msb_snapshot_group_paths(void) { return provider_has_msb_snapshot_group_paths(&default_library); }
bool provider_has_msb_snapshot_artifact_receivers(msb_library *library) {
    // General receivers predate create_artifact/list_dir. Select the producer ABI
    // before dispatch: probing by capture failure could repeat a published mutation.
    return provider_has_msb_snapshot_objects(library) && library->handle &&
        dlsym(library->handle, "msb_supports_snapshot_artifact_receivers") != NULL;
}
bool has_msb_snapshot_artifact_receivers(void) { return provider_has_msb_snapshot_artifact_receivers(&default_library); }
char *provider_call_msb_snapshot_object(msb_library *library, uint64_t cancel_id, uint64_t handle, const char *request, uint8_t *buf, size_t buf_len) {
    return library->ptr_msb_snapshot_object ? library->ptr_msb_snapshot_object(cancel_id, handle, request, buf, buf_len) : NULL;
}
char *call_msb_snapshot_object(uint64_t cancel_id, uint64_t handle, const char *request, uint8_t *buf, size_t buf_len) { return provider_call_msb_snapshot_object(&default_library, cancel_id, handle, request, buf, buf_len); }
bool provider_has_msb_snapshot_object_owned(msb_library *library) { return library->ptr_msb_snapshot_object_owned != NULL; }
bool has_msb_snapshot_object_owned(void) { return provider_has_msb_snapshot_object_owned(&default_library); }
char *provider_call_msb_snapshot_object_owned(msb_library *library, uint64_t cancel_id, uint64_t handle, const char *request, uint8_t **out, size_t *len) {
    return library->ptr_msb_snapshot_object_owned(cancel_id, handle, request, out, len);
}
char *call_msb_snapshot_object_owned(uint64_t cancel_id, uint64_t handle, const char *request, uint8_t **out, size_t *len) { return provider_call_msb_snapshot_object_owned(&default_library, cancel_id, handle, request, out, len); }
void provider_call_msb_snapshot_object_close(msb_library *library, uint64_t handle) {
    if (library->ptr_msb_snapshot_object_close) library->ptr_msb_snapshot_object_close(handle);
}
void call_msb_snapshot_object_close(uint64_t handle) { provider_call_msb_snapshot_object_close(&default_library, handle); }

// Loader errors are owned by the selected table until copied by its caller.


// RESOLVE resolves one symbol into the selected table and stores an error
// message (returning it) if the symbol is absent.
#define RESOLVE(name) \
	do { \
		library->ptr_##name = (name##_fn)dlsym(library->handle, #name); \
		if (!library->ptr_##name) { \
			snprintf(library->load_error, sizeof(library->load_error), \
				"dlsym '%s': %s", #name, dlerror()); \
			return library->load_error; \
		} \
	} while (0)

// Optional symbols let a newly-built Go package load an older embedded FFI
// bundle. Calls using the new capability detect the missing function and
// return an explicit unavailable result without breaking unrelated methods.
#define RESOLVE_OPTIONAL(name) \
	do { \
		library->ptr_##name = (name##_fn)dlsym(library->handle, #name); \
	} while (0)

// load_microsandbox opens the shared library at path and resolves every
// msb_* symbol. Returns NULL on success or a static error string on failure.
// Idempotent: returns NULL immediately if already loaded.
// Ownership: path is borrowed for the duration of the call only.
const char * provider_load_microsandbox(msb_library *library, const char *path) {
	if (library->ready) {
		return NULL;
	}
	library->handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
	if (!library->handle) {
		snprintf(library->load_error, sizeof(library->load_error), "dlopen '%s': %s", path, dlerror());
		return library->load_error;
	}
	RESOLVE(msb_free_string);
	RESOLVE(msb_set_sdk_msb_path);
	RESOLVE(msb_cancel_alloc);
	RESOLVE(msb_cancel_trigger);
	RESOLVE(msb_cancel_unregister);
	RESOLVE_OPTIONAL(msb_default_backend_info);
	RESOLVE_OPTIONAL(msb_runtime_setup);
	RESOLVE(msb_sandbox_create);
	RESOLVE(msb_sandbox_restore);
	RESOLVE_OPTIONAL(msb_creation_progress_open);
	RESOLVE_OPTIONAL(msb_creation_progress_recv);
	RESOLVE_OPTIONAL(msb_creation_progress_close);
	RESOLVE(msb_sandbox_handle_lifecycle);
	RESOLVE(msb_sandbox_lookup);
	RESOLVE(msb_sandbox_connect);
	RESOLVE(msb_sandbox_start);
	RESOLVE(msb_sandbox_handle_stop);
	RESOLVE(msb_sandbox_handle_request_stop);
	RESOLVE(msb_sandbox_handle_kill);
	RESOLVE(msb_sandbox_handle_request_kill);
	RESOLVE(msb_sandbox_handle_request_drain);
	RESOLVE(msb_sandbox_handle_wait_until_stopped);
	RESOLVE(msb_sandbox_handle_ping);
	RESOLVE(msb_sandbox_handle_touch);
	RESOLVE(msb_sandbox_handle_modify);
	RESOLVE_OPTIONAL(msb_sandbox_handle_resize_status);
	RESOLVE_OPTIONAL(msb_sandbox_handle_wait_until_resized);
	RESOLVE(msb_sandbox_close);
	RESOLVE(msb_sandbox_detach);
	RESOLVE(msb_sandbox_stop);
	RESOLVE_OPTIONAL(msb_sandbox_stop_gracefully);
	RESOLVE(msb_sandbox_request_stop);
	RESOLVE_OPTIONAL(msb_sandbox_restore_warnings);
	RESOLVE(msb_sandbox_pause);
	RESOLVE_OPTIONAL(msb_sandbox_pause_with_guest_flush);
	RESOLVE(msb_sandbox_branch);
	RESOLVE_OPTIONAL(msb_sandbox_branch_with_options);
	RESOLVE_OPTIONAL(msb_sandbox_branch_many);
	RESOLVE(msb_sandbox_resume);
	RESOLVE(msb_sandbox_handle_pause);
	RESOLVE(msb_sandbox_handle_resume);
	RESOLVE(msb_sandbox_kill);
	RESOLVE(msb_sandbox_request_kill);
	RESOLVE(msb_sandbox_list);
	RESOLVE_OPTIONAL(msb_resource_operation);
	RESOLVE_OPTIONAL(msb_resource_release);
	RESOLVE_OPTIONAL(msb_context_create);
	RESOLVE_OPTIONAL(msb_context_operation);
	RESOLVE_OPTIONAL(msb_context_release);
	RESOLVE_OPTIONAL(msb_sandbox_resource_list);
	RESOLVE_OPTIONAL(msb_sandbox_resource_operation);
	RESOLVE_OPTIONAL(msb_sandbox_resource_wait_for_status);
	RESOLVE(msb_sandbox_remove);
	RESOLVE_OPTIONAL(msb_jobs);
	RESOLVE(msb_sandbox_exec);
	RESOLVE(msb_sandbox_exec_default);
	RESOLVE(msb_sandbox_exec_stream);
	RESOLVE(msb_sandbox_exec_default_stream);
	RESOLVE(msb_sandbox_metrics);
	RESOLVE(msb_sandbox_ssh_connect);
	RESOLVE(msb_sandbox_ssh_server);
	RESOLVE(msb_ssh_server_close);
	RESOLVE(msb_ssh_server_serve_connection);
	RESOLVE(msb_ssh_client_exec);
	RESOLVE(msb_ssh_client_attach);
	RESOLVE(msb_ssh_client_close);
	RESOLVE(msb_ssh_client_sftp);
	RESOLVE(msb_sftp_read);
	RESOLVE(msb_sftp_write);
	RESOLVE(msb_sftp_mkdir);
	RESOLVE(msb_sftp_remove_file);
	RESOLVE(msb_sftp_remove_dir);
	RESOLVE(msb_sftp_rename);
	RESOLVE(msb_sftp_real_path);
	RESOLVE(msb_sftp_read_link);
	RESOLVE(msb_sftp_symlink);
	RESOLVE(msb_sftp_close);
	RESOLVE(msb_exec_recv);
	RESOLVE(msb_exec_close);
	RESOLVE(msb_exec_signal);
	RESOLVE(msb_exec_resize);
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
	RESOLVE(msb_sandbox_request_drain);
	RESOLVE(msb_sandbox_wait_until_stopped);
	RESOLVE(msb_sandbox_owns_lifecycle);
	RESOLVE(msb_sandbox_ping);
	RESOLVE(msb_sandbox_touch);
	RESOLVE(msb_sandbox_modify);
	RESOLVE_OPTIONAL(msb_execution_result);
	RESOLVE_OPTIONAL(msb_sandbox_resize_status);
	RESOLVE_OPTIONAL(msb_sandbox_resize_operations);
	RESOLVE_OPTIONAL(msb_sandbox_wait_until_resized);
	RESOLVE(msb_exec_collect);
	RESOLVE(msb_exec_wait);
	RESOLVE(msb_exec_kill);
	RESOLVE(msb_exec_id);
	RESOLVE(msb_sandbox_attach);
	RESOLVE(msb_sandbox_attach_default);
	RESOLVE(msb_sandbox_attach_shell);
	RESOLVE_OPTIONAL(msb_sandbox_shell_path);
	RESOLVE(msb_all_sandbox_metrics);
	RESOLVE(msb_sandbox_handle_metrics);
	RESOLVE(msb_sandbox_logs);
	RESOLVE(msb_sandbox_handle_logs);
	RESOLVE(msb_sandbox_log_stream);
	RESOLVE(msb_sandbox_handle_log_stream);
	RESOLVE(msb_log_recv);
	RESOLVE(msb_log_close);
	RESOLVE(msb_volume_create);
	RESOLVE(msb_volume_remove);
	RESOLVE(msb_volume_list);
	RESOLVE(msb_volume_get);
	RESOLVE(msb_volume_get_default);
	RESOLVE(msb_volume_fs_op);
	RESOLVE(msb_fs_read_stream);
	RESOLVE(msb_fs_read_stream_recv);
	RESOLVE(msb_fs_read_stream_close);
	RESOLVE(msb_fs_write_stream);
	RESOLVE(msb_fs_write_stream_write);
	RESOLVE(msb_fs_write_stream_close);
	RESOLVE(msb_agent_open_sandbox);
	RESOLVE(msb_agent_open_path);
	RESOLVE(msb_agent_request);
	RESOLVE(msb_agent_stream_open);
	RESOLVE(msb_agent_stream_next);
	RESOLVE(msb_agent_stream_close);
	RESOLVE(msb_agent_send);
	RESOLVE(msb_agent_ready_bytes);
	RESOLVE(msb_agent_close);
	RESOLVE(msb_agent_free_bytes);
	RESOLVE(msb_version);
	RESOLVE(msb_agent_socket_path);
	RESOLVE(msb_image_get);
	RESOLVE(msb_image_list);
	RESOLVE(msb_image_inspect);
	RESOLVE(msb_image_remove);
	RESOLVE(msb_image_prune);
	RESOLVE_OPTIONAL(msb_storage_usage);
	RESOLVE_OPTIONAL(msb_snapshot_object);
	RESOLVE_OPTIONAL(msb_snapshot_object_owned);
	RESOLVE_OPTIONAL(msb_snapshot_object_close);
	RESOLVE_OPTIONAL(msb_sandbox_storage_usage);
	RESOLVE_OPTIONAL(msb_storage_prune);
	RESOLVE_OPTIONAL(msb_service_create);
	RESOLVE_OPTIONAL(msb_service_get);
	RESOLVE_OPTIONAL(msb_service_list);
	RESOLVE_OPTIONAL(msb_service_update);
	RESOLVE_OPTIONAL(msb_service_enable);
	RESOLVE_OPTIONAL(msb_service_disable);
	RESOLVE_OPTIONAL(msb_service_remove);
	RESOLVE_OPTIONAL(msb_service_refresh);
	RESOLVE_OPTIONAL(msb_service_close);
	RESOLVE(msb_image_load);
	RESOLVE(msb_image_save);
	RESOLVE(msb_sandbox_handle_snapshot);
	RESOLVE(msb_snapshot_create);
	RESOLVE(msb_snapshot_create_archive);
	RESOLVE(msb_snapshot_open);
	RESOLVE(msb_snapshot_verify);
	RESOLVE(msb_snapshot_get);
	RESOLVE(msb_snapshot_list);
	RESOLVE(msb_snapshot_list_dir);
	RESOLVE(msb_snapshot_remove);
	RESOLVE(msb_snapshot_reindex);
	RESOLVE(msb_snapshot_export);
	RESOLVE(msb_snapshot_copy);
	RESOLVE(msb_snapshot_import);
	RESOLVE(msb_snapshot_import_with_base);
	RESOLVE(msb_snapshot_import_with_options);
	RESOLVE(msb_snapshot_import_many);
	RESOLVE(msb_snapshot_group_head);
	RESOLVE(msb_sandbox_compact);
	library->ready = true;
	return NULL;
}
const char * load_microsandbox(const char *path) { return provider_load_microsandbox(&default_library, path); }

// is_microsandbox_loaded returns 1 after a successful load_microsandbox call.
int provider_is_microsandbox_loaded(msb_library *library) { return library->ready ? 1 : 0; }
int is_microsandbox_loaded() { return provider_is_microsandbox_loaded(&default_library); }

// ---------------------------------------------------------------------------
// Trampolines name an immutable library table; default adapters preserve the full-package entry points.
// Calling a NULL pointer is UB; callers must check IsLoaded() (ensureLoaded)
// before reaching these. The NULL guards here are a last-resort safety net.
// ---------------------------------------------------------------------------
void provider_call_msb_free_string(msb_library *library, char *ptr) {
	if (library->ptr_msb_free_string) library->ptr_msb_free_string(ptr);
}
void call_msb_free_string(char *ptr) { provider_call_msb_free_string(&default_library, ptr); }
void provider_call_msb_set_sdk_msb_path(msb_library *library, const char *path) {
	if (library->ptr_msb_set_sdk_msb_path) library->ptr_msb_set_sdk_msb_path(path);
}
void call_msb_set_sdk_msb_path(const char *path) { provider_call_msb_set_sdk_msb_path(&default_library, path); }
uint64_t provider_call_msb_cancel_alloc(msb_library *library) {
	return library->ptr_msb_cancel_alloc ? library->ptr_msb_cancel_alloc() : 0;
}
uint64_t call_msb_cancel_alloc(void) { return provider_call_msb_cancel_alloc(&default_library); }
void provider_call_msb_cancel_trigger(msb_library *library, uint64_t id) {
	if (library->ptr_msb_cancel_trigger) library->ptr_msb_cancel_trigger(id);
}
void call_msb_cancel_trigger(uint64_t id) { provider_call_msb_cancel_trigger(&default_library, id); }
void provider_call_msb_cancel_unregister(msb_library *library, uint64_t id) {
	if (library->ptr_msb_cancel_unregister) library->ptr_msb_cancel_unregister(id);
}
void call_msb_cancel_unregister(uint64_t id) { provider_call_msb_cancel_unregister(&default_library, id); }
bool provider_has_sandbox_shell_path(msb_library *library) { return library->ptr_msb_sandbox_shell_path != NULL; }
bool has_sandbox_shell_path(void) { return provider_has_sandbox_shell_path(&default_library); }
char * provider_call_msb_sandbox_shell_path(msb_library *library, uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) {
    return library->ptr_msb_sandbox_shell_path ? library->ptr_msb_sandbox_shell_path(cancel_id, handle, buf, buf_len) : NULL;
}
char * call_msb_sandbox_shell_path(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_shell_path(&default_library, cancel_id, handle, buf, buf_len); }
bool provider_has_sandbox_restore(msb_library *library) { return library->ptr_msb_sandbox_restore != NULL; }
bool has_sandbox_restore(void) { return provider_has_sandbox_restore(&default_library); }
char * provider_call_msb_sandbox_restore(msb_library *library, uint64_t cancel_id, const char *name, const char *opts_json, uint8_t *buf, size_t buf_len) {
    return library->ptr_msb_sandbox_restore ? library->ptr_msb_sandbox_restore(cancel_id, name, opts_json, buf, buf_len) : NULL;
}
char * call_msb_sandbox_restore(uint64_t cancel_id, const char *name, const char *opts_json, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_restore(&default_library, cancel_id, name, opts_json, buf, buf_len); }
char * provider_call_msb_sandbox_create(msb_library *library, uint64_t cancel_id, const char *name, const char *opts_json, bool connect_or_create, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_create ? library->ptr_msb_sandbox_create(cancel_id, name, opts_json, connect_or_create, buf, buf_len) : NULL;
}
char * call_msb_sandbox_create(uint64_t cancel_id, const char *name, const char *opts_json, bool connect_or_create, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_create(&default_library, cancel_id, name, opts_json, connect_or_create, buf, buf_len); }

bool provider_has_creation_progress(msb_library *library) { return library->ptr_msb_creation_progress_open && library->ptr_msb_creation_progress_recv && library->ptr_msb_creation_progress_close; }
bool has_creation_progress(void) { return provider_has_creation_progress(&default_library); }
char * provider_call_creation_progress_open(msb_library *library, uint8_t *buf, size_t len) { return library->ptr_msb_creation_progress_open(buf, len); }
char * call_creation_progress_open(uint8_t *buf, size_t len) { return provider_call_creation_progress_open(&default_library, buf, len); }
char * provider_call_creation_progress_recv(msb_library *library, uint64_t cancel, uint64_t id, uint8_t *buf, size_t len) { return library->ptr_msb_creation_progress_recv(cancel, id, buf, len); }
char * call_creation_progress_recv(uint64_t cancel, uint64_t id, uint8_t *buf, size_t len) { return provider_call_creation_progress_recv(&default_library, cancel, id, buf, len); }
char * provider_call_creation_progress_close(msb_library *library, uint64_t id, uint8_t *buf, size_t len) { return library->ptr_msb_creation_progress_close(id, buf, len); }
char * call_creation_progress_close(uint64_t id, uint8_t *buf, size_t len) { return provider_call_creation_progress_close(&default_library, id, buf, len); }
char * provider_call_msb_sandbox_handle_lifecycle(msb_library *library, uint64_t cancel_id, const char *name, const char *expected_id, const char *operation, const char *opts_json, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_handle_lifecycle ? library->ptr_msb_sandbox_handle_lifecycle(cancel_id, name, expected_id, operation, opts_json, buf, buf_len) : NULL;
}
char * call_msb_sandbox_handle_lifecycle(uint64_t cancel_id, const char *name, const char *expected_id, const char *operation, const char *opts_json, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_handle_lifecycle(&default_library, cancel_id, name, expected_id, operation, opts_json, buf, buf_len); }
char * provider_call_msb_sandbox_lookup(msb_library *library, uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_lookup ? library->ptr_msb_sandbox_lookup(cancel_id, name, buf, buf_len) : NULL;
}
char * call_msb_sandbox_lookup(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_lookup(&default_library, cancel_id, name, buf, buf_len); }

bool provider_has_msb_runtime_setup(msb_library *library) { return library->ptr_msb_runtime_setup != NULL; }
bool has_msb_runtime_setup(void) { return provider_has_msb_runtime_setup(&default_library); }
char * provider_call_msb_runtime_setup(msb_library *library, uint64_t cancel_id, const char *operation, const char *config_json, const char *options_json, uint8_t *buf, size_t buf_len) {
    return library->ptr_msb_runtime_setup(cancel_id, operation, config_json, options_json, buf, buf_len);
}
char * call_msb_runtime_setup(uint64_t cancel_id, const char *operation, const char *config_json, const char *options_json, uint8_t *buf, size_t buf_len) { return provider_call_msb_runtime_setup(&default_library, cancel_id, operation, config_json, options_json, buf, buf_len); }
char * provider_call_msb_default_backend_info(msb_library *library, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_default_backend_info ? library->ptr_msb_default_backend_info(buf, buf_len) : NULL;
}
char * call_msb_default_backend_info(uint8_t *buf, size_t buf_len) { return provider_call_msb_default_backend_info(&default_library, buf, buf_len); }
char * provider_call_msb_sandbox_connect(msb_library *library, uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_connect ? library->ptr_msb_sandbox_connect(cancel_id, name, buf, buf_len) : NULL;
}
char * call_msb_sandbox_connect(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_connect(&default_library, cancel_id, name, buf, buf_len); }
char * provider_call_msb_sandbox_start(msb_library *library, uint64_t cancel_id, const char *name, bool detached, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_start ? library->ptr_msb_sandbox_start(cancel_id, name, detached, buf, buf_len) : NULL;
}
char * call_msb_sandbox_start(uint64_t cancel_id, const char *name, bool detached, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_start(&default_library, cancel_id, name, detached, buf, buf_len); }
char * provider_call_msb_sandbox_handle_stop(msb_library *library, uint64_t cancel_id, const char *name, uint64_t timeout_ms, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_handle_stop ? library->ptr_msb_sandbox_handle_stop(cancel_id, name, timeout_ms, buf, buf_len) : NULL;
}
char * call_msb_sandbox_handle_stop(uint64_t cancel_id, const char *name, uint64_t timeout_ms, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_handle_stop(&default_library, cancel_id, name, timeout_ms, buf, buf_len); }
char * provider_call_msb_sandbox_handle_request_stop(msb_library *library, uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_handle_request_stop ? library->ptr_msb_sandbox_handle_request_stop(cancel_id, name, buf, buf_len) : NULL;
}
char * call_msb_sandbox_handle_request_stop(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_handle_request_stop(&default_library, cancel_id, name, buf, buf_len); }
char * provider_call_msb_sandbox_handle_kill(msb_library *library, uint64_t cancel_id, const char *name, uint64_t timeout_ms, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_handle_kill ? library->ptr_msb_sandbox_handle_kill(cancel_id, name, timeout_ms, buf, buf_len) : NULL;
}
char * call_msb_sandbox_handle_kill(uint64_t cancel_id, const char *name, uint64_t timeout_ms, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_handle_kill(&default_library, cancel_id, name, timeout_ms, buf, buf_len); }
char * provider_call_msb_sandbox_handle_request_kill(msb_library *library, uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_handle_request_kill ? library->ptr_msb_sandbox_handle_request_kill(cancel_id, name, buf, buf_len) : NULL;
}
char * call_msb_sandbox_handle_request_kill(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_handle_request_kill(&default_library, cancel_id, name, buf, buf_len); }
char * provider_call_msb_sandbox_handle_request_drain(msb_library *library, uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_handle_request_drain ? library->ptr_msb_sandbox_handle_request_drain(cancel_id, name, buf, buf_len) : NULL;
}
char * call_msb_sandbox_handle_request_drain(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_handle_request_drain(&default_library, cancel_id, name, buf, buf_len); }
char * provider_call_msb_sandbox_handle_wait_until_stopped(msb_library *library, uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_handle_wait_until_stopped ? library->ptr_msb_sandbox_handle_wait_until_stopped(cancel_id, name, buf, buf_len) : NULL;
}
char * call_msb_sandbox_handle_wait_until_stopped(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_handle_wait_until_stopped(&default_library, cancel_id, name, buf, buf_len); }
char * provider_call_msb_sandbox_handle_ping(msb_library *library, uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_handle_ping ? library->ptr_msb_sandbox_handle_ping(cancel_id, name, buf, buf_len) : NULL;
}
char * call_msb_sandbox_handle_ping(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_handle_ping(&default_library, cancel_id, name, buf, buf_len); }
char * provider_call_msb_sandbox_handle_touch(msb_library *library, uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_handle_touch ? library->ptr_msb_sandbox_handle_touch(cancel_id, name, buf, buf_len) : NULL;
}
char * call_msb_sandbox_handle_touch(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_handle_touch(&default_library, cancel_id, name, buf, buf_len); }
char * provider_call_msb_sandbox_handle_modify(msb_library *library, uint64_t cancel_id, const char *name, const char *opts_json, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_handle_modify ? library->ptr_msb_sandbox_handle_modify(cancel_id, name, opts_json, buf, buf_len) : NULL;
}
char * call_msb_sandbox_handle_modify(uint64_t cancel_id, const char *name, const char *opts_json, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_handle_modify(&default_library, cancel_id, name, opts_json, buf, buf_len); }
char * provider_call_msb_sandbox_close(msb_library *library, uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_close ? library->ptr_msb_sandbox_close(cancel_id, handle, buf, buf_len) : NULL;
}
char * call_msb_sandbox_close(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_close(&default_library, cancel_id, handle, buf, buf_len); }
char * provider_call_msb_sandbox_detach(msb_library *library, uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_detach ? library->ptr_msb_sandbox_detach(cancel_id, handle, buf, buf_len) : NULL;
}
char * call_msb_sandbox_detach(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_detach(&default_library, cancel_id, handle, buf, buf_len); }
char * provider_call_msb_sandbox_stop(msb_library *library, uint64_t cancel_id, uint64_t handle, uint64_t timeout_ms, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_stop ? library->ptr_msb_sandbox_stop(cancel_id, handle, timeout_ms, buf, buf_len) : NULL;
}
char * call_msb_sandbox_stop(uint64_t cancel_id, uint64_t handle, uint64_t timeout_ms, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_stop(&default_library, cancel_id, handle, timeout_ms, buf, buf_len); }
bool provider_has_graceful_stop_wait(msb_library *library) { return library->ptr_msb_sandbox_stop_gracefully != NULL; }
bool has_graceful_stop_wait(void) { return provider_has_graceful_stop_wait(&default_library); }
char * provider_call_msb_sandbox_stop_gracefully(msb_library *library, uint64_t cancel_id, uint64_t handle, uint8_t has_timeout, uint64_t timeout_ms, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_stop_gracefully ? library->ptr_msb_sandbox_stop_gracefully(cancel_id, handle, has_timeout, timeout_ms, buf, buf_len) : NULL;
}
char * call_msb_sandbox_stop_gracefully(uint64_t cancel_id, uint64_t handle, uint8_t has_timeout, uint64_t timeout_ms, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_stop_gracefully(&default_library, cancel_id, handle, has_timeout, timeout_ms, buf, buf_len); }
char * provider_call_msb_sandbox_request_stop(msb_library *library, uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_request_stop ? library->ptr_msb_sandbox_request_stop(cancel_id, handle, buf, buf_len) : NULL;
}
char * call_msb_sandbox_request_stop(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_request_stop(&default_library, cancel_id, handle, buf, buf_len); }
bool provider_has_external_mount_restore(msb_library *library) { return library->ptr_msb_sandbox_restore_warnings != NULL; }
bool has_external_mount_restore(void) { return provider_has_external_mount_restore(&default_library); }
char * provider_call_msb_sandbox_restore_warnings(msb_library *library, uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_restore_warnings ? library->ptr_msb_sandbox_restore_warnings(cancel_id, handle, buf, buf_len) : NULL;
}
char * call_msb_sandbox_restore_warnings(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_restore_warnings(&default_library, cancel_id, handle, buf, buf_len); }
char * provider_call_msb_sandbox_pause(msb_library *library, uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_pause ? library->ptr_msb_sandbox_pause(cancel_id, handle, buf, buf_len) : NULL;
}
char * call_msb_sandbox_pause(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_pause(&default_library, cancel_id, handle, buf, buf_len); }
char * provider_call_msb_sandbox_branch(msb_library *library, uint64_t cancel_id, uint64_t handle, const char *source, const char *child, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_branch ? library->ptr_msb_sandbox_branch(cancel_id, handle, source, child, buf, buf_len) : NULL;
}
char * call_msb_sandbox_branch(uint64_t cancel_id, uint64_t handle, const char *source, const char *child, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_branch(&default_library, cancel_id, handle, source, child, buf, buf_len); }
bool provider_has_branch_integrity(msb_library *library) { return library->ptr_msb_sandbox_branch_with_options != NULL; }
bool has_branch_integrity(void) { return provider_has_branch_integrity(&default_library); }
bool provider_has_guest_flush(msb_library *library) { return library->ptr_msb_sandbox_pause_with_guest_flush != NULL; }
bool has_guest_flush(void) { return provider_has_guest_flush(&default_library); }
char * provider_call_msb_sandbox_pause_with_guest_flush(msb_library *library, uint64_t cancel_id, uint64_t handle, const char *source, const char *expected_id, const char *policy, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_pause_with_guest_flush ? library->ptr_msb_sandbox_pause_with_guest_flush(cancel_id, handle, source, expected_id, policy, buf, buf_len) : NULL;
}
char * call_msb_sandbox_pause_with_guest_flush(uint64_t cancel_id, uint64_t handle, const char *source, const char *expected_id, const char *policy, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_pause_with_guest_flush(&default_library, cancel_id, handle, source, expected_id, policy, buf, buf_len); }
bool provider_has_branch_many(msb_library *library) { return library->ptr_msb_sandbox_branch_many != NULL; }
bool has_branch_many(void) { return provider_has_branch_many(&default_library); }
char * provider_call_msb_sandbox_branch_many(msb_library *library, uint64_t cancel_id, uint64_t handle, const char *source, const char *names, bool record_integrity, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_branch_many ? library->ptr_msb_sandbox_branch_many(cancel_id, handle, source, names, record_integrity, buf, buf_len) : NULL;
}
char * call_msb_sandbox_branch_many(uint64_t cancel_id, uint64_t handle, const char *source, const char *names, bool record_integrity, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_branch_many(&default_library, cancel_id, handle, source, names, record_integrity, buf, buf_len); }
char * provider_call_msb_sandbox_branch_with_options(msb_library *library, uint64_t cancel_id, uint64_t handle, const char *source, const char *child, bool record_integrity, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_branch_with_options ? library->ptr_msb_sandbox_branch_with_options(cancel_id, handle, source, child, record_integrity, buf, buf_len) : NULL;
}
char * call_msb_sandbox_branch_with_options(uint64_t cancel_id, uint64_t handle, const char *source, const char *child, bool record_integrity, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_branch_with_options(&default_library, cancel_id, handle, source, child, record_integrity, buf, buf_len); }
char * provider_call_msb_sandbox_resume(msb_library *library, uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_resume ? library->ptr_msb_sandbox_resume(cancel_id, handle, buf, buf_len) : NULL;
}
char * call_msb_sandbox_resume(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_resume(&default_library, cancel_id, handle, buf, buf_len); }
char * provider_call_msb_sandbox_handle_pause(msb_library *library, uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_handle_pause ? library->ptr_msb_sandbox_handle_pause(cancel_id, name, buf, buf_len) : NULL;
}
char * call_msb_sandbox_handle_pause(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_handle_pause(&default_library, cancel_id, name, buf, buf_len); }
char * provider_call_msb_sandbox_handle_resume(msb_library *library, uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_handle_resume ? library->ptr_msb_sandbox_handle_resume(cancel_id, name, buf, buf_len) : NULL;
}
char * call_msb_sandbox_handle_resume(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_handle_resume(&default_library, cancel_id, name, buf, buf_len); }
char * provider_call_msb_sandbox_kill(msb_library *library, uint64_t cancel_id, uint64_t handle, uint64_t timeout_ms, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_kill ? library->ptr_msb_sandbox_kill(cancel_id, handle, timeout_ms, buf, buf_len) : NULL;
}
char * call_msb_sandbox_kill(uint64_t cancel_id, uint64_t handle, uint64_t timeout_ms, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_kill(&default_library, cancel_id, handle, timeout_ms, buf, buf_len); }
char * provider_call_msb_sandbox_request_kill(msb_library *library, uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_request_kill ? library->ptr_msb_sandbox_request_kill(cancel_id, handle, buf, buf_len) : NULL;
}
char * call_msb_sandbox_request_kill(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_request_kill(&default_library, cancel_id, handle, buf, buf_len); }
int provider_has_persistent_resources(msb_library *library) { return library->ptr_msb_resource_operation && library->ptr_msb_resource_release; }
int has_persistent_resources(void) { return provider_has_persistent_resources(&default_library); }
char * provider_call_msb_resource_operation(msb_library *library, uint64_t cancel, uint64_t handle, const char *request, uint8_t *buf, size_t len) {
    return library->ptr_msb_resource_operation ? library->ptr_msb_resource_operation(cancel, handle, request, buf, len) : NULL;
}
char * call_msb_resource_operation(uint64_t cancel, uint64_t handle, const char *request, uint8_t *buf, size_t len) { return provider_call_msb_resource_operation(&default_library, cancel, handle, request, buf, len); }
void provider_call_msb_resource_release(msb_library *library, uint64_t handle) { if (library->ptr_msb_resource_release) library->ptr_msb_resource_release(handle); }
void call_msb_resource_release(uint64_t handle) { provider_call_msb_resource_release(&default_library, handle); }
int provider_has_contexts(msb_library *library) { return library->ptr_msb_context_create && library->ptr_msb_context_operation && library->ptr_msb_context_release; }
int has_contexts(void) { return provider_has_contexts(&default_library); }
char * provider_call_msb_context_create(msb_library *library, uint64_t cancel, const char *options, uint8_t *buf, size_t len) {
    return library->ptr_msb_context_create ? library->ptr_msb_context_create(cancel, options, buf, len) : NULL;
}
char * call_msb_context_create(uint64_t cancel, const char *options, uint8_t *buf, size_t len) { return provider_call_msb_context_create(&default_library, cancel, options, buf, len); }
char * provider_call_msb_context_operation(msb_library *library, uint64_t cancel, uint64_t handle, const char *request, uint8_t *buf, size_t len) {
    return library->ptr_msb_context_operation ? library->ptr_msb_context_operation(cancel, handle, request, buf, len) : NULL;
}
char * call_msb_context_operation(uint64_t cancel, uint64_t handle, const char *request, uint8_t *buf, size_t len) { return provider_call_msb_context_operation(&default_library, cancel, handle, request, buf, len); }
void provider_call_msb_context_release(msb_library *library, uint64_t handle) { if (library->ptr_msb_context_release) library->ptr_msb_context_release(handle); }
void call_msb_context_release(uint64_t handle) { provider_call_msb_context_release(&default_library, handle); }
int provider_has_sandbox_resource_wait(msb_library *library) {
    return library->ptr_msb_sandbox_resource_wait_for_status != NULL;
}
int has_sandbox_resource_wait(void) { return provider_has_sandbox_resource_wait(&default_library); }
char * provider_call_msb_sandbox_resource_wait_for_status(msb_library *library, uint64_t cancel_id, uint64_t handle, const char *status, uint8_t *buf, size_t len) {
    return library->ptr_msb_sandbox_resource_wait_for_status ? library->ptr_msb_sandbox_resource_wait_for_status(cancel_id, handle, status, buf, len) : NULL;
}
char * call_msb_sandbox_resource_wait_for_status(uint64_t cancel_id, uint64_t handle, const char *status, uint8_t *buf, size_t len) { return provider_call_msb_sandbox_resource_wait_for_status(&default_library, cancel_id, handle, status, buf, len); }
int provider_has_sandbox_resources(msb_library *library) {
    return library->ptr_msb_sandbox_resource_list && library->ptr_msb_sandbox_resource_operation;
}
int has_sandbox_resources(void) { return provider_has_sandbox_resources(&default_library); }
char * provider_call_msb_sandbox_resource_list(msb_library *library, uint64_t cancel_id, const char *filter, uint8_t *buf, size_t len) {
    return library->ptr_msb_sandbox_resource_list ? library->ptr_msb_sandbox_resource_list(cancel_id, filter, buf, len) : NULL;
}
char * call_msb_sandbox_resource_list(uint64_t cancel_id, const char *filter, uint8_t *buf, size_t len) { return provider_call_msb_sandbox_resource_list(&default_library, cancel_id, filter, buf, len); }
char * provider_call_msb_sandbox_resource_operation(msb_library *library, uint64_t cancel_id, uint64_t handle, const char *op, uint8_t *buf, size_t len) {
    return library->ptr_msb_sandbox_resource_operation ? library->ptr_msb_sandbox_resource_operation(cancel_id, handle, op, buf, len) : NULL;
}
char * call_msb_sandbox_resource_operation(uint64_t cancel_id, uint64_t handle, const char *op, uint8_t *buf, size_t len) { return provider_call_msb_sandbox_resource_operation(&default_library, cancel_id, handle, op, buf, len); }
char * provider_call_msb_sandbox_list(msb_library *library, uint64_t cancel_id, const char *filter_json, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_list ? library->ptr_msb_sandbox_list(cancel_id, filter_json, buf, buf_len) : NULL;
}
char * call_msb_sandbox_list(uint64_t cancel_id, const char *filter_json, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_list(&default_library, cancel_id, filter_json, buf, buf_len); }
char * provider_call_msb_sandbox_remove(msb_library *library, uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_remove ? library->ptr_msb_sandbox_remove(cancel_id, name, buf, buf_len) : NULL;
}
char * call_msb_sandbox_remove(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_remove(&default_library, cancel_id, name, buf, buf_len); }
int provider_has_msb_jobs(msb_library *library) { return library->ptr_msb_jobs != NULL; }
int has_msb_jobs(void) { return provider_has_msb_jobs(&default_library); }
char * provider_call_msb_jobs(msb_library *library, uint64_t cancel_id, uint64_t sandbox, const char *request, uint8_t *buf, size_t buf_len) {
    return library->ptr_msb_jobs ? library->ptr_msb_jobs(cancel_id, sandbox, request, buf, buf_len) : NULL;
}
char * call_msb_jobs(uint64_t cancel_id, uint64_t sandbox, const char *request, uint8_t *buf, size_t buf_len) { return provider_call_msb_jobs(&default_library, cancel_id, sandbox, request, buf, buf_len); }
char * provider_call_msb_sandbox_exec(msb_library *library, uint64_t cancel_id, uint64_t handle, const char *cmd, const char *opts, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_exec ? library->ptr_msb_sandbox_exec(cancel_id, handle, cmd, opts, buf, buf_len) : NULL;
}
char * call_msb_sandbox_exec(uint64_t cancel_id, uint64_t handle, const char *cmd, const char *opts, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_exec(&default_library, cancel_id, handle, cmd, opts, buf, buf_len); }
char * provider_call_msb_sandbox_exec_default(msb_library *library, uint64_t cancel_id, uint64_t handle, const char *opts, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_exec_default ? library->ptr_msb_sandbox_exec_default(cancel_id, handle, opts, buf, buf_len) : NULL;
}
char * call_msb_sandbox_exec_default(uint64_t cancel_id, uint64_t handle, const char *opts, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_exec_default(&default_library, cancel_id, handle, opts, buf, buf_len); }
char * provider_call_msb_sandbox_exec_stream(msb_library *library, uint64_t cancel_id, uint64_t handle, const char *cmd, const char *opts, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_exec_stream ? library->ptr_msb_sandbox_exec_stream(cancel_id, handle, cmd, opts, buf, buf_len) : NULL;
}
char * call_msb_sandbox_exec_stream(uint64_t cancel_id, uint64_t handle, const char *cmd, const char *opts, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_exec_stream(&default_library, cancel_id, handle, cmd, opts, buf, buf_len); }
char * provider_call_msb_sandbox_exec_default_stream(msb_library *library, uint64_t cancel_id, uint64_t handle, const char *opts, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_exec_default_stream ? library->ptr_msb_sandbox_exec_default_stream(cancel_id, handle, opts, buf, buf_len) : NULL;
}
char * call_msb_sandbox_exec_default_stream(uint64_t cancel_id, uint64_t handle, const char *opts, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_exec_default_stream(&default_library, cancel_id, handle, opts, buf, buf_len); }
char * provider_call_msb_sandbox_metrics(msb_library *library, uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_metrics ? library->ptr_msb_sandbox_metrics(cancel_id, handle, buf, buf_len) : NULL;
}
char * call_msb_sandbox_metrics(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_metrics(&default_library, cancel_id, handle, buf, buf_len); }
char * provider_call_msb_sandbox_ssh_connect(msb_library *library, uint64_t cancel_id, uint64_t handle, const char *opts, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_ssh_connect ? library->ptr_msb_sandbox_ssh_connect(cancel_id, handle, opts, buf, buf_len) : NULL;
}
char * call_msb_sandbox_ssh_connect(uint64_t cancel_id, uint64_t handle, const char *opts, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_ssh_connect(&default_library, cancel_id, handle, opts, buf, buf_len); }
char * provider_call_msb_sandbox_ssh_server(msb_library *library, uint64_t cancel_id, uint64_t handle, const char *opts, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_ssh_server ? library->ptr_msb_sandbox_ssh_server(cancel_id, handle, opts, buf, buf_len) : NULL;
}
char * call_msb_sandbox_ssh_server(uint64_t cancel_id, uint64_t handle, const char *opts, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_ssh_server(&default_library, cancel_id, handle, opts, buf, buf_len); }
char * provider_call_msb_ssh_server_close(msb_library *library, uint64_t cancel_id, uint64_t server_handle, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_ssh_server_close ? library->ptr_msb_ssh_server_close(cancel_id, server_handle, buf, buf_len) : NULL;
}
char * call_msb_ssh_server_close(uint64_t cancel_id, uint64_t server_handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_ssh_server_close(&default_library, cancel_id, server_handle, buf, buf_len); }
char * provider_call_msb_ssh_server_serve_connection(msb_library *library, uint64_t cancel_id, uint64_t server_handle, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_ssh_server_serve_connection ? library->ptr_msb_ssh_server_serve_connection(cancel_id, server_handle, buf, buf_len) : NULL;
}
char * call_msb_ssh_server_serve_connection(uint64_t cancel_id, uint64_t server_handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_ssh_server_serve_connection(&default_library, cancel_id, server_handle, buf, buf_len); }
char * provider_call_msb_ssh_client_exec(msb_library *library, uint64_t cancel_id, uint64_t client_handle, const char *command, const char *opts, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_ssh_client_exec ? library->ptr_msb_ssh_client_exec(cancel_id, client_handle, command, opts, buf, buf_len) : NULL;
}
char * call_msb_ssh_client_exec(uint64_t cancel_id, uint64_t client_handle, const char *command, const char *opts, uint8_t *buf, size_t buf_len) { return provider_call_msb_ssh_client_exec(&default_library, cancel_id, client_handle, command, opts, buf, buf_len); }
char * provider_call_msb_ssh_client_attach(msb_library *library, uint64_t cancel_id, uint64_t client_handle, const char *opts, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_ssh_client_attach ? library->ptr_msb_ssh_client_attach(cancel_id, client_handle, opts, buf, buf_len) : NULL;
}
char * call_msb_ssh_client_attach(uint64_t cancel_id, uint64_t client_handle, const char *opts, uint8_t *buf, size_t buf_len) { return provider_call_msb_ssh_client_attach(&default_library, cancel_id, client_handle, opts, buf, buf_len); }
char * provider_call_msb_ssh_client_close(msb_library *library, uint64_t cancel_id, uint64_t client_handle, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_ssh_client_close ? library->ptr_msb_ssh_client_close(cancel_id, client_handle, buf, buf_len) : NULL;
}
char * call_msb_ssh_client_close(uint64_t cancel_id, uint64_t client_handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_ssh_client_close(&default_library, cancel_id, client_handle, buf, buf_len); }
char * provider_call_msb_ssh_client_sftp(msb_library *library, uint64_t cancel_id, uint64_t client_handle, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_ssh_client_sftp ? library->ptr_msb_ssh_client_sftp(cancel_id, client_handle, buf, buf_len) : NULL;
}
char * call_msb_ssh_client_sftp(uint64_t cancel_id, uint64_t client_handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_ssh_client_sftp(&default_library, cancel_id, client_handle, buf, buf_len); }
char * provider_call_msb_sftp_read(msb_library *library, uint64_t cancel_id, uint64_t sftp_handle, const char *path, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sftp_read ? library->ptr_msb_sftp_read(cancel_id, sftp_handle, path, buf, buf_len) : NULL;
}
char * call_msb_sftp_read(uint64_t cancel_id, uint64_t sftp_handle, const char *path, uint8_t *buf, size_t buf_len) { return provider_call_msb_sftp_read(&default_library, cancel_id, sftp_handle, path, buf, buf_len); }
char * provider_call_msb_sftp_write(msb_library *library, uint64_t cancel_id, uint64_t sftp_handle, const char *path, const char *data_b64, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sftp_write ? library->ptr_msb_sftp_write(cancel_id, sftp_handle, path, data_b64, buf, buf_len) : NULL;
}
char * call_msb_sftp_write(uint64_t cancel_id, uint64_t sftp_handle, const char *path, const char *data_b64, uint8_t *buf, size_t buf_len) { return provider_call_msb_sftp_write(&default_library, cancel_id, sftp_handle, path, data_b64, buf, buf_len); }
char * provider_call_msb_sftp_mkdir(msb_library *library, uint64_t cancel_id, uint64_t sftp_handle, const char *path, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sftp_mkdir ? library->ptr_msb_sftp_mkdir(cancel_id, sftp_handle, path, buf, buf_len) : NULL;
}
char * call_msb_sftp_mkdir(uint64_t cancel_id, uint64_t sftp_handle, const char *path, uint8_t *buf, size_t buf_len) { return provider_call_msb_sftp_mkdir(&default_library, cancel_id, sftp_handle, path, buf, buf_len); }
char * provider_call_msb_sftp_remove_file(msb_library *library, uint64_t cancel_id, uint64_t sftp_handle, const char *path, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sftp_remove_file ? library->ptr_msb_sftp_remove_file(cancel_id, sftp_handle, path, buf, buf_len) : NULL;
}
char * call_msb_sftp_remove_file(uint64_t cancel_id, uint64_t sftp_handle, const char *path, uint8_t *buf, size_t buf_len) { return provider_call_msb_sftp_remove_file(&default_library, cancel_id, sftp_handle, path, buf, buf_len); }
char * provider_call_msb_sftp_remove_dir(msb_library *library, uint64_t cancel_id, uint64_t sftp_handle, const char *path, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sftp_remove_dir ? library->ptr_msb_sftp_remove_dir(cancel_id, sftp_handle, path, buf, buf_len) : NULL;
}
char * call_msb_sftp_remove_dir(uint64_t cancel_id, uint64_t sftp_handle, const char *path, uint8_t *buf, size_t buf_len) { return provider_call_msb_sftp_remove_dir(&default_library, cancel_id, sftp_handle, path, buf, buf_len); }
char * provider_call_msb_sftp_rename(msb_library *library, uint64_t cancel_id, uint64_t sftp_handle, const char *old_path, const char *new_path, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sftp_rename ? library->ptr_msb_sftp_rename(cancel_id, sftp_handle, old_path, new_path, buf, buf_len) : NULL;
}
char * call_msb_sftp_rename(uint64_t cancel_id, uint64_t sftp_handle, const char *old_path, const char *new_path, uint8_t *buf, size_t buf_len) { return provider_call_msb_sftp_rename(&default_library, cancel_id, sftp_handle, old_path, new_path, buf, buf_len); }
char * provider_call_msb_sftp_real_path(msb_library *library, uint64_t cancel_id, uint64_t sftp_handle, const char *path, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sftp_real_path ? library->ptr_msb_sftp_real_path(cancel_id, sftp_handle, path, buf, buf_len) : NULL;
}
char * call_msb_sftp_real_path(uint64_t cancel_id, uint64_t sftp_handle, const char *path, uint8_t *buf, size_t buf_len) { return provider_call_msb_sftp_real_path(&default_library, cancel_id, sftp_handle, path, buf, buf_len); }
char * provider_call_msb_sftp_read_link(msb_library *library, uint64_t cancel_id, uint64_t sftp_handle, const char *path, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sftp_read_link ? library->ptr_msb_sftp_read_link(cancel_id, sftp_handle, path, buf, buf_len) : NULL;
}
char * call_msb_sftp_read_link(uint64_t cancel_id, uint64_t sftp_handle, const char *path, uint8_t *buf, size_t buf_len) { return provider_call_msb_sftp_read_link(&default_library, cancel_id, sftp_handle, path, buf, buf_len); }
char * provider_call_msb_sftp_symlink(msb_library *library, uint64_t cancel_id, uint64_t sftp_handle, const char *target, const char *link_path, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sftp_symlink ? library->ptr_msb_sftp_symlink(cancel_id, sftp_handle, target, link_path, buf, buf_len) : NULL;
}
char * call_msb_sftp_symlink(uint64_t cancel_id, uint64_t sftp_handle, const char *target, const char *link_path, uint8_t *buf, size_t buf_len) { return provider_call_msb_sftp_symlink(&default_library, cancel_id, sftp_handle, target, link_path, buf, buf_len); }
char * provider_call_msb_sftp_close(msb_library *library, uint64_t cancel_id, uint64_t sftp_handle, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sftp_close ? library->ptr_msb_sftp_close(cancel_id, sftp_handle, buf, buf_len) : NULL;
}
char * call_msb_sftp_close(uint64_t cancel_id, uint64_t sftp_handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_sftp_close(&default_library, cancel_id, sftp_handle, buf, buf_len); }
char * provider_call_msb_exec_recv(msb_library *library, uint64_t cancel_id, uint64_t exec_handle, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_exec_recv ? library->ptr_msb_exec_recv(cancel_id, exec_handle, buf, buf_len) : NULL;
}
char * call_msb_exec_recv(uint64_t cancel_id, uint64_t exec_handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_exec_recv(&default_library, cancel_id, exec_handle, buf, buf_len); }
char * provider_call_msb_exec_close(msb_library *library, uint64_t cancel_id, uint64_t exec_handle, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_exec_close ? library->ptr_msb_exec_close(cancel_id, exec_handle, buf, buf_len) : NULL;
}
char * call_msb_exec_close(uint64_t cancel_id, uint64_t exec_handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_exec_close(&default_library, cancel_id, exec_handle, buf, buf_len); }
char * provider_call_msb_exec_signal(msb_library *library, uint64_t cancel_id, uint64_t exec_handle, int32_t signal, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_exec_signal ? library->ptr_msb_exec_signal(cancel_id, exec_handle, signal, buf, buf_len) : NULL;
}
char * call_msb_exec_signal(uint64_t cancel_id, uint64_t exec_handle, int32_t signal, uint8_t *buf, size_t buf_len) { return provider_call_msb_exec_signal(&default_library, cancel_id, exec_handle, signal, buf, buf_len); }
char * provider_call_msb_exec_resize(msb_library *library, uint64_t cancel_id, uint64_t exec_handle, uint16_t rows, uint16_t cols, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_exec_resize ? library->ptr_msb_exec_resize(cancel_id, exec_handle, rows, cols, buf, buf_len) : NULL;
}
char * call_msb_exec_resize(uint64_t cancel_id, uint64_t exec_handle, uint16_t rows, uint16_t cols, uint8_t *buf, size_t buf_len) { return provider_call_msb_exec_resize(&default_library, cancel_id, exec_handle, rows, cols, buf, buf_len); }
char * provider_call_msb_fs_read(msb_library *library, uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_fs_read ? library->ptr_msb_fs_read(cancel_id, handle, path, buf, buf_len) : NULL;
}
char * call_msb_fs_read(uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len) { return provider_call_msb_fs_read(&default_library, cancel_id, handle, path, buf, buf_len); }
char * provider_call_msb_fs_write(msb_library *library, uint64_t cancel_id, uint64_t handle, const char *path, const char *data_b64, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_fs_write ? library->ptr_msb_fs_write(cancel_id, handle, path, data_b64, buf, buf_len) : NULL;
}
char * call_msb_fs_write(uint64_t cancel_id, uint64_t handle, const char *path, const char *data_b64, uint8_t *buf, size_t buf_len) { return provider_call_msb_fs_write(&default_library, cancel_id, handle, path, data_b64, buf, buf_len); }
char * provider_call_msb_fs_list(msb_library *library, uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_fs_list ? library->ptr_msb_fs_list(cancel_id, handle, path, buf, buf_len) : NULL;
}
char * call_msb_fs_list(uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len) { return provider_call_msb_fs_list(&default_library, cancel_id, handle, path, buf, buf_len); }
char * provider_call_msb_fs_stat(msb_library *library, uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_fs_stat ? library->ptr_msb_fs_stat(cancel_id, handle, path, buf, buf_len) : NULL;
}
char * call_msb_fs_stat(uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len) { return provider_call_msb_fs_stat(&default_library, cancel_id, handle, path, buf, buf_len); }
char * provider_call_msb_fs_copy_from_host(msb_library *library, uint64_t cancel_id, uint64_t handle, const char *host_path, const char *guest_path, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_fs_copy_from_host ? library->ptr_msb_fs_copy_from_host(cancel_id, handle, host_path, guest_path, buf, buf_len) : NULL;
}
char * call_msb_fs_copy_from_host(uint64_t cancel_id, uint64_t handle, const char *host_path, const char *guest_path, uint8_t *buf, size_t buf_len) { return provider_call_msb_fs_copy_from_host(&default_library, cancel_id, handle, host_path, guest_path, buf, buf_len); }
char * provider_call_msb_fs_copy_to_host(msb_library *library, uint64_t cancel_id, uint64_t handle, const char *guest_path, const char *host_path, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_fs_copy_to_host ? library->ptr_msb_fs_copy_to_host(cancel_id, handle, guest_path, host_path, buf, buf_len) : NULL;
}
char * call_msb_fs_copy_to_host(uint64_t cancel_id, uint64_t handle, const char *guest_path, const char *host_path, uint8_t *buf, size_t buf_len) { return provider_call_msb_fs_copy_to_host(&default_library, cancel_id, handle, guest_path, host_path, buf, buf_len); }
char * provider_call_msb_fs_mkdir(msb_library *library, uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_fs_mkdir ? library->ptr_msb_fs_mkdir(cancel_id, handle, path, buf, buf_len) : NULL;
}
char * call_msb_fs_mkdir(uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len) { return provider_call_msb_fs_mkdir(&default_library, cancel_id, handle, path, buf, buf_len); }
char * provider_call_msb_fs_remove(msb_library *library, uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_fs_remove ? library->ptr_msb_fs_remove(cancel_id, handle, path, buf, buf_len) : NULL;
}
char * call_msb_fs_remove(uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len) { return provider_call_msb_fs_remove(&default_library, cancel_id, handle, path, buf, buf_len); }
char * provider_call_msb_fs_remove_dir(msb_library *library, uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_fs_remove_dir ? library->ptr_msb_fs_remove_dir(cancel_id, handle, path, buf, buf_len) : NULL;
}
char * call_msb_fs_remove_dir(uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len) { return provider_call_msb_fs_remove_dir(&default_library, cancel_id, handle, path, buf, buf_len); }
char * provider_call_msb_fs_copy(msb_library *library, uint64_t cancel_id, uint64_t handle, const char *src, const char *dst, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_fs_copy ? library->ptr_msb_fs_copy(cancel_id, handle, src, dst, buf, buf_len) : NULL;
}
char * call_msb_fs_copy(uint64_t cancel_id, uint64_t handle, const char *src, const char *dst, uint8_t *buf, size_t buf_len) { return provider_call_msb_fs_copy(&default_library, cancel_id, handle, src, dst, buf, buf_len); }
char * provider_call_msb_fs_rename(msb_library *library, uint64_t cancel_id, uint64_t handle, const char *src, const char *dst, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_fs_rename ? library->ptr_msb_fs_rename(cancel_id, handle, src, dst, buf, buf_len) : NULL;
}
char * call_msb_fs_rename(uint64_t cancel_id, uint64_t handle, const char *src, const char *dst, uint8_t *buf, size_t buf_len) { return provider_call_msb_fs_rename(&default_library, cancel_id, handle, src, dst, buf, buf_len); }
char * provider_call_msb_fs_exists(msb_library *library, uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_fs_exists ? library->ptr_msb_fs_exists(cancel_id, handle, path, buf, buf_len) : NULL;
}
char * call_msb_fs_exists(uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len) { return provider_call_msb_fs_exists(&default_library, cancel_id, handle, path, buf, buf_len); }
char * provider_call_msb_sandbox_metrics_stream(msb_library *library, uint64_t cancel_id, uint64_t handle, uint64_t interval_ms, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_metrics_stream ? library->ptr_msb_sandbox_metrics_stream(cancel_id, handle, interval_ms, buf, buf_len) : NULL;
}
char * call_msb_sandbox_metrics_stream(uint64_t cancel_id, uint64_t handle, uint64_t interval_ms, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_metrics_stream(&default_library, cancel_id, handle, interval_ms, buf, buf_len); }
char * provider_call_msb_metrics_recv(msb_library *library, uint64_t cancel_id, uint64_t stream_handle, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_metrics_recv ? library->ptr_msb_metrics_recv(cancel_id, stream_handle, buf, buf_len) : NULL;
}
char * call_msb_metrics_recv(uint64_t cancel_id, uint64_t stream_handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_metrics_recv(&default_library, cancel_id, stream_handle, buf, buf_len); }
char * provider_call_msb_metrics_close(msb_library *library, uint64_t stream_handle, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_metrics_close ? library->ptr_msb_metrics_close(stream_handle, buf, buf_len) : NULL;
}
char * call_msb_metrics_close(uint64_t stream_handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_metrics_close(&default_library, stream_handle, buf, buf_len); }
char * provider_call_msb_exec_stdin_write(msb_library *library, uint64_t cancel_id, uint64_t exec_handle, const char *data_b64, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_exec_stdin_write ? library->ptr_msb_exec_stdin_write(cancel_id, exec_handle, data_b64, buf, buf_len) : NULL;
}
char * call_msb_exec_stdin_write(uint64_t cancel_id, uint64_t exec_handle, const char *data_b64, uint8_t *buf, size_t buf_len) { return provider_call_msb_exec_stdin_write(&default_library, cancel_id, exec_handle, data_b64, buf, buf_len); }
char * provider_call_msb_exec_stdin_close(msb_library *library, uint64_t cancel_id, uint64_t exec_handle, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_exec_stdin_close ? library->ptr_msb_exec_stdin_close(cancel_id, exec_handle, buf, buf_len) : NULL;
}
char * call_msb_exec_stdin_close(uint64_t cancel_id, uint64_t exec_handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_exec_stdin_close(&default_library, cancel_id, exec_handle, buf, buf_len); }
char * provider_call_msb_sandbox_request_drain(msb_library *library, uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_request_drain ? library->ptr_msb_sandbox_request_drain(cancel_id, handle, buf, buf_len) : NULL;
}
char * call_msb_sandbox_request_drain(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_request_drain(&default_library, cancel_id, handle, buf, buf_len); }
char * provider_call_msb_sandbox_wait_until_stopped(msb_library *library, uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_wait_until_stopped ? library->ptr_msb_sandbox_wait_until_stopped(cancel_id, handle, buf, buf_len) : NULL;
}
char * call_msb_sandbox_wait_until_stopped(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_wait_until_stopped(&default_library, cancel_id, handle, buf, buf_len); }
char * provider_call_msb_sandbox_owns_lifecycle(msb_library *library, uint64_t handle, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_owns_lifecycle ? library->ptr_msb_sandbox_owns_lifecycle(handle, buf, buf_len) : NULL;
}
char * call_msb_sandbox_owns_lifecycle(uint64_t handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_owns_lifecycle(&default_library, handle, buf, buf_len); }
char * provider_call_msb_sandbox_ping(msb_library *library, uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_ping ? library->ptr_msb_sandbox_ping(cancel_id, handle, buf, buf_len) : NULL;
}
char * call_msb_sandbox_ping(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_ping(&default_library, cancel_id, handle, buf, buf_len); }
char * provider_call_msb_sandbox_touch(msb_library *library, uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_touch ? library->ptr_msb_sandbox_touch(cancel_id, handle, buf, buf_len) : NULL;
}
char * call_msb_sandbox_touch(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_touch(&default_library, cancel_id, handle, buf, buf_len); }
char * provider_call_msb_sandbox_modify(msb_library *library, uint64_t cancel_id, uint64_t handle, const char *opts_json, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_modify ? library->ptr_msb_sandbox_modify(cancel_id, handle, opts_json, buf, buf_len) : NULL;
}
char * call_msb_sandbox_modify(uint64_t cancel_id, uint64_t handle, const char *opts_json, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_modify(&default_library, cancel_id, handle, opts_json, buf, buf_len); }
bool provider_has_execution_result(msb_library *library) { return library->ptr_msb_execution_result != NULL; }
char *provider_call_execution_result(msb_library *library, uint64_t cancel, uint64_t handle, const char *op, const char *command, const char *options, uint8_t **output, size_t *len) {
    return library->ptr_msb_execution_result(cancel, handle, op, command, options, output, len);
}
char * provider_call_msb_exec_collect(msb_library *library, uint64_t cancel_id, uint64_t exec_handle, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_exec_collect ? library->ptr_msb_exec_collect(cancel_id, exec_handle, buf, buf_len) : NULL;
}
char * call_msb_exec_collect(uint64_t cancel_id, uint64_t exec_handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_exec_collect(&default_library, cancel_id, exec_handle, buf, buf_len); }
char * provider_call_msb_exec_wait(msb_library *library, uint64_t cancel_id, uint64_t exec_handle, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_exec_wait ? library->ptr_msb_exec_wait(cancel_id, exec_handle, buf, buf_len) : NULL;
}
char * call_msb_exec_wait(uint64_t cancel_id, uint64_t exec_handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_exec_wait(&default_library, cancel_id, exec_handle, buf, buf_len); }
char * provider_call_msb_exec_kill(msb_library *library, uint64_t cancel_id, uint64_t exec_handle, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_exec_kill ? library->ptr_msb_exec_kill(cancel_id, exec_handle, buf, buf_len) : NULL;
}
char * call_msb_exec_kill(uint64_t cancel_id, uint64_t exec_handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_exec_kill(&default_library, cancel_id, exec_handle, buf, buf_len); }
char * provider_call_msb_exec_id(msb_library *library, uint64_t exec_handle, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_exec_id ? library->ptr_msb_exec_id(exec_handle, buf, buf_len) : NULL;
}
char * call_msb_exec_id(uint64_t exec_handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_exec_id(&default_library, exec_handle, buf, buf_len); }
char * provider_call_msb_sandbox_attach(msb_library *library, uint64_t cancel_id, uint64_t handle, const char *cmd, const char *opts_json, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_attach ? library->ptr_msb_sandbox_attach(cancel_id, handle, cmd, opts_json, buf, buf_len) : NULL;
}
char * call_msb_sandbox_attach(uint64_t cancel_id, uint64_t handle, const char *cmd, const char *opts_json, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_attach(&default_library, cancel_id, handle, cmd, opts_json, buf, buf_len); }
char * provider_call_msb_sandbox_attach_default(msb_library *library, uint64_t cancel_id, uint64_t handle, const char *opts_json, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_attach_default ? library->ptr_msb_sandbox_attach_default(cancel_id, handle, opts_json, buf, buf_len) : NULL;
}
char * call_msb_sandbox_attach_default(uint64_t cancel_id, uint64_t handle, const char *opts_json, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_attach_default(&default_library, cancel_id, handle, opts_json, buf, buf_len); }
char * provider_call_msb_sandbox_attach_shell(msb_library *library, uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_attach_shell ? library->ptr_msb_sandbox_attach_shell(cancel_id, handle, buf, buf_len) : NULL;
}
char * call_msb_sandbox_attach_shell(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_attach_shell(&default_library, cancel_id, handle, buf, buf_len); }
char * provider_call_msb_all_sandbox_metrics(msb_library *library, uint64_t cancel_id, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_all_sandbox_metrics ? library->ptr_msb_all_sandbox_metrics(cancel_id, buf, buf_len) : NULL;
}
char * call_msb_all_sandbox_metrics(uint64_t cancel_id, uint8_t *buf, size_t buf_len) { return provider_call_msb_all_sandbox_metrics(&default_library, cancel_id, buf, buf_len); }
char * provider_call_msb_sandbox_handle_metrics(msb_library *library, uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_handle_metrics ? library->ptr_msb_sandbox_handle_metrics(cancel_id, name, buf, buf_len) : NULL;
}
char * call_msb_sandbox_handle_metrics(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_handle_metrics(&default_library, cancel_id, name, buf, buf_len); }
char * provider_call_msb_sandbox_logs(msb_library *library, uint64_t cancel_id, uint64_t handle, const char *opts_json, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_logs ? library->ptr_msb_sandbox_logs(cancel_id, handle, opts_json, buf, buf_len) : NULL;
}
char * call_msb_sandbox_logs(uint64_t cancel_id, uint64_t handle, const char *opts_json, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_logs(&default_library, cancel_id, handle, opts_json, buf, buf_len); }
char * provider_call_msb_sandbox_handle_logs(msb_library *library, uint64_t cancel_id, const char *name, const char *opts_json, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_handle_logs ? library->ptr_msb_sandbox_handle_logs(cancel_id, name, opts_json, buf, buf_len) : NULL;
}
char * call_msb_sandbox_handle_logs(uint64_t cancel_id, const char *name, const char *opts_json, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_handle_logs(&default_library, cancel_id, name, opts_json, buf, buf_len); }
char * provider_call_msb_sandbox_log_stream(msb_library *library, uint64_t cancel_id, uint64_t handle, const char *opts_json, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_log_stream ? library->ptr_msb_sandbox_log_stream(cancel_id, handle, opts_json, buf, buf_len) : NULL;
}
char * call_msb_sandbox_log_stream(uint64_t cancel_id, uint64_t handle, const char *opts_json, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_log_stream(&default_library, cancel_id, handle, opts_json, buf, buf_len); }
char * provider_call_msb_sandbox_handle_log_stream(msb_library *library, uint64_t cancel_id, const char *name, const char *opts_json, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_handle_log_stream ? library->ptr_msb_sandbox_handle_log_stream(cancel_id, name, opts_json, buf, buf_len) : NULL;
}
char * call_msb_sandbox_handle_log_stream(uint64_t cancel_id, const char *name, const char *opts_json, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_handle_log_stream(&default_library, cancel_id, name, opts_json, buf, buf_len); }
char * provider_call_msb_log_recv(msb_library *library, uint64_t cancel_id, uint64_t stream_handle, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_log_recv ? library->ptr_msb_log_recv(cancel_id, stream_handle, buf, buf_len) : NULL;
}
char * call_msb_log_recv(uint64_t cancel_id, uint64_t stream_handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_log_recv(&default_library, cancel_id, stream_handle, buf, buf_len); }
char * provider_call_msb_log_close(msb_library *library, uint64_t stream_handle, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_log_close ? library->ptr_msb_log_close(stream_handle, buf, buf_len) : NULL;
}
char * call_msb_log_close(uint64_t stream_handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_log_close(&default_library, stream_handle, buf, buf_len); }
char * provider_call_msb_volume_create(msb_library *library, uint64_t cancel_id, const char *name, const char *opts_json, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_volume_create ? library->ptr_msb_volume_create(cancel_id, name, opts_json, buf, buf_len) : NULL;
}
char * call_msb_volume_create(uint64_t cancel_id, const char *name, const char *opts_json, uint8_t *buf, size_t buf_len) { return provider_call_msb_volume_create(&default_library, cancel_id, name, opts_json, buf, buf_len); }
char * provider_call_msb_volume_remove(msb_library *library, uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_volume_remove ? library->ptr_msb_volume_remove(cancel_id, name, buf, buf_len) : NULL;
}
char * call_msb_volume_remove(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) { return provider_call_msb_volume_remove(&default_library, cancel_id, name, buf, buf_len); }
char * provider_call_msb_volume_list(msb_library *library, uint64_t cancel_id, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_volume_list ? library->ptr_msb_volume_list(cancel_id, buf, buf_len) : NULL;
}
char * call_msb_volume_list(uint64_t cancel_id, uint8_t *buf, size_t buf_len) { return provider_call_msb_volume_list(&default_library, cancel_id, buf, buf_len); }
char * provider_call_msb_volume_get(msb_library *library, uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_volume_get ? library->ptr_msb_volume_get(cancel_id, name, buf, buf_len) : NULL;
}
char * call_msb_volume_get(uint64_t cancel_id, const char *name, uint8_t *buf, size_t buf_len) { return provider_call_msb_volume_get(&default_library, cancel_id, name, buf, buf_len); }
char * provider_call_msb_volume_get_default(msb_library *library, uint64_t cancel_id, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_volume_get_default ? library->ptr_msb_volume_get_default(cancel_id, buf, buf_len) : NULL;
}
char * call_msb_volume_get_default(uint64_t cancel_id, uint8_t *buf, size_t buf_len) { return provider_call_msb_volume_get_default(&default_library, cancel_id, buf, buf_len); }
char * provider_call_msb_volume_fs_op(msb_library *library, uint64_t cancel_id, const char *name, const char *op, const char *args_json, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_volume_fs_op ? library->ptr_msb_volume_fs_op(cancel_id, name, op, args_json, buf, buf_len) : NULL;
}
char * call_msb_volume_fs_op(uint64_t cancel_id, const char *name, const char *op, const char *args_json, uint8_t *buf, size_t buf_len) { return provider_call_msb_volume_fs_op(&default_library, cancel_id, name, op, args_json, buf, buf_len); }
char * provider_call_msb_fs_read_stream(msb_library *library, uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_fs_read_stream ? library->ptr_msb_fs_read_stream(cancel_id, handle, path, buf, buf_len) : NULL;
}
char * call_msb_fs_read_stream(uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len) { return provider_call_msb_fs_read_stream(&default_library, cancel_id, handle, path, buf, buf_len); }
char * provider_call_msb_fs_read_stream_recv(msb_library *library, uint64_t cancel_id, uint64_t stream_handle, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_fs_read_stream_recv ? library->ptr_msb_fs_read_stream_recv(cancel_id, stream_handle, buf, buf_len) : NULL;
}
char * call_msb_fs_read_stream_recv(uint64_t cancel_id, uint64_t stream_handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_fs_read_stream_recv(&default_library, cancel_id, stream_handle, buf, buf_len); }
char * provider_call_msb_fs_read_stream_close(msb_library *library, uint64_t stream_handle, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_fs_read_stream_close ? library->ptr_msb_fs_read_stream_close(stream_handle, buf, buf_len) : NULL;
}
char * call_msb_fs_read_stream_close(uint64_t stream_handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_fs_read_stream_close(&default_library, stream_handle, buf, buf_len); }
char * provider_call_msb_fs_write_stream(msb_library *library, uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_fs_write_stream ? library->ptr_msb_fs_write_stream(cancel_id, handle, path, buf, buf_len) : NULL;
}
char * call_msb_fs_write_stream(uint64_t cancel_id, uint64_t handle, const char *path, uint8_t *buf, size_t buf_len) { return provider_call_msb_fs_write_stream(&default_library, cancel_id, handle, path, buf, buf_len); }
char * provider_call_msb_fs_write_stream_write(msb_library *library, uint64_t cancel_id, uint64_t stream_handle, const char *data_b64, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_fs_write_stream_write ? library->ptr_msb_fs_write_stream_write(cancel_id, stream_handle, data_b64, buf, buf_len) : NULL;
}
char * call_msb_fs_write_stream_write(uint64_t cancel_id, uint64_t stream_handle, const char *data_b64, uint8_t *buf, size_t buf_len) { return provider_call_msb_fs_write_stream_write(&default_library, cancel_id, stream_handle, data_b64, buf, buf_len); }
char * provider_call_msb_fs_write_stream_close(msb_library *library, uint64_t cancel_id, uint64_t stream_handle, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_fs_write_stream_close ? library->ptr_msb_fs_write_stream_close(cancel_id, stream_handle, buf, buf_len) : NULL;
}
char * call_msb_fs_write_stream_close(uint64_t cancel_id, uint64_t stream_handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_fs_write_stream_close(&default_library, cancel_id, stream_handle, buf, buf_len); }
char * provider_call_msb_agent_open_sandbox(msb_library *library, uint64_t cancel_id, const char *name, uint64_t timeout_ms, uint64_t *out_handle) {
	return library->ptr_msb_agent_open_sandbox ? library->ptr_msb_agent_open_sandbox(cancel_id, name, timeout_ms, out_handle) : NULL;
}
char * call_msb_agent_open_sandbox(uint64_t cancel_id, const char *name, uint64_t timeout_ms, uint64_t *out_handle) { return provider_call_msb_agent_open_sandbox(&default_library, cancel_id, name, timeout_ms, out_handle); }
char * provider_call_msb_agent_open_path(msb_library *library, uint64_t cancel_id, const char *path, uint64_t timeout_ms, uint64_t *out_handle) {
	return library->ptr_msb_agent_open_path ? library->ptr_msb_agent_open_path(cancel_id, path, timeout_ms, out_handle) : NULL;
}
char * call_msb_agent_open_path(uint64_t cancel_id, const char *path, uint64_t timeout_ms, uint64_t *out_handle) { return provider_call_msb_agent_open_path(&default_library, cancel_id, path, timeout_ms, out_handle); }
char * provider_call_msb_agent_request(msb_library *library, uint64_t cancel_id, uint64_t agent_handle, uint8_t flags, const uint8_t *body_ptr, size_t body_len, uint32_t *out_id, uint8_t *out_flags, uint8_t **out_body_ptr, size_t *out_body_len) {
	return library->ptr_msb_agent_request ? library->ptr_msb_agent_request(cancel_id, agent_handle, flags, body_ptr, body_len, out_id, out_flags, out_body_ptr, out_body_len) : NULL;
}
char * call_msb_agent_request(uint64_t cancel_id, uint64_t agent_handle, uint8_t flags, const uint8_t *body_ptr, size_t body_len, uint32_t *out_id, uint8_t *out_flags, uint8_t **out_body_ptr, size_t *out_body_len) { return provider_call_msb_agent_request(&default_library, cancel_id, agent_handle, flags, body_ptr, body_len, out_id, out_flags, out_body_ptr, out_body_len); }
char * provider_call_msb_agent_stream_open(msb_library *library, uint64_t cancel_id, uint64_t agent_handle, uint8_t flags, const uint8_t *body_ptr, size_t body_len, uint32_t *out_id, uint64_t *out_stream_handle) {
	return library->ptr_msb_agent_stream_open ? library->ptr_msb_agent_stream_open(cancel_id, agent_handle, flags, body_ptr, body_len, out_id, out_stream_handle) : NULL;
}
char * call_msb_agent_stream_open(uint64_t cancel_id, uint64_t agent_handle, uint8_t flags, const uint8_t *body_ptr, size_t body_len, uint32_t *out_id, uint64_t *out_stream_handle) { return provider_call_msb_agent_stream_open(&default_library, cancel_id, agent_handle, flags, body_ptr, body_len, out_id, out_stream_handle); }
char * provider_call_msb_agent_stream_next(msb_library *library, uint64_t cancel_id, uint64_t agent_handle, uint64_t stream_handle, bool *out_present, uint32_t *out_id, uint8_t *out_flags, uint8_t **out_body_ptr, size_t *out_body_len) {
	return library->ptr_msb_agent_stream_next ? library->ptr_msb_agent_stream_next(cancel_id, agent_handle, stream_handle, out_present, out_id, out_flags, out_body_ptr, out_body_len) : NULL;
}
char * call_msb_agent_stream_next(uint64_t cancel_id, uint64_t agent_handle, uint64_t stream_handle, bool *out_present, uint32_t *out_id, uint8_t *out_flags, uint8_t **out_body_ptr, size_t *out_body_len) { return provider_call_msb_agent_stream_next(&default_library, cancel_id, agent_handle, stream_handle, out_present, out_id, out_flags, out_body_ptr, out_body_len); }
char * provider_call_msb_agent_stream_close(msb_library *library, uint64_t cancel_id, uint64_t agent_handle, uint64_t stream_handle) {
	return library->ptr_msb_agent_stream_close ? library->ptr_msb_agent_stream_close(cancel_id, agent_handle, stream_handle) : NULL;
}
char * call_msb_agent_stream_close(uint64_t cancel_id, uint64_t agent_handle, uint64_t stream_handle) { return provider_call_msb_agent_stream_close(&default_library, cancel_id, agent_handle, stream_handle); }
char * provider_call_msb_agent_send(msb_library *library, uint64_t cancel_id, uint64_t agent_handle, uint32_t id, uint8_t flags, const uint8_t *body_ptr, size_t body_len) {
	return library->ptr_msb_agent_send ? library->ptr_msb_agent_send(cancel_id, agent_handle, id, flags, body_ptr, body_len) : NULL;
}
char * call_msb_agent_send(uint64_t cancel_id, uint64_t agent_handle, uint32_t id, uint8_t flags, const uint8_t *body_ptr, size_t body_len) { return provider_call_msb_agent_send(&default_library, cancel_id, agent_handle, id, flags, body_ptr, body_len); }
char * provider_call_msb_agent_ready_bytes(msb_library *library, uint64_t agent_handle, uint8_t **out_body_ptr, size_t *out_body_len) {
	return library->ptr_msb_agent_ready_bytes ? library->ptr_msb_agent_ready_bytes(agent_handle, out_body_ptr, out_body_len) : NULL;
}
char * call_msb_agent_ready_bytes(uint64_t agent_handle, uint8_t **out_body_ptr, size_t *out_body_len) { return provider_call_msb_agent_ready_bytes(&default_library, agent_handle, out_body_ptr, out_body_len); }
char * provider_call_msb_agent_close(msb_library *library, uint64_t cancel_id, uint64_t agent_handle) {
	return library->ptr_msb_agent_close ? library->ptr_msb_agent_close(cancel_id, agent_handle) : NULL;
}
char * call_msb_agent_close(uint64_t cancel_id, uint64_t agent_handle) { return provider_call_msb_agent_close(&default_library, cancel_id, agent_handle); }
void provider_call_msb_agent_free_bytes(msb_library *library, uint8_t *ptr, size_t len) {
	if (library->ptr_msb_agent_free_bytes) library->ptr_msb_agent_free_bytes(ptr, len);
}
void call_msb_agent_free_bytes(uint8_t *ptr, size_t len) { provider_call_msb_agent_free_bytes(&default_library, ptr, len); }
char * provider_call_msb_version(msb_library *library, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_version ? library->ptr_msb_version(buf, buf_len) : NULL;
}
char * call_msb_version(uint8_t *buf, size_t buf_len) { return provider_call_msb_version(&default_library, buf, buf_len); }
char * provider_call_msb_agent_socket_path(msb_library *library, const char *name, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_agent_socket_path ? library->ptr_msb_agent_socket_path(name, buf, buf_len) : NULL;
}
char * call_msb_agent_socket_path(const char *name, uint8_t *buf, size_t buf_len) { return provider_call_msb_agent_socket_path(&default_library, name, buf, buf_len); }
char * provider_call_msb_image_get(msb_library *library, uint64_t cancel_id, const char *reference, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_image_get ? library->ptr_msb_image_get(cancel_id, reference, buf, buf_len) : NULL;
}
char * call_msb_image_get(uint64_t cancel_id, const char *reference, uint8_t *buf, size_t buf_len) { return provider_call_msb_image_get(&default_library, cancel_id, reference, buf, buf_len); }
char * provider_call_msb_image_list(msb_library *library, uint64_t cancel_id, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_image_list ? library->ptr_msb_image_list(cancel_id, buf, buf_len) : NULL;
}
char * call_msb_image_list(uint64_t cancel_id, uint8_t *buf, size_t buf_len) { return provider_call_msb_image_list(&default_library, cancel_id, buf, buf_len); }
char * provider_call_msb_image_inspect(msb_library *library, uint64_t cancel_id, const char *reference, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_image_inspect ? library->ptr_msb_image_inspect(cancel_id, reference, buf, buf_len) : NULL;
}
char * call_msb_image_inspect(uint64_t cancel_id, const char *reference, uint8_t *buf, size_t buf_len) { return provider_call_msb_image_inspect(&default_library, cancel_id, reference, buf, buf_len); }
char * provider_call_msb_image_remove(msb_library *library, uint64_t cancel_id, const char *reference, bool force, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_image_remove ? library->ptr_msb_image_remove(cancel_id, reference, force, buf, buf_len) : NULL;
}
char * call_msb_image_remove(uint64_t cancel_id, const char *reference, bool force, uint8_t *buf, size_t buf_len) { return provider_call_msb_image_remove(&default_library, cancel_id, reference, force, buf, buf_len); }
char * provider_call_msb_image_prune(msb_library *library, uint64_t cancel_id, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_image_prune ? library->ptr_msb_image_prune(cancel_id, buf, buf_len) : NULL;
}
char * call_msb_image_prune(uint64_t cancel_id, uint8_t *buf, size_t buf_len) { return provider_call_msb_image_prune(&default_library, cancel_id, buf, buf_len); }
bool has_msb_service(void) {
	return default_library.ptr_msb_service_create != NULL && default_library.ptr_msb_service_get != NULL && default_library.ptr_msb_service_list != NULL &&
		default_library.ptr_msb_service_update != NULL && default_library.ptr_msb_service_enable != NULL &&
		default_library.ptr_msb_service_disable != NULL && default_library.ptr_msb_service_remove != NULL &&
		default_library.ptr_msb_service_refresh != NULL && default_library.ptr_msb_service_close != NULL;
}
char *call_msb_service_create(uint64_t cancel_id, const char *request_json, uint8_t *buf, size_t buf_len) {
	return default_library.ptr_msb_service_create ? default_library.ptr_msb_service_create(cancel_id, request_json, buf, buf_len) : NULL;
}
char *call_msb_service_get(uint64_t cancel_id, const char *slug, uint8_t *buf, size_t buf_len) {
	return default_library.ptr_msb_service_get ? default_library.ptr_msb_service_get(cancel_id, slug, buf, buf_len) : NULL;
}
char *call_msb_service_list(uint64_t cancel_id, const char *options_json, uint8_t *buf, size_t buf_len) {
	return default_library.ptr_msb_service_list ? default_library.ptr_msb_service_list(cancel_id, options_json, buf, buf_len) : NULL;
}
char *call_msb_service_update(uint64_t cancel_id, uint64_t handle, const char *request_json, uint8_t *buf, size_t buf_len) {
	return default_library.ptr_msb_service_update ? default_library.ptr_msb_service_update(cancel_id, handle, request_json, buf, buf_len) : NULL;
}
char *call_msb_service_enable(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) {
	return default_library.ptr_msb_service_enable ? default_library.ptr_msb_service_enable(cancel_id, handle, buf, buf_len) : NULL;
}
char *call_msb_service_disable(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) {
	return default_library.ptr_msb_service_disable ? default_library.ptr_msb_service_disable(cancel_id, handle, buf, buf_len) : NULL;
}
char *call_msb_service_remove(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) {
	return default_library.ptr_msb_service_remove ? default_library.ptr_msb_service_remove(cancel_id, handle, buf, buf_len) : NULL;
}
char *call_msb_service_refresh(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) {
	return default_library.ptr_msb_service_refresh ? default_library.ptr_msb_service_refresh(cancel_id, handle, buf, buf_len) : NULL;
}
char *call_msb_service_close(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) {
	return default_library.ptr_msb_service_close ? default_library.ptr_msb_service_close(cancel_id, handle, buf, buf_len) : NULL;
}

bool provider_has_msb_storage_usage(msb_library *library) { return library->ptr_msb_storage_usage != NULL; }
bool has_msb_storage_usage(void) { return provider_has_msb_storage_usage(&default_library); }
bool provider_has_msb_sandbox_storage_usage(msb_library *library) { return library->ptr_msb_sandbox_storage_usage != NULL; }
bool has_msb_sandbox_storage_usage(void) { return provider_has_msb_sandbox_storage_usage(&default_library); }
char * provider_call_msb_sandbox_storage_usage(msb_library *library, uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_storage_usage ? library->ptr_msb_sandbox_storage_usage(cancel_id, handle, buf, buf_len) : NULL;
}
char * call_msb_sandbox_storage_usage(uint64_t cancel_id, uint64_t handle, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_storage_usage(&default_library, cancel_id, handle, buf, buf_len); }
bool provider_has_msb_storage_prune(msb_library *library) { return library->ptr_msb_storage_prune != NULL; }
bool has_msb_storage_prune(void) { return provider_has_msb_storage_prune(&default_library); }
char * provider_call_msb_storage_usage(msb_library *library, uint64_t cancel_id, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_storage_usage ? library->ptr_msb_storage_usage(cancel_id, buf, buf_len) : NULL;
}
char * call_msb_storage_usage(uint64_t cancel_id, uint8_t *buf, size_t buf_len) { return provider_call_msb_storage_usage(&default_library, cancel_id, buf, buf_len); }
char * provider_call_msb_storage_prune(msb_library *library, uint64_t cancel_id, const char *options_json, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_storage_prune ? library->ptr_msb_storage_prune(cancel_id, options_json, buf, buf_len) : NULL;
}
char * call_msb_storage_prune(uint64_t cancel_id, const char *options_json, uint8_t *buf, size_t buf_len) { return provider_call_msb_storage_prune(&default_library, cancel_id, options_json, buf, buf_len); }
char * provider_call_msb_image_load(msb_library *library, uint64_t cancel_id, const char *input_path, const char *tags_json, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_image_load ? library->ptr_msb_image_load(cancel_id, input_path, tags_json, buf, buf_len) : NULL;
}
char * call_msb_image_load(uint64_t cancel_id, const char *input_path, const char *tags_json, uint8_t *buf, size_t buf_len) { return provider_call_msb_image_load(&default_library, cancel_id, input_path, tags_json, buf, buf_len); }
char * provider_call_msb_image_save(msb_library *library, uint64_t cancel_id, const char *references_json, const char *output_path, const char *format, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_image_save ? library->ptr_msb_image_save(cancel_id, references_json, output_path, format, buf, buf_len) : NULL;
}
char * call_msb_image_save(uint64_t cancel_id, const char *references_json, const char *output_path, const char *format, uint8_t *buf, size_t buf_len) { return provider_call_msb_image_save(&default_library, cancel_id, references_json, output_path, format, buf, buf_len); }
char * provider_call_msb_sandbox_handle_snapshot(msb_library *library, uint64_t cancel_id, const char *sandbox_name, const char *snapshot_name, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_handle_snapshot ? library->ptr_msb_sandbox_handle_snapshot(cancel_id, sandbox_name, snapshot_name, buf, buf_len) : NULL;
}
char * call_msb_sandbox_handle_snapshot(uint64_t cancel_id, const char *sandbox_name, const char *snapshot_name, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_handle_snapshot(&default_library, cancel_id, sandbox_name, snapshot_name, buf, buf_len); }
char * provider_call_msb_snapshot_create(msb_library *library, uint64_t cancel_id, const char *source_sandbox, const char *opts_json, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_snapshot_create ? library->ptr_msb_snapshot_create(cancel_id, source_sandbox, opts_json, buf, buf_len) : NULL;
}
char * call_msb_snapshot_create(uint64_t cancel_id, const char *source_sandbox, const char *opts_json, uint8_t *buf, size_t buf_len) { return provider_call_msb_snapshot_create(&default_library, cancel_id, source_sandbox, opts_json, buf, buf_len); }
char * provider_call_msb_snapshot_create_archive(msb_library *library, uint64_t cancel_id, const char *source_sandbox, const char *archive_path, const char *opts_json, bool plain_tar, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_snapshot_create_archive ? library->ptr_msb_snapshot_create_archive(cancel_id, source_sandbox, archive_path, opts_json, plain_tar, buf, buf_len) : NULL;
}
char * call_msb_snapshot_create_archive(uint64_t cancel_id, const char *source_sandbox, const char *archive_path, const char *opts_json, bool plain_tar, uint8_t *buf, size_t buf_len) { return provider_call_msb_snapshot_create_archive(&default_library, cancel_id, source_sandbox, archive_path, opts_json, plain_tar, buf, buf_len); }
char * provider_call_msb_snapshot_open(msb_library *library, uint64_t cancel_id, const char *reference, const char *reference_kind, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_snapshot_open ? library->ptr_msb_snapshot_open(cancel_id, reference, reference_kind, buf, buf_len) : NULL;
}
char * call_msb_snapshot_open(uint64_t cancel_id, const char *reference, const char *reference_kind, uint8_t *buf, size_t buf_len) { return provider_call_msb_snapshot_open(&default_library, cancel_id, reference, reference_kind, buf, buf_len); }
char * provider_call_msb_snapshot_verify(msb_library *library, uint64_t cancel_id, const char *reference, const char *reference_kind, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_snapshot_verify ? library->ptr_msb_snapshot_verify(cancel_id, reference, reference_kind, buf, buf_len) : NULL;
}
char * call_msb_snapshot_verify(uint64_t cancel_id, const char *reference, const char *reference_kind, uint8_t *buf, size_t buf_len) { return provider_call_msb_snapshot_verify(&default_library, cancel_id, reference, reference_kind, buf, buf_len); }
char * provider_call_msb_snapshot_get(msb_library *library, uint64_t cancel_id, const char *name_or_digest, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_snapshot_get ? library->ptr_msb_snapshot_get(cancel_id, name_or_digest, buf, buf_len) : NULL;
}
char * call_msb_snapshot_get(uint64_t cancel_id, const char *name_or_digest, uint8_t *buf, size_t buf_len) { return provider_call_msb_snapshot_get(&default_library, cancel_id, name_or_digest, buf, buf_len); }
char * provider_call_msb_snapshot_list(msb_library *library, uint64_t cancel_id, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_snapshot_list ? library->ptr_msb_snapshot_list(cancel_id, buf, buf_len) : NULL;
}
char * call_msb_snapshot_list(uint64_t cancel_id, uint8_t *buf, size_t buf_len) { return provider_call_msb_snapshot_list(&default_library, cancel_id, buf, buf_len); }
char * provider_call_msb_snapshot_list_dir(msb_library *library, uint64_t cancel_id, const char *dir, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_snapshot_list_dir ? library->ptr_msb_snapshot_list_dir(cancel_id, dir, buf, buf_len) : NULL;
}
char * call_msb_snapshot_list_dir(uint64_t cancel_id, const char *dir, uint8_t *buf, size_t buf_len) { return provider_call_msb_snapshot_list_dir(&default_library, cancel_id, dir, buf, buf_len); }
char * provider_call_msb_snapshot_remove(msb_library *library, uint64_t cancel_id, const char *reference, const char *reference_kind, bool force, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_snapshot_remove ? library->ptr_msb_snapshot_remove(cancel_id, reference, reference_kind, force, buf, buf_len) : NULL;
}
char * call_msb_snapshot_remove(uint64_t cancel_id, const char *reference, const char *reference_kind, bool force, uint8_t *buf, size_t buf_len) { return provider_call_msb_snapshot_remove(&default_library, cancel_id, reference, reference_kind, force, buf, buf_len); }
char * provider_call_msb_snapshot_reindex(msb_library *library, uint64_t cancel_id, const char *dir, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_snapshot_reindex ? library->ptr_msb_snapshot_reindex(cancel_id, dir, buf, buf_len) : NULL;
}
char * call_msb_snapshot_reindex(uint64_t cancel_id, const char *dir, uint8_t *buf, size_t buf_len) { return provider_call_msb_snapshot_reindex(&default_library, cancel_id, dir, buf, buf_len); }
char * provider_call_msb_snapshot_export(msb_library *library, uint64_t cancel_id, const char *reference, const char *reference_kind, const char *out, const char *opts_json, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_snapshot_export ? library->ptr_msb_snapshot_export(cancel_id, reference, reference_kind, out, opts_json, buf, buf_len) : NULL;
}
char * call_msb_snapshot_export(uint64_t cancel_id, const char *reference, const char *reference_kind, const char *out, const char *opts_json, uint8_t *buf, size_t buf_len) { return provider_call_msb_snapshot_export(&default_library, cancel_id, reference, reference_kind, out, opts_json, buf, buf_len); }
char * provider_call_msb_snapshot_copy(msb_library *library, uint64_t cancel_id, const char *reference, const char *reference_kind, const char *output_archive_path, const char *opts_json, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_snapshot_copy ? library->ptr_msb_snapshot_copy(cancel_id, reference, reference_kind, output_archive_path, opts_json, buf, buf_len) : NULL;
}
char * call_msb_snapshot_copy(uint64_t cancel_id, const char *reference, const char *reference_kind, const char *output_archive_path, const char *opts_json, uint8_t *buf, size_t buf_len) { return provider_call_msb_snapshot_copy(&default_library, cancel_id, reference, reference_kind, output_archive_path, opts_json, buf, buf_len); }
char * provider_call_msb_snapshot_import(msb_library *library, uint64_t cancel_id, const char *archive, const char *dest, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_snapshot_import ? library->ptr_msb_snapshot_import(cancel_id, archive, dest, buf, buf_len) : NULL;
}
char * call_msb_snapshot_import(uint64_t cancel_id, const char *archive, const char *dest, uint8_t *buf, size_t buf_len) { return provider_call_msb_snapshot_import(&default_library, cancel_id, archive, dest, buf, buf_len); }

char * provider_call_msb_snapshot_import_with_base(msb_library *library, uint64_t cancel_id, const char *archive, const char *dest, const char *base, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_snapshot_import_with_base ? library->ptr_msb_snapshot_import_with_base(cancel_id, archive, dest, base, buf, buf_len) : NULL;
}
char * call_msb_snapshot_import_with_base(uint64_t cancel_id, const char *archive, const char *dest, const char *base, uint8_t *buf, size_t buf_len) { return provider_call_msb_snapshot_import_with_base(&default_library, cancel_id, archive, dest, base, buf, buf_len); }
char * provider_call_msb_snapshot_import_with_options(msb_library *library, uint64_t cancel_id, const char *archive, const char *opts_json, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_snapshot_import_with_options ? library->ptr_msb_snapshot_import_with_options(cancel_id, archive, opts_json, buf, buf_len) : NULL;
}
char * call_msb_snapshot_import_with_options(uint64_t cancel_id, const char *archive, const char *opts_json, uint8_t *buf, size_t buf_len) { return provider_call_msb_snapshot_import_with_options(&default_library, cancel_id, archive, opts_json, buf, buf_len); }
char * provider_call_msb_snapshot_import_many(msb_library *library, uint64_t cancel_id, const char *archives_json, const char *opts_json, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_snapshot_import_many ? library->ptr_msb_snapshot_import_many(cancel_id, archives_json, opts_json, buf, buf_len) : NULL;
}
char * call_msb_snapshot_import_many(uint64_t cancel_id, const char *archives_json, const char *opts_json, uint8_t *buf, size_t buf_len) { return provider_call_msb_snapshot_import_many(&default_library, cancel_id, archives_json, opts_json, buf, buf_len); }
char * provider_call_msb_snapshot_group_head(msb_library *library, uint64_t cancel_id, const char *selector, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_snapshot_group_head ? library->ptr_msb_snapshot_group_head(cancel_id, selector, buf, buf_len) : NULL;
}
char * call_msb_snapshot_group_head(uint64_t cancel_id, const char *selector, uint8_t *buf, size_t buf_len) { return provider_call_msb_snapshot_group_head(&default_library, cancel_id, selector, buf, buf_len); }
char * provider_call_msb_sandbox_compact(msb_library *library, uint64_t cancel_id, uint64_t handle, const char *name, const char *opts, uint8_t *buf, size_t buf_len) {
	return library->ptr_msb_sandbox_compact ? library->ptr_msb_sandbox_compact(cancel_id, handle, name, opts, buf, buf_len) : NULL;
}
char * call_msb_sandbox_compact(uint64_t cancel_id, uint64_t handle, const char *name, const char *opts, uint8_t *buf, size_t buf_len) { return provider_call_msb_sandbox_compact(&default_library, cancel_id, handle, name, opts, buf, buf_len); }

// Failed loads are never published; successful tables remain alive for pending
// native operations and finalizers, even after their Go loader is collected.
msb_library *open_msb_provider(const char *path, char **error) {
    msb_library *library = calloc(1, sizeof(msb_library));
    if (!library) { *error = strdup("unable to allocate native provider table"); return NULL; }
    const char *failure = provider_load_microsandbox(library, path);
    if (failure) {
        *error = strdup(failure);
        if (library->handle) {
#ifdef _WIN32
            FreeLibrary((HMODULE)library->handle);
#else
            dlclose(library->handle);
#endif
        }
        free(library);
        return NULL;
    }
    return library;
}
char *msb_provider_information(msb_library *library) {
    typedef char *(*metadata_fn)(void);
    metadata_fn metadata = (metadata_fn)dlsym(library->handle, "msb_provider_info");
    return metadata ? metadata() : NULL;
}
void discard_msb_provider(msb_library *library) {
    if (!library) return;
    // Only failed, unpublished providers reach this path. Successful providers
    // remain resident because native operations/finalizers may outlive wrappers.
#ifdef _WIN32
    FreeLibrary((HMODULE)library->handle);
#else
    dlclose(library->handle);
#endif
    free(library);
}
msb_library *default_msb_library(void) { return &default_library; }
*/
import "C"

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
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

var (
	loadOnce sync.Once
	loadErr  error
)

// Load opens the shared library at path and resolves every msb_* symbol.
// Safe to call multiple times — only the first call does work. The path
// is supplied by setup.materializeFFI after extracting the embedded
// library; callers should not invoke Load directly.
func Load(path string) error {
	loadOnce.Do(func() {
		providerLoadLock.Lock()
		defer providerLoadLock.Unlock()
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

// SetSdkMsbPath pushes the SDK-resolved msb binary path into the Rust
// runtime resolver's SdkPackage tier (see setup::resolve_runtime). Set-once
// on the Rust side: subsequent calls are ignored. The user's MSB_PATH env
// var still wins through the Environment tier.
func SetSdkMsbPath(path string) { defaultLibrary().SetSdkMsbPath(path) }

// autoLoader is set by the parent SDK package's init() to a function
// that materializes the embedded FFI library to disk and dlopens it.
// Decoupling lets ensureLoaded trigger the load lazily without an
// import cycle.
var autoLoader func() error

// SetAutoLoader registers a hook that ensureLoaded invokes the first
// time a wrapped FFI call hits an unloaded library. Idempotent on the
// caller's side (the hook should sync.Once-guard its work).
func SetAutoLoader(fn func() error) {
	autoLoader = fn
}

// ensureLoaded is called at the top of every exported FFI function. If
// the library isn't loaded yet, it invokes the registered auto-loader
// (set by sdk/go's init()) which extracts the embedded FFI to disk and
// dlopens it. Falls back to a clear typed error if no loader is set or
// loading failed.
func ensureLoaded() error {
	if IsLoaded() {
		return nil
	}
	if autoLoader != nil {
		if err := autoLoader(); err != nil {
			return err
		}
		if IsLoaded() {
			return nil
		}
	}
	return &Error{
		Kind:    KindLibraryNotLoaded,
		Message: "no local native provider is loaded; provision the local FFI and load sdk/go/local, or install the full SDK",
	}
}

// =============================================================================
// Types and helpers
// =============================================================================

// defaultBufSize is the output buffer allocated for each FFI call. 1 MiB
// covers JSON metadata and small file reads. FSRead on larger files returns
// KindBufferTooSmall; streaming is a follow-up.
const defaultBufSize = 1 << 20

// storageDiagnosisMaxBufSize bounds a whole-home report, including its trailing NUL.
// Larger inventories must be inspected as smaller named subsets.
const storageDiagnosisMaxBufSize = 32 << 20

// fsStreamBufSize is the output buffer used for fs read-stream Recv calls.
// The protocol's FS_CHUNK_SIZE is 3 MiB; after base64 inflation (~33%) plus
// the {"chunk_b64":"..."} JSON wrapper, each Recv response can reach ~4.1
// MiB. 6 MiB leaves comfortable headroom. The Rust side consumes the chunk
// before checking buffer size, so undersizing would silently drop data —
// don't grow this until the FFI also buffers across calls.
const fsStreamBufSize = 6 << 20

// logsBufSize covers the runtime's bounded log history (10 MiB rotated x3)
// after base64 inflation and JSON framing.
const logsBufSize = 48 << 20

// Error is the typed error surfaced across the FFI boundary. The Rust side
// serialises {kind, message} JSON with optional recovery or resize status metadata; this type unmarshals it.
// The public SDK maps Kind back into microsandbox.ErrorKind.
type Error struct {
	Removal json.RawMessage        `json:"removal,omitempty"`
	Detail  string                 `json:"detail,omitempty"`
	Report  json.RawMessage        `json:"report,omitempty"`
	Import  *SnapshotImportDetails `json:"import,omitempty"`
	Kind    string                 `json:"kind"`
	Message string                 `json:"message"`
	// Changed reports whether a failed Service change may have been applied.
	Changed      string                         `json:"changed,omitempty"`
	Recovery     *SnapshotSourceRecoveryDetails `json:"recovery,omitempty"`
	Service      *ServiceErrorDetails           `json:"service,omitempty"`
	ResizeWait   json.RawMessage                `json:"resize_wait,omitempty"`
	ResizeStatus json.RawMessage                `json:"resize_status,omitempty"`
	// Local volume errors retain host errno/Win32 identity. Older libraries omit it.
	OSError *int32 `json:"os_error,omitempty"`
}

// SnapshotImportDetails keeps publication certainty across the native boundary.
type SnapshotImportDetails struct {
	OperationID string   `json:"operation_id"`
	Archives    []string `json:"archives"`
	GroupPath   *string  `json:"group_path"`
	Outcome     string   `json:"outcome"`
	Detail      string   `json:"detail"`
}

// UndispatchedServiceChangeError records a Service change failure that happened
// before the native request was called.
type UndispatchedServiceChangeError struct {
	err error
}

func (e *UndispatchedServiceChangeError) Error() string { return e.err.Error() }

// Unwrap preserves the original pre-dispatch failure.
func (e *UndispatchedServiceChangeError) Unwrap() error { return e.err }

func undispatchedServiceChange(err error) error {
	if err == nil {
		return nil
	}
	return &UndispatchedServiceChangeError{err: err}
}

// SnapshotSourceRecoveryDetails preserves native recovery metadata across the FFI.
type SnapshotSourceRecoveryDetails struct {
	SourceSandbox    string                     `json:"source_sandbox"`
	CheckpointID     string                     `json:"checkpoint_id"`
	CheckpointRoot   string                     `json:"checkpoint_root"`
	CheckpointPath   string                     `json:"checkpoint_path"`
	Artifact         *PublishedSnapshotArtifact `json:"artifact"`
	Detail           string                     `json:"detail"`
	PublicationError *string                    `json:"publication_error"`
}

// PublishedSnapshotArtifact names a completed installed snapshot or archive.
type PublishedSnapshotArtifact struct {
	Kind       string              `json:"kind"`
	Path       string              `json:"path"`
	SnapshotID string              `json:"snapshot_id"`
	Digest     string              `json:"digest"`
	HeadUpdate *SnapshotHeadUpdate `json:"head_update,omitempty"`
}

func (e *Error) Error() string { return e.Message }

// Error kind strings. Keep in sync with sdk/go/native/src/lib.rs FfiError::kind.
const (
	KindSandboxNotFound              = "sandbox_not_found"
	KindSandboxAlreadyExists         = "sandbox_already_exists"
	KindSandboxReplaced              = "sandbox_replaced"
	KindSandboxStopTimedOut          = "sandbox_stop_timed_out"
	KindSandboxStillRunning          = "sandbox_still_running"
	KindVolumeNotFound               = "volume_not_found"
	KindVolumeAlreadyExists          = "volume_already_exists"
	KindExecTimeout                  = "exec_timeout"
	KindStopTimeout                  = "stop_timeout"
	KindNoDefaultCommand             = "no_default_command"
	KindInvalidConfig                = "invalid_config"
	KindInvalidArgument              = "invalid_argument"
	KindInvalidHandle                = "invalid_handle"
	KindBufferTooSmall               = "buffer_too_small"
	KindCancelled                    = "cancelled"
	KindInternal                     = "internal"
	KindFilesystem                   = "filesystem"
	KindImageNotFound                = "image_not_found"
	KindImageInUse                   = "image_in_use"
	KindSnapshotNotFound             = "snapshot_not_found"
	KindSnapshotAlreadyExists        = "snapshot_already_exists"
	KindSnapshotSandboxRunning       = "snapshot_sandbox_running"
	KindSnapshotImageMissing         = "snapshot_image_missing"
	KindSnapshotIntegrity            = "snapshot_integrity"
	KindSnapshotMigration            = "snapshot_migration"
	KindSnapshotSourceRecovery       = "snapshot_source_recovery"
	KindPatchFailed                  = "patch_failed"
	KindMetricsDisabled              = "metrics_disabled"
	KindMetricsUnavailable           = "metrics_unavailable"
	KindUnsupportedOperation         = "unsupported_operation"
	KindCloudOnly                    = "cloud_only"
	KindModificationNotConfirmed     = "modification_not_confirmed"
	KindServiceNotFound              = "service_not_found"
	KindServiceAlreadyExists         = "service_already_exists"
	KindService                      = "service"
	KindIO                           = "io"
	KindSnapshotImport               = "snapshot_import"
	KindSnapshotGroupRemovalRecovery = "snapshot_group_removal_recovery"
	KindSnapshotRemovalRecovery      = "snapshot_removal_recovery"
	KindSnapshotVerification         = "snapshot_verification"
	KindResizeTimeout                = "resize_timeout"
	KindResizeWait                   = "resize_wait"
)

// Sandbox is an opaque handle to a Rust-side sandbox. Call Close to release.
// Safe for concurrent use from multiple goroutines; Close uses an atomic
// swap so concurrent Close calls produce exactly one Rust-side release.
type Sandbox struct {
	library *Library

	destination *Context
	handle      atomic.Uint64
	name        string
	id          string
	backendKind string
}

// SandboxPingResult is the FFI shape returned by ping operations.
type SandboxPingResult struct {
	Name      string  `json:"name"`
	LatencyMs float64 `json:"latency_ms"`
}

// SandboxTouchResult is the FFI shape returned by touch operations.
type SandboxTouchResult struct {
	Name        string `json:"name"`
	ActivitySeq uint64 `json:"activity_seq"`
}

// AgentFrame is one raw protocol frame from agentd.
type AgentFrame struct {
	ID    uint32
	Flags uint8
	Body  []byte
}

// AgentClient is an opaque handle to a Rust-side AgentBridge.
type AgentClient struct {
	library *Library

	handle atomic.Uint64
}

// AgentStreamHandle is an opaque reference to an open raw agent stream.
type AgentStreamHandle struct {
	library *Library

	agentHandle C.uint64_t
	handle      C.uint64_t
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

// ID returns the stable persisted sandbox identity.
func (s *Sandbox) ID() string { return s.id }

// BackendKind returns the backend retained by this sandbox.
func (s *Sandbox) BackendKind() string {
	if s.backendKind == "" {
		return "unknown"
	}
	return s.backendKind
}

// call invokes fn with a fresh 1 MiB buffer and a Rust-side cancellation
// token. It runs fn on a goroutine and selects on ctx.Done; if the context
// fires first, it triggers the Rust cancel token and waits for the goroutine
// before returning — this prevents the caller's `defer C.free` on any C
// strings from racing with Rust still reading them.
//
// Rust's run_c helper (and the close/exec_close/exec_recv/exec_signal paths)
// call msb_cancel_unregister themselves; nothing to do here.
func call(ctx context.Context, fn func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char) (string, error) {
	return defaultLibrary().call(ctx, fn)
}

// callBuf is call() with a configurable output buffer. Use for FFI calls
// whose response can exceed defaultBufSize — chiefly streaming Recv paths
// that relay protocol chunks larger than 1 MiB.
func callBuf(ctx context.Context, bufSize int, fn func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char) (string, error) {
	return defaultLibrary().callBuf(ctx, bufSize, fn)
}

// Resource-producing calls must release successful results that lose the race
// with caller cancellation. Rust may already have completed ownership transfer.
func callBufWithAbandonedResult(ctx context.Context, bufSize int, fn func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char, abandoned func(string)) (string, error) {
	return defaultLibrary().callBufWithAbandonedResult(ctx, bufSize, fn, abandoned)
}

func callRaw(ctx context.Context, fn func(cancelID C.uint64_t) *C.char) error {
	return defaultLibrary().callRaw(ctx, fn)
}

func errorFromPtr(errPtr *C.char) error { return defaultLibrary().errorFromPtr(errPtr) }

func cBytePtr(data []byte) (*C.uint8_t, C.size_t) {
	if len(data) == 0 {
		return nil, 0
	}
	return (*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data))
}

func takeRustBytes(ptr *C.uint8_t, len C.size_t) []byte {
	return defaultLibrary().takeRustBytes(ptr, len)
}

func freeRustBytes(ptrSlot **C.uint8_t, lenSlot *C.size_t) {
	defaultLibrary().freeRustBytes(ptrSlot, lenSlot)
}

func allocRustBytesOut() (**C.uint8_t, *C.size_t, func()) {
	return defaultLibrary().allocRustBytesOut()
}

func timeoutMillisFromContext(ctx context.Context) C.uint64_t {
	deadline, ok := ctx.Deadline()
	if !ok {
		return 0
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 1
	}
	ms := (remaining + time.Millisecond - 1) / time.Millisecond
	return C.uint64_t(ms)
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
func releaseHandle(handle uint64) { defaultLibrary().releaseHandle(handle) }

// =============================================================================
// Agent client
// =============================================================================

// OpenAgentSandbox connects to a running sandbox by name.
func OpenAgentSandbox(ctx context.Context, name string) (*AgentClient, error) {
	return defaultLibrary().OpenAgentSandbox(ctx, name)
}

// OpenAgentPath connects to an agentd relay socket by path.
func OpenAgentPath(ctx context.Context, path string) (*AgentClient, error) {
	return defaultLibrary().OpenAgentPath(ctx, path)
}

func (c *AgentClient) h() C.uint64_t { return C.uint64_t(c.handle.Load()) }

// Request sends one raw frame and waits for one response frame.
func (c *AgentClient) Request(ctx context.Context, flags uint8, body []byte) (*AgentFrame, error) {
	if err := c.lib().ensureLoaded(); err != nil {
		return nil, err
	}
	bodyPtr, bodyLen := cBytePtr(body)
	var id C.uint32_t
	var outFlags C.uint8_t
	outBodyPtr, outBodyLen, cleanup := c.lib().allocRustBytesOut()
	defer cleanup()
	if err := c.lib().callRaw(ctx, func(cancelID C.uint64_t) *C.char {
		return C.provider_call_msb_agent_request(c.lib().table, cancelID, c.h(), C.uint8_t(flags), bodyPtr, bodyLen, &id, &outFlags, outBodyPtr, outBodyLen)
	}); err != nil {
		c.lib().freeRustBytes(outBodyPtr, outBodyLen)
		return nil, err
	}
	return &AgentFrame{ID: uint32(id), Flags: uint8(outFlags), Body: c.lib().takeRustBytes(*outBodyPtr, *outBodyLen)}, nil
}

// StreamOpen starts a raw streaming session.
func (c *AgentClient) StreamOpen(ctx context.Context, flags uint8, body []byte) (uint32, *AgentStreamHandle, error) {
	if err := c.lib().ensureLoaded(); err != nil {
		return 0, nil, err
	}
	bodyPtr, bodyLen := cBytePtr(body)
	var id C.uint32_t
	var streamHandle C.uint64_t
	if err := c.lib().callRaw(ctx, func(cancelID C.uint64_t) *C.char {
		return C.provider_call_msb_agent_stream_open(c.lib().table, cancelID, c.h(), C.uint8_t(flags), bodyPtr, bodyLen, &id, &streamHandle)
	}); err != nil {
		return 0, nil, err
	}
	return uint32(id), &AgentStreamHandle{library: c.lib(), agentHandle: c.h(), handle: streamHandle}, nil
}

// StreamNext blocks until the next raw stream frame or EOF.
func (s *AgentStreamHandle) StreamNext(ctx context.Context) (*AgentFrame, error) {
	if err := s.lib().ensureLoaded(); err != nil {
		return nil, err
	}
	var present C.bool
	var id C.uint32_t
	var flags C.uint8_t
	outBodyPtr, outBodyLen, cleanup := s.lib().allocRustBytesOut()
	defer cleanup()
	if err := s.lib().callRaw(ctx, func(cancelID C.uint64_t) *C.char {
		return C.provider_call_msb_agent_stream_next(s.lib().table, cancelID, s.agentHandle, s.handle, &present, &id, &flags, outBodyPtr, outBodyLen)
	}); err != nil {
		s.lib().freeRustBytes(outBodyPtr, outBodyLen)
		return nil, err
	}
	if !bool(present) {
		return nil, nil
	}
	return &AgentFrame{ID: uint32(id), Flags: uint8(flags), Body: s.lib().takeRustBytes(*outBodyPtr, *outBodyLen)}, nil
}

// Close releases the raw stream handle.
func (s *AgentStreamHandle) Close(ctx context.Context) error {
	if err := s.lib().ensureLoaded(); err != nil {
		return err
	}
	return s.lib().callRaw(ctx, func(cancelID C.uint64_t) *C.char {
		return C.provider_call_msb_agent_stream_close(s.lib().table, cancelID, s.agentHandle, s.handle)
	})
}

// Send sends a follow-up frame on an existing correlation id.
func (c *AgentClient) Send(ctx context.Context, id uint32, flags uint8, body []byte) error {
	if err := c.lib().ensureLoaded(); err != nil {
		return err
	}
	bodyPtr, bodyLen := cBytePtr(body)
	return c.lib().callRaw(ctx, func(cancelID C.uint64_t) *C.char {
		return C.provider_call_msb_agent_send(c.lib().table, cancelID, c.h(), C.uint32_t(id), C.uint8_t(flags), bodyPtr, bodyLen)
	})
}

// ReadyBytes returns the cached handshake core.ready CBOR body.
func (c *AgentClient) ReadyBytes() ([]byte, error) {
	if err := c.lib().ensureLoaded(); err != nil {
		return nil, err
	}
	outBodyPtr, outBodyLen, cleanup := c.lib().allocRustBytesOut()
	defer cleanup()
	if err := c.lib().errorFromPtr(C.provider_call_msb_agent_ready_bytes(c.lib().table, c.h(), outBodyPtr, outBodyLen)); err != nil {
		c.lib().freeRustBytes(outBodyPtr, outBodyLen)
		return nil, err
	}
	return c.lib().takeRustBytes(*outBodyPtr, *outBodyLen), nil
}

// Close releases the Rust-side agent client handle.
func (c *AgentClient) Close() error {
	return c.CloseCtx(context.Background())
}

// CloseCtx is Close with a caller-controlled context.
func (c *AgentClient) CloseCtx(ctx context.Context) error {
	if err := c.lib().ensureLoaded(); err != nil {
		return err
	}
	h := c.handle.Swap(0)
	if h == 0 {
		return nil
	}
	return c.lib().callRaw(ctx, func(cancelID C.uint64_t) *C.char {
		return C.provider_call_msb_agent_close(c.lib().table, cancelID, C.uint64_t(h))
	})
}

// =============================================================================
// Sandbox lifecycle
// =============================================================================

// SandboxListOptions matches the JSON request shape expected by msb_sandbox_list.
type SandboxListOptions struct {
	Cursor *string           `json:"cursor,omitempty"`
	Limit  *uint32           `json:"limit,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`
}

// SandboxPage is the JSON page returned by msb_sandbox_list.
type SandboxPage struct {
	Sandboxes  []*Sandbox `json:"sandboxes"`
	NextCursor *string    `json:"next_cursor"`
}

// CreateOptions matches the JSON payload shape expected by msb_sandbox_create.
// Zero-valued scalar fields are omitted; pointer fields preserve explicit zero.
// The Rust side applies defaults when optional fields are absent.
type CreateOptions struct {
	ContextHandle        uint64               `json:"context_handle,omitempty"`
	CreationProgress     uint64               `json:"creation_progress,omitempty"`
	Image                string               `json:"image,omitempty"`
	ImageFstype          string               `json:"image_fstype,omitempty"`
	ImageBind            string               `json:"image_bind,omitempty"`
	RootDisk             *RootDiskSpec        `json:"root_disk,omitempty"`
	MemoryMiB            uint32               `json:"memory_mib,omitempty"`
	CPUs                 uint8                `json:"cpus,omitempty"`
	MaxMemoryMiB         uint32               `json:"max_memory_mib,omitempty"`
	MaxCPUs              uint8                `json:"max_cpus,omitempty"`
	CPUPlacement         string               `json:"cpu_placement,omitempty"`
	PlacementProfile     string               `json:"placement_profile,omitempty"`
	NestedVirt           *bool                `json:"nested_virt,omitempty"`
	THP                  string               `json:"thp,omitempty"`
	Workdir              string               `json:"workdir,omitempty"`
	Shell                string               `json:"shell,omitempty"`
	SecurityProfile      string               `json:"security_profile,omitempty"`
	DeploymentProfile    string               `json:"deployment_profile,omitempty"`
	Hostname             string               `json:"hostname,omitempty"`
	User                 string               `json:"user,omitempty"`
	Replace              bool                 `json:"replace,omitempty"`
	ReplaceWithTimeoutMs *uint64              `json:"replace_with_timeout_ms,omitempty"`
	Env                  map[string]string    `json:"env,omitempty"`
	Labels               map[string]string    `json:"labels,omitempty"`
	Detached             bool                 `json:"detached,omitempty"`
	Ephemeral            bool                 `json:"ephemeral,omitempty"`
	Entrypoint           *[]string            `json:"entrypoint,omitempty"`
	Cmd                  *[]string            `json:"cmd,omitempty"`
	Init                 *InitOptions         `json:"init,omitempty"`
	LogLevel             string               `json:"log_level,omitempty"`
	QuietLogs            bool                 `json:"quiet_logs,omitempty"`
	Scripts              map[string]string    `json:"scripts,omitempty"`
	PullPolicy           string               `json:"pull_policy,omitempty"`
	MaxDurationSecs      uint64               `json:"max_duration_secs,omitempty"`
	IdleTimeoutSecs      uint64               `json:"idle_timeout_secs,omitempty"`
	RegistryAuth         *RegistryAuthOptions `json:"registry_auth,omitempty"`
	// RegistryAnonymous pulls without credentials. Mutually exclusive with
	// RegistryAuth; libraries that predate it reject the request.
	RegistryAnonymous bool `json:"registry_anonymous,omitempty"`
	// RegistryInsecure pulls over plain HTTP instead of HTTPS.
	RegistryInsecure bool `json:"registry_insecure,omitempty"`
	// RegistryCACerts holds PEM-encoded CA root certificate bundles trusted
	// when pulling.
	RegistryCACerts []string              `json:"registry_ca_certs,omitempty"`
	Ports           map[uint16]uint16     `json:"ports,omitempty"`
	PortsUDP        map[uint16]uint16     `json:"ports_udp,omitempty"`
	PortBindings    []PortBindingOptions  `json:"port_bindings,omitempty"`
	Vsock           []VsockRouteOptions   `json:"vsock,omitempty"`
	Network         *NetworkOptions       `json:"network,omitempty"`
	Proxy           *OutboundProxyOptions `json:"proxy,omitempty"`
	Secrets         []SecretOptions       `json:"secrets,omitempty"`
	Patches         []PatchOptions        `json:"patches,omitempty"`
	Volumes         map[string]MountSpec  `json:"volumes,omitempty"`
}

// InitOptions describes a guest PID-1 init handoff.
type InitOptions struct {
	Cmd  string      `json:"cmd"`
	Args []string    `json:"args,omitempty"`
	Env  [][2]string `json:"env,omitempty"`
}

// RegistryAuthOptions carries credentials for a private OCI registry.
type RegistryAuthOptions struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// RootDiskSpec describes root storage for an OCI image. Kind is "managed",
// "tmpfs", "disk-image", or "flat"; SizeMiB is a pointer
// so an explicit zero reaches the wire for validation.
type RootDiskSpec struct {
	Kind    string  `json:"kind"`
	SizeMiB *uint32 `json:"size_mib,omitempty"`
	Path    string  `json:"path,omitempty"`
	Format  string  `json:"format,omitempty"`
	Fstype  string  `json:"fstype,omitempty"`
	Clone   string  `json:"clone,omitempty"`
}

// MountSpec describes a volume mount for a sandbox.
type MountSpec struct {
	Bind               string  `json:"bind,omitempty"`
	Named              string  `json:"named,omitempty"`
	NamedMode          string  `json:"named_mode,omitempty"`
	NamedKind          string  `json:"named_kind,omitempty"`
	Owned              string  `json:"owned,omitempty"`
	Tmpfs              bool    `json:"tmpfs,omitempty"`
	Disk               string  `json:"disk,omitempty"`
	Format             string  `json:"format,omitempty"`
	Fstype             string  `json:"fstype,omitempty"`
	Readonly           bool    `json:"readonly,omitempty"`
	Noexec             bool    `json:"noexec,omitempty"`
	Nosuid             bool    `json:"nosuid,omitempty"`
	Nodev              bool    `json:"nodev,omitempty"`
	SizeMiB            uint32  `json:"size_mib,omitempty"`
	QuotaMiB           uint32  `json:"quota_mib,omitempty"`
	StatVirtualization string  `json:"stat_virtualization,omitempty"`
	HostPermissions    string  `json:"host_permissions,omitempty"`
	OverrideUid        *uint32 `json:"override_uid,omitempty"`
	OverrideGid        *uint32 `json:"override_gid,omitempty"`
}

// HTTPConfig carries HTTP denial settings to the native SDK.
type HTTPConfig struct {
	DenyResponseFormat string `json:"deny_response_format,omitempty"`
	DenyMessage        string `json:"deny_message,omitempty"`
	DenyResponse       bool   `json:"deny_response"`
	NetworkDenyMessage string `json:"network_deny_message,omitempty"`
	SecretDenyMessage  string `json:"secret_deny_message,omitempty"`
}

// NetworkOptions is the JSON representation of the network config block.
type NetworkOptions struct {
	CustomPolicy             *CustomNetworkPolicy       `json:"custom_policy,omitempty"`
	DNS                      *DNSOptions                `json:"dns,omitempty"`
	DNSRebindProtection      *bool                      `json:"dns_rebind_protection,omitempty"`
	DenyDomains              []string                   `json:"deny_domains,omitempty"`
	DenyDomainSuffixes       []string                   `json:"deny_domain_suffixes,omitempty"`
	TLS                      *TLSOptions                `json:"tls,omitempty"`
	Strict                   *bool                      `json:"strict,omitempty"`
	Ports                    map[uint16]uint16          `json:"ports,omitempty"`
	PortBindings             []PortBindingOptions       `json:"port_bindings,omitempty"`
	TCPAcceptQueueSize       *uint32                    `json:"tcp_accept_queue_size,omitempty"`
	MaxInboundTCPConnections *uint                      `json:"max_inbound_tcp_connections,omitempty"`
	IPv4Pool                 string                     `json:"ipv4_pool,omitempty"`
	IPv6Pool                 string                     `json:"ipv6_pool,omitempty"`
	NAT64Prefixes            []string                   `json:"nat64_prefixes,omitempty"`
	MaxConnections           *uint                      `json:"max_connections,omitempty"`
	MaxTCPConnections        *uint                      `json:"max_tcp_connections,omitempty"`
	MaxUDPConnections        *uint                      `json:"max_udp_connections,omitempty"`
	RateLimiter              *NetworkRateLimiterOptions `json:"rate_limiter,omitempty"`
	SecretViolationAction    string                     `json:"secret_violation_action,omitempty"`
	TrustHostCAs             *bool                      `json:"trust_host_cas,omitempty"`
	HTTP                     *HTTPConfig                `json:"http,omitempty"`
}

// RateLimiterOptions limits one traffic direction; a nil bucket leaves that
// dimension unlimited.
type RateLimiterOptions struct {
	Bandwidth *TokenBucketOptions `json:"bandwidth,omitempty"`
	Ops       *TokenBucketOptions `json:"ops,omitempty"`
}

// NetworkRateLimiterOptions groups local network limits by direction.
type NetworkRateLimiterOptions struct {
	Egress  *RateLimiterOptions `json:"egress,omitempty"`
	Ingress *RateLimiterOptions `json:"ingress,omitempty"`
}

// TokenBucketOptions is the JSON representation of a token bucket.
type TokenBucketOptions struct {
	Size         uint64 `json:"size"`
	RefillTimeMs uint64 `json:"refill_time_ms"`
	OneTimeBurst uint64 `json:"one_time_burst,omitempty"`
}

// OutboundProxyOptions is the JSON representation of an outbound proxy.
type OutboundProxyOptions struct {
	Protocol       string               `json:"protocol"`
	Address        string               `json:"address"`
	UserID         string               `json:"user_id,omitempty"`
	Username       *string              `json:"username,omitempty"`
	PasswordSource *SecretSourceOptions `json:"password_source,omitempty"`
}

// SecretSourceOptions is the JSON representation of a host-side secret source.
type SecretSourceOptions struct {
	Kind string `json:"kind"`
	Var  string `json:"var,omitempty"`
}

// PortBindingOptions publishes a host port on a specific host bind address.
type PortBindingOptions struct {
	Bind      string `json:"bind,omitempty"`
	HostPort  uint16 `json:"host_port"`
	GuestPort uint16 `json:"guest_port"`
	Protocol  string `json:"protocol,omitempty"`
}

// VsockRouteOptions exposes one host Unix socket on a host-CID vsock port.
type VsockRouteOptions struct {
	HostSocket string `json:"host_socket"`
	Port       uint32 `json:"port"`
	SocketType string `json:"socket_type,omitempty"`
}

// DNSOptions configures the in-VM DNS proxy.
type DNSOptions struct {
	RebindProtection *bool    `json:"rebind_protection,omitempty"`
	Nameservers      []string `json:"nameservers,omitempty"`
	QueryTimeoutMs   *uint64  `json:"query_timeout_ms,omitempty"`
}

// CustomNetworkPolicy is an explicit allow/deny rule set with asymmetric
// defaults: `default_egress` defaults to deny, `default_ingress` to allow.
type CustomNetworkPolicy struct {
	DefaultEgress  string        `json:"default_egress,omitempty"`
	DefaultIngress string        `json:"default_ingress,omitempty"`
	Rules          []NetworkRule `json:"rules,omitempty"`
}

// NetworkRule is a single firewall rule. Port may be a single port ("443")
// or a range ("8000-9000"); Ports lets callers pass multiple at once.
type NetworkRule struct {
	Action      string   `json:"action"`
	Direction   string   `json:"direction,omitempty"`
	Destination string   `json:"destination,omitempty"`
	Protocol    string   `json:"protocol,omitempty"`
	Protocols   []string `json:"protocols,omitempty"`
	Port        string   `json:"port,omitempty"`
	Ports       []string `json:"ports,omitempty"`
}

// TLSOptions configures the transparent HTTPS interception proxy.
type TLSOptions struct {
	Bypass                []string               `json:"bypass,omitempty"`
	VerifyUpstream        *bool                  `json:"verify_upstream,omitempty"`
	InterceptedPorts      []uint16               `json:"intercepted_ports,omitempty"`
	BlockQUIC             *bool                  `json:"block_quic,omitempty"`
	CACert                string                 `json:"ca_cert,omitempty"`
	CAKey                 string                 `json:"ca_key,omitempty"`
	UpstreamCACerts       []string               `json:"upstream_ca_certs,omitempty"`
	ScopedUpstreamCACerts []ScopedUpstreamCACert `json:"scoped_upstream_ca_certs,omitempty"`
	ScopedVerifyUpstream  []ScopedVerifyUpstream `json:"scoped_verify_upstream,omitempty"`
}

// ScopedUpstreamCACert configures a CA bundle for matching upstream hosts.
type ScopedUpstreamCACert struct {
	Pattern string `json:"pattern"`
	Path    string `json:"path"`
}

// ScopedVerifyUpstream configures upstream certificate verification for matching hosts.
type ScopedVerifyUpstream struct {
	Pattern string `json:"pattern"`
	Verify  bool   `json:"verify"`
}

// SecretOptions is the JSON representation of a single credential.
type SecretOptions struct {
	EnvVar             string                    `json:"env_var"`
	Value              string                    `json:"value"`
	Allow              []string                  `json:"allow,omitempty"`
	Passthrough        []string                  `json:"passthrough,omitempty"`
	Placeholder        string                    `json:"placeholder,omitempty"`
	RequireTLSIdentity *bool                     `json:"require_tls_identity,omitempty"`
	Substitution       SecretSubstitutionOptions `json:"substitution,omitempty"`
	ViolationAction    string                    `json:"violation_action,omitempty"`
}

// SecretSubstitutionOptions selects request locations for substitution.
type SecretSubstitutionOptions struct {
	Headers      *bool    `json:"headers,omitempty"`
	HeaderFields []string `json:"header_fields,omitempty"`
	Query        bool     `json:"query,omitempty"`
	Body         bool     `json:"body,omitempty"`
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

// OpenCreationProgress reserves an operation-local, bounded event stream.
func OpenCreationProgress(ctx context.Context) (uint64, error) {
	return defaultLibrary().OpenCreationProgress(ctx)
}

// ReceiveCreationProgress waits for the next event or context cancellation.
func ReceiveCreationProgress(ctx context.Context, id uint64) (json.RawMessage, error) {
	return defaultLibrary().ReceiveCreationProgress(ctx, id)
}

// CloseCreationProgress releases the operation's stream after its receiver has stopped.
func CloseCreationProgress(id uint64) error { return defaultLibrary().CloseCreationProgress(id) }

// CreateSandbox creates and boots a sandbox, returning a handle the caller
// must Close when done.
//
// Ownership: cName and cOpts are Go-allocated C strings borrowed by Rust for
// the duration of the call. Rust copies any strings it retains before returning.
func CreateSandbox(ctx context.Context, name string, opts CreateOptions) (*Sandbox, error) {
	return defaultLibrary().CreateSandbox(ctx, name, opts)
}

// ConnectOrCreateSandbox connects by name or creates using opts.
func ConnectOrCreateSandbox(ctx context.Context, name string, opts CreateOptions) (*Sandbox, error) {
	return defaultLibrary().ConnectOrCreateSandbox(ctx, name, opts)
}

func createSandbox(ctx context.Context, name string, opts CreateOptions, connectOrCreate bool) (*Sandbox, error) {
	return defaultLibrary().createSandbox(ctx, name, opts, connectOrCreate)
}

// RestoreSandbox uses the dedicated native restore entry point.
func RestoreSandbox(ctx context.Context, name string, opts RestoreOptions) (*Sandbox, error) {
	return defaultLibrary().RestoreSandbox(ctx, name, opts)
}

// ConnectSandbox reattaches to an existing sandbox by name and returns a
// live Sandbox. Returns an Error with Kind==KindSandboxNotFound if no such
// sandbox exists.
func ConnectSandbox(ctx context.Context, name string) (*Sandbox, error) {
	return defaultLibrary().ConnectSandbox(ctx, name)
}

// SandboxHandleInfo is the JSON payload returned by LookupSandbox.
type SandboxHandleInfo struct {
	ObjectHandle  uint64 `json:"object_handle"`
	ID            string `json:"id"`
	Name          string `json:"name"`
	Status        string `json:"status"`
	ConfigJSON    string `json:"config_json"`
	CreatedAtUnix *int64 `json:"created_at_unix"`
	UpdatedAtUnix *int64 `json:"updated_at_unix"`
	BackendKind   string `json:"backend_kind"`
}

// SandboxHandleLifecycleOptions is the JSON payload for identity-safe handle operations.
type SandboxHandleLifecycleOptions struct {
	Detached bool `json:"detached,omitempty"`
	Force    bool `json:"force,omitempty"`
	// Keep zero on the wire: an explicit zero deadline must not be mistaken
	// for an omitted/default timeout. Graceful stop never escalates to kill.
	TimeoutMs uint64 `json:"timeout_ms"`
	Status    string `json:"status,omitempty"`
}

func sandboxHandleLifecycle(
	ctx context.Context,
	name string,
	id string,
	operation string,
	opts SandboxHandleLifecycleOptions,
) (string, error) {
	return defaultLibrary().sandboxHandleLifecycle(ctx, name, id, operation, opts)
}

// SandboxHandleLiveLifecycle runs an identity-safe operation returning a live sandbox.
func SandboxHandleLiveLifecycle(
	ctx context.Context,
	name string,
	id string,
	operation string,
	opts SandboxHandleLifecycleOptions,
) (*Sandbox, error) {
	return defaultLibrary().SandboxHandleLiveLifecycle(ctx, name, id, operation, opts)
}

// SandboxHandleInfoLifecycle runs an identity-safe operation returning refreshed metadata.
func SandboxHandleInfoLifecycle(
	ctx context.Context,
	name string,
	id string,
	operation string,
	opts SandboxHandleLifecycleOptions,
) (*SandboxHandleInfo, error) {
	return defaultLibrary().SandboxHandleInfoLifecycle(ctx, name, id, operation, opts)
}

// SandboxHandleStopLifecycle waits and returns the observed terminal state.
func SandboxHandleStopLifecycle(
	ctx context.Context,
	name string,
	id string,
) (*SandboxStopResult, error) {
	return defaultLibrary().SandboxHandleStopLifecycle(ctx, name, id)
}

// SandboxHandleVoidLifecycle runs an identity-safe operation with no result payload.
func SandboxHandleVoidLifecycle(
	ctx context.Context,
	name string,
	id string,
	operation string,
	opts SandboxHandleLifecycleOptions,
) error {
	return defaultLibrary().SandboxHandleVoidLifecycle(ctx, name, id, operation, opts)
}

// StopSandboxHandle preserves persisted identity and distinguishes no deadline from zero.
func StopSandboxHandle(ctx context.Context, name, id string, timeoutMs *uint64) error {
	return defaultLibrary().StopSandboxHandle(ctx, name, id, timeoutMs)
}

func stopLifecycleRequest(timeoutMs *uint64) (string, SandboxHandleLifecycleOptions) {
	if timeoutMs == nil {
		return "stop_gracefully", SandboxHandleLifecycleOptions{}
	}
	return "stop_with_timeout", SandboxHandleLifecycleOptions{TimeoutMs: *timeoutMs}
}

// BackendInfo is the secret-safe backend diagnostic shape returned by Rust.
type BackendInfo struct {
	Kind    string  `json:"kind"`
	APIURL  *string `json:"api_url"`
	Source  string  `json:"source"`
	Profile *string `json:"profile"`
}

// SandboxStopResult is the JSON payload returned after observing a stopped sandbox.
type SandboxStopResult struct {
	Name           string  `json:"name"`
	Status         string  `json:"status"`
	ExitCode       *int    `json:"exit_code"`
	Signal         *int    `json:"signal"`
	ObservedAtUnix int64   `json:"observed_at_unix"`
	Source         *string `json:"source"`
}

// LogOptions filters persisted sandbox logs.
type LogOptions struct {
	Tail    uint64   `json:"tail,omitempty"`
	SinceMs *int64   `json:"since_ms,omitempty"`
	UntilMs *int64   `json:"until_ms,omitempty"`
	Sources []string `json:"sources,omitempty"`
}

// LogEntry is one persisted sandbox log entry.
type LogEntry struct {
	Source      string  `json:"source"`
	SessionID   *uint64 `json:"session_id"`
	TimestampMs int64   `json:"timestamp_ms"`
	DataB64     string  `json:"data_b64"`
	Cursor      string  `json:"cursor"`
}

// LogStreamOptions configures a live log stream. `SinceMs` and
// `FromCursor` are mutually exclusive.
type LogStreamOptions struct {
	Sources    []string `json:"sources,omitempty"`
	SinceMs    *int64   `json:"since_ms,omitempty"`
	FromCursor *string  `json:"from_cursor,omitempty"`
	UntilMs    *int64   `json:"until_ms,omitempty"`
	Follow     bool     `json:"follow,omitempty"`
}

func logStreamOptionsJSON(opts LogStreamOptions) (*C.char, error) {
	b, err := json.Marshal(opts)
	if err != nil {
		return nil, fmt.Errorf("marshal log stream opts: %w", err)
	}
	return C.CString(string(b)), nil
}

func logsOptionsJSON(opts LogOptions) (*C.char, error) {
	b, err := json.Marshal(opts)
	if err != nil {
		return nil, fmt.Errorf("marshal log opts: %w", err)
	}
	return C.CString(string(b)), nil
}

func parseLogEntries(out string) ([]LogEntry, error) {
	var entries []LogEntry
	if err := json.Unmarshal([]byte(out), &entries); err != nil {
		return nil, fmt.Errorf("parse logs response: %w", err)
	}
	return entries, nil
}

// SandboxLogs reads persisted logs for a live sandbox handle.
func (s *Sandbox) SandboxLogs(ctx context.Context, opts LogOptions) ([]LogEntry, error) {
	if err := s.lib().ensureLoaded(); err != nil {
		return nil, err
	}
	cOpts, err := logsOptionsJSON(opts)
	if err != nil {
		return nil, err
	}
	defer C.free(unsafe.Pointer(cOpts))
	out, err := s.lib().callBuf(ctx, logsBufSize, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_logs(s.lib().table, cancelID, s.h(), cOpts, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	return parseLogEntries(out)
}

// SandboxHandleLogs reads persisted logs for a sandbox by name.
func SandboxHandleLogs(ctx context.Context, name string, opts LogOptions) ([]LogEntry, error) {
	return defaultLibrary().SandboxHandleLogs(ctx, name, opts)
}

// LookupSandbox fetches the persisted metadata for a sandbox by name without
// connecting.
func LookupSandbox(ctx context.Context, name string) (*SandboxHandleInfo, error) {
	return defaultLibrary().LookupSandbox(ctx, name)
}

// StartSandbox boots a persisted sandbox and returns a live Sandbox.
// `detached==true` leaves the VM running after the handle is released.
func StartSandbox(ctx context.Context, name string, detached bool) (*Sandbox, error) {
	return defaultLibrary().StartSandbox(ctx, name, detached)
}

// StopSandboxByName gracefully stops a sandbox identified by name and waits for stopped observation.
func StopSandboxByName(ctx context.Context, name string, timeoutMs uint64) error {
	return defaultLibrary().StopSandboxByName(ctx, name, timeoutMs)
}

// RequestStopSandboxByName requests graceful shutdown without waiting for stopped observation.
func RequestStopSandboxByName(ctx context.Context, name string) error {
	return defaultLibrary().RequestStopSandboxByName(ctx, name)
}

// PauseSandboxByName controls resident execution without an agent connection.
func PauseSandboxByName(ctx context.Context, name string) error {
	return defaultLibrary().PauseSandboxByName(ctx, name)
}

// ResumeSandboxByName controls resident execution without an agent connection.
func ResumeSandboxByName(ctx context.Context, name string) error {
	return defaultLibrary().ResumeSandboxByName(ctx, name)
}

// KillSandboxByName terminates a sandbox identified by name and waits for stopped observation.
func KillSandboxByName(ctx context.Context, name string, timeoutMs uint64) error {
	return defaultLibrary().KillSandboxByName(ctx, name, timeoutMs)
}

// RequestKillSandboxByName requests force termination without waiting for stopped observation.
func RequestKillSandboxByName(ctx context.Context, name string) error {
	return defaultLibrary().RequestKillSandboxByName(ctx, name)
}

// RequestDrainSandboxByName requests graceful drain without waiting for completion.
func RequestDrainSandboxByName(ctx context.Context, name string) error {
	return defaultLibrary().RequestDrainSandboxByName(ctx, name)
}

// WaitSandboxByNameUntilStopped waits until a named sandbox reaches terminal state.
func WaitSandboxByNameUntilStopped(ctx context.Context, name string) (*SandboxStopResult, error) {
	return defaultLibrary().WaitSandboxByNameUntilStopped(ctx, name)
}

// PingSandboxByName checks agent reachability without refreshing idle activity.
func PingSandboxByName(ctx context.Context, name string) (*SandboxPingResult, error) {
	return defaultLibrary().PingSandboxByName(ctx, name)
}

// TouchSandboxByName explicitly refreshes idle activity for a running sandbox.
func TouchSandboxByName(ctx context.Context, name string) (*SandboxTouchResult, error) {
	return defaultLibrary().TouchSandboxByName(ctx, name)
}

// ModifySandboxByName plans or applies a sandbox modification by name.
// optsJSON carries the canonical patch/policy/dry_run request; the raw
// modification plan JSON is returned for the public package to decode.
func ModifySandboxByName(ctx context.Context, name, optsJSON string) (string, error) {
	return defaultLibrary().ModifySandboxByName(ctx, name, optsJSON)
}

// ResizeStatusSandboxByName returns the raw live resize status JSON array
// for the sandbox named name whose identity is id.
func ResizeStatusSandboxByName(ctx context.Context, name, id string) (string, error) {
	if err := ensureLoaded(); err != nil {
		return "", err
	}
	if err := requireResizeWait(); err != nil {
		return "", err
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	cID := C.CString(id)
	defer C.free(unsafe.Pointer(cID))
	return call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_sandbox_handle_resize_status(cancelID, cName, cID, buf, bufLen)
	})
}

// WaitUntilResizedSandboxByName waits for live resizes on the sandbox named
// name whose identity is id to settle within timeoutMs.
func WaitUntilResizedSandboxByName(ctx context.Context, name, id string, timeoutMs uint64) (string, error) {
	if err := ensureLoaded(); err != nil {
		return "", err
	}
	if err := requireResizeWait(); err != nil {
		return "", err
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	cID := C.CString(id)
	defer C.free(unsafe.Pointer(cID))
	return call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_sandbox_handle_wait_until_resized(cancelID, cName, cID, C.uint64_t(timeoutMs), buf, bufLen)
	})
}

// ResizeOperationsSandboxByName dispatches one new operation after native capability admission.
func ResizeOperationsSandboxByName(ctx context.Context, name, id, request string) (string, error) {
	return defaultLibrary().resizeOperations(ctx, 0, name, id, request)
}

// ResizeOperations dispatches one new operation on a retained live handle.
func (s *Sandbox) ResizeOperations(ctx context.Context, request string) (string, error) {
	handle := s.h()
	if handle == 0 {
		return "", &Error{Kind: KindInvalidHandle, Message: "sandbox handle already closed"}
	}
	// Zero selects name lookup in the native entry point. Keep the admitted handle
	// instead of reading it again after a concurrent Close or Detach clears it.
	return s.lib().resizeOperations(ctx, handle, "", "", request)
}

func (library *Library) resizeOperations(ctx context.Context, handle C.uint64_t, name, id, request string) (string, error) {
	if err := library.ensureLoaded(); err != nil {
		return "", err
	}
	if !bool(C.provider_has_resize_operations(library.table)) {
		return "", &Error{Kind: KindUnsupportedOperation, Message: "native SDK does not support resize operation tracking; update the native SDK"}
	}
	cName, cID, cRequest := C.CString(name), C.CString(id), C.CString(request)
	defer C.free(unsafe.Pointer(cName))
	defer C.free(unsafe.Pointer(cID))
	defer C.free(unsafe.Pointer(cRequest))
	// call sends exactly once, including buffer or cancellation errors after dispatch.
	return library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_resize_operations(library.table, cancelID, handle, cName, cID, cRequest, buf, bufLen)
	})
}

// ResizeWaitUnbounded is the timeoutMs value that waits without a deadline; 0 checks once.
const ResizeWaitUnbounded = math.MaxUint64

func requireResizeWait() error { return defaultLibrary().requireResizeWait() }
func (library *Library) requireResizeWait() error {
	if !bool(C.provider_has_resize_wait(library.table)) {
		return &Error{Kind: KindUnsupportedOperation, Message: "native SDK does not support live resize status; update the native SDK"}
	}
	return nil
}

// OwnsLifecycle reports whether this handle owns the sandbox VM lifecycle.
// When true, closing or stopping the handle terminates the sandbox.
func (s *Sandbox) OwnsLifecycle() (bool, error) {
	if err := s.lib().ensureLoaded(); err != nil {
		return false, err
	}
	buf := make([]byte, defaultBufSize)
	errPtr := C.provider_call_msb_sandbox_owns_lifecycle(s.lib().table, s.h(), (*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if errPtr != nil {
		msg := C.GoString(errPtr)
		C.provider_call_msb_free_string(s.lib().table, errPtr)
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
	if err := s.lib().ensureLoaded(); err != nil {
		return err
	}
	// Atomically claim the handle: only the goroutine that observes a
	// non-zero prior value is allowed to call the Rust destructor.
	h := s.handle.Swap(0)
	if h == 0 {
		return &Error{Kind: KindInvalidHandle, Message: "sandbox handle already closed"}
	}
	_, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_close(s.lib().table, cancelID, C.uint64_t(h), buf, bufLen)
	})
	return err
}

// Detach disarms shared automatic cleanup without releasing the native handle.
// Concurrent operations keep their admitted references. Close still releases it.
func (s *Sandbox) Detach(ctx context.Context) error {
	if err := s.lib().ensureLoaded(); err != nil {
		return err
	}
	h := s.handle.Load()
	if h == 0 {
		return &Error{Kind: KindInvalidHandle, Message: "sandbox handle already closed"}
	}
	_, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_detach(s.lib().table, cancelID, C.uint64_t(h), buf, bufLen)
	})
	return err
}

// Stop waits for graceful shutdown; nil has no deadline and a present zero expires immediately.
func (s *Sandbox) Stop(ctx context.Context, timeoutMs *uint64) error {
	if err := s.lib().ensureLoaded(); err != nil {
		return err
	}
	if err := s.lib().requireGracefulStopWait(); err != nil {
		return err
	}
	var hasTimeout C.uint8_t
	var millis C.uint64_t
	if timeoutMs != nil {
		hasTimeout = 1
		millis = C.uint64_t(*timeoutMs)
	}
	_, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_stop_gracefully(s.lib().table, cancelID, s.h(), hasTimeout, millis, buf, bufLen)
	})
	return err
}

func requireGracefulStopWait() error { return defaultLibrary().requireGracefulStopWait() }

// RequestStop requests graceful shutdown without waiting for stopped observation.
func (s *Sandbox) RequestStop(ctx context.Context) error {
	if err := s.lib().ensureLoaded(); err != nil {
		return err
	}
	if err := s.lib().requireGracefulStopWait(); err != nil {
		return err
	}
	_, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_request_stop(s.lib().table, cancelID, s.h(), buf, bufLen)
	})
	return err
}

// RestoreWarnings returns the runtime's structured relaxed-restore warnings as JSON.
func (s *Sandbox) RestoreWarnings(ctx context.Context) (string, error) {
	if err := s.lib().ensureLoaded(); err != nil {
		return "", err
	}
	if !bool(C.provider_has_external_mount_restore(s.lib().table)) {
		return "", &Error{Kind: KindUnsupportedOperation, Message: "native SDK does not support external mount restore diagnostics; update the native SDK"}
	}
	return s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_restore_warnings(s.lib().table, cancelID, s.h(), buf, bufLen)
	})
}

// BranchOutcome holds one named child or its startup error.
type BranchOutcome struct {
	Name    string
	Sandbox *Sandbox
	Error   error
}

func (s *Sandbox) BranchMany(ctx context.Context, names []string, integrity bool, volumes map[string]MountSpec, policy ...string) ([]BranchOutcome, error) {
	// Zero selects name lookup in the shared native entry point. A closed live handle
	// must not take that path, including when Close races with this call.
	handle := s.handle.Load()
	if handle == 0 {
		return nil, &Error{Kind: KindInvalidHandle, Message: "sandbox handle already closed"}
	}
	rows, err := s.lib().BranchManyByName(ctx, handle, s.name, "", names, integrity, volumes, policy...)
	for _, row := range rows {
		if row.Sandbox != nil {
			row.Sandbox.destination = s.destination
		}
	}
	return rows, err
}

// BranchManyByName uses one native operation, never a loop of branch captures.
func BranchManyByName(ctx context.Context, handle uint64, source, identity string, names []string, integrity bool, volumes map[string]MountSpec, policy ...string) ([]BranchOutcome, error) {
	return defaultLibrary().BranchManyByName(ctx, handle, source, identity, names, integrity, volumes, policy...)
}

// Branch creates an independent local child through the host runtime.
func (s *Sandbox) Branch(ctx context.Context, name string, recordIntegrity bool, volumes map[string]MountSpec, policy ...string) (*Sandbox, error) {
	if len(volumes) > 0 || (len(policy) > 0 && policy[0] != "") {
		rows, err := s.BranchMany(ctx, []string{name}, recordIntegrity, volumes, policy...)
		return oneBranchOutcome(rows, err)
	}
	child, err := s.lib().branchSandbox(ctx, uint64(s.h()), s.name, name, recordIntegrity)
	if child != nil {
		child.destination = s.destination
	}
	return child, err
}

// BranchSandboxByName branches execution without an agent connection to the source.
func BranchSandboxByName(ctx context.Context, source, name string, recordIntegrity bool, volumes map[string]MountSpec, policy ...string) (*Sandbox, error) {
	return defaultLibrary().BranchSandboxByName(ctx, source, name, recordIntegrity, volumes, policy...)
}

func branchSandbox(ctx context.Context, handle uint64, source, name string, recordIntegrity bool) (*Sandbox, error) {
	return defaultLibrary().branchSandbox(ctx, handle, source, name, recordIntegrity)
}

// checkGuestFlush prevents older native libraries from silently ignoring JSON fields.
// Auto full capture is unchanged; auto disk capture now requires guest writeback.
func checkGuestFlush(policy string, diskOnly bool) error {
	return defaultLibrary().checkGuestFlush(policy, diskOnly)
}

func validateGuestFlushSupport(policy string, diskOnly, supported bool) error {
	switch policy {
	case "", "auto", "required", "skip":
	default:
		return &Error{Kind: KindInvalidArgument, Message: "guest flush must be auto, required, or skip"}
	}
	if (diskOnly || (policy != "" && policy != "auto")) && !supported {
		return &Error{Kind: KindUnsupportedOperation, Message: "native SDK does not support guest flush policies; update the native SDK"}
	}
	return nil
}

func oneBranchOutcome(rows []BranchOutcome, err error) (*Sandbox, error) {
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 {
		return nil, fmt.Errorf("branch returned %d outcomes, expected one", len(rows))
	}
	return rows[0].Sandbox, rows[0].Error
}

// PauseWithGuestFlush uses the explicit-policy ABI; old libraries fail before pausing.
func PauseWithGuestFlush(ctx context.Context, handle uint64, name, identity, policy string) error {
	return defaultLibrary().PauseWithGuestFlush(ctx, handle, name, identity, policy)
}

func (s *Sandbox) PauseWithGuestFlush(ctx context.Context, policy string) error {
	handle := s.handle.Load()
	if handle == 0 {
		return &Error{Kind: KindInvalidHandle, Message: "sandbox handle already closed"}
	}
	return s.lib().PauseWithGuestFlush(ctx, handle, s.name, s.id, policy)
}

// Pause controls resident execution through the host runtime.
func (s *Sandbox) Pause(ctx context.Context) error {
	if err := s.lib().ensureLoaded(); err != nil {
		return err
	}
	_, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_pause(s.lib().table, cancelID, s.h(), buf, bufLen)
	})
	return err
}

// Resume controls resident execution through the host runtime.
func (s *Sandbox) Resume(ctx context.Context) error {
	if err := s.lib().ensureLoaded(); err != nil {
		return err
	}
	_, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_resume(s.lib().table, cancelID, s.h(), buf, bufLen)
	})
	return err
}

// Kill terminates the sandbox and waits for stopped observation.
func (s *Sandbox) Kill(ctx context.Context, timeoutMs uint64) error {
	if err := s.lib().ensureLoaded(); err != nil {
		return err
	}
	_, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_kill(s.lib().table, cancelID, s.h(), C.uint64_t(timeoutMs), buf, bufLen)
	})
	return err
}

// RequestKill requests force termination without waiting for stopped observation.
func (s *Sandbox) RequestKill(ctx context.Context) error {
	if err := s.lib().ensureLoaded(); err != nil {
		return err
	}
	_, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_request_kill(s.lib().table, cancelID, s.h(), buf, bufLen)
	})
	return err
}

// RequestDrain requests graceful drain without waiting for completion.
func (s *Sandbox) RequestDrain(ctx context.Context) error {
	if err := s.lib().ensureLoaded(); err != nil {
		return err
	}
	_, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_request_drain(s.lib().table, cancelID, s.h(), buf, bufLen)
	})
	return err
}

// WaitUntilStopped waits until the sandbox reaches terminal state.
func (s *Sandbox) WaitUntilStopped(ctx context.Context) (*SandboxStopResult, error) {
	if err := s.lib().ensureLoaded(); err != nil {
		return nil, err
	}
	out, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_wait_until_stopped(s.lib().table, cancelID, s.h(), buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var result SandboxStopResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		return nil, fmt.Errorf("parse wait_until_stopped response: %w", err)
	}
	return &result, nil
}

// Ping checks agent reachability without refreshing idle activity.
func (s *Sandbox) Ping(ctx context.Context) (*SandboxPingResult, error) {
	if err := s.lib().ensureLoaded(); err != nil {
		return nil, err
	}
	out, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_ping(s.lib().table, cancelID, s.h(), buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var result SandboxPingResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		return nil, fmt.Errorf("parse ping response: %w", err)
	}
	return &result, nil
}

// Touch explicitly refreshes idle activity for a running sandbox.
func (s *Sandbox) Touch(ctx context.Context) (*SandboxTouchResult, error) {
	if err := s.lib().ensureLoaded(); err != nil {
		return nil, err
	}
	out, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_touch(s.lib().table, cancelID, s.h(), buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var result SandboxTouchResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		return nil, fmt.Errorf("parse touch response: %w", err)
	}
	return &result, nil
}

// Modify plans or applies a modification on this live sandbox. optsJSON
// carries the canonical patch/policy/dry_run request; the raw modification
// plan JSON is returned for the public package to decode.
func (s *Sandbox) Modify(ctx context.Context, optsJSON string) (string, error) {
	if err := s.lib().ensureLoaded(); err != nil {
		return "", err
	}
	cOpts := C.CString(optsJSON)
	defer C.free(unsafe.Pointer(cOpts))
	return s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_modify(s.lib().table, cancelID, s.h(), cOpts, buf, bufLen)
	})
}

// ResizeStatus returns the raw live resize status JSON array.
func (s *Sandbox) ResizeStatus(ctx context.Context) (string, error) {
	if err := s.lib().ensureLoaded(); err != nil {
		return "", err
	}
	if err := s.lib().requireResizeWait(); err != nil {
		return "", err
	}
	return s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_resize_status(s.lib().table, cancelID, s.h(), buf, bufLen)
	})
}

// WaitUntilResized waits for live resizes to settle within timeoutMs.
func (s *Sandbox) WaitUntilResized(ctx context.Context, timeoutMs uint64) (string, error) {
	if err := s.lib().ensureLoaded(); err != nil {
		return "", err
	}
	if err := s.lib().requireResizeWait(); err != nil {
		return "", err
	}
	return s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_wait_until_resized(s.lib().table, cancelID, s.h(), C.uint64_t(timeoutMs), buf, bufLen)
	})
}

func CompactSandbox(ctx context.Context, handle uint64, name, opts string) (string, error) {
	return defaultLibrary().CompactSandbox(ctx, handle, name, opts)
}

func (s *Sandbox) Compact(ctx context.Context, opts string) (string, error) {
	return s.lib().CompactSandbox(ctx, uint64(s.h()), "", opts)
}

// RemoveSandbox removes a stopped sandbox's persisted state by name.
func RemoveSandbox(ctx context.Context, name string) error {
	return defaultLibrary().RemoveSandbox(ctx, name)
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
	TTY         bool              `json:"tty,omitempty"`
	User        string            `json:"user,omitempty"`
	Env         map[string]string `json:"env,omitempty"`
}

// ExecResult is the collected output of a completed command.
type ExecResult struct {
	Stdout   string
	Stderr   string
	ExitCode int // -1 if the guest did not report a code
}

// ShellPath reads from the native handle, avoiding a lookup through a changed default backend.
func (s *Sandbox) ShellPath(ctx context.Context) (string, error) {
	if err := s.lib().ensureLoaded(); err != nil {
		return "", err
	}
	if !bool(C.provider_has_sandbox_shell_path(s.lib().table)) {
		return "", &Error{Kind: KindUnsupportedOperation, Message: "configured shell execution requires an updated microsandbox native library"}
	}
	out, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_shell_path(s.lib().table, cancelID, s.h(), buf, bufLen)
	})
	if err != nil {
		return "", err
	}
	var response struct {
		Shell string `json:"shell"`
	}
	if err := json.Unmarshal([]byte(out), &response); err != nil {
		return "", fmt.Errorf("parse shell path: %w", err)
	}
	return response.Shell, nil
}

// Exec runs cmd in the sandbox and collects its output.
func (s *Sandbox) Exec(ctx context.Context, cmd string, opts ExecOptions) (*ExecResult, error) {
	if err := s.lib().ensureLoaded(); err != nil {
		return nil, err
	}
	if C.provider_has_execution_result(s.lib().table) {
		return s.lib().executionResult(ctx, uint64(s.h()), "exec", cmd, opts)
	}

	optsJSON, err := json.Marshal(opts)
	if err != nil {
		return nil, fmt.Errorf("marshal exec opts: %w", err)
	}
	cCmd := C.CString(cmd)
	defer C.free(unsafe.Pointer(cCmd))
	cOpts := C.CString(string(optsJSON))
	defer C.free(unsafe.Pointer(cOpts))

	out, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_exec(s.lib().table, cancelID, s.h(), cCmd, cOpts, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	return decodeCollectedOutput(out)
}

// ExecDefault runs the sandbox's effective OCI entrypoint and CMD and collects its output.
func (s *Sandbox) ExecDefault(ctx context.Context, opts ExecOptions) (*ExecResult, error) {
	if err := s.lib().ensureLoaded(); err != nil {
		return nil, err
	}
	if C.provider_has_execution_result(s.lib().table) {
		return s.lib().executionResult(ctx, uint64(s.h()), "default", "", opts)
	}

	optsJSON, err := json.Marshal(opts)
	if err != nil {
		return nil, fmt.Errorf("marshal exec opts: %w", err)
	}
	cOpts := C.CString(string(optsJSON))
	defer C.free(unsafe.Pointer(cOpts))

	out, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_exec_default(s.lib().table, cancelID, s.h(), cOpts, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	return decodeCollectedOutput(out)
}

// =============================================================================
// SSH
// =============================================================================

// SSHClientOptions is the FFI wire shape for a native SSH client connection.
type SSHClientOptions struct {
	User                  string  `json:"user,omitempty"`
	Term                  string  `json:"term,omitempty"`
	SFTP                  *bool   `json:"sftp,omitempty"`
	InactivityTimeoutSecs *uint64 `json:"inactivity_timeout_secs,omitempty"`
}

// SSHExecOptions is the FFI wire shape for an SSH exec request.
type SSHExecOptions struct {
	TTY *bool `json:"tty,omitempty"`
}

// SSHAttachOptions is the FFI wire shape for an SSH attach request.
type SSHAttachOptions struct {
	Term       string `json:"term,omitempty"`
	DetachKeys string `json:"detach_keys,omitempty"`
}

// SSHServerOptions is the FFI wire shape for preparing an SSH server endpoint.
type SSHServerOptions struct {
	HostKeyPath           string  `json:"host_key_path,omitempty"`
	AuthorizedKeysPath    string  `json:"authorized_keys_path,omitempty"`
	User                  string  `json:"user,omitempty"`
	SFTP                  *bool   `json:"sftp,omitempty"`
	InactivityTimeoutSecs *uint64 `json:"inactivity_timeout_secs,omitempty"`
}

// SSHOutput is the FFI-decoded output from an SSH exec request.
type SSHOutput struct {
	Status int
	Stdout []byte
	Stderr []byte
}

// SSHClient is an opaque reference to a Rust-side SSH client.
type SSHClient struct {
	library *Library

	handle atomic.Uint64
}

// SSHServer is an opaque reference to a Rust-side SSH server endpoint.
type SSHServer struct {
	library *Library

	handle atomic.Uint64
}

// SFTPClient is an opaque reference to a Rust-side SFTP client session.
type SFTPClient struct {
	library *Library

	handle atomic.Uint64
}

func (c *SSHClient) h() C.uint64_t { return C.uint64_t(c.handle.Load()) }

func (srv *SSHServer) h() C.uint64_t { return C.uint64_t(srv.handle.Load()) }

func (sftp *SFTPClient) h() C.uint64_t { return C.uint64_t(sftp.handle.Load()) }

// SSHConnect connects a native in-process SSH client to this sandbox.
func (s *Sandbox) SSHConnect(ctx context.Context, opts SSHClientOptions) (*SSHClient, error) {
	if err := s.lib().ensureLoaded(); err != nil {
		return nil, err
	}
	optsJSON, err := json.Marshal(opts)
	if err != nil {
		return nil, fmt.Errorf("marshal SSH client opts: %w", err)
	}
	cOpts := C.CString(string(optsJSON))
	defer C.free(unsafe.Pointer(cOpts))

	out, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_ssh_connect(s.lib().table, cancelID, s.h(), cOpts, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var resp struct {
		ClientHandle uint64 `json:"client_handle"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return nil, fmt.Errorf("parse ssh_connect response: %w", err)
	}
	client := &SSHClient{library: s.lib()}
	client.handle.Store(resp.ClientHandle)
	return client, nil
}

// SSHServer prepares a reusable SSH server endpoint for this sandbox.
func (s *Sandbox) SSHServer(ctx context.Context, opts SSHServerOptions) (*SSHServer, error) {
	if err := s.lib().ensureLoaded(); err != nil {
		return nil, err
	}
	optsJSON, err := json.Marshal(opts)
	if err != nil {
		return nil, fmt.Errorf("marshal SSH server opts: %w", err)
	}
	cOpts := C.CString(string(optsJSON))
	defer C.free(unsafe.Pointer(cOpts))

	out, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_ssh_server(s.lib().table, cancelID, s.h(), cOpts, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var resp struct {
		ServerHandle uint64 `json:"server_handle"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return nil, fmt.Errorf("parse ssh_server response: %w", err)
	}
	server := &SSHServer{library: s.lib()}
	server.handle.Store(resp.ServerHandle)
	return server, nil
}

// Exec runs an SSH exec request and collects output.
func (c *SSHClient) Exec(ctx context.Context, command string, opts SSHExecOptions) (*SSHOutput, error) {
	if err := c.lib().ensureLoaded(); err != nil {
		return nil, err
	}
	optsJSON, err := json.Marshal(opts)
	if err != nil {
		return nil, fmt.Errorf("marshal SSH exec opts: %w", err)
	}
	cCommand := C.CString(command)
	defer C.free(unsafe.Pointer(cCommand))
	cOpts := C.CString(string(optsJSON))
	defer C.free(unsafe.Pointer(cOpts))

	out, err := c.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_ssh_client_exec(c.lib().table, cancelID, c.h(), cCommand, cOpts, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Status int    `json:"status"`
		Stdout string `json:"stdout"`
		Stderr string `json:"stderr"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return nil, fmt.Errorf("parse ssh_client_exec response: %w", err)
	}
	stdout, err := base64.StdEncoding.DecodeString(resp.Stdout)
	if err != nil {
		return nil, fmt.Errorf("decode ssh stdout: %w", err)
	}
	stderr, err := base64.StdEncoding.DecodeString(resp.Stderr)
	if err != nil {
		return nil, fmt.Errorf("decode ssh stderr: %w", err)
	}
	return &SSHOutput{Status: resp.Status, Stdout: stdout, Stderr: stderr}, nil
}

// Attach bridges the local terminal to an SSH shell.
func (c *SSHClient) Attach(ctx context.Context, opts SSHAttachOptions) (int, error) {
	if err := c.lib().ensureLoaded(); err != nil {
		return -1, err
	}
	optsJSON, err := json.Marshal(opts)
	if err != nil {
		return -1, fmt.Errorf("marshal SSH attach opts: %w", err)
	}
	cOpts := C.CString(string(optsJSON))
	defer C.free(unsafe.Pointer(cOpts))

	out, err := c.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_ssh_client_attach(c.lib().table, cancelID, c.h(), cOpts, buf, bufLen)
	})
	if err != nil {
		return -1, err
	}
	var resp struct {
		Status int `json:"status"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return -1, fmt.Errorf("parse ssh_client_attach response: %w", err)
	}
	return resp.Status, nil
}

// SFTP opens an SFTP session over this SSH connection.
func (c *SSHClient) SFTP(ctx context.Context) (*SFTPClient, error) {
	if err := c.lib().ensureLoaded(); err != nil {
		return nil, err
	}
	out, err := c.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_ssh_client_sftp(c.lib().table, cancelID, c.h(), buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var resp struct {
		SFTPHandle uint64 `json:"sftp_handle"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return nil, fmt.Errorf("parse ssh_client_sftp response: %w", err)
	}
	sftp := &SFTPClient{library: c.lib()}
	sftp.handle.Store(resp.SFTPHandle)
	return sftp, nil
}

// Close closes this SSH client session. The handle is consumed.
func (c *SSHClient) Close(ctx context.Context) error {
	if err := c.lib().ensureLoaded(); err != nil {
		return err
	}
	h := c.handle.Swap(0)
	if h == 0 {
		return &Error{Kind: KindInvalidHandle, Message: "SSH client handle already closed"}
	}
	_, err := c.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_ssh_client_close(c.lib().table, cancelID, C.uint64_t(h), buf, bufLen)
	})
	return err
}

// Read reads a file over SFTP.
func (sftp *SFTPClient) Read(ctx context.Context, path string) ([]byte, error) {
	if err := sftp.lib().ensureLoaded(); err != nil {
		return nil, err
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	out, err := sftp.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sftp_read(sftp.lib().table, cancelID, sftp.h(), cPath, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return nil, fmt.Errorf("parse sftp_read response: %w", err)
	}
	data, err := base64.StdEncoding.DecodeString(resp.Data)
	if err != nil {
		return nil, fmt.Errorf("decode sftp data: %w", err)
	}
	return data, nil
}

// Write writes a file over SFTP, creating or truncating it.
func (sftp *SFTPClient) Write(ctx context.Context, path string, data []byte) error {
	if err := sftp.lib().ensureLoaded(); err != nil {
		return err
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	cData := C.CString(base64.StdEncoding.EncodeToString(data))
	defer C.free(unsafe.Pointer(cData))
	_, err := sftp.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sftp_write(sftp.lib().table, cancelID, sftp.h(), cPath, cData, buf, bufLen)
	})
	return err
}

// Mkdir creates a directory over SFTP.
func (sftp *SFTPClient) Mkdir(ctx context.Context, path string) error {
	if err := sftp.lib().ensureLoaded(); err != nil {
		return err
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	_, err := sftp.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sftp_mkdir(sftp.lib().table, cancelID, sftp.h(), cPath, buf, bufLen)
	})
	return err
}

// RemoveFile removes a file over SFTP.
func (sftp *SFTPClient) RemoveFile(ctx context.Context, path string) error {
	if err := sftp.lib().ensureLoaded(); err != nil {
		return err
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	_, err := sftp.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sftp_remove_file(sftp.lib().table, cancelID, sftp.h(), cPath, buf, bufLen)
	})
	return err
}

// RemoveDir removes an empty directory over SFTP.
func (sftp *SFTPClient) RemoveDir(ctx context.Context, path string) error {
	if err := sftp.lib().ensureLoaded(); err != nil {
		return err
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	_, err := sftp.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sftp_remove_dir(sftp.lib().table, cancelID, sftp.h(), cPath, buf, bufLen)
	})
	return err
}

// Rename renames a file or directory over SFTP.
func (sftp *SFTPClient) Rename(ctx context.Context, oldPath string, newPath string) error {
	if err := sftp.lib().ensureLoaded(); err != nil {
		return err
	}
	cOld := C.CString(oldPath)
	defer C.free(unsafe.Pointer(cOld))
	cNew := C.CString(newPath)
	defer C.free(unsafe.Pointer(cNew))
	_, err := sftp.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sftp_rename(sftp.lib().table, cancelID, sftp.h(), cOld, cNew, buf, bufLen)
	})
	return err
}

// RealPath resolves a path to its canonical absolute form over SFTP.
func (sftp *SFTPClient) RealPath(ctx context.Context, path string) (string, error) {
	if err := sftp.lib().ensureLoaded(); err != nil {
		return "", err
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	out, err := sftp.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sftp_real_path(sftp.lib().table, cancelID, sftp.h(), cPath, buf, bufLen)
	})
	if err != nil {
		return "", err
	}
	var resp struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return "", fmt.Errorf("parse sftp_real_path response: %w", err)
	}
	return resp.Path, nil
}

// ReadLink reads a symlink target over SFTP.
func (sftp *SFTPClient) ReadLink(ctx context.Context, path string) (string, error) {
	if err := sftp.lib().ensureLoaded(); err != nil {
		return "", err
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	out, err := sftp.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sftp_read_link(sftp.lib().table, cancelID, sftp.h(), cPath, buf, bufLen)
	})
	if err != nil {
		return "", err
	}
	var resp struct {
		Target string `json:"target"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return "", fmt.Errorf("parse sftp_read_link response: %w", err)
	}
	return resp.Target, nil
}

// Symlink creates a symlink over SFTP.
func (sftp *SFTPClient) Symlink(ctx context.Context, target string, linkPath string) error {
	if err := sftp.lib().ensureLoaded(); err != nil {
		return err
	}
	cTarget := C.CString(target)
	defer C.free(unsafe.Pointer(cTarget))
	cLink := C.CString(linkPath)
	defer C.free(unsafe.Pointer(cLink))
	_, err := sftp.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sftp_symlink(sftp.lib().table, cancelID, sftp.h(), cTarget, cLink, buf, bufLen)
	})
	return err
}

// Close closes this SFTP session. The handle is consumed.
func (sftp *SFTPClient) Close(ctx context.Context) error {
	if err := sftp.lib().ensureLoaded(); err != nil {
		return err
	}
	h := sftp.handle.Swap(0)
	if h == 0 {
		return &Error{Kind: KindInvalidHandle, Message: "SFTP handle already closed"}
	}
	_, err := sftp.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sftp_close(sftp.lib().table, cancelID, C.uint64_t(h), buf, bufLen)
	})
	return err
}

// Close releases this prepared server endpoint. The handle is consumed.
func (srv *SSHServer) Close(ctx context.Context) error {
	if err := srv.lib().ensureLoaded(); err != nil {
		return err
	}
	h := srv.handle.Swap(0)
	if h == 0 {
		return &Error{Kind: KindInvalidHandle, Message: "SSH server handle already closed"}
	}
	_, err := srv.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_ssh_server_close(srv.lib().table, cancelID, C.uint64_t(h), buf, bufLen)
	})
	return err
}

// ServeConnection serves one SSH transport over this process's stdin/stdout.
func (srv *SSHServer) ServeConnection(ctx context.Context) error {
	if err := srv.lib().ensureLoaded(); err != nil {
		return err
	}
	_, err := srv.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_ssh_server_serve_connection(srv.lib().table, cancelID, srv.h(), buf, bufLen)
	})
	return err
}

// =============================================================================
// Exec (streaming)
// =============================================================================

// ExecStreamHandle is an opaque reference to a running streaming exec session.
// Go owns the u64 token; Rust owns the channel resources until Close is called.
// Signal, Kill, and Resize may be called concurrently with Recv. Other method
// combinations, including concurrent Recv calls, are not supported.
type ExecStreamHandle struct {
	library *Library

	handle C.uint64_t
	// stdinPiped reflects whether the session was started with stdin_pipe=true.
	// Used to make TakeStdin return nil when there is no stdin to take.
	stdinPiped bool
	// stdinTaken is set on the first TakeStdin to enforce single-take.
	stdinTaken bool
}

// ExecEventKind identifies what an ExecStreamEvent carries.
type ExecEventKind int

const (
	ExecEventStarted ExecEventKind = iota
	ExecEventStdout
	ExecEventStderr
	ExecEventExited
	ExecEventFailed
	ExecEventStdinError
	ExecEventDone // all events consumed; no further Recv calls needed
)

// ExecFailure carries the structured payload for ExecEventFailed events.
// All fields are best-effort — on serialisation failure the runtime falls
// back to populating only Message.
type ExecFailure struct {
	Kind      string `json:"kind,omitempty"`
	Errno     *int   `json:"errno,omitempty"`
	ErrnoName string `json:"errno_name,omitempty"`
	Message   string `json:"message"`
	Path      string `json:"path,omitempty"`
}

// ExecStreamEvent is one event from a streaming exec session.
type ExecStreamEvent struct {
	Kind     ExecEventKind
	PID      uint32       // ExecEventStarted
	Data     []byte       // ExecEventStdout / ExecEventStderr
	ExitCode int          // ExecEventExited
	Failure  *ExecFailure // ExecEventFailed / ExecEventStdinError
}

// ExecSink is a write-only sink for sending data to a running process's stdin.
// Obtain via ExecStreamHandle.TakeStdin. Implements io.WriteCloser.
type ExecSink struct {
	library *Library

	execHandle C.uint64_t
}

// Write sends data to the process stdin. Implements io.Writer.
func (sk *ExecSink) Write(p []byte) (int, error) {
	if err := sk.lib().ensureLoaded(); err != nil {
		return 0, err
	}
	encoded := base64.StdEncoding.EncodeToString(p)
	cData := C.CString(encoded)
	defer C.free(unsafe.Pointer(cData))

	_, err := sk.lib().call(context.Background(), func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_exec_stdin_write(sk.lib().table, cancelID, sk.execHandle, cData, buf, bufLen)
	})
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// WriteCtx is Write with a caller-controlled context.
func (sk *ExecSink) WriteCtx(ctx context.Context, p []byte) (int, error) {
	if err := sk.lib().ensureLoaded(); err != nil {
		return 0, err
	}
	encoded := base64.StdEncoding.EncodeToString(p)
	cData := C.CString(encoded)
	defer C.free(unsafe.Pointer(cData))

	_, err := sk.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_exec_stdin_write(sk.lib().table, cancelID, sk.execHandle, cData, buf, bufLen)
	})
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close closes the stdin pipe. Implements io.Closer.
func (sk *ExecSink) Close() error {
	if err := sk.lib().ensureLoaded(); err != nil {
		return err
	}
	_, err := sk.lib().call(context.Background(), func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_exec_stdin_close(sk.lib().table, cancelID, sk.execHandle, buf, bufLen)
	})
	return err
}

// ExecStream starts a streaming exec session. The returned handle MUST be
// closed with Close when the stream ends or is no longer needed.
func (s *Sandbox) ExecStream(ctx context.Context, cmd string, opts ExecOptions) (*ExecStreamHandle, error) {
	if err := s.lib().ensureLoaded(); err != nil {
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

	out, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_exec_stream(s.lib().table, cancelID, s.h(), cCmd, cOpts, buf, bufLen)
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
	return &ExecStreamHandle{library: s.lib(), handle: C.uint64_t(resp.ExecHandle), stdinPiped: opts.StdinPipe}, nil
}

// ExecDefaultStream starts a streaming exec of the sandbox's effective OCI entrypoint and CMD.
func (s *Sandbox) ExecDefaultStream(ctx context.Context, opts ExecOptions) (*ExecStreamHandle, error) {
	if err := s.lib().ensureLoaded(); err != nil {
		return nil, err
	}
	optsJSON, err := json.Marshal(opts)
	if err != nil {
		return nil, fmt.Errorf("marshal exec opts: %w", err)
	}
	cOpts := C.CString(string(optsJSON))
	defer C.free(unsafe.Pointer(cOpts))

	out, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_exec_default_stream(s.lib().table, cancelID, s.h(), cOpts, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var resp struct {
		ExecHandle uint64 `json:"exec_handle"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return nil, fmt.Errorf("parse exec_default_stream response: %w", err)
	}
	return &ExecStreamHandle{library: s.lib(), handle: C.uint64_t(resp.ExecHandle), stdinPiped: opts.StdinPipe}, nil
}

// TakeStdin returns a sink for writing to the process's stdin. Returns nil
// when the exec session was not started with StdinPipe==true, and on every
// call after the first (matching the Node SDK's single-take semantics).
// The sink is valid until the exec session is closed.
func (h *ExecStreamHandle) TakeStdin() *ExecSink {
	if !h.stdinPiped || h.stdinTaken {
		return nil
	}
	h.stdinTaken = true
	return &ExecSink{library: h.lib(), execHandle: h.handle}
}

// Recv blocks until the next event arrives or the stream ends. Returns
// ExecEventDone when all events have been consumed. ctx cancellation returns
// ctx.Err() immediately; the underlying Rust work continues in background.
func (h *ExecStreamHandle) Recv(ctx context.Context) (*ExecStreamEvent, error) {
	if err := h.lib().ensureLoaded(); err != nil {
		return nil, err
	}
	out, err := h.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_exec_recv(h.lib().table, cancelID, h.handle, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var raw struct {
		Event string          `json:"event"`
		PID   uint32          `json:"pid"`
		Data  string          `json:"data"` // base64
		Code  int             `json:"code"`
		Error json.RawMessage `json:"error"`
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
	case "failed":
		ev.Kind = ExecEventFailed
		var f ExecFailure
		if len(raw.Error) > 0 {
			// Best-effort decode. If the wire format ever diverges from the
			// ExecFailure shape, surface the raw text as Message rather than
			// failing the whole stream.
			if jerr := json.Unmarshal(raw.Error, &f); jerr != nil {
				f = ExecFailure{Message: string(raw.Error)}
			}
		}
		ev.Failure = &f
	case "stdin_error":
		ev.Kind = ExecEventStdinError
		var f ExecFailure
		if len(raw.Error) > 0 {
			if jerr := json.Unmarshal(raw.Error, &f); jerr != nil {
				f = ExecFailure{Message: string(raw.Error)}
			}
		}
		ev.Failure = &f
	case "done":
		ev.Kind = ExecEventDone
	default:
		return nil, fmt.Errorf("unknown exec event: %q", raw.Event)
	}
	return ev, nil
}

// Signal sends a Unix signal number to the running process (e.g. 15=SIGTERM).
func (h *ExecStreamHandle) Signal(ctx context.Context, signal int) error {
	if err := h.lib().ensureLoaded(); err != nil {
		return err
	}
	_, err := h.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_exec_signal(h.lib().table, cancelID, h.handle, C.int32_t(signal), buf, bufLen)
	})
	return err
}

// Resize changes the pseudo-terminal size for this exec session.
func (h *ExecStreamHandle) Resize(ctx context.Context, rows, cols uint16) error {
	if err := h.lib().ensureLoaded(); err != nil {
		return err
	}
	_, err := h.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_exec_resize(h.lib().table, cancelID, h.handle, C.uint16_t(rows), C.uint16_t(cols), buf, bufLen)
	})
	return err
}

// Close releases the Rust-side exec handle. Does not kill the process; call
// Signal(ctx, 9) first if needed. Uses context.Background so cleanup cannot
// be cancelled.
func (h *ExecStreamHandle) Close() error {
	if err := h.lib().ensureLoaded(); err != nil {
		return err
	}
	_, err := h.lib().call(context.Background(), func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_exec_close(h.lib().table, cancelID, h.handle, buf, bufLen)
	})
	return err
}

// =============================================================================
// Metrics
// =============================================================================

// Metrics is the resource-usage snapshot reported by Rust.
type Metrics struct {
	CPUPercent              float64       `json:"cpu_percent"`
	VCPUTimeNs              uint64        `json:"vcpu_time_ns"`
	MemoryBytes             uint64        `json:"memory_bytes"`
	MemoryAvailableBytes    *uint64       `json:"memory_available_bytes"`
	MemoryHostResidentBytes *uint64       `json:"memory_host_resident_bytes"`
	MemoryLimitBytes        uint64        `json:"memory_limit_bytes"`
	DiskReadBytes           uint64        `json:"disk_read_bytes"`
	DiskWriteBytes          uint64        `json:"disk_write_bytes"`
	NetRxBytes              uint64        `json:"net_rx_bytes"`
	NetTxBytes              uint64        `json:"net_tx_bytes"`
	UpperUsedBytes          *uint64       `json:"upper_used_bytes"`
	UpperFreeBytes          *uint64       `json:"upper_free_bytes"`
	UpperHostAllocatedBytes *uint64       `json:"upper_host_allocated_bytes"`
	UptimeSecs              uint64        `json:"uptime_secs"`
	Uptime                  time.Duration `json:"-"`
}

// Metrics fetches a resource-usage snapshot for this sandbox.
func (s *Sandbox) Metrics(ctx context.Context) (*Metrics, error) {
	if err := s.lib().ensureLoaded(); err != nil {
		return nil, err
	}
	out, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_metrics(s.lib().table, cancelID, s.h(), buf, bufLen)
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
	library *Library

	handle C.uint64_t
}

// MetricsStream starts a metrics stream that emits a snapshot every interval.
// intervalMs==0 uses the minimum interval (1ms). Returns a handle that must be
// closed with MetricsStreamHandle.Close.
func (s *Sandbox) MetricsStream(ctx context.Context, intervalMs uint64) (*MetricsStreamHandle, error) {
	if err := s.lib().ensureLoaded(); err != nil {
		return nil, err
	}
	out, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_metrics_stream(s.lib().table, cancelID, s.h(), C.uint64_t(intervalMs), buf, bufLen)
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
	return &MetricsStreamHandle{library: s.lib(), handle: C.uint64_t(resp.StreamHandle)}, nil
}

// Recv blocks until the next metrics snapshot is available or the context is cancelled.
// Returns nil when the stream has ended (the sandbox exited).
func (h *MetricsStreamHandle) Recv(ctx context.Context) (*Metrics, error) {
	if err := h.lib().ensureLoaded(); err != nil {
		return nil, err
	}
	out, err := h.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_metrics_recv(h.lib().table, cancelID, h.handle, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var raw struct {
		Done                    bool    `json:"done"`
		CPUPercent              float64 `json:"cpu_percent"`
		VCPUTimeNs              uint64  `json:"vcpu_time_ns"`
		MemoryBytes             uint64  `json:"memory_bytes"`
		MemoryAvailableBytes    *uint64 `json:"memory_available_bytes"`
		MemoryHostResidentBytes *uint64 `json:"memory_host_resident_bytes"`
		MemoryLimitBytes        uint64  `json:"memory_limit_bytes"`
		DiskReadBytes           uint64  `json:"disk_read_bytes"`
		DiskWriteBytes          uint64  `json:"disk_write_bytes"`
		NetRxBytes              uint64  `json:"net_rx_bytes"`
		NetTxBytes              uint64  `json:"net_tx_bytes"`
		UpperUsedBytes          *uint64 `json:"upper_used_bytes"`
		UpperFreeBytes          *uint64 `json:"upper_free_bytes"`
		UpperHostAllocatedBytes *uint64 `json:"upper_host_allocated_bytes"`
		UptimeSecs              uint64  `json:"uptime_secs"`
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, fmt.Errorf("parse metrics_recv: %w", err)
	}
	if raw.Done {
		return nil, nil
	}
	m := &Metrics{
		CPUPercent:              raw.CPUPercent,
		VCPUTimeNs:              raw.VCPUTimeNs,
		MemoryBytes:             raw.MemoryBytes,
		MemoryAvailableBytes:    raw.MemoryAvailableBytes,
		MemoryHostResidentBytes: raw.MemoryHostResidentBytes,
		MemoryLimitBytes:        raw.MemoryLimitBytes,
		DiskReadBytes:           raw.DiskReadBytes,
		DiskWriteBytes:          raw.DiskWriteBytes,
		NetRxBytes:              raw.NetRxBytes,
		NetTxBytes:              raw.NetTxBytes,
		UpperUsedBytes:          raw.UpperUsedBytes,
		UpperFreeBytes:          raw.UpperFreeBytes,
		UpperHostAllocatedBytes: raw.UpperHostAllocatedBytes,
		UptimeSecs:              raw.UptimeSecs,
		Uptime:                  time.Duration(raw.UptimeSecs) * time.Second,
	}
	return m, nil
}

// Close drops the stream handle. The background Rust task stops when the
// channel is closed.
func (h *MetricsStreamHandle) Close() error {
	if err := h.lib().ensureLoaded(); err != nil {
		return err
	}
	buf := make([]byte, defaultBufSize)
	errPtr := C.provider_call_msb_metrics_close(h.lib().table, h.handle, (*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if errPtr != nil {
		msg := C.GoString(errPtr)
		C.provider_call_msb_free_string(h.lib().table, errPtr)
		var e Error
		if jerr := json.Unmarshal([]byte(msg), &e); jerr != nil {
			e = Error{Kind: KindInternal, Message: msg}
		}
		return &e
	}
	return nil
}

// =============================================================================
// Log streaming

// LogStreamHandle is an opaque reference to a running log stream. Call Close
// to release Rust-side resources and stop the background task.
type LogStreamHandle struct {
	library *Library

	handle C.uint64_t
}

// LogStream starts a log stream against a live sandbox handle. Caller must
// Close the returned handle to release Rust-side resources.
func (s *Sandbox) LogStream(ctx context.Context, opts LogStreamOptions) (*LogStreamHandle, error) {
	if err := s.lib().ensureLoaded(); err != nil {
		return nil, err
	}
	cOpts, err := logStreamOptionsJSON(opts)
	if err != nil {
		return nil, err
	}
	defer C.free(unsafe.Pointer(cOpts))
	out, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_log_stream(s.lib().table, cancelID, s.h(), cOpts, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var resp struct {
		StreamHandle uint64 `json:"stream_handle"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return nil, fmt.Errorf("parse log_stream response: %w", err)
	}
	return &LogStreamHandle{library: s.lib(), handle: C.uint64_t(resp.StreamHandle)}, nil
}

// SandboxHandleLogStream starts a log stream identified by name without
// requiring a live sandbox handle.
func SandboxHandleLogStream(
	ctx context.Context,
	name string,
	opts LogStreamOptions,
) (*LogStreamHandle, error) {
	return defaultLibrary().SandboxHandleLogStream(ctx, name, opts)
}

// Recv blocks until the next log entry arrives or ctx is cancelled. Returns
// nil when the stream has ended (snapshot drained, until reached, or fatal
// stream error has already been surfaced on a prior call).
func (h *LogStreamHandle) Recv(ctx context.Context) (*LogEntry, error) {
	if err := h.lib().ensureLoaded(); err != nil {
		return nil, err
	}
	out, err := h.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_log_recv(h.lib().table, cancelID, h.handle, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var done struct {
		Done bool `json:"done"`
	}
	if jerr := json.Unmarshal([]byte(out), &done); jerr == nil && done.Done {
		return nil, nil
	}
	var entry LogEntry
	if err := json.Unmarshal([]byte(out), &entry); err != nil {
		return nil, fmt.Errorf("parse log_recv response: %w", err)
	}
	return &entry, nil
}

// Close drops the stream handle. The background Rust task stops when the
// channel is closed.
func (h *LogStreamHandle) Close() error {
	if err := h.lib().ensureLoaded(); err != nil {
		return err
	}
	buf := make([]byte, defaultBufSize)
	errPtr := C.provider_call_msb_log_close(h.lib().table, h.handle, (*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if errPtr != nil {
		msg := C.GoString(errPtr)
		C.provider_call_msb_free_string(h.lib().table, errPtr)
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
	if err := h.lib().ensureLoaded(); err != nil {
		return nil, err
	}
	if C.provider_has_execution_result(h.lib().table) {
		return h.lib().executionResult(ctx, uint64(h.handle), "collect", "", ExecOptions{})
	}

	out, err := h.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_exec_collect(h.lib().table, cancelID, h.handle, buf, bufLen)
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
	if err := h.lib().ensureLoaded(); err != nil {
		return -1, err
	}
	out, err := h.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_exec_wait(h.lib().table, cancelID, h.handle, buf, bufLen)
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
	if err := h.lib().ensureLoaded(); err != nil {
		return "", err
	}
	buf := make([]byte, defaultBufSize)
	errPtr := C.provider_call_msb_exec_id(h.lib().table, h.handle, (*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if errPtr != nil {
		msg := C.GoString(errPtr)
		C.provider_call_msb_free_string(h.lib().table, errPtr)
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
	if err := h.lib().ensureLoaded(); err != nil {
		return err
	}
	_, err := h.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_exec_kill(h.lib().table, cancelID, h.handle, buf, bufLen)
	})
	return err
}

// =============================================================================
// Attach

// AttachOptions configures a single Attach call.
type AttachOptions struct {
	Args       []string          `json:"args,omitempty"`
	Cwd        string            `json:"cwd,omitempty"`
	User       string            `json:"user,omitempty"`
	Env        map[string]string `json:"env,omitempty"`
	DetachKeys string            `json:"detach_keys,omitempty"`
}

// Attach starts an interactive PTY session running cmd with the given options.
// It blocks until the process exits and returns the exit code.
func (s *Sandbox) Attach(ctx context.Context, cmd string, opts AttachOptions) (int, error) {
	if err := s.lib().ensureLoaded(); err != nil {
		return -1, err
	}
	optsBytes, err := json.Marshal(opts)
	if err != nil {
		return -1, fmt.Errorf("marshal attach opts: %w", err)
	}
	cCmd := C.CString(cmd)
	defer C.free(unsafe.Pointer(cCmd))
	cOpts := C.CString(string(optsBytes))
	defer C.free(unsafe.Pointer(cOpts))
	out, err2 := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_attach(s.lib().table, cancelID, s.h(), cCmd, cOpts, buf, bufLen)
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

// AttachDefault starts an interactive PTY session for the effective OCI entrypoint and CMD.
func (s *Sandbox) AttachDefault(ctx context.Context, opts AttachOptions) (int, error) {
	if err := s.lib().ensureLoaded(); err != nil {
		return -1, err
	}
	optsBytes, err := json.Marshal(opts)
	if err != nil {
		return -1, fmt.Errorf("marshal attach opts: %w", err)
	}
	cOpts := C.CString(string(optsBytes))
	defer C.free(unsafe.Pointer(cOpts))
	out, callErr := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_attach_default(s.lib().table, cancelID, s.h(), cOpts, buf, bufLen)
	})
	if callErr != nil {
		return -1, callErr
	}
	var resp struct {
		ExitCode int `json:"exit_code"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return -1, fmt.Errorf("parse attach_default response: %w", err)
	}
	return resp.ExitCode, nil
}

// AttachShell starts an interactive PTY session in the sandbox's default shell.
// It blocks until the shell exits and returns the exit code.
func (s *Sandbox) AttachShell(ctx context.Context) (int, error) {
	if err := s.lib().ensureLoaded(); err != nil {
		return -1, err
	}
	out, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_attach_shell(s.lib().table, cancelID, s.h(), buf, bufLen)
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
	if err := s.lib().ensureLoaded(); err != nil {
		return nil, err
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	out, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_fs_read(s.lib().table, cancelID, s.h(), cPath, buf, bufLen)
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
	if err := s.lib().ensureLoaded(); err != nil {
		return err
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	cData := C.CString(base64.StdEncoding.EncodeToString(data))
	defer C.free(unsafe.Pointer(cData))

	_, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_fs_write(s.lib().table, cancelID, s.h(), cPath, cData, buf, bufLen)
	})
	return err
}

// FsList lists the entries in a directory.
func (s *Sandbox) FsList(ctx context.Context, path string) ([]FsEntry, error) {
	if err := s.lib().ensureLoaded(); err != nil {
		return nil, err
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	out, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_fs_list(s.lib().table, cancelID, s.h(), cPath, buf, bufLen)
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
	if err := s.lib().ensureLoaded(); err != nil {
		return nil, err
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	out, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_fs_stat(s.lib().table, cancelID, s.h(), cPath, buf, bufLen)
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
	if err := s.lib().ensureLoaded(); err != nil {
		return err
	}
	cHost := C.CString(hostPath)
	defer C.free(unsafe.Pointer(cHost))
	cGuest := C.CString(guestPath)
	defer C.free(unsafe.Pointer(cGuest))

	_, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_fs_copy_from_host(s.lib().table, cancelID, s.h(), cHost, cGuest, buf, bufLen)
	})
	return err
}

// FsCopyToHost copies a file from the sandbox to the host.
func (s *Sandbox) FsCopyToHost(ctx context.Context, guestPath, hostPath string) error {
	if err := s.lib().ensureLoaded(); err != nil {
		return err
	}
	cGuest := C.CString(guestPath)
	defer C.free(unsafe.Pointer(cGuest))
	cHost := C.CString(hostPath)
	defer C.free(unsafe.Pointer(cHost))

	_, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_fs_copy_to_host(s.lib().table, cancelID, s.h(), cGuest, cHost, buf, bufLen)
	})
	return err
}

// FsMkdir creates a directory (and any missing parents) inside the sandbox.
func (s *Sandbox) FsMkdir(ctx context.Context, path string) error {
	if err := s.lib().ensureLoaded(); err != nil {
		return err
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	_, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_fs_mkdir(s.lib().table, cancelID, s.h(), cPath, buf, bufLen)
	})
	return err
}

// FsRemove deletes a single file from the sandbox. Use FsRemoveDir for directories.
func (s *Sandbox) FsRemove(ctx context.Context, path string) error {
	if err := s.lib().ensureLoaded(); err != nil {
		return err
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	_, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_fs_remove(s.lib().table, cancelID, s.h(), cPath, buf, bufLen)
	})
	return err
}

// FsRemoveDir removes a directory recursively.
func (s *Sandbox) FsRemoveDir(ctx context.Context, path string) error {
	if err := s.lib().ensureLoaded(); err != nil {
		return err
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	_, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_fs_remove_dir(s.lib().table, cancelID, s.h(), cPath, buf, bufLen)
	})
	return err
}

// FsCopy copies a file within the sandbox.
func (s *Sandbox) FsCopy(ctx context.Context, src, dst string) error {
	if err := s.lib().ensureLoaded(); err != nil {
		return err
	}
	cSrc := C.CString(src)
	defer C.free(unsafe.Pointer(cSrc))
	cDst := C.CString(dst)
	defer C.free(unsafe.Pointer(cDst))

	_, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_fs_copy(s.lib().table, cancelID, s.h(), cSrc, cDst, buf, bufLen)
	})
	return err
}

// FsRename renames (or moves) a file or directory within the sandbox.
func (s *Sandbox) FsRename(ctx context.Context, src, dst string) error {
	if err := s.lib().ensureLoaded(); err != nil {
		return err
	}
	cSrc := C.CString(src)
	defer C.free(unsafe.Pointer(cSrc))
	cDst := C.CString(dst)
	defer C.free(unsafe.Pointer(cDst))

	_, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_fs_rename(s.lib().table, cancelID, s.h(), cSrc, cDst, buf, bufLen)
	})
	return err
}

// FsExists reports whether a file or directory exists at the given path.
func (s *Sandbox) FsExists(ctx context.Context, path string) (bool, error) {
	if err := s.lib().ensureLoaded(); err != nil {
		return false, err
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	out, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_fs_exists(s.lib().table, cancelID, s.h(), cPath, buf, bufLen)
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
// Sandbox extras — AllSandboxMetrics, SandboxHandleMetrics
// =============================================================================

// AllSandboxMetrics returns a snapshot of resource usage for every running sandbox.
func AllSandboxMetrics(ctx context.Context) (map[string]*Metrics, error) {
	return defaultLibrary().AllSandboxMetrics(ctx)
}

// SandboxHandleMetrics returns a point-in-time metrics snapshot for a sandbox
// identified by name. The sandbox must be running or draining.
func SandboxHandleMetrics(ctx context.Context, name string) (*Metrics, error) {
	return defaultLibrary().SandboxHandleMetrics(ctx, name)
}

// =============================================================================
// Filesystem streaming — FsReadStreamHandle / FsWriteStreamHandle
// =============================================================================

// FsReadStreamHandle is an open read stream from a guest file.
type FsReadStreamHandle struct {
	library *Library

	handle C.uint64_t
}

// Recv returns the next chunk, or nil when EOF.
func (h *FsReadStreamHandle) Recv(ctx context.Context) ([]byte, error) {
	if err := h.lib().ensureLoaded(); err != nil {
		return nil, err
	}
	// Use the larger streaming buffer: each chunk is up to FS_CHUNK_SIZE
	// (3 MiB) base64-inflated to ~4 MiB before the {"chunk_b64":...}
	// wrapper. defaultBufSize would force the Rust side to drop the chunk.
	out, err := h.lib().callBuf(ctx, fsStreamBufSize, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_fs_read_stream_recv(h.lib().table, cancelID, h.handle, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Done     bool   `json:"done"`
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
	if err := h.lib().ensureLoaded(); err != nil {
		return err
	}
	buf := make([]byte, defaultBufSize)
	errPtr := C.provider_call_msb_fs_read_stream_close(h.lib().table, h.handle, (*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if errPtr != nil {
		msg := C.GoString(errPtr)
		C.provider_call_msb_free_string(h.lib().table, errPtr)
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
	if err := s.lib().ensureLoaded(); err != nil {
		return nil, err
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	out, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_fs_read_stream(s.lib().table, cancelID, s.h(), cPath, buf, bufLen)
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
	return &FsReadStreamHandle{library: s.lib(), handle: C.uint64_t(resp.StreamHandle)}, nil
}

// FsWriteStreamHandle is an open write stream to a guest file.
type FsWriteStreamHandle struct {
	library *Library

	handle C.uint64_t
}

// Write sends a chunk of data to the guest file.
func (h *FsWriteStreamHandle) Write(ctx context.Context, data []byte) error {
	if err := h.lib().ensureLoaded(); err != nil {
		return err
	}
	b64 := base64.StdEncoding.EncodeToString(data)
	cData := C.CString(b64)
	defer C.free(unsafe.Pointer(cData))
	_, err := h.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_fs_write_stream_write(h.lib().table, cancelID, h.handle, cData, buf, bufLen)
	})
	return err
}

// Close finalises the write (sends EOF) and waits for confirmation.
func (h *FsWriteStreamHandle) Close(ctx context.Context) error {
	if err := h.lib().ensureLoaded(); err != nil {
		return err
	}
	_, err := h.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_fs_write_stream_close(h.lib().table, cancelID, h.handle, buf, bufLen)
	})
	return err
}

// FsWriteStream opens a streaming write to a guest file.
func (s *Sandbox) FsWriteStream(ctx context.Context, path string) (*FsWriteStreamHandle, error) {
	if err := s.lib().ensureLoaded(); err != nil {
		return nil, err
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	out, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_fs_write_stream(s.lib().table, cancelID, s.h(), cPath, buf, bufLen)
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
	return &FsWriteStreamHandle{library: s.lib(), handle: C.uint64_t(resp.StreamHandle)}, nil
}

// =============================================================================
// Volumes
// =============================================================================

// VolumeCreateOptions is the JSON payload accepted by msb_volume_create.
type VolumeCreateOptions struct {
	QuotaMiB uint32            `json:"quota_mib,omitempty"`
	Kind     string            `json:"kind,omitempty"`
	SizeMiB  uint32            `json:"size_mib,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
}

// CreateVolume creates a named persistent volume and returns its metadata.
func CreateVolume(ctx context.Context, name string, opts VolumeCreateOptions) (*VolumeHandleInfo, error) {
	return defaultLibrary().CreateVolume(ctx, name, opts)
}

// parseVolumeHandle decodes the JSON written by `volume_handle_json` on the
// Rust side into a VolumeHandleInfo.
func parseVolumeHandle(s string) (*VolumeHandleInfo, error) {
	var raw struct {
		ID            *string           `json:"id"`
		Name          string            `json:"name"`
		IsDefault     bool              `json:"is_default"`
		Path          string            `json:"path"`
		Kind          string            `json:"kind"`
		QuotaMiB      *uint32           `json:"quota_mib"`
		UsedBytes     uint64            `json:"used_bytes"`
		CapacityBytes *uint64           `json:"capacity_bytes"`
		DiskFormat    *string           `json:"disk_format"`
		DiskFstype    *string           `json:"disk_fstype"`
		Labels        map[string]string `json:"labels"`
		CreatedAtUnix *int64            `json:"created_at_unix"`
	}
	if err := json.Unmarshal([]byte(s), &raw); err != nil {
		return nil, fmt.Errorf("parse volume handle: %w", err)
	}
	return &VolumeHandleInfo{
		ID:            raw.ID,
		Name:          raw.Name,
		IsDefault:     raw.IsDefault,
		Path:          raw.Path,
		Kind:          raw.Kind,
		QuotaMiB:      raw.QuotaMiB,
		UsedBytes:     raw.UsedBytes,
		CapacityBytes: raw.CapacityBytes,
		DiskFormat:    raw.DiskFormat,
		DiskFstype:    raw.DiskFstype,
		Labels:        raw.Labels,
		CreatedAtUnix: raw.CreatedAtUnix,
	}, nil
}

// RemoveVolume removes a named volume.
func RemoveVolume(ctx context.Context, name string) error {
	return defaultLibrary().RemoveVolume(ctx, name)
}

// ListVolumes returns metadata for every named volume on the host.
func ListVolumes(ctx context.Context) ([]*VolumeHandleInfo, error) {
	return defaultLibrary().ListVolumes(ctx)
}

// Version returns the runtime version reported by the loaded library.
func Version() (string, error) { return defaultLibrary().Version() }

// DefaultBackendInfo returns secret-safe information about the backend cached
// by the native SDK resolver. A nil result means the loaded compatibility
// bundle predates backend introspection.
func DefaultBackendInfo() (*BackendInfo, error) { return defaultLibrary().DefaultBackendInfo() }

// AgentSocketPath resolves the host-side path of a sandbox's agentd relay
// socket by name, without connecting.
func AgentSocketPath(name string) (string, error) { return defaultLibrary().AgentSocketPath(name) }

// VolumeHandleInfo carries metadata for a volume returned by GetVolume.
type VolumeHandleInfo struct {
	ID            *string           `json:"id"`
	Name          string            `json:"name"`
	IsDefault     bool              `json:"is_default"`
	Path          string            `json:"path"`
	Kind          string            `json:"kind"`
	QuotaMiB      *uint32           `json:"quota_mib"`
	UsedBytes     uint64            `json:"used_bytes"`
	CapacityBytes *uint64           `json:"capacity_bytes"`
	DiskFormat    *string           `json:"disk_format"`
	DiskFstype    *string           `json:"disk_fstype"`
	Labels        map[string]string `json:"labels"`
	CreatedAtUnix *int64            `json:"created_at_unix"`
}

// GetVolume looks up a volume by name and returns its metadata.
func GetVolume(ctx context.Context, name string) (*VolumeHandleInfo, error) {
	return defaultLibrary().GetVolume(ctx, name)
}

// GetDefaultVolume returns the cloud account's always-present default volume.
func GetDefaultVolume(ctx context.Context) (*VolumeHandleInfo, error) {
	return defaultLibrary().GetDefaultVolume(ctx)
}

// VolumeFsOp dispatches a buffered filesystem operation through the active backend.
func VolumeFsOp(ctx context.Context, name, op string, args any, result any) error {
	return defaultLibrary().VolumeFsOp(ctx, name, op, args, result)
}

// =============================================================================
// Image cache
// =============================================================================

// ImageHandleInfo is the JSON shape of an image handle returned by the FFI.
type ImageHandleInfo struct {
	Reference      string `json:"reference"`
	ManifestDigest string `json:"manifest_digest"`
	Architecture   string `json:"architecture"`
	OS             string `json:"os"`
	LayerCount     uint   `json:"layer_count"`
	SizeBytes      *int64 `json:"size_bytes"`
	CreatedAtUnix  *int64 `json:"created_at_unix"`
	LastUsedAtUnix *int64 `json:"last_used_at_unix"`
}

// ImageConfigDetail mirrors the parsed OCI config block.
type ImageConfigDetail struct {
	Digest     string            `json:"digest"`
	Env        []string          `json:"env"`
	Cmd        []string          `json:"cmd"`
	Entrypoint []string          `json:"entrypoint"`
	WorkingDir string            `json:"working_dir"`
	User       string            `json:"user"`
	Labels     map[string]string `json:"labels"`
	StopSignal string            `json:"stop_signal"`
}

// ImageLayerDetail describes one layer of an image manifest.
type ImageLayerDetail struct {
	DiffID              string `json:"diff_id"`
	BlobDigest          string `json:"blob_digest"`
	MediaType           string `json:"media_type"`
	CompressedSizeBytes *int64 `json:"compressed_size_bytes"`
	ErofsSizeBytes      *int64 `json:"erofs_size_bytes"`
	Position            int32  `json:"position"`
}

// ImageDetailInfo is the full inspect payload (handle + config + layers).
type ImageDetailInfo struct {
	ImageHandleInfo
	Config *ImageConfigDetail `json:"config"`
	Layers []ImageLayerDetail `json:"layers"`
}

// ImagePruneReportInfo is the JSON shape returned by image prune.
type ImagePruneReportInfo struct {
	SkippedInUse     uint32  `json:"skipped_in_use"`
	ImageRefsRemoved uint32  `json:"image_refs_removed"`
	ManifestsRemoved uint32  `json:"manifests_removed"`
	LayersRemoved    uint32  `json:"layers_removed"`
	FsmetaRemoved    uint32  `json:"fsmeta_removed"`
	VMDKRemoved      uint32  `json:"vmdk_removed"`
	BytesReclaimed   *uint64 `json:"bytes_reclaimed"`
}

// ImageGet fetches a single image by reference.
func ImageGet(ctx context.Context, reference string) (*ImageHandleInfo, error) {
	return defaultLibrary().ImageGet(ctx, reference)
}

// ImageList returns all cached images, newest first.
func ImageList(ctx context.Context) ([]*ImageHandleInfo, error) {
	return defaultLibrary().ImageList(ctx)
}

// ImageInspect returns full image detail (handle + config + layers).
func ImageInspect(ctx context.Context, reference string) (*ImageDetailInfo, error) {
	return defaultLibrary().ImageInspect(ctx, reference)
}

// ImageRemove deletes an image and (if force=false) errors when sandboxes
// still reference it.
func ImageRemove(ctx context.Context, reference string, force bool) error {
	return defaultLibrary().ImageRemove(ctx, reference, force)
}

// ImagePrune removes cached image data that is not used by sandboxes.
func ImagePrune(ctx context.Context) (*ImagePruneReportInfo, error) {
	return defaultLibrary().ImagePrune(ctx)
}

// StorageUsage observes this live sandbox through its retained native backend and identity.
func (s *Sandbox) StorageUsage(ctx context.Context) (*StorageItemUsage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	handle := s.handle.Load()
	if handle == 0 {
		return nil, &Error{Kind: KindInvalidHandle, Message: "sandbox handle already closed"}
	}
	if err := s.lib().ensureLoaded(); err != nil {
		return nil, err
	}
	if !bool(C.provider_has_msb_sandbox_storage_usage(s.lib().table)) {
		return nil, &Error{Kind: KindUnsupportedOperation, Message: "native SDK does not support sandbox storage usage; update the native SDK"}
	}
	out, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_storage_usage(s.lib().table, cancelID, C.uint64_t(handle), buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var report *StorageItemUsage
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		return nil, fmt.Errorf("parse sandbox storage usage: %w", err)
	}
	if report == nil {
		return nil, fmt.Errorf("native SDK returned no sandbox storage usage report")
	}
	return report, nil
}

// StorageUsage observes storage in the selected backend. Older native bundles remain loadable;
// only this new capability returns unsupported when its optional symbol is absent.
func StorageUsage(ctx context.Context) (*StorageUsageReport, error) {
	return defaultLibrary().StorageUsage(ctx)
}

// PruneStorage revalidates runtime cache ownership before removal and never prompts.
func PruneStorage(ctx context.Context, options StoragePruneOptions) (*StoragePruneReport, error) {
	return defaultLibrary().PruneStorage(ctx, options)
}

// CreateService creates a Service and returns it once the change is committed.
func CreateService(ctx context.Context, request ServiceCreateRequest) (*ServiceInfo, error) {
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, undispatchedServiceChange(err)
	}
	cRequest := C.CString(string(payload))
	defer C.free(unsafe.Pointer(cRequest))
	return callService(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_service_create(cancelID, cRequest, buf, bufLen)
	})
}

// GetService returns a Service by slug.
func GetService(ctx context.Context, slug string) (*ServiceInfo, error) {
	// The slug is passed as a C string, which ends at the first NUL, so a slug with one
	// would fetch a different Service.
	if strings.IndexByte(slug, 0) >= 0 {
		return nil, &Error{Kind: KindInvalidConfig, Message: fmt.Sprintf("invalid config: service slug %q is not valid", slug)}
	}
	cSlug := C.CString(slug)
	defer C.free(unsafe.Pointer(cSlug))
	return callService(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_service_get(cancelID, cSlug, buf, bufLen)
	})
}

// UpdateService sends one change and returns the Service once it is committed.
func UpdateService(ctx context.Context, handle uint64, request ServiceUpdateRequest) (*ServiceInfo, error) {
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, undispatchedServiceChange(err)
	}
	cRequest := C.CString(string(payload))
	defer C.free(unsafe.Pointer(cRequest))
	return callService(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_service_update(cancelID, C.uint64_t(handle), cRequest, buf, bufLen)
	})
}

// EnableService enables a Service and returns it once committed.
func EnableService(ctx context.Context, handle uint64) (*ServiceInfo, error) {
	return callService(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_service_enable(cancelID, C.uint64_t(handle), buf, bufLen)
	})
}

// DisableService disables a Service and returns it once committed.
func DisableService(ctx context.Context, handle uint64) (*ServiceInfo, error) {
	return callService(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_service_disable(cancelID, C.uint64_t(handle), buf, bufLen)
	})
}

// ListServices returns one page of Services.
func ListServices(ctx context.Context, options ServiceListOptions) (*ServicePage, error) {
	if err := ensureService(ctx); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(options)
	if err != nil {
		return nil, err
	}
	cOptions := C.CString(string(payload))
	defer C.free(unsafe.Pointer(cOptions))
	out, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_service_list(cancelID, cOptions, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var page *ServicePage
	if err := json.Unmarshal([]byte(out), &page); err != nil {
		return nil, fmt.Errorf("parse service page: %w", err)
	}
	if page == nil {
		return nil, fmt.Errorf("native SDK returned no service page")
	}
	return page, nil
}

// RemoveService removes a Service.
func RemoveService(ctx context.Context, handle uint64) error {
	if err := ensureService(ctx); err != nil {
		return undispatchedServiceChange(err)
	}
	_, err := call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_service_remove(cancelID, C.uint64_t(handle), buf, bufLen)
	})
	return err
}

// RefreshService gets a Service through the backend retained by its handle.
func RefreshService(ctx context.Context, handle uint64) (*ServiceInfo, error) {
	return callService(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_service_refresh(cancelID, C.uint64_t(handle), buf, bufLen)
	})
}

// CloseService releases a Service handle. It runs with context.Background so a finalizer can always complete it.
func CloseService(handle uint64) error {
	_, err := call(context.Background(), func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.call_msb_service_close(cancelID, C.uint64_t(handle), buf, bufLen)
	})
	return err
}

// ensureService loads the library and refuses before dispatch when it predates Services.
func ensureService(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ensureLoaded(); err != nil {
		return err
	}
	if !bool(C.has_msb_service()) {
		return &Error{Kind: KindUnsupportedOperation, Message: "native SDK does not support services; update the native SDK"}
	}
	return nil
}

func callService(ctx context.Context, fn func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char) (*ServiceInfo, error) {
	if err := ensureService(ctx); err != nil {
		return nil, undispatchedServiceChange(err)
	}
	out, err := call(ctx, fn)
	if err != nil {
		return nil, err
	}
	var info *ServiceInfo
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		return nil, fmt.Errorf("parse service: %w", err)
	}
	if info == nil {
		return nil, fmt.Errorf("native SDK returned no service")
	}
	return info, nil
}

// ImageLoad imports images from a local archive into the cache and returns
// a handle per imported reference. tags apply extra references to the first
// image in the archive.
func ImageLoad(ctx context.Context, inputPath string, tags []string) ([]*ImageHandleInfo, error) {
	return defaultLibrary().ImageLoad(ctx, inputPath, tags)
}

// ImageSave exports cached images to an archive file. format is "docker" or
// "oci"; empty means docker.
func ImageSave(ctx context.Context, references []string, outputPath string, format string) error {
	return defaultLibrary().ImageSave(ctx, references, outputPath, format)
}

// ---------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------

type SnapshotInfo struct {
	ObjectHandle              uint64              `json:"object_handle"`
	Reference                 string              `json:"reference"`
	ReferenceKind             string              `json:"reference_kind"`
	HeadUpdate                *SnapshotHeadUpdate `json:"head_update"`
	ID                        string              `json:"id"`
	Path                      *string             `json:"path"`
	Digest                    string              `json:"digest"`
	SizeBytes                 *uint64             `json:"size_bytes"`
	ImageRef                  string              `json:"image_ref"`
	ImageManifestDigest       string              `json:"image_manifest_digest"`
	Scope                     string              `json:"scope"`
	StateKind                 string              `json:"state_kind"`
	Format                    *string             `json:"format"`
	Fstype                    *string             `json:"fstype"`
	UpperFile                 *string             `json:"upper_file"`
	UpperIntegrityAlgorithm   *string             `json:"upper_integrity_algorithm"`
	UpperIntegrityDigest      *string             `json:"upper_integrity_digest"`
	UpperIntegrityRoot        *string             `json:"upper_integrity_root"`
	UpperIntegrityLogicalSize *uint64             `json:"upper_integrity_logical_size"`
	UpperIntegrityLeafSize    *uint32             `json:"upper_integrity_leaf_size"`
	CheckpointID              *string             `json:"checkpoint_id"`
	CheckpointManifestDigest  *string             `json:"checkpoint_manifest_digest"`
	Parent                    *string             `json:"parent"`
	CreatedAt                 string              `json:"created_at"`
	Labels                    map[string]string   `json:"labels"`
	SourceSandbox             *string             `json:"source_sandbox"`
}

type SnapshotArchiveInfo struct {
	ID               string `json:"id"`
	DescriptorDigest string `json:"descriptor_digest"`
	Path             string `json:"path"`
}

type SnapshotHandleInfo struct {
	Reference                string              `json:"reference"`
	ReferenceKind            string              `json:"reference_kind"`
	Group                    *string             `json:"group"`
	HeadUpdate               *SnapshotHeadUpdate `json:"head_update"`
	ID                       string              `json:"id"`
	Digest                   string              `json:"digest"`
	Name                     *string             `json:"name"`
	ParentDigest             *string             `json:"parent_digest"`
	ImageRef                 string              `json:"image_ref"`
	Scope                    string              `json:"scope"`
	StateKind                string              `json:"state_kind"`
	Format                   *string             `json:"format"`
	Fstype                   *string             `json:"fstype"`
	CheckpointManifestDigest *string             `json:"checkpoint_manifest_digest"`
	SizeBytes                *uint64             `json:"size_bytes"`
	Locality                 string              `json:"locality"`
	Availability             string              `json:"availability"`
	MigrationState           string              `json:"migration_state"`
	MigrationErrorCode       *string             `json:"migration_error_code"`
	CreatedAtUnix            int64               `json:"created_at_unix"`
	Path                     *string             `json:"path"`
}

type SnapshotVerifyReport struct {
	Digest   string `json:"digest"`
	Path     string `json:"path"`
	Coverage *struct {
		Kind       string   `json:"kind"`
		Unrecorded []string `json:"unrecorded,omitempty"`
	} `json:"coverage,omitempty"`
	Upper struct {
		Kind      string `json:"kind"`
		Algorithm string `json:"algorithm,omitempty"`
		Digest    string `json:"digest,omitempty"`
	} `json:"upper"`
	Checkpoint *struct {
		Kind string `json:"kind"`
		Root string `json:"root"`
	} `json:"checkpoint,omitempty"`
}

type SnapshotCreateOptions struct {
	Name            string            `json:"name,omitempty"`
	Group           string            `json:"group,omitempty"`
	DestDir         string            `json:"dest_dir,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	Force           bool              `json:"force,omitempty"`
	RecordIntegrity bool              `json:"record_integrity,omitempty"`
	Full            bool              `json:"full,omitempty"`
	GuestFlush      string            `json:"guest_flush,omitempty"`
}

type SnapshotSaveOptions struct {
	Compatibility string  `json:"compatibility,omitempty"`
	Since         string  `json:"since,omitempty"`
	LastLayers    *uint32 `json:"last_layers,omitempty"`
	WithParents   bool    `json:"with_parents,omitempty"`
	WithImage     bool    `json:"with_image,omitempty"`
	PlainTar      bool    `json:"plain_tar,omitempty"`
}

type SnapshotLoadOptions struct {
	CallerDirectory  string  `json:"caller_directory,omitempty"`
	Dest             string  `json:"dest,omitempty"`
	Base             string  `json:"base,omitempty"`
	Group            string  `json:"group,omitempty"`
	SetHead          bool    `json:"set_head,omitempty"`
	MaximumDiskBytes *uint64 `json:"maximum_disk_bytes,omitempty"`
}

type SnapshotHeadUpdate struct {
	Group    string  `json:"group"`
	Previous *string `json:"previous"`
	Head     *string `json:"head"`
	Reason   string  `json:"reason"`
	Changed  bool    `json:"changed"`
}

type SnapshotCopyOptions struct {
	Labels          map[string]string `json:"labels,omitempty"`
	RecordIntegrity bool              `json:"record_integrity,omitempty"`
}

func SandboxHandleSnapshot(ctx context.Context, sandboxName, snapshotName string) (*SnapshotInfo, error) {
	return defaultLibrary().SandboxHandleSnapshot(ctx, sandboxName, snapshotName)
}

func SnapshotCreate(ctx context.Context, sourceSandbox string, opts SnapshotCreateOptions) (*SnapshotInfo, error) {
	return defaultLibrary().SnapshotCreate(ctx, sourceSandbox, opts)
}

func SnapshotCreateArchive(ctx context.Context, sourceSandbox, archivePath string, opts SnapshotCreateOptions, plainTar bool) (*SnapshotArchiveInfo, error) {
	return defaultLibrary().SnapshotCreateArchive(ctx, sourceSandbox, archivePath, opts, plainTar)
}

func SnapshotOpen(ctx context.Context, reference, referenceKind string) (*SnapshotInfo, error) {
	return defaultLibrary().SnapshotOpen(ctx, reference, referenceKind)
}

func SnapshotVerify(ctx context.Context, reference, referenceKind string) (*SnapshotVerifyReport, error) {
	return defaultLibrary().SnapshotVerify(ctx, reference, referenceKind)
}

func SnapshotGet(ctx context.Context, nameOrDigest string) (*SnapshotHandleInfo, error) {
	return defaultLibrary().SnapshotGet(ctx, nameOrDigest)
}

func SnapshotList(ctx context.Context) ([]*SnapshotHandleInfo, error) {
	return defaultLibrary().SnapshotList(ctx)
}

func SnapshotListDir(ctx context.Context, dir string) ([]*SnapshotInfo, error) {
	return defaultLibrary().SnapshotListDir(ctx, dir)
}

func SnapshotRemove(ctx context.Context, reference, referenceKind string, force bool) error {
	return defaultLibrary().SnapshotRemove(ctx, reference, referenceKind, force)
}

func SnapshotReindex(ctx context.Context, dir string) (uint32, error) {
	return defaultLibrary().SnapshotReindex(ctx, dir)
}

func SnapshotSave(ctx context.Context, reference, referenceKind, outPath string, opts SnapshotSaveOptions) error {
	return defaultLibrary().SnapshotSave(ctx, reference, referenceKind, outPath, opts)
}

func SnapshotCopy(ctx context.Context, reference, referenceKind, outputArchivePath string, opts SnapshotCopyOptions) error {
	return defaultLibrary().SnapshotCopy(ctx, reference, referenceKind, outputArchivePath, opts)
}

func SnapshotLoad(ctx context.Context, archive, dest string) (*SnapshotHandleInfo, error) {
	return defaultLibrary().SnapshotLoad(ctx, archive, dest)
}

func SnapshotLoadWithBase(ctx context.Context, archive, dest, base string) (*SnapshotHandleInfo, error) {
	return defaultLibrary().SnapshotLoadWithBase(ctx, archive, dest, base)
}

func SnapshotLoadWithOptions(ctx context.Context, archive string, opts SnapshotLoadOptions) (*SnapshotHandleInfo, error) {
	return defaultLibrary().SnapshotLoadWithOptions(ctx, archive, opts)
}

func SnapshotLoadMany(ctx context.Context, archives []string, opts SnapshotLoadOptions) ([]*SnapshotHandleInfo, error) {
	return defaultLibrary().SnapshotLoadMany(ctx, archives, opts)
}

func SnapshotGroupHead(ctx context.Context, selector string) (*SnapshotHeadUpdate, error) {
	return defaultLibrary().SnapshotGroupHead(ctx, selector)
}

// RuntimeSetup calls the shared resolver/installer after bootstrapping the SDK library.
func RuntimeSetup(ctx context.Context, operation, configJSON, optionsJSON string) (string, error) {
	return defaultLibrary().RuntimeSetup(ctx, operation, configJSON, optionsJSON)
}

func runtimeSetupOutput(ctx context.Context, operation string, invoke func(int) (string, error)) (string, error) {
	for size := defaultBufSize; ; {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		output, err := invoke(size)
		// Only diagnosis is read-only. Retrying install, ensure or recovery after an
		// undersized response could repeat an already-completed mutation.
		var native *Error
		if operation != "diagnose_storage" || !errors.As(err, &native) || native.Kind != KindBufferTooSmall {
			return output, err
		}
		var needed, available int
		if _, parseErr := fmt.Sscanf(native.Message, "output buffer too small: need %d, have %d", &needed, &available); parseErr != nil || needed <= size || available != size {
			return "", err
		}
		if needed > storageDiagnosisMaxBufSize || size == storageDiagnosisMaxBufSize {
			return "", &Error{
				Kind:    KindBufferTooSmall,
				Message: "storage diagnosis exceeds the 32 MiB response limit; inspect smaller named subsets",
			}
		}
		// Grow geometrically even if a concurrently changing inventory requests only
		// one extra byte each time. The cap bounds both allocation and retry count.
		size = min(storageDiagnosisMaxBufSize, max(needed, size*2))
	}
}

// Jobs invokes the optional managed-job ABI without changing existing library requirements.
func Jobs(ctx context.Context, sandbox uint64, request any) (json.RawMessage, error) {
	return defaultLibrary().Jobs(ctx, sandbox, request)
}

// RequirePortModification rejects requests that an older library would ignore.
func RequirePortModification() error { return defaultLibrary().RequirePortModification() }

// RequireSecretPolicyModification rejects secret policy edits that an older
// library would skip.
func RequireSecretPolicyModification() error {
	return defaultLibrary().RequireSecretPolicyModification()
}

func (receiver *Sandbox) lib() *Library {
	if receiver.library != nil {
		return receiver.library
	}
	if receiver.destination != nil {
		return receiver.destination.lib()
	}
	return defaultLibrary()
}

func (receiver *AgentClient) lib() *Library {
	if receiver.library != nil {
		return receiver.library
	}
	return defaultLibrary()
}

func (receiver *AgentStreamHandle) lib() *Library {
	if receiver.library != nil {
		return receiver.library
	}
	return defaultLibrary()
}

func (library *Library) call(ctx context.Context, fn func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char) (string, error) {
	return library.callBuf(ctx, defaultBufSize, fn)
}

func (library *Library) callBuf(ctx context.Context, bufSize int, fn func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char) (string, error) {
	return library.callBufWithAbandonedResult(ctx, bufSize, fn, nil)
}

func (library *Library) callBufWithAbandonedResult(ctx context.Context, bufSize int, fn func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char, abandoned func(string)) (string, error) {
	done := make(chan nativeCallResult, 1)
	buf := make([]byte, bufSize)
	cancelID := C.provider_call_msb_cancel_alloc(library.table)

	go func() {
		errPtr := fn(cancelID, (*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
		if errPtr != nil {
			msg := C.GoString(errPtr)
			C.provider_call_msb_free_string(library.table, errPtr)
			var e Error
			if jerr := json.Unmarshal([]byte(msg), &e); jerr != nil {
				e = Error{Kind: KindInternal, Message: msg}
			}
			done <- nativeCallResult{err: &e}
			return
		}
		end := 0
		for end < len(buf) && buf[end] != 0 {
			end++
		}
		done <- nativeCallResult{out: string(buf[:end])}
	}()

	return awaitNativeResult(ctx, done, func() { C.provider_call_msb_cancel_trigger(library.table, cancelID) }, abandoned)
}

func (library *Library) callRaw(ctx context.Context, fn func(cancelID C.uint64_t) *C.char) error {
	type res struct {
		err error
	}
	done := make(chan res, 1)
	cancelID := C.provider_call_msb_cancel_alloc(library.table)

	go func() {
		done <- res{err: library.errorFromPtr(fn(cancelID))}
	}()

	select {
	case r := <-done:
		return r.err
	case <-ctx.Done():
		C.provider_call_msb_cancel_trigger(library.table, cancelID)
		<-done
		return ctx.Err()
	}
}

func (library *Library) errorFromPtr(errPtr *C.char) error {
	if errPtr == nil {
		return nil
	}
	msg := C.GoString(errPtr)
	C.provider_call_msb_free_string(library.table, errPtr)
	var e Error
	if jerr := json.Unmarshal([]byte(msg), &e); jerr != nil {
		e = Error{Kind: KindInternal, Message: msg}
	}
	return &e
}

func (library *Library) takeRustBytes(ptr *C.uint8_t, len C.size_t) []byte {
	if ptr == nil || len == 0 {
		return []byte{}
	}
	defer C.provider_call_msb_agent_free_bytes(library.table, ptr, len)
	return append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(ptr)), int(len))...)
}

func (library *Library) freeRustBytes(ptrSlot **C.uint8_t, lenSlot *C.size_t) {
	if ptrSlot == nil || lenSlot == nil || *ptrSlot == nil {
		return
	}
	C.provider_call_msb_agent_free_bytes(library.table, *ptrSlot, *lenSlot)
	*ptrSlot = nil
	*lenSlot = 0
}

func (library *Library) allocRustBytesOut() (**C.uint8_t, *C.size_t, func()) {
	ptrSlot := (**C.uint8_t)(C.malloc(C.size_t(unsafe.Sizeof(uintptr(0)))))
	lenSlot := (*C.size_t)(C.malloc(C.size_t(unsafe.Sizeof(C.size_t(0)))))
	*ptrSlot = nil
	*lenSlot = 0
	cleanup := func() {
		C.free(unsafe.Pointer(ptrSlot))
		C.free(unsafe.Pointer(lenSlot))
	}
	return ptrSlot, lenSlot, cleanup
}

func (library *Library) releaseHandle(handle uint64) {
	_, _ = library.call(context.Background(), func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_close(library.table, cancelID, C.uint64_t(handle), buf, bufLen)
	})
}

func (library *Library) OpenCreationProgress(ctx context.Context) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if err := library.ensureLoaded(); err != nil {
		return 0, err
	}
	if !bool(C.provider_has_creation_progress(library.table)) {
		return 0, fmt.Errorf("installed native SDK does not support creation progress")
	}
	return openCreationProgress(ctx, func() (uint64, error) {
		out, err := callSync(func(buf []byte) error {
			return library.errorFromPtr(C.provider_call_creation_progress_open(library.table, (*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf))))
		})
		if err != nil {
			return 0, err
		}
		var reply struct {
			Handle uint64 `json:"handle"`
		}
		err = json.Unmarshal([]byte(out), &reply)
		if err == nil && reply.Handle == 0 {
			err = fmt.Errorf("native creation progress returned an invalid handle")
		}
		return reply.Handle, err
	}, library.CloseCreationProgress)
}

func (library *Library) ReceiveCreationProgress(ctx context.Context, id uint64) (json.RawMessage, error) {
	out, err := library.call(ctx, func(cancel C.uint64_t, buf *C.uint8_t, n C.size_t) *C.char {
		return C.provider_call_creation_progress_recv(library.table, cancel, C.uint64_t(id), buf, n)
	})
	return json.RawMessage(out), err
}

func (library *Library) CloseCreationProgress(id uint64) error {
	_, err := callSync(func(buf []byte) error {
		return library.errorFromPtr(C.provider_call_creation_progress_close(library.table, C.uint64_t(id), (*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf))))
	})
	return err
}

func (library *Library) createSandbox(ctx context.Context, name string, opts CreateOptions, connectOrCreate bool) (*Sandbox, error) {
	if err := library.ensureLoaded(); err != nil {
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

	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_create(library.table, cancelID, cName, cOpts, C.bool(connectOrCreate), buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Handle      uint64 `json:"handle"`
		BackendKind string `json:"backend_kind"`
		ID          string `json:"id"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		// Rust has allocated a handle we can no longer trust. Best-effort
		// recover the handle from the response so we can release it;
		// otherwise the VM and registry entry would leak.
		if h := salvageHandle(out); h != 0 {
			library.releaseHandle(h)
		}
		return nil, fmt.Errorf("parse create response: %w", err)
	}
	s := &Sandbox{library: library, name: name, id: resp.ID, backendKind: resp.BackendKind}
	s.handle.Store(resp.Handle)
	return s, nil
}

func (library *Library) RestoreSandbox(ctx context.Context, name string, opts RestoreOptions) (*Sandbox, error) {
	if err := library.CheckRestoreBootOptions(ctx, opts); err != nil {
		return nil, err
	}
	if err := library.CheckRestoreGuestClock(ctx, opts.GuestClock); err != nil {
		return nil, err
	}
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	if !bool(C.provider_has_sandbox_restore(library.table)) {
		return nil, &Error{Kind: KindUnsupportedOperation, Message: "native SDK does not support Sandbox restore; update the native SDK"}
	}

	optsJSON, err := json.Marshal(opts)
	if err != nil {
		return nil, fmt.Errorf("marshal opts: %w", err)
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	cOpts := C.CString(string(optsJSON))
	defer C.free(unsafe.Pointer(cOpts))

	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_restore(library.table, cancelID, cName, cOpts, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Handle      uint64 `json:"handle"`
		BackendKind string `json:"backend_kind"`
		ID          string `json:"id"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		// Rust has allocated a handle we can no longer trust. Best-effort
		// recover the handle from the response so we can release it;
		// otherwise the VM and registry entry would leak.
		if h := salvageHandle(out); h != 0 {
			library.releaseHandle(h)
		}
		return nil, fmt.Errorf("parse restore response: %w", err)
	}
	s := &Sandbox{library: library, name: name, id: resp.ID, backendKind: resp.BackendKind}
	s.handle.Store(resp.Handle)
	return s, nil
}

func (receiver *SSHClient) lib() *Library {
	if receiver.library != nil {
		return receiver.library
	}
	return defaultLibrary()
}

func (receiver *SSHServer) lib() *Library {
	if receiver.library != nil {
		return receiver.library
	}
	return defaultLibrary()
}

func (receiver *SFTPClient) lib() *Library {
	if receiver.library != nil {
		return receiver.library
	}
	return defaultLibrary()
}

func (receiver *ExecStreamHandle) lib() *Library {
	if receiver.library != nil {
		return receiver.library
	}
	return defaultLibrary()
}

func (receiver *ExecSink) lib() *Library {
	if receiver.library != nil {
		return receiver.library
	}
	return defaultLibrary()
}

func (receiver *MetricsStreamHandle) lib() *Library {
	if receiver.library != nil {
		return receiver.library
	}
	return defaultLibrary()
}

func (receiver *LogStreamHandle) lib() *Library {
	if receiver.library != nil {
		return receiver.library
	}
	return defaultLibrary()
}

func (receiver *FsReadStreamHandle) lib() *Library {
	if receiver.library != nil {
		return receiver.library
	}
	return defaultLibrary()
}

func (receiver *FsWriteStreamHandle) lib() *Library {
	if receiver.library != nil {
		return receiver.library
	}
	return defaultLibrary()
}

func (library *Library) SetSdkMsbPath(path string) {
	if path == "" {
		return
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	C.provider_call_msb_set_sdk_msb_path(library.table, cPath)
}

func (library *Library) OpenAgentSandbox(ctx context.Context, name string) (*AgentClient, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	var handle C.uint64_t
	timeoutMs := timeoutMillisFromContext(ctx)
	if err := library.callRaw(ctx, func(cancelID C.uint64_t) *C.char {
		return C.provider_call_msb_agent_open_sandbox(library.table, cancelID, cName, timeoutMs, &handle)
	}); err != nil {
		return nil, err
	}
	c := &AgentClient{library: library}
	c.handle.Store(uint64(handle))
	return c, nil
}

func (library *Library) OpenAgentPath(ctx context.Context, path string) (*AgentClient, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	var handle C.uint64_t
	timeoutMs := timeoutMillisFromContext(ctx)
	if err := library.callRaw(ctx, func(cancelID C.uint64_t) *C.char {
		return C.provider_call_msb_agent_open_path(library.table, cancelID, cPath, timeoutMs, &handle)
	}); err != nil {
		return nil, err
	}
	c := &AgentClient{library: library}
	c.handle.Store(uint64(handle))
	return c, nil
}

func (library *Library) CreateSandbox(ctx context.Context, name string, opts CreateOptions) (*Sandbox, error) {
	return library.createSandbox(ctx, name, opts, false)
}

func (library *Library) ConnectOrCreateSandbox(ctx context.Context, name string, opts CreateOptions) (*Sandbox, error) {
	return library.createSandbox(ctx, name, opts, true)
}

func (library *Library) ConnectSandbox(ctx context.Context, name string) (*Sandbox, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_connect(library.table, cancelID, cName, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Handle      uint64 `json:"handle"`
		BackendKind string `json:"backend_kind"`
		ID          string `json:"id"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		if h := salvageHandle(out); h != 0 {
			library.releaseHandle(h)
		}
		return nil, fmt.Errorf("parse connect response: %w", err)
	}
	s := &Sandbox{library: library, name: name, id: resp.ID, backendKind: resp.BackendKind}
	s.handle.Store(resp.Handle)
	return s, nil
}

func (library *Library) sandboxHandleLifecycle(
	ctx context.Context,
	name string,
	id string,
	operation string,
	opts SandboxHandleLifecycleOptions,
) (string, error) {
	if err := library.ensureLoaded(); err != nil {
		return "", err
	}
	if operation == "stop_gracefully" || operation == "stop_with_timeout" || operation == "request_stop" {
		if err := library.requireGracefulStopWait(); err != nil {
			return "", err
		}
	}
	optsJSON, err := json.Marshal(opts)
	if err != nil {
		return "", fmt.Errorf("marshal lifecycle opts: %w", err)
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	cID := C.CString(id)
	defer C.free(unsafe.Pointer(cID))
	cOperation := C.CString(operation)
	defer C.free(unsafe.Pointer(cOperation))
	cOpts := C.CString(string(optsJSON))
	defer C.free(unsafe.Pointer(cOpts))
	var abandoned func(string)
	if operation == "get_running" || operation == "get" {
		abandoned = func(out string) {
			if handle := salvageHandle(out); handle != 0 {
				library.releaseHandle(handle)
			}
		}
	}
	return library.callBufWithAbandonedResult(ctx, defaultBufSize, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_handle_lifecycle(library.table,
			cancelID,
			cName,
			cID,
			cOperation,
			cOpts,
			buf,
			bufLen,
		)
	}, abandoned)
}

func (library *Library) SandboxHandleLiveLifecycle(
	ctx context.Context,
	name string,
	id string,
	operation string,
	opts SandboxHandleLifecycleOptions,
) (*Sandbox, error) {
	out, err := library.sandboxHandleLifecycle(ctx, name, id, operation, opts)
	if err != nil {
		return nil, err
	}
	var response struct {
		Handle      uint64 `json:"handle"`
		BackendKind string `json:"backend_kind"`
		ID          string `json:"id"`
	}
	if err := json.Unmarshal([]byte(out), &response); err != nil {
		if handle := salvageHandle(out); handle != 0 {
			library.releaseHandle(handle)
		}
		return nil, fmt.Errorf("parse lifecycle response: %w", err)
	}
	sandbox := &Sandbox{library: library, name: name, id: response.ID, backendKind: response.BackendKind}
	sandbox.handle.Store(response.Handle)
	return sandbox, nil
}

func (library *Library) SandboxHandleInfoLifecycle(
	ctx context.Context,
	name string,
	id string,
	operation string,
	opts SandboxHandleLifecycleOptions,
) (*SandboxHandleInfo, error) {
	out, err := library.sandboxHandleLifecycle(ctx, name, id, operation, opts)
	if err != nil {
		return nil, err
	}
	var info SandboxHandleInfo
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		return nil, fmt.Errorf("parse lifecycle handle response: %w", err)
	}
	return &info, nil
}

func (library *Library) SandboxHandleStopLifecycle(
	ctx context.Context,
	name string,
	id string,
) (*SandboxStopResult, error) {
	out, err := library.sandboxHandleLifecycle(
		ctx,
		name,
		id,
		"wait_until_stopped",
		SandboxHandleLifecycleOptions{},
	)
	if err != nil {
		return nil, err
	}
	var result SandboxStopResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		return nil, fmt.Errorf("parse lifecycle stop response: %w", err)
	}
	return &result, nil
}

func (library *Library) SandboxHandleVoidLifecycle(
	ctx context.Context,
	name string,
	id string,
	operation string,
	opts SandboxHandleLifecycleOptions,
) error {
	_, err := library.sandboxHandleLifecycle(ctx, name, id, operation, opts)
	return err
}

func (library *Library) StopSandboxHandle(ctx context.Context, name, id string, timeoutMs *uint64) error {
	operation, opts := stopLifecycleRequest(timeoutMs)
	return library.SandboxHandleVoidLifecycle(ctx, name, id, operation, opts)
}

func (library *Library) SandboxHandleLogs(ctx context.Context, name string, opts LogOptions) ([]LogEntry, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	cOpts, err := logsOptionsJSON(opts)
	if err != nil {
		return nil, err
	}
	defer C.free(unsafe.Pointer(cOpts))
	out, err := library.callBuf(ctx, logsBufSize, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_handle_logs(library.table, cancelID, cName, cOpts, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	return parseLogEntries(out)
}

func (library *Library) LookupSandbox(ctx context.Context, name string) (*SandboxHandleInfo, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	if bool(C.provider_has_msb_snapshot_objects(library.table)) {
		raw, err := library.SnapshotObjectCall(ctx, 0, map[string]any{"op": "lookup_source", "name": name})
		if err != nil {
			return nil, err
		}
		var info SandboxHandleInfo
		if err := json.Unmarshal(raw, &info); err != nil {
			return nil, fmt.Errorf("parse retained source: %w", err)
		}
		return &info, nil
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_lookup(library.table, cancelID, cName, buf, bufLen)
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

func (library *Library) StartSandbox(ctx context.Context, name string, detached bool) (*Sandbox, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_start(library.table, cancelID, cName, C.bool(detached), buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Handle      uint64 `json:"handle"`
		BackendKind string `json:"backend_kind"`
		ID          string `json:"id"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		if h := salvageHandle(out); h != 0 {
			library.releaseHandle(h)
		}
		return nil, fmt.Errorf("parse start response: %w", err)
	}
	s := &Sandbox{library: library, name: name, id: resp.ID, backendKind: resp.BackendKind}
	s.handle.Store(resp.Handle)
	return s, nil
}

func (library *Library) StopSandboxByName(ctx context.Context, name string, timeoutMs uint64) error {
	if err := library.ensureLoaded(); err != nil {
		return err
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	_, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_handle_stop(library.table, cancelID, cName, C.uint64_t(timeoutMs), buf, bufLen)
	})
	return err
}

func (library *Library) RequestStopSandboxByName(ctx context.Context, name string) error {
	if err := library.ensureLoaded(); err != nil {
		return err
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	_, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_handle_request_stop(library.table, cancelID, cName, buf, bufLen)
	})
	return err
}

func (library *Library) PauseSandboxByName(ctx context.Context, name string) error {
	if err := library.ensureLoaded(); err != nil {
		return err
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	_, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_handle_pause(library.table, cancelID, cName, buf, bufLen)
	})
	return err
}

func (library *Library) ResumeSandboxByName(ctx context.Context, name string) error {
	if err := library.ensureLoaded(); err != nil {
		return err
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	_, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_handle_resume(library.table, cancelID, cName, buf, bufLen)
	})
	return err
}

func (library *Library) KillSandboxByName(ctx context.Context, name string, timeoutMs uint64) error {
	if err := library.ensureLoaded(); err != nil {
		return err
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	_, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_handle_kill(library.table, cancelID, cName, C.uint64_t(timeoutMs), buf, bufLen)
	})
	return err
}

func (library *Library) RequestKillSandboxByName(ctx context.Context, name string) error {
	if err := library.ensureLoaded(); err != nil {
		return err
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	_, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_handle_request_kill(library.table, cancelID, cName, buf, bufLen)
	})
	return err
}

func (library *Library) RequestDrainSandboxByName(ctx context.Context, name string) error {
	if err := library.ensureLoaded(); err != nil {
		return err
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	_, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_handle_request_drain(library.table, cancelID, cName, buf, bufLen)
	})
	return err
}

func (library *Library) WaitSandboxByNameUntilStopped(ctx context.Context, name string) (*SandboxStopResult, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_handle_wait_until_stopped(library.table, cancelID, cName, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var result SandboxStopResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		return nil, fmt.Errorf("parse wait_until_stopped response: %w", err)
	}
	return &result, nil
}

func (library *Library) PingSandboxByName(ctx context.Context, name string) (*SandboxPingResult, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_handle_ping(library.table, cancelID, cName, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var result SandboxPingResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		return nil, fmt.Errorf("parse ping response: %w", err)
	}
	return &result, nil
}

func (library *Library) TouchSandboxByName(ctx context.Context, name string) (*SandboxTouchResult, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_handle_touch(library.table, cancelID, cName, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var result SandboxTouchResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		return nil, fmt.Errorf("parse touch response: %w", err)
	}
	return &result, nil
}

func (library *Library) ModifySandboxByName(ctx context.Context, name, optsJSON string) (string, error) {
	if err := library.ensureLoaded(); err != nil {
		return "", err
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	cOpts := C.CString(optsJSON)
	defer C.free(unsafe.Pointer(cOpts))
	return library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_handle_modify(library.table, cancelID, cName, cOpts, buf, bufLen)
	})
}

func (library *Library) requireGracefulStopWait() error {
	if !bool(C.provider_has_graceful_stop_wait(library.table)) {
		return &Error{Kind: KindUnsupportedOperation, Message: "native SDK does not support graceful stop without forced termination; update the native SDK"}
	}
	return nil
}

func (library *Library) BranchManyByName(ctx context.Context, handle uint64, source, identity string, names []string, integrity bool, volumes map[string]MountSpec, policy ...string) ([]BranchOutcome, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	if !bool(C.provider_has_branch_many(library.table)) {
		return nil, &Error{Kind: KindUnsupportedOperation, Message: "native SDK does not support batch branching; update the native SDK"}
	}
	flush := ""
	if len(policy) > 0 {
		flush = policy[0]
	}
	if err := library.checkGuestFlush(flush, false); err != nil {
		return nil, err
	}
	if names == nil {
		names = []string{}
	}
	encoded, err := json.Marshal(struct {
		Names      []string             `json:"names"`
		Identity   string               `json:"source_identity"`
		GuestFlush string               `json:"guest_flush,omitempty"`
		Volumes    map[string]MountSpec `json:"volumes,omitempty"`
	}{names, identity, flush, volumes})
	if err != nil {
		return nil, err
	}
	cSource, cNames := C.CString(source), C.CString(string(encoded))
	defer C.free(unsafe.Pointer(cSource))
	defer C.free(unsafe.Pointer(cNames))
	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, size C.size_t) *C.char {
		return C.provider_call_msb_sandbox_branch_many(library.table, cancelID, C.uint64_t(handle), cSource, cNames, C.bool(integrity), buf, size)
	})
	if err != nil {
		return nil, err
	}
	var response struct {
		Outcomes []struct {
			Name        string `json:"name"`
			ID          string `json:"id"`
			Handle      uint64 `json:"handle"`
			BackendKind string `json:"backend_kind"`
			Error       *Error `json:"error"`
		} `json:"outcomes"`
	}
	if err := json.Unmarshal([]byte(out), &response); err != nil {
		return nil, fmt.Errorf("parse batch branch response: %w", err)
	}
	results := make([]BranchOutcome, 0, len(response.Outcomes))
	for _, row := range response.Outcomes {
		item := BranchOutcome{Name: row.Name}
		if row.Error != nil {
			item.Error = row.Error
		} else {
			child := &Sandbox{library: library, name: row.Name, id: row.ID, backendKind: row.BackendKind}
			child.handle.Store(row.Handle)
			item.Sandbox = child
		}
		results = append(results, item)
	}
	return results, nil
}

func (library *Library) BranchSandboxByName(ctx context.Context, source, name string, recordIntegrity bool, volumes map[string]MountSpec, policy ...string) (*Sandbox, error) {
	if len(volumes) > 0 || (len(policy) > 0 && policy[0] != "") {
		rows, err := library.BranchManyByName(ctx, 0, source, "", []string{name}, recordIntegrity, volumes, policy...)
		return oneBranchOutcome(rows, err)
	}
	return library.branchSandbox(ctx, 0, source, name, recordIntegrity)
}

func (library *Library) branchSandbox(ctx context.Context, handle uint64, source, name string, recordIntegrity bool) (*Sandbox, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	cSource, cName := C.CString(source), C.CString(name)
	if recordIntegrity && !bool(C.provider_has_branch_integrity(library.table)) {
		C.free(unsafe.Pointer(cSource))
		C.free(unsafe.Pointer(cName))
		return nil, &Error{Kind: KindUnsupportedOperation, Message: "native SDK does not support branch integrity; update the native SDK"}
	}
	defer C.free(unsafe.Pointer(cSource))
	defer C.free(unsafe.Pointer(cName))
	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		if recordIntegrity {
			return C.provider_call_msb_sandbox_branch_with_options(library.table, cancelID, C.uint64_t(handle), cSource, cName, C.bool(true), buf, bufLen)
		}
		return C.provider_call_msb_sandbox_branch(library.table, cancelID, C.uint64_t(handle), cSource, cName, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Handle      uint64 `json:"handle"`
		BackendKind string `json:"backend_kind"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		if h := salvageHandle(out); h != 0 {
			library.releaseHandle(h)
		}
		return nil, fmt.Errorf("parse branch response: %w", err)
	}
	s := &Sandbox{library: library, name: name, backendKind: resp.BackendKind}
	s.handle.Store(resp.Handle)
	return s, nil
}

func (library *Library) checkGuestFlush(policy string, diskOnly bool) error {
	return validateGuestFlushSupport(policy, diskOnly, bool(C.provider_has_guest_flush(library.table)))
}

func (library *Library) PauseWithGuestFlush(ctx context.Context, handle uint64, name, identity, policy string) error {
	if err := library.ensureLoaded(); err != nil {
		return err
	}
	if err := library.checkGuestFlush(policy, true); err != nil {
		return err
	}
	if policy == "" {
		policy = "auto"
	}
	cName, cIdentity, cPolicy := C.CString(name), C.CString(identity), C.CString(policy)
	defer C.free(unsafe.Pointer(cName))
	defer C.free(unsafe.Pointer(cIdentity))
	defer C.free(unsafe.Pointer(cPolicy))
	_, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, size C.size_t) *C.char {
		return C.provider_call_msb_sandbox_pause_with_guest_flush(library.table, cancelID, C.uint64_t(handle), cName, cIdentity, cPolicy, buf, size)
	})
	return err
}

func (library *Library) CompactSandbox(ctx context.Context, handle uint64, name, opts string) (string, error) {
	if err := library.ensureLoaded(); err != nil {
		return "", err
	}
	cName, cOpts := C.CString(name), C.CString(opts)
	defer C.free(unsafe.Pointer(cName))
	defer C.free(unsafe.Pointer(cOpts))
	return library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_compact(library.table, cancelID, C.uint64_t(handle), cName, cOpts, buf, bufLen)
	})
}

func (library *Library) RemoveSandbox(ctx context.Context, name string) error {
	if err := library.ensureLoaded(); err != nil {
		return err
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	_, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_remove(library.table, cancelID, cName, buf, bufLen)
	})
	return err
}

func (library *Library) SandboxHandleLogStream(
	ctx context.Context,
	name string,
	opts LogStreamOptions,
) (*LogStreamHandle, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	cOpts, err := logStreamOptionsJSON(opts)
	if err != nil {
		return nil, err
	}
	defer C.free(unsafe.Pointer(cOpts))
	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_handle_log_stream(library.table, cancelID, cName, cOpts, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var resp struct {
		StreamHandle uint64 `json:"stream_handle"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return nil, fmt.Errorf("parse log_stream response: %w", err)
	}
	return &LogStreamHandle{library: library, handle: C.uint64_t(resp.StreamHandle)}, nil
}

func (library *Library) AllSandboxMetrics(ctx context.Context) (map[string]*Metrics, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_all_sandbox_metrics(library.table, cancelID, buf, bufLen)
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
	for _, s := range resp.Sandboxes {
		s.Uptime = time.Duration(s.UptimeSecs) * time.Second
	}
	return resp.Sandboxes, nil
}

func (library *Library) SandboxHandleMetrics(ctx context.Context, name string) (*Metrics, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_handle_metrics(library.table, cancelID, cName, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var raw struct {
		CPUPercent              float64 `json:"cpu_percent"`
		VCPUTimeNs              uint64  `json:"vcpu_time_ns"`
		MemoryBytes             uint64  `json:"memory_bytes"`
		MemoryAvailableBytes    *uint64 `json:"memory_available_bytes"`
		MemoryHostResidentBytes *uint64 `json:"memory_host_resident_bytes"`
		MemoryLimitBytes        uint64  `json:"memory_limit_bytes"`
		DiskReadBytes           uint64  `json:"disk_read_bytes"`
		DiskWriteBytes          uint64  `json:"disk_write_bytes"`
		NetRxBytes              uint64  `json:"net_rx_bytes"`
		NetTxBytes              uint64  `json:"net_tx_bytes"`
		UpperUsedBytes          *uint64 `json:"upper_used_bytes"`
		UpperFreeBytes          *uint64 `json:"upper_free_bytes"`
		UpperHostAllocatedBytes *uint64 `json:"upper_host_allocated_bytes"`
		UptimeSecs              uint64  `json:"uptime_secs"`
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, fmt.Errorf("parse sandbox_handle_metrics: %w", err)
	}
	return &Metrics{
		CPUPercent:              raw.CPUPercent,
		VCPUTimeNs:              raw.VCPUTimeNs,
		MemoryBytes:             raw.MemoryBytes,
		MemoryAvailableBytes:    raw.MemoryAvailableBytes,
		MemoryHostResidentBytes: raw.MemoryHostResidentBytes,
		MemoryLimitBytes:        raw.MemoryLimitBytes,
		DiskReadBytes:           raw.DiskReadBytes,
		DiskWriteBytes:          raw.DiskWriteBytes,
		NetRxBytes:              raw.NetRxBytes,
		NetTxBytes:              raw.NetTxBytes,
		UpperUsedBytes:          raw.UpperUsedBytes,
		UpperFreeBytes:          raw.UpperFreeBytes,
		UpperHostAllocatedBytes: raw.UpperHostAllocatedBytes,
		UptimeSecs:              raw.UptimeSecs,
		Uptime:                  time.Duration(raw.UptimeSecs) * time.Second,
	}, nil
}

func (library *Library) CreateVolume(ctx context.Context, name string, opts VolumeCreateOptions) (*VolumeHandleInfo, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	optsJSON, err := json.Marshal(opts)
	if err != nil {
		return nil, fmt.Errorf("marshal volume opts: %w", err)
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	cOpts := C.CString(string(optsJSON))
	defer C.free(unsafe.Pointer(cOpts))

	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_volume_create(library.table, cancelID, cName, cOpts, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	return parseVolumeHandle(out)
}

func (library *Library) RemoveVolume(ctx context.Context, name string) error {
	if err := library.ensureLoaded(); err != nil {
		return err
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	_, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_volume_remove(library.table, cancelID, cName, buf, bufLen)
	})
	return err
}

func (library *Library) ListVolumes(ctx context.Context) ([]*VolumeHandleInfo, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_volume_list(library.table, cancelID, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var infos []*VolumeHandleInfo
	if err := json.Unmarshal([]byte(out), &infos); err != nil {
		return nil, fmt.Errorf("parse volume list: %w", err)
	}
	return infos, nil
}

func (library *Library) Version() (string, error) {
	if err := library.ensureLoaded(); err != nil {
		return "", err
	}
	buf := make([]byte, defaultBufSize)
	errPtr := C.provider_call_msb_version(library.table, (*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if errPtr != nil {
		msg := C.GoString(errPtr)
		C.provider_call_msb_free_string(library.table, errPtr)
		var e Error
		if jerr := json.Unmarshal([]byte(msg), &e); jerr != nil {
			e = Error{Kind: KindInternal, Message: msg}
		}
		return "", &e
	}
	end := 0
	for end < len(buf) && buf[end] != 0 {
		end++
	}
	var resp struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(buf[:end], &resp); err != nil {
		return "", fmt.Errorf("parse version: %w", err)
	}
	return resp.Version, nil
}

func (library *Library) DefaultBackendInfo() (*BackendInfo, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	buf := make([]byte, defaultBufSize)
	errPtr := C.provider_call_msb_default_backend_info(library.table, (*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if errPtr != nil {
		msg := C.GoString(errPtr)
		C.provider_call_msb_free_string(library.table, errPtr)
		var e Error
		if jerr := json.Unmarshal([]byte(msg), &e); jerr != nil {
			e = Error{Kind: KindInternal, Message: msg}
		}
		return nil, &e
	}
	end := 0
	for end < len(buf) && buf[end] != 0 {
		end++
	}
	if end == 0 {
		return nil, nil
	}
	var info BackendInfo
	if err := json.Unmarshal(buf[:end], &info); err != nil {
		return nil, fmt.Errorf("parse backend info: %w", err)
	}
	return &info, nil
}

func (library *Library) AgentSocketPath(name string) (string, error) {
	if err := library.ensureLoaded(); err != nil {
		return "", err
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	buf := make([]byte, defaultBufSize)
	errPtr := C.provider_call_msb_agent_socket_path(library.table, cName, (*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if errPtr != nil {
		msg := C.GoString(errPtr)
		C.provider_call_msb_free_string(library.table, errPtr)
		var e Error
		if jerr := json.Unmarshal([]byte(msg), &e); jerr != nil {
			e = Error{Kind: KindInternal, Message: msg}
		}
		return "", &e
	}
	end := 0
	for end < len(buf) && buf[end] != 0 {
		end++
	}
	var resp struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(buf[:end], &resp); err != nil {
		return "", fmt.Errorf("parse agent socket path: %w", err)
	}
	return resp.Path, nil
}

func (library *Library) GetVolume(ctx context.Context, name string) (*VolumeHandleInfo, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_volume_get(library.table, cancelID, cName, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var raw struct {
		ID            *string           `json:"id"`
		Name          string            `json:"name"`
		IsDefault     bool              `json:"is_default"`
		Path          string            `json:"path"`
		Kind          string            `json:"kind"`
		QuotaMiB      *uint32           `json:"quota_mib"`
		UsedBytes     uint64            `json:"used_bytes"`
		CapacityBytes *uint64           `json:"capacity_bytes"`
		DiskFormat    *string           `json:"disk_format"`
		DiskFstype    *string           `json:"disk_fstype"`
		Labels        map[string]string `json:"labels"`
		CreatedAtUnix *int64            `json:"created_at_unix"`
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, fmt.Errorf("parse volume_get: %w", err)
	}
	return &VolumeHandleInfo{
		ID:            raw.ID,
		Name:          raw.Name,
		IsDefault:     raw.IsDefault,
		Path:          raw.Path,
		Kind:          raw.Kind,
		QuotaMiB:      raw.QuotaMiB,
		UsedBytes:     raw.UsedBytes,
		CapacityBytes: raw.CapacityBytes,
		DiskFormat:    raw.DiskFormat,
		DiskFstype:    raw.DiskFstype,
		Labels:        raw.Labels,
		CreatedAtUnix: raw.CreatedAtUnix,
	}, nil
}

func (library *Library) GetDefaultVolume(ctx context.Context) (*VolumeHandleInfo, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_volume_get_default(library.table, cancelID, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var info VolumeHandleInfo
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		return nil, fmt.Errorf("parse volume_get_default: %w", err)
	}
	return &info, nil
}

func (library *Library) VolumeFsOp(ctx context.Context, name, op string, args any, result any) error {
	if err := library.ensureLoaded(); err != nil {
		return err
	}
	encoded, err := json.Marshal(args)
	if err != nil {
		return fmt.Errorf("marshal volume fs args: %w", err)
	}
	cName := C.CString(name)
	cOp := C.CString(op)
	cArgs := C.CString(string(encoded))
	defer C.free(unsafe.Pointer(cName))
	defer C.free(unsafe.Pointer(cOp))
	defer C.free(unsafe.Pointer(cArgs))
	invoke := func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_volume_fs_op(library.table, cancelID, cName, cOp, cArgs, buf, bufLen)
	}
	out, err := library.call(ctx, invoke)
	// Local reads historically used os.ReadFile and had no fixed response-size
	// limit. Only retry this read-only operation; never replay a mutation.
	for size := defaultBufSize; op == "local_read" && err != nil; {
		var native *Error
		if !errors.As(err, &native) || native.Kind != KindBufferTooSmall {
			break
		}
		var needed, available int
		if _, parseErr := fmt.Sscanf(native.Message, "output buffer too small: need %d, have %d", &needed, &available); parseErr != nil || needed <= size {
			break
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		size = needed
		out, err = library.callBuf(ctx, size, invoke)
	}
	if err != nil {
		return err
	}
	if result == nil {
		return nil
	}
	if err := json.Unmarshal([]byte(out), result); err != nil {
		return fmt.Errorf("parse volume fs response: %w", err)
	}
	return nil
}

func (library *Library) ImageGet(ctx context.Context, reference string) (*ImageHandleInfo, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	cRef := C.CString(reference)
	defer C.free(unsafe.Pointer(cRef))
	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_image_get(library.table, cancelID, cRef, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var info ImageHandleInfo
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		return nil, fmt.Errorf("parse image_get: %w", err)
	}
	return &info, nil
}

func (library *Library) ImageList(ctx context.Context) ([]*ImageHandleInfo, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_image_list(library.table, cancelID, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var infos []*ImageHandleInfo
	if err := json.Unmarshal([]byte(out), &infos); err != nil {
		return nil, fmt.Errorf("parse image_list: %w", err)
	}
	return infos, nil
}

func (library *Library) ImageInspect(ctx context.Context, reference string) (*ImageDetailInfo, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	cRef := C.CString(reference)
	defer C.free(unsafe.Pointer(cRef))
	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_image_inspect(library.table, cancelID, cRef, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var info ImageDetailInfo
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		return nil, fmt.Errorf("parse image_inspect: %w", err)
	}
	return &info, nil
}

func (library *Library) ImageRemove(ctx context.Context, reference string, force bool) error {
	if err := library.ensureLoaded(); err != nil {
		return err
	}
	cRef := C.CString(reference)
	defer C.free(unsafe.Pointer(cRef))
	_, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_image_remove(library.table, cancelID, cRef, C.bool(force), buf, bufLen)
	})
	return err
}

func (library *Library) ImagePrune(ctx context.Context) (*ImagePruneReportInfo, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_image_prune(library.table, cancelID, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var info ImagePruneReportInfo
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		return nil, fmt.Errorf("parse image_prune: %w", err)
	}
	return &info, nil
}

func (library *Library) StorageUsage(ctx context.Context) (*StorageUsageReport, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	if !bool(C.provider_has_msb_storage_usage(library.table)) {
		return nil, &Error{Kind: KindUnsupportedOperation, Message: "native SDK does not support storage usage; update the native SDK"}
	}
	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_storage_usage(library.table, cancelID, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var report *StorageUsageReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		return nil, fmt.Errorf("parse storage usage: %w", err)
	}
	if report == nil {
		return nil, fmt.Errorf("native SDK returned no storage usage report")
	}
	return report, nil
}

func (library *Library) PruneStorage(ctx context.Context, options StoragePruneOptions) (*StoragePruneReport, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	if !bool(C.provider_has_msb_storage_prune(library.table)) {
		return nil, &Error{Kind: KindUnsupportedOperation, Message: "native SDK does not support storage pruning; update the native SDK"}
	}
	payload, err := json.Marshal(options)
	if err != nil {
		return nil, err
	}
	cOptions := C.CString(string(payload))
	defer C.free(unsafe.Pointer(cOptions))
	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_storage_prune(library.table, cancelID, cOptions, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var report *StoragePruneReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		return nil, fmt.Errorf("parse storage prune: %w", err)
	}
	if report == nil {
		return nil, fmt.Errorf("native SDK returned no storage prune report")
	}
	return report, nil
}

func (library *Library) ImageLoad(ctx context.Context, inputPath string, tags []string) ([]*ImageHandleInfo, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	if tags == nil {
		tags = []string{}
	}
	tagsJSON, err := json.Marshal(tags)
	if err != nil {
		return nil, fmt.Errorf("encode tags: %w", err)
	}
	cPath := C.CString(inputPath)
	defer C.free(unsafe.Pointer(cPath))
	cTags := C.CString(string(tagsJSON))
	defer C.free(unsafe.Pointer(cTags))
	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_image_load(library.table, cancelID, cPath, cTags, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var infos []*ImageHandleInfo
	if err := json.Unmarshal([]byte(out), &infos); err != nil {
		return nil, fmt.Errorf("parse image_load: %w", err)
	}
	return infos, nil
}

func (library *Library) ImageSave(ctx context.Context, references []string, outputPath string, format string) error {
	if err := library.ensureLoaded(); err != nil {
		return err
	}
	if references == nil {
		references = []string{}
	}
	referencesJSON, err := json.Marshal(references)
	if err != nil {
		return fmt.Errorf("encode references: %w", err)
	}
	cRefs := C.CString(string(referencesJSON))
	defer C.free(unsafe.Pointer(cRefs))
	cPath := C.CString(outputPath)
	defer C.free(unsafe.Pointer(cPath))
	cFormat := C.CString(format)
	defer C.free(unsafe.Pointer(cFormat))
	_, err = library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_image_save(library.table, cancelID, cRefs, cPath, cFormat, buf, bufLen)
	})
	return err
}

func (library *Library) SandboxHandleSnapshot(ctx context.Context, sandboxName, snapshotName string) (*SnapshotInfo, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	// The convenience API uses disk Auto too; an old native library would silently
	// retain unflushed live capture semantics. Require the same capability as Create.
	if err := library.checkGuestFlush("", true); err != nil {
		return nil, err
	}
	cSandbox := C.CString(sandboxName)
	defer C.free(unsafe.Pointer(cSandbox))
	cSnapshot := C.CString(snapshotName)
	defer C.free(unsafe.Pointer(cSnapshot))
	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_handle_snapshot(library.table, cancelID, cSandbox, cSnapshot, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var info SnapshotInfo
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		return nil, fmt.Errorf("parse snapshot: %w", err)
	}
	return &info, nil
}

func (library *Library) SnapshotCreate(ctx context.Context, sourceSandbox string, opts SnapshotCreateOptions) (*SnapshotInfo, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	if err := library.checkGuestFlush(opts.GuestFlush, !opts.Full); err != nil {
		return nil, err
	}
	if bool(C.provider_has_msb_snapshot_artifact_receivers(library.table)) {
		// Capture once through the owned response; reopening by name afterward could
		// select a replacement, and retrying a legacy response could capture twice.
		raw, err := library.SnapshotObjectCall(ctx, 0, map[string]any{"op": "create_artifact", "source": sourceSandbox, "options": opts})
		if err != nil {
			return nil, err
		}
		var info SnapshotInfo
		if err := json.Unmarshal(raw, &info); err != nil {
			return nil, fmt.Errorf("parse retained checkpoint create: %w", err)
		}
		return &info, nil
	}
	payload, err := json.Marshal(opts)
	if err != nil {
		return nil, err
	}
	cSource := C.CString(sourceSandbox)
	defer C.free(unsafe.Pointer(cSource))
	cOpts := C.CString(string(payload))
	defer C.free(unsafe.Pointer(cOpts))
	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_snapshot_create(library.table, cancelID, cSource, cOpts, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var info SnapshotInfo
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		return nil, fmt.Errorf("parse snapshot create: %w", err)
	}
	return &info, nil
}

func (library *Library) SnapshotCreateArchive(ctx context.Context, sourceSandbox, archivePath string, opts SnapshotCreateOptions, plainTar bool) (*SnapshotArchiveInfo, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	if err := library.checkGuestFlush(opts.GuestFlush, !opts.Full); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(opts)
	if err != nil {
		return nil, err
	}
	cSource := C.CString(sourceSandbox)
	defer C.free(unsafe.Pointer(cSource))
	cArchive := C.CString(archivePath)
	defer C.free(unsafe.Pointer(cArchive))
	cOpts := C.CString(string(payload))
	defer C.free(unsafe.Pointer(cOpts))
	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_snapshot_create_archive(library.table, cancelID, cSource, cArchive, cOpts, C.bool(plainTar), buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var info SnapshotArchiveInfo
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		return nil, fmt.Errorf("parse direct snapshot archive: %w", err)
	}
	return &info, nil
}

func (library *Library) SnapshotOpen(ctx context.Context, reference, referenceKind string) (*SnapshotInfo, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	if bool(C.provider_has_msb_snapshot_objects(library.table)) {
		raw, err := library.SnapshotObjectCall(ctx, 0, map[string]any{"op": "open", "reference": reference, "reference_kind": referenceKind})
		if err != nil {
			return nil, err
		}
		var info SnapshotInfo
		if err := json.Unmarshal(raw, &info); err != nil {
			return nil, fmt.Errorf("parse retained checkpoint: %w", err)
		}
		return &info, nil
	}
	cReference := C.CString(reference)
	defer C.free(unsafe.Pointer(cReference))
	cReferenceKind := C.CString(referenceKind)
	defer C.free(unsafe.Pointer(cReferenceKind))
	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_snapshot_open(library.table, cancelID, cReference, cReferenceKind, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var info SnapshotInfo
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		return nil, fmt.Errorf("parse snapshot open: %w", err)
	}
	return &info, nil
}

func (library *Library) SnapshotVerify(ctx context.Context, reference, referenceKind string) (*SnapshotVerifyReport, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	cReference := C.CString(reference)
	defer C.free(unsafe.Pointer(cReference))
	cReferenceKind := C.CString(referenceKind)
	defer C.free(unsafe.Pointer(cReferenceKind))
	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_snapshot_verify(library.table, cancelID, cReference, cReferenceKind, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var report SnapshotVerifyReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		return nil, fmt.Errorf("parse snapshot verify: %w", err)
	}
	return &report, nil
}

func (library *Library) SnapshotGet(ctx context.Context, nameOrDigest string) (*SnapshotHandleInfo, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	cName := C.CString(nameOrDigest)
	defer C.free(unsafe.Pointer(cName))
	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_snapshot_get(library.table, cancelID, cName, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var info SnapshotHandleInfo
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		return nil, fmt.Errorf("parse snapshot get: %w", err)
	}
	return &info, nil
}

func (library *Library) SnapshotList(ctx context.Context) ([]*SnapshotHandleInfo, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_snapshot_list(library.table, cancelID, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var infos []*SnapshotHandleInfo
	if err := json.Unmarshal([]byte(out), &infos); err != nil {
		return nil, fmt.Errorf("parse snapshot list: %w", err)
	}
	return infos, nil
}

func (library *Library) SnapshotListDir(ctx context.Context, dir string) ([]*SnapshotInfo, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	if bool(C.provider_has_msb_snapshot_artifact_receivers(library.table)) {
		raw, err := library.SnapshotObjectCall(ctx, 0, map[string]any{"op": "list_dir", "directory": dir})
		if err != nil {
			return nil, err
		}
		var infos []*SnapshotInfo
		if err := json.Unmarshal(raw, &infos); err != nil {
			return nil, fmt.Errorf("parse retained checkpoint list: %w", err)
		}
		return infos, nil
	}
	cDir := C.CString(dir)
	defer C.free(unsafe.Pointer(cDir))
	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_snapshot_list_dir(library.table, cancelID, cDir, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var infos []*SnapshotInfo
	if err := json.Unmarshal([]byte(out), &infos); err != nil {
		return nil, fmt.Errorf("parse snapshot list dir: %w", err)
	}
	return infos, nil
}

func (library *Library) SnapshotRemove(ctx context.Context, reference, referenceKind string, force bool) error {
	if err := library.ensureLoaded(); err != nil {
		return err
	}
	cReference := C.CString(reference)
	defer C.free(unsafe.Pointer(cReference))
	cReferenceKind := C.CString(referenceKind)
	defer C.free(unsafe.Pointer(cReferenceKind))
	_, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_snapshot_remove(library.table, cancelID, cReference, cReferenceKind, C.bool(force), buf, bufLen)
	})
	return err
}

func (library *Library) SnapshotReindex(ctx context.Context, dir string) (uint32, error) {
	if err := library.ensureLoaded(); err != nil {
		return 0, err
	}
	cDir := C.CString(dir)
	defer C.free(unsafe.Pointer(cDir))
	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_snapshot_reindex(library.table, cancelID, cDir, buf, bufLen)
	})
	if err != nil {
		return 0, err
	}
	var raw struct {
		Indexed uint32 `json:"indexed"`
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return 0, fmt.Errorf("parse snapshot reindex: %w", err)
	}
	return raw.Indexed, nil
}

func (library *Library) SnapshotSave(ctx context.Context, reference, referenceKind, outPath string, opts SnapshotSaveOptions) error {
	if err := library.ensureLoaded(); err != nil {
		return err
	}
	payload, err := json.Marshal(opts)
	if err != nil {
		return err
	}
	cReference := C.CString(reference)
	defer C.free(unsafe.Pointer(cReference))
	cReferenceKind := C.CString(referenceKind)
	defer C.free(unsafe.Pointer(cReferenceKind))
	cOut := C.CString(outPath)
	defer C.free(unsafe.Pointer(cOut))
	cOpts := C.CString(string(payload))
	defer C.free(unsafe.Pointer(cOpts))
	_, err = library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_snapshot_export(library.table, cancelID, cReference, cReferenceKind, cOut, cOpts, buf, bufLen)
	})
	return err
}

func (library *Library) SnapshotCopy(ctx context.Context, reference, referenceKind, outputArchivePath string, opts SnapshotCopyOptions) error {
	if err := library.ensureLoaded(); err != nil {
		return err
	}
	payload, err := json.Marshal(opts)
	if err != nil {
		return err
	}
	cReference := C.CString(reference)
	defer C.free(unsafe.Pointer(cReference))
	cReferenceKind := C.CString(referenceKind)
	defer C.free(unsafe.Pointer(cReferenceKind))
	cOutputArchivePath := C.CString(outputArchivePath)
	defer C.free(unsafe.Pointer(cOutputArchivePath))
	cOpts := C.CString(string(payload))
	defer C.free(unsafe.Pointer(cOpts))
	_, err = library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_snapshot_copy(library.table, cancelID, cReference, cReferenceKind, cOutputArchivePath, cOpts, buf, bufLen)
	})
	return err
}

func (library *Library) SnapshotLoad(ctx context.Context, archive, dest string) (*SnapshotHandleInfo, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	cArchive := C.CString(archive)
	defer C.free(unsafe.Pointer(cArchive))
	cDest := C.CString(dest)
	defer C.free(unsafe.Pointer(cDest))
	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_snapshot_import(library.table, cancelID, cArchive, cDest, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var info SnapshotHandleInfo
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		return nil, fmt.Errorf("parse snapshot load: %w", err)
	}
	return &info, nil
}

func (library *Library) SnapshotLoadWithBase(ctx context.Context, archive, dest, base string) (*SnapshotHandleInfo, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	cArchive, cDest, cBase := C.CString(archive), C.CString(dest), C.CString(base)
	defer C.free(unsafe.Pointer(cArchive))
	defer C.free(unsafe.Pointer(cDest))
	defer C.free(unsafe.Pointer(cBase))
	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_snapshot_import_with_base(library.table, cancelID, cArchive, cDest, cBase, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var info SnapshotHandleInfo
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		return nil, err
	}
	return &info, nil
}

func (library *Library) SnapshotLoadWithOptions(ctx context.Context, archive string, opts SnapshotLoadOptions) (*SnapshotHandleInfo, error) {
	admission, err := json.Marshal(map[string]any{"op": "load", "options": opts})
	if err != nil {
		return nil, err
	}
	if err := library.requireImportBudget(admission); err != nil {
		return nil, err
	}
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(opts)
	if err != nil {
		return nil, err
	}
	cArchive, cOpts := C.CString(archive), C.CString(string(payload))
	defer C.free(unsafe.Pointer(cArchive))
	defer C.free(unsafe.Pointer(cOpts))
	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_snapshot_import_with_options(library.table, cancelID, cArchive, cOpts, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var info SnapshotHandleInfo
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		return nil, fmt.Errorf("parse snapshot load: %w", err)
	}
	return &info, nil
}

func (library *Library) SnapshotLoadMany(ctx context.Context, archives []string, opts SnapshotLoadOptions) ([]*SnapshotHandleInfo, error) {
	admission, err := json.Marshal(map[string]any{"op": "load", "options": opts})
	if err != nil {
		return nil, err
	}
	if err := library.requireImportBudget(admission); err != nil {
		return nil, err
	}
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	// A nil slice is an empty batch, not JSON null; the core validates empty batches.
	if archives == nil {
		archives = []string{}
	}
	archivePayload, err := json.Marshal(archives)
	if err != nil {
		return nil, err
	}
	optsPayload, err := json.Marshal(opts)
	if err != nil {
		return nil, err
	}
	cArchives, cOpts := C.CString(string(archivePayload)), C.CString(string(optsPayload))
	defer C.free(unsafe.Pointer(cArchives))
	defer C.free(unsafe.Pointer(cOpts))
	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_snapshot_import_many(library.table, cancelID, cArchives, cOpts, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var infos []*SnapshotHandleInfo
	if err := json.Unmarshal([]byte(out), &infos); err != nil {
		return nil, fmt.Errorf("parse snapshot batch load: %w", err)
	}
	return infos, nil
}

func (library *Library) SnapshotGroupHead(ctx context.Context, selector string) (*SnapshotHeadUpdate, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	cSelector := C.CString(selector)
	defer C.free(unsafe.Pointer(cSelector))
	out, err := library.call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_snapshot_group_head(library.table, cancelID, cSelector, buf, bufLen)
	})
	if err != nil {
		return nil, err
	}
	var update SnapshotHeadUpdate
	if err := json.Unmarshal([]byte(out), &update); err != nil {
		return nil, fmt.Errorf("parse snapshot group head: %w", err)
	}
	return &update, nil
}

func (library *Library) RuntimeSetup(ctx context.Context, operation, configJSON, optionsJSON string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := library.ensureLoaded(); err != nil {
		return "", err
	}
	if !bool(C.provider_has_msb_runtime_setup(library.table)) {
		return "", fmt.Errorf("loaded native SDK does not support runtime setup; rebuild the SDK library")
	}
	op, config, options := C.CString(operation), C.CString(configJSON), C.CString(optionsJSON)
	defer C.free(unsafe.Pointer(op))
	defer C.free(unsafe.Pointer(config))
	defer C.free(unsafe.Pointer(options))
	return runtimeSetupOutput(ctx, operation, func(size int) (string, error) {
		return library.callBuf(ctx, size, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
			return C.provider_call_msb_runtime_setup(library.table, cancelID, op, config, options, buf, bufLen)
		})
	})
}

func (library *Library) Jobs(ctx context.Context, sandbox uint64, request any) (json.RawMessage, error) {
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	if C.provider_has_msb_jobs(library.table) == 0 {
		return nil, &Error{Kind: "unsupported_feature", Message: "native SDK bundle does not support managed jobs"}
	}
	data, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	arg := C.CString(string(data))
	defer C.free(unsafe.Pointer(arg))
	raw, err := library.callBuf(ctx, 4<<20, func(cancelID C.uint64_t, buf *C.uint8_t, length C.size_t) *C.char {
		return C.provider_call_msb_jobs(library.table, cancelID, C.uint64_t(sandbox), arg, buf, length)
	})
	return json.RawMessage(raw), err
}

func (library *Library) RequirePortModification() error {
	if err := library.ensureLoaded(); err != nil {
		return err
	}
	if !bool(C.provider_has_port_modification(library.table)) {
		return fmt.Errorf("published-port modification requires an updated native library")
	}
	return nil
}

// SnapshotObjectCall refuses old native libraries before dispatch. Receiver handles
// carry their original backend; a caller must not reconstruct them from names.
// SnapshotGroupOpen selects native support before sending the new read operation.
func SnapshotGroupOpen(ctx context.Context, directory string) ([]byte, error) {
	if err := ensureLoaded(); err != nil {
		return nil, err
	}
	if !bool(C.has_msb_snapshot_group_paths()) {
		return nil, &Error{Kind: KindUnsupportedOperation, Message: "native SDK does not support opening snapshot group paths; update the native SDK"}
	}
	return SnapshotObjectCall(ctx, 0, map[string]any{"op": "open_group", "directory": directory})
}

func SnapshotObjectCall(ctx context.Context, handle uint64, request any) ([]byte, error) {
	return defaultLibrary().SnapshotObjectCall(ctx, handle, request)
}

// requireImportBudget prevents an older provider from silently ignoring a requested limit.
func (library *Library) requireImportBudget(payload []byte) error {
	var request struct {
		Operation string          `json:"operation"`
		Op        string          `json:"op"`
		Request   json.RawMessage `json:"request"`
		Options   json.RawMessage `json:"options"`
		Args      struct {
			Options json.RawMessage `json:"options"`
		} `json:"args"`
	}
	if err := json.Unmarshal(payload, &request); err != nil {
		return err
	}
	if len(request.Request) != 0 {
		return library.requireImportBudget(request.Request)
	}
	var options SnapshotLoadOptions
	switch {
	case request.Operation == "snapshot_load":
		if len(request.Args.Options) == 0 {
			return nil
		}
		if err := json.Unmarshal(request.Args.Options, &options); err != nil {
			return err
		}
	case request.Op == "load":
		if len(request.Options) == 0 {
			return nil
		}
		if err := json.Unmarshal(request.Options, &options); err != nil {
			return err
		}
	default:
		return nil
	}
	if options.MaximumDiskBytes == nil {
		return nil
	}
	if err := library.ensureLoaded(); err != nil {
		return err
	}
	if !bool(C.provider_has_snapshot_import_budget(library.table)) {
		return &Error{Kind: KindUnsupportedOperation, Message: "snapshot import size limits require an updated native SDK"}
	}
	return nil
}

func (library *Library) requireContextSnapshotObjects() error {
	if err := library.ensureLoaded(); err != nil {
		return err
	}
	if !bool(C.provider_has_context_snapshot_objects(library.table)) {
		return &Error{Kind: KindUnsupportedOperation, Message: "snapshot history operations require an updated provider library"}
	}
	return nil
}

func (library *Library) SnapshotObjectCall(ctx context.Context, handle uint64, request any) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := library.ensureLoaded(); err != nil {
		return nil, err
	}
	if !bool(C.provider_has_msb_snapshot_objects(library.table)) {
		return nil, &Error{Kind: KindUnsupportedOperation, Message: "native SDK does not support snapshot group receivers; update the native SDK"}
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	if err := library.requireImportBudget(payload); err != nil {
		return nil, err
	}
	text := C.CString(string(payload))
	defer C.free(unsafe.Pointer(text))
	if bool(C.provider_has_msb_snapshot_object_owned(library.table)) {
		return library.snapshotObjectOwned(ctx, handle, text)
	}
	// Retain the old ABI for earlier native bundles. Never replay mutations on buffer errors.
	// Unlike metadata-only calls, a successful result transfers native ownership.
	// Cancellation racing a completed call must not discard those object handles.
	buf := make([]byte, defaultBufSize)
	cancelID := C.provider_call_msb_cancel_alloc(library.table)
	done := make(chan *C.char, 1)
	go func() {
		done <- C.provider_call_msb_snapshot_object(library.table, cancelID, C.uint64_t(handle), text, (*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	}()
	var failure *C.char
	select {
	case failure = <-done:
	case <-ctx.Done():
		C.provider_call_msb_cancel_trigger(library.table, cancelID)
		failure = <-done // native code must release the borrowed input before C.free
	}
	if failure != nil {
		err := library.errorFromPtr(failure)
		if native, ok := err.(*Error); ok && native.Kind == KindCancelled && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	end := 0
	for end < len(buf) && buf[end] != 0 {
		end++
	}
	return buf[:end], nil
}

// Successful completion wins a cancellation race: the response owns native receivers
// and may describe an already committed mutation. Always join before freeing input/slots.
func (library *Library) snapshotObjectOwned(ctx context.Context, handle uint64, text *C.char) ([]byte, error) {
	out, length, cleanup := allocRustBytesOut()
	defer cleanup()
	defer library.freeRustBytes(out, length)
	cancelID := C.provider_call_msb_cancel_alloc(library.table)
	done := make(chan *C.char, 1)
	go func() {
		done <- C.provider_call_msb_snapshot_object_owned(library.table, cancelID, C.uint64_t(handle), text, out, length)
	}()
	var failure *C.char
	select {
	case failure = <-done:
	case <-ctx.Done():
		C.provider_call_msb_cancel_trigger(library.table, cancelID)
		failure = <-done
	}
	if failure != nil {
		err := library.errorFromPtr(failure)
		if native, ok := err.(*Error); ok && native.Kind == KindCancelled && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	// Move ownership before copying, so a panicking copy cannot free the allocation twice.
	ptr, size := *out, *length
	*out, *length = nil, 0
	return library.takeRustBytes(ptr, size), nil
}

func (library *Library) releaseSnapshotObject(handle uint64) {
	C.provider_call_msb_snapshot_object_close(library.table, C.uint64_t(handle))
}

// CheckArchiveCompatibility requires explicit acknowledgement before serializing a new option.
// Old native JSON decoders can ignore unknown fields, so sending the option alone is unsafe.
func CheckArchiveCompatibility(ctx context.Context, target string) error {
	if target == "" {
		return nil
	}
	raw, err := SnapshotObjectCall(ctx, 0, map[string]any{"op": "archive_compatibility"})
	if err != nil {
		return fmt.Errorf("archive compatibility requires an updated native library: %w", err)
	}
	var targets []string
	if err := json.Unmarshal(raw, &targets); err != nil {
		return err
	}
	for _, supported := range targets {
		if supported == target {
			return nil
		}
	}
	return fmt.Errorf("unsupported archive compatibility target %q", target)
}

func (library *Library) RequireSecretPolicyModification() error {
	if err := library.ensureLoaded(); err != nil {
		return err
	}
	if !bool(C.provider_has_secret_policy_modification(library.table)) {
		return fmt.Errorf("secret policy modification requires an updated native library")
	}
	return nil
}

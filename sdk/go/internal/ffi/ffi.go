// Package ffi is the CGO bridge from the Go SDK to the microsandbox Rust
// library. It is NOT stable and must not be imported from outside this module.
//
// Build prerequisite: the Rust staticlib must be built first:
//
//	cargo build -p microsandbox-go-ffi
//
// By default the linker looks for libmicrosandbox_go_ffi in
// ../../../../target/debug relative to this file. Override via CGO_LDFLAGS
// when linking against a release build or a custom location.
//
// # Boundary contract
//
// Every msb_* call returns:
//   - NULL on success, and writes a JSON document into the caller's buffer.
//   - A heap-allocated C string (JSON error payload) on failure. Go MUST free
//     that string with C.msb_free_string.
//
// Sandboxes are identified across the boundary by opaque uint64 handles
// allocated by the Rust side. Call (*Sandbox).Close to release.
//
// # Thread safety
//
// All msb_* entry points are safe to call from multiple Go goroutines
// concurrently. The Rust side uses an RwLock-protected handle registry and
// a multi-threaded Tokio runtime.
package ffi

/*
#cgo LDFLAGS: -L${SRCDIR}/../../../../target/debug -lmicrosandbox_go_ffi -ldl -lm
#include <stdlib.h>
#include <stdint.h>

void  msb_free_string(char *ptr);

char *msb_sandbox_create(const char *name, const char *opts_json, uint8_t *buf, size_t buf_len);
char *msb_sandbox_get(const char *name, uint8_t *buf, size_t buf_len);
char *msb_sandbox_close(uint64_t handle, uint8_t *buf, size_t buf_len);
char *msb_sandbox_stop(uint64_t handle, uint8_t *buf, size_t buf_len);
char *msb_sandbox_stop_and_wait(uint64_t handle, uint8_t *buf, size_t buf_len);
char *msb_sandbox_kill(uint64_t handle, uint8_t *buf, size_t buf_len);
char *msb_sandbox_list(uint8_t *buf, size_t buf_len);
char *msb_sandbox_remove(const char *name, uint8_t *buf, size_t buf_len);
char *msb_sandbox_exec(uint64_t handle, const char *cmd, const char *exec_opts_json, uint8_t *buf, size_t buf_len);
char *msb_sandbox_metrics(uint64_t handle, uint8_t *buf, size_t buf_len);

char *msb_fs_read(uint64_t handle, const char *path, uint8_t *buf, size_t buf_len);
char *msb_fs_write(uint64_t handle, const char *path, const char *data_b64, uint8_t *buf, size_t buf_len);
char *msb_fs_list(uint64_t handle, const char *path, uint8_t *buf, size_t buf_len);
char *msb_fs_stat(uint64_t handle, const char *path, uint8_t *buf, size_t buf_len);
char *msb_fs_copy_from_host(uint64_t handle, const char *host_path, const char *guest_path, uint8_t *buf, size_t buf_len);
char *msb_fs_copy_to_host(uint64_t handle, const char *guest_path, const char *host_path, uint8_t *buf, size_t buf_len);

char *msb_volume_create(const char *name, uint32_t quota_mib, uint8_t *buf, size_t buf_len);
char *msb_volume_remove(const char *name, uint8_t *buf, size_t buf_len);
char *msb_volume_list(uint8_t *buf, size_t buf_len);
*/
import "C"

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
	"unsafe"
)

// defaultBufSize is the output buffer allocated for each FFI call. 1 MiB is
// comfortable for JSON metadata and small file reads. FSRead on files larger
// than this returns KindBufferTooSmall; callers must stream instead.
const defaultBufSize = 1 << 20

// Error is the typed error surfaced across the FFI boundary. The Rust side
// serializes a {kind, message} JSON payload and this package unmarshals it.
// The public SDK maps Kind back into microsandbox.ErrorKind.
type Error struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Message }

// Error kind strings. Keep in sync with sdk/go-ffi/src/lib.rs::error_kind.
const (
	KindSandboxNotFound      = "sandbox_not_found"
	KindSandboxStillRunning  = "sandbox_still_running"
	KindVolumeNotFound       = "volume_not_found"
	KindVolumeAlreadyExists  = "volume_already_exists"
	KindExecTimeout          = "exec_timeout"
	KindInvalidConfig        = "invalid_config"
	KindInvalidArgument      = "invalid_argument"
	KindInvalidHandle        = "invalid_handle"
	KindBufferTooSmall       = "buffer_too_small"
	KindInternal             = "internal"
)

// Sandbox is an opaque, Rust-owned sandbox reference. Call Close to release.
// Sandbox is safe to use from multiple goroutines concurrently.
type Sandbox struct {
	handle C.uint64_t
	name   string
}

// Handle returns the underlying Rust handle. Exposed only for testing and
// debugging; the public SDK does not surface it.
func (s *Sandbox) Handle() uint64 { return uint64(s.handle) }

// Name returns the sandbox name as provided at creation time.
func (s *Sandbox) Name() string { return s.name }

// call invokes fn with a fresh 1 MiB buffer, selects on ctx.Done while the
// CGO call runs on a helper goroutine, and returns the null-terminated
// buffer contents on success or the parsed FFI error on failure.
//
// # Cancellation semantics
//
// If ctx is cancelled while the Rust side is still working, call returns
// ctx.Err() immediately. The Rust work continues to completion on a Tokio
// worker thread — callers MUST assume side effects may still land. We do
// not currently propagate cancellation into Rust; that requires a per-call
// cancellation token, which is a follow-up.
func call(ctx context.Context, fn func(buf *C.uint8_t, bufLen C.size_t) *C.char) (string, error) {
	type res struct {
		out string
		err error
	}
	done := make(chan res, 1)
	buf := make([]byte, defaultBufSize)

	go func() {
		errPtr := fn((*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
		if errPtr != nil {
			msg := C.GoString(errPtr)
			C.msb_free_string(errPtr)
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
		return "", ctx.Err()
	}
}

// =============================================================================
// Sandbox lifecycle
// =============================================================================

// CreateOptions mirrors the JSON schema expected by msb_sandbox_create.
// Zero-valued fields are omitted from the request (the Rust side applies
// its own defaults).
type CreateOptions struct {
	Image     string            `json:"image,omitempty"`
	MemoryMiB uint32            `json:"memory_mib,omitempty"`
	CPUs      uint8             `json:"cpus,omitempty"`
	Workdir   string            `json:"workdir,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
}

// CreateSandbox creates and boots a sandbox, returning a handle the caller
// must Close when done.
//
// Ownership of cName and cOpts is Go's (allocated via C.CString). They are
// borrowed by Rust only for the duration of the call; Rust copies the
// strings it needs before returning.
func CreateSandbox(ctx context.Context, name string, opts CreateOptions) (*Sandbox, error) {
	optsJSON, err := json.Marshal(opts)
	if err != nil {
		return nil, fmt.Errorf("marshal opts: %w", err)
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	cOpts := C.CString(string(optsJSON))
	defer C.free(unsafe.Pointer(cOpts))

	out, err := call(ctx, func(buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.msb_sandbox_create(cName, cOpts, buf, bufLen)
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

// GetSandbox reattaches to an existing sandbox by name, returning a new
// handle. Returns an Error with Kind==KindSandboxNotFound if absent.
func GetSandbox(ctx context.Context, name string) (*Sandbox, error) {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	out, err := call(ctx, func(buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.msb_sandbox_get(cName, buf, bufLen)
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
// call multiple times — the second call returns KindInvalidHandle.
// Close uses context.Background because it must not fail on ctx cancel
// (resources would leak). Callers who need a timeout should use CloseCtx.
func (s *Sandbox) Close() error {
	return s.CloseCtx(context.Background())
}

// CloseCtx is Close with a caller-controlled context.
func (s *Sandbox) CloseCtx(ctx context.Context) error {
	_, err := call(ctx, func(buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.msb_sandbox_close(s.handle, buf, bufLen)
	})
	return err
}

// Stop gracefully stops the sandbox without waiting for exit.
func (s *Sandbox) Stop(ctx context.Context) error {
	_, err := call(ctx, func(buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.msb_sandbox_stop(s.handle, buf, bufLen)
	})
	return err
}

// StopAndWait stops the sandbox and waits for its process to exit. The
// returned int is the exit code, or -1 if unknown (e.g. killed by signal
// with no code reported).
func (s *Sandbox) StopAndWait(ctx context.Context) (int, error) {
	out, err := call(ctx, func(buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.msb_sandbox_stop_and_wait(s.handle, buf, bufLen)
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
	_, err := call(ctx, func(buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.msb_sandbox_kill(s.handle, buf, bufLen)
	})
	return err
}

// ListSandboxes returns the names of all known sandboxes (running or not).
func ListSandboxes(ctx context.Context) ([]string, error) {
	out, err := call(ctx, func(buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.msb_sandbox_list(buf, bufLen)
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
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	_, err := call(ctx, func(buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.msb_sandbox_remove(cName, buf, bufLen)
	})
	return err
}

// =============================================================================
// Exec
// =============================================================================

// ExecOptions configures a command execution.
type ExecOptions struct {
	Args        []string `json:"args,omitempty"`
	Cwd         string   `json:"cwd,omitempty"`
	TimeoutSecs uint64   `json:"timeout_secs,omitempty"`
}

// ExecResult is the output of a completed exec.
type ExecResult struct {
	Stdout   string
	Stderr   string
	ExitCode int // -1 if the guest did not return a code.
}

// Exec runs cmd in the sandbox and collects its output.
func (s *Sandbox) Exec(ctx context.Context, cmd string, opts ExecOptions) (*ExecResult, error) {
	optsJSON, err := json.Marshal(opts)
	if err != nil {
		return nil, fmt.Errorf("marshal exec opts: %w", err)
	}
	cCmd := C.CString(cmd)
	defer C.free(unsafe.Pointer(cCmd))
	cOpts := C.CString(string(optsJSON))
	defer C.free(unsafe.Pointer(cOpts))

	out, err := call(ctx, func(buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.msb_sandbox_exec(s.handle, cCmd, cOpts, buf, bufLen)
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
// Metrics
// =============================================================================

// Metrics is the resource-usage snapshot reported by the Rust side.
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

// Metrics fetches a snapshot of this sandbox's resource usage.
func (s *Sandbox) Metrics(ctx context.Context) (*Metrics, error) {
	out, err := call(ctx, func(buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.msb_sandbox_metrics(s.handle, buf, bufLen)
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

// FsStat is file metadata.
type FsStat struct {
	Kind         string `json:"kind"`
	Size         int64  `json:"size"`
	Mode         uint32 `json:"mode"`
	Readonly     bool   `json:"readonly"`
	ModifiedUnix *int64 `json:"modified_unix"`
}

// IsDir reports whether the entry is a directory.
func (s *FsStat) IsDir() bool { return s.Kind == "dir" }

// ModTime converts the Unix modified timestamp into a time.Time, or the zero
// value if the guest did not report a modified time.
func (s *FsStat) ModTime() time.Time {
	if s.ModifiedUnix == nil {
		return time.Time{}
	}
	return time.Unix(*s.ModifiedUnix, 0)
}

// FsRead reads a file from the sandbox. Files larger than ~750 KiB may
// exceed the FFI buffer and return KindBufferTooSmall; use streaming for
// those (not yet implemented at the FFI layer).
func (s *Sandbox) FsRead(ctx context.Context, path string) ([]byte, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	out, err := call(ctx, func(buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.msb_fs_read(s.handle, cPath, buf, bufLen)
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
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	cData := C.CString(base64.StdEncoding.EncodeToString(data))
	defer C.free(unsafe.Pointer(cData))

	_, err := call(ctx, func(buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.msb_fs_write(s.handle, cPath, cData, buf, bufLen)
	})
	return err
}

// FsList lists the entries in a directory.
func (s *Sandbox) FsList(ctx context.Context, path string) ([]FsEntry, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	out, err := call(ctx, func(buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.msb_fs_list(s.handle, cPath, buf, bufLen)
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
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	out, err := call(ctx, func(buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.msb_fs_stat(s.handle, cPath, buf, bufLen)
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
	cHost := C.CString(hostPath)
	defer C.free(unsafe.Pointer(cHost))
	cGuest := C.CString(guestPath)
	defer C.free(unsafe.Pointer(cGuest))

	_, err := call(ctx, func(buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.msb_fs_copy_from_host(s.handle, cHost, cGuest, buf, bufLen)
	})
	return err
}

// FsCopyToHost copies a sandbox file to the host.
func (s *Sandbox) FsCopyToHost(ctx context.Context, guestPath, hostPath string) error {
	cGuest := C.CString(guestPath)
	defer C.free(unsafe.Pointer(cGuest))
	cHost := C.CString(hostPath)
	defer C.free(unsafe.Pointer(cHost))

	_, err := call(ctx, func(buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.msb_fs_copy_to_host(s.handle, cGuest, cHost, buf, bufLen)
	})
	return err
}

// =============================================================================
// Volumes
// =============================================================================

// CreateVolume creates a named persistent volume. quotaMiB == 0 means
// unlimited.
func CreateVolume(ctx context.Context, name string, quotaMiB uint32) error {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	_, err := call(ctx, func(buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.msb_volume_create(cName, C.uint32_t(quotaMiB), buf, bufLen)
	})
	return err
}

// RemoveVolume removes a named volume.
func RemoveVolume(ctx context.Context, name string) error {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	_, err := call(ctx, func(buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.msb_volume_remove(cName, buf, bufLen)
	})
	return err
}

// ListVolumes returns the names of all volumes.
func ListVolumes(ctx context.Context) ([]string, error) {
	out, err := call(ctx, func(buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.msb_volume_list(buf, bufLen)
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

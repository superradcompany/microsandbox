package microsandbox

import (
	"errors"
	"fmt"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// ErrorKind identifies the specific type of microsandbox error.
type ErrorKind int

const (
	// ErrUnknown is the fallback when the Rust side reports a kind this
	// version of the SDK does not recognize.
	ErrUnknown ErrorKind = iota

	// ErrSandboxNotFound indicates the requested sandbox does not exist.
	ErrSandboxNotFound

	// ErrSandboxStillRunning indicates a sandbox cannot be removed while
	// it is still running.
	ErrSandboxStillRunning

	// ErrVolumeNotFound indicates the requested volume does not exist.
	ErrVolumeNotFound

	// ErrVolumeAlreadyExists indicates a volume with the given name
	// already exists.
	ErrVolumeAlreadyExists

	// ErrExecTimeout indicates a command execution exceeded its timeout.
	ErrExecTimeout

	// ErrInvalidConfig indicates the sandbox or volume configuration was
	// rejected by the runtime.
	ErrInvalidConfig

	// ErrInvalidArgument indicates a malformed argument was passed across
	// the FFI boundary (typically an SDK bug or a caller passing bad JSON).
	ErrInvalidArgument

	// ErrInvalidHandle indicates the sandbox handle is stale, closed, or
	// was never valid.
	ErrInvalidHandle

	// ErrBufferTooSmall indicates the FFI response exceeded the fixed
	// output buffer. For file reads, stream instead.
	ErrBufferTooSmall

	// ErrCancelled indicates the operation was cancelled by the caller's
	// context before the Rust runtime completed it.
	ErrCancelled

	// ErrInternal is every other error from the runtime.
	ErrInternal
)

func (k ErrorKind) String() string {
	switch k {
	case ErrSandboxNotFound:
		return "SandboxNotFound"
	case ErrSandboxStillRunning:
		return "SandboxStillRunning"
	case ErrVolumeNotFound:
		return "VolumeNotFound"
	case ErrVolumeAlreadyExists:
		return "VolumeAlreadyExists"
	case ErrExecTimeout:
		return "ExecTimeout"
	case ErrInvalidConfig:
		return "InvalidConfig"
	case ErrInvalidArgument:
		return "InvalidArgument"
	case ErrInvalidHandle:
		return "InvalidHandle"
	case ErrBufferTooSmall:
		return "BufferTooSmall"
	case ErrCancelled:
		return "Cancelled"
	case ErrInternal:
		return "Internal"
	default:
		return "Unknown"
	}
}

// Error is the standard error type returned by microsandbox operations.
// Use errors.As to extract detailed information.
type Error struct {
	Kind    ErrorKind
	Message string
	Cause   error
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("microsandbox.%s: %s: %v", e.Kind, e.Message, e.Cause)
	}
	return fmt.Sprintf("microsandbox.%s: %s", e.Kind, e.Message)
}

// Unwrap supports errors.Is / errors.As.
func (e *Error) Unwrap() error { return e.Cause }

// IsKind reports whether err (or any wrapped error) is a microsandbox.Error
// with the given kind.
func IsKind(err error, kind ErrorKind) bool {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind == kind
	}
	return false
}

// wrapFFI converts an error returned by the internal/ffi package into a
// typed *microsandbox.Error. Non-ffi errors (e.g. context cancellation,
// JSON parsing) are wrapped with ErrInternal. Returns nil for a nil err.
func wrapFFI(err error) error {
	if err == nil {
		return nil
	}
	var fe *ffi.Error
	if errors.As(err, &fe) {
		return &Error{Kind: kindFromFFI(fe.Kind), Message: fe.Message}
	}
	return &Error{Kind: ErrInternal, Message: err.Error(), Cause: err}
}

func kindFromFFI(kind string) ErrorKind {
	switch kind {
	case ffi.KindSandboxNotFound:
		return ErrSandboxNotFound
	case ffi.KindSandboxStillRunning:
		return ErrSandboxStillRunning
	case ffi.KindVolumeNotFound:
		return ErrVolumeNotFound
	case ffi.KindVolumeAlreadyExists:
		return ErrVolumeAlreadyExists
	case ffi.KindExecTimeout:
		return ErrExecTimeout
	case ffi.KindInvalidConfig:
		return ErrInvalidConfig
	case ffi.KindInvalidArgument:
		return ErrInvalidArgument
	case ffi.KindInvalidHandle:
		return ErrInvalidHandle
	case ffi.KindBufferTooSmall:
		return ErrBufferTooSmall
	case ffi.KindCancelled:
		return ErrCancelled
	default:
		return ErrInternal
	}
}

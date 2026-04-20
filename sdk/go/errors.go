package microsandbox

import (
	"context"
	"errors"
	"fmt"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// ErrorKind identifies the specific type of microsandbox error.
//
// The set of kinds is aligned with the Node.js and Python SDKs so that
// portable code written against one SDK compiles against another. Some
// kinds are reserved for error paths that the current Rust runtime does
// not yet emit; switch statements should include a default case.
type ErrorKind int

const (
	// ErrUnknown is the fallback when the Rust side reports a kind this
	// version of the SDK does not recognize.
	ErrUnknown ErrorKind = iota

	// ErrSandboxNotFound indicates the requested sandbox does not exist.
	ErrSandboxNotFound

	// ErrSandboxNotRunning indicates the sandbox exists but is not running.
	// Reserved for future use; currently surfaces as ErrInternal.
	ErrSandboxNotRunning

	// ErrSandboxAlreadyExists indicates a sandbox with the given name
	// already exists. Reserved for future use; currently surfaces as
	// ErrInvalidConfig.
	ErrSandboxAlreadyExists

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

	// ErrExecFailed indicates a command failed for a reason other than a
	// timeout or non-zero exit (e.g. the guest agent dropped the request).
	// Reserved for future use; currently surfaces as ErrInternal.
	ErrExecFailed

	// ErrFilesystem indicates a filesystem operation inside the sandbox
	// failed (e.g. read/write/list returned an error from the guest).
	ErrFilesystem

	// ErrPathNotFound indicates a sandbox filesystem path does not exist.
	// Reserved for future use; currently surfaces as ErrFilesystem.
	ErrPathNotFound

	// ErrImageNotFound indicates the OCI image reference could not be
	// resolved.
	ErrImageNotFound

	// ErrImageInUse indicates the image cannot be removed because one or
	// more sandboxes are still referencing it.
	ErrImageInUse

	// ErrImagePullFailed indicates an image pull failed after resolution
	// succeeded. Reserved for future use; currently surfaces as
	// ErrImageNotFound.
	ErrImagePullFailed

	// ErrPatchFailed indicates a rootfs patch could not be applied before
	// the VM booted.
	ErrPatchFailed

	// ErrNetworkPolicy indicates a network policy configuration or
	// runtime violation. Reserved for future use; currently surfaces as
	// ErrInvalidConfig.
	ErrNetworkPolicy

	// ErrSecretViolation indicates a secret was sent to a disallowed host.
	// Reserved for future use; currently surfaces as ErrInternal.
	ErrSecretViolation

	// ErrTLS indicates a TLS interception error. Reserved for future use;
	// currently surfaces as ErrInternal.
	ErrTLS

	// ErrIO indicates a host-side I/O error.
	ErrIO

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

	// ErrLibraryNotLoaded indicates the microsandbox library has not been
	// loaded. Call EnsureInstalled() before using any SDK functions.
	ErrLibraryNotLoaded

	// ErrInternal is every other error from the runtime.
	ErrInternal
)

func (k ErrorKind) String() string {
	switch k {
	case ErrSandboxNotFound:
		return "SandboxNotFound"
	case ErrSandboxNotRunning:
		return "SandboxNotRunning"
	case ErrSandboxAlreadyExists:
		return "SandboxAlreadyExists"
	case ErrSandboxStillRunning:
		return "SandboxStillRunning"
	case ErrVolumeNotFound:
		return "VolumeNotFound"
	case ErrVolumeAlreadyExists:
		return "VolumeAlreadyExists"
	case ErrExecTimeout:
		return "ExecTimeout"
	case ErrExecFailed:
		return "ExecFailed"
	case ErrFilesystem:
		return "Filesystem"
	case ErrPathNotFound:
		return "PathNotFound"
	case ErrImageNotFound:
		return "ImageNotFound"
	case ErrImageInUse:
		return "ImageInUse"
	case ErrImagePullFailed:
		return "ImagePullFailed"
	case ErrPatchFailed:
		return "PatchFailed"
	case ErrNetworkPolicy:
		return "NetworkPolicy"
	case ErrSecretViolation:
		return "SecretViolation"
	case ErrTLS:
		return "TLS"
	case ErrIO:
		return "IO"
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
	case ErrLibraryNotLoaded:
		return "LibraryNotLoaded"
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
//
// The string form deliberately omits the Kind to avoid duplicating the
// category when the underlying message already describes it (e.g. a
// sandbox-not-found kind paired with the runtime message "sandbox not
// found: foo"). Callers that need to branch on the category should use
// IsKind or errors.As against *Error — Kind is still preserved on the
// struct.
func (e *Error) Error() string {
	switch {
	case e.Message == "" && e.Cause != nil:
		return e.Cause.Error()
	case e.Cause != nil:
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	case e.Message == "":
		return e.Kind.String()
	default:
		return e.Message
	}
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
// typed *microsandbox.Error. context.Canceled and context.DeadlineExceeded
// map to ErrCancelled (preserving the original via Cause); other non-ffi
// errors surface as ErrInternal. Returns nil for a nil err.
func wrapFFI(err error) error {
	if err == nil {
		return nil
	}
	var fe *ffi.Error
	if errors.As(err, &fe) {
		return &Error{Kind: kindFromFFI(fe.Kind), Message: fe.Message}
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return &Error{Kind: ErrCancelled, Message: err.Error(), Cause: err}
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
	case ffi.KindFilesystem:
		return ErrFilesystem
	case ffi.KindImageNotFound:
		return ErrImageNotFound
	case ffi.KindImageInUse:
		return ErrImageInUse
	case ffi.KindPatchFailed:
		return ErrPatchFailed
	case ffi.KindIO:
		return ErrIO
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
	case ffi.KindLibraryNotLoaded:
		return ErrLibraryNotLoaded
	default:
		return ErrInternal
	}
}

package microsandbox

import (
	"errors"
	"fmt"
)

// ErrorKind identifies the specific type of microsandbox error.
type ErrorKind int

const (
	// ErrUnknown is the default error kind when no specific type matches.
	ErrUnknown ErrorKind = iota

	// ErrSandboxNotFound indicates the requested sandbox does not exist.
	ErrSandboxNotFound

	// ErrSandboxAlreadyExists indicates a sandbox with the given name already exists.
	ErrSandboxAlreadyExists

	// ErrExecTimeout indicates an execution exceeded its timeout.
	ErrExecTimeout

	// ErrExecFailed indicates a command execution failed (non-zero exit).
	ErrExecFailed

	// ErrVolumeNotFound indicates the requested volume does not exist.
	ErrVolumeNotFound

	// ErrVolumeAlreadyExists indicates a volume with the given name already exists.
	ErrVolumeAlreadyExists

	// ErrNetworkDenied indicates a network request was blocked by policy.
	ErrNetworkDenied

	// ErrSecretNotFound indicates a requested secret was not found.
	ErrSecretNotFound

	// ErrInvalidConfig indicates invalid configuration options were provided.
	ErrInvalidConfig

	// ErrResourceExhausted indicates insufficient resources (memory, CPU, disk).
	ErrResourceExhausted

	// ErrPermissionDenied indicates insufficient permissions for the operation.
	ErrPermissionDenied

	// ErrInternal indicates an internal SDK or microsandbox error.
	ErrInternal
)

func (k ErrorKind) String() string {
	switch k {
	case ErrUnknown:
		return "Unknown"
	case ErrSandboxNotFound:
		return "SandboxNotFound"
	case ErrSandboxAlreadyExists:
		return "SandboxAlreadyExists"
	case ErrExecTimeout:
		return "ExecTimeout"
	case ErrExecFailed:
		return "ExecFailed"
	case ErrVolumeNotFound:
		return "VolumeNotFound"
	case ErrVolumeAlreadyExists:
		return "VolumeAlreadyExists"
	case ErrNetworkDenied:
		return "NetworkDenied"
	case ErrSecretNotFound:
		return "SecretNotFound"
	case ErrInvalidConfig:
		return "InvalidConfig"
	case ErrResourceExhausted:
		return "ResourceExhausted"
	case ErrPermissionDenied:
		return "PermissionDenied"
	case ErrInternal:
		return "Internal"
	default:
		return fmt.Sprintf("Unknown(%d)", k)
	}
}

// Error is the standard error type returned by microsandbox operations.
// Use errors.As() to extract detailed error information.
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

// Unwrap returns the underlying cause, enabling errors.Is() and errors.As().
func (e *Error) Unwrap() error {
	return e.Cause
}

// NewError creates a new microsandbox Error with the given kind and message.
func NewError(kind ErrorKind, message string) *Error {
	return &Error{
		Kind:    kind,
		Message: message,
	}
}

// NewErrorf creates a new microsandbox Error with formatted message.
func NewErrorf(kind ErrorKind, format string, args ...interface{}) *Error {
	return &Error{
		Kind:    kind,
		Message: fmt.Sprintf(format, args...),
	}
}

// WrapError wraps an existing error with a microsandbox error kind.
func WrapError(kind ErrorKind, cause error, message string) *Error {
	return &Error{
		Kind:    kind,
		Message: message,
		Cause:   cause,
	}
}

// WrapErrorf wraps an existing error with a formatted message.
func WrapErrorf(kind ErrorKind, cause error, format string, args ...interface{}) *Error {
	return &Error{
		Kind:    kind,
		Message: fmt.Sprintf(format, args...),
		Cause:   cause,
	}
}

// IsSandboxNotFound returns true if the error indicates a sandbox was not found.
func IsSandboxNotFound(err error) bool {
	return IsKind(err, ErrSandboxNotFound)
}

// IsExecTimeout returns true if the error indicates an execution timeout.
func IsExecTimeout(err error) bool {
	return IsKind(err, ErrExecTimeout)
}

// IsExecFailed returns true if the error indicates a command execution failed.
func IsExecFailed(err error) bool {
	return IsKind(err, ErrExecFailed)
}

// IsKind checks if the error (or any wrapped error) matches the given kind.
func IsKind(err error, kind ErrorKind) bool {
	if err == nil {
		return false
	}
	var msbErr *Error
	if errors.As(err, &msbErr) {
		return msbErr.Kind == kind
	}
	return false
}

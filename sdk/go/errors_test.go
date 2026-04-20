package microsandbox

import (
	"errors"
	"fmt"
	"testing"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

func TestErrorKindString(t *testing.T) {
	cases := []struct {
		kind ErrorKind
		want string
	}{
		{ErrUnknown, "Unknown"},
		{ErrSandboxNotFound, "SandboxNotFound"},
		{ErrSandboxStillRunning, "SandboxStillRunning"},
		{ErrVolumeNotFound, "VolumeNotFound"},
		{ErrVolumeAlreadyExists, "VolumeAlreadyExists"},
		{ErrExecTimeout, "ExecTimeout"},
		{ErrInvalidConfig, "InvalidConfig"},
		{ErrInvalidArgument, "InvalidArgument"},
		{ErrInvalidHandle, "InvalidHandle"},
		{ErrBufferTooSmall, "BufferTooSmall"},
		{ErrCancelled, "Cancelled"},
		{ErrInternal, "Internal"},
		{ErrorKind(9999), "Unknown"},
	}
	for _, c := range cases {
		if got := c.kind.String(); got != c.want {
			t.Errorf("ErrorKind(%d).String() = %q, want %q", int(c.kind), got, c.want)
		}
	}
}

func TestErrorError(t *testing.T) {
	e := &Error{Kind: ErrSandboxNotFound, Message: "no such sandbox"}
	got := e.Error()
	want := "no such sandbox"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestErrorErrorWithCause(t *testing.T) {
	cause := errors.New("root cause")
	e := &Error{Kind: ErrInternal, Message: "transport failed", Cause: cause}
	got := e.Error()
	if got != "transport failed: root cause" {
		t.Errorf("unexpected: %q", got)
	}
	if !errors.Is(e, cause) {
		t.Error("errors.Is should unwrap to cause")
	}
}

func TestErrorErrorEmptyMessageFallsBackToKind(t *testing.T) {
	e := &Error{Kind: ErrInvalidHandle}
	if got := e.Error(); got != "InvalidHandle" {
		t.Errorf("want kind fallback, got %q", got)
	}
}

func TestErrorErrorEmptyMessageWithCauseUsesCause(t *testing.T) {
	cause := errors.New("dlopen: no such file")
	e := &Error{Kind: ErrLibraryNotLoaded, Cause: cause}
	if got := e.Error(); got != "dlopen: no such file" {
		t.Errorf("want cause passthrough, got %q", got)
	}
}

func TestIsKind(t *testing.T) {
	e := &Error{Kind: ErrSandboxNotFound, Message: "gone"}
	if !IsKind(e, ErrSandboxNotFound) {
		t.Error("IsKind should match direct error")
	}
	wrapped := fmt.Errorf("wrap: %w", e)
	if !IsKind(wrapped, ErrSandboxNotFound) {
		t.Error("IsKind should match wrapped error")
	}
	if IsKind(e, ErrInvalidHandle) {
		t.Error("IsKind should not match a different kind")
	}
	if IsKind(nil, ErrSandboxNotFound) {
		t.Error("IsKind(nil, ...) should return false")
	}
}

func TestWrapFFINil(t *testing.T) {
	if wrapFFI(nil) != nil {
		t.Error("wrapFFI(nil) should return nil")
	}
}

func TestWrapFFIFfiError(t *testing.T) {
	fe := &ffi.Error{Kind: ffi.KindSandboxNotFound, Message: "missing"}
	err := wrapFFI(fe)
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("wrapFFI should return *Error, got %T", err)
	}
	if e.Kind != ErrSandboxNotFound {
		t.Errorf("got Kind %v, want ErrSandboxNotFound", e.Kind)
	}
	if e.Message != "missing" {
		t.Errorf("got Message %q, want %q", e.Message, "missing")
	}
}

func TestWrapFFINonFfiError(t *testing.T) {
	raw := errors.New("plain error")
	err := wrapFFI(raw)
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("wrapFFI should return *Error, got %T", err)
	}
	if e.Kind != ErrInternal {
		t.Errorf("non-ffi error should map to ErrInternal, got %v", e.Kind)
	}
	if !errors.Is(err, raw) {
		t.Error("cause should be unwrappable via errors.Is")
	}
}

func TestKindFromFFIAllTags(t *testing.T) {
	cases := []struct {
		tag  string
		want ErrorKind
	}{
		{ffi.KindSandboxNotFound, ErrSandboxNotFound},
		{ffi.KindSandboxStillRunning, ErrSandboxStillRunning},
		{ffi.KindVolumeNotFound, ErrVolumeNotFound},
		{ffi.KindVolumeAlreadyExists, ErrVolumeAlreadyExists},
		{ffi.KindExecTimeout, ErrExecTimeout},
		{ffi.KindInvalidConfig, ErrInvalidConfig},
		{ffi.KindInvalidArgument, ErrInvalidArgument},
		{ffi.KindInvalidHandle, ErrInvalidHandle},
		{ffi.KindBufferTooSmall, ErrBufferTooSmall},
		{ffi.KindCancelled, ErrCancelled},
		{"unrecognized_tag", ErrInternal},
	}
	for _, c := range cases {
		got := kindFromFFI(c.tag)
		if got != c.want {
			t.Errorf("kindFromFFI(%q) = %v, want %v", c.tag, got, c.want)
		}
	}
}

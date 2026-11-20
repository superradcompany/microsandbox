//go:build resize_compat

package microsandbox

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// Run against an actual native library that predates the resize symbols, in
// its own test process. Empty handles and names prove refusal happens before
// any native dispatch.
func TestResizeRefusesOlderNativeLibrary(t *testing.T) {
	path := os.Getenv("MSB_OLD_RESIZE_NATIVE")
	if path == "" {
		t.Skip("requires a native library predating live resize status")
	}
	if err := ffi.Load(path); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sandbox := &Sandbox{inner: new(ffi.Sandbox)}
	handle := &SandboxHandle{name: "missing", backendKind: BackendLocal}
	for name, operation := range map[string]func() error{
		"live status": func() error { _, err := sandbox.ResizeStatus(ctx); return err },
		"live wait":   func() error { _, err := sandbox.WaitUntilResized(ctx); return err },
		"live timed": func() error {
			_, err := sandbox.WaitUntilResizedWithTimeout(ctx, time.Second)
			return err
		},
		"handle status": func() error { _, err := handle.ResizeStatus(ctx); return err },
		"handle wait":   func() error { _, err := handle.WaitUntilResized(ctx); return err },
		"handle timed": func() error {
			_, err := handle.WaitUntilResizedWithTimeout(ctx, 0)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := operation()
			var sdkError *Error
			if !errors.As(err, &sdkError) || !IsKind(err, ErrUnsupportedOperation) {
				t.Fatalf("old-native call did not refuse before dispatch: %v", err)
			}
		})
	}
}

// The older binding may support ordinary resize status but lacks the additive
// operation entry point. Closed handles retain invalid-handle semantics; named
// requests must report the missing capability before entering the native library.
func TestResizeOperationsRefuseOlderNativeLibrary(t *testing.T) {
	path := os.Getenv("MSB_OLD_RESIZE_OPERATIONS_NATIVE")
	if path == "" {
		t.Skip("requires a native library predating operation tracking")
	}
	if err := ffi.Load(path); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sandbox := &Sandbox{inner: new(ffi.Sandbox)}
	handle := &SandboxHandle{name: "missing", backendKind: BackendLocal}
	records := []ResizeOperation{resizeRecord()}
	for name, call := range map[string]func() error{
		"sandbox modify": func() error { _, err := sandbox.ModifyWithResizeTracking(ctx, ModifyOptions{}); return err },
		"handle modify":  func() error { _, err := handle.ModifyWithResizeTracking(ctx, ModifyOptions{}); return err },
		"sandbox read":   func() error { _, err := sandbox.ResizeOperations(ctx); return err },
		"handle read":    func() error { _, err := handle.ResizeOperations(ctx); return err },
		"sandbox wait":   func() error { _, err := sandbox.WaitForResizeOperations(ctx, records); return err },
		"handle wait":    func() error { _, err := handle.WaitForResizeOperations(ctx, records); return err },
		"sandbox timed wait": func() error {
			_, err := sandbox.WaitForResizeOperationsWithTimeout(ctx, records, time.Second)
			return err
		},
		"handle timed wait": func() error { _, err := handle.WaitForResizeOperationsWithTimeout(ctx, records, 0); return err },
	} {
		t.Run(name, func(t *testing.T) {
			err := call()
			kind := ErrUnsupportedOperation
			if strings.HasPrefix(name, "sandbox ") {
				kind = ErrInvalidHandle
			}
			if !IsKind(err, kind) {
				t.Fatalf("did not refuse before dispatch with %s: %v", kind, err)
			}
		})
	}
}

//go:build resize_compat

package microsandbox

import (
	"context"
	"errors"
	"os"
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

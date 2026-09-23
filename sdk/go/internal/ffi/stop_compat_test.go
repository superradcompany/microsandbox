//go:build stop_compat

package ffi

import (
	"context"
	"errors"
	"os"
	"testing"
)

// Run against an actual older native library, in its own test process. Empty
// handles/names prove refusal happens before dispatch or any sandbox mutation.
func TestGracefulStopRefusesOlderNativeLibrary(t *testing.T) {
	path := os.Getenv("MSB_OLD_STOP_NATIVE")
	if path == "" {
		t.Skip("requires a native library predating explicit graceful stop waits")
	}
	if err := Load(path); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sandbox := &Sandbox{}
	zero := uint64(0)
	for name, operation := range map[string]func() error{
		"live unbounded": func() error { return sandbox.Stop(ctx, nil) },
		"live bounded":   func() error { return sandbox.Stop(ctx, &zero) },
		"live request":   func() error { return sandbox.RequestStop(ctx) },
		"handle unbounded": func() error {
			return StopSandboxHandle(ctx, "", "", nil)
		},
		"handle bounded": func() error {
			return StopSandboxHandle(ctx, "", "", &zero)
		},
		"handle request": func() error {
			return SandboxHandleVoidLifecycle(ctx, "", "", "request_stop", SandboxHandleLifecycleOptions{})
		},
	} {
		t.Run(name, func(t *testing.T) {
			var nativeError *Error
			if err := operation(); !errors.As(err, &nativeError) || nativeError.Kind != KindUnsupportedOperation {
				t.Fatalf("old-native call did not refuse before dispatch: %v", err)
			}
		})
	}
}

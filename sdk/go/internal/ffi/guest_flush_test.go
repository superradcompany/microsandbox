package ffi

import (
	"context"
	"errors"
	"testing"
)

func TestGuestFlushNativeCompatibility(t *testing.T) {
	for _, supported := range []bool{false, true} {
		for _, disk := range []bool{false, true} {
			for _, policy := range []string{"", "auto", "required", "skip", "unknown"} {
				err := validateGuestFlushSupport(policy, disk, supported)
				wantError := policy == "unknown" || (!supported && (disk || policy == "required" || policy == "skip"))
				if (err != nil) != wantError {
					t.Fatalf("supported=%v disk=%v policy=%q: %v", supported, disk, policy, err)
				}
			}
		}
	}
}

func TestGuestFlushNeverFallsBackToNameLookupForClosedHandle(t *testing.T) {
	sandbox := &Sandbox{name: "still-running-source"}
	for _, operation := range []func() error{
		func() error { return sandbox.PauseWithGuestFlush(context.Background(), "required") },
		func() error {
			_, err := sandbox.Branch(context.Background(), "child", false, "required")
			return err
		},
	} {
		var nativeError *Error
		if err := operation(); !errors.As(err, &nativeError) || nativeError.Kind != KindInvalidHandle {
			t.Fatalf("closed handle was dispatched: %v", err)
		}
	}
}

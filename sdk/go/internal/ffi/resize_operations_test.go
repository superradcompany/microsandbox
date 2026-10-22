package ffi

import (
	"context"
	"errors"
	"testing"
)

func TestResizeOperationsRejectClosedHandleBeforeNativeDispatch(t *testing.T) {
	// Close and Detach preserve cached identity but clear the native handle.
	// These requests must never turn into by-name requests or load a native library.
	sandbox := &Sandbox{name: "still-running-source", id: "local:42", backendKind: "local"}
	for _, request := range []string{
		`{"operation":"read"}`,
		`{"operation":"modify","options":{}}`,
		`{"operation":"wait","operations":[],"timeout_ms":0}`,
	} {
		result, err := sandbox.ResizeOperations(context.Background(), request)
		var nativeError *Error
		if !errors.As(err, &nativeError) || nativeError.Kind != KindInvalidHandle {
			t.Fatalf("closed resize handle reached loading or name lookup: %v", err)
		}
		if result != "" {
			t.Fatalf("closed resize handle returned a result: %q", result)
		}
	}
}

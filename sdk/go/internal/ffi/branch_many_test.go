package ffi

import (
	"context"
	"errors"
	"testing"
)

func TestBranchManyRejectsClosedLiveHandleBeforeNativeDispatch(t *testing.T) {
	// Close and Detach retain the name and identity while clearing the native handle.
	// No native library is needed: rejection must happen before loading or dispatch.
	sandbox := &Sandbox{name: "still-running-source", id: "local:42", backendKind: "local"}
	outcomes, err := sandbox.BranchMany(context.Background(), []string{"child"}, false)
	var nativeError *Error
	if !errors.As(err, &nativeError) || nativeError.Kind != KindInvalidHandle {
		t.Fatalf("closed batch source reached name lookup: %v", err)
	}
	if outcomes != nil {
		t.Fatalf("closed batch source returned outcomes: %+v", outcomes)
	}
}

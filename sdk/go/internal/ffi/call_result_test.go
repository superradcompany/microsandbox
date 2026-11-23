package ffi

import (
	"context"
	"errors"
	"testing"
)

func TestNativeResultSuccessTransfersOwnership(t *testing.T) {
	done := make(chan nativeCallResult, 1)
	done <- nativeCallResult{out: `{"handle":42}`}
	out, err := awaitNativeResult(context.Background(), done,
		func() { t.Error("successful call was cancelled") },
		func(string) { t.Error("delivered resource was released") })
	if err != nil || salvageHandle(out) != 42 {
		t.Fatalf("result = %q, %v", out, err)
	}
}

func TestCancelledNativeResultReleasesLateSuccess(t *testing.T) {
	for _, nativeError := range []error{nil, errors.New("native cancelled")} {
		name := "failure"
		if nativeError == nil {
			name = "success"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			done := make(chan nativeCallResult)
			cancelled := make(chan struct{})
			finished := make(chan struct{})
			released := make(chan uint64, 1)
			go func() {
				defer close(finished)
				out, err := awaitNativeResult(ctx, done, func() { close(cancelled) }, func(out string) {
					released <- salvageHandle(out)
				})
				if out != "" || !errors.Is(err, context.Canceled) {
					t.Errorf("result = %q, %v", out, err)
				}
			}()
			<-cancelled
			select {
			case <-finished:
				t.Fatal("returned before native arguments were safe to release")
			default:
			}
			done <- nativeCallResult{out: `{"handle":42}`, err: nativeError}
			<-finished
			if nativeError == nil {
				if handle := <-released; handle != 42 {
					t.Fatalf("released %d", handle)
				}
			} else if len(released) != 0 {
				t.Fatal("released a handle from a failed native call")
			}
		})
	}
}

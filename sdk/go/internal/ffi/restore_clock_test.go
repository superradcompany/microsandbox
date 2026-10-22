package ffi

import (
	"context"
	"errors"
	"testing"
)

func TestRestoreGuestClockCancellationDoesNotRequireNativeLibrary(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := CheckRestoreGuestClock(ctx, "off"); !errors.Is(err, context.Canceled) {
		t.Fatalf("lost cancellation: %v", err)
	}
	if err := CheckRestoreGuestClock(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
}

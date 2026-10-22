//go:build snapshot_compat

package ffi

import (
	"context"
	"errors"
	"os"
	"testing"
)

// Run separately: loading a native library predating group receivers must still
// work, while the new calls refuse rather than treating a missing symbol as success.
func TestSnapshotObjectsRefuseOlderNativeLibrary(t *testing.T) {
	path := os.Getenv("MSB_OLD_SNAPSHOT_NATIVE")
	if path == "" {
		t.Skip("requires a pre-group-receiver native library")
	}
	if err := Load(path); err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"get", "list", "head", "capture", "archive_compatibility", "restore_guest_clock"} {
		_, err := SnapshotObjectCall(context.Background(), 0, map[string]any{"op": op})
		var native *Error
		if !errors.As(err, &native) || native.Kind != KindUnsupportedOperation {
			t.Fatalf("%s: expected unsupported before dispatch, got %v", op, err)
		}
	}
	if err := CheckArchiveCompatibility(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if err := CheckRestoreGuestClock(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	for _, policy := range []string{"sync", "off"} {
		var unsupported *Error
		err := CheckRestoreGuestClock(context.Background(), policy)
		if !errors.As(err, &unsupported) || unsupported.Kind != KindUnsupportedOperation {
			t.Fatalf("guest clock %s was not refused: %v", policy, err)
		}
	}

	var native *Error
	err := CheckArchiveCompatibility(context.Background(), "0.7.8")
	if !errors.As(err, &native) || native.Kind != KindUnsupportedOperation {
		t.Fatalf("explicit archive target was not refused before an old decoder: %v", err)
	}

}

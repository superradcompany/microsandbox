//go:build storage_compat

package ffi

import (
	"context"
	"errors"
	"os"
	"testing"
)

// Run in a separate process against an actual older native library. Loading it must succeed;
// new storage methods must refuse before inspecting or mutating any local storage.
func TestStorageRefusesOlderNativeLibraryWithoutBreakingLoading(t *testing.T) {
	path := os.Getenv("MSB_OLD_STORAGE_NATIVE")
	if path == "" {
		t.Skip("requires a native library predating storage usage/prune symbols")
	}
	if err := Load(path); err != nil {
		t.Fatal(err)
	}
	sandbox := &Sandbox{}
	sandbox.handle.Store(42)
	for name, operation := range map[string]func() error{
		"usage":         func() error { _, err := StorageUsage(context.Background()); return err },
		"prune":         func() error { _, err := PruneStorage(context.Background(), StoragePruneOptions{}); return err },
		"sandbox usage": func() error { _, err := sandbox.StorageUsage(context.Background()); return err },
		"dry run": func() error {
			_, err := PruneStorage(context.Background(), StoragePruneOptions{DryRun: true})
			return err
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

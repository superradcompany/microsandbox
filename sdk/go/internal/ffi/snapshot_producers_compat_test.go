//go:build snapshot_producer_compat

package ffi

import (
	"context"
	"os"
	"strings"
	"testing"
)

// Run in its own test process with the actual intermediate native library: it
// exports general snapshot receivers but predates retained artifact producers.
func TestProducerOperationsWithPreProducerNative(t *testing.T) {
	library := os.Getenv("MSB_PRE_PRODUCER_NATIVE")
	if library == "" {
		t.Skip("requires the actual pre-producer native library")
	}
	if err := Load(library); err != nil {
		t.Fatal(err)
	}
	// Verify the fixture really has the intermediate ABI. A library without any
	// receivers, or one already supporting the new operations, misses this regression.
	_, probeErr := SnapshotObjectCall(context.Background(), 0, map[string]any{"op": "list_dir", "directory": t.TempDir()})
	if probeErr == nil || !strings.Contains(probeErr.Error(), "unknown variant `list_dir`") {
		t.Fatalf("expected pre-producer receiver ABI, got %v", probeErr)
	}
	t.Run("empty_directory", func(t *testing.T) {
		rows, err := SnapshotListDir(context.Background(), t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 0 {
			t.Fatalf("expected empty directory, got %d", len(rows))
		}
	})
	t.Run("capture_dispatch", func(t *testing.T) {
		_, err := SnapshotCreate(context.Background(), "missing-compat-source", SnapshotCreateOptions{Full: true})
		if err == nil {
			t.Fatal("missing source unexpectedly captured")
		}
		if strings.Contains(err.Error(), "invalid snapshot operation") {
			t.Fatalf("existing capture dispatched an unsupported operation: %v", err)
		}
	})
}

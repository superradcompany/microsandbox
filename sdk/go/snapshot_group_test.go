package microsandbox

import (
	"context"
	"errors"
	"testing"
)

// Legacy producers remain usable, but cannot promise the retained identity needed
// by the new spawn/removal operations. Refuse before loading or dispatching native code.
func TestCheckpointWithoutReceiverReportsUnsupported(t *testing.T) {
	checkpoint := &SnapshotArtifact{}
	_, spawnErr := checkpoint.SpawnSandbox(context.Background(), "unused")
	_, removeErr := checkpoint.Remove(context.Background())
	for _, err := range []error{spawnErr, removeErr} {
		var unsupported *Error
		if !errors.As(err, &unsupported) || unsupported.Kind != ErrUnsupportedOperation {
			t.Fatalf("expected unsupported operation, got %v", err)
		}
	}
}

// Invalid option multiplicity must fail before loading a native library or publishing a group.
func TestSnapshotLoadRejectsMultipleOptions(t *testing.T) {
	_, err := Snapshot.Load(context.Background(), "history", nil, SnapshotImportOptions{}, SnapshotImportOptions{})
	if err == nil || err.Error() != "snapshot load accepts at most one options value" {
		t.Fatalf("expected option validation, got %v", err)
	}
}

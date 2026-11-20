package microsandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Legacy producers remain usable, but cannot promise the retained identity needed
// by the new spawn/removal operations. Refuse before loading or dispatching native code.
func TestCheckpointWithoutReceiverReportsUnsupported(t *testing.T) {
	checkpoint := &Checkpoint{}
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
	_, err := (&Snapshots{}).Load(context.Background(), "history", nil, SnapshotImportOptions{}, SnapshotImportOptions{})
	if err == nil || err.Error() != "snapshot load accepts at most one options value" {
		t.Fatalf("expected option validation, got %v", err)
	}
}

func testHistories(t *testing.T) *Snapshots {
	t.Helper()
	selected, err := configuredContext()
	if err != nil {
		t.Fatal(err)
	}
	return selected.Snapshots()
}

func TestGroupImportRetainsCallerDirectory(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	files := []string{"nested/../delta.msb"}
	options := SnapshotImportOptions{Dest: "output", Base: "history"}
	resolved, opts, dir, err := prepareGroupImportPaths(files, options)
	if err != nil || dir != cwd || resolved[0] != files[0] || opts != options {
		t.Fatalf("relative inputs changed: %q, %+v, %q, %v", resolved, opts, dir, err)
	}
	absolute := filepath.Join(cwd, "delta.msb")
	_, _, dir, err = prepareGroupImportPaths([]string{absolute}, SnapshotImportOptions{})
	if err != nil || dir != "" {
		t.Fatalf("absolute import depended on cwd: %q, %v", dir, err)
	}
}

func TestCaptureDirectoryAnchorsRelativeInput(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	input := "target"
	if filepath.Separator == '/' {
		input = "link/../target"
	}
	got, err := anchorSnapshotDirectory(input)
	if err != nil {
		t.Fatal(err)
	}
	if got != cwd+string(os.PathSeparator)+input {
		t.Fatalf("capture directory changed: %q", got)
	}
	if empty, err := anchorSnapshotDirectory(""); err != nil || empty != "" {
		t.Fatalf("default directory: %q, %v", empty, err)
	}
}

//go:build snapshot_native

package microsandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// Run this test in a fresh process: native backend selection is process-wide.
func TestSnapshotGroupOpenDirectory(t *testing.T) {
	library := os.Getenv("MSB_SNAPSHOT_NATIVE_LIBRARY")
	if library == "" {
		t.Skip("requires a freshly built native library")
	}
	root := t.TempDir()
	t.Setenv("MSB_HOME", filepath.Join(root, "home"))
	t.Setenv("MSB_BACKEND", "local")
	t.Setenv("MSB_CONFIG_PATH", filepath.Join(root, "absent.json"))
	if err := ffi.Load(library); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(root, "external", "history")
	named := filepath.Join(root, "home", "snapshots", "history")
	metadata := []byte(`{"schema":"microsandbox.snapshot-group/1","head":null}`)
	for _, path := range []string{external, named} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "group.json"), metadata, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	history, err := Snapshot.Open(ctx, external)
	if os.Getenv("MSB_EXPECT_OLD_GROUP_PATHS") == "1" {
		var unsupported *Error
		if !errors.As(err, &unsupported) || unsupported.Kind != ErrUnsupportedOperation {
			t.Fatalf("expected unsupported: %v", err)
		}
		// The refusal must leave existing name-based operations usable.
		if _, err := Snapshot.Get(ctx, "history"); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	info, err := history.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	expected, _ := filepath.EvalSymlinks(external)
	if info.Path != expected || history.Name() != "history" {
		t.Fatalf("wrong group: %+v", info)
	}
	if head, err := history.Head(ctx); err != nil || head != nil {
		t.Fatalf("head: %v %v", head, err)
	}
	if _, err := Snapshot.Open(ctx, filepath.Join(root, "missing")); err == nil {
		t.Fatal("missing directory accepted")
	}
	if _, err := history.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(external); !os.IsNotExist(err) {
		t.Fatalf("external group still exists: %v", err)
	}
	if saved, err := os.ReadFile(filepath.Join(named, "group.json")); err != nil || string(saved) != string(metadata) {
		t.Fatalf("named group changed: %s %v", saved, err)
	}
}

//go:build snapshot_live

package microsandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// Exercise the legacy producers themselves: reopening their results would hide a
// missing native receiver and could select another backend or replacement file.
func TestCheckpointProducerReceiversLive(t *testing.T) {
	library, archive := os.Getenv("MSB_TEST_PRODUCER_LIBRARY"), os.Getenv("MSB_TEST_GROUP_ARCHIVE")
	if library == "" || archive == "" {
		t.Skip("requires native library, native archive and isolated MSB_HOME")
	}
	if err := ffi.Load(library); err != nil {
		t.Fatal(err)
	}
	legacy := os.Getenv("MSB_TEST_PRODUCER_LEGACY") == "1"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	// Register history cleanup before sandbox cleanup, so dependent guests are
	// removed first even when a producer assertion aborts the scenario.
	for _, name := range []string{"producer-seed", "producer-history"} {
		t.Cleanup(func() {
			cleanup, done := context.WithTimeout(context.Background(), 30*time.Second)
			defer done()
			if group, err := Snapshot.Get(cleanup, name); err == nil {
				if _, err := group.Remove(cleanup); err != nil {
					t.Errorf("cleanup %s: %v", name, err)
				}
			}
		})
	}
	for _, name := range []string{"prod-src", "prod-a", "prod-b"} {
		t.Cleanup(func() {
			cleanup, done := context.WithTimeout(context.Background(), 30*time.Second)
			defer done()
			if source, err := GetSandbox(cleanup, name); err == nil {
				_ = source.Stop(cleanup)
			}
			_ = RemoveSandbox(cleanup, name)
		})
	}
	seed, err := Snapshot.Load(ctx, "producer-seed", []string{archive})
	if err != nil {
		t.Fatal(err)
	}
	source, err := seed.Snapshot.SpawnSandbox(ctx, "prod-src", WithRestoreCPUs(1), WithRestoreMemory(256))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	out, err := source.Exec(ctx, "sh", []string{"-c", "echo producer-receiver > /producer-marker; sync"})
	if err != nil || !out.Success() {
		t.Fatalf("write: %v %+v", err, out)
	}
	if err := source.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	created, err := Checkpoint.Create(ctx, SnapshotCreateOptions{FromSandbox: source.Name(), Group: "producer-history", Name: "ready", RecordIntegrity: true})
	if err != nil {
		t.Fatal(err)
	}
	if (created.object == nil) != legacy {
		t.Fatalf("Checkpoint.Create receiver disagrees with legacy=%v", legacy)
	}
	listed, err := Checkpoint.ListDir(ctx, filepath.Join(os.Getenv("MSB_HOME"), "snapshots", "producer-history"))
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].ID() != created.ID() || (listed[0].object == nil) != legacy {
		t.Fatalf("ListDir lost exact receiver: %+v", listed)
	}
	if legacy {
		for _, checkpoint := range []*SnapshotArtifact{created, listed[0]} {
			_, spawnErr := checkpoint.SpawnSandbox(ctx, "must-not-start")
			_, removeErr := checkpoint.Remove(ctx)
			for _, err := range []error{spawnErr, removeErr} {
				var unsupported *Error
				if !errors.As(err, &unsupported) || unsupported.Kind != ErrUnsupportedOperation {
					t.Fatalf("legacy producer should refuse retained operation: %v", err)
				}
			}
			if _, err := checkpoint.Verify(ctx); err != nil {
				t.Fatalf("legacy verification: %v", err)
			}
		}
		// Reopening is an explicit caller choice after validating the old producer;
		// production capture/list routing must never silently reselect its result.
		created, err = Checkpoint.Open(ctx, created.Path())
		if err != nil {
			t.Fatal(err)
		}
		listed[0], err = Checkpoint.Open(ctx, listed[0].Path())
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := RemoveSandbox(ctx, source.Name()); err != nil {
		t.Fatal(err)
	}
	for index, checkpoint := range []*SnapshotArtifact{created, listed[0]} {
		name := []string{"prod-a", "prod-b"}[index]
		child, err := checkpoint.SpawnSandbox(ctx, name)
		if err != nil {
			t.Fatalf("%s spawn: %v", name, err)
		}
		output, execErr := child.Exec(ctx, "cat", []string{"/producer-marker"})
		if execErr != nil || !output.Success() || output.Stdout() != "producer-receiver\n" {
			t.Fatalf("%s contents: %v %+v", name, execErr, output)
		}
		_ = child.Stop(ctx)
		_ = child.Close()
		if err := RemoveSandbox(ctx, name); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := listed[0].Remove(ctx)
	if err != nil || removed.ID != created.ID() {
		t.Fatalf("listed removal: %v %+v", err, removed)
	}
	// An independent returned receiver retains the original identity after deletion.
	if _, err := created.Remove(ctx); err == nil {
		t.Fatal("stale created receiver removed a nonexistent checkpoint")
	}
	t.Log("Create/ListDir receivers spawn exact saved contents after source deletion; removal reports exact identity")
}

package microsandbox

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// An isolated child avoids selecting a process-global native backend for other tests.
func TestCheckpointRemovalNative(t *testing.T) {
	library := os.Getenv("MSB_CHECKPOINT_REMOVAL_LIBRARY")
	if library == "" {
		t.Skip("requires current native library")
	}
	if os.Getenv("MSB_CHECKPOINT_REMOVAL_CHILD") != "1" {
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(exe, "-test.run=^TestCheckpointRemovalNative$", "-test.v")
		cmd.Env = append(os.Environ(), "MSB_CHECKPOINT_REMOVAL_CHILD=1", "MSB_HOME="+t.TempDir())
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("native child: %v\n%s", err, out)
		}
		return
	}
	if err := ffi.Load(library); err != nil {
		t.Fatal(err)
	}
	home := os.Getenv("MSB_HOME")
	groupPath := filepath.Join(home, "snapshots", "history")
	id := "snap_000000000000000000000000000003a2"
	path := filepath.Join(groupPath, id)
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	// A metadata-only fixture tests removal, never guest restoration.
	manifest := `{"schema":"microsandbox.snapshot/1","snapshot_id":"` + id + `","scope":"checkpoint","state":{"kind":"checkpoint","checkpoint_id":"checkpoint_test","checkpoint_root":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","restore_intents":["resume"],"requirements_summary":{}},"capture":{"created_at":"2026-09-10T00:00:00Z","source_lineage":null,"source_checkpoint":null,"consistency":"crash-consistent"},"image":{"reference":"alpine","manifest_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"root_disk":{"layout":"managed"},"parent":null,"requires":[],"extensions":{}}`
	if err := os.WriteFile(filepath.Join(path, "snapshot.json"), []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	head, _ := json.Marshal(map[string]any{"schema": "microsandbox.snapshot-group/1", "head": id})
	if err := os.WriteFile(filepath.Join(groupPath, "group.json"), head, 0600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	checkpoint, err := Checkpoint.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	report, err := checkpoint.Remove(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if report.ID != id || report.HeadUpdate == nil || !report.HeadUpdate.Changed || report.HeadUpdate.Head != nil || report.HeadUpdate.Previous == nil || *report.HeadUpdate.Previous != id {
		t.Fatalf("lost removal outcome: %+v", report)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("artifact remains: %v", err)
	}
	if _, err := checkpoint.Remove(ctx, CheckpointRemoveOptions{Force: true}); err == nil {
		t.Fatal("manufactured repeated removal")
	}
	// Recreate a populated group to exercise the group receiver across the real FFI.
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "snapshot.json"), []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(groupPath, "group.json"), head, 0600); err != nil {
		t.Fatal(err)
	}
	group, err := Snapshot.Get(ctx, "history")
	if err != nil {
		t.Fatal(err)
	}
	info, err := group.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.Name != "history" || info.Head == nil || *info.Head != id || info.CheckpointCount != 1 || info.Source != nil {
		t.Fatalf("lost group metadata: %+v", info)
	}
	removedGroup, err := group.Remove(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if removedGroup.Group != "history" || len(removedGroup.Removed) != 1 || removedGroup.Removed[0] != id || removedGroup.HeadUpdate == nil || removedGroup.HeadUpdate.Head != nil {
		t.Fatalf("lost group removal outcome: %+v", removedGroup)
	}
	if _, err := os.Stat(groupPath); !os.IsNotExist(err) {
		t.Fatalf("group remains: %v", err)
	}

}

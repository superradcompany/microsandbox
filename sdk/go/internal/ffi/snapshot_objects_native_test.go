//go:build snapshot_native

package ffi

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A fresh interpreter owns the native backend; no user catalog or default backend is reused.
func TestSnapshotOwnedResponseExceedsLegacyBuffer(t *testing.T) {
	library := os.Getenv("MSB_SNAPSHOT_NATIVE_LIBRARY")
	if library == "" {
		t.Skip("requires a freshly built native library")
	}
	if os.Getenv("MSB_SNAPSHOT_RESPONSE_CHILD") != "1" {
		home := t.TempDir()
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSnapshotOwnedResponseExceedsLegacyBuffer$", "-test.count=1")
		for _, entry := range os.Environ() {
			key, _, _ := strings.Cut(entry, "=")
			switch key {
			case "MSB_HOME", "MSB_CONFIG_PATH", "MSB_BACKEND", "MSB_PROFILE", "MSB_SNAPSHOT_RESPONSE_CHILD":
				continue
			}
			child.Env = append(child.Env, entry)
		}
		child.Env = append(child.Env, "MSB_HOME="+home, "MSB_CONFIG_PATH="+filepath.Join(home, "absent.json"), "MSB_BACKEND=local", "MSB_SNAPSHOT_RESPONSE_CHILD=1")
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("native response test: %v\n%s", err, output)
		}
		return
	}
	if err := Load(library); err != nil {
		t.Fatal(err)
	}

	// Group receivers have no per-member descriptor cost. Their combined listing
	// exercises the real native result transfer above the legacy 1 MiB ceiling.
	const count = 16000
	root := filepath.Join(os.Getenv("MSB_HOME"), "snapshots")
	for i := 0; i < count; i++ {
		name := fmt.Sprintf("group-%s-%05d", strings.Repeat("x", 48), i)
		directory := filepath.Join(root, name)
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "group.json"), []byte(`{"schema":"microsandbox.snapshot-group/1","head":null}`), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	raw, err := SnapshotObjectCall(ctx, 0, map[string]any{"op": "list"})
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= defaultBufSize {
		t.Fatalf("response only has %d bytes", len(raw))
	}
	var groups []struct {
		Handle uint64 `json:"object_handle"`
		Name   string `json:"name"`
	}
	if err := json.Unmarshal(raw, &groups); err != nil {
		t.Fatal(err)
	}
	if len(groups) != count {
		t.Fatalf("returned %d groups, want %d", len(groups), count)
	}
	defer func() {
		for _, group := range groups {
			releaseSnapshotObject(group.Handle)
		}
	}()
	for _, group := range groups {
		if group.Handle == 0 {
			t.Fatal("missing retained receiver")
		}
	}
	// The first/last receiver remain usable after freeing the large response buffer.
	for _, group := range []struct {
		Handle uint64 `json:"object_handle"`
		Name   string `json:"name"`
	}{groups[0], groups[len(groups)-1]} {
		inspected, err := SnapshotObjectCall(ctx, group.Handle, map[string]any{"op": "inspect_group"})
		if err != nil {
			t.Fatal(err)
		}
		var info struct {
			Name  string `json:"name"`
			Count int    `json:"checkpoint_count"`
		}
		if err := json.Unmarshal(inspected, &info); err != nil {
			t.Fatal(err)
		}
		if info.Name != group.Name || info.Count != 0 {
			t.Fatalf("incorrect retained group: %+v", info)
		}
	}
	t.Logf("transferred %d bytes and %d retained group receivers", len(raw), len(groups))
}

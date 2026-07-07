package microsandbox

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

func TestSnapshotCreateEmptyName(t *testing.T) {
	_, err := Snapshot.Create(context.Background(), SnapshotCreateOptions{FromSandbox: "baseline"})
	if !IsKind(err, ErrInvalidConfig) {
		t.Fatalf("err = %v, want ErrInvalidConfig", err)
	}
	if !strings.Contains(err.Error(), "Name") {
		t.Fatalf("error should name the missing field: %q", err.Error())
	}
}

func TestSnapshotCreateEmptyFromSandbox(t *testing.T) {
	_, err := Snapshot.Create(context.Background(), SnapshotCreateOptions{Name: "after-pip-install"})
	if !IsKind(err, ErrInvalidConfig) {
		t.Fatalf("err = %v, want ErrInvalidConfig", err)
	}
	if !strings.Contains(err.Error(), "FromSandbox") {
		t.Fatalf("error should name the missing field: %q", err.Error())
	}
}

func marshalSnapshotCreateOptions(t *testing.T, opts ffi.SnapshotCreateOptions) map[string]any {
	t.Helper()
	raw, err := json.Marshal(opts)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

func TestFFIWireShape_SnapshotCreateResumable(t *testing.T) {
	got := marshalSnapshotCreateOptions(t, ffi.SnapshotCreateOptions{
		Name:      "after-pip-install",
		Resumable: true,
	})
	if v := mustField(t, got, "resumable"); v != true {
		t.Fatalf("resumable = %v, want true", v)
	}
	if _, present := got["dest_dir"]; present {
		t.Fatal("dest_dir must not appear in payload when unset")
	}
}

func TestFFIWireShape_SnapshotCreateDestDir(t *testing.T) {
	got := marshalSnapshotCreateOptions(t, ffi.SnapshotCreateOptions{
		Name:    "after-pip-install",
		DestDir: "/data/snapshots",
	})
	if v := mustField(t, got, "dest_dir"); v != "/data/snapshots" {
		t.Fatalf("dest_dir = %v, want %q", v, "/data/snapshots")
	}
	if _, present := got["resumable"]; present {
		t.Fatal("resumable must not appear in payload when unset")
	}
}

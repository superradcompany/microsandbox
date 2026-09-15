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

func TestSnapshotCloneEmptySource(t *testing.T) {
	_, err := Snapshot.Clone(context.Background(), "", "slim", SnapshotCloneOptions{})
	if !IsKind(err, ErrInvalidConfig) {
		t.Fatalf("err = %v, want ErrInvalidConfig", err)
	}
	if !strings.Contains(err.Error(), "source") {
		t.Fatalf("error should name the missing field: %q", err.Error())
	}
}

func TestSnapshotCloneEmptyNewName(t *testing.T) {
	_, err := Snapshot.Clone(context.Background(), "bloated", "", SnapshotCloneOptions{})
	if !IsKind(err, ErrInvalidConfig) {
		t.Fatalf("err = %v, want ErrInvalidConfig", err)
	}
	if !strings.Contains(err.Error(), "newName") {
		t.Fatalf("error should name the missing field: %q", err.Error())
	}
}

func marshalSnapshotCloneOptions(t *testing.T, opts ffi.SnapshotCloneOptions) map[string]any {
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

func TestFFIWireShape_SnapshotCloneCompactAndRootDisk(t *testing.T) {
	got := marshalSnapshotCloneOptions(t, ffi.SnapshotCloneOptions{
		Compact:         true,
		RootDiskSizeMib: 8192,
	})
	if v := mustField(t, got, "compact"); v != true {
		t.Fatalf("compact = %v, want true", v)
	}
	if v := mustField(t, got, "root_disk_size_mib"); v != float64(8192) {
		t.Fatalf("root_disk_size_mib = %v, want 8192", v)
	}
	if _, present := got["dest_dir"]; present {
		t.Fatal("dest_dir must not appear in payload when unset")
	}
}

func TestFFIWireShape_SnapshotCloneDefaultsOmitCompactAndRootDisk(t *testing.T) {
	got := marshalSnapshotCloneOptions(t, ffi.SnapshotCloneOptions{})
	if _, present := got["compact"]; present {
		t.Fatal("compact must not appear in payload when unset")
	}
	if _, present := got["root_disk_size_mib"]; present {
		t.Fatal("root_disk_size_mib must not appear in payload when unset")
	}
}

func TestSnapshotStateProjectionDistinguishesMissingAndMerkleIntegrity(t *testing.T) {
	format := "raw"
	fstype := "ext4"
	upperFile := "upper.ext4"
	without := snapshotStateFromInfo(&ffi.SnapshotInfo{
		StateKind: "file",
		Format:    &format,
		Fstype:    &fstype,
		UpperFile: &upperFile,
	})
	if without.File == nil || without.File.HasIntegrity {
		t.Fatalf("missing integrity projected as recorded: %#v", without.File)
	}

	algorithm := "msb-file-merkle-blake3-v1"
	root := "blake3:" + strings.Repeat("d", 64)
	logicalSize := uint64(4096)
	leafSize := uint32(65536)
	withMerkle := snapshotStateFromInfo(&ffi.SnapshotInfo{
		StateKind:                 "file",
		Format:                    &format,
		Fstype:                    &fstype,
		UpperFile:                 &upperFile,
		UpperIntegrityAlgorithm:   &algorithm,
		UpperIntegrityDigest:      &root,
		UpperIntegrityRoot:        &root,
		UpperIntegrityLogicalSize: &logicalSize,
		UpperIntegrityLeafSize:    &leafSize,
	})
	if withMerkle.File == nil || !withMerkle.File.HasIntegrity {
		t.Fatalf("recorded Merkle integrity was lost: %#v", withMerkle.File)
	}
	got := withMerkle.File.Integrity
	if got.Algorithm != algorithm || got.Digest != root || got.Root != root || got.LogicalSize != logicalSize || got.LeafSize != leafSize {
		t.Fatalf("Merkle integrity projection = %#v", got)
	}
}

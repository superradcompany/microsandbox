package microsandbox

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

type snapshotSaver interface {
	SaveTo(context.Context, string, SnapshotSaveOptions) error
}

type snapshotCopier interface {
	CopyTo(string) *SnapshotCopyBuilder
}

var (
	_ snapshotSaver  = (*SnapshotArtifact)(nil)
	_ snapshotSaver  = (*SnapshotHandle)(nil)
	_ snapshotCopier = (*SnapshotArtifact)(nil)
)

func TestSnapshotCopyBuilderCopiesMutableInput(t *testing.T) {
	snapshot := &SnapshotArtifact{reference: "/snapshots/example", referenceKind: "path"}
	labels := map[string]string{"environment": "test"}
	builder := snapshot.CopyTo("/tmp/copied.tar.zst").Labels(labels).RecordIntegrity(true)
	labels["environment"] = "changed"

	if got := builder.labels["environment"]; got != "test" {
		t.Fatalf("builder label = %q, want %q", got, "test")
	}
	if !builder.recordIntegrity {
		t.Fatal("builder recordIntegrity = false, want true")
	}
	if builder.outputArchivePath != "/tmp/copied.tar.zst" {
		t.Fatalf("builder output path = %q", builder.outputArchivePath)
	}
}

func TestZeroSnapshotCopyBuilderFailsCleanly(t *testing.T) {
	var builder SnapshotCopyBuilder
	err := builder.Save(context.Background())
	if !IsKind(err, ErrInvalidConfig) {
		t.Fatalf("Save error = %v, want ErrInvalidConfig", err)
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

func TestFFIWireShape_SnapshotCreateFull(t *testing.T) {
	got := marshalSnapshotCreateOptions(t, ffi.SnapshotCreateOptions{
		Name: "after-pip-install",
		Full: true,
	})
	if v := mustField(t, got, "full"); v != true {
		t.Fatalf("full = %v, want true", v)
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
	if _, present := got["full"]; present {
		t.Fatal("full must not appear in payload when unset")
	}
}

func TestFFIWireShape_SnapshotGroupWithGeneratedName(t *testing.T) {
	got := marshalSnapshotCreateOptions(t, ffi.SnapshotCreateOptions{Group: "work"})
	if got["group"] != "work" {
		t.Fatalf("group = %v, want work", got["group"])
	}
	if _, present := got["name"]; present {
		t.Fatal("generated names must be omitted for the Rust builder to assign")
	}
}

func TestFFIWireShape_SnapshotLoadGroupOptions(t *testing.T) {
	payload, err := json.Marshal(ffi.SnapshotLoadOptions{
		Dest: "/snapshots", Base: "work:baseline", Group: "work", SetHead: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatal(err)
	}
	if got["dest"] != "/snapshots" || got["base"] != "work:baseline" || got["group"] != "work" || got["set_head"] != true {
		t.Fatalf("unexpected load options: %s", payload)
	}
}

func TestFFIWireShape_SnapshotHeadUpdate(t *testing.T) {
	var update ffi.SnapshotHeadUpdate
	if err := json.Unmarshal([]byte(`{"group":"work","previous":null,"head":"baseline","reason":"initialized","changed":true}`), &update); err != nil {
		t.Fatal(err)
	}
	if update.Group != "work" || update.Previous != nil || update.Head != "baseline" || update.Reason != "initialized" || !update.Changed {
		t.Fatalf("unexpected head update: %#v", update)
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

func TestLegacySnapshotPaths(t *testing.T) {
	path := "/local/snapshot"
	snapshot := snapshotFromInfo(&ffi.SnapshotInfo{Path: &path, Reference: path, ReferenceKind: "path"})
	handle := snapshotHandleFromInfo(&ffi.SnapshotHandleInfo{Path: &path, Reference: path, ReferenceKind: "path"})
	if snapshot.Path() != path || handle.Path() != path {
		t.Fatal("legacy accessors did not preserve local path")
	}
	for _, kind := range []string{"id", "path"} {
		t.Run(kind, func(t *testing.T) {
			remoteSnapshot := snapshotFromInfo(&ffi.SnapshotInfo{Reference: "/remote/snapshot", ReferenceKind: kind})
			remoteHandle := snapshotHandleFromInfo(&ffi.SnapshotHandleInfo{Reference: "/remote/snapshot", ReferenceKind: kind})
			for name, accessor := range map[string]func() string{"snapshot": remoteSnapshot.Path, "handle": remoteHandle.Path} {
				t.Run(name, func(t *testing.T) {
					defer func() {
						if recover() == nil {
							t.Fatal("remote path accessor must panic")
						}
					}()
					accessor()
				})
			}
		})
	}
}

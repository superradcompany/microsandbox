package microsandbox

import (
	"archive/tar"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// Use a subprocess because native backend selection is process-global.
func TestArchiveCompatibilityNative(t *testing.T) {
	library := os.Getenv("MSB_ARCHIVE_NATIVE_LIBRARY")
	if library == "" {
		t.Skip("requires a current native library")
	}
	if os.Getenv("MSB_ARCHIVE_NATIVE_CHILD") != "1" {
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(exe, "-test.run=^TestArchiveCompatibilityNative$", "-test.v")
		cmd.Env = append(os.Environ(), "MSB_ARCHIVE_NATIVE_CHILD=1", "MSB_HOME="+t.TempDir())
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("native child: %v\n%s", err, out)
		}
		return
	}
	if err := ffi.Load(library); err != nil {
		t.Fatal(err)
	}
	path := t.TempDir()
	// Opaque disk bytes suffice for archive transport; this does not test guest restore.
	manifest := `{"schema":1,"artifact":"snapshot","scope":"disk","created_at":"2026-05-01T12:00:00Z","parent":null,"image":{"ref":"docker.io/library/alpine:3.20","manifest_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"source_sandbox":null,"state":{"kind":"file","format":"raw","fstype":"ext4","upper":{"file":"upper.ext4","size_bytes":5,"integrity":null}},"labels":{},"extensions":{},"requires":[]}`
	for name, contents := range map[string]string{"snapshot.json": manifest, "upper.ext4": "hello", "group-member.json": `{"schema":"microsandbox.snapshot-group-member/1","name":"ready"}`} {
		if err := os.WriteFile(filepath.Join(path, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	snapshot, err := Checkpoint.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	// The canonical receiver API has a useful no-options form as well as the
	// historical SaveTo form. Reject conflicting options before creating output.
	defaultArchive := filepath.Join(t.TempDir(), "default.msb")
	if err := snapshot.Save(ctx, defaultArchive); err != nil {
		t.Fatal(err)
	}
	conflictingArchive := filepath.Join(t.TempDir(), "conflicting.msb")
	if err := snapshot.Save(ctx, conflictingArchive, SnapshotSaveOptions{}, SnapshotSaveOptions{}); err == nil {
		t.Fatal("accepted multiple option values")
	}
	if _, err := os.Stat(conflictingArchive); !os.IsNotExist(err) {
		t.Fatalf("conflicting options touched output: %v", err)
	}
	for target, key := range map[string]string{"current": "microsandbox.member-names", "0.7.8": "msb-snapshot-member-names"} {
		out := filepath.Join(t.TempDir(), "out.tar")
		if err := snapshot.SaveTo(ctx, out, SnapshotSaveOptions{PlainTar: true, Compatibility: target}); err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(out)
		if err != nil {
			t.Fatal(err)
		}
		reader := tar.NewReader(file)
		found := false
		for {
			header, err := reader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if header.Name != "archive.json" {
				continue
			}
			var inventory struct {
				Extensions map[string]map[string]string `json:"extensions"`
				Requires   []string                     `json:"requires"`
			}
			if err := json.NewDecoder(reader).Decode(&inventory); err != nil {
				t.Fatal(err)
			}
			names, exists := inventory.Extensions[key]
			if !exists || len(names) != 1 {
				t.Fatalf("lost selected dialect: %+v", inventory)
			}
			for _, name := range names {
				if name != "ready" {
					t.Fatalf("lost name: %q", name)
				}
			}
			required := false
			for _, value := range inventory.Requires {
				if value == key {
					required = true
				}
			}
			if required != (target == "current") {
				t.Fatalf("incorrect requirement: %+v", inventory)
			}
			found = true
		}
		file.Close()
		if !found {
			t.Fatal("missing archive inventory")
		}
	}
	out := filepath.Join(t.TempDir(), "invalid.tar")
	if err := snapshot.SaveTo(ctx, out, SnapshotSaveOptions{Compatibility: "0.7"}); err == nil {
		t.Fatal("accepted unsupported target")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("invalid target touched output: %v", err)
	}
}

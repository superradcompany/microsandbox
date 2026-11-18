//go:build volume_compat

package microsandbox

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// An actual older native library must reject these operation names before any
// filesystem access. Run in a separate process because the native loader is sticky.
func TestVolumeFsRefusesOlderNative(t *testing.T) {
	library := os.Getenv("MSB_OLD_VOLUME_NATIVE")
	if library == "" {
		t.Skip("requires a native library predating confined local operations")
	}
	if err := ffi.Load(library); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	marker := filepath.Join(root, "marker")
	if err := os.WriteFile(marker, []byte("unchanged"), 0o644); err != nil {
		t.Fatal(err)
	}
	fs := &VolumeFs{root: root}
	ctx := context.Background()
	for name, operation := range map[string]func() error{
		"read":       func() error { _, err := fs.Read(ctx, "marker"); return err },
		"write":      func() error { return fs.Write(ctx, "marker", []byte("changed")) },
		"mkdir":      func() error { return fs.Mkdir(ctx, "new") },
		"exists":     func() error { _, err := fs.Exists(ctx, "marker"); return err },
		"remove":     func() error { return fs.Remove(ctx, "marker") },
		"remove all": func() error { return fs.RemoveAll(ctx, "marker") },
	} {
		t.Run(name, func(t *testing.T) {
			if err := operation(); !IsKind(err, ErrUnsupportedOperation) {
				t.Fatalf("want upgrade-required refusal, got %v", err)
			}
		})
	}
	if got, err := os.ReadFile(marker); err != nil || string(got) != "unchanged" {
		t.Fatalf("old-native refusal mutated marker: %q, %v", got, err)
	}
	if entries, err := os.ReadDir(root); err != nil || len(entries) != 1 {
		t.Fatalf("old-native refusal mutated root: %v, %v", entries, err)
	}
}

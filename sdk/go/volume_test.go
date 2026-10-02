package microsandbox

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

func TestVolumeName(t *testing.T) {
	v := &Volume{name: "my-volume"}
	if v.Name() != "my-volume" {
		t.Errorf("Name() = %q, want %q", v.Name(), "my-volume")
	}
}

// Invalid host-rooted and parent paths are rejected even before loading native
// code. Symlink confinement is exercised against the native implementation.
func TestVolumeFsPathEscape(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	fs := &VolumeFs{root: root}
	volumeRoot := filepath.VolumeName(root) + string(filepath.Separator)

	cases := []struct {
		name string
		rel  string
	}{
		{"parent traversal", "../escape"},
		{"deep traversal", "a/b/../../../escape"},
		{"absolute path", filepath.Join(volumeRoot, "etc", "passwd")},
		{"rooted forward slash", "/absolute"},
		{"rooted separator", string(filepath.Separator) + "absolute"},
		{"absolute under root", filepath.Join(root, "..", "escape")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := fs.Read(ctx, c.rel); !errors.Is(err, ErrPathEscape) {
				t.Errorf("Read(%q): want ErrPathEscape, got %v", c.rel, err)
			}
			if err := fs.Write(ctx, c.rel, []byte("x")); !errors.Is(err, ErrPathEscape) {
				t.Errorf("Write(%q): want ErrPathEscape, got %v", c.rel, err)
			}
			if _, err := fs.Exists(ctx, c.rel); !errors.Is(err, ErrPathEscape) {
				t.Errorf("Exists(%q): want ErrPathEscape, got %v", c.rel, err)
			}
			if err := fs.Remove(ctx, c.rel); !errors.Is(err, ErrPathEscape) {
				t.Errorf("Remove(%q): want ErrPathEscape, got %v", c.rel, err)
			}
		})
	}
}

func TestVolumeFsEmptyRoot(t *testing.T) {
	fs := &VolumeFs{root: ""}
	if _, err := fs.Read(context.Background(), "anything"); err == nil {
		t.Error("expected error on empty root")
	}
}

func TestVolumeFsHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	fs := &VolumeFs{root: t.TempDir()}
	if _, err := fs.Read(ctx, "anything"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Read() = %v, want context.Canceled", err)
	}
}

func TestCloudVolumeFsTargetUsesImmutableID(t *testing.T) {
	id := "11111111-1111-1111-1111-111111111111"
	info := &ffi.VolumeHandleInfo{ID: &id, Name: "reusable-name"}

	if got := volumeFsTarget(info); got != "cloud-id:"+id {
		t.Fatalf("volumeFsTarget() = %q, want immutable cloud ID", got)
	}
}

func TestDefaultVolumeCannotBeRemoved(t *testing.T) {
	handle := &VolumeHandle{isDefault: true}
	err := handle.Remove(context.Background())
	if !IsKind(err, ErrUnsupportedOperation) {
		t.Fatalf("Remove() = %v, want ErrUnsupportedOperation", err)
	}
}

package microsandbox

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestVolumeName(t *testing.T) {
	v := &Volume{name: "my-volume"}
	if v.Name() != "my-volume" {
		t.Errorf("Name() = %q, want %q", v.Name(), "my-volume")
	}
}

// VolumeFs.abs must reject any relative path that resolves outside the root.
// This is the test that catches the "fs.root + / + rel" footgun where a
// caller-supplied "../../etc/passwd" would happily escape the volume.
func TestVolumeFsPathEscape(t *testing.T) {
	root := t.TempDir()
	fs := &VolumeFs{root: root}

	cases := []struct {
		name string
		rel  string
	}{
		{"parent traversal", "../escape"},
		{"deep traversal", "a/b/../../../escape"},
		{"absolute path", "/etc/passwd"},
		{"absolute under root", filepath.Join(root, "..", "escape")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := fs.Read(c.rel); !errors.Is(err, ErrPathEscape) {
				t.Errorf("Read(%q): want ErrPathEscape, got %v", c.rel, err)
			}
			if err := fs.Write(c.rel, []byte("x")); !errors.Is(err, ErrPathEscape) {
				t.Errorf("Write(%q): want ErrPathEscape, got %v", c.rel, err)
			}
			if _, err := fs.Exists(c.rel); !errors.Is(err, ErrPathEscape) {
				t.Errorf("Exists(%q): want ErrPathEscape, got %v", c.rel, err)
			}
			if err := fs.Remove(c.rel); !errors.Is(err, ErrPathEscape) {
				t.Errorf("Remove(%q): want ErrPathEscape, got %v", c.rel, err)
			}
		})
	}
}

// Sanity: legitimate paths still work end-to-end.
func TestVolumeFsHappyPath(t *testing.T) {
	root := t.TempDir()
	fs := &VolumeFs{root: root}

	if err := fs.Mkdir("sub/dir"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := fs.WriteString("sub/dir/file.txt", "hi"); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := fs.ReadString("sub/dir/file.txt")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got != "hi" {
		t.Errorf("Read: got %q want %q", got, "hi")
	}

	ok, err := fs.Exists("sub/dir/file.txt")
	if err != nil || !ok {
		t.Fatalf("Exists: got %v, %v", ok, err)
	}

	// Confirm the file actually lives under root.
	abs := filepath.Join(root, "sub", "dir", "file.txt")
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("expected file at %q: %v", abs, err)
	}
}

func TestVolumeFsEmptyRoot(t *testing.T) {
	fs := &VolumeFs{root: ""}
	if _, err := fs.Read("anything"); err == nil {
		t.Error("expected error on empty root")
	}
}

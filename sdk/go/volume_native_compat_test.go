//go:build microsandbox_ffi_path

package microsandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestVolumeFsRemoveEmptyRoot(t *testing.T) {
	setupNative(t)
	for _, path := range []string{"", "."} {
		t.Run(path, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "volume")
			if err := os.Mkdir(root, 0o755); err != nil {
				t.Fatal(err)
			}
			fs := &VolumeFs{root: root}
			if err := fs.Remove(context.Background(), path); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(root); !os.IsNotExist(err) {
				t.Fatalf("root remains: %v", err)
			}
		})
	}
}

func TestVolumeFsMissingRoot(t *testing.T) {
	setupNative(t)
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "parent", "volume")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	fs := &VolumeFs{root: root}
	if err := os.RemoveAll(filepath.Dir(root)); err != nil {
		t.Fatal(err)
	}
	if exists, err := fs.Exists(ctx, "file"); err != nil || exists {
		t.Errorf("Exists after root removal = %v, %v; want false, nil", exists, err)
	}
	if err := fs.Mkdir(ctx, "sub/dir"); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteString(ctx, "sub/dir/file", "restored"); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(root, "sub", "dir", "file")); err != nil || string(data) != "restored" {
		t.Fatalf("recreated root: %q, %v", data, err)
	}
}

func TestVolumeFsPreservesOSErrors(t *testing.T) {
	setupNative(t)
	ctx := context.Background()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nonempty"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nonempty", "file"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "file"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	fs := &VolumeFs{root: root}
	// Compare with the actual host OS, rather than assuming errno values are
	// interchangeable between Unix platforms and Windows.
	cases := []struct {
		name     string
		baseline func() error
		volume   func() error
	}{
		{"read missing", func() error { _, err := os.ReadFile(filepath.Join(root, "missing")); return err }, func() error { _, err := fs.Read(ctx, "missing"); return err }},
		{"read missing parent", func() error { _, err := os.ReadFile(filepath.Join(root, "missing", "file")); return err }, func() error { _, err := fs.Read(ctx, "missing/file"); return err }},
		{"write missing parent", func() error { return os.WriteFile(filepath.Join(root, "missing", "file"), nil, 0o644) }, func() error { return fs.Write(ctx, "missing/file", nil) }},
		{"remove missing parent", func() error { return os.Remove(filepath.Join(root, "missing", "file")) }, func() error { return fs.Remove(ctx, "missing/file") }},
		{"mkdir existing file", func() error { return os.MkdirAll(filepath.Join(root, "file"), 0o755) }, func() error { return fs.Mkdir(ctx, "file") }},
		{"remove nonempty", func() error { return os.Remove(filepath.Join(root, "nonempty")) }, func() error { return fs.Remove(ctx, "nonempty") }},
		{"remove nonempty root", func() error { return os.Remove(root) }, func() error { return fs.Remove(ctx, ".") }},
		{"write directory", func() error { return os.WriteFile(filepath.Join(root, "nonempty"), nil, 0o644) }, func() error { return fs.Write(ctx, "nonempty", nil) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			want, got := c.baseline(), c.volume()
			var errno syscall.Errno
			if !errors.As(want, &errno) {
				t.Fatalf("baseline has no errno: %v", want)
			}
			if !errors.Is(got, errno) {
				t.Errorf("got %T %v; want matching OS error %v", got, got, want)
			}
			var pathError *os.PathError
			if !errors.As(got, &pathError) {
				t.Errorf("lost *os.PathError: %T", got)
			}
			if os.IsNotExist(got) != os.IsNotExist(want) || os.IsExist(got) != os.IsExist(want) || os.IsPermission(got) != os.IsPermission(want) {
				t.Errorf("lost standard OS error classification: got %v; want %v", got, want)
			}
		})
	}
	if data, err := os.ReadFile(filepath.Join(root, "nonempty", "file")); err != nil || string(data) != "keep" {
		t.Fatalf("failed nonrecursive removal changed contents: %q, %v", data, err)
	}
}

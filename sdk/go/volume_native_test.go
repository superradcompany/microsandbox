//go:build microsandbox_ffi_path

package microsandbox

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Sanity: legitimate paths still work end-to-end.
func TestVolumeFsHappyPath(t *testing.T) {
	setupNative(t)
	ctx := context.Background()
	root := t.TempDir()
	fs := &VolumeFs{root: root}

	if err := fs.Mkdir(ctx, "sub/dir"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := fs.WriteString(ctx, "sub/dir/file.txt", "hi"); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := fs.ReadString(ctx, "sub/dir/file.txt")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got != "hi" {
		t.Errorf("Read: got %q want %q", got, "hi")
	}

	ok, err := fs.Exists(ctx, "sub/dir/file.txt")
	if err != nil || !ok {
		t.Fatalf("Exists: got %v, %v", ok, err)
	}

	// Confirm the file actually lives under root.
	abs := filepath.Join(root, "sub", "dir", "file.txt")
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("expected file at %q: %v", abs, err)
	}
}

// Exercise the real native boundary: checking or cleaning a host path before
// os.ReadFile/os.WriteFile is insufficient when an intermediate entry is a link.
func TestVolumeFsConfinesLinksAndMissingPaths(t *testing.T) {
	setupNative(t)
	ctx := context.Background()
	root, outside := t.TempDir(), t.TempDir()
	fs := &VolumeFs{root: root}
	sentinel := filepath.Join(outside, "sentinel")
	if err := os.WriteFile(sentinel, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{
		"escape":   outside,
		"dangling": filepath.Join(outside, "new"),
	} {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	for _, path := range []string{"escape/sentinel", "dangling/file", "missing/../../outside"} {
		for name, operation := range map[string]func() error{
			"read":       func() error { _, err := fs.Read(ctx, path); return err },
			"write":      func() error { return fs.Write(ctx, path, []byte("changed")) },
			"mkdir":      func() error { return fs.Mkdir(ctx, path) },
			"exists":     func() error { _, err := fs.Exists(ctx, path); return err },
			"remove":     func() error { return fs.Remove(ctx, path) },
			"remove all": func() error { return fs.RemoveAll(ctx, path) },
		} {
			t.Run(name+"/"+path, func(t *testing.T) {
				if err := operation(); !errors.Is(err, ErrPathEscape) {
					t.Fatalf("want ErrPathEscape, got %v", err)
				}
			})
		}
	}
	if data, err := os.ReadFile(sentinel); err != nil || string(data) != "outside" {
		t.Fatalf("outside marker changed: %q, %v", data, err)
	}
	if entries, err := os.ReadDir(outside); err != nil || len(entries) != 1 {
		t.Fatalf("outside directory changed: %v, %v", entries, err)
	}
	// A final symlink is safe to unlink: removing it must preserve its target.
	if err := fs.RemoveAll(ctx, "escape"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("RemoveAll followed the final link: %v", err)
	}
}

func TestVolumeFsPreservesGoFilesystemSemantics(t *testing.T) {
	setupNative(t)
	ctx := context.Background()
	root := t.TempDir()
	fs := &VolumeFs{root: root}
	if err := fs.WriteString(ctx, "missing/file", "data"); !os.IsNotExist(err) {
		t.Fatalf("Write must retain missing-parent error, got %v", err)
	}
	if err := fs.Mkdir(ctx, "nested/empty"); err != nil {
		t.Fatal(err)
	}
	if err := fs.Remove(ctx, "nested/empty"); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteString(ctx, "nested/file", "inside"); err != nil {
		t.Fatal(err)
	}
	if err := fs.Remove(ctx, "nested"); err == nil {
		t.Fatal("Remove must not remove a nonempty directory")
	}
	if err := os.Symlink("nested", filepath.Join(root, "relative")); err != nil {
		t.Skip(err)
	}
	if err := os.Symlink(filepath.Join(root, "nested"), filepath.Join(root, "absolute")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"relative/file", "absolute/file", "nested/../nested/file"} {
		if got, err := fs.ReadString(ctx, path); err != nil || got != "inside" {
			t.Fatalf("%s: %q, %v", path, got, err)
		}
	}
	if err := fs.RemoveAll(ctx, "nested/file"); err != nil {
		t.Fatal(err)
	}
	if err := fs.RemoveAll(ctx, "missing"); err != nil {
		t.Fatal(err)
	}
	if err := fs.RemoveAll(ctx, "nested"); err != nil {
		t.Fatal(err)
	}
	if exists, err := fs.Exists(ctx, "nested"); err != nil || exists {
		t.Fatalf("Exists = %v, %v", exists, err)
	}
}

func TestVolumeFsKeepsRetainedRoot(t *testing.T) {
	setupNative(t)
	root := t.TempDir()
	fs := &VolumeFs{root: root, target: "same-name"}
	// An unrelated active home must never rebind this previously returned handle.
	t.Setenv("MSB_HOME", t.TempDir())
	if err := fs.WriteString(context.Background(), "marker", "original"); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(root, "marker")); err != nil || string(data) != "original" {
		t.Fatalf("retained root lost: %q, %v", data, err)
	}
}

// Crossing the native JSON boundary must not add a one-megabyte read limit.
func TestVolumeFsReadsLargeFiles(t *testing.T) {
	setupNative(t)
	fs := &VolumeFs{root: t.TempDir()}
	want := bytes.Repeat([]byte("volume-data"), 200000)
	if err := fs.Write(context.Background(), "large", want); err != nil {
		t.Fatal(err)
	}
	got, err := fs.Read(context.Background(), "large")
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("large read: %d bytes, %v", len(got), err)
	}
}

func TestVolumeFsRelocatedRoot(t *testing.T) {
	setupNative(t)
	parent, moved := t.TempDir(), t.TempDir()
	root := filepath.Join(parent, "volume")
	if err := os.Symlink(moved, root); err != nil {
		t.Skip(err)
	}
	fs := &VolumeFs{root: root}
	ctx := context.Background()
	if err := fs.WriteString(ctx, "marker", "inside"); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(moved, "marker")); err != nil || string(data) != "inside" {
		t.Fatalf("relocated root: %q, %v", data, err)
	}
	// Go's historical RemoveAll unlinks a root link rather than its target.
	if err := fs.RemoveAll(ctx, "."); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("root link remains: %v", err)
	}
	if _, err := os.Stat(filepath.Join(moved, "marker")); err != nil {
		t.Fatal(err)
	}
}

func TestVolumeFsRemovesDirectoryLinks(t *testing.T) {
	setupNative(t)
	for _, recursive := range []bool{false, true} {
		for _, dangling := range []bool{false, true} {
			root, outside := t.TempDir(), t.TempDir()
			target := filepath.Join(outside, "target")
			if err := os.Mkdir(target, 0o755); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(root, "link")
			if err := os.Symlink(target, link); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			// Create the link while the directory exists so Windows records its
			// directory type, then remove the target to exercise dangling cleanup.
			if dangling {
				if err := os.Remove(target); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(filepath.Join(target, "sentinel"), []byte("outside"), 0o644); err != nil {
				t.Fatal(err)
			}
			fs := &VolumeFs{root: root}
			var err error
			if recursive {
				err = fs.RemoveAll(context.Background(), "link")
			} else {
				err = fs.Remove(context.Background(), "link")
			}
			if err != nil {
				t.Fatalf("remove directory link (recursive=%v, dangling=%v): %v", recursive, dangling, err)
			}
			if _, err := os.Lstat(link); !os.IsNotExist(err) {
				t.Fatalf("link remains: %v", err)
			}
			if !dangling {
				if data, err := os.ReadFile(filepath.Join(target, "sentinel")); err != nil || string(data) != "outside" {
					t.Fatalf("link target changed: %q, %v", data, err)
				}
			}
		}
	}
}

func TestVolumeFsRemoveAllRoot(t *testing.T) {
	setupNative(t)
	for _, path := range []string{"", ".", "nested/.."} {
		t.Run(path, func(t *testing.T) {
			parent, outside := t.TempDir(), t.TempDir()
			root := filepath.Join(parent, "volume")
			if err := os.MkdirAll(filepath.Join(root, "nested"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(outside, "sentinel"), []byte("outside"), 0o644); err != nil {
				t.Fatal(err)
			}
			// A descendant link must be removed without traversing its target.
			if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
				t.Logf("symlink unavailable: %v", err)
			}
			fs := &VolumeFs{root: root}
			if err := fs.RemoveAll(context.Background(), path); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(root); !os.IsNotExist(err) {
				t.Fatalf("root remains: %v", err)
			}
			if data, err := os.ReadFile(filepath.Join(outside, "sentinel")); err != nil || string(data) != "outside" {
				t.Fatalf("outside changed: %q, %v", data, err)
			}
			if err := fs.RemoveAll(context.Background(), "."); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestVolumeFsRejectsAmbiguousParentAfterLink(t *testing.T) {
	setupNative(t)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "nested", "deep"), 0o755); err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string]string{"config": "A", "nested/config": "B"} {
		if err := os.WriteFile(filepath.Join(root, path), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("nested/deep", filepath.Join(root, "link")); err != nil {
		t.Skip(err)
	}
	fs := &VolumeFs{root: root}
	ctx := context.Background()
	for name, op := range map[string]func() error{
		"write":  func() error { return fs.WriteString(ctx, "link/../config", "changed") },
		"read":   func() error { _, err := fs.Read(ctx, "link/../config"); return err },
		"remove": func() error { return fs.RemoveAll(ctx, "link/../config") },
	} {
		t.Run(name, func(t *testing.T) {
			if err := op(); err == nil {
				t.Fatal("ambiguous operation succeeded")
			}
		})
	}
	for path, data := range map[string]string{"config": "A", "nested/config": "B", "nested/../config": "A", "missing/../config": "A"} {
		if got, err := fs.ReadString(ctx, path); err != nil || got != data {
			t.Fatalf("%s: %q, %v", path, got, err)
		}
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(alias, "config"), filepath.Join(root, "alternate")); err != nil {
		t.Fatal(err)
	}
	if got, err := fs.ReadString(ctx, "alternate"); err != nil || got != "A" {
		t.Fatalf("alternate link: %q, %v", got, err)
	}
}

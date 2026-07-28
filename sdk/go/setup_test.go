package microsandbox

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestPlatformRuntimeFiles(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		goos      string
		msb       string
		libkrunfw string
		symlinks  [][2]string
	}{
		{
			name:      "darwin",
			goos:      "darwin",
			msb:       "msb",
			libkrunfw: "libkrunfw.5.dylib",
			symlinks:  [][2]string{{"libkrunfw.dylib", "libkrunfw.5.dylib"}},
		},
		{
			name:      "linux",
			goos:      "linux",
			msb:       "msb",
			libkrunfw: "libkrunfw.so.5.6.0",
			symlinks: [][2]string{
				{"libkrunfw.so.5", "libkrunfw.so.5.6.0"},
				{"libkrunfw.so", "libkrunfw.so.5"},
			},
		},
		{
			name:      "windows",
			goos:      "windows",
			msb:       "msb.exe",
			libkrunfw: "libkrunfw.dll",
			symlinks:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := msbFilenameFor(tt.goos); got != tt.msb {
				t.Errorf("msbFilenameFor(%q) = %q, want %q", tt.goos, got, tt.msb)
			}
			if got := libkrunfwFilenameFor(tt.goos); got != tt.libkrunfw {
				t.Errorf("libkrunfwFilenameFor(%q) = %q, want %q", tt.goos, got, tt.libkrunfw)
			}
			if got := libkrunfwSymlinksFor(tt.goos); !reflect.DeepEqual(got, tt.symlinks) {
				t.Errorf("libkrunfwSymlinksFor(%q) = %#v, want %#v", tt.goos, got, tt.symlinks)
			}
		})
	}
}

func TestOSStringFor(t *testing.T) {
	t.Parallel()

	for _, goos := range []string{"darwin", "linux", "windows"} {
		goos := goos
		t.Run(goos, func(t *testing.T) {
			t.Parallel()
			got, err := osStringFor(goos)
			if err != nil {
				t.Fatalf("osStringFor(%q): %v", goos, err)
			}
			if got != goos {
				t.Errorf("osStringFor(%q) = %q, want %q", goos, got, goos)
			}
		})
	}

	if _, err := osStringFor("freebsd"); err == nil {
		t.Fatal("osStringFor(\"freebsd\") succeeded, want unsupported-platform error")
	}
}

func TestExtractMsbAndKrunfwWindowsBundle(t *testing.T) {
	t.Parallel()

	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	files := []struct {
		name string
		data string
	}{
		{name: "msb.exe", data: "msb"},
		{name: "libkrunfw.dll", data: "krunfw"},
		{name: "libmicrosandbox_go_ffi.dll", data: "ffi"},
	}
	for _, file := range files {
		hdr := &tar.Header{
			Name: file.name,
			Mode: 0o755,
			Size: int64(len(file.data)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
		if _, err := tw.Write([]byte(file.data)); err != nil {
			t.Fatalf("write tar data: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}

	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	libDir := filepath.Join(root, "lib")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("create bin dir: %v", err)
	}
	if err := os.MkdirAll(libDir, 0o755); err != nil {
		t.Fatalf("create lib dir: %v", err)
	}
	if err := extractMsbAndKrunfw(bytes.NewReader(archive.Bytes()), binDir, libDir); err != nil {
		t.Fatalf("extract Windows bundle: %v", err)
	}

	assertFileContents(t, filepath.Join(binDir, "msb.exe"), "msb")
	assertFileContents(t, filepath.Join(libDir, "libkrunfw.dll"), "krunfw")
	if _, err := os.Stat(filepath.Join(libDir, "libmicrosandbox_go_ffi.dll")); !os.IsNotExist(err) {
		t.Fatalf("embedded FFI library should not be extracted, stat error = %v", err)
	}
}

func assertFileContents(t *testing.T, path, want string) {
	t.Helper()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != want {
		t.Errorf("%s contents = %q, want %q", path, got, want)
	}
}

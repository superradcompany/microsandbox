package microsandbox

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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
			libkrunfw: "libkrunfw.so.5.6.1",
			symlinks: [][2]string{
				{"libkrunfw.so.5", "libkrunfw.so.5.6.1"},
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

func TestBundleDigestFromChecksums(t *testing.T) {
	t.Parallel()

	linuxDigest := strings.Repeat("ab", 32)
	darwinDigest := strings.Repeat("CD", 32)
	checksums := linuxDigest + "  microsandbox-linux-x86_64.tar.gz\n" +
		darwinDigest + " *microsandbox-darwin-aarch64.tar.gz\n" +
		"malformed line\n"

	got, err := bundleDigestFromChecksums(checksums, "microsandbox-linux-x86_64.tar.gz")
	if err != nil {
		t.Fatalf("bundleDigestFromChecksums: %v", err)
	}
	if got != linuxDigest {
		t.Errorf("digest = %q, want %q", got, linuxDigest)
	}

	// Binary-mode "*" markers are stripped and digests normalized to
	// lowercase.
	got, err = bundleDigestFromChecksums(checksums, "microsandbox-darwin-aarch64.tar.gz")
	if err != nil {
		t.Fatalf("bundleDigestFromChecksums: %v", err)
	}
	if got != strings.ToLower(darwinDigest) {
		t.Errorf("digest = %q, want %q", got, strings.ToLower(darwinDigest))
	}

	if _, err := bundleDigestFromChecksums(checksums, "microsandbox-windows-x86_64.tar.gz"); err == nil ||
		!strings.Contains(err.Error(), "microsandbox-windows-x86_64.tar.gz") {
		t.Errorf("missing entry error = %v, want mention of the bundle filename", err)
	}

	if _, err := bundleDigestFromChecksums("nothex  bundle.tar.gz\n", "bundle.tar.gz"); err == nil ||
		!strings.Contains(err.Error(), "invalid SHA-256") {
		t.Errorf("invalid digest error = %v, want invalid SHA-256 error", err)
	}
}

// makeBundleTarball builds an in-memory tar.gz shaped like a release bundle
// for the current platform.
func makeBundleTarball(t *testing.T) []byte {
	t.Helper()

	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	files := []struct {
		name string
		data string
	}{
		{name: msbFilename(), data: "msb"},
		{name: libkrunfwFilename(), data: "krunfw"},
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
	return archive.Bytes()
}

// Not parallel: overrides releaseDownloadBase, which parallel tests must
// not observe.
func TestDownloadMsbAndKrunfwVerifiesBundleDigest(t *testing.T) {
	bundle := makeBundleTarball(t)
	sum := sha256.Sum256(bundle)
	digest := hex.EncodeToString(sum[:])
	filename, err := bundleFilename()
	if err != nil {
		t.Fatalf("bundleFilename: %v", err)
	}

	tests := []struct {
		name            string
		checksums       string
		checksumsStatus int
		wantErr         string
	}{
		{
			name:      "verified install",
			checksums: digest + "  " + filename + "\n",
		},
		{
			name:      "digest mismatch",
			checksums: strings.Repeat("0", 64) + "  " + filename + "\n",
			wantErr:   "SHA-256 mismatch",
		},
		{
			name:            "checksums unavailable",
			checksumsStatus: http.StatusNotFound,
			wantErr:         "fetch release checksums",
		},
		{
			name:      "missing bundle entry",
			checksums: digest + "  other.tar.gz\n",
			wantErr:   "no entry for",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v" + sdkVersion + "/checksums.sha256":
					if tt.checksumsStatus != 0 {
						w.WriteHeader(tt.checksumsStatus)
						return
					}
					_, _ = w.Write([]byte(tt.checksums))
				case "/v" + sdkVersion + "/" + filename:
					_, _ = w.Write(bundle)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer srv.Close()

			orig := releaseDownloadBase
			releaseDownloadBase = srv.URL
			defer func() { releaseDownloadBase = orig }()

			dir := t.TempDir()
			err := downloadMsbAndKrunfw(context.Background(), dir)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("downloadMsbAndKrunfw: %v", err)
				}
				assertFileContents(t, filepath.Join(dir, "bin", msbFilename()), "msb")
				assertFileContents(t, filepath.Join(dir, "lib", libkrunfwFilename()), "krunfw")
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("downloadMsbAndKrunfw error = %v, want containing %q", err, tt.wantErr)
			}
			if _, statErr := os.Stat(filepath.Join(dir, "bin", msbFilename())); !os.IsNotExist(statErr) {
				t.Fatalf("msb must not be extracted when verification fails, stat error = %v", statErr)
			}
		})
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

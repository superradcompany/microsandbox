package microsandbox

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// sdkVersion is the microsandbox release that this SDK binds to. The
// EnsureInstalled downloader fetches runtime artefacts (msb + libkrunfw +
// libmicrosandbox_go_ffi) from the matching GitHub release. Bump in lockstep
// with the workspace Cargo.toml version and with sdk/node-ts/package.json.
const sdkVersion = "0.3.13"

// libkrunfwABI is the major SONAME version of libkrunfw that msb links
// against. Mirrors LIBKRUNFW_ABI in sdk/node-ts/postinstall.js.
const libkrunfwABI = "5"

// libkrunfwVersion is the full version of the prebuilt libkrunfw shipped in
// each release tarball. Mirrors LIBKRUNFW_VERSION in postinstall.js.
const libkrunfwVersion = "5.2.1"

// githubOrg / githubRepo locate the GitHub release assets.
const (
	githubOrg  = "superradcompany"
	githubRepo = "microsandbox"
)

// Environment variable overrides — intended for development against
// unreleased builds. If set, EnsureInstalled skips the download entirely.
const (
	// EnvLibPath overrides the path to libmicrosandbox_go_ffi.{dylib,so}.
	// Identical to ffi.MICROSANDBOX_LIB_PATH.
	EnvLibPath = "MICROSANDBOX_LIB_PATH"

	// EnvSkipDownload, if set to a truthy value, disables the automatic
	// download and assumes the user has placed the artefacts by hand.
	EnvSkipDownload = "MICROSANDBOX_SKIP_DOWNLOAD"
)

// httpTimeout bounds the full bundle download. 5 minutes is generous for a
// ~100 MiB tarball on a slow link.
const httpTimeout = 5 * time.Minute

// ensureInstallOnce serialises concurrent EnsureInstalled callers.
var ensureInstallOnce sync.Mutex

// EnsureInstalled makes sure the microsandbox runtime (the shared library
// this SDK calls into, plus the msb launcher and libkrunfw) is present on
// the host and loads the library into the current process.
//
// Call this once at program startup before any other SDK function:
//
//	if err := microsandbox.EnsureInstalled(ctx); err != nil {
//	    log.Fatal(err)
//	}
//
// It is idempotent: if the runtime is already present at the pinned version,
// it only performs a dlopen. If the runtime is missing or out of date, it
// downloads the release bundle matching this SDK version from GitHub and
// installs it under ~/.microsandbox/.
//
// Set MICROSANDBOX_LIB_PATH to a pre-built libmicrosandbox_go_ffi on disk
// to bypass the download (useful for development builds).
func EnsureInstalled(ctx context.Context) error {
	ensureInstallOnce.Lock()
	defer ensureInstallOnce.Unlock()

	if ffi.IsLoaded() {
		return nil
	}

	// Honor the developer override: if MICROSANDBOX_LIB_PATH is set, load
	// it straight away and skip the bundle logic entirely. The user is
	// responsible for making sure msb + libkrunfw are also available.
	if override := os.Getenv(EnvLibPath); override != "" {
		if err := ffi.Load(override); err != nil {
			return newErrLoad(err)
		}
		return nil
	}

	baseDir, err := defaultInstallDir()
	if err != nil {
		return err
	}
	binDir := filepath.Join(baseDir, "bin")
	libDir := filepath.Join(baseDir, "lib")

	// Fast path: everything is already on disk at the pinned version.
	if bundleInstalled(binDir, libDir) {
		return loadFromLibDir(libDir)
	}

	if truthy(os.Getenv(EnvSkipDownload)) {
		return &Error{
			Kind: ErrLibraryNotLoaded,
			Message: fmt.Sprintf(
				"microsandbox runtime not installed at %s and %s is set; "+
					"install the runtime manually or unset the variable",
				baseDir, EnvSkipDownload),
		}
	}

	if err := downloadAndExtract(ctx, baseDir); err != nil {
		return &Error{
			Kind:    ErrLibraryNotLoaded,
			Message: fmt.Sprintf("download microsandbox runtime: %v", err),
			Cause:   err,
		}
	}

	return loadFromLibDir(libDir)
}

// IsInstalled reports whether the runtime artefacts (msb, libkrunfw, and the
// Go FFI shared library) are present under ~/.microsandbox/ at the SDK's
// pinned version. It does NOT dlopen the library.
func IsInstalled() bool {
	baseDir, err := defaultInstallDir()
	if err != nil {
		return false
	}
	return bundleInstalled(filepath.Join(baseDir, "bin"), filepath.Join(baseDir, "lib"))
}

// defaultInstallDir returns ~/.microsandbox, creating it on first access.
func defaultInstallDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, ".microsandbox"), nil
}

// loadFromLibDir resolves the platform library name under libDir and calls
// ffi.Load.
func loadFromLibDir(libDir string) error {
	libPath := filepath.Join(libDir, goFFILibName())
	if err := ffi.Load(libPath); err != nil {
		return newErrLoad(err)
	}
	return nil
}

// newErrLoad wraps a raw ffi.Load error in a typed *Error.
func newErrLoad(err error) error {
	return &Error{
		Kind:    ErrLibraryNotLoaded,
		Message: fmt.Sprintf("load microsandbox library: %v", err),
		Cause:   err,
	}
}

// bundleInstalled reports whether msb, libkrunfw, and the Go FFI library are
// all present and msb is at the expected version.
func bundleInstalled(binDir, libDir string) bool {
	msbBin := filepath.Join(binDir, "msb")
	if _, err := os.Stat(msbBin); err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(libDir, libkrunfwFilename())); err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(libDir, goFFILibName())); err != nil {
		return false
	}
	return installedMsbVersion(msbBin) == sdkVersion
}

// installedMsbVersion runs `msb --version` and returns the version string,
// or "" on any error. Matches installedMsbVersion in postinstall.js.
func installedMsbVersion(msbPath string) string {
	out, err := exec.Command(msbPath, "--version").Output()
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(out))
	if !strings.HasPrefix(s, "msb ") {
		return ""
	}
	return strings.TrimPrefix(s, "msb ")
}

// goFFILibName returns the platform-specific filename of the Go FFI cdylib.
func goFFILibName() string {
	if runtime.GOOS == "darwin" {
		return "libmicrosandbox_go_ffi.dylib"
	}
	return "libmicrosandbox_go_ffi.so"
}

// libkrunfwFilename returns the exact filename of the prebuilt libkrunfw
// for the current platform.
func libkrunfwFilename() string {
	if runtime.GOOS == "darwin" {
		return fmt.Sprintf("libkrunfw.%s.dylib", libkrunfwABI)
	}
	return fmt.Sprintf("libkrunfw.so.%s", libkrunfwVersion)
}

// libkrunfwSymlinks returns (linkName, target) pairs mirroring
// libkrunfwSymlinks() in postinstall.js. Without these symlinks the dynamic
// linker cannot resolve the libkrunfw SONAME that msb was built against.
func libkrunfwSymlinks() [][2]string {
	full := libkrunfwFilename()
	if runtime.GOOS == "darwin" {
		return [][2]string{{"libkrunfw.dylib", full}}
	}
	soname := fmt.Sprintf("libkrunfw.so.%s", libkrunfwABI)
	return [][2]string{
		{soname, full},
		{"libkrunfw.so", soname},
	}
}

// archString converts Go's runtime.GOARCH into the tag used in release
// asset filenames ("aarch64" or "x86_64").
func archString() (string, error) {
	switch runtime.GOARCH {
	case "arm64":
		return "aarch64", nil
	case "amd64":
		return "x86_64", nil
	default:
		return "", fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)
	}
}

// osString converts Go's runtime.GOOS into the tag used in release assets.
func osString() (string, error) {
	switch runtime.GOOS {
	case "darwin", "linux":
		return runtime.GOOS, nil
	default:
		return "", fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// bundleURL is the GitHub release asset URL for the current OS/arch.
func bundleURL() (string, error) {
	arch, err := archString()
	if err != nil {
		return "", err
	}
	osName, err := osString()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(
		"https://github.com/%s/%s/releases/download/v%s/%s-%s-%s.tar.gz",
		githubOrg, githubRepo, sdkVersion, githubRepo, osName, arch,
	), nil
}

// downloadAndExtract fetches the release bundle and extracts its contents
// into ~/.microsandbox/{bin,lib}/, then materialises the libkrunfw SONAME
// symlinks the dynamic linker needs.
func downloadAndExtract(ctx context.Context, baseDir string) error {
	binDir := filepath.Join(baseDir, "bin")
	libDir := filepath.Join(baseDir, "lib")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(libDir, 0o755); err != nil {
		return err
	}

	url, err := bundleURL()
	if err != nil {
		return err
	}

	reqCtx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	client := &http.Client{
		// http.Client follows up to 10 redirects by default, which matches
		// the behaviour in postinstall.js (GitHub release assets issue a
		// 302 to the CDN).
		Timeout: httpTimeout,
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}

	if err := extractBundle(resp.Body, binDir, libDir); err != nil {
		return err
	}

	// Create libkrunfw SONAME symlinks. Without them ld.so can't find the
	// library msb was linked against.
	for _, pair := range libkrunfwSymlinks() {
		linkPath := filepath.Join(libDir, pair[0])
		target := pair[1]
		_ = os.Remove(linkPath) // ignore ENOENT
		if err := os.Symlink(target, linkPath); err != nil {
			return fmt.Errorf("symlink %s -> %s: %w", linkPath, target, err)
		}
	}

	// Sanity check.
	if _, err := os.Stat(filepath.Join(binDir, "msb")); err != nil {
		return fmt.Errorf("msb not found after extraction: %w", err)
	}
	if _, err := os.Stat(filepath.Join(libDir, libkrunfwFilename())); err != nil {
		return fmt.Errorf("%s not found after extraction: %w", libkrunfwFilename(), err)
	}
	if _, err := os.Stat(filepath.Join(libDir, goFFILibName())); err != nil {
		return fmt.Errorf("%s not found after extraction: %w", goFFILibName(), err)
	}
	return nil
}

// extractBundle streams a tar.gz from r and copies each file into binDir or
// libDir depending on its name. Non-regular files (symlinks in the archive,
// directories) are skipped — symlinks are materialised separately.
func extractBundle(r io.Reader, binDir, libDir string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		// The release tarball is flat — no subdirectories. Strip any path
		// components defensively so we can't write outside {bin,lib}/.
		name := filepath.Base(hdr.Name)
		if name == "" || name == "." || name == ".." {
			continue
		}

		var dest string
		switch {
		case strings.HasPrefix(name, "libkrunfw"),
			strings.HasPrefix(name, "libmicrosandbox_go_ffi"):
			dest = filepath.Join(libDir, name)
		default:
			dest = filepath.Join(binDir, name)
		}

		if err := writeFile(dest, tr, 0o755); err != nil {
			return err
		}
	}
	return nil
}

// writeFile atomically writes src into dest with the given mode. Writes to a
// sibling tempfile first so a crashed download can't leave a half-written
// msb binary on disk.
func writeFile(dest string, src io.Reader, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".microsandbox-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	if _, err := io.Copy(tmp, src); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("write %s: %w", dest, err)
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("chmod %s: %w", dest, err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, dest); err != nil {
		cleanup()
		return fmt.Errorf("rename %s -> %s: %w", tmpName, dest, err)
	}
	return nil
}

// truthy reports whether s is a common "on" value. Matches the convention
// used by most Go libraries for boolean env vars.
func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

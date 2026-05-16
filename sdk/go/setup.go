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

	"github.com/superradcompany/microsandbox/sdk/go/internal/bundle"
	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// sdkVersion is the microsandbox release that this SDK binds to. The
// embedded FFI library and the downloaded msb+libkrunfw artefacts are
// both pinned to this version. Bump when cutting a new SDK release so
// it matches published binaries.
const sdkVersion = "0.4.6"

// libkrunfwABI is the major SONAME version of libkrunfw that msb links
// against.
const libkrunfwABI = "5"

// libkrunfwVersion is the full version of the prebuilt libkrunfw shipped in
// each release tarball.
const libkrunfwVersion = "5.2.1"

// githubOrg / githubRepo locate the GitHub release assets for the
// msb + libkrunfw download (FFI library ships embedded in the SDK).
const (
	githubOrg  = "superradcompany"
	githubRepo = "microsandbox"
)

// httpTimeout bounds the msb + libkrunfw bundle download.
const httpTimeout = 5 * time.Minute

// SetupOption configures EnsureInstalled.
type SetupOption func(*setupConfig)

type setupConfig struct {
	skipDownload bool
}

// WithSkipDownload prevents EnsureInstalled from fetching the msb +
// libkrunfw bundle from GitHub releases. Use when the runtime is
// already on disk at the install path (e.g. air-gapped CI, vendored
// fixtures). The embedded FFI library is unaffected — it ships with
// the SDK and is materialized automatically on first use.
func WithSkipDownload() SetupOption {
	return func(c *setupConfig) { c.skipDownload = true }
}

// init wires the FFI auto-loader so the first SDK call (e.g.
// CreateSandbox) transparently extracts + dlopens the embedded
// library. No explicit EnsureInstalled call is needed for FFI
// bootstrap.
func init() {
	ffi.SetAutoLoader(autoLoadFFI)
}

var (
	autoLoadOnce sync.Once
	autoLoadErr  error
)

// autoLoadFFI extracts the embedded FFI library into the install
// directory and dlopens it. Registered with the internal/ffi package
// via SetAutoLoader so ensureLoaded() drives it lazily on first use.
// sync.Once-guarded; safe to call from concurrent SDK goroutines.
//
// This handles ONLY the FFI plumbing — msb + libkrunfw downloading
// is the explicit job of EnsureInstalled.
func autoLoadFFI() error {
	autoLoadOnce.Do(func() {
		dir, err := installDir()
		if err != nil {
			autoLoadErr = err
			return
		}
		ffiPath, err := materializeFFI(dir)
		if err != nil {
			autoLoadErr = err
			return
		}
		if err := ffi.Load(ffiPath); err != nil {
			autoLoadErr = wrapDlopenErr(err, ffiPath)
			return
		}
		// Pin the resolver's SDK-tier msb path to our install dir.
		ffi.SetSdkMsbPath(filepath.Join(dir, "bin", "msb"))
	})
	return autoLoadErr
}

var (
	installMu   sync.Mutex
	installDone bool
)

// EnsureInstalled ensures the msb + libkrunfw runtime is present at
// ~/.microsandbox/ and downloads it from the matching GitHub release
// if not. It is OPTIONAL: the SDK's FFI library is embedded in the
// Go binary and loads automatically on first use, so EnsureInstalled
// only governs the optional msb runtime download.
//
// Call it explicitly at startup if you want to surface install errors
// up front rather than at first sandbox-spawn time:
//
//	if err := microsandbox.EnsureInstalled(ctx); err != nil {
//	    log.Fatal(err)
//	}
//
// Idempotent — subsequent calls are no-ops. Options apply only to
// the first call.
func EnsureInstalled(ctx context.Context, opts ...SetupOption) error {
	installMu.Lock()
	defer installMu.Unlock()

	if installDone {
		return nil
	}

	cfg := setupConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}

	dir, err := installDir()
	if err != nil {
		return err
	}

	if msbAndKrunfwInstalled(dir) {
		installDone = true
		return nil
	}
	if cfg.skipDownload {
		return &Error{
			Kind: ErrLibraryNotLoaded,
			Message: fmt.Sprintf(
				"microsandbox: msb/libkrunfw not present under %s and "+
					"WithSkipDownload() was set; install them manually",
				dir),
		}
	}
	if err := downloadMsbAndKrunfw(ctx, dir); err != nil {
		return &Error{
			Kind:    ErrLibraryNotLoaded,
			Message: fmt.Sprintf("microsandbox: download msb+libkrunfw: %v", err),
			Cause:   err,
		}
	}
	installDone = true
	return nil
}

// IsInstalled reports whether msb + libkrunfw are present at
// ~/.microsandbox/ at the SDK's pinned version. It does NOT touch
// the FFI library (which ships embedded in the SDK).
func IsInstalled() bool {
	dir, err := installDir()
	if err != nil {
		return false
	}
	return msbAndKrunfwInstalled(dir)
}

// SDKVersion returns the microsandbox release version this SDK was
// compiled against.
func SDKVersion() string { return sdkVersion }

// RuntimeVersion returns the version reported by the loaded FFI
// library. Triggers FFI auto-load if needed; returns an FFI error if
// the library couldn't be loaded.
func RuntimeVersion() (string, error) {
	v, err := ffi.Version()
	return v, wrapFFI(err)
}

// installDir returns the fixed on-disk location ~/.microsandbox/.
// Not user-overridable — every Go binary that links this SDK shares
// this cache so msb + libkrunfw aren't redownloaded per consumer.
func installDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, ".microsandbox"), nil
}

// materializeFFI extracts the embedded FFI library into a per-version
// subdir under <dir>/lib/ and returns the on-disk path. The
// per-version subdir lets multiple SDK versions coexist without
// clobbering each other.
func materializeFFI(dir string) (string, error) {
	ffiBytes, err := bundle.Bytes()
	if err != nil {
		return "", &Error{Kind: ErrLibraryNotLoaded, Message: err.Error(), Cause: err}
	}
	libDir := filepath.Join(dir, "lib", "v"+sdkVersion)
	if err := os.MkdirAll(libDir, 0o755); err != nil {
		return "", fmt.Errorf("create %s: %w", libDir, err)
	}
	dest := filepath.Join(libDir, bundle.Filename())
	if existing, err := os.ReadFile(dest); err == nil && bytesEqual(existing, ffiBytes) {
		return dest, nil
	}
	if err := writeFile(dest, ffiBytes, 0o755); err != nil {
		return "", err
	}
	return dest, nil
}

// wrapDlopenErr decorates a raw ffi.Load error with the SDK version and
// a minimum-glibc hint so GLIBC mismatch failures are diagnosable.
func wrapDlopenErr(err error, path string) error {
	msg := fmt.Sprintf(
		"microsandbox: failed to load bundled FFI library %s\n  cause: %v",
		path, err,
	)
	// If the underlying loader error mentions GLIBC, add the SDK version
	// + baseline hint so users know how to recover.
	if strings.Contains(err.Error(), "GLIBC") {
		msg += fmt.Sprintf(
			"\n  hint:  this SDK release (v%s) requires glibc >= 2.28; "+
				"upgrade your distro or pin to an older SDK version",
			sdkVersion,
		)
	}
	return &Error{
		Kind:    ErrLibraryNotLoaded,
		Message: msg,
		Cause:   err,
	}
}

// msbAndKrunfwInstalled reports whether msb is present at the expected
// version and libkrunfw is present.
func msbAndKrunfwInstalled(installDir string) bool {
	msbBin := filepath.Join(installDir, "bin", "msb")
	if _, err := os.Stat(msbBin); err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(installDir, "lib", libkrunfwFilename())); err != nil {
		return false
	}
	return installedMsbVersion(msbBin) == sdkVersion
}

// installedMsbVersion runs `msb --version` and returns the version string,
// or "" on any error.
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

// libkrunfwFilename returns the exact filename of the prebuilt libkrunfw
// for the current platform.
func libkrunfwFilename() string {
	if runtime.GOOS == "darwin" {
		return fmt.Sprintf("libkrunfw.%s.dylib", libkrunfwABI)
	}
	return fmt.Sprintf("libkrunfw.so.%s", libkrunfwVersion)
}

// libkrunfwSymlinks returns (linkName, target) pairs for the libkrunfw
// SONAME layout. Without these symlinks the dynamic linker cannot resolve
// the libkrunfw SONAME that msb was built against.
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

// downloadMsbAndKrunfw fetches the release bundle and extracts msb +
// libkrunfw into <installDir>/{bin,lib}/. The FFI library inside the
// tarball is ignored (the SDK ships it embedded).
func downloadMsbAndKrunfw(ctx context.Context, installDir string) error {
	binDir := filepath.Join(installDir, "bin")
	libDir := filepath.Join(installDir, "lib")
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

	client := &http.Client{Timeout: httpTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}

	if err := extractMsbAndKrunfw(resp.Body, binDir, libDir); err != nil {
		return err
	}

	// Create libkrunfw SONAME symlinks. Without them ld.so can't find
	// the library msb was linked against.
	for _, pair := range libkrunfwSymlinks() {
		linkPath := filepath.Join(libDir, pair[0])
		target := pair[1]
		_ = os.Remove(linkPath)
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
	return nil
}

// extractMsbAndKrunfw streams a tar.gz from r and copies msb + libkrunfw*
// into the appropriate dirs. Any libmicrosandbox_go_ffi entries are
// skipped — the SDK ships its FFI library embedded.
func extractMsbAndKrunfw(r io.Reader, binDir, libDir string) error {
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

		name := filepath.Base(hdr.Name)
		if name == "" || name == "." || name == ".." {
			continue
		}
		// FFI lib travels alongside msb+libkrunfw in the legacy tarball
		// shape; we now use the embed instead. Skip it on extract.
		if strings.HasPrefix(name, "libmicrosandbox_go_ffi") {
			continue
		}

		var dest string
		switch {
		case strings.HasPrefix(name, "libkrunfw"):
			dest = filepath.Join(libDir, name)
		default:
			dest = filepath.Join(binDir, name)
		}

		buf, err := io.ReadAll(tr)
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		if err := writeFile(dest, buf, 0o755); err != nil {
			return err
		}
	}
	return nil
}

// writeFile atomically writes data to dest with the given mode. Writes to
// a sibling tempfile first so a crashed write can't leave a half-written
// file on disk.
func writeFile(dest string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".microsandbox-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	if _, err := tmp.Write(data); err != nil {
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

// bytesEqual is a tiny byte-slice equality without an `bytes` import.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

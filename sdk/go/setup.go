package microsandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/superradcompany/microsandbox/sdk/go/internal/bundle"
	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// sdkVersion is the microsandbox release that this SDK binds to. The
// embedded FFI library uses this version. Runtime downloads use the
// version pinned in that native SDK. Both are updated by the release train.
const sdkVersion = "0.6.18"

// init wires the FFI auto-loader so the first SDK call (e.g.
// CreateSandbox) transparently extracts + dlopens the embedded
// library. No explicit EnsureRuntime call is needed for FFI
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
// is the explicit job of EnsureRuntime.
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
		// The native resolver discovers the runtime home itself. Registering this
		// path as an explicit SDK override would mask caller configuration.
	})
	return autoLoadErr
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

// installDir returns the SDK FFI extraction root: nonempty MSB_HOME or
// ~/.microsandbox. RuntimeConfig overrides affect host runtime resolution and
// installation, independently of this per-version SDK library cache.
func installDir() (string, error) {
	if h := os.Getenv("MSB_HOME"); h != "" {
		return h, nil
	}
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

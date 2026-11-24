package microsandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/superradcompany/microsandbox/sdk/go/core/internal/ffi"
)

// sdkVersion is the microsandbox release that this SDK binds to. The
// embedded FFI library uses this version. Runtime downloads use the
// version pinned in that native SDK. Both are updated by the release train.
const sdkVersion = "0.8.2"

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

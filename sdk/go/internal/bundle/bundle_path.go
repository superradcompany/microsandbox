//go:build microsandbox_ffi_path

package bundle

import (
	"fmt"
	"os"
	"runtime"
)

// Bytes reads the FFI library bytes from $MICROSANDBOX_FFI_PATH.
// Builds tagged with `microsandbox_ffi_path` use this variant in place
// of the embedded library — intended for SDK contributors testing a
// locally-built libmicrosandbox_go_ffi.{so,dylib} without rebuilding
// the embed.
func Bytes() ([]byte, error) {
	path := os.Getenv(FFIPathEnv)
	if path == "" {
		return nil, fmt.Errorf(
			"microsandbox: build tagged with microsandbox_ffi_path but %s is unset",
			FFIPathEnv,
		)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf(
			"microsandbox: read %s=%s: %w", FFIPathEnv, path, err,
		)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf(
			"microsandbox: %s=%s is empty", FFIPathEnv, path,
		)
	}
	return b, nil
}

// Filename mirrors what the embedded variant would produce for the
// current platform, so callers can write the bytes to disk under the
// expected name.
func Filename() string {
	if runtime.GOOS == "darwin" {
		return "libmicrosandbox_go_ffi.dylib"
	}
	return "libmicrosandbox_go_ffi.so"
}

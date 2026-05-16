//go:build !((darwin && arm64) || (linux && amd64) || (linux && arm64)) && !microsandbox_ffi_path

package bundle

import (
	"fmt"
	"runtime"
)

// Bytes reports the platform as unsupported. The SDK ships embedded
// libraries only for darwin/arm64, linux/amd64, and linux/arm64; other
// GOOS/GOARCH combinations need either a dev build
// (-tags microsandbox_ffi_path) or a release that adds them.
func Bytes() ([]byte, error) {
	return nil, fmt.Errorf(
		"microsandbox: no FFI library bundled for %s/%s",
		runtime.GOOS, runtime.GOARCH,
	)
}

// Filename is empty on unsupported platforms.
func Filename() string { return "" }

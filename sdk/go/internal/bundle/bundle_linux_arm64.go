//go:build linux && arm64 && !microsandbox_ffi_path

package bundle

import (
	_ "embed"
	"errors"
)

//go:embed bundles/libmicrosandbox_go_ffi-linux-arm64.so
var ffiBytes []byte

// Bytes returns the embedded libmicrosandbox_go_ffi.so bytes pinned to
// this SDK release.
func Bytes() ([]byte, error) {
	if len(ffiBytes) == 0 {
		return nil, errors.New(errEmptyBundleMsg)
	}
	return ffiBytes, nil
}

// Filename is the on-disk filename to use when extracting the embedded
// library.
func Filename() string { return "libmicrosandbox_go_ffi.so" }

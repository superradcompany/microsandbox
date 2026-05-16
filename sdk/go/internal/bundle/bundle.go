// Package bundle exposes the libmicrosandbox_go_ffi shared library bytes
// that ship with this SDK release. The bytes are pinned to the SDK
// version: every release commits its own per-platform .so/.dylib into
// bundles/, and //go:embed wires the matching one into the binary at
// `go build` time.
//
// Public surface:
//
//	bundle.Bytes()    — embedded library bytes for the current platform
//	bundle.Filename() — on-disk filename to use when extracting them
//
// Build modes selected at compile time:
//
//	default                       — //go:embed of the matching platform .so
//	-tags microsandbox_ffi_path   — reads from $MICROSANDBOX_FFI_PATH
//	                                (no embed; used by integration/smoke
//	                                tests and SDK contributors iterating
//	                                on a locally-built library)
//
// Unsupported platforms compile but return an error from Bytes().
package bundle

// FFIPathEnv is the env var consulted by builds tagged with
// `microsandbox_ffi_path`. It must point at a locally-built
// libmicrosandbox_go_ffi.{so,dylib}. The variable is undocumented in
// user-facing docs because it has no effect on default builds.
const FFIPathEnv = "MICROSANDBOX_FFI_PATH"

// errEmptyBundleMsg is the error message returned by the per-platform
// Bytes() implementations when the embedded bundle is the 0-byte sentinel
// committed on main. Tagged releases populate the real bytes via the
// release pipeline. The wording lives here so all three platform files
// stay in lockstep when it's edited.
var errEmptyBundleMsg = "microsandbox: bundled FFI library is empty; " +
	"this build is from a source tree without populated bundles (e.g. " +
	"the main branch). Tagged releases ship real binaries; for SDK " +
	"contributors, build with -tags microsandbox_ffi_path and set " +
	FFIPathEnv

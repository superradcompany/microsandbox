package microsandbox

import "github.com/superradcompany/microsandbox/sdk/go/vfs"

// virtualMountLogf reports virtual-mount diagnostics. Defaults to a no-op;
// use [SetVirtualMountLogger] to route messages into your own logger.
var virtualMountLogf = func(string, ...any) {}

func init() {
	vfs.SetFilteredReaddirNameLog(func(name []byte) {
		virtualMountLogf("microsandbox: virtual-mount: dropped invalid readdir name %q", string(name))
	})
}

// SetVirtualMountLogger routes virtual-mount diagnostics (provider serve-loop
// exit, recovered panics, and handles garbage-collected without Close) to fn.
// Passing nil restores the default no-op logger.
func SetVirtualMountLogger(fn func(format string, args ...any)) {
	if fn == nil {
		virtualMountLogf = func(string, ...any) {}
		return
	}
	virtualMountLogf = fn
}

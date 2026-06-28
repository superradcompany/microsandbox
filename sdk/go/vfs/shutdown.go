package vfs

import (
	"sync"
	"time"
)

// virtualMountServeShutdownWait bounds how long teardown waits for in-flight provider
// calls after the connection closes. Keep in sync with SERVE_SHUTDOWN_JOIN_TIMEOUT in
// crates/filesystem/lib/backends/vfs/rpc/serve.rs.
const virtualMountServeShutdownWait = 30 * time.Second

func waitGroupWithTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

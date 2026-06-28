package microsandbox

import "context"

// watchVirtualMountProvidersStopped requests sandbox stop when any provider
// server exits while the VM may still be running. Each watch is tied to the
// registry generation that registered the servers so a same-name replace does
// not stop the replacement sandbox when the prior generation's servers close.
func watchVirtualMountProvidersStopped(name string, entry *virtualMountRegistryEntry, servers []virtualMountServer) {
	for i := range servers {
		srv := &servers[i]
		done := srv.done
		go func() {
			<-done
			// First provider exit in this generation shuts down every mount and
			// requests sandbox stop once.
			entry.providerExitOnce.Do(func() {
				closeVirtualMountServers(servers)
				teardownVirtualMountProvidersForEntry(name, entry)
				requestStopIfVirtualMountProviderStopped(name, entry)
			})
		}()
	}
}

func requestStopIfVirtualMountProviderStopped(name string, entry *virtualMountRegistryEntry) {
	if entry == nil {
		return
	}
	// Ignore exits from a superseded registry generation (e.g. WithReplace).
	if cur, ok := sandboxVirtualMountRegistry.Load(name); !ok || cur.(*virtualMountRegistryEntry) != entry {
		return
	}

	ctx := context.Background()
	handle, err := GetSandbox(ctx, name)
	if err == nil && !isTerminalSandboxStatus(handle.Status()) {
		if stopErr := handle.RequestStop(ctx); stopErr != nil {
			// Best-effort: still tear down providers once the provider thread exits.
			_ = stopErr
		}
	}
	scheduleVirtualMountTeardownForCapturedEntry(ctx, name, entry)
}

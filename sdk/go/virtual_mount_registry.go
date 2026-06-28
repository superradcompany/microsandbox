package microsandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// virtualMountTeardownWaitTimeout bounds how long deferred provider teardown waits for
// terminal sandbox state per attempt. Keep in sync with wait_until_sandbox_stopped in
// sdk/rust/lib/sandbox/virtual_mount/server.rs.
const virtualMountTeardownWaitTimeout = 300 * time.Second

// virtualMountTeardownMaxWait bounds how long the background teardown waiter retries
// before forcing provider shutdown. Keep in sync with MAX_TEARDOWN_WAIT in
// sdk/rust/lib/sandbox/virtual_mount/server.rs.
const virtualMountTeardownMaxWait = 30 * time.Minute

// Process-local registry for virtual-mount provider sockets. Virtual mounts
// live only in the creating process; additional Sandbox handles in the same
// process share the registry via reference counting.
//
// Provider sockets are tied to VM lifetime: they stay open while the guest may
// perform I/O and are torn down once (via teardownVirtualMountProvidersForEntry) after the
// VM reaches stopped state. Handle refcounts only track how many local handles
// still hold a release token; they do not close sockets on their own.
type virtualMountRegistryEntry struct {
	mu               sync.Mutex
	servers          []virtualMountServer
	refs             int
	teardownOnce     sync.Once
	stopWaitOnce     sync.Once
	providerExitOnce sync.Once
}

var (
	sandboxVirtualMountRegistry         sync.Map // sandbox name -> *virtualMountRegistryEntry
	sandboxesWithVirtualMounts sync.Map // sandbox name -> struct{}
	virtualMountRegisterLocks           sync.Map // sandbox name -> *sync.Mutex
)

func virtualMountRegisterLock(name string) *sync.Mutex {
	lock, _ := virtualMountRegisterLocks.LoadOrStore(name, &sync.Mutex{})
	return lock.(*sync.Mutex)
}

func markVirtualMountSandbox(name string) {
	sandboxesWithVirtualMounts.Store(name, struct{}{})
}

func unmarkVirtualMountSandbox(name string) {
	sandboxesWithVirtualMounts.Delete(name)
}

func sandboxHadVirtualMounts(name string) bool {
	_, ok := sandboxesWithVirtualMounts.Load(name)
	return ok
}

func isTerminalSandboxStatus(status SandboxStatus) bool {
	switch status {
	case SandboxStatusStopped, SandboxStatusCrashed:
		return true
	default:
		return false
	}
}

func snapshotVirtualMountRegistryEntry(name string) *virtualMountRegistryEntry {
	v, ok := sandboxVirtualMountRegistry.Load(name)
	if !ok {
		return nil
	}
	return v.(*virtualMountRegistryEntry)
}

// teardownVirtualMountCapturedEntry closes providers for one registry generation captured
// before a stop/kill/remove. Safe when entry is stale after a same-name replace.
func teardownVirtualMountCapturedEntry(name string, entry *virtualMountRegistryEntry) {
	if entry == nil {
		return
	}
	teardownVirtualMountProvidersForEntry(name, entry)
}

// scheduleVirtualMountTeardownForCapturedEntry waits for terminal state, then tears down
// the captured entry. Unlike name-based scheduling, a later same-name replace
// cannot redirect teardown onto the replacement generation.
func scheduleVirtualMountTeardownForCapturedEntry(ctx context.Context, name string, entry *virtualMountRegistryEntry) {
	if entry == nil {
		return
	}
	scheduleVirtualMountTeardownAfterStopped(ctx, name, entry)
}

func clearVirtualMountRegistrySlots(name string, entry *virtualMountRegistryEntry) {
	if cur, ok := sandboxVirtualMountRegistry.Load(name); ok && cur.(*virtualMountRegistryEntry) == entry {
		sandboxVirtualMountRegistry.Delete(name)
		unmarkVirtualMountSandbox(name)
	}
}

// isLiveVirtualMountRegistryEntry reports whether entry is still the active registry
// generation for name with open provider sockets.
func isLiveVirtualMountRegistryEntry(name string, entry *virtualMountRegistryEntry) bool {
	lock := virtualMountRegisterLock(name)
	lock.Lock()
	defer lock.Unlock()
	cur, ok := sandboxVirtualMountRegistry.Load(name)
	if !ok {
		return false
	}
	live := cur.(*virtualMountRegistryEntry)
	if live != entry {
		return false
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	return entry.servers != nil && virtualMountServersLive(entry.servers)
}

// registerVirtualMountServers installs a fresh entry (refs=1) for name and returns it,
// or nil when there are no servers. The returned entry is the release token:
// callers release through it, not by name, so a later same-name registration
// can never disturb a handle that acquired an earlier one.
func registerVirtualMountServers(name string, servers []virtualMountServer) *virtualMountRegistryEntry {
	if len(servers) == 0 {
		return nil
	}
	lock := virtualMountRegisterLock(name)
	lock.Lock()
	defer lock.Unlock()

	entry := &virtualMountRegistryEntry{servers: servers, refs: 1}
	// A live entry already under this name means the sandbox was replaced (e.g.
	// WithReplace) without its previous handle being closed. That sandbox's VM
	// is gone, so its provider servers can no longer serve anyone — close them
	// now instead of leaking them, and take over the name. The stale handle
	// still holds the old entry as its own token, so its eventual release acts
	// on that detached entry and leaves this one untouched.
	if prev, ok := sandboxVirtualMountRegistry.Load(name); ok {
		old := prev.(*virtualMountRegistryEntry)
		teardownVirtualMountProvidersForEntry(name, old)
	}
	sandboxVirtualMountRegistry.Store(name, entry)
	markVirtualMountSandbox(name)
	watchVirtualMountProvidersStopped(name, entry, servers)
	return entry
}

// acquireVirtualMountServers takes an additional reference on name's live entry and
// returns it as a release token. Returns (nil, false) when no live entry exists.
func acquireVirtualMountServers(name string) (*virtualMountRegistryEntry, bool) {
	lock := virtualMountRegisterLock(name)
	lock.Lock()
	defer lock.Unlock()
	v, ok := sandboxVirtualMountRegistry.Load(name)
	if !ok {
		return nil, false
	}
	entry := v.(*virtualMountRegistryEntry)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.servers == nil || !virtualMountServersLive(entry.servers) {
		return nil, false
	}
	entry.refs++
	return entry, true
}

// releaseVirtualMountEntry drops one handle reference on entry. It never closes provider
// sockets while the VM may still be running: teardownVirtualMountProvidersForEntry does
// that once stopped state is observed.
func releaseVirtualMountEntry(name string, entry *virtualMountRegistryEntry) {
	if entry == nil {
		return
	}
	entry.mu.Lock()
	// Entries zeroed by a same-name replace or teardown are stale tokens.
	if entry.refs <= 0 {
		entry.mu.Unlock()
		return
	}
	entry.refs--
	refs := entry.refs
	servers := entry.servers
	entry.mu.Unlock()
	if refs > 0 {
		return
	}
	// Last handle ref dropped. If teardown already closed the sockets, remove
	// the registry slot; otherwise tear down now when the VM is already stopped.
	if servers == nil {
		clearVirtualMountRegistrySlots(name, entry)
		return
	}
	virtualMountEntryTeardownIfStopped(context.Background(), name, entry)
}

// teardownVirtualMountProvidersForEntry closes providers for one registry generation.
// Idempotent and safe even when entry is no longer the live registry slot.
func teardownVirtualMountProvidersForEntry(name string, entry *virtualMountRegistryEntry) {
	if entry == nil {
		return
	}
	entry.teardownOnce.Do(func() {
		entry.mu.Lock()
		if entry.servers == nil {
			entry.mu.Unlock()
			clearVirtualMountRegistrySlots(name, entry)
			return
		}
		entry.refs = 0
		servers := entry.servers
		entry.servers = nil
		entry.mu.Unlock()
		closeVirtualMountServers(servers)
		clearVirtualMountRegistrySlots(name, entry)
	})
}

// teardownVirtualMountProvidersByName closes providers for name's current live entry.
func teardownVirtualMountProvidersByName(name string) {
	v, ok := sandboxVirtualMountRegistry.Load(name)
	if !ok {
		return
	}
	teardownVirtualMountProvidersForEntry(name, v.(*virtualMountRegistryEntry))
}

// virtualMountEntryTeardownIfStopped tears down entry when the sandbox is already in a
// terminal state (or its persisted record is gone).
func virtualMountEntryTeardownIfStopped(ctx context.Context, name string, entry *virtualMountRegistryEntry) {
	if entry == nil {
		return
	}
	entry.mu.Lock()
	if entry.servers == nil {
		entry.mu.Unlock()
		return
	}
	entry.mu.Unlock()

	handle, err := GetSandbox(ctx, name)
	if err != nil {
		if IsKind(err, ErrSandboxNotFound) {
			teardownVirtualMountProvidersForEntry(name, entry)
		}
		return
	}
	if isTerminalSandboxStatus(handle.Status()) {
		teardownVirtualMountProvidersForEntry(name, entry)
	}
}

// scheduleVirtualMountTeardownAfterStopped waits for terminal state, then tears down
// providers for entry. At most one background wait runs per registry entry.
func scheduleVirtualMountTeardownAfterStopped(ctx context.Context, name string, entry *virtualMountRegistryEntry) {
	if entry == nil {
		return
	}
	entry.mu.Lock()
	if entry.servers == nil {
		entry.mu.Unlock()
		return
	}
	entry.mu.Unlock()

	entry.stopWaitOnce.Do(func() {
		go func() {
			deadline := time.Now().Add(virtualMountTeardownMaxWait)
			for time.Now().Before(deadline) {
				waitCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), virtualMountTeardownWaitTimeout)
				_, waitErr := ffi.WaitSandboxByNameUntilStopped(waitCtx, name)
				cancel()
				if waitErr == nil {
					teardownVirtualMountProvidersForEntry(name, entry)
					return
				}
				virtualMountLogf(
					"microsandbox: timed out or failed waiting for sandbox %q to stop before tearing down virtual mounts: %v; retrying",
					name, waitErr,
				)
			}
			virtualMountLogf(
				"microsandbox: stopped waiting for sandbox %q to stop after %v; forcing virtual-mount provider shutdown",
				name, virtualMountTeardownMaxWait,
			)
			teardownVirtualMountProvidersForEntry(name, entry)
			return
		}()
	})
}

func virtualMountReconnectError(name string) error {
	return fmt.Errorf(
		"connect to sandbox %q: virtual mount provider is not active in this process; keep a lifecycle-owning Sandbox handle open in the process that created the mount, Connect from that same process while providers are still running, or remove the sandbox record and create a new one with WithVirtualMount",
		name,
	)
}

func virtualMountRestartError(name string) error {
	return fmt.Errorf(
		"start sandbox %q: cannot restart a sandbox that used virtual mounts — the provider socket cannot be reattached after stop; remove the sandbox record and create a new one with WithVirtualMount instead of StartSandbox",
		name,
	)
}

func virtualMountIncompleteCreateError(name, operation string) error {
	return fmt.Errorf(
		"%s sandbox %q: virtual mount create did not complete successfully — remove the sandbox record or recreate with WithReplace, then create again with WithVirtualMount instead of %s",
		operation,
		name,
		operation,
	)
}

func virtualMountAlreadyRunningError(name string) error {
	return fmt.Errorf(
		"start sandbox %q: sandbox is already running with virtual mounts; use Connect instead",
		name,
	)
}

func configVirtualMountFlags(configJSON string) (had, attempted bool, err error) {
	if configJSON == "" {
		return false, false, nil
	}
	var cfg struct {
		HadVirtualMounts       bool `json:"had_virtual_mounts"`
		AttemptedVirtualMounts bool `json:"attempted_virtual_mounts"`
	}
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return false, false, fmt.Errorf("parse sandbox config: %w", err)
	}
	return cfg.HadVirtualMounts, cfg.AttemptedVirtualMounts, nil
}

func configHadVirtualMounts(configJSON string) (bool, error) {
	had, _, err := configVirtualMountFlags(configJSON)
	return had, err
}

func virtualMountRestartBlockedForStatus(name string, configHadMounts bool, status SandboxStatus) error {
	if !configHadMounts {
		return nil
	}
	switch status {
	case SandboxStatusRunning, SandboxStatusDraining, SandboxStatusPaused:
		return virtualMountAlreadyRunningError(name)
	default:
		return virtualMountRestartError(name)
	}
}

func virtualMountRestartBlocked(ctx context.Context, name string) error {
	handle, err := GetSandbox(ctx, name)
	if err != nil {
		// No persisted sandbox means there is nothing to restart — permit it.
		// Any other lookup failure leaves the guard undecided, so surface it
		// rather than silently allowing a possibly-unrestartable start.
		if IsKind(err, ErrSandboxNotFound) {
			return nil
		}
		return fmt.Errorf("check virtual-mount restart for sandbox %q: %w", name, err)
	}
	configHadMounts, configAttemptedMounts, err := configVirtualMountFlags(handle.ConfigJSON())
	if err != nil {
		return fmt.Errorf("check virtual-mount restart for sandbox %q: %w", name, err)
	}
	if configAttemptedMounts && !configHadMounts {
		return virtualMountIncompleteCreateError(name, "start")
	}
	return virtualMountRestartBlockedForStatus(name, configHadMounts, handle.Status())
}

// connectVirtualMounts gates a Connect on virtual-mount lifecycle.
func connectVirtualMounts(name, configJSON string) (*virtualMountRegistryEntry, error) {
	configHadMounts, configAttemptedMounts, err := configVirtualMountFlags(configJSON)
	if err != nil {
		return nil, fmt.Errorf("connect sandbox %q: %w", name, err)
	}
	if configAttemptedMounts && !configHadMounts {
		return nil, virtualMountIncompleteCreateError(name, "connect to")
	}
	if !sandboxHadVirtualMounts(name) && !configHadMounts {
		return nil, nil
	}
	// The provider socket lives only in the process that created the mount.
	// If we can't acquire a live entry here, connecting would hand back a dead
	// mount, so refuse instead.
	if entry, ok := acquireVirtualMountServers(name); ok {
		return entry, nil
	}
	return nil, virtualMountReconnectError(name)
}

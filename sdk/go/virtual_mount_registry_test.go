package microsandbox

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestRegisterVirtualMountServersConcurrentReplaceDoesNotLeak(t *testing.T) {
	name := fmt.Sprintf("concurrent-register-%d", time.Now().UnixNano())
	t.Cleanup(func() { teardownVirtualMountProvidersByName(name) })

	const workers = 8
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			_, servers, err := buildFFIVirtualMounts([]VirtualMountConfig{
				{GuestPath: "/inbox", Provider: stubPathFs{}},
			}, nil)
			if err != nil {
				t.Errorf("buildFFIVirtualMounts: %v", err)
				return
			}
			registerVirtualMountServers(name, servers)
		}()
	}
	wg.Wait()

	v, ok := sandboxVirtualMountRegistry.Load(name)
	if !ok {
		t.Fatal("expected a live registry entry after concurrent registration")
	}
	entry := v.(*virtualMountRegistryEntry)
	entry.mu.Lock()
	refs := entry.refs
	servers := entry.servers
	entry.mu.Unlock()
	if refs != 1 {
		t.Fatalf("refs = %d, want 1", refs)
	}
	if len(servers) != 1 {
		t.Fatalf("len(servers) = %d, want 1", len(servers))
	}
}

func TestVirtualMountTeardownWaitTimeoutMatchesRust(t *testing.T) {
	// Keep in sync with wait_until_sandbox_stopped in sdk/rust/lib/sandbox/virtual_mount/server.rs.
	const rustWaitUntilStoppedTimeout = 300 * time.Second
	if virtualMountTeardownWaitTimeout != rustWaitUntilStoppedTimeout {
		t.Fatalf("virtualMountTeardownWaitTimeout = %v, want %v", virtualMountTeardownWaitTimeout, rustWaitUntilStoppedTimeout)
	}
}

func TestSandboxHandleEnsureCurrentRejectsStaleDbID(t *testing.T) {
	handle := &SandboxHandle{name: "demo", dbID: 1}
	current := &SandboxHandle{name: "demo", dbID: 2}
	err := handle.ensureCurrentMismatch(current)
	if err == nil {
		t.Fatal("expected stale handle error")
	}
	if !IsKind(err, ErrSandboxHandleStale) {
		t.Fatalf("IsKind = false, err = %v", err)
	}
	if err := handle.ensureCurrentMismatch(handle); err != nil {
		t.Fatalf("matching db_id should pass: %v", err)
	}
}

func TestSandboxHandleEnsureCurrentRejectsStaleUpdatedAtWhenDbIDMissing(t *testing.T) {
	oldUpdated := int64(100)
	newUpdated := int64(200)
	handle := &SandboxHandle{name: "demo", dbID: 0, updatedAtUnix: &oldUpdated}
	current := &SandboxHandle{name: "demo", dbID: 0, updatedAtUnix: &newUpdated}
	if err := handle.ensureCurrentMismatch(current); err == nil {
		t.Fatal("expected stale handle error when updated_at differs and db_id is missing")
	}
	same := &SandboxHandle{name: "demo", dbID: 0, updatedAtUnix: &oldUpdated}
	if err := handle.ensureCurrentMismatch(same); err != nil {
		t.Fatalf("matching updated_at with missing db_id should pass: %v", err)
	}
}

func TestSandboxHandleStaleGuardedMethodsRejectMismatchedDbID(t *testing.T) {
	stale := &SandboxHandle{name: "demo", dbID: 1, configJSON: `{"had_virtual_mounts":false}`}
	current := &SandboxHandle{name: "demo", dbID: 2, configJSON: `{"had_virtual_mounts":false}`}

	check := func(t *testing.T, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("expected stale handle error")
		}
		if !IsKind(err, ErrSandboxHandleStale) {
			t.Fatalf("IsKind = false, err = %v", err)
		}
	}

	check(t, stale.ensureCurrentMismatch(current))
	check(t, stale.connectVirtualMountsMismatch(current))
	check(t, stale.logsGuardMismatch(current))
	check(t, stale.removeGuardMismatch(current))
}

func (h *SandboxHandle) removeGuardMismatch(current *SandboxHandle) error {
	return h.ensureCurrentMismatch(current)
}

func (h *SandboxHandle) logsGuardMismatch(current *SandboxHandle) error {
	return h.ensureCurrentMismatch(current)
}

func (h *SandboxHandle) connectVirtualMountsMismatch(current *SandboxHandle) error {
	if err := h.ensureCurrentMismatch(current); err != nil {
		return err
	}
	_, err := connectVirtualMounts(h.name, current.configJSON)
	return err
}

func (h *SandboxHandle) ensureCurrentMismatch(current *SandboxHandle) error {
	if current.dbID != h.dbID {
		return staleSandboxHandleError(h.name)
	}
	if h.dbID == 0 && h.updatedAtUnix != nil && current.updatedAtUnix != nil &&
		*current.updatedAtUnix != *h.updatedAtUnix {
		return staleSandboxHandleError(h.name)
	}
	if h.virtualMountEntry != nil && current.virtualMountEntry != h.virtualMountEntry {
		return staleSandboxHandleError(h.name)
	}
	return nil
}

func TestIsLiveVirtualMountRegistryEntryRejectsReplacedGeneration(t *testing.T) {
	name := fmt.Sprintf("live-entry-%d", time.Now().UnixNano())
	t.Cleanup(func() { teardownVirtualMountProvidersByName(name) })

	_, first, err := buildFFIVirtualMounts([]VirtualMountConfig{
		{GuestPath: "/a", Provider: stubPathFs{}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	old := registerVirtualMountServers(name, first)
	_, second, err := buildFFIVirtualMounts([]VirtualMountConfig{
		{GuestPath: "/b", Provider: stubPathFs{}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	registerVirtualMountServers(name, second)
	if isLiveVirtualMountRegistryEntry(name, old) {
		t.Fatal("stale entry must not be live after replace")
	}
}

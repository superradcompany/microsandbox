package microsandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/vfs"
)

type stubPathFs struct{ vfs.ReadOnly }

func (stubPathFs) GetAttr([]byte) (vfs.Attr, error) {
	return vfs.Attr{Kind: vfs.Dir, Mode: 0o755}, nil
}

func (stubPathFs) ReadDir([]byte) ([]vfs.DirEntry, error) { return nil, nil }

func (stubPathFs) Read([]byte, uint64, uint32) ([]byte, error) { return nil, nil }

func TestBuildFFIVirtualMountsOmitsDefaultFsConfig(t *testing.T) {
	vms, servers, err := buildFFIVirtualMounts([]VirtualMountConfig{
		{GuestPath: "/inbox", Provider: stubPathFs{}},
	}, nil)
	if err != nil {
		t.Fatalf("buildFFIVirtualMounts: %v", err)
	}
	defer closeVirtualMountServers(servers)
	if vms[0].FsConfig != nil {
		t.Fatalf("fs_config = %+v, want nil for defaults", vms[0].FsConfig)
	}
}

func TestValidateGuestMountPath(t *testing.T) {
	cases := []struct {
		path string
		ok   bool
	}{
		{"", false},
		{"inbox", false},
		{"/", false},
		{"/inbox/", false},
		{"/in:box", false},
		{"/data/../x", false},
		{"/foo//bar", false},
		{"/./inbox", false},
		{"/.msb/vfs", false},
		{"/inbox", true},
	}
	for _, tc := range cases {
		err := validateGuestMountPath(tc.path)
		if tc.ok && err != nil {
			t.Fatalf("%q: %v", tc.path, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("%q: expected error", tc.path)
		}
	}
}

func TestBuildFFIVirtualMountsMultipleGuestPaths(t *testing.T) {
	vms, servers, err := buildFFIVirtualMounts([]VirtualMountConfig{
		{GuestPath: "/inbox", Provider: stubPathFs{}},
		{GuestPath: "/data", Provider: stubPathFs{}},
	}, nil)
	if err != nil {
		t.Fatalf("buildFFIVirtualMounts: %v", err)
	}
	defer closeVirtualMountServers(servers)
	if len(vms) != 2 {
		t.Fatalf("len(vms) = %d, want 2", len(vms))
	}
	if vms[0].GuestPath != "/inbox" || vms[1].GuestPath != "/data" {
		t.Fatalf("guest paths = %q, %q", vms[0].GuestPath, vms[1].GuestPath)
	}
}

func TestTeardownMaxWaitConstantsMatchRust(t *testing.T) {
	const rustSeconds = 30 * 60
	if virtualMountTeardownMaxWait != rustSeconds*time.Second {
		t.Fatalf("virtualMountTeardownMaxWait = %v, want %v", virtualMountTeardownMaxWait, rustSeconds*time.Second)
	}
}

func TestBuildFFIVirtualMountsRejectsDuplicateGuestPaths(t *testing.T) {
	_, _, err := buildFFIVirtualMounts([]VirtualMountConfig{
		{GuestPath: "/inbox", Provider: stubPathFs{}},
		{GuestPath: "/inbox", Provider: stubPathFs{}},
	}, nil)
	if err == nil {
		t.Fatal("expected error for duplicate guest path")
	}
	if !strings.Contains(err.Error(), "overlaps with") {
		t.Fatalf("error = %v", err)
	}
}

func TestBuildFFIVirtualMountsRejectsNestedGuestPaths(t *testing.T) {
	_, _, err := buildFFIVirtualMounts([]VirtualMountConfig{
		{GuestPath: "/data", Provider: stubPathFs{}},
		{GuestPath: "/data/inbox", Provider: stubPathFs{}},
	}, nil)
	if err == nil {
		t.Fatal("expected error for nested guest paths")
	}
	if !strings.Contains(err.Error(), "overlaps with") {
		t.Fatalf("error = %v", err)
	}
}

func TestBuildFFIVirtualMountsRejectsNestedVolumeOverlap(t *testing.T) {
	_, _, err := buildFFIVirtualMounts([]VirtualMountConfig{
		{GuestPath: "/data/inbox", Provider: stubPathFs{}},
	}, map[string]MountConfig{
		"/data": {Bind: "/host/data"},
	})
	if err == nil {
		t.Fatal("expected error for nested volume overlap")
	}
	if !strings.Contains(err.Error(), "conflicts with an existing volume mount") {
		t.Fatalf("error = %v", err)
	}
}

func TestGuestPathsOverlap(t *testing.T) {
	if !guestPathsOverlap("/data", "/data/inbox") {
		t.Fatal("expected nested overlap")
	}
	if guestPathsOverlap("/data", "/data2") {
		t.Fatal("unexpected overlap")
	}
}

func TestVirtualMountServersRegistryRefCount(t *testing.T) {
	_, servers, err := buildFFIVirtualMounts([]VirtualMountConfig{
		{GuestPath: "/inbox", Provider: stubPathFs{}},
	}, nil)
	if err != nil {
		t.Fatalf("buildFFIVirtualMounts: %v", err)
	}

	entry := registerVirtualMountServers("demo", servers)
	if entry == nil {
		t.Fatal("expected registerVirtualMountServers to return an entry")
	}
	acquired, ok := acquireVirtualMountServers("demo")
	if !ok {
		t.Fatal("expected acquire to succeed while registry entry exists")
	}
	releaseVirtualMountEntry("demo", acquired)
	releaseVirtualMountEntry("demo", entry)

	if _, ok := sandboxVirtualMountRegistry.Load("demo"); !ok {
		t.Fatal("registry entry should remain until VM teardown")
	}
	teardownVirtualMountProvidersByName("demo")
	if _, ok := sandboxVirtualMountRegistry.Load("demo"); ok {
		t.Fatal("registry entry should be removed after teardown")
	}
}

func TestReplaceWithoutVirtualMountsTearsDownPriorProviders(t *testing.T) {
	_, servers, err := buildFFIVirtualMounts([]VirtualMountConfig{
		{GuestPath: "/inbox", Provider: stubPathFs{}},
	}, nil)
	if err != nil {
		t.Fatalf("buildFFIVirtualMounts: %v", err)
	}
	registerVirtualMountServers("replace-plain", servers)
	if !sandboxHadVirtualMounts("replace-plain") {
		t.Fatal("expected in-memory mark after register")
	}

	// CreateSandbox calls this when WithReplace is set and the new config has
	// no virtual mounts.
	teardownVirtualMountProvidersByName("replace-plain")

	if sandboxHadVirtualMounts("replace-plain") {
		t.Fatal("mark should clear when replace tears down prior providers")
	}
	if _, ok := sandboxVirtualMountRegistry.Load("replace-plain"); ok {
		t.Fatal("registry should be empty after replace-without-mounts teardown")
	}
}

func TestVirtualMountServersRegistryReplaceClosesOldEntry(t *testing.T) {
	_, first, err := buildFFIVirtualMounts([]VirtualMountConfig{
		{GuestPath: "/inbox", Provider: stubPathFs{}},
	}, nil)
	if err != nil {
		t.Fatalf("buildFFIVirtualMounts: %v", err)
	}
	_, second, err := buildFFIVirtualMounts([]VirtualMountConfig{
		{GuestPath: "/inbox", Provider: stubPathFs{}},
	}, nil)
	if err != nil {
		t.Fatalf("buildFFIVirtualMounts: %v", err)
	}

	old := registerVirtualMountServers("reuse", first)
	// Re-register under the same name (e.g. WithReplace) without releasing the
	// first handle. The replacement takes over the slot; the old entry is force
	// closed.
	current := registerVirtualMountServers("reuse", second)
	t.Cleanup(func() { teardownVirtualMountProvidersByName("reuse") })

	if v, _ := sandboxVirtualMountRegistry.Load("reuse"); v.(*virtualMountRegistryEntry) != current {
		t.Fatal("registry slot should point at the replacement entry")
	}
	// Releasing the stale first handle must not disturb the replacement.
	releaseVirtualMountEntry("reuse", old)
	if _, ok := sandboxVirtualMountRegistry.Load("reuse"); !ok {
		t.Fatal("releasing the stale entry must not delete the replacement's slot")
	}
}

func TestProviderWatchIgnoresSupersededRegistryEntry(t *testing.T) {
	name := "watch-replace-" + strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-"))
	t.Cleanup(func() { teardownVirtualMountProvidersByName(name) })

	_, first, err := buildFFIVirtualMounts([]VirtualMountConfig{
		{GuestPath: "/inbox", Provider: stubPathFs{}},
	}, nil)
	if err != nil {
		t.Fatalf("buildFFIVirtualMounts first: %v", err)
	}
	oldEntry := registerVirtualMountServers(name, first)

	_, second, err := buildFFIVirtualMounts([]VirtualMountConfig{
		{GuestPath: "/inbox", Provider: stubPathFs{}},
	}, nil)
	if err != nil {
		t.Fatalf("buildFFIVirtualMounts second: %v", err)
	}
	current := registerVirtualMountServers(name, second)

	// Simulate the old generation's provider exiting after replace.
	teardownVirtualMountProvidersForEntry(name, oldEntry)

	if v, ok := sandboxVirtualMountRegistry.Load(name); !ok || v.(*virtualMountRegistryEntry) != current {
		t.Fatal("replacement registry entry should remain after old generation teardown")
	}
}

func TestConnectVirtualMountsRequiresActiveRegistry(t *testing.T) {
	markVirtualMountSandbox("orphan")
	t.Cleanup(func() { unmarkVirtualMountSandbox("orphan") })

	_, err := connectVirtualMounts("orphan", `{"had_virtual_mounts":true}`)
	if err == nil {
		t.Fatal("expected reconnect error without active registry")
	}
	if !strings.Contains(err.Error(), "virtual mount provider is not active") {
		t.Fatalf("error = %v", err)
	}
}

func TestConnectVirtualMountsConfigOnlyIsRejected(t *testing.T) {
	// A sandbox created with virtual mounts in another process leaves no
	// in-process marker, but its persisted config flags the mounts. Connecting
	// here must refuse rather than hand back a dead provider socket.
	_, err := connectVirtualMounts("cross-process", `{"had_virtual_mounts":true}`)
	if err == nil {
		t.Fatal("expected reconnect error for a config-only virtual-mount sandbox")
	}
	if !strings.Contains(err.Error(), "virtual mount provider is not active") {
		t.Fatalf("error = %v", err)
	}

	// With no marker and no config flag, there is nothing to gate.
	if _, err := connectVirtualMounts("plain", `{}`); err != nil {
		t.Fatalf("unexpected error for non-virtual-mount sandbox: %v", err)
	}
}

func TestBuildFFIVirtualMountsIncludesFdAndCache(t *testing.T) {
	vms, servers, err := buildFFIVirtualMounts([]VirtualMountConfig{
		{
			GuestPath:    "/inbox",
			Provider:     stubPathFs{},
			EntryTimeout: 2 * time.Second,
			AttrTimeout:  3 * time.Second,
			CachePolicy:  VfsCacheAlways,
			Writeback:    true,
		},
	}, nil)
	if err != nil {
		t.Fatalf("buildFFIVirtualMounts: %v", err)
	}
	defer closeVirtualMountServers(servers)

	if len(vms) != 1 {
		t.Fatalf("len(vms) = %d, want 1", len(vms))
	}
	if vms[0].GuestPath != "/inbox" || vms[0].FD <= 0 {
		t.Fatalf("unexpected mount: %+v", vms[0])
	}
	if vms[0].FsConfig == nil || vms[0].FsConfig.CachePolicy == nil || *vms[0].FsConfig.CachePolicy != "always" {
		t.Fatalf("fs_config = %+v", vms[0].FsConfig)
	}
}

func TestMarshalCreateOptionsIncludesVirtualMounts(t *testing.T) {
	vms, servers, err := buildFFIVirtualMounts([]VirtualMountConfig{
		{GuestPath: "/data", Provider: stubPathFs{}},
	}, nil)
	if err != nil {
		t.Fatalf("buildFFIVirtualMounts: %v", err)
	}
	defer closeVirtualMountServers(servers)

	opts := buildFFICreateOptions(SandboxConfig{Image: "alpine"})
	opts.VirtualMounts = vms

	raw, err := json.Marshal(opts)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	mounts, ok := got["virtual_mounts"].([]any)
	if !ok || len(mounts) != 1 {
		t.Fatalf("virtual_mounts = %#v", got["virtual_mounts"])
	}
}

func TestBuildFFIVirtualMountsRejectsVolumeOverlap(t *testing.T) {
	_, _, err := buildFFIVirtualMounts([]VirtualMountConfig{
		{GuestPath: "/data", Provider: stubPathFs{}},
	}, map[string]MountConfig{
		"/data": {Bind: "/host/data"},
	})
	if err == nil {
		t.Fatal("expected error for virtual mount overlapping volume")
	}
	if !strings.Contains(err.Error(), "conflicts with an existing volume mount") {
		t.Fatalf("error = %v", err)
	}
}

func TestBuildFFIVirtualMountsRejectsInvalidCachePolicy(t *testing.T) {
	_, _, err := buildFFIVirtualMounts([]VirtualMountConfig{
		{GuestPath: "/inbox", Provider: stubPathFs{}, CachePolicy: VfsCachePolicy("Never")},
	}, nil)
	if err == nil {
		t.Fatal("expected error for invalid cache policy")
	}
	if !strings.Contains(err.Error(), "invalid virtual mount cache_policy") {
		t.Fatalf("error = %v", err)
	}
}

func TestBuildFFIVirtualMountsRejectsTooMany(t *testing.T) {
	mounts := make([]VirtualMountConfig, maxVirtualMounts+1)
	for i := range mounts {
		mounts[i] = VirtualMountConfig{
			GuestPath: fmt.Sprintf("/mount%d", i),
			Provider:  stubPathFs{},
		}
	}
	_, _, err := buildFFIVirtualMounts(mounts, nil)
	if err == nil {
		t.Fatal("expected error for too many virtual mounts")
	}
	if !strings.Contains(err.Error(), "too many virtual mounts") {
		t.Fatalf("error = %v", err)
	}
}

func TestReleaseVirtualMountEntryIgnoresStaleToken(t *testing.T) {
	entry := &virtualMountRegistryEntry{refs: 0, servers: nil}
	releaseVirtualMountEntry("demo", entry)
	if entry.refs != 0 {
		t.Fatalf("refs = %d, want 0 after stale release", entry.refs)
	}
}

func TestVirtualMountMarkClearsOnlyOnLastProviderRelease(t *testing.T) {
	_, servers, err := buildFFIVirtualMounts([]VirtualMountConfig{
		{GuestPath: "/inbox", Provider: stubPathFs{}},
	}, nil)
	if err != nil {
		t.Fatalf("buildFFIVirtualMounts: %v", err)
	}
	entry := registerVirtualMountServers("mark-test", servers)
	if !sandboxHadVirtualMounts("mark-test") {
		t.Fatal("expected in-memory mark after register")
	}
	releaseVirtualMountEntry("mark-test", entry)
	if !sandboxHadVirtualMounts("mark-test") {
		t.Fatal("mark should remain until VM teardown")
	}
	teardownVirtualMountProvidersByName("mark-test")
	if sandboxHadVirtualMounts("mark-test") {
		t.Fatal("expected mark cleared after teardown")
	}
}

func TestConfigVirtualMountFlags(t *testing.T) {
	had, attempted, err := configVirtualMountFlags(`{"had_virtual_mounts":true,"attempted_virtual_mounts":true}`)
	if err != nil || !had || !attempted {
		t.Fatalf("had=%v attempted=%v err=%v", had, attempted, err)
	}
	had, attempted, err = configVirtualMountFlags(`{"attempted_virtual_mounts":true}`)
	if err != nil || had || !attempted {
		t.Fatalf("attempted-only: had=%v attempted=%v err=%v", had, attempted, err)
	}
	had, attempted, err = configVirtualMountFlags(`{"had_virtual_mounts":false}`)
	if err != nil || had || attempted {
		t.Fatalf("empty: had=%v attempted=%v err=%v", had, attempted, err)
	}
	if _, _, err := configVirtualMountFlags(`{`); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestConfigHadVirtualMounts(t *testing.T) {
	got, err := configHadVirtualMounts(`{"had_virtual_mounts":true}`)
	if err != nil || !got {
		t.Fatalf("got (%v, %v), want (true, nil)", got, err)
	}
	got, err = configHadVirtualMounts(`{"had_virtual_mounts":false}`)
	if err != nil || got {
		t.Fatalf("got (%v, %v), want (false, nil)", got, err)
	}
	if _, err := configHadVirtualMounts(`{`); err == nil {
		t.Fatal("expected error for malformed config JSON")
	}
}

func TestReleaseVirtualMountAfterSuccess(t *testing.T) {
	called := false
	release := func() { called = true }

	releaseVirtualMountAfterSuccess(nil, release)
	if !called {
		t.Fatal("expected release on success")
	}

	called = false
	releaseVirtualMountAfterSuccess(fmt.Errorf("stop failed"), release)
	if called {
		t.Fatal("expected no release on failure")
	}
}

func TestVfsCloseDefersRelease(t *testing.T) {
	if !virtualMountCloseDefersRelease(true, nil) {
		t.Fatal("lifecycle owner should defer virtual mount release on Close")
	}
	if virtualMountCloseDefersRelease(false, nil) {
		t.Fatal("Connect handle should release virtual mount immediately on Close")
	}
	if !virtualMountCloseDefersRelease(false, fmt.Errorf("stale handle")) {
		t.Fatal("unknown ownership should defer virtual mount release on Close")
	}
}

func TestVfsFinalizeReleaseImmediateForConnectHandle(t *testing.T) {
	_, servers, err := buildFFIVirtualMounts([]VirtualMountConfig{
		{GuestPath: "/inbox", Provider: stubPathFs{}},
	}, nil)
	if err != nil {
		t.Fatalf("buildFFIVirtualMounts: %v", err)
	}
	entry := registerVirtualMountServers("virtual-mount-finalize-connect", servers)

	before := entry.refs
	virtualMountFinalizeRelease("virtual-mount-finalize-connect", entry, false, nil)
	if entry.refs != before-1 {
		t.Fatalf("refs = %d, want %d after Connect-style finalize", entry.refs, before-1)
	}
	releaseVirtualMountEntry("virtual-mount-finalize-connect", entry)
}

func TestBuildFFIVirtualMountsRejectsBindVirtioTagCollision(t *testing.T) {
	_, _, err := buildFFIVirtualMounts([]VirtualMountConfig{
		{GuestPath: "/data", Provider: stubPathFs{}},
	}, map[string]MountConfig{
		"/data": Mount.Bind("/host/data", MountOptions{}),
	})
	if err == nil {
		t.Fatal("expected error when virtual mount shares guest path/tag with bind volume")
	}
	if !strings.Contains(err.Error(), "conflicts with") {
		t.Fatalf("error = %v", err)
	}
}

func TestBuildFFIVirtualMountsRejectsTmpfsOverlap(t *testing.T) {
	_, _, err := buildFFIVirtualMounts([]VirtualMountConfig{
		{GuestPath: "/tmp", Provider: stubPathFs{}},
	}, map[string]MountConfig{
		"/tmp": Mount.Tmpfs(TmpfsOptions{SizeMiB: 256}),
	})
	if err == nil {
		t.Fatal("expected error when virtual mount overlaps tmpfs guest path")
	}
	if !strings.Contains(err.Error(), "conflicts with") {
		t.Fatalf("error = %v", err)
	}
}

func TestAcquireVirtualMountServersKeepsProviderUntilLastRef(t *testing.T) {
	_, servers, err := buildFFIVirtualMounts([]VirtualMountConfig{
		{GuestPath: "/a", Provider: stubPathFs{}},
	}, nil)
	if err != nil {
		t.Fatalf("buildFFIVirtualMounts: %v", err)
	}
	defer closeVirtualMountServers(servers)

	name := fmt.Sprintf("virtual-mount-refcount-%d", os.Getpid())
	sandboxVirtualMountRegistry.Delete(name)
	entry := registerVirtualMountServers(name, servers)
	defer sandboxVirtualMountRegistry.Delete(name)

	connEntry, ok := acquireVirtualMountServers(name)
	if !ok || connEntry == nil {
		t.Fatal("expected acquire to succeed while registry entry is live")
	}
	releaseVirtualMountEntry(name, connEntry)
	if entry.refs != 1 {
		t.Fatalf("refs = %d, want 1 after Connect-style release", entry.refs)
	}

	releaseVirtualMountEntry(name, entry)
	if _, ok := sandboxVirtualMountRegistry.Load(name); !ok {
		t.Fatal("registry should remain until VM teardown")
	}
	teardownVirtualMountProvidersByName(name)
	if _, ok := sandboxVirtualMountRegistry.Load(name); ok {
		t.Fatal("expected registry entry removed after teardown")
	}
}

func virtualMountRegistryHasLiveServers(name string) bool {
	v, ok := sandboxVirtualMountRegistry.Load(name)
	if !ok {
		return false
	}
	entry := v.(*virtualMountRegistryEntry)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	return entry.servers != nil && virtualMountServersLive(entry.servers)
}

func TestProviderExitClearsLiveRegistryServers(t *testing.T) {
	_, servers, err := buildFFIVirtualMounts([]VirtualMountConfig{
		{GuestPath: "/a", Provider: stubPathFs{}},
		{GuestPath: "/b", Provider: stubPathFs{}},
	}, nil)
	if err != nil {
		t.Fatalf("buildFFIVirtualMounts: %v", err)
	}
	name := fmt.Sprintf("virtual-mount-exit-live-%d", os.Getpid())
	sandboxVirtualMountRegistry.Delete(name)
	registerVirtualMountServers(name, servers)
	if !virtualMountRegistryHasLiveServers(name) {
		t.Fatal("expected live registry servers after register")
	}

	servers[0].close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !virtualMountRegistryHasLiveServers(name) {
			sandboxVirtualMountRegistry.Delete(name)
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("expected registry servers cleared after provider exit")
}

func TestProviderExitShutsDownSiblingsBeforeRegistry(t *testing.T) {
	_, servers, err := buildFFIVirtualMounts([]VirtualMountConfig{
		{GuestPath: "/a", Provider: stubPathFs{}},
		{GuestPath: "/b", Provider: stubPathFs{}},
	}, nil)
	if err != nil {
		t.Fatalf("buildFFIVirtualMounts: %v", err)
	}
	name := fmt.Sprintf("virtual-mount-pre-reg-%d", os.Getpid())
	entry := &virtualMountRegistryEntry{servers: servers, refs: 1}
	watchVirtualMountProvidersStopped(name, entry, servers)

	dupFD, err := syscall.Dup(int(servers[1].childFile.Fd()))
	if err != nil {
		t.Fatalf("dup child fd: %v", err)
	}
	runtimeConn, err := net.FileConn(os.NewFile(uintptr(dupFD), "virtual-mount-child"))
	if err != nil {
		t.Fatalf("FileConn: %v", err)
	}
	t.Cleanup(func() { _ = runtimeConn.Close() })

	servers[0].close()

	deadline := time.Now().Add(2 * time.Second)
	buf := make([]byte, 1)
	for time.Now().Before(deadline) {
		_ = runtimeConn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		n, readErr := runtimeConn.Read(buf)
		if readErr == nil && n == 0 {
			return
		}
		if readErr != nil {
			return
		}
	}
	t.Fatal("expected sibling provider socket to close after first provider exit")
}

func TestConnectVirtualMountsRequiresLiveRegistry(t *testing.T) {
	const name = "virtual-mount-connect-no-registry"
	_, err := connectVirtualMounts(name, `{"had_virtual_mounts":true}`)
	if err == nil {
		t.Fatal("expected connect to fail without live registry entry")
	}
	if !strings.Contains(err.Error(), "virtual mount provider is not active") {
		t.Fatalf("error = %v", err)
	}
}

func TestConnectVirtualMountsWithLiveProviders(t *testing.T) {
	const name = "virtual-mount-connect-live-providers"
	_, servers, err := buildFFIVirtualMounts([]VirtualMountConfig{
		{GuestPath: "/inbox", Provider: stubPathFs{}},
	}, nil)
	if err != nil {
		t.Fatalf("buildFFIVirtualMounts: %v", err)
	}
	entry := registerVirtualMountServers(name, servers)
	defer teardownVirtualMountProvidersByName(name)

	connEntry, err := connectVirtualMounts(name, `{"had_virtual_mounts":true}`)
	if err != nil {
		t.Fatalf("connectVirtualMounts: %v", err)
	}
	if connEntry == nil {
		t.Fatal("expected non-nil connect entry")
	}
	releaseVirtualMountEntry(name, connEntry)
	releaseVirtualMountEntry(name, entry)
}

func TestCreateSandboxRejectsDetachedVirtualMount(t *testing.T) {
	_, err := CreateSandbox(context.Background(), "demo",
		WithImage("alpine"),
		WithDetached(),
		WithVirtualMount("/inbox", stubPathFs{}),
	)
	if err == nil {
		t.Fatal("expected error for detached + virtual mount")
	}
	if !strings.Contains(err.Error(), "virtual mounts") || !strings.Contains(err.Error(), "detached") {
		t.Fatalf("error = %v", err)
	}
}

func TestVirtualMountRestartBlockedForStatus(t *testing.T) {
	if err := virtualMountRestartBlockedForStatus("demo", false, SandboxStatusStopped); err != nil {
		t.Fatalf("unexpected block without had_virtual_mounts: %v", err)
	}
	err := virtualMountRestartBlockedForStatus("demo", true, SandboxStatusRunning)
	if err == nil || !strings.Contains(err.Error(), "Connect") {
		t.Fatalf("running: error = %v", err)
	}
	err = virtualMountRestartBlockedForStatus("demo", true, SandboxStatusStopped)
	if err == nil || !strings.Contains(err.Error(), "cannot restart a sandbox that used virtual mounts") {
		t.Fatalf("stopped: error = %v", err)
	}
}

func TestConnectVirtualMountsRejectsIncompleteCreate(t *testing.T) {
	_, err := connectVirtualMounts("demo", `{"attempted_virtual_mounts":true}`)
	if err == nil {
		t.Fatal("expected connect to fail for incomplete virtual-mount create")
	}
	if !strings.Contains(err.Error(), "did not complete successfully") {
		t.Fatalf("error = %v", err)
	}
}

func TestVirtualMountIncompleteCreateBlocksStart(t *testing.T) {
	err := virtualMountIncompleteCreateError("demo", "start")
	if err == nil || !strings.Contains(err.Error(), "did not complete successfully") {
		t.Fatalf("error = %v", err)
	}
}

func TestValidateCallTimeout(t *testing.T) {
	if err := validateCallTimeout(30 * time.Second); err != nil {
		t.Fatalf("30s: %v", err)
	}
	if err := validateCallTimeout(maxCallTimeoutSecs * time.Second); err != nil {
		t.Fatalf("max: %v", err)
	}
	err := validateCallTimeout((maxCallTimeoutSecs + 1) * time.Second)
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("over max: %v", err)
	}
}

func TestGuestMountTagDeterministic(t *testing.T) {
	a := guestMountTag("/data")
	b := guestMountTag("/data")
	if a != b || a == "" {
		t.Fatalf("guestMountTag = %q, %q", a, b)
	}
}

func TestTeardownVirtualMountProviders(t *testing.T) {
	_, servers, err := buildFFIVirtualMounts([]VirtualMountConfig{
		{GuestPath: "/inbox", Provider: stubPathFs{}},
	}, nil)
	if err != nil {
		t.Fatalf("buildFFIVirtualMounts: %v", err)
	}
	registerVirtualMountServers("by-name-stop", servers)
	teardownVirtualMountProvidersByName("by-name-stop")
	if sandboxHadVirtualMounts("by-name-stop") {
		t.Fatal("expected mark cleared after teardown")
	}
	// Idempotent second call.
	teardownVirtualMountProvidersByName("by-name-stop")
}

func TestTeardownForEntryDoesNotAffectReplacement(t *testing.T) {
	_, first, err := buildFFIVirtualMounts([]VirtualMountConfig{
		{GuestPath: "/inbox", Provider: stubPathFs{}},
	}, nil)
	if err != nil {
		t.Fatalf("buildFFIVirtualMounts: %v", err)
	}
	_, second, err := buildFFIVirtualMounts([]VirtualMountConfig{
		{GuestPath: "/inbox", Provider: stubPathFs{}},
	}, nil)
	if err != nil {
		t.Fatalf("buildFFIVirtualMounts: %v", err)
	}

	oldEntry := registerVirtualMountServers("gen", first)
	newEntry := registerVirtualMountServers("gen", second)
	t.Cleanup(func() { teardownVirtualMountProvidersForEntry("gen", newEntry) })

	// A stale teardown for the replaced generation must not touch the live one.
	teardownVirtualMountCapturedEntry("gen", oldEntry)
	releaseVirtualMountEntry("gen", oldEntry)

	newEntry.mu.Lock()
	alive := newEntry.servers != nil
	newEntry.mu.Unlock()
	if !alive {
		t.Fatal("replacement providers should remain live after stale teardown")
	}
}

func TestCapturedEntryTeardownAfterReplace(t *testing.T) {
	_, first, err := buildFFIVirtualMounts([]VirtualMountConfig{
		{GuestPath: "/inbox", Provider: stubPathFs{}},
	}, nil)
	if err != nil {
		t.Fatalf("buildFFIVirtualMounts: %v", err)
	}
	_, second, err := buildFFIVirtualMounts([]VirtualMountConfig{
		{GuestPath: "/inbox", Provider: stubPathFs{}},
	}, nil)
	if err != nil {
		t.Fatalf("buildFFIVirtualMounts: %v", err)
	}

	// Simulate SandboxHandle capturing the entry before a same-name replace.
	oldEntry := registerVirtualMountServers("handle-replace", first)
	registerVirtualMountServers("handle-replace", second)
	t.Cleanup(func() {
		if v, ok := sandboxVirtualMountRegistry.Load("handle-replace"); ok {
			teardownVirtualMountProvidersForEntry("handle-replace", v.(*virtualMountRegistryEntry))
		}
	})

	teardownVirtualMountCapturedEntry("handle-replace", oldEntry)

	v, ok := sandboxVirtualMountRegistry.Load("handle-replace")
	if !ok {
		t.Fatal("replacement entry should remain registered")
	}
	newEntry := v.(*virtualMountRegistryEntry)
	newEntry.mu.Lock()
	alive := newEntry.servers != nil
	newEntry.mu.Unlock()
	if !alive {
		t.Fatal("name-based teardown of a stale captured entry must not close the replacement")
	}
}

func TestScheduleTeardownTargetsEntryNotName(t *testing.T) {
	_, first, err := buildFFIVirtualMounts([]VirtualMountConfig{
		{GuestPath: "/inbox", Provider: stubPathFs{}},
	}, nil)
	if err != nil {
		t.Fatalf("buildFFIVirtualMounts: %v", err)
	}
	_, second, err := buildFFIVirtualMounts([]VirtualMountConfig{
		{GuestPath: "/inbox", Provider: stubPathFs{}},
	}, nil)
	if err != nil {
		t.Fatalf("buildFFIVirtualMounts: %v", err)
	}

	oldEntry := registerVirtualMountServers("wait-entry", first)
	// Simulate a background waiter that captured the old entry before replace.
	teardownVirtualMountProvidersForEntry("wait-entry", oldEntry)

	newEntry := registerVirtualMountServers("wait-entry", second)
	t.Cleanup(func() { teardownVirtualMountProvidersForEntry("wait-entry", newEntry) })

	newEntry.mu.Lock()
	alive := newEntry.servers != nil
	newEntry.mu.Unlock()
	if !alive {
		t.Fatal("late stale teardown must not close the replacement entry")
	}
}

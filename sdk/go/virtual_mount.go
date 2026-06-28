package microsandbox

import (
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
	"github.com/superradcompany/microsandbox/sdk/go/vfs"
)

// maxVirtualMounts matches microsandbox_runtime::vm::MAX_VIRTUAL_MOUNTS — keep
// in sync when either side changes.
const maxVirtualMounts = 16

// maxCallTimeoutSecs matches MAX_CALL_TIMEOUT_SECS in
// crates/filesystem/lib/backends/vfs/config.rs.
const maxCallTimeoutSecs = 86400

const maxCacheTimeoutSecs = 86400

// VfsCachePolicy controls FUSE kernel caching for a virtual mount.
type VfsCachePolicy string

const (
	// VfsCacheNever disables guest-side caching (direct I/O semantics).
	VfsCacheNever VfsCachePolicy = "never"
	// VfsCacheAuto lets the kernel decide when to cache.
	VfsCacheAuto VfsCachePolicy = "auto"
	// VfsCacheAlways enables aggressive attr/entry/data caching.
	VfsCacheAlways VfsCachePolicy = "always"
)

// VirtualMountConfig describes one programmable guest mount backed by a Go
// vfs.PathFs implementation in the parent process.
type VirtualMountConfig struct {
	GuestPath    string
	Provider     vfs.PathFs
	EntryTimeout time.Duration
	AttrTimeout  time.Duration
	CachePolicy  VfsCachePolicy
	Writeback    bool
	// CallTimeout bounds how long a single guest filesystem op waits for the
	// provider before it is failed (surfaced to the guest as EIO). Zero uses the
	// runtime default. Raise it for slow backends (cold object-store misses).
	CallTimeout time.Duration
}

// VirtualMountOption configures a virtual mount passed to WithVirtualMount.
type VirtualMountOption func(*VirtualMountConfig)

// WithVirtualMountEntryTimeout sets the FUSE entry cache timeout for the mount.
func WithVirtualMountEntryTimeout(d time.Duration) VirtualMountOption {
	return func(c *VirtualMountConfig) { c.EntryTimeout = d }
}

// WithVirtualMountAttrTimeout sets the FUSE attribute cache timeout for the mount.
func WithVirtualMountAttrTimeout(d time.Duration) VirtualMountOption {
	return func(c *VirtualMountConfig) { c.AttrTimeout = d }
}

// WithVirtualMountCachePolicy sets the FUSE cache policy for the mount.
func WithVirtualMountCachePolicy(policy VfsCachePolicy) VirtualMountOption {
	return func(c *VirtualMountConfig) { c.CachePolicy = policy }
}

// WithVirtualMountWriteback enables writeback caching for the mount.
func WithVirtualMountWriteback(enabled bool) VirtualMountOption {
	return func(c *VirtualMountConfig) { c.Writeback = enabled }
}

// WithVirtualMountCallTimeout sets how long a single guest filesystem op waits
// for the provider before failing with EIO. Zero uses the runtime default.
func WithVirtualMountCallTimeout(d time.Duration) VirtualMountOption {
	return func(c *VirtualMountConfig) { c.CallTimeout = d }
}

// WithVirtualMount mounts a programmable filesystem at guestPath. The provider
// must be safe for concurrent use from multiple goroutines.
//
// guestPath must be an absolute guest path (e.g. "/inbox").
//
// Virtual mounts require an attached sandbox: they cannot be used with
// WithDetached because the provider socket lives in this process.
//
// Keep the returned Sandbox handle open (or call Stop/Kill and wait) for the
// VM's lifetime. Always call Close before dropping a lifecycle-owning handle;
// Close on such a handle tears providers down once the VM reaches stopped state.
// If a handle is garbage-collected without Close, lifecycle owners defer
// provider release until the VM stops (guest I/O keeps working); Connect handles
// release their reference immediately.
func WithVirtualMount(guestPath string, provider vfs.PathFs, opts ...VirtualMountOption) SandboxOption {
	return func(o *SandboxConfig) {
		cfg := VirtualMountConfig{
			GuestPath: guestPath,
			Provider:  provider,
		}
		for _, opt := range opts {
			opt(&cfg)
		}
		o.VirtualMounts = append(o.VirtualMounts, cfg)
	}
}

type virtualMountServer struct {
	parentConn net.Conn
	childFile  *os.File
	done       chan struct{}
	closeOnce  sync.Once
}

// virtualMountCloseWait bounds how long close waits for the serve goroutine after
// shutting down the socketpair. Keep in sync with virtualMountServeShutdownWait.
const virtualMountCloseWait = 30 * time.Second

func (s *virtualMountServer) close() {
	s.closeOnce.Do(func() {
		if s.parentConn != nil {
			_ = s.parentConn.Close()
		}
		if s.childFile != nil {
			_ = s.childFile.Close()
		}
		if s.done != nil {
			select {
			case <-s.done:
			case <-time.After(virtualMountCloseWait):
				virtualMountLogf(
					"microsandbox: timed out waiting for virtual mount serve goroutine during close",
				)
			}
		}
	})
}

// isServing reports whether the virtual mount provider serve loop (`vfs.Serve`) is still running.
func (s *virtualMountServer) isServing() bool {
	if s.done == nil {
		return false
	}
	select {
	case <-s.done:
		return false
	default:
		return true
	}
}

func virtualMountServersLive(servers []virtualMountServer) bool {
	if len(servers) == 0 {
		return false
	}
	for i := range servers {
		if !servers[i].isServing() {
			return false
		}
	}
	return true
}

// validateGuestMountPath rejects guest paths the runtime would refuse, so the
// caller gets a fast, local error instead of one surfaced from deep in the FFI
// boundary. These rules intentionally mirror the Rust SDK's
// validate_guest_mount_path (sdk/rust/lib/sandbox/types.rs) — keep the two in
// sync when either changes.
func validateGuestMountPath(path string) error {
	if path == "" {
		return fmt.Errorf("guest path is required")
	}
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("guest path %q must be absolute", path)
	}
	if path == "/" {
		return fmt.Errorf("cannot mount a volume at guest root /")
	}
	if strings.ContainsAny(path, ":;,") {
		return fmt.Errorf("guest path %q must not contain ':', ';', or ','", path)
	}
	if strings.HasSuffix(path, "/") {
		return fmt.Errorf("guest path %q must not end with '/'", path)
	}
	if path == "/.msb" || strings.HasPrefix(path, "/.msb/") {
		return fmt.Errorf("guest path %q overlaps the reserved runtime tree at /.msb", path)
	}
	for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if component == ".." {
			return fmt.Errorf("guest path %q must not contain '..' components", path)
		}
		if component == "." {
			return fmt.Errorf("guest path %q must not contain '.' components", path)
		}
		if component == "" {
			return fmt.Errorf("guest path %q must not contain empty components", path)
		}
	}
	return nil
}

func virtualMountHasFsConfig(m VirtualMountConfig) bool {
	return m.EntryTimeout > 0 ||
		m.AttrTimeout > 0 ||
		m.CachePolicy != "" ||
		m.Writeback ||
		m.CallTimeout > 0
}

func virtualMountFsConfig(m VirtualMountConfig) *ffi.VirtualFsMountOptions {
	cfg := &ffi.VirtualFsMountOptions{
		Writeback: m.Writeback,
	}
	if secs := durationSecs(m.EntryTimeout); secs != nil {
		cfg.EntryTimeoutSecs = secs
	}
	if secs := durationSecs(m.AttrTimeout); secs != nil {
		cfg.AttrTimeoutSecs = secs
	}
	if m.CachePolicy != "" {
		policy := string(m.CachePolicy)
		cfg.CachePolicy = &policy
	}
	if secs := durationSecs(m.CallTimeout); secs != nil {
		cfg.CallTimeoutSecs = secs
	}
	return cfg
}

// durationSecs converts a duration to whole seconds for the Rust mount config.
// Sub-second values round up to 1 second; zero means "use the default".
func durationSecs(d time.Duration) *uint64 {
	if d <= 0 {
		return nil
	}
	// Round any positive sub-second duration up to 1s (the wire unit).
	secs := uint64((d + time.Second - 1) / time.Second)
	return &secs
}

// validateVfsCachePolicy accepts the cache-policy values the runtime
// understands. The accepted set mirrors the Rust side
// (VirtualFsMountConfig::validate / into_virtual_fs_config in
// crates/filesystem) — keep them in sync when adding a policy.
func validateVfsCachePolicy(policy VfsCachePolicy) error {
	switch policy {
	case "", VfsCacheNever, VfsCacheAuto, VfsCacheAlways:
		return nil
	default:
		return fmt.Errorf("invalid virtual mount cache_policy: %q", policy)
	}
}

func validateCallTimeout(d time.Duration) error {
	if d <= 0 {
		return nil
	}
	secs := (d + time.Second - 1) / time.Second
	if secs > maxCallTimeoutSecs {
		return fmt.Errorf(
			"invalid virtual mount call_timeout: too large (max %ds)",
			maxCallTimeoutSecs,
		)
	}
	return nil
}

func validateCacheTimeout(label string, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	secs := (d + time.Second - 1) / time.Second
	if secs > maxCacheTimeoutSecs {
		return fmt.Errorf(
			"invalid virtual mount %s: too large (max %ds)",
			label, maxCacheTimeoutSecs,
		)
	}
	return nil
}

// guestMountTag derives the stable virtio-fs tag / virtio-blk id for a guest
// path. Keep in sync with guest_mount_tag in sdk/rust/lib/runtime/spawn.rs.
//
// The 12-hex suffix is a truncated SHA-256 digest (48 bits). Collisions between
// unrelated paths are unlikely but possible — validate_virtual_mount_device_tags
// rejects duplicate tags among configured mounts.
func guestMountTag(guestPath string) string {
	const slugMax = 7
	const hashHexLen = 12

	slug := strings.TrimPrefix(strings.ReplaceAll(guestPath, "/", "_"), "_")
	if len(slug) > slugMax {
		slug = slug[:slugMax]
	}

	sum := sha256.Sum256([]byte(guestPath))
	var out strings.Builder
	out.Grow(len(slug) + 1 + hashHexLen)
	if slug != "" {
		out.WriteString(slug)
		out.WriteByte('_')
	}
	for i := 0; i < hashHexLen/2; i++ {
		fmt.Fprintf(&out, "%02x", sum[i])
	}
	return out.String()
}

// guestPathsOverlap reports whether two guest mount paths are the same or one
// is nested under the other. Keep in sync with guest_paths_overlap in
// sdk/rust/lib/sandbox/types.rs.
func guestPathsOverlap(a, b string) bool {
	if a == b {
		return true
	}
	isStrictPrefix := func(parent, child string) bool {
		return len(child) > len(parent) &&
			strings.HasPrefix(child, parent) &&
			child[len(parent)] == '/'
	}
	return isStrictPrefix(a, b) || isStrictPrefix(b, a)
}

func buildFFIVirtualMounts(mounts []VirtualMountConfig, volumeGuestPaths map[string]MountConfig) ([]ffi.VirtualMountOptions, []virtualMountServer, error) {
	if len(mounts) == 0 {
		return nil, nil, nil
	}
	if len(mounts) > maxVirtualMounts {
		return nil, nil, fmt.Errorf("too many virtual mounts (max %d)", maxVirtualMounts)
	}
	// Validate every mount before creating any sockets or serve goroutines, so
	// a later invalid mount cannot orphan servers already started for earlier
	// ones (leaking a goroutine, conn, and fd each).
	seen := make(map[string]struct{}, len(mounts))
	seenTags := make(map[string]string, len(mounts)+len(volumeGuestPaths))
	for guest, vol := range volumeGuestPaths {
		// Bind, named, and disk-image mounts each get a virtio-fs tag derived
		// from the guest path (tmpfs does not).
		if vol.Kind() == MountKindTmpfs {
			continue
		}
		tag := guestMountTag(guest)
		seenTags[tag] = guest
	}
	for _, mount := range mounts {
		for seenPath := range seen {
			if guestPathsOverlap(seenPath, mount.GuestPath) {
				return nil, nil, fmt.Errorf(
					"virtual mount guest path %q overlaps with %q",
					mount.GuestPath, seenPath,
				)
			}
		}
		seen[mount.GuestPath] = struct{}{}
		if mount.Provider == nil {
			return nil, nil, fmt.Errorf("virtual mount %q: provider is nil", mount.GuestPath)
		}
		if err := validateGuestMountPath(mount.GuestPath); err != nil {
			return nil, nil, fmt.Errorf("virtual mount: %w", err)
		}
		if err := validateVfsCachePolicy(mount.CachePolicy); err != nil {
			return nil, nil, fmt.Errorf("virtual mount %q: %w", mount.GuestPath, err)
		}
		if err := validateCallTimeout(mount.CallTimeout); err != nil {
			return nil, nil, fmt.Errorf("virtual mount %q: %w", mount.GuestPath, err)
		}
		if err := validateCacheTimeout("entry_timeout", mount.EntryTimeout); err != nil {
			return nil, nil, fmt.Errorf("virtual mount %q: %w", mount.GuestPath, err)
		}
		if err := validateCacheTimeout("attr_timeout", mount.AttrTimeout); err != nil {
			return nil, nil, fmt.Errorf("virtual mount %q: %w", mount.GuestPath, err)
		}
		for volumeGuest := range volumeGuestPaths {
			if guestPathsOverlap(volumeGuest, mount.GuestPath) {
				return nil, nil, fmt.Errorf(
					"virtual mount guest path %q conflicts with an existing volume mount at %q",
					mount.GuestPath, volumeGuest,
				)
			}
		}
		tag := guestMountTag(mount.GuestPath)
		if other, ok := seenTags[tag]; ok {
			return nil, nil, fmt.Errorf(
				"virtual mount guest path %q conflicts with %q (virtio tag %q)",
				mount.GuestPath, other, tag,
			)
		}
		seenTags[tag] = mount.GuestPath
	}

	out := make([]ffi.VirtualMountOptions, 0, len(mounts))
	servers := make([]virtualMountServer, 0, len(mounts))
	for _, mount := range mounts {
		parentConn, childFile, err := virtualMountSocketPair()
		if err != nil {
			closeVirtualMountServers(servers)
			return nil, nil, fmt.Errorf("virtual mount %q: %w", mount.GuestPath, err)
		}
		done := make(chan struct{})
		go func(conn net.Conn, fs vfs.PathFs) {
			defer close(done)
			_ = vfs.Serve(conn, fs, vfs.WithErrorLog(virtualMountLogf))
		}(parentConn, mount.Provider)

		vm := ffi.VirtualMountOptions{
			GuestPath: mount.GuestPath,
			FD:        int(childFile.Fd()),
		}
		if virtualMountHasFsConfig(mount) {
			vm.FsConfig = virtualMountFsConfig(mount)
		}
		out = append(out, vm)
		servers = append(servers, virtualMountServer{
			parentConn: parentConn,
			childFile:  childFile,
			done:       done,
		})
	}
	return out, servers, nil
}

func virtualMountSocketPair() (net.Conn, *os.File, error) {
	// Mark both raw fds close-on-exec so they don't leak into other subprocesses
	// the program execs. SOCK_CLOEXEC isn't portable (macOS socket() rejects it),
	// so set FD_CLOEXEC explicitly, holding ForkLock across creation+set so no
	// Go-initiated fork can inherit them in between. The child fd is still
	// inherited by the msb runtime: the Rust pre_exec relocation dup2's it onto
	// a fresh target fd (which clears close-on-exec) before exec.
	syscall.ForkLock.RLock()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		syscall.ForkLock.RUnlock()
		return nil, nil, err
	}
	syscall.CloseOnExec(fds[0])
	syscall.CloseOnExec(fds[1])
	syscall.ForkLock.RUnlock()
	parentFile := os.NewFile(uintptr(fds[0]), "virtual-mount-parent")
	childFile := os.NewFile(uintptr(fds[1]), "virtual-mount-child")
	if parentFile == nil || childFile == nil {
		if parentFile != nil {
			_ = parentFile.Close()
		}
		if childFile != nil {
			_ = childFile.Close()
		}
		return nil, nil, fmt.Errorf("socketpair: failed to wrap fds")
	}
	parentConn, err := net.FileConn(parentFile)
	_ = parentFile.Close()
	if err != nil {
		_ = childFile.Close()
		return nil, nil, err
	}
	return parentConn, childFile, nil
}

func closeVirtualMountServers(servers []virtualMountServer) {
	for i := range servers {
		servers[i].close()
	}
}

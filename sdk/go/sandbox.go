package microsandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

const (
	defaultStopTimeout = 10 * time.Second
	defaultKillTimeout = 5 * time.Second
)

// Sandbox represents a live microsandbox VM. It holds a Rust-side handle
// that must be released with Close.
//
// Sandbox is safe for concurrent use from multiple goroutines.
type Sandbox struct {
	inner *ffi.Sandbox
	// virtualMountEntry is this handle's release token for its virtual-mount provider
	// servers, or nil when the sandbox has none. Releasing through the entry
	// (rather than by name) keeps a replaced same-name sandbox from disturbing
	// this handle's refcount.
	virtualMountEntry *virtualMountRegistryEntry
	// virtualMountReleaseOnce schedules at most one background wait that releases
	// virtual-mount sockets after RequestStop/RequestKill observes stopped state.
	virtualMountReleaseOnce sync.Once
}

// CreateSandbox creates and boots a new sandbox. The returned Sandbox owns the
// VM process — call Close (or Stop + Close) when done.
//
// Sandbox names are limited to 128 UTF-8 bytes.
//
// ctx controls the boot operation only; cancelling ctx after this function
// returns has no effect on the running sandbox.
func CreateSandbox(ctx context.Context, name string, opts ...SandboxOption) (*Sandbox, error) {
	o := SandboxConfig{}
	for _, opt := range opts {
		opt(&o)
	}

	if o.Detached && len(o.VirtualMounts) > 0 {
		return nil, fmt.Errorf("virtual mounts cannot be used with detached sandboxes: the provider socket lives in the controlling process")
	}

	// Mirror Rust create_local: tear down any in-process providers for this
	// name before spawn so WithReplace without new virtual mounts cannot leave
	// zombie provider goroutines from the replaced sandbox.
	if o.Replace {
		teardownVirtualMountProvidersByName(name)
	}

	ffiOpts := buildFFICreateOptions(o)
	virtualMountServers, err := attachVirtualMounts(&ffiOpts, o)
	if err != nil {
		return nil, err
	}

	var virtualMountEntry *virtualMountRegistryEntry
	if len(virtualMountServers) > 0 {
		virtualMountEntry = registerVirtualMountServers(name, virtualMountServers)
	}

	inner, err := ffi.CreateSandbox(ctx, name, ffiOpts)
	if err != nil {
		// Rust create may have stopped the VM after post-spawn validation; close
		// the Go-side virtual mount serve loops (`vfs.Serve`) started in attachVirtualMounts.
		if virtualMountEntry != nil {
			teardownVirtualMountProvidersForEntry(name, virtualMountEntry)
		} else {
			closeVirtualMountServers(virtualMountServers)
		}
		// WithReplace may have stopped a prior same-name sandbox whose
		// providers are still registered; tear them down when already stopped.
		if prev, ok := sandboxVirtualMountRegistry.Load(name); ok && prev != virtualMountEntry {
			virtualMountEntryTeardownIfStopped(context.Background(), name, prev.(*virtualMountRegistryEntry))
		}
		return nil, wrapFFI(err)
	}
	for i := range virtualMountServers {
		// Rust spawn closes the child fd after dup; do not close it again here.
		virtualMountServers[i].childFile = nil
	}
	if virtualMountEntry != nil {
		if !virtualMountServersLive(virtualMountServers) {
			teardownVirtualMountProvidersForEntry(name, virtualMountEntry)
			abortSandboxAfterFailedVirtualMountCreate(ctx, name, inner)
			return nil, fmt.Errorf(
				"create sandbox %q: virtual mount provider exited before create completed",
				name,
			)
		}
		scheduleVirtualMountTeardownAfterStopped(context.Background(), name, virtualMountEntry)
	}
	return newSandboxWithVirtualMount(inner, virtualMountEntry), nil
}

// abortSandboxAfterFailedVirtualMountCreate stops a VM whose create succeeded at
// the FFI layer but failed post-create virtual-mount validation (mirrors Rust
// abort_sandbox_after_failed_create).
func abortSandboxAfterFailedVirtualMountCreate(ctx context.Context, name string, inner *ffi.Sandbox) {
	_ = inner.Close()
	stopCtx := context.WithoutCancel(ctx)
	stopMs := uint64(defaultStopTimeout / time.Millisecond)
	if err := ffi.StopSandboxByName(stopCtx, name, stopMs); err != nil {
		_ = ffi.KillSandboxByName(stopCtx, name, stopMs)
	}
}

func newSandboxWithVirtualMount(inner *ffi.Sandbox, virtualMountEntry *virtualMountRegistryEntry) *Sandbox {
	s := &Sandbox{inner: inner, virtualMountEntry: virtualMountEntry}
	if virtualMountEntry != nil {
		runtime.SetFinalizer(s, finalizeSandboxVirtualMount)
	}
	return s
}

// virtualMountFinalizeRelease runs when a Sandbox with virtual mounts is garbage-collected
// without Close(). Lifecycle owners defer provider teardown until stopped state
// is observed so a leaked handle does not break guest I/O on a still-running VM.
// Connect handles drop their reference immediately.
func virtualMountFinalizeRelease(name string, entry *virtualMountRegistryEntry, ownsLifecycle bool, ownsErr error) {
	if entry == nil {
		return
	}
	virtualMountLogf(
		"microsandbox: sandbox %q handle was garbage-collected without Close(); releasing virtual-mount provider reference",
		name,
	)
	if virtualMountCloseDefersRelease(ownsLifecycle, ownsErr) {
		scheduleVirtualMountTeardownAfterStopped(context.Background(), name, entry)
		return
	}
	releaseVirtualMountEntry(name, entry)
}

// finalizeSandboxVirtualMount is a last-resort leak guard when a Sandbox with virtual
// mounts is garbage-collected without Close().
func finalizeSandboxVirtualMount(s *Sandbox) {
	if s.virtualMountEntry == nil {
		return
	}
	name := s.inner.Name()
	entry := s.virtualMountEntry
	s.virtualMountEntry = nil
	runtime.SetFinalizer(s, nil)
	owns, err := s.inner.OwnsLifecycle()
	virtualMountFinalizeRelease(name, entry, owns, wrapFFI(err))
	// Best-effort: release the native handle when the Go wrapper was leaked.
	if err := wrapFFI(s.inner.Close()); err != nil && !IsKind(err, ErrInvalidHandle) {
		virtualMountLogf(
			"microsandbox: sandbox %q finalizer Close failed: %v",
			name, err,
		)
	}
}

func attachVirtualMounts(ffiOpts *ffi.CreateOptions, o SandboxConfig) ([]virtualMountServer, error) {
	if len(o.VirtualMounts) == 0 {
		return nil, nil
	}
	vms, servers, err := buildFFIVirtualMounts(o.VirtualMounts, o.Volumes)
	if err != nil {
		return nil, err
	}
	ffiOpts.VirtualMounts = vms
	return servers, nil
}

// buildFFICreateOptions translates SandboxConfig into the FFI wire shape.
// Extracted so tests can assert the JSON envelope without booting the runtime.
func buildFFICreateOptions(o SandboxConfig) ffi.CreateOptions {
	ffiOpts := ffi.CreateOptions{
		Image:           o.Image,
		ImageFstype:     o.ImageFstype,
		Snapshot:        o.Snapshot,
		MemoryMiB:       o.MemoryMiB,
		CPUs:            o.CPUs,
		Workdir:         o.Workdir,
		Shell:           o.Shell,
		SecurityProfile: string(o.SecurityProfile),
		Hostname:        o.Hostname,
		User:            o.User,
		Replace:         o.Replace,
		Env:             o.Env,
		Labels:          o.Labels,
		Detached:        o.Detached,
		Ephemeral:       o.Ephemeral,
		Entrypoint:      o.Entrypoint,
		LogLevel:        string(o.LogLevel),
		QuietLogs:       o.QuietLogs,
		Scripts:         o.Scripts,
		PullPolicy:      string(o.PullPolicy),
		MaxDurationSecs: durationSecsCeil(o.MaxDuration),
		IdleTimeoutSecs: durationSecsCeil(o.IdleTimeout),
		Ports:           o.Ports,
		PortsUDP:        o.PortsUDP,
		PortBindings:    buildFFIPortBindings(o.PortBindings),
	}
	if o.ociUpperSizeSet || o.OCIUpperSizeMiB != 0 {
		ffiOpts.OCIUpperSizeMiB = &o.OCIUpperSizeMiB
	}
	if o.ReplaceWithTimeout != nil {
		var ms uint64
		if d := *o.ReplaceWithTimeout; d > 0 {
			ms = uint64((d + time.Millisecond - 1) / time.Millisecond)
		}
		ffiOpts.ReplaceWithTimeoutMs = &ms
	}
	if o.Init != nil {
		init := &ffi.InitOptions{Cmd: o.Init.Cmd, Args: append([]string(nil), o.Init.Args...)}
		if len(o.Init.Env) > 0 {
			init.Env = make([][2]string, 0, len(o.Init.Env))
			for k, v := range o.Init.Env {
				init.Env = append(init.Env, [2]string{k, v})
			}
		}
		ffiOpts.Init = init
	}
	if o.RegistryAuth != nil {
		ffiOpts.RegistryAuth = &ffi.RegistryAuthOptions{
			Username: o.RegistryAuth.Username,
			Password: o.RegistryAuth.Password,
		}
	}

	if len(o.Volumes) > 0 {
		ffiOpts.Volumes = make(map[string]ffi.MountSpec, len(o.Volumes))
		for guestPath, m := range o.Volumes {
			ffiOpts.Volumes[guestPath] = ffi.MountSpec{
				Bind:               m.Bind,
				Named:              m.Named,
				NamedMode:          m.NamedMode,
				NamedKind:          m.NamedKind,
				Tmpfs:              m.Tmpfs,
				Disk:               m.Disk,
				Format:             m.Format,
				Fstype:             m.Fstype,
				Readonly:           m.Readonly,
				Noexec:             m.Noexec,
				Nosuid:             m.Nosuid,
				Nodev:              m.Nodev,
				SizeMiB:            m.SizeMiB,
				QuotaMiB:           m.QuotaMiB,
				StatVirtualization: string(m.StatVirtualization),
				HostPermissions:    string(m.HostPermissions),
			}
		}
	}

	if o.Network != nil {
		ffiOpts.Network = buildFFINetwork(o.Network)
	}

	for _, s := range o.Secrets {
		ffiOpts.Secrets = append(ffiOpts.Secrets, ffi.SecretOptions{
			EnvVar:            s.EnvVar,
			Value:             s.Value,
			AllowHosts:        s.AllowHosts,
			AllowHostPatterns: s.AllowHostPatterns,
			Placeholder:       s.Placeholder,
			RequireTLS:        s.RequireTLS,
			OnViolation:       string(s.OnViolation),
		})
	}

	for _, p := range o.Patches {
		ffiOpts.Patches = append(ffiOpts.Patches, ffi.PatchOptions{
			Kind:    string(p.Kind),
			Path:    p.Path,
			Content: p.Content,
			Mode:    p.Mode,
			Replace: p.Replace,
			Src:     p.Src,
			Dst:     p.Dst,
			Target:  p.Target,
			Link:    p.Link,
		})
	}

	return ffiOpts
}

// durationSecsCeil rounds a Duration up to whole seconds. Sub-second values
// round up to 1 so that "any positive timeout" remains positive on the wire.
func durationSecsCeil(d time.Duration) uint64 {
	if d <= 0 {
		return 0
	}
	return uint64((d + time.Second - 1) / time.Second)
}

func durationMillisCeil(d time.Duration) uint64 {
	if d <= 0 {
		return 0
	}
	return uint64((d + time.Millisecond - 1) / time.Millisecond)
}

func stopTimeoutMillis(opts []StopOption) uint64 {
	o := lifecycleOptions{timeout: defaultStopTimeout}
	for _, opt := range opts {
		opt(&o)
	}
	return durationMillisCeil(o.timeout)
}

func killTimeoutMillis(opts []KillOption) uint64 {
	o := lifecycleOptions{timeout: defaultKillTimeout}
	for _, opt := range opts {
		opt(&o)
	}
	return durationMillisCeil(o.timeout)
}

func sandboxStopResultFromFFI(result *ffi.SandboxStopResult) *SandboxStopResult {
	if result == nil {
		return nil
	}
	return &SandboxStopResult{
		Name:       result.Name,
		Status:     SandboxStatus(result.Status),
		ExitCode:   result.ExitCode,
		Signal:     result.Signal,
		ObservedAt: time.Unix(result.ObservedAtUnix, 0),
		Source:     result.Source,
	}
}

// buildFFINetwork converts a public NetworkConfig into its ffi counterpart.
func buildFFINetwork(n *NetworkConfig) *ffi.NetworkOptions {
	out := &ffi.NetworkOptions{
		Policy:              string(n.Policy),
		DNSRebindProtection: n.DNSRebindProtection,
		DenyDomains:         n.DenyDomains,
		DenyDomainSuffixes:  n.DenyDomainSuffixes,
		Ports:               n.Ports,
		PortBindings:        buildFFIPortBindings(n.PortBindings),
		IPv4Pool:            n.IPv4Pool,
		IPv6Pool:            n.IPv6Pool,
		MaxConnections:      n.MaxConnections,
		OnSecretViolation:   string(n.OnSecretViolation),
		TrustHostCAs:        n.TrustHostCAs,
	}

	if len(n.Rules) > 0 || n.DefaultEgress != "" || n.DefaultIngress != "" {
		cp := &ffi.CustomNetworkPolicy{
			DefaultEgress:  string(n.DefaultEgress),
			DefaultIngress: string(n.DefaultIngress),
		}
		for _, r := range n.Rules {
			rule := ffi.NetworkRule{
				Action:      string(r.Action),
				Direction:   string(r.Direction),
				Destination: r.Destination,
				Protocol:    string(r.Protocol),
				Port:        r.Port,
				Ports:       append([]string(nil), r.Ports...),
			}
			for _, p := range r.Protocols {
				rule.Protocols = append(rule.Protocols, string(p))
			}
			cp.Rules = append(cp.Rules, rule)
		}
		out.CustomPolicy = cp
	}

	if n.DNS != nil {
		out.DNS = &ffi.DNSOptions{
			RebindProtection: n.DNS.RebindProtection,
			Nameservers:      append([]string(nil), n.DNS.Nameservers...),
			QueryTimeoutMs:   n.DNS.QueryTimeoutMs,
		}
	}

	if n.TLS != nil {
		out.TLS = &ffi.TLSOptions{
			Bypass:           n.TLS.Bypass,
			VerifyUpstream:   n.TLS.VerifyUpstream,
			InterceptedPorts: n.TLS.InterceptedPorts,
			BlockQUIC:        n.TLS.BlockQUIC,
			CACert:           n.TLS.CACert,
			CAKey:            n.TLS.CAKey,
			UpstreamCACerts:  append([]string(nil), n.TLS.UpstreamCACerts...),
		}
	}

	return out
}

func buildFFIPortBindings(bindings []PortBinding) []ffi.PortBindingOptions {
	out := make([]ffi.PortBindingOptions, 0, len(bindings))
	for _, b := range bindings {
		out = append(out, ffi.PortBindingOptions{
			Bind:      b.Bind,
			HostPort:  b.HostPort,
			GuestPort: b.GuestPort,
			Protocol:  string(b.Protocol),
		})
	}
	return out
}

// GetSandbox returns metadata for a sandbox by name without connecting to it.
// Sandbox names are limited to 128 UTF-8 bytes.
// Returns ErrSandboxNotFound if no such sandbox exists. The returned
// SandboxHandle exposes Connect/Start/Stop/Kill/Remove to operate on the sandbox.
func GetSandbox(ctx context.Context, name string) (*SandboxHandle, error) {
	info, err := ffi.LookupSandbox(ctx, name)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return newSandboxHandle(info), nil
}

// StartSandbox boots a stopped sandbox by name and returns a live Sandbox.
// Sandbox names are limited to 128 UTF-8 bytes.
func StartSandbox(ctx context.Context, name string) (*Sandbox, error) {
	if err := virtualMountRestartBlocked(ctx, name); err != nil {
		return nil, err
	}
	inner, err := ffi.StartSandbox(ctx, name, false)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &Sandbox{inner: inner}, nil
}

// StartSandboxDetached boots a stopped sandbox in detached mode. The VM keeps
// running after the returned handle is released. Sandbox names are limited to
// 128 UTF-8 bytes.
func StartSandboxDetached(ctx context.Context, name string) (*Sandbox, error) {
	if err := virtualMountRestartBlocked(ctx, name); err != nil {
		return nil, err
	}
	inner, err := ffi.StartSandbox(ctx, name, true)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &Sandbox{inner: inner}, nil
}

// AllSandboxMetrics returns a point-in-time metrics snapshot for every running
// sandbox, keyed by sandbox name. Only running and draining sandboxes appear.
func AllSandboxMetrics(ctx context.Context) (map[string]*Metrics, error) {
	raw, err := ffi.AllSandboxMetrics(ctx)
	if err != nil {
		return nil, wrapFFI(err)
	}
	out := make(map[string]*Metrics, len(raw))
	for name, m := range raw {
		out[name] = &Metrics{
			CPUPercent:              m.CPUPercent,
			VCPUTimeNs:              m.VCPUTimeNs,
			MemoryBytes:             m.MemoryBytes,
			MemoryAvailableBytes:    m.MemoryAvailableBytes,
			MemoryHostResidentBytes: m.MemoryHostResidentBytes,
			MemoryLimitBytes:        m.MemoryLimitBytes,
			DiskReadBytes:           m.DiskReadBytes,
			DiskWriteBytes:          m.DiskWriteBytes,
			NetRxBytes:              m.NetRxBytes,
			NetTxBytes:              m.NetTxBytes,
			UpperUsedBytes:          m.UpperUsedBytes,
			UpperFreeBytes:          m.UpperFreeBytes,
			UpperHostAllocatedBytes: m.UpperHostAllocatedBytes,
			Uptime:                  m.Uptime,
		}
	}
	return out, nil
}

// SandboxFilter narrows the results of ListSandboxes. The zero value matches
// every sandbox. Build one fluently, e.g.
// NewSandboxFilter().WithLabels(map[string]string{"user.id": "alice"}).
type SandboxFilter struct {
	labels map[string]string
}

type lifecycleOptions struct {
	timeout time.Duration
}

// StopOption configures Sandbox.Stop and SandboxHandle.Stop.
type StopOption func(*lifecycleOptions)

// KillOption configures Sandbox.Kill and SandboxHandle.Kill.
type KillOption func(*lifecycleOptions)

// SandboxStopResult describes a terminal sandbox state observed by WaitUntilStopped.
type SandboxStopResult struct {
	Name       string
	Status     SandboxStatus
	ExitCode   *int
	Signal     *int
	ObservedAt time.Time
	Source     *string
}

// WithStopTimeout sets how long Stop waits for graceful shutdown before force-killing.
func WithStopTimeout(timeout time.Duration) StopOption {
	return func(o *lifecycleOptions) { o.timeout = timeout }
}

// WithKillTimeout sets how long Kill waits for stopped-state observation.
func WithKillTimeout(timeout time.Duration) KillOption {
	return func(o *lifecycleOptions) { o.timeout = timeout }
}

// NewSandboxFilter returns an empty filter that matches every sandbox.
func NewSandboxFilter() SandboxFilter { return SandboxFilter{} }

// WithLabels requires matched sandboxes to carry all of these labels
// (AND-matched). Repeated calls merge; later keys overwrite earlier ones.
func (f SandboxFilter) WithLabels(labels map[string]string) SandboxFilter {
	if f.labels == nil {
		f.labels = make(map[string]string, len(labels))
	}
	for k, v := range labels {
		f.labels[k] = v
	}
	return f
}

// ListSandboxes returns metadata for every known sandbox (running or stopped),
// ordered by creation time (newest first). Use ListSandboxesWith to narrow the
// results by labels.
func ListSandboxes(ctx context.Context) ([]*SandboxHandle, error) {
	return listSandboxes(ctx, nil)
}

// ListSandboxesWith returns sandbox metadata narrowed by a SandboxFilter, e.g.
// NewSandboxFilter().WithLabels(map[string]string{"user.id": "alice"}). Label
// selectors are AND-matched.
func ListSandboxesWith(ctx context.Context, filter SandboxFilter) ([]*SandboxHandle, error) {
	return listSandboxes(ctx, filter.labels)
}

func listSandboxes(ctx context.Context, labels map[string]string) ([]*SandboxHandle, error) {
	infos, err := ffi.ListSandboxes(ctx, labels)
	if err != nil {
		return nil, wrapFFI(err)
	}
	out := make([]*SandboxHandle, len(infos))
	for i, info := range infos {
		out[i] = newSandboxHandle(info)
	}
	return out, nil
}

// RemoveSandbox removes a stopped sandbox's persisted state by name.
// Sandbox names are limited to 128 UTF-8 bytes.
//
// This is a name-addressed API: it always targets the current sandbox record
// for name and does not check SandboxHandle db_id generation. Prefer
// (*SandboxHandle).Remove after GetSandbox when holding a metadata handle.
//
// When this process still hosts virtual-mount providers for name, they are torn
// down as part of remove so provider goroutines and sockets cannot leak after
// persisted state is deleted.
func RemoveSandbox(ctx context.Context, name string) error {
	entry := snapshotVirtualMountRegistryEntry(name)
	err := wrapFFI(ffi.RemoveSandbox(ctx, name))
	if err == nil {
		teardownVirtualMountCapturedEntry(name, entry)
	}
	return err
}

// ---------------------------------------------------------------------------
// SandboxHandle — lightweight metadata reference to a sandbox
// ---------------------------------------------------------------------------

// SandboxHandle is a lightweight reference to a sandbox's persisted state.
// It carries metadata (name, status, timestamps) and provides methods to
// connect, start, stop, or remove the sandbox. Obtain via GetSandbox.
type SandboxHandle struct {
	name          string
	status        SandboxStatus
	configJSON    string
	dbID          int32
	createdAtUnix *int64
	updatedAtUnix *int64
	// virtualMountEntry is the provider generation captured when this handle was created.
	// Stop/kill/remove tear down only this entry so a stale handle cannot disturb
	// a later same-name replace.
	virtualMountEntry *virtualMountRegistryEntry
}

func staleSandboxHandleError(name string) error {
	return &Error{
		Kind: ErrSandboxHandleStale,
		Message: fmt.Sprintf(
			"sandbox %q was replaced or removed since this handle was created; refresh the handle with GetSandbox before connect, start, stop, or remove",
			name,
		),
	}
}

func (h *SandboxHandle) ensureCurrent(ctx context.Context) (*SandboxHandle, error) {
	current, err := GetSandbox(ctx, h.name)
	if err != nil {
		return nil, err
	}
	if current.dbID != h.dbID {
		return nil, staleSandboxHandleError(h.name)
	}
	// When the native library omits db_id (0), fall back to updated_at so a
	// same-name replace is still detected. Also compare virtualMountEntry pointers when
	// virtual mounts captured a registry generation on this handle.
	if h.dbID == 0 && h.updatedAtUnix != nil && current.updatedAtUnix != nil &&
		*current.updatedAtUnix != *h.updatedAtUnix {
		return nil, staleSandboxHandleError(h.name)
	}
	if h.virtualMountEntry != nil && current.virtualMountEntry != h.virtualMountEntry {
		return nil, staleSandboxHandleError(h.name)
	}
	return current, nil
}

// reensureCurrent repeats the db_id generation check immediately before a
// name-addressed mutation so a same-name replace cannot slip in after an
// earlier ensureCurrent call.
func (h *SandboxHandle) reensureCurrent(ctx context.Context) error {
	_, err := h.ensureCurrent(ctx)
	return err
}

func newSandboxHandle(info *ffi.SandboxHandleInfo) *SandboxHandle {
	return &SandboxHandle{
		name:          info.Name,
		status:        SandboxStatus(info.Status),
		configJSON:    info.ConfigJSON,
		dbID:          info.DbID,
		createdAtUnix: info.CreatedAtUnix,
		updatedAtUnix: info.UpdatedAtUnix,
		virtualMountEntry:      snapshotVirtualMountRegistryEntry(info.Name),
	}
}

// Name returns the sandbox name. Names are limited to 128 UTF-8 bytes.
func (h *SandboxHandle) Name() string { return h.name }

// Status returns the sandbox's last-known lifecycle status.
//
// This reflects handle creation time. Call Refresh after same-name replace
// before relying on lifecycle methods; use Refresh to obtain a current status.
func (h *SandboxHandle) Status() SandboxStatus { return h.status }

// ConfigJSON returns the raw JSON configuration stored for this sandbox.
func (h *SandboxHandle) ConfigJSON() string { return h.configJSON }

// Config parses the stored sandbox configuration.
func (h *SandboxHandle) Config() (*SandboxConfig, error) {
	var config SandboxConfig
	if err := json.Unmarshal([]byte(h.configJSON), &config); err != nil {
		return nil, err
	}
	return &config, nil
}

// Refresh returns a fresh handle for the same sandbox name.
func (h *SandboxHandle) Refresh(ctx context.Context) (*SandboxHandle, error) {
	return GetSandbox(ctx, h.name)
}

// CreatedAt returns the sandbox creation time, or the zero value if unknown.
func (h *SandboxHandle) CreatedAt() time.Time {
	if h.createdAtUnix == nil {
		return time.Time{}
	}
	return time.Unix(*h.createdAtUnix, 0)
}

// UpdatedAt returns the last-updated time, or the zero value if unknown.
func (h *SandboxHandle) UpdatedAt() time.Time {
	if h.updatedAtUnix == nil {
		return time.Time{}
	}
	return time.Unix(*h.updatedAtUnix, 0)
}

// Metrics returns a point-in-time resource snapshot for this sandbox.
// The sandbox must be running or draining.
func (h *SandboxHandle) Metrics(ctx context.Context) (*Metrics, error) {
	if err := h.reensureCurrent(ctx); err != nil {
		return nil, err
	}
	m, err := ffi.SandboxHandleMetrics(ctx, h.name)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &Metrics{
		CPUPercent:              m.CPUPercent,
		VCPUTimeNs:              m.VCPUTimeNs,
		MemoryBytes:             m.MemoryBytes,
		MemoryAvailableBytes:    m.MemoryAvailableBytes,
		MemoryHostResidentBytes: m.MemoryHostResidentBytes,
		MemoryLimitBytes:        m.MemoryLimitBytes,
		DiskReadBytes:           m.DiskReadBytes,
		DiskWriteBytes:          m.DiskWriteBytes,
		NetRxBytes:              m.NetRxBytes,
		NetTxBytes:              m.NetTxBytes,
		UpperUsedBytes:          m.UpperUsedBytes,
		UpperFreeBytes:          m.UpperFreeBytes,
		UpperHostAllocatedBytes: m.UpperHostAllocatedBytes,
		Uptime:                  m.Uptime,
	}, nil
}

// Connect reattaches to the running sandbox and returns a live handle.
func (h *SandboxHandle) Connect(ctx context.Context) (*Sandbox, error) {
	current, err := h.ensureCurrent(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := configHadVirtualMounts(current.configJSON); err != nil {
		return nil, fmt.Errorf("connect sandbox %q: %w", h.name, err)
	}
	virtualMountEntry, err := connectVirtualMounts(h.name, current.configJSON)
	if err != nil {
		return nil, err
	}
	if err := h.reensureCurrent(ctx); err != nil {
		releaseVirtualMountEntry(h.name, virtualMountEntry)
		return nil, err
	}
	inner, err := ffi.ConnectSandbox(ctx, h.name)
	if err != nil {
		releaseVirtualMountEntry(h.name, virtualMountEntry)
		return nil, wrapFFI(err)
	}
	if virtualMountEntry != nil && !isLiveVirtualMountRegistryEntry(h.name, virtualMountEntry) {
		_ = inner.Close()
		releaseVirtualMountEntry(h.name, virtualMountEntry)
		return nil, virtualMountReconnectError(h.name)
	}
	return newSandboxWithVirtualMount(inner, virtualMountEntry), nil
}

// Start boots the sandbox (if stopped) and returns a live handle.
func (h *SandboxHandle) Start(ctx context.Context) (*Sandbox, error) {
	if err := h.reensureCurrent(ctx); err != nil {
		return nil, err
	}
	return StartSandbox(ctx, h.name)
}

// StartDetached boots the sandbox in detached mode.
func (h *SandboxHandle) StartDetached(ctx context.Context) (*Sandbox, error) {
	if err := h.reensureCurrent(ctx); err != nil {
		return nil, err
	}
	return StartSandboxDetached(ctx, h.name)
}

// Stop gracefully stops the sandbox and waits until stopped state is observed.
func (h *SandboxHandle) Stop(ctx context.Context, opts ...StopOption) error {
	if err := h.reensureCurrent(ctx); err != nil {
		return err
	}
	err := wrapFFI(ffi.StopSandboxByName(ctx, h.name, stopTimeoutMillis(opts)))
	releaseVirtualMountAfterSuccess(err, func() { teardownVirtualMountCapturedEntry(h.name, h.virtualMountEntry) })
	return err
}

// RequestStop requests graceful shutdown and returns once the request is sent.
//
// When the sandbox has virtual mounts, a background wait releases provider
// sockets once stopped state is observed.
func (h *SandboxHandle) RequestStop(ctx context.Context) error {
	if err := h.reensureCurrent(ctx); err != nil {
		return err
	}
	err := wrapFFI(ffi.RequestStopSandboxByName(ctx, h.name))
	if err == nil {
		scheduleVirtualMountTeardownForCapturedEntry(ctx, h.name, h.virtualMountEntry)
	}
	return err
}

// Kill force-kills the sandbox and waits until stopped state is observed.
func (h *SandboxHandle) Kill(ctx context.Context, opts ...KillOption) error {
	if err := h.reensureCurrent(ctx); err != nil {
		return err
	}
	err := wrapFFI(ffi.KillSandboxByName(ctx, h.name, killTimeoutMillis(opts)))
	releaseVirtualMountAfterSuccess(err, func() { teardownVirtualMountCapturedEntry(h.name, h.virtualMountEntry) })
	return err
}

// RequestKill requests force termination and returns once the request is sent.
//
// When the sandbox has virtual mounts, a background wait releases provider
// sockets once stopped state is observed.
func (h *SandboxHandle) RequestKill(ctx context.Context) error {
	if err := h.reensureCurrent(ctx); err != nil {
		return err
	}
	err := wrapFFI(ffi.RequestKillSandboxByName(ctx, h.name))
	if err == nil {
		scheduleVirtualMountTeardownForCapturedEntry(ctx, h.name, h.virtualMountEntry)
	}
	return err
}

// RequestDrain requests graceful drain and returns once the request is sent.
func (h *SandboxHandle) RequestDrain(ctx context.Context) error {
	if err := h.reensureCurrent(ctx); err != nil {
		return err
	}
	err := wrapFFI(ffi.RequestDrainSandboxByName(ctx, h.name))
	if err == nil {
		scheduleVirtualMountTeardownForCapturedEntry(ctx, h.name, h.virtualMountEntry)
	}
	return err
}

// WaitUntilStopped waits until this sandbox is observed in terminal state.
func (h *SandboxHandle) WaitUntilStopped(ctx context.Context) (*SandboxStopResult, error) {
	if err := h.reensureCurrent(ctx); err != nil {
		return nil, err
	}
	result, err := ffi.WaitSandboxByNameUntilStopped(ctx, h.name)
	return sandboxStopResultFromFFI(result), wrapFFI(err)
}

// Remove deletes the sandbox's persisted state. The sandbox must be stopped.
func (h *SandboxHandle) Remove(ctx context.Context) error {
	if err := h.reensureCurrent(ctx); err != nil {
		return err
	}
	err := wrapFFI(ffi.RemoveSandbox(ctx, h.name))
	if err == nil {
		teardownVirtualMountCapturedEntry(h.name, h.virtualMountEntry)
	}
	return err
}

// Snapshot captures this stopped sandbox under a bare name in the default
// snapshots directory.
func (h *SandboxHandle) Snapshot(ctx context.Context, name string) (*SnapshotArtifact, error) {
	if err := h.reensureCurrent(ctx); err != nil {
		return nil, err
	}
	info, err := ffi.SandboxHandleSnapshot(ctx, h.name, name)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return snapshotFromInfo(info), nil
}

// SnapshotTo captures this stopped sandbox to an explicit artifact directory.
func (h *SandboxHandle) SnapshotTo(ctx context.Context, path string) (*SnapshotArtifact, error) {
	if err := h.reensureCurrent(ctx); err != nil {
		return nil, err
	}
	info, err := ffi.SandboxHandleSnapshotTo(ctx, h.name, path)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return snapshotFromInfo(info), nil
}

// ---------------------------------------------------------------------------
// Live sandbox methods
// ---------------------------------------------------------------------------

// Name returns the sandbox's name. Names are limited to 128 UTF-8 bytes.
func (s *Sandbox) Name() string { return s.inner.Name() }

// Stop gracefully stops the sandbox and waits until stopped state is observed.
func (s *Sandbox) Stop(ctx context.Context, opts ...StopOption) error {
	err := wrapFFI(s.inner.Stop(ctx, stopTimeoutMillis(opts)))
	releaseVirtualMountAfterSuccess(err, s.teardownVirtualMountAfterVMStopped)
	return err
}

// RequestStop requests graceful shutdown and returns once the request is sent.
//
// When the sandbox has virtual mounts, a background wait releases provider
// sockets once stopped state is observed, so dropping the handle after
// RequestStop alone does not leak goroutines or socket pairs.
func (s *Sandbox) RequestStop(ctx context.Context) error {
	err := wrapFFI(s.inner.RequestStop(ctx))
	if err == nil {
		s.scheduleReleaseVirtualMountWhenStopped(ctx)
	}
	return err
}

// Kill force-kills the sandbox and waits until stopped state is observed.
func (s *Sandbox) Kill(ctx context.Context, opts ...KillOption) error {
	err := wrapFFI(s.inner.Kill(ctx, killTimeoutMillis(opts)))
	releaseVirtualMountAfterSuccess(err, s.teardownVirtualMountAfterVMStopped)
	return err
}

// RequestKill requests force termination and returns once the request is sent.
//
// When the sandbox has virtual mounts, a background wait releases provider
// sockets once stopped state is observed (same as [Sandbox.RequestStop]).
func (s *Sandbox) RequestKill(ctx context.Context) error {
	err := wrapFFI(s.inner.RequestKill(ctx))
	if err == nil {
		s.scheduleReleaseVirtualMountWhenStopped(ctx)
	}
	return err
}

// Close releases the Rust-side handle. Safe to call multiple times; the
// second call returns ErrInvalidHandle.
//
// For a sandbox created with WithDetached(), Close will stop the VM —
// use Detach instead if the intent is to leave the sandbox running.
//
// When the sandbox has virtual mounts, a lifecycle-owning handle defers
// provider teardown until stopped state is observed (same as RequestStop), so
// the guest can finish I/O during shutdown. Connect handles only drop their
// handle reference; sockets stay up until the VM stops.
func (s *Sandbox) Close() error {
	err := wrapFFI(s.inner.Close())
	s.releaseVirtualMountsAfterClose()
	return err
}

// releaseVirtualMountsAfterClose tears down or schedules teardown of
// virtual-mount provider sockets after Close (even when the FFI close fails).
func (s *Sandbox) releaseVirtualMountsAfterClose() {
	if s.virtualMountEntry == nil {
		return
	}
	owns, err := s.inner.OwnsLifecycle()
	if virtualMountCloseDefersRelease(owns, wrapFFI(err)) {
		s.scheduleReleaseVirtualMountWhenStopped(context.Background())
	}
	s.dropVirtualMountHandleRef()
}

// virtualMountCloseDefersRelease reports whether Close should wait for stopped state
// before releasing virtual-mount sockets. Lifecycle owners (and handles where
// ownership cannot be determined) defer; Connect handles release immediately.
func virtualMountCloseDefersRelease(ownsLifecycle bool, ownsErr error) bool {
	return ownsErr != nil || ownsLifecycle
}

// releaseVirtualMountAfterSuccess releases virtual-mount provider sockets when an
// operation that stops or closes the sandbox succeeded.
func releaseVirtualMountAfterSuccess(err error, release func()) {
	if err == nil {
		release()
	}
}

func (s *Sandbox) dropVirtualMountHandleRef() {
	if s.virtualMountEntry == nil {
		return
	}
	runtime.SetFinalizer(s, nil)
	releaseVirtualMountEntry(s.inner.Name(), s.virtualMountEntry)
	s.virtualMountEntry = nil
}

func (s *Sandbox) teardownVirtualMountAfterVMStopped() {
	teardownVirtualMountProvidersForEntry(s.inner.Name(), s.virtualMountEntry)
	s.dropVirtualMountHandleRef()
}

// scheduleReleaseVirtualMountWhenStopped waits for terminal state after a non-blocking
// stop/kill request, then tears down virtual-mount provider sockets. Stop/Kill
// tear down synchronously; this covers RequestStop/RequestKill without requiring
// another call before the handle is dropped. Provider sockets are always torn
// down afterward, even when the wait fails, so a wedged or already-torn-down
// handle cannot leak goroutines or registry entries.
func (s *Sandbox) scheduleReleaseVirtualMountWhenStopped(ctx context.Context) {
	if s.virtualMountEntry == nil {
		return
	}
	s.virtualMountReleaseOnce.Do(func() {
		scheduleVirtualMountTeardownAfterStopped(ctx, s.inner.Name(), s.virtualMountEntry)
	})
}

// scheduleVirtualMountTeardownAfterStoppedForName schedules teardown for name's current
// live registry entry.
func scheduleVirtualMountTeardownAfterStoppedForName(ctx context.Context, name string) {
	if entry := snapshotVirtualMountRegistryEntry(name); entry != nil {
		scheduleVirtualMountTeardownAfterStopped(ctx, name, entry)
	}
}

// Detach releases the Rust-side handle without stopping the VM. Use this
// on sandboxes created with WithDetached() once the caller is done with
// the handle but the sandbox should continue running in the background.
//
// After Detach, the handle is invalid; a subsequent Close returns
// ErrInvalidHandle.
//
// Detach is rejected for a sandbox with virtual mounts: the provider socket
// lives in this process, so detaching (which is meant to outlive the handle)
// would stop serving the mount and leak its goroutine/socket/registry entry.
// This mirrors the same restriction enforced at creation time.
func (s *Sandbox) Detach(ctx context.Context) error {
	if s.virtualMountEntry != nil {
		return fmt.Errorf("cannot detach a sandbox with virtual mounts: the provider socket lives in this process and would stop serving once detached")
	}
	return wrapFFI(s.inner.Detach(ctx))
}

// RequestDrain requests graceful drain and returns once the request is sent.
func (s *Sandbox) RequestDrain(ctx context.Context) error {
	err := wrapFFI(s.inner.RequestDrain(ctx))
	if err == nil {
		s.scheduleReleaseVirtualMountWhenStopped(ctx)
	}
	return err
}

// WaitUntilStopped waits until this sandbox is observed in terminal state.
func (s *Sandbox) WaitUntilStopped(ctx context.Context) (*SandboxStopResult, error) {
	result, err := s.inner.WaitUntilStopped(ctx)
	return sandboxStopResultFromFFI(result), wrapFFI(err)
}

// OwnsLifecycle reports whether this handle owns the VM process. When true,
// closing or stopping the handle terminates the sandbox.
//
// The error return covers stale handles and FFI-layer failures; callers that
// don't care can use OwnsLifecycleOrFalse.
func (s *Sandbox) OwnsLifecycle() (bool, error) {
	owns, err := s.inner.OwnsLifecycle()
	return owns, wrapFFI(err)
}

// OwnsLifecycleOrFalse is a convenience that swallows the error and returns
// false on any failure. Suitable for log lines and best-effort branching.
func (s *Sandbox) OwnsLifecycleOrFalse() bool {
	owns, err := s.inner.OwnsLifecycle()
	return err == nil && owns
}

// Attach starts an interactive PTY session running cmd with optional args.
// It blocks until the process exits and returns the exit code.
// The caller's terminal must be a real TTY; this is primarily useful for
// CLI tools, not library code.
func (s *Sandbox) Attach(ctx context.Context, cmd string, args ...string) (int, error) {
	code, err := s.inner.Attach(ctx, cmd, args)
	return code, wrapFFI(err)
}

// AttachShell starts an interactive PTY session in the sandbox's default shell.
// It blocks until the shell exits and returns the exit code.
func (s *Sandbox) AttachShell(ctx context.Context) (int, error) {
	code, err := s.inner.AttachShell(ctx)
	return code, wrapFFI(err)
}

// FS returns a filesystem accessor for this sandbox.
func (s *Sandbox) FS() *SandboxFSOps {
	return &SandboxFSOps{sandbox: s}
}

// Metrics returns the current resource usage for this sandbox.
func (s *Sandbox) Metrics(ctx context.Context) (*Metrics, error) {
	m, err := s.inner.Metrics(ctx)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &Metrics{
		CPUPercent:              m.CPUPercent,
		VCPUTimeNs:              m.VCPUTimeNs,
		MemoryBytes:             m.MemoryBytes,
		MemoryAvailableBytes:    m.MemoryAvailableBytes,
		MemoryHostResidentBytes: m.MemoryHostResidentBytes,
		MemoryLimitBytes:        m.MemoryLimitBytes,
		DiskReadBytes:           m.DiskReadBytes,
		DiskWriteBytes:          m.DiskWriteBytes,
		NetRxBytes:              m.NetRxBytes,
		NetTxBytes:              m.NetTxBytes,
		UpperUsedBytes:          m.UpperUsedBytes,
		UpperFreeBytes:          m.UpperFreeBytes,
		UpperHostAllocatedBytes: m.UpperHostAllocatedBytes,
		Uptime:                  m.Uptime,
	}, nil
}

// MetricsStreamHandle is a live metrics subscription. Obtain via
// Sandbox.MetricsStream. Call Close to release Rust-side resources.
type MetricsStreamHandle struct {
	inner *ffi.MetricsStreamHandle
}

// Recv blocks until the next metrics snapshot arrives or ctx is cancelled.
// Returns nil, nil when the stream has ended (sandbox exited).
func (h *MetricsStreamHandle) Recv(ctx context.Context) (*Metrics, error) {
	m, err := h.inner.Recv(ctx)
	if err != nil {
		return nil, wrapFFI(err)
	}
	if m == nil {
		return nil, nil
	}
	return &Metrics{
		CPUPercent:              m.CPUPercent,
		VCPUTimeNs:              m.VCPUTimeNs,
		MemoryBytes:             m.MemoryBytes,
		MemoryAvailableBytes:    m.MemoryAvailableBytes,
		MemoryHostResidentBytes: m.MemoryHostResidentBytes,
		MemoryLimitBytes:        m.MemoryLimitBytes,
		DiskReadBytes:           m.DiskReadBytes,
		DiskWriteBytes:          m.DiskWriteBytes,
		NetRxBytes:              m.NetRxBytes,
		NetTxBytes:              m.NetTxBytes,
		UpperUsedBytes:          m.UpperUsedBytes,
		UpperFreeBytes:          m.UpperFreeBytes,
		UpperHostAllocatedBytes: m.UpperHostAllocatedBytes,
		Uptime:                  m.Uptime,
	}, nil
}

// Close stops the metrics stream and releases Rust-side resources.
func (h *MetricsStreamHandle) Close() error {
	return wrapFFI(h.inner.Close())
}

// MetricsStream starts a streaming metrics subscription that delivers a
// snapshot every interval. Close the returned handle when done.
//
// interval is rounded up to milliseconds; a zero or negative value uses the
// runtime minimum (~1 ms).
func (s *Sandbox) MetricsStream(ctx context.Context, interval time.Duration) (*MetricsStreamHandle, error) {
	var ms uint64
	if interval > 0 {
		ms = uint64((interval + time.Millisecond - 1) / time.Millisecond)
	}
	h, err := s.inner.MetricsStream(ctx, ms)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &MetricsStreamHandle{inner: h}, nil
}

// Metrics is a snapshot of sandbox resource usage.
type Metrics struct {
	CPUPercent              float64
	VCPUTimeNs              uint64
	MemoryBytes             uint64
	MemoryAvailableBytes    *uint64
	MemoryHostResidentBytes *uint64
	MemoryLimitBytes        uint64
	DiskReadBytes           uint64
	DiskWriteBytes          uint64
	NetRxBytes              uint64
	NetTxBytes              uint64
	UpperUsedBytes          *uint64
	UpperFreeBytes          *uint64
	UpperHostAllocatedBytes *uint64
	Uptime                  time.Duration
}

package microsandbox

import (
	"context"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// Sandbox represents a live microsandbox VM. It holds a Rust-side handle
// that must be released with Close.
//
// Sandbox is safe for concurrent use from multiple goroutines.
type Sandbox struct {
	inner *ffi.Sandbox
}

// CreateSandbox creates and boots a new sandbox. The returned Sandbox owns the
// VM process — call Close (or StopAndWait + Close) when done.
//
// ctx controls the boot operation only; cancelling ctx after this function
// returns has no effect on the running sandbox.
func CreateSandbox(ctx context.Context, name string, opts ...SandboxOption) (*Sandbox, error) {
	o := SandboxConfig{}
	for _, opt := range opts {
		opt(&o)
	}

	ffiOpts := ffi.CreateOptions{
		Image:     o.Image,
		MemoryMiB: o.MemoryMiB,
		CPUs:      o.CPUs,
		Workdir:   o.Workdir,
		Env:       o.Env,
		Detached:  o.Detached,
		Ports:     o.Ports,
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
		})
	}

	for _, p := range o.Patches {
		ffiOpts.Patches = append(ffiOpts.Patches, ffi.PatchOptions{
			Kind:    p.Kind,
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

	inner, err := ffi.CreateSandbox(ctx, name, ffiOpts)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &Sandbox{inner: inner}, nil
}

// CreateSandboxDetached creates and boots a sandbox in detached mode. The VM
// continues running after the returned handle is released or the Go process
// exits. Reattach via GetSandbox.
func CreateSandboxDetached(ctx context.Context, name string, opts ...SandboxOption) (*Sandbox, error) {
	opts = append(opts, WithDetached())
	return CreateSandbox(ctx, name, opts...)
}

// buildFFINetwork converts a public NetworkConfig into its ffi counterpart.
func buildFFINetwork(n *NetworkConfig) *ffi.NetworkOptions {
	out := &ffi.NetworkOptions{
		Policy:              n.Policy,
		BlockDomains:        n.BlockDomains,
		BlockDomainSuffixes: n.BlockDomainSuffixes,
		DNSRebindProtection: n.DNSRebindProtection,
		Ports:               n.Ports,
	}

	if len(n.Rules) > 0 || n.DefaultAction != "" {
		cp := &ffi.CustomNetworkPolicy{DefaultAction: n.DefaultAction}
		for _, r := range n.Rules {
			cp.Rules = append(cp.Rules, ffi.NetworkRule{
				Action:      r.Action,
				Direction:   r.Direction,
				Destination: r.Destination,
				Protocol:    r.Protocol,
				Port:        r.Port,
			})
		}
		out.CustomPolicy = cp
	}

	if n.TLS != nil {
		out.TLS = &ffi.TLSOptions{
			Bypass:           n.TLS.Bypass,
			VerifyUpstream:   n.TLS.VerifyUpstream,
			InterceptedPorts: n.TLS.InterceptedPorts,
			BlockQUIC:        n.TLS.BlockQUIC,
			CACert:           n.TLS.CACert,
			CAKey:            n.TLS.CAKey,
		}
	}

	return out
}

// GetSandbox returns metadata for a sandbox by name without connecting to it.
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
func StartSandbox(ctx context.Context, name string) (*Sandbox, error) {
	inner, err := ffi.StartSandbox(ctx, name, false)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &Sandbox{inner: inner}, nil
}

// StartSandboxDetached boots a stopped sandbox in detached mode. The VM keeps
// running after the returned handle is released.
func StartSandboxDetached(ctx context.Context, name string) (*Sandbox, error) {
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
			CPUPercent:       m.CPUPercent,
			MemoryBytes:      m.MemoryBytes,
			MemoryLimitBytes: m.MemoryLimitBytes,
			DiskReadBytes:    m.DiskReadBytes,
			DiskWriteBytes:   m.DiskWriteBytes,
			NetRxBytes:       m.NetRxBytes,
			NetTxBytes:       m.NetTxBytes,
			Uptime:           m.Uptime,
		}
	}
	return out, nil
}

// ListSandboxes returns the names of all known sandboxes.
func ListSandboxes(ctx context.Context) ([]string, error) {
	names, err := ffi.ListSandboxes(ctx)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return names, nil
}

// RemoveSandbox removes a stopped sandbox's persisted state by name.
func RemoveSandbox(ctx context.Context, name string) error {
	return wrapFFI(ffi.RemoveSandbox(ctx, name))
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
	createdAtUnix *int64
	updatedAtUnix *int64
}

func newSandboxHandle(info *ffi.SandboxHandleInfo) *SandboxHandle {
	return &SandboxHandle{
		name:          info.Name,
		status:        SandboxStatus(info.Status),
		configJSON:    info.ConfigJSON,
		createdAtUnix: info.CreatedAtUnix,
		updatedAtUnix: info.UpdatedAtUnix,
	}
}

// Name returns the sandbox name.
func (h *SandboxHandle) Name() string { return h.name }

// Status returns the sandbox's last-known lifecycle status.
func (h *SandboxHandle) Status() SandboxStatus { return h.status }

// ConfigJSON returns the raw JSON configuration stored for this sandbox.
func (h *SandboxHandle) ConfigJSON() string { return h.configJSON }

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
	m, err := ffi.SandboxHandleMetrics(ctx, h.name)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &Metrics{
		CPUPercent:       m.CPUPercent,
		MemoryBytes:      m.MemoryBytes,
		MemoryLimitBytes: m.MemoryLimitBytes,
		DiskReadBytes:    m.DiskReadBytes,
		DiskWriteBytes:   m.DiskWriteBytes,
		NetRxBytes:       m.NetRxBytes,
		NetTxBytes:       m.NetTxBytes,
		Uptime:           m.Uptime,
	}, nil
}

// Connect reattaches to the running sandbox and returns a live handle.
func (h *SandboxHandle) Connect(ctx context.Context) (*Sandbox, error) {
	inner, err := ffi.ConnectSandbox(ctx, h.name)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &Sandbox{inner: inner}, nil
}

// Start boots the sandbox (if stopped) and returns a live handle.
func (h *SandboxHandle) Start(ctx context.Context) (*Sandbox, error) {
	return StartSandbox(ctx, h.name)
}

// StartDetached boots the sandbox in detached mode.
func (h *SandboxHandle) StartDetached(ctx context.Context) (*Sandbox, error) {
	return StartSandboxDetached(ctx, h.name)
}

// Stop gracefully stops the sandbox.
func (h *SandboxHandle) Stop(ctx context.Context) error {
	return wrapFFI(ffi.StopSandboxByName(ctx, h.name))
}

// Kill terminates the sandbox immediately.
func (h *SandboxHandle) Kill(ctx context.Context) error {
	return wrapFFI(ffi.KillSandboxByName(ctx, h.name))
}

// Remove deletes the sandbox's persisted state. The sandbox must be stopped.
func (h *SandboxHandle) Remove(ctx context.Context) error {
	return RemoveSandbox(ctx, h.name)
}

// ---------------------------------------------------------------------------
// Live sandbox methods
// ---------------------------------------------------------------------------

// Name returns the sandbox's name.
func (s *Sandbox) Name() string { return s.inner.Name() }

// Stop gracefully stops the sandbox. It does not wait for the VM process
// to exit — use StopAndWait for that.
func (s *Sandbox) Stop(ctx context.Context) error {
	return wrapFFI(s.inner.Stop(ctx))
}

// StopAndWait stops the sandbox and waits for its VM process to exit.
// Returns the exit code (-1 if the guest didn't report one).
func (s *Sandbox) StopAndWait(ctx context.Context) (int, error) {
	code, err := s.inner.StopAndWait(ctx)
	return code, wrapFFI(err)
}

// Kill terminates the sandbox immediately.
func (s *Sandbox) Kill(ctx context.Context) error {
	return wrapFFI(s.inner.Kill(ctx))
}

// Close releases the Rust-side handle. Safe to call multiple times; the
// second call returns ErrInvalidHandle.
//
// For a sandbox created with WithDetached(), Close will stop the VM —
// use Detach instead if the intent is to leave the sandbox running.
func (s *Sandbox) Close() error {
	return wrapFFI(s.inner.Close())
}

// Detach releases the Rust-side handle without stopping the VM. Use this
// on sandboxes created with WithDetached() once the caller is done with
// the handle but the sandbox should continue running in the background.
//
// After Detach, the handle is invalid; a subsequent Close returns
// ErrInvalidHandle.
func (s *Sandbox) Detach(ctx context.Context) error {
	return wrapFFI(s.inner.Detach(ctx))
}

// Drain sends a graceful drain signal (SIGUSR1) to the sandbox. This is only
// meaningful if the guest process handles SIGUSR1; it will error if this
// handle does not own the lifecycle.
func (s *Sandbox) Drain(ctx context.Context) error {
	return wrapFFI(s.inner.Drain(ctx))
}

// Wait blocks until the sandbox process exits and returns its exit code.
// Returns -1 if the guest did not report an exit code. Errors if this handle
// does not own the lifecycle.
func (s *Sandbox) Wait(ctx context.Context) (int, error) {
	code, err := s.inner.Wait(ctx)
	return code, wrapFFI(err)
}

// OwnsLifecycle reports whether this handle owns the VM process. When true,
// closing or stopping the handle terminates the sandbox.
func (s *Sandbox) OwnsLifecycle() bool {
	owns, _ := s.inner.OwnsLifecycle()
	return owns
}

// RemovePersisted removes the sandbox's persisted state (filesystem and
// database record). The sandbox must already be stopped. This handle becomes
// invalid after the call.
func (s *Sandbox) RemovePersisted(ctx context.Context) error {
	return wrapFFI(s.inner.RemovePersisted(ctx))
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
func (s *Sandbox) FS() *SandboxFs {
	return &SandboxFs{sandbox: s}
}

// Metrics returns the current resource usage for this sandbox.
func (s *Sandbox) Metrics(ctx context.Context) (*Metrics, error) {
	m, err := s.inner.Metrics(ctx)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &Metrics{
		CPUPercent:       m.CPUPercent,
		MemoryBytes:      m.MemoryBytes,
		MemoryLimitBytes: m.MemoryLimitBytes,
		DiskReadBytes:    m.DiskReadBytes,
		DiskWriteBytes:   m.DiskWriteBytes,
		NetRxBytes:       m.NetRxBytes,
		NetTxBytes:       m.NetTxBytes,
		Uptime:           m.Uptime,
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
		CPUPercent:       m.CPUPercent,
		MemoryBytes:      m.MemoryBytes,
		MemoryLimitBytes: m.MemoryLimitBytes,
		DiskReadBytes:    m.DiskReadBytes,
		DiskWriteBytes:   m.DiskWriteBytes,
		NetRxBytes:       m.NetRxBytes,
		NetTxBytes:       m.NetTxBytes,
		Uptime:           m.Uptime,
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
	CPUPercent       float64
	MemoryBytes      uint64
	MemoryLimitBytes uint64
	DiskReadBytes    uint64
	DiskWriteBytes   uint64
	NetRxBytes       uint64
	NetTxBytes       uint64
	Uptime           time.Duration
}

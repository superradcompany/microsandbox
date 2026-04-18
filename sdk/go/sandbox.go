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

// NewSandbox creates and boots a new sandbox. The returned Sandbox owns the
// VM process — call Close (or StopAndWait + Close) when done.
//
// ctx controls the boot operation only; cancelling ctx after this function
// returns has no effect on the running sandbox.
func NewSandbox(ctx context.Context, name string, opts ...SandboxOption) (*Sandbox, error) {
	o := SandboxOptions{}
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

// buildFFINetwork converts a public NetworkOptions into its ffi counterpart.
func buildFFINetwork(n *NetworkOptions) *ffi.NetworkOptions {
	out := &ffi.NetworkOptions{
		Policy:              n.Policy,
		BlockDomains:        n.BlockDomains,
		BlockDomainSuffixes: n.BlockDomainSuffixes,
		DNSRebindProtection: n.DNSRebindProtection,
		Ports:               n.Ports,
	}

	if n.CustomPolicy != nil {
		cp := &ffi.CustomNetworkPolicy{DefaultAction: n.CustomPolicy.DefaultAction}
		for _, r := range n.CustomPolicy.Rules {
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

// GetSandbox reattaches to an existing sandbox by name. Returns an error
// with Kind==ErrSandboxNotFound if no such sandbox exists.
func GetSandbox(ctx context.Context, name string) (*Sandbox, error) {
	inner, err := ffi.GetSandbox(ctx, name)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &Sandbox{inner: inner}, nil
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
// For an attached sandbox the caller typically calls StopAndWait first;
// for a handle obtained via GetSandbox, Close alone is enough.
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

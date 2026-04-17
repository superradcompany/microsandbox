package microsandbox

import (
	"context"

	"github.com/Khrees2412/microsandbox/sdk/go/internal/ffi"
)

// Sandbox represents a running microsandbox instance.
// It provides methods for execution, filesystem access, and lifecycle management.
type Sandbox struct {
	name   string
	ffi    ffi.FFI
	handle ffi.SandboxHandle
}

// NewSandbox creates and boots a new sandbox with the given name and options.
// The sandbox will be stopped when the parent process exits unless created in detached mode.
func NewSandbox(ctx context.Context, name string, opts ...SandboxOption) (*Sandbox, error) {
	return newSandboxInternal(ctx, ffi.NewRealFFI(), name, opts...)
}

// NewSandboxDetached creates a sandbox in detached mode that survives the parent process.
// Use GetSandbox() to reconnect to a detached sandbox.
func NewSandboxDetached(ctx context.Context, name string, opts ...SandboxOption) (*Sandbox, error) {
	opts = append(opts, WithDetached())
	return newSandboxInternal(ctx, ffi.NewRealFFI(), name, opts...)
}

func newSandboxInternal(ctx context.Context, f ffi.FFI, name string, opts ...SandboxOption) (*Sandbox, error) {
	options := &SandboxOptions{}
	for _, opt := range opts {
		opt(options)
	}

	handle, err := f.SandboxCreate(ctx, name, ffi.SandboxOptions{
		Image:   options.Image,
		Memory:  options.MemoryMiB,
		CPUs:    options.CPUs,
		Workdir: options.Workdir,
		Env:     options.Env,
	})
	if err != nil {
		return nil, WrapErrorf(ErrInternal, err, "failed to create sandbox %q", name)
	}

	return &Sandbox{
		name:   name,
		ffi:    f,
		handle: handle,
	}, nil
}

// GetSandbox reconnects to an existing detached sandbox by name.
// Returns ErrSandboxNotFound if the sandbox does not exist.
func GetSandbox(ctx context.Context, name string) (*Sandbox, error) {
	return getSandboxInternal(ctx, ffi.NewRealFFI(), name)
}

func getSandboxInternal(ctx context.Context, f ffi.FFI, name string) (*Sandbox, error) {
	handle, err := f.GetSandbox(ctx, name)
	if err != nil {
		return nil, WrapErrorf(ErrSandboxNotFound, err, "sandbox %q not found", name)
	}

	return &Sandbox{
		name:   name,
		ffi:    f,
		handle: handle,
	}, nil
}

// ListSandboxes returns the names of all running sandboxes.
func ListSandboxes(ctx context.Context) ([]string, error) {
	return listSandboxesInternal(ctx, ffi.NewRealFFI())
}

func listSandboxesInternal(ctx context.Context, f ffi.FFI) ([]string, error) {
	names, err := f.ListSandboxes(ctx)
	if err != nil {
		return nil, WrapError(ErrInternal, err, "failed to list sandboxes")
	}
	return names, nil
}

// RemoveSandbox removes a sandbox by name.
// The sandbox must be stopped first.
func RemoveSandbox(ctx context.Context, name string) error {
	return removeSandboxInternal(ctx, ffi.NewRealFFI(), name)
}

func removeSandboxInternal(ctx context.Context, f ffi.FFI, name string) error {
	err := f.RemoveSandbox(ctx, name)
	if err != nil {
		return WrapErrorf(ErrInternal, err, "failed to remove sandbox %q", name)
	}
	return nil
}

// Name returns the sandbox name.
func (s *Sandbox) Name() string {
	return s.name
}

// Stop gracefully stops the sandbox.
func (s *Sandbox) Stop(ctx context.Context) error {
	err := s.ffi.SandboxStop(ctx, s.handle)
	if err != nil {
		return WrapErrorf(ErrInternal, err, "failed to stop sandbox %q", s.name)
	}
	return nil
}

// Kill immediately terminates the sandbox without graceful shutdown.
func (s *Sandbox) Kill(ctx context.Context) error {
	return s.Stop(ctx)
}

// Detach hands off the sandbox to run in the background.
// After detaching, use GetSandbox() to reconnect.
func (s *Sandbox) Detach(_ context.Context) error {
	return nil
}

// StopAndWait stops the sandbox and blocks until it is fully stopped.
func (s *Sandbox) StopAndWait(ctx context.Context) error {
	return s.Stop(ctx)
}

// FS returns a filesystem accessor for the sandbox.
func (s *Sandbox) FS() *SandboxFs {
	return &SandboxFs{sandbox: s}
}

// =============================================================================
// Metrics
// =============================================================================

// Metrics represents resource usage for a sandbox.
type Metrics struct {
	CPU       float64
	MemoryMiB uint64
	DiskRead  uint64
	DiskWrite uint64
	NetRx     uint64
	NetTx     uint64
}

// Metrics returns the current resource usage for this sandbox.
func (s *Sandbox) Metrics(ctx context.Context) (*Metrics, error) {
	m, err := s.ffi.SandboxMetrics(ctx, s.handle)
	if err != nil {
		return nil, WrapErrorf(ErrInternal, err, "failed to get metrics for sandbox %q", s.name)
	}

	return &Metrics{
		CPU:       m.CPU,
		MemoryMiB: m.MemoryMiB,
		DiskRead:  m.DiskRead,
		DiskWrite: m.DiskWrite,
		NetRx:     m.NetRx,
		NetTx:     m.NetTx,
	}, nil
}

// AllSandboxMetrics returns metrics for all running sandboxes.
func AllSandboxMetrics(ctx context.Context) (map[string]*Metrics, error) {
	return allSandboxMetricsInternal(ctx, ffi.NewRealFFI())
}

func allSandboxMetricsInternal(ctx context.Context, f ffi.FFI) (map[string]*Metrics, error) {
	names, err := f.ListSandboxes(ctx)
	if err != nil {
		return nil, WrapError(ErrInternal, err, "failed to list sandboxes for metrics")
	}

	result := make(map[string]*Metrics)
	for _, name := range names {
		handle, err := f.GetSandbox(ctx, name)
		if err != nil {
			continue
		}

		m, err := f.SandboxMetrics(ctx, handle)
		if err != nil {
			continue
		}

		result[name] = &Metrics{
			CPU:       m.CPU,
			MemoryMiB: m.MemoryMiB,
			DiskRead:  m.DiskRead,
			DiskWrite: m.DiskWrite,
			NetRx:     m.NetRx,
			NetTx:     m.NetTx,
		}
	}

	return result, nil
}

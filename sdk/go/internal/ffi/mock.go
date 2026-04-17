package ffi

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// FFI is the interface that abstracts the Rust FFI layer.
// This allows testing with MockFFI without requiring CGO.
type FFI interface {
	// Sandbox operations
	SandboxCreate(ctx context.Context, name string, opts SandboxOptions) (SandboxHandle, error)
	SandboxStop(ctx context.Context, handle SandboxHandle) error
	SandboxExec(ctx context.Context, handle SandboxHandle, cmd string, args []string) (*ExecResult, error)
	SandboxExecStream(ctx context.Context, handle SandboxHandle, cmd string, args []string) (<-chan ExecEvent, error)
	SandboxMetrics(ctx context.Context, handle SandboxHandle) (*Metrics, error)
	GetSandbox(ctx context.Context, name string) (SandboxHandle, error)
	ListSandboxes(ctx context.Context) ([]string, error)
	RemoveSandbox(ctx context.Context, name string) error

	// Volume operations
	VolumeCreate(ctx context.Context, name string, quotaMiB int) error
	VolumeRemove(ctx context.Context, name string) error
	VolumeList(ctx context.Context) ([]string, error)

	// Filesystem operations
	FSRead(ctx context.Context, handle SandboxHandle, path string) ([]byte, error)
	FSWrite(ctx context.Context, handle SandboxHandle, path string, data []byte) error
	FSList(ctx context.Context, handle SandboxHandle, path string) ([]FsEntry, error)
	FSStat(ctx context.Context, handle SandboxHandle, path string) (*FsStat, error)
	FSCopyIn(ctx context.Context, handle SandboxHandle, hostPath, guestPath string) error
	FSCopyOut(ctx context.Context, handle SandboxHandle, guestPath, hostPath string) error
}

// RealFFI is a placeholder for the real CGO-based FFI implementation.
// This will be implemented in Phase 3 with actual CGO bindings.
type RealFFI struct{}

// NewRealFFI creates a new RealFFI instance.
// Note: This will panic until the real CGO implementation is added.
// For testing, use NewMockFFI() instead.
func NewRealFFI() FFI {
	return &RealFFI{}
}

// SandboxCreate implements FFI.SandboxCreate
func (r *RealFFI) SandboxCreate(ctx context.Context, name string, opts SandboxOptions) (SandboxHandle, error) {
	return nil, fmt.Errorf("RealFFI not yet implemented - use MockFFI for testing")
}

// SandboxStop implements FFI.SandboxStop
func (r *RealFFI) SandboxStop(ctx context.Context, handle SandboxHandle) error {
	return fmt.Errorf("RealFFI not yet implemented - use MockFFI for testing")
}

// SandboxExec implements FFI.SandboxExec
func (r *RealFFI) SandboxExec(ctx context.Context, handle SandboxHandle, cmd string, args []string) (*ExecResult, error) {
	return nil, fmt.Errorf("RealFFI not yet implemented - use MockFFI for testing")
}

// SandboxExecStream implements FFI.SandboxExecStream
func (r *RealFFI) SandboxExecStream(ctx context.Context, handle SandboxHandle, cmd string, args []string) (<-chan ExecEvent, error) {
	return nil, fmt.Errorf("RealFFI not yet implemented - use MockFFI for testing")
}

// SandboxMetrics implements FFI.SandboxMetrics
func (r *RealFFI) SandboxMetrics(ctx context.Context, handle SandboxHandle) (*Metrics, error) {
	return nil, fmt.Errorf("RealFFI not yet implemented - use MockFFI for testing")
}

// GetSandbox implements FFI.GetSandbox
func (r *RealFFI) GetSandbox(ctx context.Context, name string) (SandboxHandle, error) {
	return nil, fmt.Errorf("RealFFI not yet implemented - use MockFFI for testing")
}

// ListSandboxes implements FFI.ListSandboxes
func (r *RealFFI) ListSandboxes(ctx context.Context) ([]string, error) {
	return nil, fmt.Errorf("RealFFI not yet implemented - use MockFFI for testing")
}

// RemoveSandbox implements FFI.RemoveSandbox
func (r *RealFFI) RemoveSandbox(ctx context.Context, name string) error {
	return fmt.Errorf("RealFFI not yet implemented - use MockFFI for testing")
}

// VolumeCreate implements FFI.VolumeCreate
func (r *RealFFI) VolumeCreate(ctx context.Context, name string, quotaMiB int) error {
	return fmt.Errorf("RealFFI not yet implemented - use MockFFI for testing")
}

// VolumeRemove implements FFI.VolumeRemove
func (r *RealFFI) VolumeRemove(ctx context.Context, name string) error {
	return fmt.Errorf("RealFFI not yet implemented - use MockFFI for testing")
}

// VolumeList implements FFI.VolumeList
func (r *RealFFI) VolumeList(ctx context.Context) ([]string, error) {
	return nil, fmt.Errorf("RealFFI not yet implemented - use MockFFI for testing")
}

// FSRead implements FFI.FSRead
func (r *RealFFI) FSRead(ctx context.Context, handle SandboxHandle, path string) ([]byte, error) {
	return nil, fmt.Errorf("RealFFI not yet implemented - use MockFFI for testing")
}

// FSWrite implements FFI.FSWrite
func (r *RealFFI) FSWrite(ctx context.Context, handle SandboxHandle, path string, data []byte) error {
	return fmt.Errorf("RealFFI not yet implemented - use MockFFI for testing")
}

// FSList implements FFI.FSList
func (r *RealFFI) FSList(ctx context.Context, handle SandboxHandle, path string) ([]FsEntry, error) {
	return nil, fmt.Errorf("RealFFI not yet implemented - use MockFFI for testing")
}

// FSStat implements FFI.FSStat
func (r *RealFFI) FSStat(ctx context.Context, handle SandboxHandle, path string) (*FsStat, error) {
	return nil, fmt.Errorf("RealFFI not yet implemented - use MockFFI for testing")
}

// FSCopyIn implements FFI.FSCopyIn
func (r *RealFFI) FSCopyIn(ctx context.Context, handle SandboxHandle, hostPath, guestPath string) error {
	return fmt.Errorf("RealFFI not yet implemented - use MockFFI for testing")
}

// FSCopyOut implements FFI.FSCopyOut
func (r *RealFFI) FSCopyOut(ctx context.Context, handle SandboxHandle, guestPath, hostPath string) error {
	return fmt.Errorf("RealFFI not yet implemented - use MockFFI for testing")
}

// MockFFI provides a testable implementation of the FFI interface
// that simulates the Rust FFI layer without requiring CGO or Rust.
type MockFFI struct {
	mu sync.RWMutex

	// Configuration for mock behavior
	ShouldFail    bool
	FailMessage   string
	ExecOutput    string
	ExecExitCode  int
	ExecStderr    string
	StreamEvents  []ExecEvent
	Delay         time.Duration
	SandboxExists map[string]bool
	VolumeExists  map[string]bool
	MetricsResult *Metrics
	FSReadResult  []byte
	FSListResult  []FsEntry
	FSStatResult  *FsStat

	// Tracking calls for assertions
	CreateCalls    []CreateCall
	ExecCalls      []ExecCall
	StopCalls      []string
	VolumeCalls    []VolumeCall
	FSReadCalls    []string
	FSCopyInCalls  []CopyCall
	FSCopyOutCalls []CopyCall
}

// CreateCall tracks a sandbox creation call
type CreateCall struct {
	Name    string
	Image   string
	Memory  int
	CPUs    int
	Workdir string
	Env     map[string]string
}

// ExecCall tracks an exec call
type ExecCall struct {
	Sandbox string
	Cmd     string
	Args    []string
}

// VolumeCall tracks a volume operation
type VolumeCall struct {
	Name   string
	Action string // "create", "remove", "list"
}

// CopyCall tracks a copy operation
type CopyCall struct {
	Source      string
	Destination string
}

// ExecEvent represents a streaming exec event
type ExecEvent interface {
	isEvent()
}

// StdoutEvent is emitted when stdout data is received
type StdoutEvent struct {
	Data []byte
}

func (StdoutEvent) isEvent() {}

// StderrEvent is emitted when stderr data is received
type StderrEvent struct {
	Data []byte
}

func (StderrEvent) isEvent() {}

// ExitedEvent is emitted when the process exits
type ExitedEvent struct {
	Code int
}

func (ExitedEvent) isEvent() {}

// Metrics represents sandbox resource usage
type Metrics struct {
	CPU       float64
	MemoryMiB uint64
	DiskRead  uint64
	DiskWrite uint64
	NetRx     uint64
	NetTx     uint64
}

// FsEntry represents a directory entry
type FsEntry struct {
	Path string
	Kind string // "file", "dir", "symlink"
	Size int64
	Mode uint32
}

// FsStat represents file metadata
type FsStat struct {
	Path    string
	Size    int64
	Mode    uint32
	ModTime time.Time
	IsDir   bool
}

// SandboxOptions holds sandbox creation options
type SandboxOptions struct {
	Image   string
	Memory  int
	CPUs    int
	Workdir string
	Env     map[string]string
}

// SandboxHandle represents an open sandbox connection
type SandboxHandle interface {
	Name() string
	Close() error
}

// MockSandboxHandle is the mock implementation of SandboxHandle
type MockSandboxHandle struct {
	name string
	ffi  *MockFFI
}

func (h *MockSandboxHandle) Name() string { return h.name }
func (h *MockSandboxHandle) Close() error { return nil }

// ExecResult holds the result of a command execution
type ExecResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// NewMockFFI creates a new MockFFI with sensible defaults.
// Use this for testing instead of NewRealFFI().
func NewMockFFI() *MockFFI {
	return &MockFFI{
		SandboxExists: make(map[string]bool),
		VolumeExists:  make(map[string]bool),
		ExecOutput:    "",
		ExecExitCode:  0,
		ExecStderr:    "",
		StreamEvents:  []ExecEvent{},
		MetricsResult: &Metrics{CPU: 10.0, MemoryMiB: 128},
		FSReadResult:  []byte(""),
		FSListResult:  []FsEntry{},
		FSStatResult:  &FsStat{},
	}
}

// Ensure MockFFI implements FFI interface
var _ FFI = (*MockFFI)(nil)

// Reset clears all tracking and configuration
func (m *MockFFI) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.ShouldFail = false
	m.FailMessage = ""
	m.CreateCalls = nil
	m.ExecCalls = nil
	m.StopCalls = nil
	m.VolumeCalls = nil
	m.FSReadCalls = nil
	m.FSCopyInCalls = nil
	m.FSCopyOutCalls = nil
	m.SandboxExists = make(map[string]bool)
	m.VolumeExists = make(map[string]bool)
}

// SandboxCreate simulates creating a sandbox
func (m *MockFFI) SandboxCreate(ctx context.Context, name string, opts SandboxOptions) (SandboxHandle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.Delay > 0 {
		select {
		case <-time.After(m.Delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	m.CreateCalls = append(m.CreateCalls, CreateCall{
		Name:    name,
		Image:   opts.Image,
		Memory:  opts.Memory,
		CPUs:    opts.CPUs,
		Workdir: opts.Workdir,
		Env:     opts.Env,
	})

	if m.ShouldFail {
		return nil, fmt.Errorf("%s", m.FailMessage)
	}

	m.SandboxExists[name] = true
	return &MockSandboxHandle{name: name, ffi: m}, nil
}

// SandboxStop simulates stopping a sandbox
func (m *MockFFI) SandboxStop(ctx context.Context, handle SandboxHandle) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.Delay > 0 {
		select {
		case <-time.After(m.Delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	m.StopCalls = append(m.StopCalls, handle.Name())
	delete(m.SandboxExists, handle.Name())

	if m.ShouldFail {
		return fmt.Errorf("%s", m.FailMessage)
	}
	return nil
}

// SandboxExec simulates executing a command in a sandbox
func (m *MockFFI) SandboxExec(ctx context.Context, handle SandboxHandle, cmd string, args []string) (*ExecResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.Delay > 0 {
		select {
		case <-time.After(m.Delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	m.ExecCalls = append(m.ExecCalls, ExecCall{
		Sandbox: handle.Name(),
		Cmd:     cmd,
		Args:    args,
	})

	if m.ShouldFail {
		return nil, fmt.Errorf("%s", m.FailMessage)
	}

	return &ExecResult{
		Stdout:   m.ExecOutput,
		Stderr:   m.ExecStderr,
		ExitCode: m.ExecExitCode,
	}, nil
}

// SandboxExecStream simulates streaming exec
func (m *MockFFI) SandboxExecStream(ctx context.Context, handle SandboxHandle, cmd string, args []string) (<-chan ExecEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.Delay > 0 {
		select {
		case <-time.After(m.Delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	if m.ShouldFail {
		return nil, fmt.Errorf("%s", m.FailMessage)
	}

	eventChan := make(chan ExecEvent, len(m.StreamEvents)+1)
	for _, event := range m.StreamEvents {
		eventChan <- event
	}
	// Always end with exit event
	eventChan <- ExitedEvent{Code: m.ExecExitCode}
	close(eventChan)

	return eventChan, nil
}

// VolumeCreate simulates creating a volume
func (m *MockFFI) VolumeCreate(ctx context.Context, name string, quotaMiB int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.Delay > 0 {
		select {
		case <-time.After(m.Delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	m.VolumeCalls = append(m.VolumeCalls, VolumeCall{
		Name:   name,
		Action: "create",
	})

	if m.ShouldFail {
		return fmt.Errorf("%s", m.FailMessage)
	}

	m.VolumeExists[name] = true
	return nil
}

// VolumeRemove simulates removing a volume
func (m *MockFFI) VolumeRemove(ctx context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.Delay > 0 {
		select {
		case <-time.After(m.Delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	m.VolumeCalls = append(m.VolumeCalls, VolumeCall{
		Name:   name,
		Action: "remove",
	})

	if m.ShouldFail {
		return fmt.Errorf("%s", m.FailMessage)
	}

	delete(m.VolumeExists, name)
	return nil
}

// VolumeList simulates listing volumes
func (m *MockFFI) VolumeList(ctx context.Context) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.Delay > 0 {
		select {
		case <-time.After(m.Delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	if m.ShouldFail {
		return nil, fmt.Errorf("%s", m.FailMessage)
	}

	volumes := make([]string, 0, len(m.VolumeExists))
	for name := range m.VolumeExists {
		volumes = append(volumes, name)
	}
	return volumes, nil
}

// SandboxMetrics simulates getting sandbox metrics
func (m *MockFFI) SandboxMetrics(ctx context.Context, handle SandboxHandle) (*Metrics, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.Delay > 0 {
		select {
		case <-time.After(m.Delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	if m.ShouldFail {
		return nil, fmt.Errorf("%s", m.FailMessage)
	}

	return m.MetricsResult, nil
}

// FSRead simulates reading a file from sandbox
func (m *MockFFI) FSRead(ctx context.Context, handle SandboxHandle, path string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.Delay > 0 {
		select {
		case <-time.After(m.Delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	m.FSReadCalls = append(m.FSReadCalls, path)

	if m.ShouldFail {
		return nil, fmt.Errorf("%s", m.FailMessage)
	}

	result := make([]byte, len(m.FSReadResult))
	copy(result, m.FSReadResult)
	return result, nil
}

// FSWrite simulates writing a file to sandbox
func (m *MockFFI) FSWrite(ctx context.Context, handle SandboxHandle, path string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.Delay > 0 {
		select {
		case <-time.After(m.Delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if m.ShouldFail {
		return fmt.Errorf("%s", m.FailMessage)
	}

	return nil
}

// FSList simulates listing a directory in sandbox
func (m *MockFFI) FSList(ctx context.Context, handle SandboxHandle, path string) ([]FsEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.Delay > 0 {
		select {
		case <-time.After(m.Delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	if m.ShouldFail {
		return nil, fmt.Errorf("%s", m.FailMessage)
	}

	result := make([]FsEntry, len(m.FSListResult))
	copy(result, m.FSListResult)
	return result, nil
}

// FSStat simulates getting file metadata
func (m *MockFFI) FSStat(ctx context.Context, handle SandboxHandle, path string) (*FsStat, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.Delay > 0 {
		select {
		case <-time.After(m.Delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	if m.ShouldFail {
		return nil, fmt.Errorf("%s", m.FailMessage)
	}

	return m.FSStatResult, nil
}

// FSCopyIn simulates copying a file from host to sandbox
func (m *MockFFI) FSCopyIn(ctx context.Context, handle SandboxHandle, hostPath, guestPath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.Delay > 0 {
		select {
		case <-time.After(m.Delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	m.FSCopyInCalls = append(m.FSCopyInCalls, CopyCall{
		Source:      hostPath,
		Destination: guestPath,
	})

	if m.ShouldFail {
		return fmt.Errorf("%s", m.FailMessage)
	}

	return nil
}

// FSCopyOut simulates copying a file from sandbox to host
func (m *MockFFI) FSCopyOut(ctx context.Context, handle SandboxHandle, guestPath, hostPath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.Delay > 0 {
		select {
		case <-time.After(m.Delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	m.FSCopyOutCalls = append(m.FSCopyOutCalls, CopyCall{
		Source:      guestPath,
		Destination: hostPath,
	})

	if m.ShouldFail {
		return fmt.Errorf("%s", m.FailMessage)
	}

	return nil
}

// GetSandbox simulates reconnecting to a detached sandbox
func (m *MockFFI) GetSandbox(ctx context.Context, name string) (SandboxHandle, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.Delay > 0 {
		select {
		case <-time.After(m.Delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	if m.ShouldFail {
		return nil, fmt.Errorf("%s", m.FailMessage)
	}

	if !m.SandboxExists[name] {
		return nil, fmt.Errorf("sandbox not found: %s", name)
	}

	return &MockSandboxHandle{name: name, ffi: m}, nil
}

// ListSandboxes simulates listing all sandboxes
func (m *MockFFI) ListSandboxes(ctx context.Context) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.Delay > 0 {
		select {
		case <-time.After(m.Delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	if m.ShouldFail {
		return nil, fmt.Errorf("%s", m.FailMessage)
	}

	sandboxes := make([]string, 0, len(m.SandboxExists))
	for name := range m.SandboxExists {
		sandboxes = append(sandboxes, name)
	}
	return sandboxes, nil
}

// RemoveSandbox simulates removing a sandbox
func (m *MockFFI) RemoveSandbox(ctx context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.Delay > 0 {
		select {
		case <-time.After(m.Delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if m.ShouldFail {
		return fmt.Errorf("%s", m.FailMessage)
	}

	delete(m.SandboxExists, name)
	return nil
}

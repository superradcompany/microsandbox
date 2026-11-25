package microsandbox

import (
	"context"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// ContextKind identifies a retained destination, independent of request cancellation.
type ContextKind string

const (
	ContextLocal  ContextKind = "local"
	ContextRemote ContextKind = "remote"
)

// Context selects where resources live. It is separate from context.Context,
// which supplies cancellation and deadlines for a single operation.
type Context interface {
	Kind() ContextKind
	Info() (ContextInfo, error)
	Sandboxes() *Sandboxes
	Volumes() *Volumes
	Snapshots() *Snapshots
	Checkpoints() *Checkpoints
	nativeContext() *ffi.Context
}

// ContextInfo describes a captured destination without exposing credentials.
type ContextInfo struct {
	Kind    ContextKind `json:"kind"`
	Source  string      `json:"source"`
	Profile string      `json:"profile,omitempty"`
	APIURL  string      `json:"api_url,omitempty"`
}

// Info returns the settings captured by this local context.
func (c *LocalContext) Info() (ContextInfo, error) { return contextInfo(c) }

// Info returns the settings captured by this remote context.
func (c *RemoteContext) Info() (ContextInfo, error) { return contextInfo(c) }

func contextInfo(c Context) (ContextInfo, error) {
	native, err := nativeDestination(c)
	if err != nil {
		return ContextInfo{}, err
	}
	info, err := native.Info()
	if err != nil {
		return ContextInfo{}, wrapFFI(err)
	}
	result := ContextInfo{Kind: ContextKind(info.Kind), Source: info.Source}
	if info.Profile != nil {
		result.Profile = *info.Profile
	}
	if info.APIURL != nil {
		result.APIURL = *info.APIURL
	}
	return result, nil
}

type LocalOptions struct {
	Home       string
	ConfigPath string
}
type LocalContext struct{ inner *ffi.Context }
type RemoteContext struct{ inner *ffi.Context }

func NewLocalContext(options LocalOptions) (*LocalContext, error) {
	inner, err := ffi.SelectedProvider("local").NewContext(struct {
		Kind       string `json:"kind"`
		Home       string `json:"home,omitempty"`
		ConfigPath string `json:"configPath,omitempty"`
	}{"local", options.Home, options.ConfigPath})
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &LocalContext{inner: inner}, nil
}

// NewRemoteContext captures the explicit key and configured endpoint.
func NewRemoteContext(apiKey string) (*RemoteContext, error) {
	return NewRemoteContextWithOptions(WithRemoteAPIKey(apiKey))
}

// NewRemoteContextWithURL selects an explicit compatible remote endpoint.
func NewRemoteContextWithURL(url, apiKey string) (*RemoteContext, error) {
	return NewRemoteContextWithOptions(WithRemoteURL(url), WithRemoteAPIKey(apiKey))
}

func RemoteContextFromProfile(name string) (*RemoteContext, error) {
	inner, err := ffi.SelectedProvider("remote").NewContext(struct {
		Kind    string `json:"kind"`
		Profile string `json:"profile"`
	}{"remote", name})
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &RemoteContext{inner: inner}, nil
}
func RemoteContextFromEnv() (*RemoteContext, error) {
	return NewRemoteContextWithOptions()
}

func (c *LocalContext) Kind() ContextKind  { return ContextLocal }
func (c *RemoteContext) Kind() ContextKind { return ContextRemote }
func (c *LocalContext) nativeContext() *ffi.Context {
	if c == nil {
		return nil
	}
	return c.inner
}
func (c *RemoteContext) nativeContext() *ffi.Context {
	if c == nil {
		return nil
	}
	return c.inner
}
func (c *LocalContext) Sandboxes() *Sandboxes  { return SandboxCtx(c) }
func (c *RemoteContext) Sandboxes() *Sandboxes { return SandboxCtx(c) }

// Sandboxes retains its destination. Nil contexts fail on operation, never falling
// back to the local destination (including a typed nil *RemoteContext).
type Sandboxes struct{ selected Context }

func SandboxCtx(selected Context) *Sandboxes { return &Sandboxes{selected: selected} }
func (s *Sandboxes) Context() Context        { return s.selected }
func nativeDestination(selected Context) (*ffi.Context, error) {
	if selected == nil || selected.nativeContext() == nil {
		return nil, &Error{Kind: ErrInvalidConfig, Message: "destination context must not be nil or uninitialized"}
	}
	return selected.nativeContext(), nil
}
func (s *Sandboxes) Create(ctx context.Context, name string, options ...SandboxOption) (*Sandbox, error) {
	return s.create(ctx, name, false, options...)
}
func (s *Sandboxes) ConnectOrCreate(ctx context.Context, name string, options ...SandboxOption) (*Sandbox, error) {
	return s.create(ctx, name, true, options...)
}
func (s *Sandboxes) create(ctx context.Context, name string, connectOrCreate bool, options ...SandboxOption) (*Sandbox, error) {
	destination, err := nativeDestination(s.selected)
	if err != nil {
		return nil, err
	}
	config := SandboxConfig{}
	for _, option := range options {
		option(&config)
	}
	if err := prepareSandboxCreateConfig(&config); err != nil {
		return nil, err
	}
	inner, err := destination.CreateSandbox(ctx, name, buildFFICreateOptions(config), connectOrCreate)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &Sandbox{inner: inner}, nil
}
func (s *Sandboxes) get(ctx context.Context, operation, name string) (*Sandbox, error) {
	destination, err := nativeDestination(s.selected)
	if err != nil {
		return nil, err
	}
	inner, err := destination.Sandbox(ctx, operation, name)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &Sandbox{inner: inner}, nil
}
func (s *Sandboxes) Get(ctx context.Context, name string) (*Sandbox, error) {
	return s.get(ctx, "sandbox_get", name)
}
func (s *Sandboxes) GetRunning(ctx context.Context, name string) (*Sandbox, error) {
	return s.get(ctx, "sandbox_get_running", name)
}
func (s *Sandboxes) Start(ctx context.Context, name string) (*Sandbox, error) {
	return s.get(ctx, "sandbox_start", name)
}
func (s *Sandboxes) StartDetached(ctx context.Context, name string) (*Sandbox, error) {
	return s.get(ctx, "sandbox_start_detached", name)
}
func (s *Sandboxes) List(ctx context.Context, configure ...SandboxListOption) (*SandboxPage, error) {
	destination, err := nativeDestination(s.selected)
	if err != nil {
		return nil, err
	}
	options := sandboxListOptions{}
	for _, apply := range configure {
		apply(&options)
	}
	page, err := destination.ListSandboxes(ctx, ffi.SandboxListOptions{Cursor: options.cursor, Limit: options.limit, Labels: options.labels})
	if err != nil {
		return nil, wrapFFI(err)
	}
	out := make([]*Sandbox, len(page.Sandboxes))
	for i, inner := range page.Sandboxes {
		out[i] = &Sandbox{inner: inner}
	}
	return &SandboxPage{Sandboxes: out, NextCursor: page.NextCursor}, nil
}
func (s *Sandboxes) Remove(ctx context.Context, name string) error {
	destination, err := nativeDestination(s.selected)
	if err != nil {
		return err
	}
	return wrapFFI(destination.RemoveSandbox(ctx, name))
}
func (s *Sandbox) Context() Context {
	destination := s.inner.Context()
	if destination == nil {
		return nil
	}
	if destination.Kind() == "remote" {
		return &RemoteContext{inner: destination}
	}
	return &LocalContext{inner: destination}
}

// Resolve once per package operation and pass the retained native context through
// retries, progress streams and returned resources.
func configuredContext() (Context, error) { return ConfiguredContext() }

// ConfiguredContext resolves and retains the configured destination without creating
// a sandbox. Later configuration changes do not redirect operations on this context.
// Invalid configuration is returned immediately.
func ConfiguredContext() (Context, error) {
	inner, err := ffi.ConfiguredContext()
	if err != nil {
		return nil, wrapFFI(err)
	}
	return contextFromNative(inner), nil
}

func (c *LocalContext) Volumes() *Volumes  { return VolumeCtx(c) }
func (c *RemoteContext) Volumes() *Volumes { return VolumeCtx(c) }
func contextFromNative(destination *ffi.Context) Context {
	if destination == nil {
		return nil
	}
	if destination.Kind() == "remote" {
		return &RemoteContext{inner: destination}
	}
	return &LocalContext{inner: destination}
}

func (c *LocalContext) Snapshots() *Snapshots  { return SnapshotCtx(c) }
func (c *RemoteContext) Snapshots() *Snapshots { return SnapshotCtx(c) }

func (c *LocalContext) Checkpoints() *Checkpoints  { return CheckpointCtx(c) }
func (c *RemoteContext) Checkpoints() *Checkpoints { return CheckpointCtx(c) }

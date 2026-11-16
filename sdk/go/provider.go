package microsandbox

import (
	"fmt"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// NativeProvider owns a validated library. All contexts and resources derived
// from it retain that same library, including their cancellation and destructors.
// Libraries stay resident while the process runs; Close never unloads native code.
type NativeProvider struct {
	library *ffi.Library
	kind    string
}

// LoadNativeProvider loads an explicitly provisioned trusted native library.
// It performs no downloads. The ABI, exact SDK version and selected capability
// must match before the library can construct a context.
func LoadNativeProvider(path string, kind ContextKind) (*NativeProvider, error) {
	if kind != ContextLocal && kind != ContextRemote {
		return nil, fmt.Errorf("unknown provider kind %q", kind)
	}
	library, err := ffi.LoadProvider(path, string(kind), SDKVersion())
	if err != nil {
		return nil, err
	}
	ffi.RegisterProvider(string(kind), library)
	return &NativeProvider{library: library, kind: string(kind)}, nil
}

func (p *NativeProvider) NewLocalContext(options LocalOptions) (*LocalContext, error) {
	if p == nil || p.library == nil || p.kind != "local" {
		return nil, fmt.Errorf("local context requires a local native provider")
	}
	inner, err := p.library.NewContext(struct {
		Kind       string `json:"kind"`
		Home       string `json:"home,omitempty"`
		ConfigPath string `json:"configPath,omitempty"`
	}{"local", options.Home, options.ConfigPath})
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &LocalContext{inner: inner}, nil
}

// NewRemoteContext selects the hosted endpoint using an explicit API key.
func (p *NativeProvider) NewRemoteContext(apiKey string) (*RemoteContext, error) {
	return p.newRemoteContext("", apiKey)
}

// NewRemoteContextWithURL selects an explicit compatible remote endpoint.
func (p *NativeProvider) NewRemoteContextWithURL(url, apiKey string) (*RemoteContext, error) {
	if err := validateRemoteContextURL(url); err != nil {
		return nil, err
	}
	return p.newRemoteContext(url, apiKey)
}

func (p *NativeProvider) newRemoteContext(url, apiKey string) (*RemoteContext, error) {
	if p == nil || p.library == nil || p.kind != "remote" {
		return nil, fmt.Errorf("remote context requires a remote native provider")
	}
	inner, err := p.library.NewContext(struct {
		Kind   string `json:"kind"`
		URL    string `json:"url,omitempty"`
		APIKey string `json:"apiKey"`
	}{"remote", url, apiKey})
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &RemoteContext{inner: inner}, nil
}

// RegisterFullNativeLoader lets the full distribution install its lazy bundled
// loader without making the shared core import that distribution or its payload.
func RegisterFullNativeLoader(loader func() error) { ffi.SetAutoLoader(loader) }

// LoadFullNative loads the full distribution's own exact-version artifact.
func LoadFullNative(path string) error { return ffi.Load(path) }

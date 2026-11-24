// Package remote selects the remote-only native build. It never downloads on import or use.
package remote

import core "github.com/superradcompany/microsandbox/sdk/go/core"

// Load selects an explicitly provisioned trusted library, or the verified install cache when path is empty.
func Load(path string) (*core.NativeProvider, error) {
	if path == "" {
		return core.InstalledNativeProvider(core.ContextRemote, "")
	}
	return core.LoadNativeProvider(path, core.ContextRemote)
}

// NewContext captures the loaded provider for all derived resources.
func NewContext(path string, apiKey string) (*core.RemoteContext, error) {
	provider, err := Load(path)
	if err != nil {
		return nil, err
	}
	return provider.NewRemoteContext(apiKey)
}

// NewContextWithOptions captures explicit settings and environment defaults.
func NewContextWithOptions(path string, options ...core.RemoteContextOption) (*core.RemoteContext, error) {
	provider, err := Load(path)
	if err != nil {
		return nil, err
	}
	return provider.NewRemoteContextWithOptions(options...)
}

// NewContextWithURL captures an explicit endpoint on the selected provider.
func NewContextWithURL(path, url, apiKey string) (*core.RemoteContext, error) {
	provider, err := Load(path)
	if err != nil {
		return nil, err
	}
	return provider.NewRemoteContextWithURL(url, apiKey)
}

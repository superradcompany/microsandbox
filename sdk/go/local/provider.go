// Package local selects the local-only native build. It never downloads on import or use.
package local

import core "github.com/superradcompany/microsandbox/sdk/go/core"

// Load selects an explicitly provisioned trusted library, or the verified install cache when path is empty.
func Load(path string) (*core.NativeProvider, error) {
	if path == "" {
		return core.InstalledNativeProvider(core.ContextLocal, "")
	}
	return core.LoadNativeProvider(path, core.ContextLocal)
}

// NewContext captures the loaded provider for all derived resources.
func NewContext(path string, options core.LocalOptions) (*core.LocalContext, error) {
	provider, err := Load(path)
	if err != nil {
		return nil, err
	}
	return provider.NewLocalContext(options)
}

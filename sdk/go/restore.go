package microsandbox

import (
	"context"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// RestoreOption configures restoration, not fresh-boot configuration.
type RestoreOption func(*RestoreConfig)

// RestoreConfig contains only explicit destination resource choices.
type RestoreConfig struct {
	Forked                      bool
	SnapshotDiskOnly            bool
	SnapshotBase                string
	User                        string
	LogLevel                    LogLevel
	ExternalMountPolicy         ExternalMountRestorePolicy
	DangerouslyInheritResources bool
	Volumes                     map[string]MountConfig
	CapturedVolumes             []string
	Ports                       []PortBinding
	Vsock                       []VsockRoute
}

// RestoreSandbox restores an installed snapshot or archive into a detached sandbox.
// Close releases the handle; use Stop or Destroy to stop the restored VM.
func RestoreSandbox(ctx context.Context, snapshot, name string, opts ...RestoreOption) (*Sandbox, error) {
	config := RestoreConfig{}
	for _, opt := range opts {
		opt(&config)
	}
	if err := validateOwnedMounts(config.Volumes); err != nil {
		return nil, err
	}
	inner, err := ffi.RestoreSandbox(ctx, name, buildFFIRestoreOptions(snapshot, config))
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &Sandbox{inner: inner}, nil
}

// WithRestoreConfig replaces the restore configuration.
func WithRestoreConfig(config RestoreConfig) RestoreOption {
	return func(o *RestoreConfig) { *o = config }
}

// WithDangerouslyInheritResources explicitly reuses validated local source bindings.
func WithDangerouslyInheritResources() RestoreOption {
	return func(o *RestoreConfig) { o.DangerouslyInheritResources = true }
}

func buildFFIRestoreOptions(snapshot string, config RestoreConfig) ffi.RestoreOptions {
	// Reuse mount/route serialization only. Never pass a creation config to the
	// native restore operation or copy global creation defaults into it.
	resources := buildFFICreateOptions(SandboxConfig{Volumes: config.Volumes})
	return ffi.RestoreOptions{
		Snapshot: snapshot, Forked: config.Forked, DiskOnly: config.SnapshotDiskOnly,
		SnapshotBase: config.SnapshotBase, User: config.User, LogLevel: string(config.LogLevel),
		ExternalMountPolicy:         string(config.ExternalMountPolicy),
		DangerouslyInheritResources: config.DangerouslyInheritResources,
		Volumes:                     resources.Volumes, CapturedVolumes: config.CapturedVolumes,
		Ports: buildFFIPortBindings(config.Ports), Vsock: buildFFIVsockRoutes(config.Vsock),
	}
}

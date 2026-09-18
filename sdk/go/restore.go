package microsandbox

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// RestoreOption configures restoration, not image or startup-command selection.
type RestoreOption func(*RestoreConfig)

// RestoreConfig contains only explicit destination resource choices.
type RestoreConfig struct {
	// CPU and memory overrides must match captured geometry for full execution restore.
	CPUs      *uint8
	MemoryMiB *uint32
	// NetworkPolicy accepts only Rules, DefaultEgress, and DefaultIngress.
	NetworkPolicy *NetworkConfig
	// MaxConnections caps TCP connections.
	// Deprecated: use MaxTCPConnections instead; specifying both is an error.
	MaxConnections *uint
	// MaxTCPConnections caps destination TCP connections; zero means unlimited.
	MaxTCPConnections *uint
	// MaxUDPConnections caps destination UDP relay sessions; zero means unlimited.
	MaxUDPConnections *uint
	DisableNetwork    bool
	// Explicit guest security requires disk scope or SnapshotDiskOnly.
	SecurityProfile SecurityProfile
	// Nil omits a lifetime override; explicit zero requests immediate expiry.
	MaxDuration                 *time.Duration
	IdleTimeout                 *time.Duration
	Forked                      bool
	SnapshotDiskOnly            bool
	SnapshotBase                string
	User                        string
	LogLevel                    LogLevel
	ExternalMountPolicy         ExternalMountRestorePolicy
	DangerouslyInheritResources bool
	AllowMissingResources       bool
	Volumes                     map[string]MountConfig
	CapturedVolumes             []string
	Ports                       []PortBinding
	Vsock                       []VsockRoute
}

// RestoreSandbox restores an installed snapshot or archive into a detached sandbox.
// Close releases the handle; use Stop or Destroy to stop the restored VM.
func RestoreSandbox[T SnapshotSeed](ctx context.Context, snapshot T, name string, opts ...RestoreOption) (*Sandbox, error) {
	config := RestoreConfig{}
	for _, opt := range opts {
		opt(&config)
	}
	if err := validateRestoreConfig(config); err != nil {
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

// WithRestoreCPUs selects CPUs; full execution restore requires the captured count.
func WithRestoreCPUs(cpus uint8) RestoreOption {
	return func(o *RestoreConfig) { o.CPUs = &cpus }
}

// WithRestoreMemory selects memory in MiB; full restore requires captured geometry.
func WithRestoreMemory(mebibytes uint32) RestoreOption {
	return func(o *RestoreConfig) { o.MemoryMiB = &mebibytes }
}

// WithRestoreNetworkPolicy selects host-side policy only. Use the existing
// NetworkPolicy factories; DNS, TLS, ports, and other NetworkConfig fields are rejected.
func WithRestoreNetworkPolicy(policy *NetworkConfig) RestoreOption {
	return func(o *RestoreConfig) { o.NetworkPolicy = policy }
}

// WithRestoreMaxConnections caps destination host-side concurrent TCP connections.
// Deprecated: use WithRestoreMaxTCPConnections instead; specifying both is an error.
func WithRestoreMaxConnections(count uint) RestoreOption {
	return func(o *RestoreConfig) { o.MaxConnections = &count }
}

// WithRestoreMaxTCPConnections caps destination TCP connections. Zero means unlimited.
func WithRestoreMaxTCPConnections(count uint) RestoreOption {
	return func(o *RestoreConfig) { o.MaxTCPConnections = &count }
}

// WithRestoreMaxUDPConnections caps destination UDP relay sessions. Zero means unlimited.
func WithRestoreMaxUDPConnections(count uint) RestoreOption {
	return func(o *RestoreConfig) { o.MaxUDPConnections = &count }
}

// WithRestoreDisableNetwork disables networking; full restore rejects removing a captured NIC.
func WithRestoreDisableNetwork() RestoreOption {
	return func(o *RestoreConfig) { o.DisableNetwork = true }
}

// WithRestoreSecurityProfile selects guest security for disk boot only.
// Full execution restore rejects any explicit profile, including Default.
func WithRestoreSecurityProfile(profile SecurityProfile) RestoreOption {
	return func(o *RestoreConfig) { o.SecurityProfile = profile }
}

// WithRestoreMaxDuration sets the destination runtime limit. Zero requests immediate expiry.
func WithRestoreMaxDuration(duration time.Duration) RestoreOption {
	return func(o *RestoreConfig) { o.MaxDuration = &duration }
}

// WithRestoreIdleTimeout sets the destination idle limit. Zero requests immediate expiry.
func WithRestoreIdleTimeout(duration time.Duration) RestoreOption {
	return func(o *RestoreConfig) { o.IdleTimeout = &duration }
}

func validateRestoreConfig(config RestoreConfig) error {
	if config.MaxConnections != nil && config.MaxTCPConnections != nil {
		return fmt.Errorf("microsandbox: restore MaxConnections and MaxTCPConnections cannot both be specified")
	}
	for name, duration := range map[string]*time.Duration{
		"max duration": config.MaxDuration, "idle timeout": config.IdleTimeout,
	} {
		if duration != nil && *duration < 0 {
			return fmt.Errorf("microsandbox: restore %s must be non-negative", name)
		}
	}
	if config.NetworkPolicy != nil {
		remaining := *config.NetworkPolicy
		remaining.Rules, remaining.DefaultEgress, remaining.DefaultIngress = nil, "", ""
		// Check the whole remainder so future NetworkConfig fields cannot silently
		// become ignored or broaden restore's deliberately policy-only surface.
		if !reflect.DeepEqual(remaining, NetworkConfig{}) {
			return fmt.Errorf("microsandbox: restore network policy accepts only Rules, DefaultEgress, and DefaultIngress")
		}
	}
	return validateOwnedMounts(config.Volumes)
}

// WithDangerouslyInheritResources explicitly reuses validated local source bindings.
func WithDangerouslyInheritResources() RestoreOption {
	return func(o *RestoreConfig) { o.DangerouslyInheritResources = true }
}

// WithAllowMissingResources accepts unavailable restore resources without inheriting them.
func WithAllowMissingResources() RestoreOption {
	return func(o *RestoreConfig) { o.AllowMissingResources = true }
}

func buildFFIRestoreOptions[T SnapshotSeed](snapshot T, config RestoreConfig) ffi.RestoreOptions {
	// Reuse mount/route serialization only. Never pass a creation config to the
	// native restore operation or copy global creation defaults into it.
	resources := buildFFICreateOptions(SandboxConfig{Volumes: config.Volumes})
	// Preserve a cloud ID versus a host-volume path instead of guessing from its spelling.
	var reference, referenceKind string
	switch value := any(snapshot).(type) {
	case string:
		reference = value
	case *SnapshotArtifact:
		if value != nil {
			reference, referenceKind = value.Reference(), value.ReferenceKind()
		}
	case *SnapshotHandle:
		if value != nil {
			reference, referenceKind = value.Reference(), value.ReferenceKind()
		}
	}
	var policy *ffi.CustomNetworkPolicy
	if config.NetworkPolicy != nil {
		policy = buildFFINetwork(config.NetworkPolicy).CustomPolicy
		if policy == nil {
			policy = &ffi.CustomNetworkPolicy{}
		}
	}
	seconds := func(duration *time.Duration) *uint64 {
		if duration == nil {
			return nil
		}
		value := durationSecsCeil(*duration)
		return &value
	}
	return ffi.RestoreOptions{
		Snapshot: reference, SnapshotReferenceKind: referenceKind,
		CPUs: config.CPUs, MemoryMiB: config.MemoryMiB, NetworkPolicy: policy,
		MaxConnections: config.MaxConnections, MaxTCPConnections: config.MaxTCPConnections,
		MaxUDPConnections: config.MaxUDPConnections, DisableNetwork: config.DisableNetwork,
		SecurityProfile: string(config.SecurityProfile),
		MaxDurationSecs: seconds(config.MaxDuration), IdleTimeoutSecs: seconds(config.IdleTimeout),
		Forked: config.Forked, DiskOnly: config.SnapshotDiskOnly,
		SnapshotBase: config.SnapshotBase, User: config.User, LogLevel: string(config.LogLevel),
		ExternalMountPolicy:         string(config.ExternalMountPolicy),
		DangerouslyInheritResources: config.DangerouslyInheritResources,
		AllowMissingResources:       config.AllowMissingResources,
		Volumes:                     resources.Volumes, CapturedVolumes: config.CapturedVolumes,
		Ports: buildFFIPortBindings(config.Ports), Vsock: buildFFIVsockRoutes(config.Vsock),
	}
}

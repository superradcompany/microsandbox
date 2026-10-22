package microsandbox

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// GuestClockPolicy controls wall-clock synchronization after boot or full resume.
type GuestClockPolicy string

const (
	GuestClockSync GuestClockPolicy = "sync"
	GuestClockOff  GuestClockPolicy = "off"
)

// RestoreOption configures restoration, not image or startup-command selection.
type RestoreOption func(*RestoreConfig)

// RestoreConfig contains only explicit destination resource choices.
type RestoreConfig struct {
	// Defaults for new commands only; never replay captured execution or start a workload.
	Workdir *string
	Shell   *string
	// Pointer-to-slice fields preserve explicit empty arrays as well as omission.
	Entrypoint *[]string
	Cmd        *[]string
	Env        map[string]string
	// PullPolicy controls retrieval of the digest-pinned base; empty uses the existing default.
	PullPolicy PullPolicy
	// CPU and memory overrides must match captured geometry for full execution restore.
	CPUs      *uint8
	MemoryMiB *uint32
	// Explicit ceilings apply to disk boot; full resume requires captured maxima.
	MaxCPUs      *uint8
	MaxMemoryMiB *uint32
	// Labels annotate the new sandbox, never its source snapshot.
	Labels map[string]string
	// Init and Hostname apply only to disk boot. Full-memory resume refuses either override.
	Init *InitConfig
	// A pointer preserves an explicit empty hostname so validation can reject it.
	Hostname *string
	// NetworkPolicy accepts only Rules, DefaultEgress, and DefaultIngress.
	NetworkPolicy *NetworkConfig
	// Proxy is resolved on the destination host before boot or full resume.
	Proxy *OutboundProxy
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
	MaxDuration *time.Duration
	IdleTimeout *time.Duration
	// Empty preserves the recorded/default policy; explicit selection requires native support.
	GuestClock GuestClockPolicy
	CowMemory  bool
	// Forked enables copy-on-write restore memory.
	//
	// Deprecated: use CowMemory instead.
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
	// TCPAcceptQueueSize sets the accept-queue depth for the child's published TCP
	// listeners, 1 to 2147483647. Nil keeps the default, 1024.
	TCPAcceptQueueSize *uint32

	// MaxInboundTCPConnections caps active inbound TCP connections; zero is unlimited. Nil uses the runtime default.
	MaxInboundTCPConnections *uint
	Vsock                    []VsockRoute
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

// WithRestoreWorkdir sets the guest working directory for new commands.
func WithRestoreWorkdir(path string) RestoreOption {
	return func(o *RestoreConfig) { o.Workdir = &path }
}

// WithRestoreShell sets the shell for new commands without executing it at restore time.
func WithRestoreShell(shell string) RestoreOption { return func(o *RestoreConfig) { o.Shell = &shell } }

// WithRestoreEntrypoint sets future default-workload argv. No arguments explicitly clears it.
func WithRestoreEntrypoint(argv ...string) RestoreOption {
	value := append([]string{}, argv...)
	return func(o *RestoreConfig) { o.Entrypoint = &value }
}

// WithRestoreCmd sets future default-workload CMD; no arguments explicitly clears it.
// This does not request startup execution.
func WithRestoreCmd(argv ...string) RestoreOption {
	value := append([]string{}, argv...)
	return func(o *RestoreConfig) { o.Cmd = &value }
}

// WithRestoreEnv adds a destination environment default for new commands.
func WithRestoreEnv(key, value string) RestoreOption {
	return func(o *RestoreConfig) {
		if o.Env == nil {
			o.Env = make(map[string]string)
		}
		o.Env[key] = value
	}
}

// WithRestoreConfig replaces the restore configuration.
func WithRestoreConfig(config RestoreConfig) RestoreOption {
	return func(o *RestoreConfig) { *o = config }
}

// WithRestorePullPolicy controls retrieval of the snapshot's pinned base image.
func WithRestorePullPolicy(policy PullPolicy) RestoreOption {
	return func(o *RestoreConfig) { o.PullPolicy = policy }
}

// WithRestoreProxy selects the destination proxy without changing captured guest identity.
func WithRestoreProxy(proxy *OutboundProxy) RestoreOption {
	return func(o *RestoreConfig) { o.Proxy = proxy }
}

// WithRestoreCPUs selects CPUs; full execution restore requires the captured count.
func WithRestoreCPUs(cpus uint8) RestoreOption {
	return func(o *RestoreConfig) { o.CPUs = &cpus }
}

// WithRestoreMemory selects memory in MiB; full restore requires captured geometry.
func WithRestoreMemory(mebibytes uint32) RestoreOption {
	return func(o *RestoreConfig) { o.MemoryMiB = &mebibytes }
}

// WithRestoreMaxCPUs selects the CPU ceiling; full resume requires the captured maximum.
func WithRestoreMaxCPUs(cpus uint8) RestoreOption {
	return func(o *RestoreConfig) { o.MaxCPUs = &cpus }
}

// WithRestoreMaxMemory selects the memory ceiling in MiB; full resume requires the captured maximum.
func WithRestoreMaxMemory(mebibytes uint32) RestoreOption {
	return func(o *RestoreConfig) { o.MaxMemoryMiB = &mebibytes }
}

// WithRestoreLabel annotates the destination sandbox, replacing an earlier value for this key.
func WithRestoreLabel(key, value string) RestoreOption {
	return func(o *RestoreConfig) {
		if o.Labels == nil {
			o.Labels = make(map[string]string)
		}
		o.Labels[key] = value
	}
}

// WithRestoreInit selects guest PID 1, arguments and environment for disk boot.
// Full-memory resume refuses replacement, including an explicit Init.Auto().
func WithRestoreInit(init InitConfig) RestoreOption {
	return func(o *RestoreConfig) { o.Init = &init }
}

// WithRestoreHostname selects the guest hostname for disk boot only.
func WithRestoreHostname(hostname string) RestoreOption {
	return func(o *RestoreConfig) { o.Hostname = &hostname }
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

// WithRestoreMaxInboundTCPConnections caps active inbound TCP connections; zero is unlimited.
func WithRestoreMaxInboundTCPConnections(value uint) RestoreOption {
	return func(o *RestoreConfig) { o.MaxInboundTCPConnections = &value }
}

// WithRestoreTCPAcceptQueueSize sets the accept-queue depth for the child's published TCP
// listeners, 1 to 2147483647. The host kernel clamps it to its somaxconn.
func WithRestoreTCPAcceptQueueSize(size uint32) RestoreOption {
	return func(o *RestoreConfig) { o.TCPAcceptQueueSize = &size }
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

// WithRestoreGuestClock selects an explicit wall-clock policy, including overriding a saved off.
func WithRestoreGuestClock(policy GuestClockPolicy) RestoreOption {
	return func(o *RestoreConfig) { o.GuestClock = policy }
}

func validateRestoreConfig(config RestoreConfig) error {
	if config.GuestClock != "" && config.GuestClock != GuestClockSync && config.GuestClock != GuestClockOff {
		return fmt.Errorf("microsandbox: guest clock must be sync or off")
	}
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
	// Reuse mount and init serialization only. Never pass a creation config to the
	// native restore operation or copy global creation defaults into it.
	resources := buildFFICreateOptions(SandboxConfig{Volumes: config.Volumes, Init: config.Init})
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
		Snapshot: reference, SnapshotReferenceKind: referenceKind, PullPolicy: string(config.PullPolicy),
		CPUs: config.CPUs, MemoryMiB: config.MemoryMiB, NetworkPolicy: policy,
		Init: resources.Init, Hostname: config.Hostname, Proxy: buildFFIOutboundProxy(config.Proxy),
		MaxCPUs: config.MaxCPUs, MaxMemoryMiB: config.MaxMemoryMiB,
		Labels:  config.Labels,
		Workdir: config.Workdir, Shell: config.Shell, Entrypoint: restoreArgv(config.Entrypoint), Cmd: restoreArgv(config.Cmd), Env: config.Env,
		MaxConnections: config.MaxConnections, MaxTCPConnections: config.MaxTCPConnections,
		MaxUDPConnections: config.MaxUDPConnections, DisableNetwork: config.DisableNetwork,
		SecurityProfile: string(config.SecurityProfile),
		GuestClock:      string(config.GuestClock),
		MaxDurationSecs: seconds(config.MaxDuration), IdleTimeoutSecs: seconds(config.IdleTimeout),
		// Keep the native wire spelling stable across SDK/runtime versions.
		Forked: config.CowMemory || config.Forked, DiskOnly: config.SnapshotDiskOnly,
		SnapshotBase: config.SnapshotBase, User: config.User, LogLevel: string(config.LogLevel),
		ExternalMountPolicy:         string(config.ExternalMountPolicy),
		DangerouslyInheritResources: config.DangerouslyInheritResources,
		AllowMissingResources:       config.AllowMissingResources,
		Volumes:                     resources.Volumes, CapturedVolumes: config.CapturedVolumes,
		Ports: buildFFIPortBindings(config.Ports), TCPAcceptQueueSize: config.TCPAcceptQueueSize,
		MaxInboundTCPConnections: config.MaxInboundTCPConnections,
		Vsock:                    buildFFIVsockRoutes(config.Vsock),
	}
}

// A pointer to a nil slice is still an explicit empty choice, not JSON null/omission.
func restoreArgv(value *[]string) *[]string {
	if value == nil {
		return nil
	}
	copy := append([]string{}, (*value)...)
	return &copy
}

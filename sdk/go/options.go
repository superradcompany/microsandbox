package microsandbox

import "time"

// SandboxConfig holds configuration for creating a sandbox.
//
// Most callers construct a sandbox via CreateSandbox with functional options;
// SandboxConfig is exported for callers that prefer to build a config value
// directly and pass it via WithConfig.
type SandboxConfig struct {
	Image           string
	MemoryMiB       uint32
	CPUs            uint8
	Workdir         string
	Shell           string
	Hostname        string
	User            string
	Replace         bool
	// ReplaceWithGrace, if non-nil, sets a specific grace period
	// between SIGTERM and SIGKILL when replacing an existing sandbox.
	// nil means "use the runtime default" (10s when Replace is set).
	// Setting this implies Replace=true. Zero is honored — it skips
	// SIGTERM and SIGKILLs immediately. Use WithReplaceWithGrace.
	ReplaceWithGrace *time.Duration
	Env             map[string]string
	Detached        bool
	Entrypoint      []string
	Init            *InitConfig
	LogLevel        LogLevel
	QuietLogs       bool
	Scripts         map[string]string
	PullPolicy      PullPolicy
	MaxDuration     time.Duration
	IdleTimeout     time.Duration
	StopSignal      string
	Labels          map[string]string
	RegistryAuth    *RegistryAuth
	Ports           map[uint16]uint16 // host port → guest port (TCP)
	PortsUDP        map[uint16]uint16 // host port → guest port (UDP)
	Network         *NetworkConfig
	Secrets         []SecretEntry
	Patches         []PatchConfig
	Volumes         map[string]MountConfig // guest path → mount config
}

// SandboxOption is a functional option for configuring a sandbox.
type SandboxOption func(*SandboxConfig)

// WithImage sets the container image to use (e.g. "python:3.12").
func WithImage(image string) SandboxOption {
	return func(o *SandboxConfig) { o.Image = image }
}

// WithMemory sets the memory limit in MiB.
func WithMemory(mebibytes uint32) SandboxOption {
	return func(o *SandboxConfig) { o.MemoryMiB = mebibytes }
}

// WithCPUs sets the CPU limit in whole cores.
func WithCPUs(cpus uint8) SandboxOption {
	return func(o *SandboxConfig) { o.CPUs = cpus }
}

// WithWorkdir sets the working directory inside the sandbox.
func WithWorkdir(path string) SandboxOption {
	return func(o *SandboxConfig) { o.Workdir = path }
}

// WithShell sets the default shell binary path inside the guest.
// Defaults to /bin/sh on most images.
func WithShell(shell string) SandboxOption {
	return func(o *SandboxConfig) { o.Shell = shell }
}

// WithEnv adds environment variables to the sandbox. Called repeatedly,
// the maps merge; later keys overwrite earlier ones.
func WithEnv(env map[string]string) SandboxOption {
	return func(o *SandboxConfig) {
		if o.Env == nil {
			o.Env = make(map[string]string, len(env))
		}
		for k, v := range env {
			o.Env[k] = v
		}
	}
}

// WithHostname sets the guest hostname.
func WithHostname(hostname string) SandboxOption {
	return func(o *SandboxConfig) { o.Hostname = hostname }
}

// WithUser sets the user to run the sandbox process as (UID or name).
func WithUser(user string) SandboxOption {
	return func(o *SandboxConfig) { o.User = user }
}

// WithReplace stops any existing sandbox with the same name before
// creating. Sends SIGTERM, waits up to 10s for graceful exit, then
// escalates to SIGKILL. Use WithReplaceWithGrace to set a different
// grace period or skip SIGTERM entirely.
func WithReplace() SandboxOption {
	return func(o *SandboxConfig) { o.Replace = true }
}

// WithReplaceWithGrace is like WithReplace but with a caller-specified
// grace period between SIGTERM and SIGKILL. Implies WithReplace —
// calling this alone is enough. A zero duration skips SIGTERM and
// SIGKILLs immediately.
func WithReplaceWithGrace(grace time.Duration) SandboxOption {
	return func(o *SandboxConfig) {
		o.Replace = true
		g := grace
		o.ReplaceWithGrace = &g
	}
}

// WithDetached creates the sandbox in detached mode. The sandbox continues
// running after the Go process exits. Reattach via GetSandbox or CreateSandboxDetached.
func WithDetached() SandboxOption {
	return func(o *SandboxConfig) { o.Detached = true }
}

// WithEntrypoint overrides the user-workload entrypoint baked into the image.
// Note this is the user workload (what the agent execs per request), not the
// guest PID 1 — for that, use WithInit.
func WithEntrypoint(cmd ...string) SandboxOption {
	return func(o *SandboxConfig) { o.Entrypoint = append([]string(nil), cmd...) }
}

// WithInit hands off PID 1 to a guest init binary.
//
//	microsandbox.WithInit(microsandbox.Init.Auto())
//	microsandbox.WithInit(microsandbox.Init.Cmd("/lib/systemd/systemd",
//	    microsandbox.InitOptions{Args: []string{"--unit=multi-user.target"}}))
func WithInit(cfg InitConfig) SandboxOption {
	return func(o *SandboxConfig) {
		c := cfg
		o.Init = &c
	}
}

// WithLogLevel sets the sandbox process log level.
func WithLogLevel(level LogLevel) SandboxOption {
	return func(o *SandboxConfig) { o.LogLevel = level }
}

// WithQuietLogs suppresses sandbox-level log output.
func WithQuietLogs() SandboxOption {
	return func(o *SandboxConfig) { o.QuietLogs = true }
}

// WithScripts attaches named scripts that can be invoked via the agent.
// Multiple calls merge; later entries overwrite earlier ones with the same name.
func WithScripts(scripts map[string]string) SandboxOption {
	return func(o *SandboxConfig) {
		if o.Scripts == nil {
			o.Scripts = make(map[string]string, len(scripts))
		}
		for k, v := range scripts {
			o.Scripts[k] = v
		}
	}
}

// WithPullPolicy controls when the runtime pulls the image.
func WithPullPolicy(p PullPolicy) SandboxOption {
	return func(o *SandboxConfig) { o.PullPolicy = p }
}

// WithMaxDuration caps the sandbox's total runtime. Zero means unlimited.
// Sub-second precision is rounded up to whole seconds.
func WithMaxDuration(d time.Duration) SandboxOption {
	return func(o *SandboxConfig) { o.MaxDuration = d }
}

// WithIdleTimeout stops the sandbox after a period without exec activity.
// Zero means unlimited. Sub-second precision is rounded up to whole seconds.
func WithIdleTimeout(d time.Duration) SandboxOption {
	return func(o *SandboxConfig) { o.IdleTimeout = d }
}

// WithStopSignal overrides the signal sent on graceful stop (defaults to SIGTERM).
// Pass standard names like "SIGTERM" or "SIGINT".
func WithStopSignal(sig string) SandboxOption {
	return func(o *SandboxConfig) { o.StopSignal = sig }
}

// WithRegistryAuth sets credentials for pulling private OCI images.
func WithRegistryAuth(auth RegistryAuth) SandboxOption {
	return func(o *SandboxConfig) {
		a := auth
		o.RegistryAuth = &a
	}
}

// WithLabels attaches key-value labels to the sandbox config. They merge on
// top of any image-level labels (user values win on conflict). Multiple calls
// merge; later keys overwrite earlier ones.
func WithLabels(labels map[string]string) SandboxOption {
	return func(o *SandboxConfig) {
		if o.Labels == nil {
			o.Labels = make(map[string]string, len(labels))
		}
		for k, v := range labels {
			o.Labels[k] = v
		}
	}
}

// WithPorts publishes host TCP ports into the sandbox. The map key is the
// host port and the value is the guest port.
func WithPorts(ports map[uint16]uint16) SandboxOption {
	return func(o *SandboxConfig) {
		if o.Ports == nil {
			o.Ports = make(map[uint16]uint16, len(ports))
		}
		for h, g := range ports {
			o.Ports[h] = g
		}
	}
}

// WithPortsUDP publishes host UDP ports into the sandbox.
func WithPortsUDP(ports map[uint16]uint16) SandboxOption {
	return func(o *SandboxConfig) {
		if o.PortsUDP == nil {
			o.PortsUDP = make(map[uint16]uint16, len(ports))
		}
		for h, g := range ports {
			o.PortsUDP[h] = g
		}
	}
}

// WithNetwork sets the network configuration for the sandbox.
func WithNetwork(net *NetworkConfig) SandboxOption {
	return func(o *SandboxConfig) { o.Network = net }
}

// WithSecrets appends credential secrets to the sandbox. Secrets never enter
// the VM; the network proxy substitutes them at the transport layer.
func WithSecrets(secrets ...SecretEntry) SandboxOption {
	return func(o *SandboxConfig) { o.Secrets = append(o.Secrets, secrets...) }
}

// WithPatches appends rootfs patches applied before the VM boots.
// Patches are only compatible with OverlayFS rootfs (not disk images).
func WithPatches(patches ...PatchConfig) SandboxOption {
	return func(o *SandboxConfig) { o.Patches = append(o.Patches, patches...) }
}

// ---------------------------------------------------------------------------
// Init (PID 1 handoff)
// ---------------------------------------------------------------------------

// InitConfig describes a guest PID-1 init process. Construct via the Init
// factory.
type InitConfig struct {
	Cmd  string
	Args []string
	Env  map[string]string
}

// InitOptions tunes the Init factory beyond the required cmd.
type InitOptions struct {
	Args []string
	Env  map[string]string
}

type initFactory struct{}

// Init is the factory namespace for InitConfig values.
//
//	microsandbox.WithInit(microsandbox.Init.Auto())
//	microsandbox.WithInit(microsandbox.Init.Cmd("/sbin/init", microsandbox.InitOptions{}))
var Init initFactory

// Auto delegates to agentd to probe common init paths.
func (initFactory) Auto() InitConfig { return InitConfig{Cmd: "auto"} }

// Cmd sets the init binary path with optional args/env.
func (initFactory) Cmd(cmd string, opts InitOptions) InitConfig {
	return InitConfig{Cmd: cmd, Args: append([]string(nil), opts.Args...), Env: opts.Env}
}

// ---------------------------------------------------------------------------
// Registry credentials
// ---------------------------------------------------------------------------

// RegistryAuth carries credentials for a private OCI registry.
type RegistryAuth struct {
	Username string
	Password string
}

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

// NetworkConfig configures the sandbox network stack.
type NetworkConfig struct {
	// Policy is a preset name: "none", "public-only", "allow-all", "non-local".
	// Mutually exclusive with custom rules.
	Policy NetworkPolicyPreset

	// Rules are custom ordered allow/deny rules (first match wins). When
	// set, Policy is still honoured: preset rules come first, custom rules
	// follow. Use DefaultEgress / DefaultIngress to set fall-through behaviour.
	Rules []PolicyRule

	// DefaultEgress is "allow" or "deny"; falls through here when no rule
	// matches an outbound connection. Defaults to "deny".
	DefaultEgress PolicyAction

	// DefaultIngress is "allow" or "deny"; falls through here when no rule
	// matches an inbound connection. Defaults to "allow".
	DefaultIngress PolicyAction

	// DenyDomains is a list of exact domain names to refuse DNS resolution for.
	DenyDomains []string

	// DenyDomainSuffixes is a list of domain suffixes (e.g. ".ads") to block.
	DenyDomainSuffixes []string

	// DNS configures the in-VM DNS proxy.
	DNS *DNSConfig

	// DNSRebindProtection is a legacy convenience; prefer DNS.RebindProtection.
	// When DNS is also set, the nested value wins.
	DNSRebindProtection *bool

	// TLS configures the transparent TLS interception proxy.
	TLS *TLSConfig

	// Ports publishes host TCP ports into the sandbox (host→guest).
	Ports map[uint16]uint16

	// MaxConnections caps concurrent network connections from the sandbox.
	MaxConnections *uint

	// OnSecretViolation is the sandbox-wide action when a secret is sent to
	// a disallowed host. Per-secret overrides via SecretEntry.OnViolation.
	OnSecretViolation ViolationAction

	// TrustHostCAs ships the host's extra CA bundles into the guest.
	TrustHostCAs *bool
}

// DNSConfig configures the in-VM DNS proxy.
type DNSConfig struct {
	// RebindProtection blocks DNS rebinding attacks (default true).
	RebindProtection *bool
	// Nameservers is a list of upstream resolvers (e.g. "1.1.1.1:53").
	Nameservers []string
	// QueryTimeoutMs caps DNS query latency.
	QueryTimeoutMs *uint64
}

// PolicyRule is a single firewall rule.
type PolicyRule struct {
	Action      PolicyAction
	Direction   PolicyDirection
	Destination string // "*", "loopback", "private", "link-local", "metadata",
	// "multicast", "public", "host", a CIDR ("10.0.0.0/8"), a domain suffix
	// (".internal"), or a plain domain ("api.example.com").

	// Protocol is the legacy single-protocol field. Prefer Protocols when
	// matching multiple. The empty string means any.
	Protocol PolicyProtocol
	// Protocols is a multi-protocol set (empty = any).
	Protocols []PolicyProtocol

	// Port is a single port ("443") or range ("8000-9000").
	Port string
	// Ports lets callers pass several values at once.
	Ports []string
}

// TLSConfig configures the transparent HTTPS inspection proxy.
type TLSConfig struct {
	// Bypass is a list of domain patterns (supports "*.suffix") to skip MITM.
	Bypass []string

	// VerifyUpstream verifies upstream TLS certificates (default true).
	VerifyUpstream *bool

	// InterceptedPorts lists ports on which TLS is intercepted (default [443]).
	InterceptedPorts []uint16

	// BlockQUIC blocks QUIC on intercepted ports to force TLS fallback.
	BlockQUIC *bool

	// CACert is the path to the interception CA certificate PEM file.
	CACert string

	// CAKey is the path to the interception CA private key PEM file.
	CAKey string

	// UpstreamCACerts is a list of paths to additional CA bundles trusted
	// for upstream verification.
	UpstreamCACerts []string
}

// networkPolicyFactory is the static-method surface matching the Node
// NetworkPolicy class and the Python Network classmethods. Invoke through
// the package-level NetworkPolicy value, e.g. `microsandbox.NetworkPolicy.PublicOnly()`.
type networkPolicyFactory struct{}

// NetworkPolicy is the factory namespace for common network presets.
//
//	microsandbox.WithNetwork(microsandbox.NetworkPolicy.PublicOnly())
var NetworkPolicy networkPolicyFactory

// None returns a NetworkConfig that blocks all network access.
func (networkPolicyFactory) None() *NetworkConfig {
	return &NetworkConfig{Policy: NetworkPolicyPresetNone}
}

// PublicOnly returns a NetworkConfig that allows only public internet traffic
// (RFC-1918 private ranges are blocked). This is the default when no network
// configuration is supplied.
func (networkPolicyFactory) PublicOnly() *NetworkConfig {
	return &NetworkConfig{Policy: NetworkPolicyPresetPublicOnly}
}

// AllowAll returns a NetworkConfig that permits all network traffic.
func (networkPolicyFactory) AllowAll() *NetworkConfig {
	return &NetworkConfig{Policy: NetworkPolicyPresetAllowAll}
}

// NonLocal returns a NetworkConfig that allows public internet plus
// private/LAN egress; blocks loopback, link-local, and metadata.
func (networkPolicyFactory) NonLocal() *NetworkConfig {
	return &NetworkConfig{Policy: NetworkPolicyPresetNonLocal}
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

// SecretEntry configures a single credential that the network proxy
// substitutes at the transport layer. The value never reaches the guest VM.
type SecretEntry struct {
	// EnvVar is the environment variable name that holds the placeholder inside
	// the sandbox.
	EnvVar string

	// Value is the actual secret; it never crosses the FFI into the guest.
	Value string

	// AllowHosts restricts substitution to exact host matches.
	AllowHosts []string

	// AllowHostPatterns restricts substitution to wildcard host patterns
	// (e.g. "*.openai.com").
	AllowHostPatterns []string

	// Placeholder is the string used inside the sandbox in place of the secret.
	// Auto-generated from EnvVar when empty.
	Placeholder string

	// RequireTLS requires a verified TLS identity before substituting.
	// Defaults to true when nil.
	RequireTLS *bool

	// OnViolation overrides the sandbox-level action when this secret is
	// detected going to a disallowed host. The last non-empty value across
	// all secrets wins (matches Node/Python behaviour, since the runtime
	// applies it network-wide).
	OnViolation ViolationAction
}

// SecretEnvOptions tunes Secret.Env beyond the required envVar and value.
type SecretEnvOptions struct {
	AllowHosts        []string
	AllowHostPatterns []string
	Placeholder       string
	RequireTLS        *bool
	OnViolation       ViolationAction
}

// secretFactory is the factory namespace matching Node's `Secret.env(...)` and
// Python's `Secret.env(...)`. Invoke through the package-level Secret value.
type secretFactory struct{}

// Secret is the factory namespace for creating SecretEntry values.
//
//	microsandbox.Secret.Env("OPENAI_API_KEY",
//	    os.Getenv("OPENAI_API_KEY"),
//	    microsandbox.SecretEnvOptions{AllowHosts: []string{"api.openai.com"}},
//	)
var Secret secretFactory

// Env returns a SecretEntry bound to an environment variable. Pass an empty
// SecretEnvOptions{} if no additional tuning is needed.
func (secretFactory) Env(envVar, value string, opts SecretEnvOptions) SecretEntry {
	return SecretEntry{
		EnvVar:            envVar,
		Value:             value,
		AllowHosts:        opts.AllowHosts,
		AllowHostPatterns: opts.AllowHostPatterns,
		Placeholder:       opts.Placeholder,
		RequireTLS:        opts.RequireTLS,
		OnViolation:       opts.OnViolation,
	}
}

// ---------------------------------------------------------------------------
// Patches
// ---------------------------------------------------------------------------

// PatchConfig represents a single rootfs modification applied before boot.
type PatchConfig struct {
	Kind    PatchKind
	Path    string
	Content string
	Mode    *uint32
	Replace bool
	Src     string
	Dst     string
	Target  string
	Link    string
}

// PatchOptions tunes Patch factory methods that accept a mode and replace flag.
type PatchOptions struct {
	Mode    *uint32
	Replace bool
}

// patchFactory is the factory namespace matching Node's Patch class and
// Python's Patch class. Invoke through the package-level Patch value.
type patchFactory struct{}

// Patch is the factory namespace for constructing PatchConfig values.
//
//	microsandbox.WithPatches(
//	    microsandbox.Patch.Text("/etc/greeting.txt", "Hello!\n", microsandbox.PatchOptions{}),
//	    microsandbox.Patch.Mkdir("/app", microsandbox.PatchOptions{}),
//	)
var Patch patchFactory

// Text writes text to a file, creating or replacing it.
func (patchFactory) Text(path, content string, opts PatchOptions) PatchConfig {
	return PatchConfig{Kind: PatchKindText, Path: path, Content: content, Mode: opts.Mode, Replace: opts.Replace}
}

// Append appends text to an existing file.
func (patchFactory) Append(path, content string) PatchConfig {
	return PatchConfig{Kind: PatchKindAppend, Path: path, Content: content}
}

// Mkdir creates a directory (idempotent). Only opts.Mode is used; Replace is
// ignored.
func (patchFactory) Mkdir(path string, opts PatchOptions) PatchConfig {
	return PatchConfig{Kind: PatchKindMkdir, Path: path, Mode: opts.Mode}
}

// Remove removes a file or directory (idempotent).
func (patchFactory) Remove(path string) PatchConfig {
	return PatchConfig{Kind: PatchKindRemove, Path: path}
}

// Symlink creates a symlink from link → target. Only opts.Replace is used.
func (patchFactory) Symlink(target, link string, opts PatchOptions) PatchConfig {
	return PatchConfig{Kind: PatchKindSymlink, Target: target, Link: link, Replace: opts.Replace}
}

// CopyFile copies a host file into the rootfs.
func (patchFactory) CopyFile(src, dst string, opts PatchOptions) PatchConfig {
	return PatchConfig{Kind: PatchKindCopyFile, Src: src, Dst: dst, Mode: opts.Mode, Replace: opts.Replace}
}

// CopyDir copies a host directory into the rootfs. Only opts.Replace is used.
func (patchFactory) CopyDir(src, dst string, opts PatchOptions) PatchConfig {
	return PatchConfig{Kind: PatchKindCopyDir, Src: src, Dst: dst, Replace: opts.Replace}
}

// ---------------------------------------------------------------------------
// Exec options
// ---------------------------------------------------------------------------

// ExecConfig configures a single Exec or ExecStream call. Callers typically
// set fields via WithExecCwd and WithExecTimeout functional options; it is
// exported for parity with the other SDKs' ExecConfig types.
type ExecConfig struct {
	Cwd       string
	Timeout   time.Duration
	StdinPipe bool
	User      string
	Env       map[string]string
}

// ExecOption is a functional option for Exec.
type ExecOption func(*ExecConfig)

// WithExecCwd sets the working directory for a single command.
func WithExecCwd(path string) ExecOption {
	return func(o *ExecConfig) { o.Cwd = path }
}

// WithExecTimeout sets a per-command timeout. When exceeded, the guest
// terminates the process and the call returns an error with
// Kind==ErrExecTimeout.
func WithExecTimeout(d time.Duration) ExecOption {
	return func(o *ExecConfig) { o.Timeout = d }
}

// WithExecStdinPipe enables a stdin pipe for the exec session, allowing data
// to be written to the process via ExecHandle.TakeStdin.
func WithExecStdinPipe() ExecOption {
	return func(o *ExecConfig) { o.StdinPipe = true }
}

// WithExecUser sets the user to run the command as (UID or name).
func WithExecUser(user string) ExecOption {
	return func(o *ExecConfig) { o.User = user }
}

// WithExecEnv adds per-command environment variables. Called repeatedly, maps
// merge; later keys overwrite earlier ones.
func WithExecEnv(env map[string]string) ExecOption {
	return func(o *ExecConfig) {
		if o.Env == nil {
			o.Env = make(map[string]string, len(env))
		}
		for k, v := range env {
			o.Env[k] = v
		}
	}
}

// ---------------------------------------------------------------------------
// Mounts
// ---------------------------------------------------------------------------

// MountConfig describes how a host path, named volume, tmpfs, or disk image
// is mounted into the sandbox at a guest path. Construct via the Mount factory:
//
//	microsandbox.Mount.Named("my-data", microsandbox.MountOptions{})
//	microsandbox.Mount.Bind("/host/path", microsandbox.MountOptions{Readonly: true})
//	microsandbox.Mount.Tmpfs(microsandbox.TmpfsOptions{SizeMiB: 256})
//	microsandbox.Mount.Disk("/host/data.img", microsandbox.DiskOptions{Format: "raw"})
//
// Use the factory rather than constructing the struct directly: it enforces
// the mutually-exclusive kinds (bind / named / tmpfs / disk).
type MountConfig struct {
	// kind is the discriminator. Exposed via Kind() for callers that need
	// to introspect; setting fields below directly is discouraged.
	kind MountKind

	Bind     string
	Named    string
	Tmpfs    bool
	Disk     string
	Format   string
	Fstype   string
	Readonly bool
	SizeMiB  uint32
}

// MountKind discriminates between the four mount flavours.
type MountKind uint8

const (
	// MountKindBind is a host bind mount.
	MountKindBind MountKind = iota + 1
	// MountKindNamed is a named persistent volume.
	MountKindNamed
	// MountKindTmpfs is an in-memory tmpfs.
	MountKindTmpfs
	// MountKindDisk is a host disk image (raw / qcow2 / ...).
	MountKindDisk
)

// Kind reports which flavour of mount this is.
func (m MountConfig) Kind() MountKind { return m.kind }

// MountOptions tunes bind and named mount factories.
type MountOptions struct {
	Readonly bool
}

// TmpfsOptions tunes the Tmpfs factory.
type TmpfsOptions struct {
	SizeMiB  uint32
	Readonly bool
}

// DiskOptions tunes the Disk factory.
type DiskOptions struct {
	// Format hint ("raw", "qcow2"). Optional; the runtime can usually probe.
	Format string
	// Fstype hint ("ext4", "xfs"). Optional.
	Fstype   string
	Readonly bool
}

// mountFactory is the factory namespace for constructing MountConfig values.
// Invoke through the package-level Mount value.
type mountFactory struct{}

// Mount is the factory namespace for volume mount configurations.
//
//	microsandbox.WithMounts(map[string]microsandbox.MountConfig{
//	    "/data": microsandbox.Mount.Named("my-vol", microsandbox.MountOptions{}),
//	    "/tmp":  microsandbox.Mount.Tmpfs(microsandbox.TmpfsOptions{SizeMiB: 256}),
//	})
var Mount mountFactory

// Bind returns a MountConfig that bind-mounts a host directory into the sandbox.
func (mountFactory) Bind(hostPath string, opts MountOptions) MountConfig {
	return MountConfig{kind: MountKindBind, Bind: hostPath, Readonly: opts.Readonly}
}

// Named returns a MountConfig that mounts a named persistent volume.
func (mountFactory) Named(name string, opts MountOptions) MountConfig {
	return MountConfig{kind: MountKindNamed, Named: name, Readonly: opts.Readonly}
}

// Tmpfs returns a MountConfig that mounts an ephemeral in-memory filesystem.
func (mountFactory) Tmpfs(opts TmpfsOptions) MountConfig {
	return MountConfig{kind: MountKindTmpfs, Tmpfs: true, SizeMiB: opts.SizeMiB, Readonly: opts.Readonly}
}

// Disk mounts a host disk image at the given guest path.
func (mountFactory) Disk(hostPath string, opts DiskOptions) MountConfig {
	return MountConfig{
		kind:     MountKindDisk,
		Disk:     hostPath,
		Format:   opts.Format,
		Fstype:   opts.Fstype,
		Readonly: opts.Readonly,
	}
}

// WithMounts adds volume mount configurations keyed by guest path.
// Called multiple times, the maps merge; later entries overwrite earlier ones
// for the same guest path.
func WithMounts(mounts map[string]MountConfig) SandboxOption {
	return func(o *SandboxConfig) {
		if o.Volumes == nil {
			o.Volumes = make(map[string]MountConfig, len(mounts))
		}
		for k, v := range mounts {
			o.Volumes[k] = v
		}
	}
}

// ---------------------------------------------------------------------------
// Volume options
// ---------------------------------------------------------------------------

// VolumeConfig holds configuration for a named volume.
type VolumeConfig struct {
	QuotaMiB uint32
	Labels   map[string]string
}

// VolumeOption is a functional option for CreateVolume.
type VolumeOption func(*VolumeConfig)

// WithVolumeQuota sets the volume's quota in MiB. Zero means unlimited.
func WithVolumeQuota(mebibytes uint32) VolumeOption {
	return func(o *VolumeConfig) { o.QuotaMiB = mebibytes }
}

// WithVolumeLabels attaches key-value labels to the volume. Multiple calls
// merge; later entries overwrite earlier ones for the same key.
func WithVolumeLabels(labels map[string]string) VolumeOption {
	return func(o *VolumeConfig) {
		if o.Labels == nil {
			o.Labels = make(map[string]string, len(labels))
		}
		for k, v := range labels {
			o.Labels[k] = v
		}
	}
}

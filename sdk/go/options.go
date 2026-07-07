package microsandbox

import (
	"encoding/json"
	"fmt"
	"time"
)

// SandboxConfig holds configuration for creating a sandbox.
//
// Most callers construct a sandbox via CreateSandbox with functional options;
// SandboxConfig is exported for callers that prefer to build a config value
// directly and pass it via WithConfig.
type SandboxConfig struct {
	Name            string
	Image           string
	ImageFstype     string
	ImageBind       string
	OCIUpperSizeMiB uint32
	ociUpperSizeSet bool
	Snapshot        string
	MemoryMiB       uint32
	CPUs            uint8
	MaxMemoryMiB    uint32
	MaxCPUs         uint8
	Workdir         string
	Shell           string
	SecurityProfile SecurityProfile
	Hostname        string
	User            string
	Replace         bool
	// ReplaceWithTimeout, if non-nil, sets a specific timeout between
	// SIGTERM and SIGKILL when replacing an existing sandbox. nil means
	// "use the runtime default" (10s when Replace is set). Setting this
	// implies Replace=true. Zero is honored — it skips SIGTERM and
	// SIGKILLs immediately. Use WithReplaceWithTimeout.
	ReplaceWithTimeout *time.Duration
	Env                map[string]string
	Labels             map[string]string
	Detached           bool
	Ephemeral          bool
	Entrypoint         []string
	Init               *InitConfig
	LogLevel           LogLevel
	QuietLogs          bool
	Scripts            map[string]string
	PullPolicy         PullPolicy
	MaxDuration        time.Duration
	IdleTimeout        time.Duration
	RegistryAuth       *RegistryAuth
	Ports              map[uint16]uint16 // host port → guest port (TCP)
	PortsUDP           map[uint16]uint16 // host port → guest port (UDP)
	PortBindings       []PortBinding     // explicit bind address host→guest ports
	Network            *NetworkConfig
	Secrets            []SecretEntry
	Patches            []PatchConfig
	Volumes            map[string]MountConfig // guest path → mount config
}

// SandboxOption is a functional option for configuring a sandbox.
type SandboxOption func(*SandboxConfig)

type persistedSandboxConfig struct {
	Name            string               `json:"name"`
	Image           json.RawMessage      `json:"image"`
	ImageFstype     string               `json:"image_fstype"`
	OCIUpperSizeMiB uint32               `json:"oci_upper_size_mib"`
	MemoryMiB       uint32               `json:"memory_mib"`
	CPUs            uint8                `json:"cpus"`
	MaxMemoryMiB    uint32               `json:"max_memory_mib"`
	MaxCPUs         uint8                `json:"max_cpus"`
	Resources       *persistedResources  `json:"resources"`
	Workdir         string               `json:"workdir"`
	Shell           string               `json:"shell"`
	SecurityProfile SecurityProfile      `json:"security_profile"`
	Hostname        string               `json:"hostname"`
	User            string               `json:"user"`
	Replace         bool                 `json:"replace"`
	Labels          map[string]string    `json:"labels"`
	Detached        bool                 `json:"detached"`
	Lifecycle       *persistedLifecycle  `json:"lifecycle"`
	Entrypoint      []string             `json:"entrypoint"`
	Init            *persistedInitConfig `json:"init"`
	LogLevel        LogLevel             `json:"log_level"`
	QuietLogs       bool                 `json:"quiet_logs"`
	Scripts         map[string]string    `json:"scripts"`
	PullPolicy      PullPolicy           `json:"pull_policy"`
}

type persistedInitConfig struct {
	Cmd  string      `json:"cmd"`
	Args []string    `json:"args"`
	Env  [][2]string `json:"env"`
}

type persistedResources struct {
	// Canonical field names; the cpus/max_cpus pair decodes configs
	// persisted before the vcpus rename.
	Vcpus        uint8  `json:"vcpus"`
	MaxVcpus     uint8  `json:"max_vcpus"`
	CPUs         uint8  `json:"cpus"`
	MemoryMiB    uint32 `json:"memory_mib"`
	MaxCPUs      uint8  `json:"max_cpus"`
	MaxMemoryMiB uint32 `json:"max_memory_mib"`
}

func (r persistedResources) effectiveCPUs() uint8 {
	if r.Vcpus != 0 {
		return r.Vcpus
	}
	return r.CPUs
}

func (r persistedResources) effectiveMaxCPUs() uint8 {
	if r.MaxVcpus != 0 {
		return r.MaxVcpus
	}
	return r.MaxCPUs
}

type persistedLifecycle struct {
	Ephemeral       bool   `json:"ephemeral"`
	MaxDurationSecs uint64 `json:"max_duration_secs"`
	IdleTimeoutSecs uint64 `json:"idle_timeout_secs"`
}

// UnmarshalJSON decodes the persisted Rust sandbox config into the Go SDK's
// public configuration shape.
func (c *SandboxConfig) UnmarshalJSON(data []byte) error {
	var raw persistedSandboxConfig
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	image, imageFstype, upperSizeMiB, upperSizeSet, err := decodePersistedRootfsSource(raw.Image)
	if err != nil {
		return err
	}
	if raw.ImageFstype != "" {
		imageFstype = raw.ImageFstype
	}
	if raw.OCIUpperSizeMiB != 0 {
		upperSizeMiB = raw.OCIUpperSizeMiB
		upperSizeSet = true
	}

	*c = SandboxConfig{
		Name:            raw.Name,
		Image:           image,
		ImageFstype:     imageFstype,
		OCIUpperSizeMiB: upperSizeMiB,
		ociUpperSizeSet: upperSizeSet,
		MemoryMiB:       raw.memoryMiB(),
		CPUs:            raw.cpus(),
		MaxMemoryMiB:    raw.maxMemoryMiB(),
		MaxCPUs:         raw.maxCPUs(),
		Workdir:         raw.Workdir,
		Shell:           raw.Shell,
		SecurityProfile: raw.SecurityProfile,
		Hostname:        raw.Hostname,
		User:            raw.User,
		Replace:         raw.Replace,
		Labels:          raw.Labels,
		Detached:        raw.Detached,
		Ephemeral:       raw.lifecycleEphemeral(),
		Entrypoint:      raw.Entrypoint,
		Init:            decodePersistedInit(raw.Init),
		LogLevel:        raw.LogLevel,
		QuietLogs:       raw.QuietLogs,
		Scripts:         raw.Scripts,
		PullPolicy:      raw.PullPolicy,
		MaxDuration:     time.Duration(raw.lifecycleMaxDurationSecs()) * time.Second,
		IdleTimeout:     time.Duration(raw.lifecycleIdleTimeoutSecs()) * time.Second,
	}
	return nil
}

func (c persistedSandboxConfig) cpus() uint8 {
	if c.Resources != nil {
		return c.Resources.effectiveCPUs()
	}
	return c.CPUs
}

func (c persistedSandboxConfig) memoryMiB() uint32 {
	if c.Resources != nil {
		return c.Resources.MemoryMiB
	}
	return c.MemoryMiB
}

func (c persistedSandboxConfig) maxCPUs() uint8 {
	if c.Resources != nil {
		if max := c.Resources.effectiveMaxCPUs(); max != 0 {
			return max
		}
		return c.Resources.effectiveCPUs()
	}
	if c.MaxCPUs != 0 {
		return c.MaxCPUs
	}
	return c.CPUs
}

func (c persistedSandboxConfig) maxMemoryMiB() uint32 {
	if c.Resources != nil {
		if c.Resources.MaxMemoryMiB != 0 {
			return c.Resources.MaxMemoryMiB
		}
		return c.Resources.MemoryMiB
	}
	if c.MaxMemoryMiB != 0 {
		return c.MaxMemoryMiB
	}
	return c.MemoryMiB
}

func (c persistedSandboxConfig) lifecycleEphemeral() bool {
	return c.Lifecycle != nil && c.Lifecycle.Ephemeral
}

func (c persistedSandboxConfig) lifecycleMaxDurationSecs() uint64 {
	if c.Lifecycle == nil {
		return 0
	}
	return c.Lifecycle.MaxDurationSecs
}

func (c persistedSandboxConfig) lifecycleIdleTimeoutSecs() uint64 {
	if c.Lifecycle == nil {
		return 0
	}
	return c.Lifecycle.IdleTimeoutSecs
}

func decodePersistedInit(raw *persistedInitConfig) *InitConfig {
	if raw == nil {
		return nil
	}
	cfg := &InitConfig{
		Cmd:  raw.Cmd,
		Args: append([]string(nil), raw.Args...),
	}
	if len(raw.Env) > 0 {
		cfg.Env = make(map[string]string, len(raw.Env))
		for _, entry := range raw.Env {
			cfg.Env[entry[0]] = entry[1]
		}
	}
	return cfg
}

func decodePersistedRootfsSource(raw json.RawMessage) (string, string, uint32, bool, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", "", 0, false, nil
	}

	var plain string
	if err := json.Unmarshal(raw, &plain); err == nil {
		return plain, "", 0, false, nil
	}

	var tagged map[string]json.RawMessage
	if err := json.Unmarshal(raw, &tagged); err != nil {
		return "", "", 0, false, err
	}

	// Canonical tags are snake_case; the PascalCase forms decode configs
	// persisted before the casing change (mirrors the core's serde aliases).
	variant := func(keys ...string) (json.RawMessage, bool) {
		for _, k := range keys {
			if v, ok := tagged[k]; ok {
				return v, true
			}
		}
		return nil, false
	}

	if value, ok := variant("oci", "Oci"); ok {
		var source struct {
			Reference    string  `json:"reference"`
			UpperSizeMiB *uint32 `json:"upper_size_mib"`
		}
		if err := json.Unmarshal(value, &source); err != nil {
			return "", "", 0, false, err
		}
		if source.UpperSizeMiB == nil {
			return source.Reference, "", 0, false, nil
		}
		return source.Reference, "", *source.UpperSizeMiB, true, nil
	}

	if value, ok := variant("bind", "Bind"); ok {
		var path string
		if err := json.Unmarshal(value, &path); err != nil {
			return "", "", 0, false, err
		}
		return path, "", 0, false, nil
	}

	if value, ok := variant("disk_image", "DiskImage"); ok {
		var source struct {
			Path   string  `json:"path"`
			Fstype *string `json:"fstype"`
		}
		if err := json.Unmarshal(value, &source); err != nil {
			return "", "", 0, false, err
		}
		if source.Fstype == nil {
			return source.Path, "", 0, false, nil
		}
		return source.Path, *source.Fstype, 0, false, nil
	}

	return "", "", 0, false, fmt.Errorf("unknown rootfs source variant: %v", tagged)
}

// SecurityProfile selects the in-guest security profile.
type SecurityProfile string

const (
	// SecurityProfileDefault preserves normal guest-root semantics.
	SecurityProfileDefault SecurityProfile = "default"
	// SecurityProfileRestricted applies stronger in-guest hardening.
	SecurityProfileRestricted SecurityProfile = "restricted"
)

// WithImage sets the container image to use (e.g. "python:3.12").
func WithImage(image string) SandboxOption {
	return func(o *SandboxConfig) { o.Image = image }
}

// WithOCIUpperSize sets the writable overlay upper size for an OCI image, in MiB.
// It is valid only with WithImage when the image resolves to an OCI reference.
func WithOCIUpperSize(mebibytes uint32) SandboxOption {
	return func(o *SandboxConfig) {
		o.OCIUpperSizeMiB = mebibytes
		o.ociUpperSizeSet = true
	}
}

// WithImageDisk sets a disk image as the sandbox root filesystem and provides
// an optional inner filesystem hint (for example "ext4"). The disk format is
// inferred from the path extension (.qcow2, .raw, or .vmdk).
func WithImageDisk(path string, fstype string) SandboxOption {
	return func(o *SandboxConfig) {
		o.Image = path
		o.ImageFstype = fstype
	}
}

// WithBindRootfs uses a host directory directly as the sandbox root filesystem
// (a bind rootfs): the directory's contents become the guest root filesystem
// as-is, with no OCI pull and no overlay. Mutually exclusive with WithImage,
// WithImageDisk, and WithSnapshot.
func WithBindRootfs(path string) SandboxOption {
	return func(o *SandboxConfig) { o.ImageBind = path }
}

// WithSnapshot boots from a snapshot artifact by bare name or filesystem path.
// It is mutually exclusive with WithImage.
func WithSnapshot(pathOrName string) SandboxOption {
	return func(o *SandboxConfig) { o.Snapshot = pathOrName }
}

// WithMemory sets the memory limit in MiB (default 512MiB).
func WithMemory(mebibytes uint32) SandboxOption {
	return func(o *SandboxConfig) { o.MemoryMiB = mebibytes }
}

// WithCPUs sets the CPU limit in whole cores (default 1).
func WithCPUs(cpus uint8) SandboxOption {
	return func(o *SandboxConfig) { o.CPUs = cpus }
}

// WithMaxMemory sets the boot-time maximum hotpluggable memory in MiB.
func WithMaxMemory(mebibytes uint32) SandboxOption {
	return func(o *SandboxConfig) { o.MaxMemoryMiB = mebibytes }
}

// WithMaxCPUs sets the boot-time maximum possible vCPU count.
func WithMaxCPUs(cpus uint8) SandboxOption {
	return func(o *SandboxConfig) { o.MaxCPUs = cpus }
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

// WithSecurityProfile selects the in-guest security profile.
func WithSecurityProfile(profile SecurityProfile) SandboxOption {
	return func(o *SandboxConfig) { o.SecurityProfile = profile }
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

// WithLabels attaches labels to the sandbox for metrics attribution. Called
// repeatedly, the maps merge; later keys overwrite earlier ones. Keys must not
// use the reserved prefixes "sandbox.", "microsandbox.", or "service.".
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

// WithLabel attaches a single label to the sandbox. See WithLabels.
func WithLabel(key, value string) SandboxOption {
	return func(o *SandboxConfig) {
		if o.Labels == nil {
			o.Labels = make(map[string]string, 1)
		}
		o.Labels[key] = value
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
// escalates to SIGKILL. Use WithReplaceWithTimeout to set a different
// timeout or skip SIGTERM entirely.
func WithReplace() SandboxOption {
	return func(o *SandboxConfig) { o.Replace = true }
}

// WithReplaceWithTimeout is like WithReplace but with a caller-specified
// timeout between SIGTERM and SIGKILL. Implies WithReplace — calling
// this alone is enough. A zero duration skips SIGTERM and SIGKILLs
// immediately.
func WithReplaceWithTimeout(timeout time.Duration) SandboxOption {
	return func(o *SandboxConfig) {
		o.Replace = true
		t := timeout
		o.ReplaceWithTimeout = &t
	}
}

// WithDetached creates the sandbox in detached mode. The sandbox continues
// running after the Go process exits. Reattach via GetSandbox.
func WithDetached() SandboxOption {
	return func(o *SandboxConfig) { o.Detached = true }
}

// WithEphemeral marks whether the runtime should remove the sandbox's DB row,
// on-disk state, logs, and captured output after it reaches a terminal status.
func WithEphemeral(ephemeral bool) SandboxOption {
	return func(o *SandboxConfig) { o.Ephemeral = ephemeral }
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

// WithRegistryAuth sets credentials for pulling private OCI images.
func WithRegistryAuth(auth RegistryAuth) SandboxOption {
	return func(o *SandboxConfig) {
		a := auth
		o.RegistryAuth = &a
	}
}

// WithPorts makes TCP services running in the sandbox reachable on localhost
// ports on the host. Each map entry exposes guest port value on host port key.
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

// WithPortsUDP makes UDP services running in the sandbox reachable on localhost
// ports on the host. Each map entry exposes guest port value on host port key.
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

// PortBinding describes how to expose a service running in the sandbox on a
// specific host address and port.
// Protocol defaults to TCP when empty. Use Bind "0.0.0.0" to expose the
// published port on all IPv4 interfaces.
type PortBinding struct {
	Bind      string
	HostPort  uint16
	GuestPort uint16
	Protocol  PortProtocol
}

// PortProtocol identifies the protocol for an exposed sandbox service.
type PortProtocol string

const (
	PortProtocolTCP PortProtocol = "tcp"
	PortProtocolUDP PortProtocol = "udp"
)

// WithPortBindings makes services running in the sandbox reachable on explicit
// host addresses and ports.
func WithPortBindings(bindings ...PortBinding) SandboxOption {
	return func(o *SandboxConfig) {
		o.PortBindings = append(o.PortBindings, bindings...)
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

// Auto uses a known image ENTRYPOINT init when present, preserving attached
// init-entrypoint commands, otherwise it delegates to agentd to probe common init paths.
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

	// Ports makes sandbox TCP services reachable on localhost ports on the host.
	Ports map[uint16]uint16

	// PortBindings makes sandbox services reachable on explicit host bind addresses.
	PortBindings []PortBinding

	// IPv4Pool is used to derive per-sandbox /30 guest subnets.
	// Defaults to "172.16.0.0/12".
	IPv4Pool string

	// IPv6Pool is used to derive per-sandbox /64 guest prefixes.
	// Defaults to "fd42:6d73:62::/48".
	IPv6Pool string

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
	// "multicast", "public", "host", an IP ("1.1.1.1"), a CIDR
	// ("10.0.0.0/8"), a domain suffix (".internal"), or a plain domain
	// ("api.example.com").

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

// ScopedUpstreamCACert configures an upstream CA bundle for a host pattern.
type ScopedUpstreamCACert struct {
	// Pattern is an exact host or "*.suffix" wildcard.
	Pattern string

	// Path is the path to a CA bundle trusted for matching upstream hosts.
	Path string
}

// ScopedVerifyUpstream configures upstream certificate verification for a host pattern.
type ScopedVerifyUpstream struct {
	// Pattern is an exact host or "*.suffix" wildcard.
	Pattern string

	// Verify controls upstream certificate verification for matching hosts.
	Verify bool
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

	// ScopedUpstreamCACerts is a list of host-scoped CA bundles trusted
	// only for matching upstream hosts.
	ScopedUpstreamCACerts []ScopedUpstreamCACert

	// ScopedVerifyUpstream is a list of host-scoped upstream verification
	// overrides.
	ScopedVerifyUpstream []ScopedVerifyUpstream
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
	// the sandbox. It must be non-empty and cannot contain '=' or NUL; shell
	// identifier syntax is not required.
	EnvVar string

	// Value is the actual secret; it never crosses the FFI into the guest.
	Value string

	// AllowHosts restricts substitution to exact host matches.
	AllowHosts []string

	// AllowHostPatterns restricts substitution to wildcard host patterns
	// (e.g. "*.openai.com").
	AllowHostPatterns []string

	// Placeholder is the string used inside the sandbox in place of the secret.
	// Auto-generated from EnvVar when empty. Custom values must be non-empty,
	// at most 1024 bytes, and cannot contain NUL, CR, or LF.
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

	Bind      string
	Named     string
	NamedMode string
	NamedKind string
	QuotaMiB  uint32
	Tmpfs     bool
	Disk      string
	Format    string
	Fstype    string
	Readonly  bool
	Noexec    bool
	Nosuid    bool
	Nodev     bool
	SizeMiB   uint32

	// StatVirtualization is the per-mount stat-virtualization policy. Only
	// meaningful for Bind and Named mounts. Zero value preserves the
	// conservative default (Strict).
	StatVirtualization StatVirtualization

	// HostPermissions is the per-mount host-permission propagation policy.
	// Only meaningful for Bind and Named mounts. Zero value preserves the
	// conservative default (Private).
	HostPermissions HostPermissions
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
//
// StatVirtualization and HostPermissions are virtiofs-only and rejected at
// build time if combined with a tmpfs or disk-image mount. The zero values
// preserve the conservative defaults (Strict + Private).
type MountOptions struct {
	Readonly           bool
	Noexec             bool
	Nosuid             bool
	Nodev              bool
	StatVirtualization StatVirtualization
	HostPermissions    HostPermissions
}

// NamedVolumeOptions tunes sandbox-time named volume provisioning.
type NamedVolumeOptions struct {
	Mode     string // "existing", "create", or "ensure-exists"; empty means existing.
	Kind     string // "dir" or "disk"; empty means dir.
	SizeMiB  uint32
	QuotaMiB uint32
}

// TmpfsOptions tunes the Tmpfs factory.
type TmpfsOptions struct {
	SizeMiB  uint32
	Readonly bool
	Noexec   bool
	Nosuid   bool
	Nodev    bool
}

// DiskOptions tunes the Disk factory.
type DiskOptions struct {
	// Format hint ("raw", "qcow2"). Optional; the runtime can usually probe.
	Format string
	// Fstype hint ("ext4", "xfs"). Optional.
	Fstype   string
	Readonly bool
	Noexec   bool
	Nosuid   bool
	Nodev    bool
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
	return MountConfig{
		kind:               MountKindBind,
		Bind:               hostPath,
		Readonly:           opts.Readonly,
		Noexec:             opts.Noexec,
		Nosuid:             opts.Nosuid,
		Nodev:              opts.Nodev,
		StatVirtualization: opts.StatVirtualization,
		HostPermissions:    opts.HostPermissions,
	}
}

// Named returns a MountConfig that mounts a named persistent volume.
func (mountFactory) Named(name string, opts MountOptions) MountConfig {
	return MountConfig{
		kind:               MountKindNamed,
		Named:              name,
		Readonly:           opts.Readonly,
		Noexec:             opts.Noexec,
		Nosuid:             opts.Nosuid,
		Nodev:              opts.Nodev,
		StatVirtualization: opts.StatVirtualization,
		HostPermissions:    opts.HostPermissions,
	}
}

// NamedWith returns a MountConfig that mounts a named persistent volume with
// explicit creation behavior.
func (mountFactory) NamedWith(name string, opts MountOptions, namedOpts NamedVolumeOptions) MountConfig {
	return MountConfig{
		kind:               MountKindNamed,
		Named:              name,
		NamedMode:          namedOpts.Mode,
		NamedKind:          namedOpts.Kind,
		SizeMiB:            namedOpts.SizeMiB,
		QuotaMiB:           namedOpts.QuotaMiB,
		Readonly:           opts.Readonly,
		Noexec:             opts.Noexec,
		Nosuid:             opts.Nosuid,
		Nodev:              opts.Nodev,
		StatVirtualization: opts.StatVirtualization,
		HostPermissions:    opts.HostPermissions,
	}
}

// Tmpfs returns a MountConfig that mounts an ephemeral in-memory filesystem.
func (mountFactory) Tmpfs(opts TmpfsOptions) MountConfig {
	return MountConfig{
		kind:     MountKindTmpfs,
		Tmpfs:    true,
		SizeMiB:  opts.SizeMiB,
		Readonly: opts.Readonly,
		Noexec:   opts.Noexec,
		Nosuid:   opts.Nosuid,
		Nodev:    opts.Nodev,
	}
}

// Disk mounts a host disk image at the given guest path.
func (mountFactory) Disk(hostPath string, opts DiskOptions) MountConfig {
	return MountConfig{
		kind:     MountKindDisk,
		Disk:     hostPath,
		Format:   opts.Format,
		Fstype:   opts.Fstype,
		Readonly: opts.Readonly,
		Noexec:   opts.Noexec,
		Nosuid:   opts.Nosuid,
		Nodev:    opts.Nodev,
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
	Kind     VolumeKind
	SizeMiB  uint32
	Labels   map[string]string
}

// VolumeKind describes the storage backing for a named volume.
type VolumeKind string

const (
	// VolumeKindDir creates a directory-backed named volume.
	VolumeKindDir VolumeKind = "dir"

	// VolumeKindDisk creates a raw ext4 disk-backed named volume.
	VolumeKindDisk VolumeKind = "disk"
)

// VolumeOption is a functional option for CreateVolume.
type VolumeOption func(*VolumeConfig)

// WithVolumeKind selects the storage backing for a named volume.
func WithVolumeKind(kind VolumeKind) VolumeOption {
	return func(o *VolumeConfig) { o.Kind = kind }
}

// WithVolumeSize sets disk volume capacity in MiB.
func WithVolumeSize(mebibytes uint32) VolumeOption {
	return func(o *VolumeConfig) { o.SizeMiB = mebibytes }
}

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

package microsandbox

import "time"

// SandboxConfig holds configuration for creating a sandbox.
//
// Most callers construct a sandbox via CreateSandbox with functional options;
// SandboxConfig is exported for callers that prefer to build a config value
// directly and pass it via WithConfig.
type SandboxConfig struct {
	Image     string
	MemoryMiB uint32
	CPUs      uint8
	Workdir   string
	Env       map[string]string
	Detached  bool
	Ports     map[uint16]uint16 // host port → guest port (TCP)
	Network   *NetworkConfig
	Secrets   []SecretEntry
	Patches   []PatchConfig
	Volumes   map[string]MountConfig // guest path → mount config
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

// WithDetached creates the sandbox in detached mode. The sandbox continues
// running after the Go process exits. Reattach via GetSandbox or CreateSandboxDetached.
func WithDetached() SandboxOption {
	return func(o *SandboxConfig) { o.Detached = true }
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
// Network
// ---------------------------------------------------------------------------

// NetworkConfig configures the sandbox network stack.
type NetworkConfig struct {
	// Policy is a preset name: "none", "public-only", or "allow-all".
	// Mutually exclusive with Rules.
	Policy string

	// Rules are custom ordered allow/deny rules (first match wins). When
	// set, Policy is ignored. Combine with DefaultAction.
	Rules []PolicyRule

	// DefaultAction is "allow" or "deny"; used when Rules are set and no
	// rule matches. Defaults to "allow" when empty.
	DefaultAction string

	// BlockDomains is a list of exact domain names to refuse DNS resolution for.
	BlockDomains []string

	// BlockDomainSuffixes is a list of domain suffixes (e.g. ".ads") to block.
	BlockDomainSuffixes []string

	// DNSRebindProtection enables DNS rebind attack protection (default true
	// when unset, set explicitly to disable).
	DNSRebindProtection *bool

	// TLS configures the transparent TLS interception proxy.
	TLS *TlsConfig

	// Ports publishes host TCP ports into the sandbox (host→guest).
	Ports map[uint16]uint16
}

// PolicyRule is a single firewall rule.
type PolicyRule struct {
	Action      string // "allow" or "deny"
	Direction   string // "egress" (default) or "ingress"
	Destination string // "*", "loopback", "private", "link-local", "metadata",
	// "multicast", a CIDR ("10.0.0.0/8"), a domain suffix (".internal"),
	// or a plain domain ("api.example.com").
	Protocol string // "tcp", "udp", "icmpv4", "icmpv6" — empty means any
	Port     uint16 // 0 means any port
}

// TlsConfig configures the transparent HTTPS inspection proxy.
type TlsConfig struct {
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
	return &NetworkConfig{Policy: "none"}
}

// PublicOnly returns a NetworkConfig that allows only public internet traffic
// (RFC-1918 private ranges are blocked). This is the default when no network
// configuration is supplied.
func (networkPolicyFactory) PublicOnly() *NetworkConfig {
	return &NetworkConfig{Policy: "public-only"}
}

// AllowAll returns a NetworkConfig that permits all network traffic.
func (networkPolicyFactory) AllowAll() *NetworkConfig {
	return &NetworkConfig{Policy: "allow-all"}
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
}

// SecretEnvOptions tunes Secret.Env beyond the required envVar and value.
type SecretEnvOptions struct {
	AllowHosts        []string
	AllowHostPatterns []string
	Placeholder       string
	RequireTLS        *bool
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
	}
}

// ---------------------------------------------------------------------------
// Patches
// ---------------------------------------------------------------------------

// PatchConfig represents a single rootfs modification applied before boot.
type PatchConfig struct {
	Kind    string // "text","append","mkdir","remove","symlink","copy_file","copy_dir"
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
	return PatchConfig{Kind: "text", Path: path, Content: content, Mode: opts.Mode, Replace: opts.Replace}
}

// Append appends text to an existing file.
func (patchFactory) Append(path, content string) PatchConfig {
	return PatchConfig{Kind: "append", Path: path, Content: content}
}

// Mkdir creates a directory (idempotent). Only opts.Mode is used; Replace is
// ignored.
func (patchFactory) Mkdir(path string, opts PatchOptions) PatchConfig {
	return PatchConfig{Kind: "mkdir", Path: path, Mode: opts.Mode}
}

// Remove removes a file or directory (idempotent).
func (patchFactory) Remove(path string) PatchConfig {
	return PatchConfig{Kind: "remove", Path: path}
}

// Symlink creates a symlink from link → target. Only opts.Replace is used.
func (patchFactory) Symlink(target, link string, opts PatchOptions) PatchConfig {
	return PatchConfig{Kind: "symlink", Target: target, Link: link, Replace: opts.Replace}
}

// CopyFile copies a host file into the rootfs.
func (patchFactory) CopyFile(src, dst string, opts PatchOptions) PatchConfig {
	return PatchConfig{Kind: "copy_file", Src: src, Dst: dst, Mode: opts.Mode, Replace: opts.Replace}
}

// CopyDir copies a host directory into the rootfs. Only opts.Replace is used.
func (patchFactory) CopyDir(src, dst string, opts PatchOptions) PatchConfig {
	return PatchConfig{Kind: "copy_dir", Src: src, Dst: dst, Replace: opts.Replace}
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

// ---------------------------------------------------------------------------
// Mounts
// ---------------------------------------------------------------------------

// MountConfig describes how a host path, named volume, or tmpfs is mounted
// into the sandbox at a guest path. Construct via the Mount factory:
//
//	microsandbox.Mount.Named("my-data")
//	microsandbox.Mount.Bind("/host/path")
//	microsandbox.Mount.Tmpfs()
type MountConfig struct {
	Bind     string // host path for a bind mount
	Named    string // volume name for a named volume mount
	Tmpfs    bool   // true for an in-memory tmpfs mount
	Readonly bool
	SizeMiB  uint32 // max size for tmpfs (0 = unlimited)
}

// mountFactory is the factory namespace for constructing MountConfig values.
// Invoke through the package-level Mount value.
type mountFactory struct{}

// Mount is the factory namespace for volume mount configurations.
//
//	microsandbox.WithMounts(map[string]microsandbox.MountConfig{
//	    "/data": microsandbox.Mount.Named("my-vol"),
//	    "/tmp":  microsandbox.Mount.Tmpfs(),
//	})
var Mount mountFactory

// Bind returns a MountConfig that bind-mounts a host directory into the sandbox.
func (mountFactory) Bind(hostPath string) MountConfig {
	return MountConfig{Bind: hostPath}
}

// Named returns a MountConfig that mounts a named persistent volume.
func (mountFactory) Named(name string) MountConfig {
	return MountConfig{Named: name}
}

// Tmpfs returns a MountConfig that mounts an ephemeral in-memory filesystem.
func (mountFactory) Tmpfs() MountConfig {
	return MountConfig{Tmpfs: true}
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
}

// VolumeOption is a functional option for CreateVolume.
type VolumeOption func(*VolumeConfig)

// WithVolumeQuota sets the volume's quota in MiB. Zero means unlimited.
func WithVolumeQuota(mebibytes uint32) VolumeOption {
	return func(o *VolumeConfig) { o.QuotaMiB = mebibytes }
}

package microsandbox

import "time"

// SandboxOptions holds configuration for creating a sandbox.
type SandboxOptions struct {
	Image    string
	MemoryMiB uint32
	CPUs     uint8
	Workdir  string
	Env      map[string]string
	Detached bool
	Ports    map[uint16]uint16 // host port → guest port (TCP)
	Network  *NetworkOptions
	Secrets  []SecretOptions
	Patches  []PatchOptions
}

// SandboxOption is a functional option for configuring a sandbox.
type SandboxOption func(*SandboxOptions)

// WithImage sets the container image to use (e.g. "python:3.12").
func WithImage(image string) SandboxOption {
	return func(o *SandboxOptions) { o.Image = image }
}

// WithMemory sets the memory limit in MiB.
func WithMemory(mebibytes uint32) SandboxOption {
	return func(o *SandboxOptions) { o.MemoryMiB = mebibytes }
}

// WithCPUs sets the CPU limit in whole cores.
func WithCPUs(cpus uint8) SandboxOption {
	return func(o *SandboxOptions) { o.CPUs = cpus }
}

// WithWorkdir sets the working directory inside the sandbox.
func WithWorkdir(path string) SandboxOption {
	return func(o *SandboxOptions) { o.Workdir = path }
}

// WithEnv adds environment variables to the sandbox. Called repeatedly,
// the maps merge; later keys overwrite earlier ones.
func WithEnv(env map[string]string) SandboxOption {
	return func(o *SandboxOptions) {
		if o.Env == nil {
			o.Env = make(map[string]string, len(env))
		}
		for k, v := range env {
			o.Env[k] = v
		}
	}
}

// WithDetached creates the sandbox in detached mode. The sandbox continues
// running after the Go process exits. Reattach via GetSandbox.
func WithDetached() SandboxOption {
	return func(o *SandboxOptions) { o.Detached = true }
}

// WithPorts publishes host TCP ports into the sandbox. The map key is the
// host port and the value is the guest port.
func WithPorts(ports map[uint16]uint16) SandboxOption {
	return func(o *SandboxOptions) {
		if o.Ports == nil {
			o.Ports = make(map[uint16]uint16, len(ports))
		}
		for h, g := range ports {
			o.Ports[h] = g
		}
	}
}

// WithNetwork sets the network configuration for the sandbox.
func WithNetwork(net *NetworkOptions) SandboxOption {
	return func(o *SandboxOptions) { o.Network = net }
}

// WithSecrets appends credential secrets to the sandbox. Secrets never enter
// the VM; the network proxy substitutes them at the transport layer.
func WithSecrets(secrets ...SecretOptions) SandboxOption {
	return func(o *SandboxOptions) { o.Secrets = append(o.Secrets, secrets...) }
}

// WithPatches appends rootfs patches applied before the VM boots.
// Patches are only compatible with OverlayFS rootfs (not disk images).
func WithPatches(patches ...PatchOptions) SandboxOption {
	return func(o *SandboxOptions) { o.Patches = append(o.Patches, patches...) }
}

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

// NetworkOptions configures the sandbox network stack.
type NetworkOptions struct {
	// Policy is a preset name: "none", "public-only" (default), or "allow-all".
	// Mutually exclusive with CustomPolicy.
	Policy string

	// CustomPolicy defines a fine-grained allow/deny rule set.
	// Mutually exclusive with Policy.
	CustomPolicy *CustomNetworkPolicy

	// BlockDomains is a list of exact domain names to refuse DNS resolution for.
	BlockDomains []string

	// BlockDomainSuffixes is a list of domain suffixes (e.g. ".ads") to block.
	BlockDomainSuffixes []string

	// DNSRebindProtection enables DNS rebind attack protection (default true
	// when unset, set explicitly to disable).
	DNSRebindProtection *bool

	// TLS configures the transparent TLS interception proxy.
	TLS *TLSOptions

	// Ports publishes host TCP ports into the sandbox (host→guest).
	Ports map[uint16]uint16
}

// CustomNetworkPolicy defines a default action and an ordered list of rules.
type CustomNetworkPolicy struct {
	// DefaultAction is "allow" or "deny". Defaults to "allow" when empty.
	DefaultAction string

	// Rules are evaluated in order; first match wins.
	Rules []NetworkRule
}

// NetworkRule is a single firewall rule.
type NetworkRule struct {
	Action      string // "allow" or "deny"
	Direction   string // "egress" (default) or "ingress"
	Destination string // "*", "loopback", "private", "link-local", "metadata",
	// "multicast", a CIDR ("10.0.0.0/8"), a domain suffix (".internal"),
	// or a plain domain ("api.example.com").
	Protocol string // "tcp", "udp", "icmpv4", "icmpv6" — empty means any
	Port     uint16 // 0 means any port
}

// TLSOptions configures the transparent HTTPS inspection proxy.
type TLSOptions struct {
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

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

// SecretOptions configures a single credential that the network proxy
// substitutes at the transport layer. The value never reaches the guest VM.
type SecretOptions struct {
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

// NewSecret returns a SecretOptions for an environment variable. The secret
// is allowed to be substituted only on the listed hosts.
func NewSecret(envVar, value string, allowHosts ...string) SecretOptions {
	return SecretOptions{EnvVar: envVar, Value: value, AllowHosts: allowHosts}
}

// ---------------------------------------------------------------------------
// Patches
// ---------------------------------------------------------------------------

// PatchOptions represents a single rootfs modification applied before boot.
type PatchOptions struct {
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

func ptrUint32(v uint32) *uint32 { return &v }

// PatchText writes text to a file, creating or replacing it.
func PatchText(path, content string, mode *uint32, replace bool) PatchOptions {
	return PatchOptions{Kind: "text", Path: path, Content: content, Mode: mode, Replace: replace}
}

// PatchAppend appends text to an existing file.
func PatchAppend(path, content string) PatchOptions {
	return PatchOptions{Kind: "append", Path: path, Content: content}
}

// PatchMkdir creates a directory (idempotent).
func PatchMkdir(path string, mode *uint32) PatchOptions {
	return PatchOptions{Kind: "mkdir", Path: path, Mode: mode}
}

// PatchRemove removes a file or directory (idempotent).
func PatchRemove(path string) PatchOptions {
	return PatchOptions{Kind: "remove", Path: path}
}

// PatchSymlink creates a symlink from link → target.
func PatchSymlink(target, link string, replace bool) PatchOptions {
	return PatchOptions{Kind: "symlink", Target: target, Link: link, Replace: replace}
}

// PatchCopyFile copies a host file into the rootfs.
func PatchCopyFile(src, dst string, mode *uint32, replace bool) PatchOptions {
	return PatchOptions{Kind: "copy_file", Src: src, Dst: dst, Mode: mode, Replace: replace}
}

// PatchCopyDir copies a host directory into the rootfs.
func PatchCopyDir(src, dst string, replace bool) PatchOptions {
	return PatchOptions{Kind: "copy_dir", Src: src, Dst: dst, Replace: replace}
}

// ---------------------------------------------------------------------------
// Exec options
// ---------------------------------------------------------------------------

// ExecOptions configures a single Exec call.
type ExecOptions struct {
	Cwd     string
	Timeout time.Duration
}

// ExecOption is a functional option for Exec.
type ExecOption func(*ExecOptions)

// WithExecCwd sets the working directory for a single command.
func WithExecCwd(path string) ExecOption {
	return func(o *ExecOptions) { o.Cwd = path }
}

// WithExecTimeout sets a per-command timeout. When exceeded, the guest
// terminates the process and the call returns an error with
// Kind==ErrExecTimeout.
func WithExecTimeout(d time.Duration) ExecOption {
	return func(o *ExecOptions) { o.Timeout = d }
}

// ---------------------------------------------------------------------------
// Volume options
// ---------------------------------------------------------------------------

// VolumeOptions holds configuration for a named volume.
type VolumeOptions struct {
	QuotaMiB uint32
}

// VolumeOption is a functional option for NewVolume.
type VolumeOption func(*VolumeOptions)

// WithVolumeQuota sets the volume's quota in MiB. Zero means unlimited.
func WithVolumeQuota(mebibytes uint32) VolumeOption {
	return func(o *VolumeOptions) { o.QuotaMiB = mebibytes }
}

package microsandbox

import (
	"time"
)

// =============================================================================
// Sandbox Options
// =============================================================================

// SandboxOptions holds configuration for creating a sandbox.
type SandboxOptions struct {
	Image     string
	MemoryMiB int
	CPUs      int
	Env       map[string]string
	Workdir   string
	Volumes   []VolumeMount
	Network   *NetworkPolicy
	Secrets   []Secret
	Patches   []Patch
	Ports     []PortMapping
	Scripts   map[string]string
	Detached  bool
}

// SandboxOption is a functional option for configuring a sandbox.
type SandboxOption func(*SandboxOptions)

// WithImage sets the container image to use.
// Supports OCI images ("python:3.12"), local rootfs ("./my-rootfs"),
// and disk images via WithDiskImage.
func WithImage(image string) SandboxOption {
	return func(o *SandboxOptions) {
		o.Image = image
	}
}

// WithMemory sets the memory limit in MiB.
func WithMemory(mebibytes int) SandboxOption {
	return func(o *SandboxOptions) {
		o.MemoryMiB = mebibytes
	}
}

// WithCPUs sets the CPU limit (number of cores).
func WithCPUs(cpus int) SandboxOption {
	return func(o *SandboxOptions) {
		o.CPUs = cpus
	}
}

// WithEnv sets environment variables for the sandbox.
func WithEnv(env map[string]string) SandboxOption {
	return func(o *SandboxOptions) {
		if o.Env == nil {
			o.Env = make(map[string]string)
		}
		for k, v := range env {
			o.Env[k] = v
		}
	}
}

// WithWorkdir sets the working directory inside the sandbox.
func WithWorkdir(path string) SandboxOption {
	return func(o *SandboxOptions) {
		o.Workdir = path
	}
}

// WithVolume mounts a volume in the sandbox.
func WithVolume(guestPath string, mount VolumeMount) SandboxOption {
	return func(o *SandboxOptions) {
		mount.GuestPath = guestPath
		o.Volumes = append(o.Volumes, mount)
	}
}

// WithNetwork sets the network policy for the sandbox.
func WithNetwork(policy NetworkPolicy) SandboxOption {
	return func(o *SandboxOptions) {
		o.Network = &policy
	}
}

// WithSecret injects a secret into the sandbox.
func WithSecret(secret Secret) SandboxOption {
	return func(o *SandboxOptions) {
		o.Secrets = append(o.Secrets, secret)
	}
}

// WithPatch applies a pre-boot filesystem modification.
func WithPatch(patch Patch) SandboxOption {
	return func(o *SandboxOptions) {
		o.Patches = append(o.Patches, patch)
	}
}

// WithPort publishes a guest port to the host.
// hostPort is the port on the host, guestPort is the port inside the sandbox.
func WithPort(hostPort, guestPort int) SandboxOption {
	return func(o *SandboxOptions) {
		o.Ports = append(o.Ports, PortMapping{
			HostPort:  hostPort,
			GuestPort: guestPort,
		})
	}
}

// WithScript adds a script that can be executed inside the sandbox.
func WithScript(name, content string) SandboxOption {
	return func(o *SandboxOptions) {
		if o.Scripts == nil {
			o.Scripts = make(map[string]string)
		}
		o.Scripts[name] = content
	}
}

// WithDetached creates the sandbox in detached mode (survives parent process).
func WithDetached() SandboxOption {
	return func(o *SandboxOptions) {
		o.Detached = true
	}
}

// =============================================================================
// Exec Options
// =============================================================================

// ExecOptions holds configuration for executing commands.
type ExecOptions struct {
	Cwd     string
	Env     map[string]string
	Timeout time.Duration
}

// ExecOption is a functional option for configuring exec.
type ExecOption func(*ExecOptions)

// WithExecCwd sets the working directory for the command.
func WithExecCwd(path string) ExecOption {
	return func(o *ExecOptions) {
		o.Cwd = path
	}
}

// WithExecEnv sets environment variables for the command.
func WithExecEnv(env map[string]string) ExecOption {
	return func(o *ExecOptions) {
		if o.Env == nil {
			o.Env = make(map[string]string)
		}
		for k, v := range env {
			o.Env[k] = v
		}
	}
}

// WithExecTimeout sets a timeout for the command execution.
func WithExecTimeout(duration time.Duration) ExecOption {
	return func(o *ExecOptions) {
		o.Timeout = duration
	}
}

// =============================================================================
// Volume Options
// =============================================================================

// VolumeOptions holds configuration for volumes.
type VolumeOptions struct {
	QuotaMiB int
	ReadOnly bool
}

// VolumeOption is a functional option for configuring volumes.
type VolumeOption func(*VolumeOptions)

// WithVolumeQuota sets the quota for a named volume in MiB.
func WithVolumeQuota(mebibytes int) VolumeOption {
	return func(o *VolumeOptions) {
		o.QuotaMiB = mebibytes
	}
}

// Readonly marks a volume mount as read-only.
func Readonly() VolumeOption {
	return func(o *VolumeOptions) {
		o.ReadOnly = true
	}
}

// =============================================================================
// Network Policy Options
// =============================================================================

// NetworkPolicyType defines the network access level.
type NetworkPolicyType string

const (
	NetworkPublicOnly NetworkPolicyType = "public_only"
	NetworkAllowAll   NetworkPolicyType = "allow_all"
	NetworkNoNetwork  NetworkPolicyType = "no_network"
	NetworkAllowlist  NetworkPolicyType = "allowlist"
)

// NetworkPolicy controls network access for a sandbox.
type NetworkPolicy struct {
	Type          NetworkPolicyType
	BlockDomains  []string
	BlockSuffixes []string
	AllowHosts    []string
}

// PublicOnly allows outbound connections to public IPs only (blocks private IPs).
// This is the default policy.
func PublicOnly() NetworkPolicy {
	return NetworkPolicy{Type: NetworkPublicOnly}
}

// AllowAll permits all network access.
func AllowAll() NetworkPolicy {
	return NetworkPolicy{Type: NetworkAllowAll}
}

// NoNetwork fully airgaps the sandbox.
func NoNetwork() NetworkPolicy {
	return NetworkPolicy{Type: NetworkNoNetwork}
}

// Allowlist permits only specified hosts.
func Allowlist(hosts ...string) NetworkPolicy {
	return NetworkPolicy{
		Type:       NetworkAllowlist,
		AllowHosts: hosts,
	}
}

// BlockDomain adds a specific domain to block.
func (p NetworkPolicy) BlockDomain(domain string) NetworkPolicy {
	p.BlockDomains = append(p.BlockDomains, domain)
	return p
}

// BlockDomainSuffix adds a domain suffix to block (e.g., ".evil.com").
func (p NetworkPolicy) BlockDomainSuffix(suffix string) NetworkPolicy {
	p.BlockSuffixes = append(p.BlockSuffixes, suffix)
	return p
}

// =============================================================================
// Secret Options
// =============================================================================

// SecretType defines how a secret is injected.
type SecretType string

const (
	SecretTypeEnv SecretType = "env"
)

// Secret represents a host-side credential injection.
type Secret struct {
	Type       SecretType
	Name       string
	Value      string
	AllowHosts []string
}

// EnvSecret creates an environment variable secret.
// The real value never enters the VM — it's substituted at the network layer.
func EnvSecret(name string, opts ...SecretOption) Secret {
	s := Secret{
		Type: SecretTypeEnv,
		Name: name,
	}
	for _, opt := range opts {
		opt(&s)
	}
	return s
}

// SecretOption is a functional option for configuring secrets.
type SecretOption func(*Secret)

// SecretValue sets the secret value.
func SecretValue(value string) SecretOption {
	return func(s *Secret) {
		s.Value = value
	}
}

// AllowHosts restricts which hosts can receive this secret.
func AllowHosts(hosts ...string) SecretOption {
	return func(s *Secret) {
		s.AllowHosts = hosts
	}
}

// =============================================================================
// Patch Options
// =============================================================================

// PatchType defines the type of filesystem modification.
type PatchType string

const (
	PatchTypeText   PatchType = "text"
	PatchTypeMkdir  PatchType = "mkdir"
	PatchTypeAppend PatchType = "append"
)

// Patch represents a pre-boot filesystem modification.
type Patch struct {
	Type    PatchType
	Path    string
	Content string
	Mode    uint32
}

// TextPatch writes text content to a file.
func TextPatch(path, content string) Patch {
	return Patch{
		Type:    PatchTypeText,
		Path:    path,
		Content: content,
	}
}

// MkdirPatch creates a directory.
func MkdirPatch(path string, mode uint32) Patch {
	return Patch{
		Type: PatchTypeMkdir,
		Path: path,
		Mode: mode,
	}
}

// AppendPatch appends content to a file.
func AppendPatch(path, content string) Patch {
	return Patch{
		Type:    PatchTypeAppend,
		Path:    path,
		Content: content,
	}
}

// =============================================================================
// Volume Mount Types
// =============================================================================

// VolumeMountType defines the type of volume mount.
type VolumeMountType string

const (
	VolumeMountNamed VolumeMountType = "named"
	VolumeMountBind  VolumeMountType = "bind"
	VolumeMountTmpfs VolumeMountType = "tmpfs"
)

// VolumeMount represents a volume mounted in a sandbox.
type VolumeMount struct {
	Type      VolumeMountType
	GuestPath string
	Name      string // For named volumes
	HostPath  string // For bind mounts
	SizeMiB   int    // For tmpfs
	ReadOnly  bool
}

// NamedVolume mounts a named volume.
func NamedVolume(name string, opts ...VolumeOption) VolumeMount {
	var options VolumeOptions
	for _, opt := range opts {
		opt(&options)
	}
	return VolumeMount{
		Type:     VolumeMountNamed,
		Name:     name,
		ReadOnly: options.ReadOnly,
	}
}

// BindVolume mounts a host path.
func BindVolume(hostPath string, opts ...VolumeOption) VolumeMount {
	var options VolumeOptions
	for _, opt := range opts {
		opt(&options)
	}
	return VolumeMount{
		Type:     VolumeMountBind,
		HostPath: hostPath,
		ReadOnly: options.ReadOnly,
	}
}

// TmpfsVolume creates a tmpfs mount with the specified size in MiB.
func TmpfsVolume(sizeMiB int, opts ...VolumeOption) VolumeMount {
	var options VolumeOptions
	for _, opt := range opts {
		opt(&options)
	}
	return VolumeMount{
		Type:     VolumeMountTmpfs,
		SizeMiB:  sizeMiB,
		ReadOnly: options.ReadOnly,
	}
}

// =============================================================================
// Port Mapping
// =============================================================================

// PortMapping represents a port publish from guest to host.
type PortMapping struct {
	HostPort  int
	GuestPort int
}

package microsandbox

import "time"

// SandboxOptions holds configuration for creating a sandbox. Only the
// fields mirrored by the Rust FFI are exposed; advanced configuration
// (volumes, network policy, secrets, patches, ports, scripts, detached
// mode) is deliberately not yet plumbed to avoid silently dropping inputs.
type SandboxOptions struct {
	Image     string
	MemoryMiB uint32
	CPUs      uint8
	Workdir   string
	Env       map[string]string
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

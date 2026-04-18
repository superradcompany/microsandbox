package microsandbox

import (
	"reflect"
	"testing"
	"time"
)

func TestWithImage(t *testing.T) {
	o := SandboxOptions{}
	WithImage("python:3.12")(&o)
	if o.Image != "python:3.12" {
		t.Errorf("got %q, want %q", o.Image, "python:3.12")
	}
}

func TestWithMemory(t *testing.T) {
	o := SandboxOptions{}
	WithMemory(512)(&o)
	if o.MemoryMiB != 512 {
		t.Errorf("got %d, want 512", o.MemoryMiB)
	}
}

func TestWithCPUs(t *testing.T) {
	o := SandboxOptions{}
	WithCPUs(2)(&o)
	if o.CPUs != 2 {
		t.Errorf("got %d, want 2", o.CPUs)
	}
}

func TestWithWorkdir(t *testing.T) {
	o := SandboxOptions{}
	WithWorkdir("/app")(&o)
	if o.Workdir != "/app" {
		t.Errorf("got %q, want %q", o.Workdir, "/app")
	}
}

func TestWithEnvMerge(t *testing.T) {
	o := SandboxOptions{}
	WithEnv(map[string]string{"A": "1", "B": "2"})(&o)
	WithEnv(map[string]string{"B": "overwritten", "C": "3"})(&o)

	want := map[string]string{"A": "1", "B": "overwritten", "C": "3"}
	if !reflect.DeepEqual(o.Env, want) {
		t.Errorf("got %v, want %v", o.Env, want)
	}
}

func TestWithEnvNilInitial(t *testing.T) {
	o := SandboxOptions{}
	if o.Env != nil {
		t.Fatal("Env should start nil")
	}
	WithEnv(map[string]string{"K": "V"})(&o)
	if o.Env["K"] != "V" {
		t.Error("WithEnv should initialise map when Env is nil")
	}
}

func TestWithExecCwd(t *testing.T) {
	o := ExecOptions{}
	WithExecCwd("/tmp")(&o)
	if o.Cwd != "/tmp" {
		t.Errorf("got %q, want %q", o.Cwd, "/tmp")
	}
}

func TestWithExecTimeout(t *testing.T) {
	o := ExecOptions{}
	WithExecTimeout(30 * time.Second)(&o)
	if o.Timeout != 30*time.Second {
		t.Errorf("got %v, want 30s", o.Timeout)
	}
}

func TestWithVolumeQuota(t *testing.T) {
	o := VolumeOptions{}
	WithVolumeQuota(1024)(&o)
	if o.QuotaMiB != 1024 {
		t.Errorf("got %d, want 1024", o.QuotaMiB)
	}
}

// SandboxOptions options compose correctly when applied in sequence.
func TestSandboxOptionsCompose(t *testing.T) {
	o := SandboxOptions{}
	opts := []SandboxOption{
		WithImage("alpine:3.19"),
		WithMemory(256),
		WithCPUs(1),
		WithWorkdir("/home"),
		WithEnv(map[string]string{"DEBUG": "true"}),
	}
	for _, opt := range opts {
		opt(&o)
	}
	if o.Image != "alpine:3.19" {
		t.Errorf("Image: got %q", o.Image)
	}
	if o.MemoryMiB != 256 {
		t.Errorf("MemoryMiB: got %d", o.MemoryMiB)
	}
	if o.CPUs != 1 {
		t.Errorf("CPUs: got %d", o.CPUs)
	}
	if o.Workdir != "/home" {
		t.Errorf("Workdir: got %q", o.Workdir)
	}
	if o.Env["DEBUG"] != "true" {
		t.Errorf("Env[DEBUG]: got %q", o.Env["DEBUG"])
	}
}

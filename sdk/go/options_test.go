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

func TestWithDetached(t *testing.T) {
	o := SandboxOptions{}
	if o.Detached {
		t.Fatal("Detached should start false")
	}
	WithDetached()(&o)
	if !o.Detached {
		t.Error("WithDetached should set Detached to true")
	}
}

func TestWithPortsMerge(t *testing.T) {
	o := SandboxOptions{}
	WithPorts(map[uint16]uint16{8080: 80})(&o)
	WithPorts(map[uint16]uint16{9090: 90})(&o)
	if o.Ports[8080] != 80 {
		t.Errorf("Ports[8080]: got %d, want 80", o.Ports[8080])
	}
	if o.Ports[9090] != 90 {
		t.Errorf("Ports[9090]: got %d, want 90", o.Ports[9090])
	}
}

func TestWithPortsNilInitial(t *testing.T) {
	o := SandboxOptions{}
	if o.Ports != nil {
		t.Fatal("Ports should start nil")
	}
	WithPorts(map[uint16]uint16{3000: 3000})(&o)
	if o.Ports[3000] != 3000 {
		t.Error("WithPorts should initialise map when Ports is nil")
	}
}

func TestWithNetwork(t *testing.T) {
	o := SandboxOptions{}
	net := &NetworkOptions{Policy: "public-only"}
	WithNetwork(net)(&o)
	if o.Network != net {
		t.Error("WithNetwork should set the Network pointer")
	}
}

func TestWithNetworkNilClearsPolicy(t *testing.T) {
	o := SandboxOptions{Network: &NetworkOptions{Policy: "allow-all"}}
	WithNetwork(nil)(&o)
	if o.Network != nil {
		t.Error("WithNetwork(nil) should clear Network")
	}
}

func TestWithSecrets(t *testing.T) {
	o := SandboxOptions{}
	s1 := NewSecret("API_KEY", "sk-secret", "api.example.com")
	s2 := NewSecret("DB_PASS", "hunter2")
	WithSecrets(s1)(&o)
	WithSecrets(s2)(&o)
	if len(o.Secrets) != 2 {
		t.Fatalf("want 2 secrets, got %d", len(o.Secrets))
	}
	if o.Secrets[0].EnvVar != "API_KEY" {
		t.Errorf("Secrets[0].EnvVar: got %q", o.Secrets[0].EnvVar)
	}
	if o.Secrets[0].AllowHosts[0] != "api.example.com" {
		t.Errorf("Secrets[0].AllowHosts[0]: got %q", o.Secrets[0].AllowHosts[0])
	}
	if o.Secrets[1].EnvVar != "DB_PASS" {
		t.Errorf("Secrets[1].EnvVar: got %q", o.Secrets[1].EnvVar)
	}
}

func TestNewSecret(t *testing.T) {
	s := NewSecret("TOK", "val", "a.com", "b.com")
	if s.EnvVar != "TOK" {
		t.Errorf("EnvVar: got %q", s.EnvVar)
	}
	if s.Value != "val" {
		t.Errorf("Value: got %q", s.Value)
	}
	if len(s.AllowHosts) != 2 || s.AllowHosts[0] != "a.com" {
		t.Errorf("AllowHosts: got %v", s.AllowHosts)
	}
}

func TestWithPatches(t *testing.T) {
	o := SandboxOptions{}
	p1 := PatchText("/etc/foo", "bar\n", nil, false)
	p2 := PatchMkdir("/var/run/app", nil)
	WithPatches(p1, p2)(&o)
	if len(o.Patches) != 2 {
		t.Fatalf("want 2 patches, got %d", len(o.Patches))
	}
	if o.Patches[0].Kind != "text" {
		t.Errorf("Patches[0].Kind: got %q", o.Patches[0].Kind)
	}
	if o.Patches[1].Kind != "mkdir" {
		t.Errorf("Patches[1].Kind: got %q", o.Patches[1].Kind)
	}
}

func TestPatchConstructors(t *testing.T) {
	mode := uint32(0o644)
	cases := []struct {
		patch PatchOptions
		kind  string
	}{
		{PatchText("/a", "x", &mode, true), "text"},
		{PatchAppend("/b", "y"), "append"},
		{PatchMkdir("/c", nil), "mkdir"},
		{PatchRemove("/d"), "remove"},
		{PatchSymlink("/target", "/link", false), "symlink"},
		{PatchCopyFile("./src", "/dst", &mode, false), "copy_file"},
		{PatchCopyDir("./src", "/dst", true), "copy_dir"},
	}
	for _, c := range cases {
		if c.patch.Kind != c.kind {
			t.Errorf("Kind: got %q, want %q", c.patch.Kind, c.kind)
		}
	}
}

func TestPatchTextFields(t *testing.T) {
	mode := uint32(0o755)
	p := PatchText("/etc/conf", "data\n", &mode, true)
	if p.Path != "/etc/conf" {
		t.Errorf("Path: got %q", p.Path)
	}
	if p.Content != "data\n" {
		t.Errorf("Content: got %q", p.Content)
	}
	if p.Mode == nil || *p.Mode != 0o755 {
		t.Errorf("Mode: got %v", p.Mode)
	}
	if !p.Replace {
		t.Error("Replace should be true")
	}
}

func TestPatchSymlinkFields(t *testing.T) {
	p := PatchSymlink("/usr/bin/python3", "/usr/bin/python", true)
	if p.Target != "/usr/bin/python3" {
		t.Errorf("Target: got %q", p.Target)
	}
	if p.Link != "/usr/bin/python" {
		t.Errorf("Link: got %q", p.Link)
	}
}

func TestPatchCopyFileFields(t *testing.T) {
	p := PatchCopyFile("./cert.pem", "/etc/ssl/cert.pem", nil, false)
	if p.Src != "./cert.pem" {
		t.Errorf("Src: got %q", p.Src)
	}
	if p.Dst != "/etc/ssl/cert.pem" {
		t.Errorf("Dst: got %q", p.Dst)
	}
	if p.Mode != nil {
		t.Error("Mode should be nil when not provided")
	}
}

func TestNetworkOptionsPreset(t *testing.T) {
	for _, preset := range []string{"none", "public-only", "allow-all"} {
		n := &NetworkOptions{Policy: preset}
		o := SandboxOptions{}
		WithNetwork(n)(&o)
		if o.Network.Policy != preset {
			t.Errorf("Policy: got %q, want %q", o.Network.Policy, preset)
		}
	}
}

func TestNetworkOptionsDNS(t *testing.T) {
	n := &NetworkOptions{
		BlockDomains:        []string{"evil.com"},
		BlockDomainSuffixes: []string{".ads"},
	}
	if n.BlockDomains[0] != "evil.com" {
		t.Errorf("BlockDomains[0]: got %q", n.BlockDomains[0])
	}
	if n.BlockDomainSuffixes[0] != ".ads" {
		t.Errorf("BlockDomainSuffixes[0]: got %q", n.BlockDomainSuffixes[0])
	}
}

func TestNetworkOptionsCustomPolicy(t *testing.T) {
	n := &NetworkOptions{
		CustomPolicy: &CustomNetworkPolicy{
			DefaultAction: "deny",
			Rules: []NetworkRule{
				{Action: "allow", Direction: "egress", Destination: "api.example.com", Protocol: "tcp", Port: 443},
			},
		},
	}
	if n.CustomPolicy.DefaultAction != "deny" {
		t.Errorf("DefaultAction: got %q", n.CustomPolicy.DefaultAction)
	}
	r := n.CustomPolicy.Rules[0]
	if r.Action != "allow" || r.Destination != "api.example.com" || r.Port != 443 {
		t.Errorf("Rule: got %+v", r)
	}
}

func TestTLSOptionsFields(t *testing.T) {
	boolTrue := true
	tls := &TLSOptions{
		Bypass:           []string{"*.internal"},
		VerifyUpstream:   &boolTrue,
		InterceptedPorts: []uint16{443, 8443},
		BlockQUIC:        &boolTrue,
		CACert:           "/ca.pem",
		CAKey:            "/ca.key",
	}
	if tls.Bypass[0] != "*.internal" {
		t.Errorf("Bypass[0]: got %q", tls.Bypass[0])
	}
	if tls.VerifyUpstream == nil || !*tls.VerifyUpstream {
		t.Error("VerifyUpstream should be true")
	}
	if len(tls.InterceptedPorts) != 2 {
		t.Errorf("InterceptedPorts: got %v", tls.InterceptedPorts)
	}
	if tls.CACert != "/ca.pem" {
		t.Errorf("CACert: got %q", tls.CACert)
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

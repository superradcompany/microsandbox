package microsandbox

import (
	"reflect"
	"testing"
	"time"
)

func TestWithImage(t *testing.T) {
	o := SandboxConfig{}
	WithImage("python:3.12")(&o)
	if o.Image != "python:3.12" {
		t.Errorf("got %q, want %q", o.Image, "python:3.12")
	}
}

func TestWithMemory(t *testing.T) {
	o := SandboxConfig{}
	WithMemory(512)(&o)
	if o.MemoryMiB != 512 {
		t.Errorf("got %d, want 512", o.MemoryMiB)
	}
}

func TestWithCPUs(t *testing.T) {
	o := SandboxConfig{}
	WithCPUs(2)(&o)
	if o.CPUs != 2 {
		t.Errorf("got %d, want 2", o.CPUs)
	}
}

func TestWithWorkdir(t *testing.T) {
	o := SandboxConfig{}
	WithWorkdir("/app")(&o)
	if o.Workdir != "/app" {
		t.Errorf("got %q, want %q", o.Workdir, "/app")
	}
}

func TestWithEnvMerge(t *testing.T) {
	o := SandboxConfig{}
	WithEnv(map[string]string{"A": "1", "B": "2"})(&o)
	WithEnv(map[string]string{"B": "overwritten", "C": "3"})(&o)

	want := map[string]string{"A": "1", "B": "overwritten", "C": "3"}
	if !reflect.DeepEqual(o.Env, want) {
		t.Errorf("got %v, want %v", o.Env, want)
	}
}

func TestWithEnvNilInitial(t *testing.T) {
	o := SandboxConfig{}
	if o.Env != nil {
		t.Fatal("Env should start nil")
	}
	WithEnv(map[string]string{"K": "V"})(&o)
	if o.Env["K"] != "V" {
		t.Error("WithEnv should initialise map when Env is nil")
	}
}

func TestWithExecCwd(t *testing.T) {
	o := ExecConfig{}
	WithExecCwd("/tmp")(&o)
	if o.Cwd != "/tmp" {
		t.Errorf("got %q, want %q", o.Cwd, "/tmp")
	}
}

func TestWithExecTimeout(t *testing.T) {
	o := ExecConfig{}
	WithExecTimeout(30 * time.Second)(&o)
	if o.Timeout != 30*time.Second {
		t.Errorf("got %v, want 30s", o.Timeout)
	}
}

func TestWithVolumeQuota(t *testing.T) {
	o := VolumeConfig{}
	WithVolumeQuota(1024)(&o)
	if o.QuotaMiB != 1024 {
		t.Errorf("got %d, want 1024", o.QuotaMiB)
	}
}

func TestWithDetached(t *testing.T) {
	o := SandboxConfig{}
	if o.Detached {
		t.Fatal("Detached should start false")
	}
	WithDetached()(&o)
	if !o.Detached {
		t.Error("WithDetached should set Detached to true")
	}
}

func TestWithPortsMerge(t *testing.T) {
	o := SandboxConfig{}
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
	o := SandboxConfig{}
	if o.Ports != nil {
		t.Fatal("Ports should start nil")
	}
	WithPorts(map[uint16]uint16{3000: 3000})(&o)
	if o.Ports[3000] != 3000 {
		t.Error("WithPorts should initialise map when Ports is nil")
	}
}

func TestWithNetwork(t *testing.T) {
	o := SandboxConfig{}
	net := &NetworkConfig{Policy: "public-only"}
	WithNetwork(net)(&o)
	if o.Network != net {
		t.Error("WithNetwork should set the Network pointer")
	}
}

func TestWithNetworkNilClearsPolicy(t *testing.T) {
	o := SandboxConfig{Network: &NetworkConfig{Policy: "allow-all"}}
	WithNetwork(nil)(&o)
	if o.Network != nil {
		t.Error("WithNetwork(nil) should clear Network")
	}
}

func TestNetworkPolicyFactory(t *testing.T) {
	cases := []struct {
		got  *NetworkConfig
		want string
	}{
		{NetworkPolicy.None(), "none"},
		{NetworkPolicy.PublicOnly(), "public-only"},
		{NetworkPolicy.AllowAll(), "allow-all"},
	}
	for _, c := range cases {
		if c.got.Policy != c.want {
			t.Errorf("Policy: got %q, want %q", c.got.Policy, c.want)
		}
	}
}

func TestWithSecrets(t *testing.T) {
	o := SandboxConfig{}
	s1 := Secret.Env("API_KEY", "sk-secret", SecretEnvOptions{AllowHosts: []string{"api.example.com"}})
	s2 := Secret.Env("DB_PASS", "hunter2", SecretEnvOptions{})
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

func TestSecretEnvFactory(t *testing.T) {
	rt := true
	s := Secret.Env("TOK", "val", SecretEnvOptions{
		AllowHosts:        []string{"a.com", "b.com"},
		AllowHostPatterns: []string{"*.corp"},
		Placeholder:       "$TOK",
		RequireTLS:        &rt,
	})
	if s.EnvVar != "TOK" || s.Value != "val" {
		t.Errorf("EnvVar/Value: got %q/%q", s.EnvVar, s.Value)
	}
	if len(s.AllowHosts) != 2 || s.AllowHosts[0] != "a.com" {
		t.Errorf("AllowHosts: got %v", s.AllowHosts)
	}
	if len(s.AllowHostPatterns) != 1 || s.AllowHostPatterns[0] != "*.corp" {
		t.Errorf("AllowHostPatterns: got %v", s.AllowHostPatterns)
	}
	if s.Placeholder != "$TOK" {
		t.Errorf("Placeholder: got %q", s.Placeholder)
	}
	if s.RequireTLS == nil || !*s.RequireTLS {
		t.Error("RequireTLS should be true")
	}
}

func TestWithPatches(t *testing.T) {
	o := SandboxConfig{}
	p1 := Patch.Text("/etc/foo", "bar\n", PatchOptions{})
	p2 := Patch.Mkdir("/var/run/app", PatchOptions{})
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

func TestPatchFactoryKinds(t *testing.T) {
	mode := uint32(0o644)
	cases := []struct {
		patch PatchConfig
		kind  string
	}{
		{Patch.Text("/a", "x", PatchOptions{Mode: &mode, Replace: true}), "text"},
		{Patch.Append("/b", "y"), "append"},
		{Patch.Mkdir("/c", PatchOptions{}), "mkdir"},
		{Patch.Remove("/d"), "remove"},
		{Patch.Symlink("/target", "/link", PatchOptions{}), "symlink"},
		{Patch.CopyFile("./src", "/dst", PatchOptions{Mode: &mode}), "copy_file"},
		{Patch.CopyDir("./src", "/dst", PatchOptions{Replace: true}), "copy_dir"},
	}
	for _, c := range cases {
		if c.patch.Kind != c.kind {
			t.Errorf("Kind: got %q, want %q", c.patch.Kind, c.kind)
		}
	}
}

func TestPatchTextFields(t *testing.T) {
	mode := uint32(0o755)
	p := Patch.Text("/etc/conf", "data\n", PatchOptions{Mode: &mode, Replace: true})
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
	p := Patch.Symlink("/usr/bin/python3", "/usr/bin/python", PatchOptions{Replace: true})
	if p.Target != "/usr/bin/python3" {
		t.Errorf("Target: got %q", p.Target)
	}
	if p.Link != "/usr/bin/python" {
		t.Errorf("Link: got %q", p.Link)
	}
	if !p.Replace {
		t.Error("Replace should be true")
	}
}

func TestPatchCopyFileFields(t *testing.T) {
	p := Patch.CopyFile("./cert.pem", "/etc/ssl/cert.pem", PatchOptions{})
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

func TestNetworkConfigPreset(t *testing.T) {
	for _, preset := range []string{"none", "public-only", "allow-all"} {
		n := &NetworkConfig{Policy: preset}
		o := SandboxConfig{}
		WithNetwork(n)(&o)
		if o.Network.Policy != preset {
			t.Errorf("Policy: got %q, want %q", o.Network.Policy, preset)
		}
	}
}

func TestNetworkConfigDNS(t *testing.T) {
	n := &NetworkConfig{
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

func TestNetworkConfigCustomRules(t *testing.T) {
	n := &NetworkConfig{
		DefaultAction: "deny",
		Rules: []PolicyRule{
			{Action: "allow", Direction: "egress", Destination: "api.example.com", Protocol: "tcp", Port: 443},
		},
	}
	if n.DefaultAction != "deny" {
		t.Errorf("DefaultAction: got %q", n.DefaultAction)
	}
	r := n.Rules[0]
	if r.Action != "allow" || r.Destination != "api.example.com" || r.Port != 443 {
		t.Errorf("Rule: got %+v", r)
	}
}

func TestTlsConfigFields(t *testing.T) {
	boolTrue := true
	tls := &TlsConfig{
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

// SandboxConfig options compose correctly when applied in sequence.
func TestSandboxConfigCompose(t *testing.T) {
	o := SandboxConfig{}
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

package microsandbox

import (
	"encoding/json"
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

func TestWithOCIUpperSize(t *testing.T) {
	o := SandboxConfig{}
	WithOCIUpperSize(8192)(&o)
	if o.OCIUpperSizeMiB != 8192 {
		t.Errorf("OCIUpperSizeMiB = %d, want 8192", o.OCIUpperSizeMiB)
	}
	if !o.ociUpperSizeSet {
		t.Error("ociUpperSizeSet = false, want true")
	}
}

func TestWithOCIUpperSizeZeroIsExplicit(t *testing.T) {
	o := SandboxConfig{}
	WithOCIUpperSize(0)(&o)
	if o.OCIUpperSizeMiB != 0 {
		t.Errorf("OCIUpperSizeMiB = %d, want 0", o.OCIUpperSizeMiB)
	}
	if !o.ociUpperSizeSet {
		t.Error("ociUpperSizeSet = false, want true")
	}
}

func TestWithImageDisk(t *testing.T) {
	o := SandboxConfig{}
	WithImageDisk("./alpine.raw", "ext4")(&o)
	if o.Image != "./alpine.raw" {
		t.Errorf("Image = %q, want %q", o.Image, "./alpine.raw")
	}
	if o.ImageFstype != "ext4" {
		t.Errorf("ImageFstype = %q, want %q", o.ImageFstype, "ext4")
	}
}

func TestWithSnapshot(t *testing.T) {
	o := SandboxConfig{}
	WithSnapshot("after-pip-install")(&o)
	if o.Snapshot != "after-pip-install" {
		t.Errorf("got %q, want %q", o.Snapshot, "after-pip-install")
	}
}

func TestWithMemory(t *testing.T) {
	o := SandboxConfig{}
	WithMemory(512)(&o)
	if o.MemoryMiB != 512 {
		t.Errorf("got %d, want 512", o.MemoryMiB)
	}
}

func TestWithMaxMemory(t *testing.T) {
	o := SandboxConfig{}
	WithMaxMemory(4096)(&o)
	if o.MaxMemoryMiB != 4096 {
		t.Errorf("got %d, want 4096", o.MaxMemoryMiB)
	}
}

func TestWithCPUs(t *testing.T) {
	o := SandboxConfig{}
	WithCPUs(2)(&o)
	if o.CPUs != 2 {
		t.Errorf("got %d, want 2", o.CPUs)
	}
}

func TestWithMaxCPUs(t *testing.T) {
	o := SandboxConfig{}
	WithMaxCPUs(8)(&o)
	if o.MaxCPUs != 8 {
		t.Errorf("got %d, want 8", o.MaxCPUs)
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

func TestWithReplace(t *testing.T) {
	o := SandboxConfig{}
	WithReplace()(&o)
	if !o.Replace {
		t.Error("WithReplace should set Replace to true")
	}
	if o.ReplaceWithTimeout != nil {
		t.Errorf("WithReplace should leave ReplaceWithTimeout nil, got %v", *o.ReplaceWithTimeout)
	}
}

func TestWithReplaceWithTimeout(t *testing.T) {
	cases := []struct {
		name    string
		timeout time.Duration
	}{
		{"five seconds", 5 * time.Second},
		{"zero (immediate SIGKILL)", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := SandboxConfig{}
			WithReplaceWithTimeout(tc.timeout)(&o)
			if !o.Replace {
				t.Error("WithReplaceWithTimeout should imply Replace")
			}
			if o.ReplaceWithTimeout == nil {
				t.Fatal("ReplaceWithTimeout should be set")
			}
			if *o.ReplaceWithTimeout != tc.timeout {
				t.Errorf("ReplaceWithTimeout: got %v, want %v", *o.ReplaceWithTimeout, tc.timeout)
			}
		})
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

func TestWithPortBindings(t *testing.T) {
	o := SandboxConfig{}
	WithPortBindings(
		PortBinding{Bind: "0.0.0.0", HostPort: 8080, GuestPort: 80},
		PortBinding{Bind: "::", HostPort: 5353, GuestPort: 53, Protocol: PortProtocolUDP},
	)(&o)

	if len(o.PortBindings) != 2 {
		t.Fatalf("PortBindings len = %d, want 2", len(o.PortBindings))
	}
	if o.PortBindings[0].Bind != "0.0.0.0" || o.PortBindings[0].HostPort != 8080 || o.PortBindings[0].GuestPort != 80 {
		t.Fatalf("PortBindings[0] = %#v", o.PortBindings[0])
	}
	if o.PortBindings[1].Protocol != PortProtocolUDP {
		t.Fatalf("PortBindings[1].Protocol = %q, want udp", o.PortBindings[1].Protocol)
	}
}

func TestWithNetwork(t *testing.T) {
	o := SandboxConfig{}
	net := &NetworkConfig{Policy: NetworkPolicyPresetPublicOnly}
	WithNetwork(net)(&o)
	if o.Network != net {
		t.Error("WithNetwork should set the Network pointer")
	}
}

func TestWithNetworkNilClearsPolicy(t *testing.T) {
	o := SandboxConfig{Network: &NetworkConfig{Policy: NetworkPolicyPresetAllowAll}}
	WithNetwork(nil)(&o)
	if o.Network != nil {
		t.Error("WithNetwork(nil) should clear Network")
	}
}

func TestNetworkPolicyFactory(t *testing.T) {
	cases := []struct {
		got  *NetworkConfig
		want NetworkPolicyPreset
	}{
		{NetworkPolicy.None(), NetworkPolicyPresetNone},
		{NetworkPolicy.PublicOnly(), NetworkPolicyPresetPublicOnly},
		{NetworkPolicy.AllowAll(), NetworkPolicyPresetAllowAll},
		{NetworkPolicy.NonLocal(), NetworkPolicyPresetNonLocal},
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
		kind  PatchKind
	}{
		{Patch.Text("/a", "x", PatchOptions{Mode: &mode, Replace: true}), PatchKindText},
		{Patch.Append("/b", "y"), PatchKindAppend},
		{Patch.Mkdir("/c", PatchOptions{}), PatchKindMkdir},
		{Patch.Remove("/d"), PatchKindRemove},
		{Patch.Symlink("/target", "/link", PatchOptions{}), PatchKindSymlink},
		{Patch.CopyFile("./src", "/dst", PatchOptions{Mode: &mode}), PatchKindCopyFile},
		{Patch.CopyDir("./src", "/dst", PatchOptions{Replace: true}), PatchKindCopyDir},
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
	for _, preset := range []NetworkPolicyPreset{
		NetworkPolicyPresetNone,
		NetworkPolicyPresetPublicOnly,
		NetworkPolicyPresetAllowAll,
		NetworkPolicyPresetNonLocal,
	} {
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
		DenyDomains:        []string{"evil.com"},
		DenyDomainSuffixes: []string{".ads"},
	}
	if n.DenyDomains[0] != "evil.com" {
		t.Errorf("DenyDomains[0]: got %q", n.DenyDomains[0])
	}
	if n.DenyDomainSuffixes[0] != ".ads" {
		t.Errorf("DenyDomainSuffixes[0]: got %q", n.DenyDomainSuffixes[0])
	}
}

func TestNetworkConfigCustomRules(t *testing.T) {
	n := &NetworkConfig{
		DefaultEgress:  PolicyActionDeny,
		DefaultIngress: PolicyActionAllow,
		Rules: []PolicyRule{
			{
				Action:      PolicyActionAllow,
				Direction:   PolicyDirectionEgress,
				Destination: "api.example.com",
				Protocol:    PolicyProtocolTCP,
				Port:        "443",
			},
			{
				Action:      PolicyActionDeny,
				Direction:   PolicyDirectionEgress,
				Destination: ".ads",
				Ports:       []string{"8000-9000"},
				Protocols:   []PolicyProtocol{PolicyProtocolTCP, PolicyProtocolUDP},
			},
		},
	}
	if n.DefaultEgress != PolicyActionDeny {
		t.Errorf("DefaultEgress: got %q", n.DefaultEgress)
	}
	if n.DefaultIngress != PolicyActionAllow {
		t.Errorf("DefaultIngress: got %q", n.DefaultIngress)
	}
	r0 := n.Rules[0]
	if r0.Action != PolicyActionAllow || r0.Destination != "api.example.com" || r0.Port != "443" {
		t.Errorf("Rule[0]: got %+v", r0)
	}
	r1 := n.Rules[1]
	if r1.Ports[0] != "8000-9000" || len(r1.Protocols) != 2 {
		t.Errorf("Rule[1]: got %+v", r1)
	}
}

func TestTlsConfigFields(t *testing.T) {
	boolTrue := true
	tls := &TLSConfig{
		Bypass:           []string{"*.internal"},
		VerifyUpstream:   &boolTrue,
		InterceptedPorts: []uint16{443, 8443},
		BlockQUIC:        &boolTrue,
		CACert:           "/ca.pem",
		CAKey:            "/ca.key",
		UpstreamCACerts:  []string{"/corp.pem"},
		ScopedUpstreamCACerts: []ScopedUpstreamCACert{
			{Pattern: "*.internal", Path: "/internal.pem"},
		},
		ScopedVerifyUpstream: []ScopedVerifyUpstream{
			{Pattern: "*.preview.internal", Verify: false},
		},
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
	if tls.UpstreamCACerts[0] != "/corp.pem" {
		t.Errorf("UpstreamCACerts[0]: got %q", tls.UpstreamCACerts[0])
	}
	if tls.ScopedUpstreamCACerts[0].Pattern != "*.internal" {
		t.Errorf("ScopedUpstreamCACerts[0]: got %+v", tls.ScopedUpstreamCACerts[0])
	}
	if tls.ScopedVerifyUpstream[0].Pattern != "*.preview.internal" {
		t.Errorf("ScopedVerifyUpstream[0]: got %+v", tls.ScopedVerifyUpstream[0])
	}
}

func TestWithShell(t *testing.T) {
	o := SandboxConfig{}
	WithShell("/bin/bash")(&o)
	if o.Shell != "/bin/bash" {
		t.Errorf("Shell: got %q", o.Shell)
	}
}

func TestWithEntrypoint(t *testing.T) {
	o := SandboxConfig{}
	WithEntrypoint("/usr/bin/python", "-m", "myapp")(&o)
	if len(o.Entrypoint) != 3 || o.Entrypoint[0] != "/usr/bin/python" {
		t.Errorf("Entrypoint: got %v", o.Entrypoint)
	}
}

func TestWithInitFactories(t *testing.T) {
	o := SandboxConfig{}
	WithInit(Init.Auto())(&o)
	if o.Init == nil || o.Init.Cmd != "auto" {
		t.Fatalf("Auto init: got %+v", o.Init)
	}
	o2 := SandboxConfig{}
	WithInit(Init.Cmd("/sbin/init", InitOptions{
		Args: []string{"--daemon"},
		Env:  map[string]string{"FOO": "BAR"},
	}))(&o2)
	if o2.Init == nil || o2.Init.Cmd != "/sbin/init" {
		t.Fatalf("Cmd init: got %+v", o2.Init)
	}
	if o2.Init.Args[0] != "--daemon" || o2.Init.Env["FOO"] != "BAR" {
		t.Errorf("Cmd init args/env: got %+v", o2.Init)
	}
}

func TestSandboxConfigUnmarshalJSONIncludesPersistedInit(t *testing.T) {
	var cfg SandboxConfig
	data := []byte(`{
		"name": "dev",
		"image": "alpine",
		"init": {
			"cmd": "/sbin/init",
			"args": ["--daemon"],
			"env": [["FOO", "BAR"], ["PATH", "/usr/bin:/bin"]]
		}
	}`)

	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	if cfg.Init == nil {
		t.Fatal("Init = nil, want persisted init config")
	}
	if cfg.Init.Cmd != "/sbin/init" {
		t.Errorf("Init.Cmd = %q, want /sbin/init", cfg.Init.Cmd)
	}
	if !reflect.DeepEqual(cfg.Init.Args, []string{"--daemon"}) {
		t.Errorf("Init.Args = %v, want [--daemon]", cfg.Init.Args)
	}
	wantEnv := map[string]string{"FOO": "BAR", "PATH": "/usr/bin:/bin"}
	if !reflect.DeepEqual(cfg.Init.Env, wantEnv) {
		t.Errorf("Init.Env = %v, want %v", cfg.Init.Env, wantEnv)
	}
}

func TestWithLogLevelAndQuietLogs(t *testing.T) {
	o := SandboxConfig{}
	WithLogLevel(LogLevelDebug)(&o)
	WithQuietLogs()(&o)
	if o.LogLevel != LogLevelDebug || !o.QuietLogs {
		t.Errorf("got %q quiet=%v", o.LogLevel, o.QuietLogs)
	}
}

func TestWithScriptsMerge(t *testing.T) {
	o := SandboxConfig{}
	WithScripts(map[string]string{"build": "make", "test": "go test"})(&o)
	WithScripts(map[string]string{"test": "pytest", "lint": "ruff"})(&o)
	want := map[string]string{"build": "make", "test": "pytest", "lint": "ruff"}
	if !reflect.DeepEqual(o.Scripts, want) {
		t.Errorf("Scripts: got %v want %v", o.Scripts, want)
	}
}

func TestWithPullPolicy(t *testing.T) {
	o := SandboxConfig{}
	WithPullPolicy(PullPolicyAlways)(&o)
	if o.PullPolicy != PullPolicyAlways {
		t.Errorf("PullPolicy: got %q", o.PullPolicy)
	}
}

func TestWithMaxDurationAndIdleTimeout(t *testing.T) {
	o := SandboxConfig{}
	WithMaxDuration(90 * time.Second)(&o)
	WithIdleTimeout(30 * time.Second)(&o)
	if o.MaxDuration != 90*time.Second {
		t.Errorf("MaxDuration: got %v", o.MaxDuration)
	}
	if o.IdleTimeout != 30*time.Second {
		t.Errorf("IdleTimeout: got %v", o.IdleTimeout)
	}
}

func TestWithEphemeral(t *testing.T) {
	o := SandboxConfig{}
	WithEphemeral(true)(&o)
	if !o.Ephemeral {
		t.Error("Ephemeral: got false")
	}
}

func TestWithRegistryAuth(t *testing.T) {
	o := SandboxConfig{}
	WithRegistryAuth(RegistryAuth{Username: "u", Password: "p"})(&o)
	if o.RegistryAuth == nil || o.RegistryAuth.Username != "u" || o.RegistryAuth.Password != "p" {
		t.Errorf("RegistryAuth: got %+v", o.RegistryAuth)
	}
}

func TestWithPortsUDP(t *testing.T) {
	o := SandboxConfig{}
	WithPortsUDP(map[uint16]uint16{53: 53})(&o)
	if o.PortsUDP[53] != 53 {
		t.Errorf("PortsUDP[53]: got %d", o.PortsUDP[53])
	}
}

func TestMountFactoryKinds(t *testing.T) {
	cases := []struct {
		mount MountConfig
		kind  MountKind
	}{
		{Mount.Bind("/host", MountOptions{}), MountKindBind},
		{Mount.Named("vol", MountOptions{Readonly: true}), MountKindNamed},
		{Mount.Tmpfs(TmpfsOptions{SizeMiB: 128}), MountKindTmpfs},
		{Mount.Disk("/host/data.img", DiskOptions{Format: "raw", Fstype: "ext4"}), MountKindDisk},
	}
	for _, c := range cases {
		if c.mount.Kind() != c.kind {
			t.Errorf("Kind: got %d want %d", c.mount.Kind(), c.kind)
		}
	}
}

func TestMountReadonlyOption(t *testing.T) {
	m := Mount.Bind("/etc/hosts", MountOptions{Readonly: true, Noexec: true, Nosuid: true, Nodev: true})
	if !m.Readonly || !m.Noexec || !m.Nosuid || !m.Nodev {
		t.Error("Bind readonly/noexec/nosuid/nodev: want true")
	}
	tm := Mount.Tmpfs(TmpfsOptions{SizeMiB: 64, Readonly: true, Noexec: true, Nosuid: true, Nodev: true})
	if !tm.Readonly || !tm.Noexec || !tm.Nosuid || !tm.Nodev || tm.SizeMiB != 64 {
		t.Errorf("Tmpfs: got %+v", tm)
	}
	d := Mount.Disk("/host/img", DiskOptions{Readonly: true, Noexec: true, Nosuid: true, Nodev: true, Fstype: "xfs"})
	if !d.Readonly || !d.Noexec || !d.Nosuid || !d.Nodev || d.Fstype != "xfs" {
		t.Errorf("Disk: got %+v", d)
	}
}

func TestMountBindDefaultsLeavePoliciesEmpty(t *testing.T) {
	m := Mount.Bind("/host/data", MountOptions{})
	if m.StatVirtualization != "" {
		t.Errorf("StatVirtualization: want empty, got %q", m.StatVirtualization)
	}
	if m.HostPermissions != "" {
		t.Errorf("HostPermissions: want empty, got %q", m.HostPermissions)
	}
}

func TestMountBindPropagatesPolicies(t *testing.T) {
	m := Mount.Bind("/host/data", MountOptions{
		Readonly:           true,
		StatVirtualization: StatVirtualizationRelaxed,
		HostPermissions:    HostPermissionsMirror,
	})
	if m.StatVirtualization != StatVirtualizationRelaxed {
		t.Errorf("StatVirtualization: got %q, want relaxed", m.StatVirtualization)
	}
	if m.HostPermissions != HostPermissionsMirror {
		t.Errorf("HostPermissions: got %q, want mirror", m.HostPermissions)
	}
	if !m.Readonly {
		t.Error("Readonly: want true")
	}
}

func TestMountNamedPropagatesPolicies(t *testing.T) {
	m := Mount.Named("cache", MountOptions{
		StatVirtualization: StatVirtualizationOff,
	})
	if m.StatVirtualization != StatVirtualizationOff {
		t.Errorf("StatVirtualization: got %q, want off", m.StatVirtualization)
	}
	// Host permissions defaults to empty (i.e. runtime default Private).
	if m.HostPermissions != "" {
		t.Errorf("HostPermissions: want empty, got %q", m.HostPermissions)
	}
}

func TestStatVirtualizationConstants(t *testing.T) {
	cases := map[StatVirtualization]string{
		StatVirtualizationDefault: "",
		StatVirtualizationStrict:  "strict",
		StatVirtualizationRelaxed: "relaxed",
		StatVirtualizationOff:     "off",
	}
	for got, want := range cases {
		if string(got) != want {
			t.Errorf("StatVirtualization: got %q, want %q", got, want)
		}
	}
}

func TestHostPermissionsConstants(t *testing.T) {
	cases := map[HostPermissions]string{
		HostPermissionsDefault: "",
		HostPermissionsPrivate: "private",
		HostPermissionsMirror:  "mirror",
	}
	for got, want := range cases {
		if string(got) != want {
			t.Errorf("HostPermissions: got %q, want %q", got, want)
		}
	}
}

func TestWithVolumeLabelsMerge(t *testing.T) {
	o := VolumeConfig{}
	WithVolumeLabels(map[string]string{"a": "1"})(&o)
	WithVolumeLabels(map[string]string{"a": "2", "b": "3"})(&o)
	want := map[string]string{"a": "2", "b": "3"}
	if !reflect.DeepEqual(o.Labels, want) {
		t.Errorf("Labels: got %v want %v", o.Labels, want)
	}
}

func TestSecretEnvOnViolation(t *testing.T) {
	s := Secret.Env("TOK", "v", SecretEnvOptions{OnViolation: ViolationActionBlockAndTerminate})
	if s.OnViolation != ViolationActionBlockAndTerminate {
		t.Errorf("OnViolation: got %q", s.OnViolation)
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

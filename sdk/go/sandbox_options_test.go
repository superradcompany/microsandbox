package microsandbox

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func marshalCreateOptions(t *testing.T, opts ...SandboxOption) map[string]any {
	t.Helper()
	cfg := SandboxConfig{}
	for _, o := range opts {
		o(&cfg)
	}
	raw, err := json.Marshal(buildFFICreateOptions(cfg))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

func mustField(t *testing.T, m map[string]any, key string) any {
	t.Helper()
	v, ok := m[key]
	if !ok {
		t.Fatalf("expected JSON field %q in payload; got %v", key, m)
	}
	return v
}

func TestFFIWireShape_WithImage(t *testing.T) {
	got := marshalCreateOptions(t, WithImage("python:3.12"))
	if v := mustField(t, got, "image"); v != "python:3.12" {
		t.Fatalf("image = %v, want %q", v, "python:3.12")
	}
	if _, present := got["snapshot"]; present {
		t.Fatal("snapshot must not appear in payload when only image is set")
	}
}

func TestFFIWireShape_WithSnapshot(t *testing.T) {
	got := marshalCreateOptions(t, WithSnapshot("after-pip-install"))
	if v := mustField(t, got, "snapshot"); v != "after-pip-install" {
		t.Fatalf("snapshot = %v, want %q", v, "after-pip-install")
	}
	if _, present := got["image"]; present {
		t.Fatal("image must not appear in payload when only snapshot is set")
	}
}

func TestFFIWireShape_ScalarKnobs(t *testing.T) {
	got := marshalCreateOptions(t,
		WithImage("alpine"),
		WithMemory(512),
		WithCPUs(2),
		WithWorkdir("/app"),
		WithShell("/bin/bash"),
		WithHostname("sb"),
		WithUser("nobody"),
		WithReplace(),
		WithDetached(),
		WithQuietLogs(),
		WithLogLevel(LogLevelDebug),
		WithPullPolicy(PullPolicyAlways),
		WithMaxDuration(45*time.Second),
		WithIdleTimeout(2*time.Minute),
	)
	checks := []struct {
		key  string
		want any
	}{
		{"image", "alpine"},
		{"memory_mib", float64(512)},
		{"cpus", float64(2)},
		{"workdir", "/app"},
		{"shell", "/bin/bash"},
		{"hostname", "sb"},
		{"user", "nobody"},
		{"replace", true},
		{"detached", true},
		{"quiet_logs", true},
		{"log_level", "debug"},
		{"pull_policy", "always"},
		{"max_duration_secs", float64(45)},
		{"idle_timeout_secs", float64(120)},
	}
	for _, c := range checks {
		if v := mustField(t, got, c.key); v != c.want {
			t.Errorf("%s = %v (%T), want %v", c.key, v, v, c.want)
		}
	}
}

func TestFFIWireShape_ReplaceWithGraceMs(t *testing.T) {
	got := marshalCreateOptions(t,
		WithImage("alpine"),
		WithReplaceWithGrace(750*time.Millisecond),
	)
	if v := mustField(t, got, "replace_with_grace_ms"); v != float64(750) {
		t.Fatalf("replace_with_grace_ms = %v, want 750", v)
	}
	if v := mustField(t, got, "replace"); v != true {
		t.Fatalf("replace = %v, want true", v)
	}

	// Zero must round-trip (means "skip SIGTERM"), not be omitted.
	got = marshalCreateOptions(t,
		WithImage("alpine"),
		WithReplaceWithGrace(0),
	)
	v, ok := got["replace_with_grace_ms"]
	if !ok {
		t.Fatal("zero grace was omitted")
	}
	if v != float64(0) {
		t.Fatalf("replace_with_grace_ms = %v, want 0", v)
	}
}

func TestFFIWireShape_EnvAndScripts(t *testing.T) {
	got := marshalCreateOptions(t,
		WithImage("alpine"),
		WithEnv(map[string]string{"FOO": "1"}),
		WithEnv(map[string]string{"BAR": "2"}), // repeated -> merge
		WithScripts(map[string]string{"run": "echo hi"}),
	)
	env := mustField(t, got, "env").(map[string]any)
	if env["FOO"] != "1" || env["BAR"] != "2" {
		t.Fatalf("env merge failed: %v", env)
	}
	scripts := mustField(t, got, "scripts").(map[string]any)
	if scripts["run"] != "echo hi" {
		t.Fatalf("scripts = %v", scripts)
	}
}

func TestFFIWireShape_Ports(t *testing.T) {
	got := marshalCreateOptions(t,
		WithImage("alpine"),
		WithPorts(map[uint16]uint16{8080: 80}),
		WithPortsUDP(map[uint16]uint16{5353: 53}),
	)
	ports := mustField(t, got, "ports").(map[string]any)
	if ports["8080"] != float64(80) {
		t.Fatalf("ports = %v", ports)
	}
	portsUDP := mustField(t, got, "ports_udp").(map[string]any)
	if portsUDP["5353"] != float64(53) {
		t.Fatalf("ports_udp = %v", portsUDP)
	}
}

func TestFFIWireShape_RegistryAuth(t *testing.T) {
	got := marshalCreateOptions(t,
		WithImage("private.example.com/img"),
		WithRegistryAuth(RegistryAuth{Username: "u", Password: "p"}),
	)
	ra := mustField(t, got, "registry_auth").(map[string]any)
	if ra["username"] != "u" || ra["password"] != "p" {
		t.Fatalf("registry_auth = %v", ra)
	}
}

func TestFFIWireShape_Init(t *testing.T) {
	got := marshalCreateOptions(t,
		WithImage("alpine"),
		WithInit(Init.Cmd("/sbin/init", InitOptions{
			Args: []string{"--foo"},
			Env:  map[string]string{"X": "1"},
		})),
	)
	init := mustField(t, got, "init").(map[string]any)
	if init["cmd"] != "/sbin/init" {
		t.Fatalf("init.cmd = %v", init["cmd"])
	}
	args := init["args"].([]any)
	if len(args) != 1 || args[0] != "--foo" {
		t.Fatalf("init.args = %v", args)
	}
	envArr := init["env"].([]any)
	if len(envArr) != 1 {
		t.Fatalf("init.env = %v", envArr)
	}
	pair := envArr[0].([]any)
	if pair[0] != "X" || pair[1] != "1" {
		t.Fatalf("init.env[0] = %v", pair)
	}
}

func TestFFIWireShape_Patches(t *testing.T) {
	mode := uint32(0o755)
	got := marshalCreateOptions(t,
		WithImage("alpine"),
		WithPatches(
			Patch.Text("/etc/x", "hello", PatchOptions{Mode: &mode, Replace: true}),
			Patch.Mkdir("/app", PatchOptions{Mode: &mode}),
			Patch.Symlink("/x", "/y", PatchOptions{Replace: true}),
		),
	)
	patches := mustField(t, got, "patches").([]any)
	if len(patches) != 3 {
		t.Fatalf("patches length = %d, want 3", len(patches))
	}
	first := patches[0].(map[string]any)
	if first["kind"] != "text" || first["path"] != "/etc/x" || first["content"] != "hello" {
		t.Fatalf("patches[0] = %v", first)
	}
	if first["replace"] != true {
		t.Fatalf("patches[0].replace = %v, want true", first["replace"])
	}
}

func TestFFIWireShape_Volumes(t *testing.T) {
	got := marshalCreateOptions(t,
		WithImage("alpine"),
		WithMounts(map[string]MountConfig{
			"/data":    Mount.Named("vol-a", MountOptions{}),
			"/host":    Mount.Bind("/var/lib", MountOptions{Readonly: true}),
			"/scratch": Mount.Tmpfs(TmpfsOptions{SizeMiB: 128}),
			"/img":     Mount.Disk("/tmp/pool.img", DiskOptions{Format: "raw", Readonly: true}),
		}),
	)
	volumes := mustField(t, got, "volumes").(map[string]any)
	if v := volumes["/data"].(map[string]any); v["named"] != "vol-a" {
		t.Fatalf("/data named = %v", v)
	}
	if v := volumes["/host"].(map[string]any); v["bind"] != "/var/lib" || v["readonly"] != true {
		t.Fatalf("/host = %v", v)
	}
	if v := volumes["/scratch"].(map[string]any); v["tmpfs"] != true || v["size_mib"] != float64(128) {
		t.Fatalf("/scratch = %v", v)
	}
	if v := volumes["/img"].(map[string]any); v["disk"] != "/tmp/pool.img" || v["format"] != "raw" {
		t.Fatalf("/img = %v", v)
	}
}

func TestFFIWireShape_Secrets(t *testing.T) {
	got := marshalCreateOptions(t,
		WithImage("alpine"),
		WithSecrets(Secret.Env("OPENAI_API_KEY", "sk-xxx", SecretEnvOptions{
			AllowHosts:        []string{"api.openai.com"},
			AllowHostPatterns: []string{"*.openai.com"},
			OnViolation:       ViolationActionBlockAndTerminate,
		})),
	)
	secs := mustField(t, got, "secrets").([]any)
	if len(secs) != 1 {
		t.Fatalf("secrets length = %d", len(secs))
	}
	s := secs[0].(map[string]any)
	if s["env_var"] != "OPENAI_API_KEY" || s["value"] != "sk-xxx" {
		t.Fatalf("secret = %v", s)
	}
	if s["on_violation"] != "block-and-terminate" {
		t.Fatalf("on_violation = %v", s["on_violation"])
	}
	hosts := s["allow_hosts"].([]any)
	if len(hosts) != 1 || hosts[0] != "api.openai.com" {
		t.Fatalf("allow_hosts = %v", hosts)
	}
}

func TestFFIWireShape_NetworkPreset(t *testing.T) {
	got := marshalCreateOptions(t,
		WithImage("alpine"),
		WithNetwork(NetworkPolicy.PublicOnly()),
	)
	net := mustField(t, got, "network").(map[string]any)
	if net["policy"] != "public-only" {
		t.Fatalf("network.policy = %v", net["policy"])
	}
}

func TestFFIWireShape_NetworkCustomRules(t *testing.T) {
	got := marshalCreateOptions(t,
		WithImage("alpine"),
		WithNetwork(&NetworkConfig{
			DefaultEgress:  PolicyActionDeny,
			DefaultIngress: PolicyActionAllow,
			Rules: []PolicyRule{
				{
					Action:      PolicyActionAllow,
					Direction:   PolicyDirectionEgress,
					Destination: "api.openai.com",
					Protocol:    PolicyProtocolTCP,
					Port:        "443",
				},
			},
			DenyDomains: []string{"blocked.example.com"},
			DNS: &DNSConfig{
				Nameservers: []string{"1.1.1.1:53"},
			},
			IPv4Pool: "172.31.240.0/24",
			IPv6Pool: "fd7a:115c:a1e0:100::/56",
		}),
	)
	net := mustField(t, got, "network").(map[string]any)

	// The custom policy is nested under custom_policy.
	cp := net["custom_policy"].(map[string]any)
	if cp["default_egress"] != "deny" || cp["default_ingress"] != "allow" {
		t.Fatalf("defaults = %v", cp)
	}
	rules := cp["rules"].([]any)
	r0 := rules[0].(map[string]any)
	if r0["action"] != "allow" || r0["direction"] != "egress" {
		t.Fatalf("rule[0] = %v", r0)
	}
	if r0["destination"] != "api.openai.com" || r0["protocol"] != "tcp" || r0["port"] != "443" {
		t.Fatalf("rule[0] details = %v", r0)
	}

	deny := net["deny_domains"].([]any)
	if len(deny) != 1 || deny[0] != "blocked.example.com" {
		t.Fatalf("deny_domains = %v", deny)
	}
	if net["ipv4_pool"] != "172.31.240.0/24" {
		t.Fatalf("ipv4_pool = %v", net["ipv4_pool"])
	}
	if net["ipv6_pool"] != "fd7a:115c:a1e0:100::/56" {
		t.Fatalf("ipv6_pool = %v", net["ipv6_pool"])
	}
	dns := net["dns"].(map[string]any)
	ns := dns["nameservers"].([]any)
	if len(ns) != 1 || ns[0] != "1.1.1.1:53" {
		t.Fatalf("dns.nameservers = %v", ns)
	}
}

// The Rust side relies on serde(default), so zero-valued Go fields must not
// reach the wire — otherwise the runtime can't tell "unset" from "set to zero".
func TestFFIWireShape_EmptyConfigOmitsOptionalFields(t *testing.T) {
	got := marshalCreateOptions(t)

	for _, key := range []string{
		"image", "snapshot", "memory_mib", "cpus", "workdir", "shell",
		"hostname", "user", "replace", "detached", "env", "scripts",
		"ports", "ports_udp", "network", "secrets", "patches", "volumes",
		"init", "registry_auth",
	} {
		if _, present := got[key]; present {
			body, _ := json.Marshal(got)
			t.Errorf("empty config emitted key %q; payload = %s", key, body)
		}
	}
}

func TestFFIWireShape_KitchenSinkDoesNotPanic(t *testing.T) {
	got := marshalCreateOptions(t,
		WithImage("python:3.12"),
		WithMemory(1024),
		WithCPUs(4),
		WithEnv(map[string]string{"A": "1"}),
		WithMounts(map[string]MountConfig{
			"/data": Mount.Named("vol", MountOptions{}),
		}),
		WithNetwork(&NetworkConfig{
			DefaultEgress: PolicyActionDeny,
			Rules: []PolicyRule{
				{Action: PolicyActionAllow, Destination: "*"},
			},
			TLS: &TLSConfig{Bypass: []string{"*.googleapis.com"}},
		}),
		WithSecrets(Secret.Env("K", "v", SecretEnvOptions{
			AllowHosts: []string{"h"},
		})),
		WithPatches(Patch.Mkdir("/app", PatchOptions{})),
		WithPorts(map[uint16]uint16{8080: 80}),
		WithReplace(),
		WithDetached(),
		WithMaxDuration(30*time.Second),
	)
	body, _ := json.Marshal(got)
	if !strings.Contains(string(body), "python:3.12") {
		t.Fatalf("kitchen-sink payload missing image: %s", body)
	}
}

package microsandbox

import (
	"encoding/json"
	"os"
	"path/filepath"
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

func TestSandboxConfigUnmarshalPersistedRootfsSource(t *testing.T) {
	raw := []byte(`{
		"name": "go-sdk-example-main",
		"image": {
			"Oci": {
				"reference": "mirror.gcr.io/library/alpine",
				"root_disk": {"kind": "managed", "size_mib": 4096}
			}
		},
		"cpus": 1,
		"memory_mib": 512,
		"workdir": "/",
		"labels": {"suite": "sdk"},
		"scripts": {"hello": "echo hi"}
	}`)

	var cfg SandboxConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if cfg.Name != "go-sdk-example-main" {
		t.Fatalf("Name = %q", cfg.Name)
	}
	if cfg.Image != "mirror.gcr.io/library/alpine" {
		t.Fatalf("Image = %q", cfg.Image)
	}
	if cfg.RootDisk == nil || cfg.RootDisk.Kind() != RootDiskKindManaged || cfg.RootDisk.SizeMiB != 4096 {
		t.Fatalf("RootDisk = %#v, want managed 4096", cfg.RootDisk)
	}
	if cfg.OCIUpperSizeMiB != 4096 || !cfg.ociUpperSizeSet {
		t.Fatalf("legacy OCI upper mirror = %d, set = %v", cfg.OCIUpperSizeMiB, cfg.ociUpperSizeSet)
	}
	if cfg.CPUs != 1 || cfg.MemoryMiB != 512 || cfg.Workdir != "/" {
		t.Fatalf("scalar config mismatch: %#v", cfg)
	}
	if cfg.Labels["suite"] != "sdk" || cfg.Scripts["hello"] != "echo hi" {
		t.Fatalf("map config mismatch: labels=%v scripts=%v", cfg.Labels, cfg.Scripts)
	}
}

func TestSandboxConfigUnmarshalPersistedTmpfsRootDisk(t *testing.T) {
	raw := []byte(`{
		"name": "go-sdk-example-main",
		"image": {
			"Oci": {
				"reference": "mirror.gcr.io/library/alpine",
				"root_disk": {"kind": "tmpfs"}
			}
		}
	}`)

	var cfg SandboxConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if cfg.RootDisk == nil || cfg.RootDisk.Kind() != RootDiskKindTmpfs {
		t.Fatalf("RootDisk = %#v, want tmpfs", cfg.RootDisk)
	}
	if cfg.ociUpperSizeSet {
		t.Fatal("legacy upper mirror must stay unset for tmpfs root disks")
	}
}

func TestSandboxConfigUnmarshalPersistedDiskImageRootDisk(t *testing.T) {
	raw := []byte(`{
		"name": "go-sdk-example-main",
		"image": {
			"Oci": {
				"reference": "mirror.gcr.io/library/alpine",
				"root_disk": {"kind": "disk-image", "path": "/imgs/scratch.img", "format": "Raw", "fstype": "ext4"}
			}
		}
	}`)

	var cfg SandboxConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	rd := cfg.RootDisk
	if rd == nil || rd.Kind() != RootDiskKindDiskImage {
		t.Fatalf("RootDisk = %#v, want disk-image", rd)
	}
	if rd.Path != "/imgs/scratch.img" || rd.Format != "raw" || rd.Fstype != "ext4" {
		t.Fatalf("disk-image fields = %#v", rd)
	}
}

func TestSandboxConfigUnmarshalLegacyFlatUpperSize(t *testing.T) {
	raw := []byte(`{
		"name": "go-sdk-example-main",
		"image": {
			"Oci": {
				"reference": "mirror.gcr.io/library/alpine",
				"upper_size_mib": 4096
			}
		}
	}`)

	var cfg SandboxConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if cfg.RootDisk == nil || cfg.RootDisk.Kind() != RootDiskKindManaged || cfg.RootDisk.SizeMiB != 4096 {
		t.Fatalf("RootDisk = %#v, want managed 4096 from legacy field", cfg.RootDisk)
	}
	if cfg.OCIUpperSizeMiB != 4096 || !cfg.ociUpperSizeSet {
		t.Fatalf("legacy OCI upper mirror = %d, set = %v", cfg.OCIUpperSizeMiB, cfg.ociUpperSizeSet)
	}
}

func TestSandboxConfigUnmarshalNestedResources(t *testing.T) {
	raw := []byte(`{
		"name": "go-sdk-example-main",
		"image": {
			"Oci": {
				"reference": "mirror.gcr.io/library/alpine",
				"upper_size_mib": 4096
			}
		},
		"resources": {
			"cpus": 2,
			"memory_mib": 1024,
			"max_cpus": 8,
			"max_memory_mib": 4096
		}
	}`)

	var cfg SandboxConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if cfg.CPUs != 2 || cfg.MemoryMiB != 1024 {
		t.Fatalf("effective resources mismatch: %#v", cfg)
	}
	if cfg.MaxCPUs != 8 || cfg.MaxMemoryMiB != 4096 {
		t.Fatalf("max resources mismatch: %#v", cfg)
	}
}

func TestSandboxConfigUnmarshalLegacyNestedResourcesDefaultMax(t *testing.T) {
	raw := []byte(`{
		"name": "go-sdk-example-main",
		"resources": {
			"cpus": 4,
			"memory_mib": 2048
		}
	}`)

	var cfg SandboxConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if cfg.MaxCPUs != 4 || cfg.MaxMemoryMiB != 2048 {
		t.Fatalf("legacy max resources mismatch: %#v", cfg)
	}
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

func TestFFIWireShape_WithBindRootfs(t *testing.T) {
	got := marshalCreateOptions(t, WithBindRootfs("/srv/rootfs"))
	if v := mustField(t, got, "image_bind"); v != "/srv/rootfs" {
		t.Fatalf("image_bind = %v, want %q", v, "/srv/rootfs")
	}
	if _, present := got["image"]; present {
		t.Fatal("image must not appear in payload when only image_bind is set")
	}
}

func TestFFIWireShape_WithRootDiskManaged(t *testing.T) {
	got := marshalCreateOptions(t, WithImage("python:3.12"), WithRootDisk(RootDisk.Managed(8192)))
	rd := mustField(t, got, "root_disk").(map[string]any)
	if rd["kind"] != "managed" || rd["size_mib"] != float64(8192) {
		t.Fatalf("root_disk = %v, want managed 8192", rd)
	}
}

func TestFFIWireShape_WithRootDiskTmpfs(t *testing.T) {
	got := marshalCreateOptions(t,
		WithImage("python:3.12"),
		WithRootDisk(RootDisk.Tmpfs(RootDiskTmpfsOptions{SizeMiB: 512})),
	)
	rd := mustField(t, got, "root_disk").(map[string]any)
	if rd["kind"] != "tmpfs" || rd["size_mib"] != float64(512) {
		t.Fatalf("root_disk = %v, want tmpfs 512", rd)
	}
}

func TestFFIWireShape_WithRootDiskTmpfsDefaultSizeOmitsSize(t *testing.T) {
	got := marshalCreateOptions(t,
		WithImage("python:3.12"),
		WithRootDisk(RootDisk.Tmpfs(RootDiskTmpfsOptions{})),
	)
	rd := mustField(t, got, "root_disk").(map[string]any)
	if rd["kind"] != "tmpfs" {
		t.Fatalf("root_disk = %v, want tmpfs", rd)
	}
	if _, present := rd["size_mib"]; present {
		t.Fatalf("size_mib must be omitted for the runtime default; root_disk = %v", rd)
	}
}

func TestFFIWireShape_WithRootDiskImage(t *testing.T) {
	got := marshalCreateOptions(t,
		WithImage("python:3.12"),
		WithRootDisk(RootDisk.Disk("./scratch.img", RootDiskImageOptions{Format: "raw", Fstype: "ext4"})),
	)
	rd := mustField(t, got, "root_disk").(map[string]any)
	if rd["kind"] != "disk-image" || rd["path"] != "./scratch.img" || rd["format"] != "raw" || rd["fstype"] != "ext4" {
		t.Fatalf("root_disk = %v, want disk-image fields", rd)
	}
	if _, present := rd["size_mib"]; present {
		t.Fatalf("size_mib must be omitted for disk-image root disks; root_disk = %v", rd)
	}
}

func TestFFIWireShape_WithRootDiskFlat(t *testing.T) {
	got := marshalCreateOptions(t,
		WithImage("python:3.12"),
		WithRootDisk(RootDisk.Flat(RootDiskFlatOptions{
			SizeMiB: 8192,
			Fstype:  "ext4",
			Clone:   FlatCloneReflink,
		})),
	)
	rd := mustField(t, got, "root_disk").(map[string]any)
	if rd["kind"] != "flat" || rd["size_mib"] != float64(8192) || rd["fstype"] != "ext4" || rd["clone"] != "reflink" {
		t.Fatalf("root_disk = %v, want flat ext4 reflink fields", rd)
	}
}

func TestFFIWireShape_WithOCIUpperSize(t *testing.T) {
	got := marshalCreateOptions(t, WithImage("python:3.12"), WithOCIUpperSize(8192))
	rd := mustField(t, got, "root_disk").(map[string]any)
	if rd["kind"] != "managed" || rd["size_mib"] != float64(8192) {
		t.Fatalf("root_disk = %v, want managed 8192 from deprecated alias", rd)
	}
	if _, present := got["oci_upper_size_mib"]; present {
		t.Fatal("deprecated flat field must not reach the wire")
	}
}

func TestFFIWireShape_WithOCIUpperSizeZero(t *testing.T) {
	got := marshalCreateOptions(t, WithImage("python:3.12"), WithOCIUpperSize(0))
	rd := mustField(t, got, "root_disk").(map[string]any)
	if rd["kind"] != "managed" || rd["size_mib"] != float64(0) {
		t.Fatalf("root_disk = %v, want explicit managed 0", rd)
	}
}

func TestFFIWireShape_LegacyConfigFieldMapsToRootDisk(t *testing.T) {
	// WithConfig users may still set the deprecated public field directly.
	got := marshalCreateOptions(t, WithImage("python:3.12"), func(o *SandboxConfig) {
		o.OCIUpperSizeMiB = 2048
	})
	rd := mustField(t, got, "root_disk").(map[string]any)
	if rd["kind"] != "managed" || rd["size_mib"] != float64(2048) {
		t.Fatalf("root_disk = %v, want managed 2048 from legacy field", rd)
	}
}

func TestFFIWireShape_WithFromSnapshot(t *testing.T) {
	got := marshalCreateOptions(t, WithFromSnapshot("after-pip-install"))
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
		WithMaxMemory(4096),
		WithMaxCPUs(8),
		WithCPUPlacement(CPUPlacementSpread),
		WithPlacementProfile("latency"),
		WithWorkdir("/app"),
		WithShell("/bin/bash"),
		WithHostname("sb"),
		WithUser("nobody"),
		WithReplace(),
		WithDetached(),
		WithEphemeral(true),
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
		{"cpu_placement", "spread"},
		{"placement_profile", "latency"},
		{"memory_mib", float64(512)},
		{"cpus", float64(2)},
		{"max_memory_mib", float64(4096)},
		{"max_cpus", float64(8)},
		{"workdir", "/app"},
		{"shell", "/bin/bash"},
		{"hostname", "sb"},
		{"user", "nobody"},
		{"replace", true},
		{"detached", true},
		{"ephemeral", true},
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

func TestFFIWireShape_ReplaceWithTimeoutMs(t *testing.T) {
	got := marshalCreateOptions(t,
		WithImage("alpine"),
		WithReplaceWithTimeout(750*time.Millisecond),
	)
	if v := mustField(t, got, "replace_with_timeout_ms"); v != float64(750) {
		t.Fatalf("replace_with_timeout_ms = %v, want 750", v)
	}
	if v := mustField(t, got, "replace"); v != true {
		t.Fatalf("replace = %v, want true", v)
	}

	// Zero must round-trip (means "skip SIGTERM"), not be omitted.
	got = marshalCreateOptions(t,
		WithImage("alpine"),
		WithReplaceWithTimeout(0),
	)
	v, ok := got["replace_with_timeout_ms"]
	if !ok {
		t.Fatal("zero timeout was omitted")
	}
	if v != float64(0) {
		t.Fatalf("replace_with_timeout_ms = %v, want 0", v)
	}
}

func TestFFIWireShape_CommandOverridesPreserveExplicitClear(t *testing.T) {
	got := marshalCreateOptions(t, WithEntrypoint("python", "-u"), WithCmd("worker.py"))
	if entrypoint := mustField(t, got, "entrypoint").([]any); len(entrypoint) != 2 {
		t.Fatalf("entrypoint = %v", entrypoint)
	}
	if cmd := mustField(t, got, "cmd").([]any); len(cmd) != 1 || cmd[0] != "worker.py" {
		t.Fatalf("cmd = %v", cmd)
	}

	cleared := marshalCreateOptions(t, WithEntrypoint(), WithCmd())
	if entrypoint := mustField(t, cleared, "entrypoint").([]any); len(entrypoint) != 0 {
		t.Fatalf("cleared entrypoint = %v", entrypoint)
	}
	if cmd := mustField(t, cleared, "cmd").([]any); len(cmd) != 0 {
		t.Fatalf("cleared cmd = %v", cmd)
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

func TestFFIWireShape_Labels(t *testing.T) {
	got := marshalCreateOptions(t,
		WithImage("alpine"),
		WithLabels(map[string]string{"user.id": "alice"}),
		WithLabel("tenant", "acme"),
	)
	labels := mustField(t, got, "labels").(map[string]any)
	if labels["user.id"] != "alice" || labels["tenant"] != "acme" {
		t.Fatalf("labels = %v", labels)
	}
}

func TestFFIWireShape_Ports(t *testing.T) {
	got := marshalCreateOptions(t,
		WithImage("alpine"),
		WithPorts(map[uint16]uint16{8080: 80}),
		WithPortsUDP(map[uint16]uint16{5353: 53}),
		WithPortBindings(PortBinding{Bind: "0.0.0.0", HostPort: 8081, GuestPort: 81}),
	)
	ports := mustField(t, got, "ports").(map[string]any)
	if ports["8080"] != float64(80) {
		t.Fatalf("ports = %v", ports)
	}
	portsUDP := mustField(t, got, "ports_udp").(map[string]any)
	if portsUDP["5353"] != float64(53) {
		t.Fatalf("ports_udp = %v", portsUDP)
	}
	bindings := mustField(t, got, "port_bindings").([]any)
	first := bindings[0].(map[string]any)
	if first["bind"] != "0.0.0.0" || first["host_port"] != float64(8081) || first["guest_port"] != float64(81) {
		t.Fatalf("port_bindings = %v", bindings)
	}
}

func TestFFIWireShape_Vsock(t *testing.T) {
	got := marshalCreateOptions(t,
		WithImage("alpine"),
		WithVsock(
			VsockRoute{HostSocket: "/run/host-api.sock", Port: 5000},
			VsockRoute{HostSocket: "/run/events.sock", Port: 5001, SocketType: VsockSocketTypeDgram},
		),
	)
	routes := mustField(t, got, "vsock").([]any)
	stream := routes[0].(map[string]any)
	dgram := routes[1].(map[string]any)
	if stream["host_socket"] != "/run/host-api.sock" || stream["port"] != float64(5000) {
		t.Fatalf("stream vsock route = %v", stream)
	}
	if _, present := stream["socket_type"]; present {
		t.Fatalf("default stream type should be omitted: %v", stream)
	}
	if dgram["socket_type"] != "dgram" || dgram["port"] != float64(5001) {
		t.Fatalf("datagram vsock route = %v", dgram)
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

func TestFFIWireShape_RegistryOverrides(t *testing.T) {
	got := marshalCreateOptions(t,
		WithImage("localhost:5050/img"),
		WithRegistryInsecure(),
		WithRegistryCACerts([]byte("pem-one")),
		WithRegistryCACerts([]byte("pem-two")),
	)
	if got["registry_insecure"] != true {
		t.Fatalf("registry_insecure = %v", got["registry_insecure"])
	}
	certs := mustField(t, got, "registry_ca_certs").([]any)
	if len(certs) != 2 || certs[0] != "pem-one" || certs[1] != "pem-two" {
		t.Fatalf("registry_ca_certs = %v", certs)
	}
}

func TestResolveRegistryCACertPaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(path, []byte("pem-from-file"), 0o600); err != nil {
		t.Fatalf("write ca.pem: %v", err)
	}

	cfg := SandboxConfig{}
	WithRegistryCACerts([]byte("pem-inline"))(&cfg)
	WithRegistryCACertsPath(path)(&cfg)
	if err := resolveRegistryCACertPaths(&cfg); err != nil {
		t.Fatalf("resolveRegistryCACertPaths: %v", err)
	}
	if len(cfg.RegistryCACerts) != 2 ||
		string(cfg.RegistryCACerts[0]) != "pem-inline" ||
		string(cfg.RegistryCACerts[1]) != "pem-from-file" {
		t.Fatalf("RegistryCACerts = %q", cfg.RegistryCACerts)
	}
}

func TestResolveRegistryCACertPathsMissingFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.pem")
	cfg := SandboxConfig{}
	WithRegistryCACertsPath(missing)(&cfg)
	err := resolveRegistryCACertPaths(&cfg)
	if err == nil {
		t.Fatal("resolveRegistryCACertPaths: got nil error for a missing file")
	}
	if !strings.Contains(err.Error(), missing) {
		t.Errorf("error %q does not mention the path %q", err, missing)
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
			"/host":    Mount.Bind("/var/lib", MountOptions{Readonly: true, Noexec: true, Nosuid: true, Nodev: true}),
			"/scratch": Mount.Tmpfs(TmpfsOptions{SizeMiB: 128, Noexec: true, Nosuid: true}),
			"/img":     Mount.Disk("/tmp/pool.img", DiskOptions{Format: "raw", Readonly: true}),
		}),
	)
	volumes := mustField(t, got, "volumes").(map[string]any)
	if v := volumes["/data"].(map[string]any); v["named"] != "vol-a" {
		t.Fatalf("/data named = %v", v)
	}
	if v := volumes["/host"].(map[string]any); v["bind"] != "/var/lib" || v["readonly"] != true || v["noexec"] != true || v["nosuid"] != true || v["nodev"] != true {
		t.Fatalf("/host = %v", v)
	}
	if v := volumes["/scratch"].(map[string]any); v["tmpfs"] != true || v["size_mib"] != float64(128) || v["noexec"] != true || v["nosuid"] != true {
		t.Fatalf("/scratch = %v", v)
	}
	if v := volumes["/img"].(map[string]any); v["disk"] != "/tmp/pool.img" || v["format"] != "raw" {
		t.Fatalf("/img = %v", v)
	}
}

func TestFFIWireShape_MountOwner(t *testing.T) {
	got := marshalCreateOptions(t,
		WithImage("alpine"),
		WithMounts(map[string]MountConfig{
			"/owned":   Mount.Bind("/host/owned", MountOptions{Owner: &MountOwner{UID: 1000, GID: 1000}}),
			"/root":    Mount.Bind("/host/root", MountOptions{Owner: &MountOwner{UID: 0, GID: 0}}),
			"/default": Mount.Bind("/host/default", MountOptions{}),
		}),
	)
	volumes := mustField(t, got, "volumes").(map[string]any)

	// An explicit owner rides the wire as override_uid/override_gid.
	if v := volumes["/owned"].(map[string]any); v["override_uid"] != float64(1000) || v["override_gid"] != float64(1000) {
		t.Fatalf("/owned = %v", v)
	}
	// uid 0 (root) is a real value and must be present, not omitted.
	if v := volumes["/root"].(map[string]any); v["override_uid"] != float64(0) || v["override_gid"] != float64(0) {
		t.Fatalf("/root = %v", v)
	}
	// No owner → the keys are omitted entirely (unset, not 0).
	if v := volumes["/default"].(map[string]any); v["override_uid"] != nil || v["override_gid"] != nil {
		t.Fatalf("/default should omit override_uid/override_gid, got %v", v)
	}
}

func TestFFIWireShape_SecurityProfile(t *testing.T) {
	got := marshalCreateOptions(t,
		WithImage("alpine"),
		WithSecurityProfile(SecurityProfileRestricted),
	)
	if got["security_profile"] != "restricted" {
		t.Fatalf("security_profile = %v", got["security_profile"])
	}
}

func TestFFIWireShape_DeploymentProfile(t *testing.T) {
	got := marshalCreateOptions(t,
		WithImage("alpine"),
		WithDeploymentProfile(DeploymentProfileMultiTenant),
	)
	if got["deployment_profile"] != "multi-tenant" {
		t.Fatalf("deployment_profile = %v", got["deployment_profile"])
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

func TestFFIWireShape_NetworkProfile(t *testing.T) {
	got := marshalCreateOptions(t,
		WithImage("alpine"),
		WithNetwork(NetworkPolicy.FromProfiles(NetworkProfilePublic)),
	)
	net := mustField(t, got, "network").(map[string]any)
	policy := mustField(t, net, "custom_policy").(map[string]any)
	rules := mustField(t, policy, "rules").([]any)
	if len(rules) != 2 {
		t.Fatalf("network.custom_policy.rules len = %d, want 2", len(rules))
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

func TestBuildFFINetworkRateLimiters(t *testing.T) {
	out := buildFFINetwork(&NetworkConfig{
		RateLimiter: &NetworkRateLimiterConfig{
			Egress: &RateLimiterConfig{
				Bandwidth: &TokenBucketConfig{
					Size:         1 << 20,
					RefillTime:   time.Second,
					OneTimeBurst: 512 << 10,
				},
				Ops: &TokenBucketConfig{Size: 1000, RefillTime: 100 * time.Millisecond},
			},
			Ingress: &RateLimiterConfig{
				Bandwidth: &TokenBucketConfig{Size: 2 << 20, RefillTime: 500 * time.Millisecond},
			},
		},
	})

	egress := out.RateLimiter.Egress
	if egress == nil || egress.Bandwidth == nil || egress.Ops == nil {
		t.Fatalf("egress rate limiter = %+v", egress)
	}
	if egress.Bandwidth.Size != 1<<20 || egress.Bandwidth.RefillTimeMs != 1000 {
		t.Fatalf("egress bandwidth = %+v", egress.Bandwidth)
	}
	if egress.Bandwidth.OneTimeBurst != 512<<10 {
		t.Fatalf("egress bandwidth burst = %d", egress.Bandwidth.OneTimeBurst)
	}
	if egress.Ops.Size != 1000 || egress.Ops.RefillTimeMs != 100 || egress.Ops.OneTimeBurst != 0 {
		t.Fatalf("egress ops = %+v", egress.Ops)
	}

	ingress := out.RateLimiter.Ingress
	if ingress == nil || ingress.Bandwidth == nil {
		t.Fatalf("ingress rate limiter = %+v", ingress)
	}
	if ingress.Ops != nil {
		t.Fatalf("ingress ops should stay nil, got %+v", ingress.Ops)
	}
	if ingress.Bandwidth.Size != 2<<20 || ingress.Bandwidth.RefillTimeMs != 500 {
		t.Fatalf("ingress bandwidth = %+v", ingress.Bandwidth)
	}
}

func TestBuildFFINetworkRateLimitersNil(t *testing.T) {
	out := buildFFINetwork(&NetworkConfig{})
	if out.RateLimiter != nil {
		t.Fatalf("nil rate limiters should stay nil: %+v", out)
	}
}

func TestBuildFFITokenBucketKeepsInvalidRefillTimesInvalid(t *testing.T) {
	for _, refillTime := range []time.Duration{
		-time.Second,
		0,
		time.Microsecond,
		1500 * time.Microsecond,
	} {
		out := buildFFITokenBucket(&TokenBucketConfig{Size: 1, RefillTime: refillTime})
		if out.RefillTimeMs != 0 {
			t.Fatalf("refill time %s became %dms", refillTime, out.RefillTimeMs)
		}
	}

	out := buildFFITokenBucket(&TokenBucketConfig{Size: 1, RefillTime: time.Millisecond})
	if out.RefillTimeMs != 1 {
		t.Fatalf("1ms refill time became %dms", out.RefillTimeMs)
	}
}

func TestFFIWireShape_NetworkRateLimiters(t *testing.T) {
	got := marshalCreateOptions(t,
		WithImage("alpine"),
		WithNetwork(&NetworkConfig{
			RateLimiter: &NetworkRateLimiterConfig{
				Egress: &RateLimiterConfig{
					Bandwidth: &TokenBucketConfig{
						Size:         1 << 20,
						RefillTime:   time.Second,
						OneTimeBurst: 512 << 10,
					},
				},
				Ingress: &RateLimiterConfig{
					Ops: &TokenBucketConfig{Size: 1000, RefillTime: 100 * time.Millisecond},
				},
			},
		}),
	)
	net := mustField(t, got, "network").(map[string]any)
	rateLimiter := net["rate_limiter"].(map[string]any)

	egress := rateLimiter["egress"].(map[string]any)
	bw := egress["bandwidth"].(map[string]any)
	if bw["size"] != float64(1<<20) || bw["refill_time_ms"] != float64(1000) {
		t.Fatalf("egress bandwidth = %v", bw)
	}
	if bw["one_time_burst"] != float64(512<<10) {
		t.Fatalf("egress bandwidth burst = %v", bw["one_time_burst"])
	}
	if _, present := egress["ops"]; present {
		t.Fatalf("nil ops bucket should be omitted: %v", egress)
	}

	ingress := rateLimiter["ingress"].(map[string]any)
	ops := ingress["ops"].(map[string]any)
	if ops["size"] != float64(1000) || ops["refill_time_ms"] != float64(100) {
		t.Fatalf("ingress ops = %v", ops)
	}
	// A zero burst must not reach the wire; the Rust side defaults it.
	if _, present := ops["one_time_burst"]; present {
		t.Fatalf("zero one_time_burst should be omitted: %v", ops)
	}
	if _, present := ingress["bandwidth"]; present {
		t.Fatalf("nil bandwidth bucket should be omitted: %v", ingress)
	}
}

// The Rust side relies on serde(default), so zero-valued Go scalar fields must
// not reach the wire. Explicit optional values use pointers when zero is valid
// on the wire for validation.
func TestFFIWireShape_EmptyConfigOmitsOptionalFields(t *testing.T) {
	got := marshalCreateOptions(t)

	for _, key := range []string{
		"image", "snapshot", "memory_mib", "cpus", "max_memory_mib", "max_cpus", "workdir", "shell",
		"thp",
		"hostname", "user", "replace", "detached", "env", "scripts",
		"ports", "ports_udp", "vsock", "network", "secrets", "patches", "volumes",
		"init", "registry_auth", "registry_insecure", "registry_ca_certs", "root_disk",
	} {
		if _, present := got[key]; present {
			body, _ := json.Marshal(got)
			t.Errorf("empty config emitted key %q; payload = %s", key, body)
		}
	}
}

func TestFFIWireShape_THPPolicy(t *testing.T) {
	got := marshalCreateOptions(t, WithImage("python:3.12"), WithTHP(THPAlways))
	if got["thp"] != "always" {
		t.Fatalf("thp = %v, want always", got["thp"])
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

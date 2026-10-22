package microsandbox

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRestoreDestinationControlsPreserveExplicitValues(t *testing.T) {
	var config RestoreConfig
	for _, option := range []RestoreOption{
		WithRestoreCPUs(2), WithRestoreMemory(512),
		WithRestoreNetworkPolicy(NetworkPolicy.FromProfiles(NetworkProfilePublic)),
		WithRestoreMaxConnections(0), WithRestoreDisableNetwork(),
		WithRestoreSecurityProfile(SecurityProfileDefault),
		WithRestoreMaxDuration(0), WithRestoreIdleTimeout(1500 * time.Millisecond),
	} {
		option(&config)
	}
	if err := validateRestoreConfig(config); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(buildFFIRestoreOptions("baseline", config))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	for field, want := range map[string]any{
		"cpus": float64(2), "memory_mib": float64(512), "max_connections": float64(0),
		"disable_network": true, "security_profile": "default",
		"max_duration_secs": float64(0), "idle_timeout_secs": float64(2),
	} {
		if got[field] != want {
			t.Errorf("%s = %#v, want %#v", field, got[field], want)
		}
	}
	policy := got["network_policy"].(map[string]any)
	if policy["default_egress"] != "deny" || len(policy["rules"].([]any)) == 0 {
		t.Fatalf("policy lost: %#v", policy)
	}
	for _, field := range []string{"image", "network", "cmd", "replace", "detached"} {
		if _, ok := got[field]; ok {
			t.Errorf("unexpected creation field %s", field)
		}
	}
}

func TestRestoreOmittedControlsRemainAbsent(t *testing.T) {
	encoded, err := json.Marshal(buildFFIRestoreOptions("baseline", RestoreConfig{}))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got["snapshot"] != "baseline" {
		t.Fatalf("omitted destination controls must not become defaults: %s", encoded)
	}
}

func TestRestoreConnectionLimitsPreserveExplicitZero(t *testing.T) {
	for _, tcp := range []struct {
		name   string
		field  string
		option RestoreOption
	}{
		{"canonical", "max_tcp_connections", WithRestoreMaxTCPConnections(0)},
		{"legacy", "max_connections", WithRestoreMaxConnections(0)},
	} {
		t.Run(tcp.name, func(t *testing.T) {
			var config RestoreConfig
			tcp.option(&config)
			WithRestoreMaxUDPConnections(0)(&config)
			if err := validateRestoreConfig(config); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(buildFFIRestoreOptions("baseline", config))
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]any
			if err := json.Unmarshal(encoded, &got); err != nil {
				t.Fatal(err)
			}
			if len(got) != 3 || got[tcp.field] != float64(0) || got["max_udp_connections"] != float64(0) {
				t.Fatalf("connection limits lost or unexpected aliases emitted: %s", encoded)
			}
		})
	}
}

func TestRestorePublishedTCPConfigurationReachesFFI(t *testing.T) {
	var config RestoreConfig
	WithRestoreTCPAcceptQueueSize(4096)(&config)
	WithRestoreMaxInboundTCPConnections(0)(&config)
	encoded, err := json.Marshal(buildFFIRestoreOptions("baseline", config))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if got["max_inbound_tcp_connections"] != float64(0) {
		t.Fatalf("published TCP overrides lost: %s", encoded)
	}
	if got["tcp_accept_queue_size"] != float64(4096) {
		t.Fatalf("tcp_accept_queue_size lost: %s", encoded)
	}

	encoded, err = json.Marshal(buildFFIRestoreOptions("baseline", RestoreConfig{}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "tcp_accept_queue_size") {
		t.Fatalf("unset accept queue size reached the wire: %s", encoded)
	}
}

func TestRestoreDiskVolumeReachesFFI(t *testing.T) {
	config := RestoreConfig{Volumes: map[string]MountConfig{
		"/data2": Mount.Disk("/images/seed.img", DiskOptions{Fstype: "ext4", Readonly: true}),
	}}
	encoded, err := json.Marshal(buildFFIRestoreOptions("baseline", config))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Volumes map[string]map[string]any `json:"volumes"`
	}
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	disk := got.Volumes["/data2"]
	if disk["disk"] != "/images/seed.img" || disk["fstype"] != "ext4" || disk["readonly"] != true {
		t.Fatalf("disk volume lost: %s", encoded)
	}
}

func TestRestoreRejectsDuplicateTCPAliasesBeforeFFI(t *testing.T) {
	// Matching values are also ambiguous: reject both spellings instead of
	// letting option order silently select which limit reaches the runtime.
	for _, canonical := range []uint{0, 64} {
		var config RestoreConfig
		WithRestoreMaxConnections(0)(&config)
		WithRestoreMaxTCPConnections(canonical)(&config)
		if err := validateRestoreConfig(config); err == nil || !strings.Contains(err.Error(), "MaxConnections and MaxTCPConnections") {
			t.Fatalf("duplicate TCP aliases must fail validation: %v", err)
		}
		if _, err := RestoreSandbox(context.Background(), "baseline", "child", WithRestoreConfig(config)); err == nil {
			t.Fatal("restore must reject duplicate TCP aliases before FFI")
		}
		_, result := RestoreSandboxWithProgress(context.Background(), "baseline", "child", WithRestoreConfig(config))
		if outcome := <-result; outcome.Err == nil {
			t.Fatal("progress restore must reject duplicate TCP aliases before FFI")
		}
	}
}

func TestRestoreRejectsBroadNetworkOptionsBeforeFFI(t *testing.T) {
	zero := uint(0)
	for _, policy := range []*NetworkConfig{
		{TLS: &TLSConfig{}}, {DNS: &DNSConfig{}}, {Ports: map[uint16]uint16{8080: 80}},
		{IPv4Pool: "10.0.0.0/8"}, {DenyDomains: []string{"example.com"}},
		{MaxConnections: &zero}, {MaxTCPConnections: &zero}, {MaxUDPConnections: &zero},
	} {
		config := RestoreConfig{NetworkPolicy: policy}
		if err := validateRestoreConfig(config); err == nil {
			t.Fatalf("accepted %#v", policy)
		}
		if _, err := RestoreSandbox(context.Background(), "baseline", "child", WithRestoreConfig(config)); err == nil {
			t.Fatal("restore must reject before entering FFI")
		}
		_, result := RestoreSandboxWithProgress(context.Background(), "baseline", "child", WithRestoreConfig(config))
		if outcome := <-result; outcome.Err == nil {
			t.Fatal("progress restore must reject before FFI")
		}
	}
}

func TestRestoreRejectsNegativeLifetimes(t *testing.T) {
	for _, option := range []RestoreOption{WithRestoreMaxDuration(-1), WithRestoreIdleTimeout(-1)} {
		var config RestoreConfig
		option(&config)
		if err := validateRestoreConfig(config); err == nil {
			t.Fatal("negative duration accepted")
		}
	}
}

func TestForkDiskVolumeReachesFFI(t *testing.T) {
	diskPath := filepath.Join(t.TempDir(), "seed.img")
	var options forkOptions
	WithForkVolumes(map[string]MountConfig{
		"/data": Mount.Disk(diskPath, DiskOptions{Fstype: "ext4", Readonly: true}),
	})(&options)
	volumes, err := ffiForkVolumes(options.volumes)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(volumes)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]map[string]any
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	disk := got["/data"]
	if disk["disk"] != diskPath || disk["fstype"] != "ext4" || disk["readonly"] != true {
		t.Fatalf("disk volume lost: %s", encoded)
	}
	if volumes, err := ffiForkVolumes(nil); volumes != nil || err != nil {
		t.Fatalf("no volumes encoded as %v, %v", volumes, err)
	}
	owned := map[string]MountConfig{"/data": Mount.Owned(OwnedVolumeOptions{Kind: VolumeKindDisk})}
	if _, err := ffiForkVolumes(owned); err == nil {
		t.Fatal("invalid owned mount was accepted")
	}
}

func TestForkVolumesAnchorRelativeHostPaths(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	absoluteDisk := filepath.Join(cwd, "abs", "seed.img")
	volumes, err := ffiForkVolumes(map[string]MountConfig{
		"/data":   Mount.Disk("images/seed.img", DiskOptions{}),
		"/shared": Mount.Bind("shared", MountOptions{}),
		"/cache":  Mount.Named("cache", MountOptions{}),
		"/abs":    Mount.Disk(absoluteDisk, DiskOptions{}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := volumes["/data"].Disk, filepath.Join(cwd, "images/seed.img"); got != want {
		t.Fatalf("disk path = %q, want %q", got, want)
	}
	if got, want := volumes["/shared"].Bind, filepath.Join(cwd, "shared"); got != want {
		t.Fatalf("bind path = %q, want %q", got, want)
	}
	if got := volumes["/cache"].Named; got != "cache" {
		t.Fatalf("named volume = %q, want cache", got)
	}
	if got := volumes["/abs"].Disk; got != absoluteDisk {
		t.Fatalf("absolute disk path = %q, want %q", got, absoluteDisk)
	}
}

func TestForkVolumesPreserveSymlinkParentPaths(t *testing.T) {
	if filepath.Separator == '\\' {
		t.Skip("Windows resolves parent components lexically")
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.MkdirAll(filepath.Join(target, "child"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "seed.img"), []byte("through-link"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "seed.img"), []byte("wrong-image"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(filepath.Join(target, "child"), link); err != nil {
		t.Fatal(err)
	}
	relativeLink, err := filepath.Rel(cwd, link)
	if err != nil {
		t.Fatal(err)
	}
	for _, hostPath := range []string{relativeLink + "/../seed.img", link + "/../seed.img"} {
		volumes, err := ffiForkVolumes(map[string]MountConfig{
			"/data":   Mount.Disk(hostPath, DiskOptions{}),
			"/shared": Mount.Bind(hostPath, MountOptions{}),
		})
		if err != nil {
			t.Fatal(err)
		}
		want := hostPath
		if !filepath.IsAbs(want) {
			want = strings.TrimSuffix(cwd, "/") + "/" + want
		}
		for _, got := range []string{volumes["/data"].Disk, volumes["/shared"].Bind} {
			if got != want {
				t.Fatalf("host path = %q, want %q", got, want)
			}
			data, err := os.ReadFile(got)
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != "through-link" {
				t.Fatalf("host path %q opened %q, want through-link", got, data)
			}
		}
	}
}

func TestRestoreGuestClockPresenceAndValidation(t *testing.T) {
	for _, policy := range []GuestClockPolicy{"", GuestClockSync, GuestClockOff} {
		var config RestoreConfig
		WithRestoreGuestClock(policy)(&config)
		if err := validateRestoreConfig(config); err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(buildFFIRestoreOptions("baseline", config))
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]any
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatal(err)
		}
		value, present := fields["guest_clock"]
		if policy == "" && present {
			t.Fatal("omission became an override")
		}
		if policy != "" && (!present || value != string(policy)) {
			t.Fatalf("lost policy: %s", raw)
		}
	}
	if err := validateRestoreConfig(RestoreConfig{GuestClock: "invalid"}); err == nil {
		t.Fatal("accepted invalid policy")
	}
}

func TestRestoreBootOptionsRetainExplicitEmptyHostnameAndInit(t *testing.T) {
	var config RestoreConfig
	WithRestoreInit(Init.Cmd("/bin/sh", InitOptions{Args: []string{"-c", "exec sleep 300"}, Env: map[string]string{"KEY": "value"}}))(&config)
	WithRestoreHostname("")(&config)
	options := buildFFIRestoreOptions("saved", config)
	if options.Hostname == nil || *options.Hostname != "" {
		t.Fatal("explicit empty hostname was dropped")
	}
	if options.Init == nil || options.Init.Cmd != "/bin/sh" || len(options.Init.Args) != 2 || len(options.Init.Env) != 1 || options.Init.Env[0] != [2]string{"KEY", "value"} {
		t.Fatalf("init changed: %+v", options.Init)
	}
	// Conversion owns argv; later caller edits cannot change the deferred native request.
	config.Init.Args[0] = "changed"
	if options.Init.Args[0] != "-c" {
		t.Fatal("init argv retained caller backing")
	}
}

func TestRestoreCeilingsRetainOmissionAndExplicitZero(t *testing.T) {
	for _, value := range []uint32{0, 512} {
		var config RestoreConfig
		WithRestoreMaxCPUs(uint8(value / 256))(&config)
		WithRestoreMaxMemory(value)(&config)
		raw, err := json.Marshal(buildFFIRestoreOptions("saved", config))
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]any
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatal(err)
		}
		if got["max_cpus"] != float64(value/256) || got["max_memory_mib"] != float64(value) {
			t.Fatalf("explicit ceilings changed: %s", raw)
		}
	}
	raw, err := json.Marshal(buildFFIRestoreOptions("saved", RestoreConfig{}))
	if err != nil {
		t.Fatal(err)
	}
	var omitted map[string]any
	if err := json.Unmarshal(raw, &omitted); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"max_cpus", "max_memory_mib"} {
		if _, found := omitted[key]; found {
			t.Fatalf("omission became a ceiling: %s", raw)
		}
	}
}

func TestRestoreDestinationLabelsPreserveExplicitAndOmittedValues(t *testing.T) {
	config := RestoreConfig{}
	for _, option := range []RestoreOption{WithRestoreLabel("team", "first"), WithRestoreLabel("team", "last")} {
		option(&config)
	}
	raw, err := json.Marshal(buildFFIRestoreOptions("saved", config))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got["labels"].(map[string]any)["team"] != "last" {
		t.Fatalf("destination options lost: %s", raw)
	}
	raw, err = json.Marshal(buildFFIRestoreOptions("saved", RestoreConfig{}))
	if err != nil {
		t.Fatal(err)
	}
	got = nil
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"labels"} {
		if _, ok := got[key]; ok {
			t.Fatalf("omitted option became explicit: %s", raw)
		}
	}
}

func TestRestoreCommandDefaultsPreserveEmptyAndOmittedValues(t *testing.T) {
	var config RestoreConfig
	for _, option := range []RestoreOption{WithRestoreWorkdir("/root"), WithRestoreShell("/bin/ash"), WithRestoreEntrypoint(), WithRestoreCmd(), WithRestoreEnv("KEY", "")} {
		option(&config)
	}
	var empty []string
	for _, argv := range []*[]string{config.Cmd, &empty} {
		config.Cmd = argv
		data, err := json.Marshal(buildFFIRestoreOptions("source", config))
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"cmd", "entrypoint"} {
			if string(fields[field]) != "[]" {
				t.Fatalf("%s lost empty intent: %s", field, data)
			}
		}
		if string(fields["env"]) != `{"KEY":""}` || string(fields["workdir"]) != `"/root"` || string(fields["shell"]) != `"/bin/ash"` {
			t.Fatal(string(data))
		}
	}
}

func TestRestoreProxyKeepsDestinationCredentialReference(t *testing.T) {
	var config RestoreConfig
	WithRestoreProxy(SOCKS5Proxy("127.0.0.1:1080").Credentials("destination", SecretSourceEnv("DEST_PROXY_PASSWORD")))(&config)
	proxy := buildFFIRestoreOptions("saved", config).Proxy
	if proxy == nil || proxy.Protocol != "socks5" || proxy.Username == nil || *proxy.Username != "destination" || proxy.PasswordSource == nil || proxy.PasswordSource.Var != "DEST_PROXY_PASSWORD" {
		t.Fatal("destination proxy or unresolved credential source was lost")
	}
	if buildFFIRestoreOptions("saved", RestoreConfig{}).Proxy != nil {
		t.Fatal("omitted destination proxy must remain absent")
	}
}

func TestRestorePullPolicyPreservesExistingValues(t *testing.T) {
	for _, policy := range []PullPolicy{PullPolicyDefault, PullPolicyAlways, PullPolicyIfMissing, PullPolicyNever} {
		var options RestoreConfig
		WithRestorePullPolicy(policy)(&options)
		wire := buildFFIRestoreOptions("saved", options)
		if wire.PullPolicy != string(policy) || wire.Snapshot != "saved" {
			t.Fatal("pull policy changed the snapshot selection")
		}
	}
}

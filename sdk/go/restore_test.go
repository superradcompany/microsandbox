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

func TestRestoreTCPAcceptQueueSizeReachesFFI(t *testing.T) {
	var config RestoreConfig
	WithRestoreTCPAcceptQueueSize(4096)(&config)
	encoded, err := json.Marshal(buildFFIRestoreOptions("baseline", config))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
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

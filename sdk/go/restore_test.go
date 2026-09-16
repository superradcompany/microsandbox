package microsandbox

import (
	"context"
	"encoding/json"
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

func TestRestoreRejectsBroadNetworkOptionsBeforeFFI(t *testing.T) {
	for _, policy := range []*NetworkConfig{
		{TLS: &TLSConfig{}}, {DNS: &DNSConfig{}}, {Ports: map[uint16]uint16{8080: 80}},
		{IPv4Pool: "10.0.0.0/8"}, {DenyDomains: []string{"example.com"}},
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

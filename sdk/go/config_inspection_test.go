package microsandbox

import (
	"encoding/json"
	"testing"
)

func TestRemoteInspectionPreservesUnavailableAndRuntime(t *testing.T) {
	var view SandboxConfigInspection
	err := json.Unmarshal([]byte(`{"kind":"remote","name":"task","spec":{"image":null,"resources":{"vcpus":2,"memory_mib":512},"runtime":{"shell":"/bin/bash","cmd":["ready"],"workdir":"/tmp"},"mounts":[{"type":"Named","guest":"/data"}],"network":{"secrets":[{"env_var":"TOKEN","placeholder":"placeholder"}]}},"unavailable":["image","init"],"redacted":["mounts[0].source","network.secrets[0].value"]}`), &view)
	if err != nil {
		t.Fatal(err)
	}
	if view.Kind != "remote" || view.Spec.Resources.CPUs != nil || view.Spec.Resources.VCPUs == nil || *view.Spec.Resources.VCPUs != 2 {
		t.Fatal("resource availability lost")
	}
	if view.Spec.Runtime.Shell == nil || *view.Spec.Runtime.Shell != "/bin/bash" || view.Spec.Runtime.Cmd[0] != "ready" {
		t.Fatal("runtime settings lost")
	}
	if string(view.Spec.Image) != "null" || len(view.Unavailable) != 2 || len(view.Redacted) != 2 {
		t.Fatal("redaction lost")
	}
	if _, ok := view.Spec.Mounts[0]["source"]; ok {
		t.Fatal("invented mount source")
	}
}

// Local-only fields remain observable without claiming that remote projections
// contain the same data or that observations can be replayed as creation input.
func TestLocalInspectionPreservesPersistedFields(t *testing.T) {
	var view SandboxConfigInspection
	err := json.Unmarshal([]byte(`{"kind":"local","name":"task","spec":{"image":{"Oci":{"reference":"alpine"}},"resources":{"cpus":2,"memory_mib":512,"cpu_placement":"spread","placement_profile":"batch","nested_virt":false},"runtime":{"guest_clock":"off"},"deployment_profile":"single_tenant","vsock":{"services":[]},"init":null},"unavailable":[],"redacted":[]}`), &view)
	if err != nil {
		t.Fatal(err)
	}
	if view.Spec.Resources.VCPUs != nil || view.Spec.Resources.CPUs == nil || *view.Spec.Resources.CPUs != 2 {
		t.Fatal("local capacity lost")
	}
	if view.Spec.Resources.NestedVirt == nil || *view.Spec.Resources.NestedVirt {
		t.Fatal("explicit false lost")
	}
	if view.Spec.Resources.PlacementProfile == nil || *view.Spec.Resources.PlacementProfile != "batch" || view.Spec.DeploymentProfile == nil || view.Spec.Vsock == nil {
		t.Fatal("local settings lost")
	}
	if view.Spec.Runtime.GuestClock == nil || *view.Spec.Runtime.GuestClock != "off" {
		t.Fatal("guest clock lost")
	}
}

func TestInspectedPoliciesUsePublicTypes(t *testing.T) {
	for persisted, expected := range map[string]PullPolicy{
		"Always": PullPolicyAlways, "IfMissing": PullPolicyIfMissing, "Never": PullPolicyNever,
	} {
		var spec SandboxInspectionSpec
		if err := json.Unmarshal([]byte(`{"pull_policy":"`+persisted+`","runtime":{"log_level":"warn"}}`), &spec); err != nil {
			t.Fatal(err)
		}
		if spec.PullPolicy == nil || *spec.PullPolicy != expected || spec.Runtime.LogLevel == nil || *spec.Runtime.LogLevel != LogLevelWarn {
			t.Fatalf("invalid typed inspection for %q: %+v", persisted, spec)
		}
	}
	var view SandboxConfigInspection
	if err := json.Unmarshal([]byte(`{"kind":"remote","spec":{"runtime":{"log_level":null}}}`), &view); err != nil {
		t.Fatal(err)
	}
	if view.Spec.PullPolicy != nil || view.Spec.Runtime.LogLevel != nil {
		t.Fatal("unset inspection settings acquired defaults")
	}
}

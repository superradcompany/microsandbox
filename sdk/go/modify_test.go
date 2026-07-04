package microsandbox

import (
	"encoding/json"
	"testing"
)

func marshalModifyRequest(t *testing.T, opts ModifyOptions) map[string]any {
	t.Helper()
	raw, err := buildModifyRequestJSON(opts)
	if err != nil {
		t.Fatalf("buildModifyRequestJSON: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

func TestModifyRequestJSONEmptyOptions(t *testing.T) {
	out := marshalModifyRequest(t, ModifyOptions{})

	patch, ok := out["patch"].(map[string]any)
	if !ok {
		t.Fatalf("expected patch object; got %v", out)
	}
	if len(patch) != 0 {
		t.Fatalf("expected empty patch; got %v", patch)
	}
	if _, present := out["policy"]; present {
		t.Fatalf("expected policy omitted; got %v", out)
	}
	if _, present := out["dry_run"]; present {
		t.Fatalf("expected dry_run omitted; got %v", out)
	}
}

func TestModifyRequestJSONFullOptions(t *testing.T) {
	out := marshalModifyRequest(t, ModifyOptions{
		CPUs:         2,
		MaxCPUs:      8,
		MemoryMiB:    1024,
		MaxMemoryMiB: 4096,
		Env:          map[string]string{"B": "2", "A": "1"},
		EnvRemove:    []string{"OLD"},
		Labels:       map[string]string{"tier": "gold", "app": "api"},
		LabelsRemove: []string{"stale"},
		Workdir:      "/srv",
		Policy:       ModificationPolicyRestart,
		DryRun:       true,
	})

	if out["policy"] != "restart" {
		t.Fatalf("policy = %v", out["policy"])
	}
	if out["dry_run"] != true {
		t.Fatalf("dry_run = %v", out["dry_run"])
	}

	patch := out["patch"].(map[string]any)
	if patch["cpus"] != float64(2) || patch["max_cpus"] != float64(8) {
		t.Fatalf("cpus fields = %v / %v", patch["cpus"], patch["max_cpus"])
	}
	if patch["memory_mib"] != float64(1024) || patch["max_memory_mib"] != float64(4096) {
		t.Fatalf("memory fields = %v / %v", patch["memory_mib"], patch["max_memory_mib"])
	}
	if patch["workdir"] != "/srv" {
		t.Fatalf("workdir = %v", patch["workdir"])
	}

	// Env and labels are emitted in sorted key order.
	env := patch["env"].([]any)
	if len(env) != 2 {
		t.Fatalf("env = %v", env)
	}
	first := env[0].(map[string]any)
	if first["key"] != "A" || first["value"] != "1" {
		t.Fatalf("env[0] = %v", first)
	}
	labels := patch["labels"].([]any)
	if len(labels) != 2 {
		t.Fatalf("labels = %v", labels)
	}
	firstLabel := labels[0].([]any)
	if firstLabel[0] != "app" || firstLabel[1] != "api" {
		t.Fatalf("labels[0] = %v", firstLabel)
	}

	envRemove := patch["env_remove"].([]any)
	if len(envRemove) != 1 || envRemove[0] != "OLD" {
		t.Fatalf("env_remove = %v", envRemove)
	}
	labelsRemove := patch["labels_remove"].([]any)
	if len(labelsRemove) != 1 || labelsRemove[0] != "stale" {
		t.Fatalf("labels_remove = %v", labelsRemove)
	}
}

func TestParseModificationPlan(t *testing.T) {
	raw := `{
		"sandbox": "api",
		"status": "running",
		"applied": false,
		"policy": "no_restart",
		"changes": [
			{
				"kind": "config",
				"field": "cpus",
				"change": "updated",
				"before": "2",
				"after": "4",
				"disposition": "live"
			},
			{
				"kind": "secret",
				"field": "secret",
				"name": "API_KEY",
				"change": "rotated",
				"before_ref": "$API_KEY",
				"after_ref": "$API_KEY",
				"disposition": "requires restart",
				"allow_hosts": ["api.example.com"]
			}
		],
		"conflicts": [{"field": "memory", "message": "memory must be greater than 0"}],
		"warnings": []
	}`

	plan, err := parseModificationPlan(raw)
	if err != nil {
		t.Fatalf("parseModificationPlan: %v", err)
	}
	if plan.Sandbox != "api" || plan.Status != "running" || plan.Applied {
		t.Fatalf("plan header = %+v", plan)
	}
	if plan.Policy != ModificationPolicyNoRestart {
		t.Fatalf("policy = %q", plan.Policy)
	}
	if len(plan.Changes) != 2 {
		t.Fatalf("changes = %+v", plan.Changes)
	}

	config := plan.Changes[0]
	if config.Kind != "config" || config.Field != "cpus" || config.Change != "updated" {
		t.Fatalf("config change = %+v", config)
	}
	if config.Before == nil || *config.Before != "2" || config.After == nil || *config.After != "4" {
		t.Fatalf("config before/after = %+v", config)
	}
	if config.Disposition != "live" {
		t.Fatalf("config disposition = %q", config.Disposition)
	}

	secret := plan.Changes[1]
	if secret.Kind != "secret" || secret.Name != "API_KEY" || secret.Change != "rotated" {
		t.Fatalf("secret change = %+v", secret)
	}
	if len(secret.AllowHosts) != 1 || secret.AllowHosts[0] != "api.example.com" {
		t.Fatalf("secret allow_hosts = %+v", secret.AllowHosts)
	}

	if len(plan.Conflicts) != 1 || plan.Conflicts[0].Field != "memory" {
		t.Fatalf("conflicts = %+v", plan.Conflicts)
	}
	if len(plan.ResizeStatus) != 0 {
		t.Fatalf("resize status = %+v", plan.ResizeStatus)
	}
}

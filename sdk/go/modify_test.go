package microsandbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
		CPUs:            2,
		MaxCPUs:         8,
		MemoryMiB:       1024,
		MaxMemoryMiB:    4096,
		RootDiskSizeMiB: 8192,
		Env:             map[string]string{"B": "2", "A": "1"},
		EnvRemove:       []string{"OLD"},
		Labels:          map[string]string{"tier": "gold", "app": "api"},
		LabelsRemove:    []string{"stale"},
		Workdir:         "/srv",
		Policy:          ModificationPolicyRestart,
		DryRun:          true,
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
	if patch["root_disk_size_mib"] != float64(8192) {
		t.Fatalf("root_disk_size_mib = %v", patch["root_disk_size_mib"])
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

func TestModifyRequestJSONSecretSources(t *testing.T) {
	out := marshalModifyRequest(t, ModifyOptions{
		Secrets: map[string]SecretModifySpec{
			// Deliberately unsorted; entries must serialize in name order.
			"STRIPE_KEY": {Value: "sk_test_123"},
			"API_KEY": {
				Env:          "HOST_API_KEY",
				Placeholder:  "$API_KEY",
				AllowedHosts: []string{"api.example.com"},
			},
			"DB_PASS": {Store: "vault://prod/db"},
		},
		SecretsRemove: []string{"OLD"},
	})

	patch := out["patch"].(map[string]any)
	secrets := patch["secrets"].([]any)
	if len(secrets) != 3 {
		t.Fatalf("expected 3 secrets; got %d", len(secrets))
	}

	// Env-sourced entry, first in sorted order.
	apiKey := secrets[0].(map[string]any)
	if apiKey["name"] != "API_KEY" {
		t.Fatalf("secrets[0] name = %v", apiKey["name"])
	}
	source := apiKey["source"].(map[string]any)
	if source["kind"] != "env" || source["var"] != "HOST_API_KEY" {
		t.Fatalf("env source = %v", source)
	}
	if _, present := source["reference"]; present {
		t.Fatalf("env source must omit reference; got %v", source)
	}
	if apiKey["placeholder"] != "$API_KEY" {
		t.Fatalf("placeholder = %v", apiKey["placeholder"])
	}
	hosts := apiKey["allowed_hosts"].([]any)
	if len(hosts) != 1 || hosts[0] != "api.example.com" {
		t.Fatalf("allowed_hosts = %v", hosts)
	}
	if _, present := apiKey["value"]; present {
		t.Fatalf("empty value must be omitted from the wire")
	}

	// Store-sourced entry.
	dbPass := secrets[1].(map[string]any)
	if dbPass["name"] != "DB_PASS" {
		t.Fatalf("secrets[1] name = %v", dbPass["name"])
	}
	source = dbPass["source"].(map[string]any)
	if source["kind"] != "store" || source["reference"] != "vault://prod/db" {
		t.Fatalf("store source = %v", source)
	}
	if _, present := source["var"]; present {
		t.Fatalf("store source must omit var; got %v", source)
	}

	// Value-sourced entry: value serializes as a plain string, no source.
	stripe := secrets[2].(map[string]any)
	if stripe["name"] != "STRIPE_KEY" {
		t.Fatalf("secrets[2] name = %v", stripe["name"])
	}
	if _, present := stripe["source"]; present {
		t.Fatalf("value-sourced entry must omit source")
	}
	if stripe["value"] != "sk_test_123" {
		t.Fatalf("value field mismatch")
	}

	remove := patch["secrets_remove"].([]any)
	if len(remove) != 1 || remove[0] != "OLD" {
		t.Fatalf("secrets_remove = %v", remove)
	}
}

func TestModifyRequestJSONSecretMutualExclusion(t *testing.T) {
	for _, spec := range []SecretModifySpec{
		{Env: "HOST_VAR", Value: "sk_test_123"},
		{Value: "sk_test_123", Store: "vault://ref"},
		{Env: "HOST_VAR", Store: "vault://ref"},
		{Env: "HOST_VAR", Value: "sk_test_123", Store: "vault://ref"},
	} {
		_, err := buildModifyRequestJSON(ModifyOptions{
			Secrets: map[string]SecretModifySpec{"STRIPE_KEY": spec},
		})
		if err == nil {
			t.Fatalf("expected mutual-exclusion error")
		}
		if !strings.Contains(err.Error(), `secret "STRIPE_KEY"`) {
			t.Fatalf("error must name the secret; got %v", err)
		}
		// The raw secret material must never leak into error messages.
		if strings.Contains(err.Error(), "sk_test_123") {
			t.Fatalf("error message leaks the secret value")
		}
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

func TestModifyRequestJSONMounts(t *testing.T) {
	out := marshalModifyRequest(t, ModifyOptions{
		Mounts: map[string]MountConfig{
			// Entries serialize in guest-path order.
			"/tmp/scratch": Mount.Tmpfs(TmpfsOptions{SizeMiB: 64, Noexec: true}),
			"/data":        Mount.Named("shared", MountOptions{Readonly: true}),
			"/code": Mount.Bind("/srv/code", MountOptions{
				StatVirtualization: StatVirtualizationRelaxed,
				Owner:              &MountOwner{UID: 1000, GID: 1000},
				QuotaMiB:           512,
			}),
			"/disk": Mount.Disk("/srv/data.qcow2", DiskOptions{Fstype: "ext4"}),
		},
		MountsRemove: []string{"/old"},
	})

	patch := out["patch"].(map[string]any)
	mounts := patch["mounts"].([]any)
	if len(mounts) != 4 {
		t.Fatalf("expected 4 mounts; got %d", len(mounts))
	}
	want := []string{"/code", "/data", "/disk", "/tmp/scratch"}
	for i, guest := range want {
		if got := mounts[i].(map[string]any)["guest"]; got != guest {
			t.Fatalf("mounts[%d] guest = %v; want %s", i, got, guest)
		}
	}

	bind := mounts[0].(map[string]any)
	options := bind["options"].(map[string]any)
	if bind["type"] != "Bind" || bind["host"] != "/srv/code" || bind["quota_mib"] != float64(512) ||
		bind["stat_virtualization"] != "relaxed" || options["override_uid"] != float64(1000) {
		t.Fatalf("bind mount = %v", bind)
	}
	named := mounts[1].(map[string]any)
	if named["type"] != "Named" || named["name"] != "shared" ||
		named["options"].(map[string]any)["readonly"] != true {
		t.Fatalf("named mount = %v", named)
	}
	disk := mounts[2].(map[string]any)
	if disk["type"] != "DiskImage" || disk["format"] != "Qcow2" || disk["fstype"] != "ext4" {
		t.Fatalf("disk mount = %v", disk)
	}
	tmpfs := mounts[3].(map[string]any)
	if tmpfs["type"] != "Tmpfs" || tmpfs["size_mib"] != float64(64) ||
		tmpfs["options"].(map[string]any)["noexec"] != true {
		t.Fatalf("tmpfs mount = %v", tmpfs)
	}

	removals := patch["mounts_remove"].([]any)
	if len(removals) != 1 || removals[0] != "/old" {
		t.Fatalf("mounts_remove = %v", removals)
	}
}

func TestModifyRequestJSONOmitsEmptyMounts(t *testing.T) {
	out := marshalModifyRequest(t, ModifyOptions{Mounts: map[string]MountConfig{}})
	patch := out["patch"].(map[string]any)
	for _, key := range []string{"mounts", "mounts_remove"} {
		if _, present := patch[key]; present {
			t.Fatalf("expected %s omitted; got %v", key, patch)
		}
	}
}

func TestModifyRequestRejectsOwnedMount(t *testing.T) {
	_, err := buildModifyRequestJSON(ModifyOptions{
		Mounts: map[string]MountConfig{"/scratch": Mount.Owned(OwnedVolumeOptions{})},
	})
	if err == nil || !strings.Contains(err.Error(), "/scratch") {
		t.Fatalf("expected owned mount rejection naming /scratch; got %v", err)
	}
}

func TestCheckModifyMountsSkipsNativeLibraryWithoutMounts(t *testing.T) {
	if err := checkModifyMounts(ModifyOptions{Env: map[string]string{"A": "1"}}); err != nil {
		t.Fatalf("checkModifyMounts: %v", err)
	}
}

func TestModifyRequestDiskFormatInference(t *testing.T) {
	cases := []struct{ host, format, want string }{
		{"/srv/a.qcow2", "", "Qcow2"},
		{"/srv/a.vmdk", "", "Vmdk"},
		{"/srv/a.img", "", "Raw"},
		{"/srv/a", "", "Raw"},
		// Extension matching is case-sensitive, as in the core builder.
		{"/srv/a.QCOW2", "", "Raw"},
		// A bare dotfile has no extension.
		{"/srv/.qcow2", "", "Raw"},
		{"/srv/a.img", "qcow2", "Qcow2"},
		{"/srv/a.qcow2", "raw", "Raw"},
	}
	for _, c := range cases {
		got, err := diskImageFormat(c.format, c.host)
		if err != nil || got != c.want {
			t.Errorf("diskImageFormat(%q, %q) = %q, %v; want %q", c.format, c.host, got, err, c.want)
		}
	}
}

func TestModifyRequestRejectsUnknownDiskFormat(t *testing.T) {
	for _, format := range []string{"QCOW2", "iso"} {
		_, err := buildModifyRequestJSON(ModifyOptions{
			Mounts: map[string]MountConfig{"/disk": Mount.Disk("/srv/a.img", DiskOptions{Format: format})},
		})
		if err == nil || !strings.Contains(err.Error(), "/disk") ||
			!strings.Contains(err.Error(), "unknown disk image format: "+format) {
			t.Fatalf("format %q: expected a rejection naming /disk; got %v", format, err)
		}
	}
}

func TestModifyRequestRejectsOptionsThatDoNotFitTheMountKind(t *testing.T) {
	cases := map[string]MountConfig{
		"bind size":    {kind: MountKindBind, Bind: "/srv", SizeMiB: 64},
		"bind format":  {kind: MountKindBind, Bind: "/srv", Format: "raw"},
		"named fstype": {kind: MountKindNamed, Named: "v", Fstype: "ext4"},
		"tmpfs stat":   {kind: MountKindTmpfs, Tmpfs: true, StatVirtualization: StatVirtualizationRelaxed},
		"tmpfs perms":  {kind: MountKindTmpfs, Tmpfs: true, HostPermissions: HostPermissionsMirror},
		"tmpfs owner":  {kind: MountKindTmpfs, Tmpfs: true, Owner: &MountOwner{UID: 1, GID: 1}},
		"tmpfs quota":  {kind: MountKindTmpfs, Tmpfs: true, QuotaMiB: 64},
		"disk quota":   {kind: MountKindDisk, Disk: "/srv/a.img", QuotaMiB: 64},
		"disk stat":    {kind: MountKindDisk, Disk: "/srv/a.img", StatVirtualization: StatVirtualizationOff},
	}
	for name, mount := range cases {
		_, err := buildModifyRequestJSON(ModifyOptions{Mounts: map[string]MountConfig{"/m": mount}})
		if err == nil || !strings.Contains(err.Error(), `"/m"`) {
			t.Errorf("%s: expected a rejection naming /m; got %v", name, err)
		}
	}

}

func TestModifyRequestAcceptsOnlyPlainNamedMounts(t *testing.T) {
	plain := map[string]MountConfig{
		"factory":       Mount.Named("v", MountOptions{}),
		"existing":      Mount.NamedWith("v", MountOptions{}, NamedVolumeOptions{Mode: "existing", Kind: "dir"}),
		"ensure-exists": Mount.NamedWith("v", MountOptions{}, NamedVolumeOptions{Mode: "ensure-exists"}),
	}
	configured := map[string]MountConfig{
		"create": Mount.NamedWith("v", MountOptions{}, NamedVolumeOptions{Mode: "create"}),
		"disk":   Mount.NamedWith("v", MountOptions{}, NamedVolumeOptions{Kind: "disk", SizeMiB: 64}),
		"quota":  Mount.NamedWith("v", MountOptions{}, NamedVolumeOptions{QuotaMiB: 64}),
	}

	for name, mount := range plain {
		_, err := buildModifyRequestJSON(ModifyOptions{Mounts: map[string]MountConfig{"/m": mount}})

		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, mount := range configured {
		_, err := buildModifyRequestJSON(ModifyOptions{Mounts: map[string]MountConfig{"/m": mount}})

		if err == nil || !strings.Contains(err.Error(), "modify does not create or configure named volumes") {
			t.Errorf("%s: expected a refusal; got %v", name, err)
		}
	}
}

func TestCheckModifyMountsRefusesAnOlderNativeLibrary(t *testing.T) {
	original := modifyMountsSupported
	t.Cleanup(func() { modifyMountsSupported = original })
	modifyMountsSupported = func() (bool, error) { return false, nil }

	mount := map[string]MountConfig{"/scratch": Mount.Tmpfs(TmpfsOptions{SizeMiB: 64})}
	for _, opts := range []ModifyOptions{
		{Mounts: mount},
		{MountsRemove: []string{"/old"}},
		{Env: map[string]string{"A": "1"}, Mounts: mount},
	} {
		err := checkModifyMounts(opts)
		if err == nil || !strings.Contains(err.Error(), "does not support modifying mounts") {
			t.Fatalf("expected an older-library refusal for %+v; got %v", opts, err)
		}
	}
	if err := checkModifyMounts(ModifyOptions{Env: map[string]string{"A": "1"}}); err != nil {
		t.Fatalf("ordinary modify refused: %v", err)
	}

	modifyMountsSupported = func() (bool, error) { return true, nil }
	if err := checkModifyMounts(ModifyOptions{Mounts: mount}); err != nil {
		t.Fatalf("supported library refused: %v", err)
	}
}

func TestModifyPortWireDefaultsAndExplicitRemoval(t *testing.T) {
	out := marshalModifyRequest(t, ModifyOptions{
		Ports:       []PortBinding{{HostPort: 8080, GuestPort: 80}},
		PortsRemove: []PortEndpoint{{Bind: "::1", HostPort: 5353, Protocol: PortProtocolUDP}},
	})
	patch := out["patch"].(map[string]any)
	port := patch["ports"].([]any)[0].(map[string]any)
	if port["host_bind"] != "127.0.0.1" || port["protocol"] != "tcp" || port["guest_port"] != float64(80) {
		t.Fatalf("unexpected port wire mapping: %v", port)
	}
	removal := patch["ports_remove"].([]any)[0].(map[string]any)
	if removal["host_bind"] != "::1" || removal["protocol"] != "udp" || removal["host_port"] != float64(5353) {
		t.Fatalf("unexpected removal: %v", removal)
	}
	if _, present := removal["guest_port"]; present {
		t.Fatal("removal must not include a guest destination")
	}
}

func secretWire(t *testing.T, spec SecretModifySpec) map[string]any {
	t.Helper()
	out := marshalModifyRequest(t, ModifyOptions{
		Secrets: map[string]SecretModifySpec{"API_KEY": spec},
	})
	return out["patch"].(map[string]any)["secrets"].([]any)[0].(map[string]any)
}

func TestModifyRequestJSONSecretPolicyFields(t *testing.T) {
	headers := false
	requireTLS := false
	entry := secretWire(t, SecretModifySpec{
		Substitution: &SecretSubstitution{
			Headers:      &headers,
			HeaderFields: []string{"authorization"},
			Query:        true,
			Body:         true,
		},
		AllowPlaceholderFor: []string{"echo.example.com"},
		ViolationAction:     ViolationActionBlockAndTerminate,
		RequireTLSIdentity:  &requireTLS,
	})

	sub := entry["substitution"].(map[string]any)
	if sub["headers"] != false || sub["query"] != true || sub["body"] != true {
		t.Fatalf("substitution = %v", sub)
	}
	fields := sub["header_fields"].([]any)
	if len(fields) != 1 || fields[0] != "authorization" {
		t.Fatalf("header_fields = %v", sub["header_fields"])
	}
	passthrough := entry["passthrough_hosts"].([]any)
	if len(passthrough) != 1 || passthrough[0] != "echo.example.com" {
		t.Fatalf("passthrough_hosts = %v", entry["passthrough_hosts"])
	}
	if _, present := entry["allow_placeholder_for"]; present {
		t.Fatalf("AllowPlaceholderFor must be sent as passthrough_hosts; got %v", entry)
	}
	if entry["violation_action"] != "block-and-terminate" {
		t.Fatalf("violation_action = %v", entry["violation_action"])
	}
	if value, present := entry["require_tls_identity"]; !present || value != false {
		t.Fatalf("require_tls_identity false must be sent; got %v", entry)
	}
}

func TestModifyRequestJSONSecretPolicyOmitted(t *testing.T) {
	entry := secretWire(t, SecretModifySpec{AllowedHosts: []string{"api.example.com"}})
	for _, key := range []string{"substitution", "passthrough_hosts", "violation_action", "require_tls_identity"} {
		if _, present := entry[key]; present {
			t.Fatalf("%s must be omitted when unset; got %v", key, entry)
		}
	}
}

func TestModifyRequestJSONSubstitutionDefaults(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fields []string
	}{
		{"nil HeaderFields", nil},
		{"empty HeaderFields", []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := buildModifyRequestJSON(ModifyOptions{
				Secrets: map[string]SecretModifySpec{
					"API_KEY": {Substitution: &SecretSubstitution{HeaderFields: tc.fields, Query: true}},
				},
			})
			if err != nil {
				t.Fatalf("buildModifyRequestJSON: %v", err)
			}
			want := `"substitution":{"headers":true,"header_fields":[],"query":true,"body":false}`
			if !strings.Contains(raw, want) {
				t.Fatalf("expected %s in %s", want, raw)
			}
		})
	}
}

func TestModifyRequestJSONSecretViolationActionSnakeCase(t *testing.T) {
	raw, err := buildModifyRequestJSON(ModifyOptions{
		Secrets: map[string]SecretModifySpec{
			"STRIPE_KEY": {ViolationAction: "block_and_terminate"},
		},
	})
	if err != nil {
		t.Fatalf("buildModifyRequestJSON: %v", err)
	}
	if want := `"violation_action":"block_and_terminate"`; !strings.Contains(raw, want) {
		t.Fatalf("expected %s in %s", want, raw)
	}
}

func TestModifyRequestJSONSecretViolationActionInvalid(t *testing.T) {
	_, err := buildModifyRequestJSON(ModifyOptions{
		Secrets: map[string]SecretModifySpec{
			"STRIPE_KEY": {Value: "sk_test_123", ViolationAction: "explode"},
		},
	})
	if err == nil {
		t.Fatalf("expected unknown ViolationAction to be rejected")
	}
	if !strings.Contains(err.Error(), `secret "STRIPE_KEY"`) || !strings.Contains(err.Error(), "ViolationAction") {
		t.Fatalf("error must name the secret and the field; got %v", err)
	}
	if strings.Contains(err.Error(), "sk_test_123") {
		t.Fatalf("error message leaks the secret value")
	}
}

func TestSecretPolicyRequested(t *testing.T) {
	requireTLS := true
	for _, tc := range []struct {
		name string
		spec SecretModifySpec
		want bool
	}{
		{"material and hosts only", SecretModifySpec{Env: "HOST_VAR", Placeholder: "$K", AllowedHosts: []string{"a.example.com"}}, false},
		{"Substitution", SecretModifySpec{Substitution: &SecretSubstitution{}}, true},
		{"AllowPlaceholderFor", SecretModifySpec{AllowPlaceholderFor: []string{"a.example.com"}}, true},
		{"ViolationAction", SecretModifySpec{ViolationAction: ViolationActionBlock}, true},
		{"RequireTLSIdentity", SecretModifySpec{RequireTLSIdentity: &requireTLS}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := ModifyOptions{Secrets: map[string]SecretModifySpec{
				"PLAIN":   {Value: "v"},
				"API_KEY": tc.spec,
			}}
			if got := secretPolicyRequested(opts); got != tc.want {
				t.Fatalf("secretPolicyRequested = %v, want %v", got, tc.want)
			}
		})
	}
	if secretPolicyRequested(ModifyOptions{}) {
		t.Fatalf("secretPolicyRequested must be false without secrets")
	}
}

func TestAnchorModifyMountsCapturesLocalHostPathsOnly(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	absolute := filepath.Join(cwd, "abs")
	opts := ModifyOptions{Mounts: map[string]MountConfig{
		"/data": {Bind: "rel/data"},
		"/disk": {Disk: "rel/disk.raw"},
		"/abs":  {Bind: absolute},
	}}

	local, err := anchorModifyMounts(opts, BackendLocal)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := anchorModifyMounts(opts, BackendCloud)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"/data": filepath.Join(cwd, "rel/data"),
		"/disk": filepath.Join(cwd, "rel/disk.raw"),
		"/abs":  absolute,
	}
	for guest, path := range want {
		mount := local.Mounts[guest]
		if got := mount.Bind + mount.Disk; got != path {
			t.Errorf("local %s: got %q, want %q", guest, got, path)
		}
	}
	if remote.Mounts["/data"].Bind != "rel/data" || remote.Mounts["/disk"].Disk != "rel/disk.raw" {
		t.Errorf("remote paths changed: %+v", remote.Mounts)
	}
	if opts.Mounts["/data"].Bind != "rel/data" {
		t.Errorf("caller's options were modified: %+v", opts.Mounts)
	}
}

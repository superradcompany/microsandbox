package microsandbox

import (
	"context"
	"encoding/json"
	"testing"
)

func TestCompactionPreservesExplicitZeroAndRejectsCloudHandle(t *testing.T) {
	zero := uint32(0)
	raw, err := json.Marshal(DiskCompactionOptions{Layers: &zero})
	if err != nil || string(raw) != `{"layers":0}` {
		t.Fatalf("explicit zero lost: %s %v", raw, err)
	}
	h := &SandboxHandle{name: "same-name-as-local", backendKind: BackendCloud}
	if _, err := h.Compact(context.Background(), DiskCompactionOptions{}); !IsKind(err, ErrUnsupportedOperation) {
		t.Fatalf("cloud handle must refuse before local lookup: %v", err)
	}
}

func TestCompactionSelectorsAndDiskResults(t *testing.T) {
	encoded, err := json.Marshal(DiskCompactionOptions{Disk: "/data", RootDiskOnly: true})
	if err != nil || string(encoded) != `{"disk":"/data","root_disk_only":true}` {
		t.Fatalf("selectors must reach shared validation without being dropped: %s %v", encoded, err)
	}
	result, err := parseCompaction(`{"dry_run":true,"input_layers":6,"selected_layers":4,"output_layers":4,"materialized_bytes":0,"total_us":10,"pause_us":0,"disks":[{"guest_path":"/data","input_layers":3,"selected_layers":2,"output_layers":2,"materialized_bytes":0,"total_us":4}]}`, nil)
	if err != nil || len(result.Disks) != 1 || result.Disks[0].GuestPath != "/data" || result.Disks[0].SelectedLayers != 2 {
		t.Fatalf("per-disk result lost: %#v %v", result, err)
	}
}

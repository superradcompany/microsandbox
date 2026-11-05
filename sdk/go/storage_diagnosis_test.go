package microsandbox

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"testing"
)

func TestStorageDiagnosisExactBytesAndPartialResults(t *testing.T) {
	const payload = `{"home":"/selected","required_runtime_capability":"protected_guest_state","sandboxes":[{"name":"app","status":"eligible","running":true,"protection_registered":true,"reason":null,"inspection":{"status":"eligible","reasons":[],"estimated_bytes":18446744073709551615,"candidates":[{"id":"view-1","disk_id":"root","layers":2,"virtual_size":18446744073709551615,"estimated_bytes":0}]}},{"name":"missing","status":"unavailable","running":false,"protection_registered":false,"reason":"not_found","inspection":null}]}`
	var report StorageDiagnosis
	if err := json.Unmarshal([]byte(payload), &report); err != nil {
		t.Fatal(err)
	}
	if report.Sandboxes[0].Status != StorageEligible || !report.Sandboxes[0].Running || report.Sandboxes[0].Inspection.Candidates[0].VirtualSize != math.MaxUint64 {
		t.Fatalf("invalid report: %+v", report)
	}
	if report.Sandboxes[1].Inspection != nil || *report.Sandboxes[1].Reason != "not_found" {
		t.Fatal("lost partial result")
	}
}

func TestStorageDiagnosisPreviewMetadata(t *testing.T) {
	const payload = `{"sandboxes":[{"guest_mounts":{"owned-1":"/work"},"inspection":{"preview_available":true}},{"inspection":{}}]}`
	var report StorageDiagnosis
	if err := json.Unmarshal([]byte(payload), &report); err != nil {
		t.Fatal(err)
	}
	current, legacy := report.Sandboxes[0], report.Sandboxes[1]
	if current.GuestMounts["owned-1"] != "/work" || !current.Inspection.PreviewAvailable {
		t.Fatal("lost guest mount or preview availability")
	}
	if len(legacy.GuestMounts) != 0 || legacy.Inspection.PreviewAvailable {
		t.Fatal("older payload invented a preview")
	}
}

func TestStorageDiagnosisRejectsAmbiguousScopeAndCancellationBeforeLoading(t *testing.T) {
	for _, selection := range []StorageSelection{{}, {Names: []string{}}, {Names: []string{"app"}, All: true}} {
		if _, err := DiagnoseStorage(context.Background(), RuntimeConfig{}, selection); err == nil {
			t.Fatal("ambiguous selection accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DiagnoseStorage(ctx, RuntimeConfig{}, StorageSelection{Names: []string{"app"}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled call: %v", err)
	}
}

func TestStorageRecoveryCancellationDoesNotLoadNative(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := RecoverStorage(ctx, "app", StorageRecoveryOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled recovery: %v", err)
	}
	encoded, err := json.Marshal(StorageRecoveryOptions{Selections: []StorageRecoverySelection{{DiskID: "root", CandidateID: "view"}}})
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(encoded, &value); err != nil {
		t.Fatal(err)
	}
	if value["accept_selected_view"] != false || value["legacy_writers_stopped"] != false {
		t.Fatal("wrapper invented recovery acknowledgement")
	}
}

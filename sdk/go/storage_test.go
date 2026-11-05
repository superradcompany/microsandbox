package microsandbox

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
)

func TestStorageReportsPreserveUnknownValuesAndExactByteIntegers(t *testing.T) {
	const payload = `{"images":{"count":2,"in_use":null,"logical_bytes":18446744073709551615,"allocated_bytes":null,"reclaimable_logical_bytes":null,"items":[],"notes":[]},"branch_memory":{"count":0,"in_use":0,"logical_bytes":0,"allocated_bytes":0,"reclaimable_logical_bytes":0,"items":[],"notes":[]},"notes":[]}`
	var report StorageUsageReport
	if err := json.Unmarshal([]byte(payload), &report); err != nil {
		t.Fatal(err)
	}
	if report.Images.InUse != nil || report.Images.AllocatedBytes != nil || report.Images.ReclaimableLogicalBytes != nil {
		t.Fatalf("unknown accounting became zero: %+v", report.Images)
	}
	if report.Images.LogicalBytes == nil || *report.Images.LogicalBytes != math.MaxUint64 {
		t.Fatalf("raw byte count lost precision: %+v", report.Images.LogicalBytes)
	}
	if report.BranchMemory.LogicalBytes == nil || *report.BranchMemory.LogicalBytes != 0 {
		t.Fatal("known empty cache must retain a zero value")
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"logical_bytes":18446744073709551615`) || !strings.Contains(string(encoded), `"in_use":null`) {
		t.Fatalf("JSON report changed accounting semantics: %s", encoded)
	}
}

func TestStoragePruneReportPreservesFailuresAndUnknownPhysicalReclamation(t *testing.T) {
	const payload = `{"dry_run":false,"entries":[{"path":"a.ram","kind":"branch_memory","logical_bytes":17,"allocated_bytes":4096,"state":"removed","error":null},{"path":"b.ram","kind":"branch_memory","logical_bytes":null,"allocated_bytes":null,"state":"error","error":"permission denied"}],"files_removed":1,"logical_bytes_removed":17,"physical_bytes_reclaimed":null,"truncated":false}`
	var report StoragePruneReport
	if err := json.Unmarshal([]byte(payload), &report); err != nil {
		t.Fatal(err)
	}
	if report.PhysicalBytesReclaimed != nil || report.LogicalBytesRemoved != 17 || report.FilesRemoved != 1 {
		t.Fatalf("invalid removal accounting: %+v", report)
	}
	if len(report.Entries) != 2 || report.Entries[1].Error == nil || *report.Entries[1].Error != "permission denied" {
		t.Fatalf("lost per-file failure: %+v", report.Entries)
	}
}

func TestSandboxStorageItemPreservesUnknownOwnershipAndExactBytes(t *testing.T) {
	const payload = `{"name":"retained-sandbox","path":"/managed/sandboxes/retained-sandbox","logical_bytes":18446744073709551615,"allocated_bytes":null,"in_use":null,"reclaimable":null,"reasons":["Host bind mounts are excluded."]}`
	var report StorageItemUsage
	if err := json.Unmarshal([]byte(payload), &report); err != nil {
		t.Fatal(err)
	}
	if report.LogicalBytes == nil || *report.LogicalBytes != math.MaxUint64 || report.AllocatedBytes != nil || report.InUse != nil || report.Reclaimable != nil {
		t.Fatalf("per-object accounting lost precision or unknown state: %+v", report)
	}
	if report.Name != "retained-sandbox" || len(report.Reasons) != 1 {
		t.Fatalf("per-object accounting lost identity or scope: %+v", report)
	}
}

func TestStoragePruneOptionsRetainExplicitDryRunAndAge(t *testing.T) {
	encoded, err := json.Marshal(StoragePruneOptions{DryRun: true, OlderThanSeconds: 600})
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"dry_run":true,"older_than_seconds":600}` {
		t.Fatalf("unexpected native request: %s", encoded)
	}
}

func TestCancelledStorageOperationsDoNotLoadOrDispatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := StorageUsage(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("usage with cancelled context returned %v", err)
	}
	if _, err := PruneStorage(ctx, StoragePruneOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("prune with cancelled context returned %v", err)
	}
}

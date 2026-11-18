package microsandbox

import (
	"context"
	"encoding/json"
	"math"
	"reflect"
	"testing"
)

func resizeRecord() ResizeOperation {
	return ResizeOperation{ID: "operation", RuntimeBootID: "runtime", Generation: math.MaxUint64,
		RequestedTarget: ResizeTarget{Resource: "memory", TotalMiB: math.MaxUint64},
		AcceptedTarget:  ResizeTarget{Resource: "memory", TotalMiB: 514},
		Status:          ResourceResizeStatus{Resource: "memory", Requested: "514 MiB", Actual: "256 MiB", Enforced: "514 MiB", State: "accepted"},
		Outcome:         ResizePending, Observation: ResizeObservationPaused}
}

func TestResizeOperationsPreserveFullWidthRecords(t *testing.T) {
	original := []ResizeOperation{resizeRecord()}
	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseResizeOperations(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(parsed, original) {
		t.Fatalf("round trip changed operation: %#v", parsed)
	}
	request, err := resizeWaitRequest(parsed, math.MaxUint64)
	if err != nil {
		t.Fatal(err)
	}
	var decoded resizeOperationRequest
	if err := json.Unmarshal([]byte(request), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.TimeoutMs != math.MaxUint64 || !reflect.DeepEqual(decoded.Operations, original) {
		t.Fatalf("request lost precision: %#v", decoded)
	}
	for _, raw := range []string{`[{"generation":18446744073709551616}]`, `[{"generation":1.5}]`, `[{"generation":-1}]`} {
		if _, err := parseResizeOperations(raw); err == nil {
			t.Fatalf("accepted invalid generation: %s", raw)
		}
	}
}

func TestTrackedModifyPreservesOptionsAndMissingTracking(t *testing.T) {
	cpus := uint8(2)
	opts := ModifyOptions{CPUs: cpus, Labels: map[string]string{"purpose": "test"}, DryRun: true}
	expected, err := buildModifyRequestJSON(opts)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := trackedModifyRequest(opts)
	if err != nil {
		t.Fatal(err)
	}
	var request resizeOperationRequest
	if err := json.Unmarshal([]byte(raw), &request); err != nil {
		t.Fatal(err)
	}
	if request.Operation != "modify" || string(request.Options) != expected {
		t.Fatalf("changed modify options: %s", raw)
	}
	result, err := parseModificationResult(`{"plan":{"applied":true},"resize_operations":null}`)
	if err != nil || !result.Plan.Applied || result.ResizeOperations != nil {
		t.Fatalf("missing tracking: %#v %v", result, err)
	}
}

func TestInvalidOperationCountsFailBeforeFFI(t *testing.T) {
	sandbox := new(Sandbox)
	handle := new(SandboxHandle)
	for _, records := range [][]ResizeOperation{nil, {}, {resizeRecord(), resizeRecord(), resizeRecord()}} {
		if _, err := sandbox.WaitForResizeOperations(context.Background(), records); err == nil {
			t.Fatal("sandbox accepted invalid count")
		}
		if _, err := handle.WaitForResizeOperations(context.Background(), records); err == nil {
			t.Fatal("handle accepted invalid count")
		}
	}
}

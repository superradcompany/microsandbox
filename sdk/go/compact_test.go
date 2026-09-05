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

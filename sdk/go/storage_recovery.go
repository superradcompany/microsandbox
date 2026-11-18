package microsandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// StorageRecoverySelection chooses a complete role-bound disk view from diagnosis.
type StorageRecoverySelection struct {
	DiskID      string `json:"disk_id"`
	CandidateID string `json:"candidate_id"`
}

// StorageRecoveryOptions requires acknowledgement for explicit views that may omit later writes.
type StorageRecoveryOptions struct {
	Selections         []StorageRecoverySelection `json:"selections,omitempty"`
	AcceptSelectedView bool                       `json:"accept_selected_view"`
	// macOS: all legacy VMs across homes are stopped, and no new writers may start during recovery.
	LegacyWritersStopped bool `json:"legacy_writers_stopped"`
}

// StorageRecovery describes a stopped sandbox whose storage is ready, with originals retained.
type StorageRecovery struct {
	Name              string `json:"name"`
	Ready             bool   `json:"ready"`
	OriginalsRetained bool   `json:"originals_retained"`
}

// RecoverStorage imports or recovers stopped storage using the active SDK backend. It never boots
// or stops a VM. Candidate selections are revalidated under lifecycle locks before mutation.
func RecoverStorage(ctx context.Context, name string, options StorageRecoveryOptions) (StorageRecovery, error) {
	var result StorageRecovery
	encoded, err := json.Marshal(struct {
		Name    string                 `json:"name"`
		Options StorageRecoveryOptions `json:"options"`
	}{name, options})
	if err != nil {
		return result, err
	}
	// Older libraries parse the unchanged empty setup config and reject the unknown
	// operation before touching sandbox storage; never send a name in the config slot.
	output, err := ffi.RuntimeSetup(ctx, "recover_storage", "{}", string(encoded))
	if err != nil {
		if strings.Contains(err.Error(), "unknown runtime setup operation") {
			return result, fmt.Errorf("storage recovery requires an updated native SDK; upgrade or rebuild it: %w", err)
		}
		return result, wrapFFI(err)
	}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		return result, fmt.Errorf("decode storage recovery: %w", err)
	}
	return result, nil
}

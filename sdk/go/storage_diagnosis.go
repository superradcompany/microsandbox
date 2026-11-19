package microsandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// StorageSelection explicitly selects names or all sandboxes in the configured home.
type StorageSelection struct {
	Names []string
	All   bool
}

// StorageDiagnosticStatus identifies readiness independently of the triggering operation.
type StorageDiagnosticStatus string

const (
	StorageReady               StorageDiagnosticStatus = "ready"
	StorageEligible            StorageDiagnosticStatus = "eligible"
	StorageMaintenanceRequired StorageDiagnosticStatus = "maintenance_required"
	StorageRecoveryRequired    StorageDiagnosticStatus = "recovery_required"
	StorageInProgress          StorageDiagnosticStatus = "in_progress"
	StorageUnavailable         StorageDiagnosticStatus = "unavailable"
)

// StorageCandidate is a provisional role-bound disk view, never an authorization token.
type StorageCandidate struct {
	ID             string `json:"id"`
	DiskID         string `json:"disk_id"`
	Layers         uint64 `json:"layers"`
	VirtualSize    uint64 `json:"virtual_size"`
	EstimatedBytes uint64 `json:"estimated_bytes"`
}

// StorageInspection is the shared engine's non-mutating inspection result.
type StorageInspection struct {
	Status           string             `json:"status"`
	Reasons          []string           `json:"reasons"`
	PreviewAvailable bool               `json:"preview_available"`
	Candidates       []StorageCandidate `json:"candidates"`
	EstimatedBytes   uint64             `json:"estimated_bytes"`
}

// StorageSandboxDiagnosis preserves individual errors when a requested set is inspected.
type StorageSandboxDiagnosis struct {
	Name                 string                  `json:"name"`
	Status               StorageDiagnosticStatus `json:"status"`
	Running              bool                    `json:"running"`
	GuestMounts          map[string]string       `json:"guest_mounts"`
	ProtectionRegistered bool                    `json:"protection_registered"`
	Reason               *string                 `json:"reason"`
	Inspection           *StorageInspection      `json:"inspection"`
}

// StorageDiagnosis reports readiness without migrating catalog records or disk state.
type StorageDiagnosis struct {
	Home                      string                    `json:"home"`
	Sandboxes                 []StorageSandboxDiagnosis `json:"sandboxes"`
	RequiredRuntimeCapability string                    `json:"required_runtime_capability"`
}

// DiagnoseStorage inspects explicitly selected local storage. SQLite may maintain WAL read-lock
// sidecars. Runtime installation, catalog repair and VM start/stop never occur. As for other SDK
// calls, first use can materialize the SDK's embedded native library.
func DiagnoseStorage(ctx context.Context, config RuntimeConfig, selection StorageSelection) (StorageDiagnosis, error) {
	var result StorageDiagnosis
	if selection.All == (len(selection.Names) > 0) {
		return result, fmt.Errorf("select sandbox names or All, exclusively")
	}
	var scope any = "all"
	if !selection.All {
		scope = map[string]any{"named": selection.Names}
	}
	encoded, err := json.Marshal(scope)
	if err != nil {
		return result, err
	}
	configuration, err := json.Marshal(config)
	if err != nil {
		return result, err
	}
	output, err := ffi.RuntimeSetup(ctx, "diagnose_storage", string(configuration), string(encoded))
	if err != nil {
		if strings.Contains(err.Error(), "unknown runtime setup operation") {
			return result, fmt.Errorf("storage diagnostics require an updated native SDK; upgrade or rebuild the library: %w", err)
		}
		return result, wrapFFI(err)
	}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		return result, fmt.Errorf("decode storage diagnosis: %w", err)
	}
	return result, nil
}
